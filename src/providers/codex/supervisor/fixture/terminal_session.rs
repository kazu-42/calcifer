//! Real-PTY fault harness for the default-unused supervised terminal kernel.
//!
//! The fixture is deliberately closed over [`Scenario`]. It cannot execute an
//! arbitrary provider command or retain terminal payloads.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitCode, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use calcifer_unix_child_fd::descriptor_identity;

use super::*;
use crate::providers::codex::supervisor::terminal::{
    GateOpen, InputGate, PtyMaster, PtyOwner, RecoveryTty, TerminalBuffer, TerminalChannelPair,
    TerminalChunk, TerminalEndpoint, TerminalError, TerminalRead, TerminalShutdown, TerminalSize,
    TerminalSnapshot, TerminalTty, TerminalWrite, claim_controlling_terminal_from_stdin,
    terminal_size,
};

const GUARDIAN_TERMINAL_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_TERMINAL_FD";
const GUARDIAN_RECOVERY_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_RECOVERY_FD";
const GUARDIAN_FOREGROUND_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_FOREGROUND_PGRP";
const COORDINATOR_FOREGROUND_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_FOREGROUND_TERMINAL";
const HEARTBEAT_EXPECTED_GROUP_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_HEARTBEAT_EXPECTED_GROUP";

const TUI_READINESS_TOKEN: u8 = 1;
const TUI_EXIT_BYTE: u8 = 0x04;
const EVENT_POLL: Duration = Duration::from_millis(10);
const ANCHOR_TIMEOUT: Duration = Duration::from_secs(30);
static CLEANUP_RESOLUTION_ENABLED: AtomicBool = AtomicBool::new(false);
static FOREGROUND_RECLAIM_RESOLUTION_ENABLED: AtomicBool = AtomicBool::new(false);

struct SignalFlag {
    pending: Arc<AtomicBool>,
    registration: Option<signal_hook::SigId>,
}

impl SignalFlag {
    fn register(signal: i32) -> Result<Self, FixtureError> {
        let pending = Arc::new(AtomicBool::new(false));
        let registration = signal_hook::flag::register(signal, Arc::clone(&pending))
            .map_err(|_| FixtureError::Process)?;
        Ok(Self {
            pending,
            registration: Some(registration),
        })
    }

    fn take(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }

    fn clear(&self) {
        self.pending.store(false, Ordering::Release);
    }

    fn wait_until(&self, deadline: Instant) -> bool {
        loop {
            if self.take() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(EVENT_POLL);
        }
    }
}

impl Drop for SignalFlag {
    fn drop(&mut self) {
        if let Some(registration) = self.registration.take() {
            let _ = signal_hook::low_level::unregister(registration);
        }
    }
}

enum TerminalSignalAction {
    Forward(UnixSignal),
    Resize,
    Suspend,
    Continue,
}

/// Fixed-memory signal latches for the coordinator's normal-thread loop.
///
/// The async handlers installed by `signal-hook` only set one atomic bit.
/// Repeated WINCH events therefore coalesce to the latest tty size instead of
/// creating a queue, while distinct signal classes remain independently
/// observable.
struct TerminalSignalFlags {
    hup: SignalFlag,
    interrupt: SignalFlag,
    quit: SignalFlag,
    term: SignalFlag,
    winch: SignalFlag,
    tstp: SignalFlag,
    cont: SignalFlag,
}

impl TerminalSignalFlags {
    fn install() -> Result<Self, FixtureError> {
        use signal_hook::consts::signal::{
            SIGCONT, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP, SIGWINCH,
        };

        let hup = SignalFlag::register(SIGHUP)?;
        let interrupt = SignalFlag::register(SIGINT)?;
        let quit = SignalFlag::register(SIGQUIT)?;
        let term = SignalFlag::register(SIGTERM)?;
        let winch = SignalFlag::register(SIGWINCH)?;
        let tstp = SignalFlag::register(SIGTSTP)?;
        let cont = SignalFlag::register(SIGCONT)?;
        Ok(Self {
            hup,
            interrupt,
            quit,
            term,
            winch,
            tstp,
            cont,
        })
    }

    fn next(&self, suspended: bool) -> Option<TerminalSignalAction> {
        if self.hup.take() {
            Some(TerminalSignalAction::Forward(UnixSignal::Hup))
        } else if self.term.take() {
            Some(TerminalSignalAction::Forward(UnixSignal::Term))
        } else if !suspended && self.tstp.take() {
            Some(TerminalSignalAction::Suspend)
        } else if self.interrupt.take() {
            Some(TerminalSignalAction::Forward(UnixSignal::Int))
        } else if self.quit.take() {
            Some(TerminalSignalAction::Forward(UnixSignal::Quit))
        } else if !suspended && self.winch.take() {
            Some(TerminalSignalAction::Resize)
        } else if suspended && self.cont.take() {
            Some(TerminalSignalAction::Continue)
        } else {
            None
        }
    }

    fn clear_continue(&self) {
        self.cont.clear();
    }

    fn wait_for_continue(&self, deadline: Instant) -> bool {
        self.cont.wait_until(deadline)
    }
}

/// Keeps the synthetic shell's terminal session alive while its exact child
/// coordinator is fault-injected.
///
/// A real interactive shell remains the controlling-terminal session leader
/// when Calcifer is killed. Making the coordinator itself the session leader
/// would let Darwin revoke the PTY on coordinator exit and turn a valid
/// recovery descriptor into a different device identity. This anchor models
/// the real ownership boundary: it never handles terminal bytes and uses only
/// its direct [`Child`] handle as signal authority.
pub(super) fn run_terminal_anchor(scenario: Scenario) -> Result<ExitCode, FixtureError> {
    let proof = claim_controlling_terminal_from_stdin().map_err(|_| FixtureError::Process)?;
    if proof.process() != proof.process_group()
        || proof.process() != proof.session()
        || proof.process() != proof.foreground_process_group()
    {
        return Err(FixtureError::Invariant);
    }
    let anchor_snapshot =
        TerminalSnapshot::capture(io::stdin()).map_err(|_| FixtureError::Process)?;

    let mut command = Command::new(current_fixture_executable()?);
    command
        .args(["coordinator", scenario.as_str()])
        .env(COORDINATOR_FOREGROUND_ENV, "1")
        .process_group(0);
    let mut coordinator = command.spawn().map_err(|_| FixtureError::Process)?;
    let deadline = bounded_deadline(ANCHOR_TIMEOUT);
    let mut child_reaped = false;
    let result = drive_terminal_anchor(&mut coordinator, scenario, deadline, &mut child_reaped);
    if result.is_err() {
        if !child_reaped {
            let _ = coordinator.kill();
            if wait_exact_child(&mut coordinator, bounded_deadline(PHASE_TIMEOUT)).is_err() {
                let _ = restore_anchor_terminal(&anchor_snapshot);
                RetainedTerminalAnchorState {
                    coordinator,
                    snapshot: anchor_snapshot,
                }
                .park()
            }
        }
        if restore_anchor_terminal(&anchor_snapshot).is_err() {
            RetainedTerminalAnchorState {
                coordinator,
                snapshot: anchor_snapshot,
            }
            .park()
        }
    }
    result
}

struct RetainedTerminalAnchorState {
    coordinator: Child,
    snapshot: TerminalSnapshot,
}

impl RetainedTerminalAnchorState {
    fn park(self) -> ! {
        let _ = (self.coordinator.id(), self.snapshot.descriptor_identity());
        std::mem::forget(self);
        loop {
            thread::park();
        }
    }
}

fn restore_anchor_terminal(snapshot: &TerminalSnapshot) -> Result<(), FixtureError> {
    reclaim_anchor_foreground()?;
    restore_snapshot_with_sigttou_block(snapshot, io::stdin())
        .map_err(|_| FixtureError::Process)?;
    write_restored_marker_idempotent()
}

fn drive_terminal_anchor(
    coordinator: &mut Child,
    scenario: Scenario,
    deadline: Instant,
    child_reaped: &mut bool,
) -> Result<ExitCode, FixtureError> {
    let coordinator_group = wait_for_direct_child_group(coordinator, deadline, child_reaped)?;
    rustix::termios::tcsetpgrp(io::stdin(), coordinator_group)
        .map_err(|_| FixtureError::Process)?;
    if rustix::termios::tcgetpgrp(io::stdin()).map_err(|_| FixtureError::Process)?
        != coordinator_group
    {
        return Err(FixtureError::Invariant);
    }
    write_process_marker("coordinator.pid", coordinator_group.as_raw_nonzero().get())?;
    write_marker("anchor.foreground", b"ready\n")?;
    let mut controls = AnchorControlState::default();

    loop {
        match fs::read(marker_path("test.kill-coordinator")?) {
            Ok(value) if value == b"release\n" => {
                if scenario == Scenario::PtyForegroundReclaim {
                    // Freeze the exact coordinator process group while its
                    // lifecycle endpoint is still open. This prevents the
                    // guardian from racing EOF recovery ahead of the fault's
                    // foreground handoff.
                    signal_direct_child_group(
                        coordinator,
                        coordinator_group,
                        rustix::process::Signal::STOP,
                    )?;
                    wait_for_direct_child_stopped(coordinator, deadline)?;
                    write_marker("anchor.coordinator-frozen", b"stopped\n")?;

                    // Model a living shell/session anchor selecting itself as
                    // foreground before the guardian can observe lifecycle
                    // EOF. The current raw attributes deliberately remain in
                    // place as the no-clobber sentinel.
                    reclaim_anchor_foreground()?;
                    write_marker("anchor.foreground-reclaimed", b"reclaimed\n")?;
                    coordinator.kill().map_err(|_| FixtureError::Process)?;
                    let status = wait_exact_child(coordinator, deadline)?;
                    *child_reaped = true;
                    if status.success() {
                        return Err(FixtureError::Invariant);
                    }
                    write_marker("coordinator.killed", b"killed\n")?;
                    wait_for_exact_marker_until(
                        "terminal.restore-error",
                        b"not_foreground_process_group",
                        deadline,
                    )?;
                    write_marker("anchor.restore-refused-observed", b"observed\n")?;
                    wait_for_exact_marker_until(
                        "test.resolve-foreground-reclaim",
                        b"release\n",
                        deadline,
                    )?;
                    // Returning an error transfers final recovery to the
                    // anchor snapshot owned by `run_terminal_anchor`.
                    return Err(FixtureError::Process);
                }

                coordinator.kill().map_err(|_| FixtureError::Process)?;
                let status = wait_exact_child(coordinator, deadline)?;
                *child_reaped = true;
                if status.success() {
                    return Err(FixtureError::Invariant);
                }
                write_marker("coordinator.killed", b"killed\n")?;

                // Keep the terminal session leader alive until the guardian's
                // fallback restoration has completed. In the guardian-death
                // case the coordinator already restored before it parked.
                wait_for_exact_marker_until("terminal.restored", b"restored\n", deadline)?;
                if scenario != Scenario::PtyGuardianDeath {
                    wait_for_exact_marker_until("guardian.cleaned", b"complete\n", deadline)?;
                }
                reclaim_anchor_foreground()?;
                return Ok(ExitCode::from(EXIT_FAILURE));
            }
            // Test capabilities are created with a truncate-and-write helper.
            // A concurrent reader can briefly observe an empty or partial
            // file; only the complete fixed token releases authority.
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(FixtureError::Storage),
        }

        dispatch_anchor_controls(coordinator, coordinator_group, &mut controls)?;

        match coordinator.try_wait() {
            Ok(Some(status)) => {
                *child_reaped = true;
                reclaim_anchor_foreground()?;
                return propagate_exit_status(status);
            }
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(FixtureError::Process),
        }
        if Instant::now() >= deadline {
            return Err(FixtureError::Deadline);
        }
        thread::sleep(EVENT_POLL);
    }
}

#[derive(Default)]
struct AnchorControlState {
    hup: bool,
    interrupt: bool,
    quit: bool,
    term: bool,
    winch_storm: bool,
    tstp: bool,
    suspended: bool,
    cont: bool,
}

fn dispatch_anchor_controls(
    coordinator: &mut Child,
    coordinator_group: rustix::process::Pid,
    controls: &mut AnchorControlState,
) -> Result<(), FixtureError> {
    use rustix::process::Signal;

    for (marker, already_sent, signal) in [
        ("test.signal-hup", &mut controls.hup, Signal::HUP),
        ("test.signal-int", &mut controls.interrupt, Signal::INT),
        ("test.signal-quit", &mut controls.quit, Signal::QUIT),
        ("test.signal-term", &mut controls.term, Signal::TERM),
        ("test.signal-tstp", &mut controls.tstp, Signal::TSTP),
    ] {
        if !*already_sent && test_capability_released(marker)? {
            signal_direct_child_group(coordinator, coordinator_group, signal)?;
            *already_sent = true;
        }
    }

    if !controls.winch_storm && test_capability_released("test.signal-winch-storm")? {
        for _ in 0..128 {
            signal_direct_child_group(coordinator, coordinator_group, Signal::WINCH)?;
        }
        controls.winch_storm = true;
        write_marker("anchor.winch-storm-sent", b"sent\n")?;
    }

    if controls.tstp && !controls.suspended && !controls.cont {
        let pid = rustix::process::Pid::from_child(&*coordinator);
        let options = rustix::process::WaitIdOptions::STOPPED
            | rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOHANG
            | rustix::process::WaitIdOptions::NOWAIT;
        match rustix::process::waitid(rustix::process::WaitId::Pid(pid), options) {
            Ok(Some(status)) if status.stopped() => {
                reclaim_anchor_foreground()?;
                controls.suspended = true;
                write_marker("anchor.coordinator-stopped", b"stopped\n")?;
            }
            Ok(Some(status)) if status.exited() || status.killed() || status.dumped() => {
                return Err(FixtureError::Process);
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(FixtureError::Process),
        }
    }

    if controls.suspended && !controls.cont && test_capability_released("test.signal-cont")? {
        rustix::termios::tcsetpgrp(io::stdin(), coordinator_group)
            .map_err(|_| FixtureError::Process)?;
        if rustix::termios::tcgetpgrp(io::stdin()).map_err(|_| FixtureError::Process)?
            != coordinator_group
        {
            return Err(FixtureError::Invariant);
        }
        signal_direct_child_group(coordinator, coordinator_group, Signal::CONT)?;
        controls.cont = true;
        controls.suspended = false;
        write_marker("anchor.coordinator-continued", b"continued\n")?;
    }
    Ok(())
}

fn test_capability_released(name: &str) -> Result<bool, FixtureError> {
    match fs::read(marker_path(name)?) {
        Ok(value) if value == b"release\n" => Ok(true),
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(FixtureError::Storage),
    }
}

fn signal_direct_child_group(
    child: &Child,
    expected_group: rustix::process::Pid,
    signal: rustix::process::Signal,
) -> Result<(), FixtureError> {
    let pid = rustix::process::Pid::from_child(child);
    if pid != expected_group
        || rustix::process::getpgid(Some(pid)).map_err(|_| FixtureError::Process)? != expected_group
    {
        return Err(FixtureError::Invariant);
    }
    rustix::process::kill_process_group(expected_group, signal).map_err(|_| FixtureError::Process)
}

fn wait_for_direct_child_group(
    child: &mut Child,
    deadline: Instant,
    child_reaped: &mut bool,
) -> Result<rustix::process::Pid, FixtureError> {
    let pid = rustix::process::Pid::from_child(&*child);
    loop {
        match rustix::process::getpgid(Some(pid)) {
            Ok(group) if group == pid => return Ok(group),
            Ok(_) | Err(rustix::io::Errno::SRCH) => {}
            Err(_) => return Err(FixtureError::Process),
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                *child_reaped = true;
                return Err(FixtureError::Process);
            }
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(FixtureError::Process),
        }
        if Instant::now() >= deadline {
            return Err(FixtureError::Deadline);
        }
        thread::sleep(EVENT_POLL);
    }
}

fn wait_for_direct_child_stopped(child: &Child, deadline: Instant) -> Result<(), FixtureError> {
    let pid = rustix::process::Pid::from_child(child);
    loop {
        let options = rustix::process::WaitIdOptions::STOPPED
            | rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOHANG
            | rustix::process::WaitIdOptions::NOWAIT;
        match rustix::process::waitid(rustix::process::WaitId::Pid(pid), options) {
            Ok(Some(status)) if status.stopped() => return Ok(()),
            Ok(Some(status)) if status.exited() || status.killed() || status.dumped() => {
                return Err(FixtureError::Process);
            }
            Ok(Some(_)) | Ok(None) if Instant::now() < deadline => {
                thread::sleep(EVENT_POLL);
            }
            Ok(Some(_)) | Ok(None) => return Err(FixtureError::Deadline),
            Err(rustix::io::Errno::INTR) if Instant::now() < deadline => {}
            Err(rustix::io::Errno::INTR) => return Err(FixtureError::Deadline),
            Err(_) => return Err(FixtureError::Process),
        }
    }
}

fn reclaim_anchor_foreground() -> Result<(), FixtureError> {
    let guard = calcifer_unix_child_fd::block_sigttou_for_current_thread()
        .map_err(|_| FixtureError::Process)?;
    let group = rustix::process::getpgrp();
    let result = rustix::termios::tcsetpgrp(io::stdin(), group)
        .map_err(|_| FixtureError::Process)
        .and_then(|()| {
            if rustix::termios::tcgetpgrp(io::stdin()).map_err(|_| FixtureError::Process)? == group
            {
                Ok(())
            } else {
                Err(FixtureError::Invariant)
            }
        });
    drop(guard);
    result
}

fn propagate_exit_status(status: ExitStatus) -> Result<ExitCode, FixtureError> {
    if let Some(code) = status.code().and_then(|code| u8::try_from(code).ok()) {
        return Ok(ExitCode::from(code));
    }
    if let Some(signal) = status.signal() {
        signal_hook::low_level::emulate_default_handler(signal)
            .map_err(|_| FixtureError::Process)?;
    }
    Err(FixtureError::Process)
}

/// Runs the outer coordinator attached by the integration test to a real PTY.
pub(super) fn run_coordinator(scenario: Scenario) -> Result<ExitCode, FixtureError> {
    run_terminal_coordinator(scenario)
}

/// Runs the guardian with lifecycle, terminal-byte, and recovery capabilities
/// inherited through three distinct standard descriptors.
pub(super) fn run_guardian(scenario: Scenario) -> Result<ExitCode, FixtureError> {
    run_terminal_guardian(scenario)
}

/// Fixed fake TUI used only by the internal real-exec harness.
///
/// The child claims the PTY slave after exec, proves all three standard
/// streams refer to a terminal, enters raw mode on the *inner* PTY, emits one
/// readiness byte, and then echoes one byte at a time. It never allocates or
/// retains a transcript.
pub(super) fn run_fake_tui(scenario: Scenario) -> Result<ExitCode, FixtureError> {
    let inherited_readiness = calcifer_unix_child_fd::take_inherited_readiness_fd()
        .map_err(|_| FixtureError::Descriptor)?;
    let mut readiness = UnixStream::from(inherited_readiness);
    let proof = claim_controlling_terminal_from_stdin().map_err(|_| FixtureError::Process)?;
    if !rustix::termios::isatty(io::stdin())
        || !rustix::termios::isatty(io::stdout())
        || !rustix::termios::isatty(io::stderr())
        || proof.process() != proof.process_group()
        || proof.process() != proof.session()
        || proof.process() != proof.foreground_process_group()
    {
        return Err(FixtureError::Invariant);
    }
    write_marker("tui.tty", b"verified\n")?;

    if terminal_size(io::stdin()).map_err(|_| FixtureError::Process)? != TerminalSize::new(37, 111)
    {
        return Err(FixtureError::Invariant);
    }
    write_marker("tui.winsize", b"37x111\n")?;

    let mut attributes =
        rustix::termios::tcgetattr(io::stdin()).map_err(|_| FixtureError::Process)?;
    attributes.make_raw();
    rustix::termios::tcsetattr(
        io::stdin(),
        rustix::termios::OptionalActions::Now,
        &attributes,
    )
    .map_err(|_| FixtureError::Process)?;

    // Install every scenario-specific handler before the test can release
    // readiness. Once READY is published the coordinator may immediately
    // forward a signal, so installing afterward would leave a default-action
    // race in the real-exec fixture.
    let signal_flags = TuiSignalFlags::install(scenario)?;
    let _heartbeat_descendant = if scenario == Scenario::PtySuspendResume {
        Some(spawn_tstp_heartbeat_descendant()?)
    } else {
        None
    };
    if scenario == Scenario::PtyTuiEarlyExit {
        write_marker("tui.early-exit-armed", b"armed\n")?;
        wait_for_exact_marker("test.release-fault", b"release\n")?;
        write_marker("tui.early-exit", b"before-readiness\n")?;
        return Ok(ExitCode::SUCCESS);
    }
    wait_for_exact_marker("test.release-ready", b"release\n")?;
    write_marker("tui.ready", b"ready\n")?;
    readiness
        .write_all(&[TUI_READINESS_TOKEN])
        .and_then(|()| readiness.flush())
        .map_err(|_| FixtureError::Process)?;
    readiness
        .shutdown(std::net::Shutdown::Both)
        .map_err(|_| FixtureError::Process)?;
    drop(readiness);

    if scenario == Scenario::PtyTuiExitBeforeGate {
        write_marker("tui.pre-gate-exit-armed", b"armed\n")?;
        wait_for_exact_marker("test.release-fault", b"release\n")?;
        write_marker("tui.pre-gate-exit", b"exiting\n")?;
        return Ok(ExitCode::from(23));
    }

    let mut signal_state = TuiSignalState::default();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut byte = [0_u8; 1];
    loop {
        signal_flags.observe(&mut signal_state)?;
        if scenario == Scenario::PtyTuiExitBeforeResumeGate && signal_state.continue_seen {
            // This scenario proves the post-resume, pre-input-gate failure
            // boundary. Keep the TUI alive until the coordinator has accepted
            // the guardian's typed `Resumed` event and published that the new
            // gate is still closed; otherwise scheduler order can turn the
            // fixture into a different pre-resume early-exit case.
            wait_for_exact_marker("coordinator.resume-gate-held", b"held\n")?;
            write_marker("tui.pre-resume-gate-exit", b"exiting\n")?;
            return Ok(ExitCode::from(23));
        }
        if scenario == Scenario::PtySlaveCloseWhileLive && marker_exists("test.release-fault")? {
            write_marker("tui.slave-close", b"closed-while-live\n")?;
            return exec_detached_tui_without_slave();
        }
        if scenario == Scenario::PtyOutputBackpressure && marker_exists("test.release-output")? {
            write_marker("tui.output-started", b"started\n")?;
            return run_fixed_output_flood(&signal_flags, &mut signal_state, &mut stdout);
        }
        let timeout =
            rustix::event::Timespec::try_from(EVENT_POLL).map_err(|_| FixtureError::Deadline)?;
        let mut descriptors = [rustix::event::PollFd::new(
            &stdin,
            rustix::event::PollFlags::IN,
        )];
        match rustix::event::poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => continue,
            Ok(_)
                if descriptors[0]
                    .revents()
                    .contains(rustix::event::PollFlags::NVAL) =>
            {
                return Err(FixtureError::Process);
            }
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return Err(FixtureError::Process),
        }
        // `StdinLock` is buffered and may prefetch the rest of a PTY chunk.
        // Polling the raw descriptor after a one-byte buffered read would then
        // wait forever while the unread bytes live only in that user-space
        // buffer. The fake TUI is the sole stdin reader, so keep poll and read
        // on the same unbuffered descriptor.
        let read = match rustix::io::read(&stdin, &mut byte) {
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => continue,
            Err(_) => return Err(FixtureError::Process),
            Ok(read) => read,
        };
        if read == 0 {
            break;
        }
        if byte[0] == TUI_EXIT_BYTE {
            write_marker("tui.exit-byte", b"received\n")?;
            break;
        }
        stdout
            .write_all(&byte)
            .and_then(|()| stdout.flush())
            .map_err(|_| FixtureError::Process)?;
    }
    Ok(if scenario == Scenario::PtyExitNonzero {
        ExitCode::from(23)
    } else {
        ExitCode::SUCCESS
    })
}

fn spawn_tstp_heartbeat_descendant() -> Result<Child, FixtureError> {
    let expected_group = rustix::process::getpgrp();
    let mut command = Command::new(current_fixture_executable()?);
    command
        .arg("tstp-heartbeat-descendant")
        .env_clear()
        .env(MARKER_ROOT_ENV, marker_root()?)
        .env(
            HEARTBEAT_EXPECTED_GROUP_ENV,
            expected_group.as_raw_nonzero().get().to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command.spawn().map_err(|_| FixtureError::Process)?;
    let pid = rustix::process::Pid::from_child(&child);
    if rustix::process::getpgid(Some(pid)).map_err(|_| FixtureError::Process)? != expected_group {
        return Err(FixtureError::Invariant);
    }
    wait_for_exact_marker("tui.heartbeat-armed", b"armed\n")?;
    Ok(child)
}

/// Same-process-group synthetic descendant that deliberately handles TSTP
/// without stopping. A monotonically increasing, atomically replaced counter
/// lets the integration test prove that the guardian's mandatory SIGSTOP
/// sweep contains the complete group before `Suspended` is acknowledged.
pub(super) fn run_tstp_heartbeat_descendant() -> Result<ExitCode, FixtureError> {
    use signal_hook::consts::signal::SIGTSTP;

    let expected_group = env::var(HEARTBEAT_EXPECTED_GROUP_ENV)
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .and_then(rustix::process::Pid::from_raw)
        .ok_or(FixtureError::Environment)?;
    let process = rustix::process::getpid();
    if rustix::process::getpgrp() != expected_group
        || rustix::process::getpgid(Some(process)).map_err(|_| FixtureError::Process)?
            != expected_group
        || rustix::process::getsid(Some(process)).map_err(|_| FixtureError::Process)?
            != expected_group
    {
        return Err(FixtureError::Invariant);
    }

    let _ignored_tstp = SignalFlag::register(SIGTSTP)?;
    write_process_marker("descendant.pid", process.as_raw_pid())?;
    write_heartbeat(1)?;
    write_marker("tui.heartbeat-armed", b"armed\n")?;
    let mut heartbeat = 1_u64;
    loop {
        thread::sleep(Duration::from_millis(20));
        heartbeat = heartbeat.checked_add(1).ok_or(FixtureError::Invariant)?;
        write_heartbeat(heartbeat)?;
    }
}

fn write_heartbeat(value: u64) -> Result<(), FixtureError> {
    let temporary = marker_path("tui.heartbeat-next")?;
    let destination = marker_path("tui.heartbeat")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| FixtureError::Storage)?;
    file.write_all(&value.to_be_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| FixtureError::Storage)?;
    let metadata = file.metadata().map_err(|_| FixtureError::Storage)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != 8
    {
        return Err(FixtureError::Storage);
    }
    drop(file);
    fs::rename(temporary, destination).map_err(|_| FixtureError::Storage)
}

fn exec_detached_tui_without_slave() -> Result<ExitCode, FixtureError> {
    let mut command = Command::new(current_fixture_executable()?);
    command
        .arg("detached-tui")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _error = command.exec();
    Err(FixtureError::Process)
}

fn run_fixed_output_flood(
    signal_flags: &TuiSignalFlags,
    signal_state: &mut TuiSignalState,
    stdout: &mut io::StdoutLock<'_>,
) -> Result<ExitCode, FixtureError> {
    const OUTPUT_CHUNK: [u8; 4096] = [b'B'; 4096];
    let flags = rustix::fs::fcntl_getfl(&*stdout).map_err(|_| FixtureError::Descriptor)?;
    rustix::fs::fcntl_setfl(&*stdout, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|_| FixtureError::Descriptor)?;
    loop {
        signal_flags.observe(signal_state)?;
        match stdout.write(&OUTPUT_CHUNK) {
            Ok(0) => return Err(FixtureError::Process),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let timeout = rustix::event::Timespec::try_from(EVENT_POLL)
                    .map_err(|_| FixtureError::Deadline)?;
                let mut descriptors = [rustix::event::PollFd::new(
                    &*stdout,
                    rustix::event::PollFlags::OUT,
                )];
                match rustix::event::poll(&mut descriptors, Some(&timeout)) {
                    Ok(_) | Err(rustix::io::Errno::INTR) => {}
                    Err(_) => return Err(FixtureError::Process),
                }
            }
            Err(_) if signal_state.terminate_seen => {
                if !signal_state.output_channel_closed_seen {
                    signal_state.output_channel_closed_seen = true;
                    write_marker("tui.output-channel-closed", b"closed\n")?;
                }
                thread::sleep(EVENT_POLL);
            }
            Err(_) => return Err(FixtureError::Process),
        }
    }
}

#[derive(Default)]
struct TuiSignalState {
    interrupt_seen: bool,
    quit_seen: bool,
    resize_seen: bool,
    continue_seen: bool,
    tstp_seen: bool,
    terminate_seen: bool,
    hangup_seen: bool,
    output_channel_closed_seen: bool,
}

struct TuiSignalFlags {
    interrupt: Option<SignalFlag>,
    quit: Option<SignalFlag>,
    winch: Option<SignalFlag>,
    cont: Option<SignalFlag>,
    tstp: Option<SignalFlag>,
    terminate: Option<SignalFlag>,
    hangup: Option<SignalFlag>,
}

impl TuiSignalFlags {
    fn install(scenario: Scenario) -> Result<Self, FixtureError> {
        use signal_hook::consts::signal::{
            SIGCONT, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP, SIGWINCH,
        };

        let handles_interactive = scenario == Scenario::PtySignals;
        let handles_job_control = matches!(
            scenario,
            Scenario::PtySuspendResume
                | Scenario::PtyResumeFailure
                | Scenario::PtyTuiExitBeforeResumeGate
        );
        let ignores_terminate = scenario == Scenario::PtyOutputBackpressure;
        let flags = Self {
            interrupt: handles_interactive
                .then(|| SignalFlag::register(SIGINT))
                .transpose()?,
            quit: handles_interactive
                .then(|| SignalFlag::register(SIGQUIT))
                .transpose()?,
            winch: (handles_interactive || handles_job_control)
                .then(|| SignalFlag::register(SIGWINCH))
                .transpose()?,
            cont: handles_job_control
                .then(|| SignalFlag::register(SIGCONT))
                .transpose()?,
            tstp: handles_job_control
                .then(|| SignalFlag::register(SIGTSTP))
                .transpose()?,
            terminate: ignores_terminate
                .then(|| SignalFlag::register(SIGTERM))
                .transpose()?,
            hangup: ignores_terminate
                .then(|| SignalFlag::register(SIGHUP))
                .transpose()?,
        };
        if ignores_terminate {
            write_marker("tui.term-ignore-armed", b"armed\n")?;
        }
        Ok(flags)
    }

    fn observe(&self, state: &mut TuiSignalState) -> Result<(), FixtureError> {
        if !state.interrupt_seen && self.interrupt.as_ref().is_some_and(SignalFlag::take) {
            state.interrupt_seen = true;
            write_marker("tui.signal-int", b"handled\n")?;
        }
        if !state.quit_seen && self.quit.as_ref().is_some_and(SignalFlag::take) {
            state.quit_seen = true;
            write_marker("tui.signal-quit", b"handled\n")?;
        }
        if !state.resize_seen && self.winch.as_ref().is_some_and(SignalFlag::take) {
            state.resize_seen = true;
            write_size_marker("tui.resized")?;
        }
        if !state.tstp_seen && self.tstp.as_ref().is_some_and(SignalFlag::take) {
            state.tstp_seen = true;
            write_marker("tui.leader-self-stop", b"stopping\n")?;
            // The direct leader alone stops first. This makes the synthetic
            // regression distinguish the old leader-only observation from
            // the mandatory subsequent group-wide SIGSTOP sweep.
            rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::STOP)
                .map_err(|_| FixtureError::Process)?;
        }
        if !state.continue_seen && self.cont.as_ref().is_some_and(SignalFlag::take) {
            state.continue_seen = true;
            write_size_marker("tui.resumed")?;
        }
        if !state.terminate_seen && self.terminate.as_ref().is_some_and(SignalFlag::take) {
            state.terminate_seen = true;
            write_marker("tui.signal-term-ignored", b"ignored\n")?;
        }
        if !state.hangup_seen && self.hangup.as_ref().is_some_and(SignalFlag::take) {
            state.hangup_seen = true;
            write_marker("tui.signal-hup-ignored", b"ignored\n")?;
        }
        Ok(())
    }
}

fn write_size_marker(name: &str) -> Result<(), FixtureError> {
    let size = terminal_size(io::stdin()).map_err(|_| FixtureError::Process)?;
    write_terminal_size_marker(name, size)
}

fn wait_for_exact_marker(name: &str, expected: &[u8]) -> Result<(), FixtureError> {
    wait_for_exact_marker_until(name, expected, bounded_deadline(PHASE_TIMEOUT))
}

fn wait_for_exact_marker_until(
    name: &str,
    expected: &[u8],
    deadline: Instant,
) -> Result<(), FixtureError> {
    if expected.len() > 32 {
        return Err(FixtureError::Invariant);
    }
    loop {
        let path = marker_path(name)?;
        match fs::read(&path) {
            Ok(value) if value == expected => return Ok(()),
            Ok(_) if Instant::now() >= deadline => return Err(FixtureError::Storage),
            Ok(_) => thread::sleep(EVENT_POLL),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if Instant::now() >= deadline {
                    return Err(FixtureError::Deadline);
                }
                thread::sleep(EVENT_POLL);
            }
            Err(_) => return Err(FixtureError::Storage),
        }
    }
}

fn parse_positive_process_group(name: &str) -> Result<i32, FixtureError> {
    let value = env::var(name).map_err(|_| FixtureError::Environment)?;
    let value = value
        .parse::<i32>()
        .map_err(|_| FixtureError::Environment)?;
    if value <= 0 {
        return Err(FixtureError::Environment);
    }
    Ok(value)
}

struct TuiReadinessReceiver {
    stream: UnixStream,
    saw_token: bool,
}

fn tui_readiness_pair() -> Result<(TuiReadinessReceiver, UnixStream), FixtureError> {
    let (receiver, sender) = UnixStream::pair().map_err(|_| FixtureError::Channel)?;
    for stream in [&receiver, &sender] {
        let flags = rustix::io::fcntl_getfd(stream).map_err(|_| FixtureError::Descriptor)?;
        rustix::io::fcntl_setfd(stream, flags | rustix::io::FdFlags::CLOEXEC)
            .map_err(|_| FixtureError::Descriptor)?;
        if !rustix::io::fcntl_getfd(stream)
            .map_err(|_| FixtureError::Descriptor)?
            .contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(FixtureError::Descriptor);
        }
    }
    receiver
        .set_nonblocking(true)
        .map_err(|_| FixtureError::Channel)?;
    Ok((
        TuiReadinessReceiver {
            stream: receiver,
            saw_token: false,
        },
        sender,
    ))
}

impl TuiReadinessReceiver {
    fn descriptor_identity(
        &self,
    ) -> Result<calcifer_unix_child_fd::DescriptorIdentity, FixtureError> {
        descriptor_identity(self.stream.as_fd()).map_err(|_| FixtureError::Descriptor)
    }

    fn poll(&mut self) -> Result<Option<VerifiedTuiReadiness>, FixtureError> {
        let mut bytes = [0_u8; 2];
        match self.stream.read(&mut bytes) {
            Ok(0) if self.saw_token => Ok(Some(VerifiedTuiReadiness { _private: () })),
            Ok(0) => Err(FixtureError::Protocol),
            Ok(1) if !self.saw_token && bytes[0] == TUI_READINESS_TOKEN => {
                self.saw_token = true;
                Ok(None)
            }
            Ok(_) => Err(FixtureError::Protocol),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(_) => Err(FixtureError::Channel),
        }
    }
}

trait PumpIo: AsFd + Send + Sync + 'static {
    fn enable_nonblocking(&self) -> Result<(), FixtureError>;
    fn read_into<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, FixtureError>;
    fn try_write(&self, chunk: &mut TerminalChunk<'_>) -> Result<TerminalWrite, FixtureError>;
}

impl PumpIo for TerminalTty {
    fn enable_nonblocking(&self) -> Result<(), FixtureError> {
        TerminalTty::enable_nonblocking(self).map_err(|_| FixtureError::Process)
    }

    fn read_into<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, FixtureError> {
        TerminalTty::read_into(self, buffer).map_err(|_| FixtureError::Process)
    }

    fn try_write(&self, chunk: &mut TerminalChunk<'_>) -> Result<TerminalWrite, FixtureError> {
        TerminalTty::try_write(self, chunk).map_err(|_| FixtureError::Process)
    }
}

impl PumpIo for TerminalEndpoint {
    fn enable_nonblocking(&self) -> Result<(), FixtureError> {
        TerminalEndpoint::enable_nonblocking(self).map_err(|_| FixtureError::Channel)
    }

    fn read_into<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, FixtureError> {
        TerminalEndpoint::read_into(self, buffer).map_err(|_| FixtureError::Channel)
    }

    fn try_write(&self, chunk: &mut TerminalChunk<'_>) -> Result<TerminalWrite, FixtureError> {
        TerminalEndpoint::try_write(self, chunk).map_err(|_| FixtureError::Channel)
    }
}

impl PumpIo for PtyMaster {
    fn enable_nonblocking(&self) -> Result<(), FixtureError> {
        PtyMaster::enable_nonblocking(self).map_err(|_| FixtureError::Process)
    }

    fn read_into<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, FixtureError> {
        PtyMaster::read_into(self, buffer).map_err(|_| FixtureError::Process)
    }

    fn try_write(&self, chunk: &mut TerminalChunk<'_>) -> Result<TerminalWrite, FixtureError> {
        PtyMaster::try_write(self, chunk).map_err(|_| FixtureError::Process)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PumpExit {
    Stopped,
    LeftEof,
    RightEof,
    Failed,
}

#[derive(Clone, Copy)]
enum PumpDirection {
    LeftToRight,
    RightToLeft,
}

#[derive(Clone, Copy)]
enum PumpObservation {
    OuterOutputBackpressure,
}

impl PumpObservation {
    fn record(self) -> Result<(), FixtureError> {
        match self {
            Self::OuterOutputBackpressure => {
                write_marker("terminal.output-backpressure", b"observed\n")
            }
        }
    }
}

enum DirectionWorkerState {
    Dormant,
    Running(JoinHandle<PumpExit>),
    Paused,
    Finished(PumpExit),
}

struct DirectionWorker {
    stop: Arc<AtomicBool>,
    state: DirectionWorkerState,
}

impl DirectionWorker {
    fn dormant() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            state: DirectionWorkerState::Dormant,
        }
    }

    fn start(
        &mut self,
        restart: bool,
        spawn: impl FnOnce(Arc<AtomicBool>) -> Result<JoinHandle<PumpExit>, FixtureError>,
    ) -> Result<(), FixtureError> {
        let was_paused = matches!(&self.state, DirectionWorkerState::Paused);
        let allowed = if restart {
            was_paused
        } else {
            matches!(&self.state, DirectionWorkerState::Dormant)
        };
        if !allowed {
            return Err(FixtureError::Invariant);
        }

        self.stop.store(false, Ordering::Release);
        match spawn(Arc::clone(&self.stop)) {
            Ok(handle) => {
                self.state = DirectionWorkerState::Running(handle);
                Ok(())
            }
            Err(error) => {
                self.stop.store(was_paused, Ordering::Release);
                Err(error)
            }
        }
    }

    fn pause(&mut self) -> Result<(), FixtureError> {
        let handle = match &self.state {
            DirectionWorkerState::Running(handle) => handle,
            DirectionWorkerState::Dormant
            | DirectionWorkerState::Paused
            | DirectionWorkerState::Finished(_) => return Err(FixtureError::Invariant),
        };
        self.stop.store(true, Ordering::Release);
        let deadline = phase_deadline();
        while !handle.is_finished() && Instant::now() < deadline {
            thread::sleep(EVENT_POLL);
        }
        if !handle.is_finished() {
            return Err(FixtureError::Deadline);
        }

        let state = std::mem::replace(&mut self.state, DirectionWorkerState::Dormant);
        let DirectionWorkerState::Running(handle) = state else {
            return Err(FixtureError::Invariant);
        };
        let exit = handle.join().unwrap_or(PumpExit::Failed);
        if exit == PumpExit::Stopped {
            self.state = DirectionWorkerState::Paused;
            Ok(())
        } else {
            self.state = DirectionWorkerState::Finished(exit);
            Err(FixtureError::Worker)
        }
    }

    fn request_stop(&self) {
        if matches!(&self.state, DirectionWorkerState::Running(_)) {
            self.stop.store(true, Ordering::Release);
        }
    }

    fn observed_terminal_exit(&self) -> bool {
        match &self.state {
            DirectionWorkerState::Running(handle) => handle.is_finished(),
            DirectionWorkerState::Finished(exit) => *exit != PumpExit::Stopped,
            DirectionWorkerState::Dormant | DirectionWorkerState::Paused => false,
        }
    }

    fn thread_finished(&self) -> bool {
        match &self.state {
            DirectionWorkerState::Running(handle) => handle.is_finished(),
            DirectionWorkerState::Dormant
            | DirectionWorkerState::Paused
            | DirectionWorkerState::Finished(_) => true,
        }
    }

    fn quiesce(&mut self) -> Result<(), FixtureError> {
        match &self.state {
            DirectionWorkerState::Running(_) => self.pause(),
            DirectionWorkerState::Dormant
            | DirectionWorkerState::Paused
            | DirectionWorkerState::Finished(_) => Ok(()),
        }
    }

    fn join_after_stop(&mut self) -> Option<PumpExit> {
        let state = std::mem::replace(&mut self.state, DirectionWorkerState::Dormant);
        match state {
            DirectionWorkerState::Dormant => {
                self.state = DirectionWorkerState::Dormant;
                None
            }
            DirectionWorkerState::Paused => {
                self.state = DirectionWorkerState::Paused;
                Some(PumpExit::Stopped)
            }
            DirectionWorkerState::Finished(exit) => {
                self.state = DirectionWorkerState::Finished(exit);
                Some(exit)
            }
            DirectionWorkerState::Running(handle) => {
                let exit = handle.join().unwrap_or(PumpExit::Failed);
                self.state = DirectionWorkerState::Finished(exit);
                Some(exit)
            }
        }
    }
}

#[must_use = "a live terminal pump must be joined or retained"]
struct PumpCore<L: PumpIo, R: PumpIo> {
    left: Arc<L>,
    right: Arc<R>,
    left_to_right: DirectionWorker,
    right_to_left: DirectionWorker,
}

impl<L: PumpIo, R: PumpIo> PumpCore<L, R> {
    fn start_output(left: L, right: R) -> Result<Self, FixtureError> {
        left.enable_nonblocking()?;
        right.enable_nonblocking()?;
        let left = Arc::new(left);
        let right = Arc::new(right);
        let mut pump = Self {
            left,
            right,
            left_to_right: DirectionWorker::dormant(),
            right_to_left: DirectionWorker::dormant(),
        };
        pump.start_left_to_right(false)?;
        Ok(pump)
    }

    fn start_duplex(left: L, right: R) -> Result<Self, FixtureError> {
        let mut pump = Self::start_output(left, right)?;
        pump.start_input()?;
        Ok(pump)
    }

    fn start_input(&mut self) -> Result<(), FixtureError> {
        self.start_right_to_left(false, None)
    }

    fn start_input_with_observation(
        &mut self,
        observation: PumpObservation,
    ) -> Result<(), FixtureError> {
        self.start_right_to_left(false, Some(observation))
    }

    fn pause_left_to_right(&mut self) -> Result<(), FixtureError> {
        self.left_to_right.pause()
    }

    fn restart_left_to_right(&mut self) -> Result<(), FixtureError> {
        self.start_left_to_right(true)
    }

    fn pause_right_to_left(&mut self) -> Result<(), FixtureError> {
        self.right_to_left.pause()
    }

    fn restart_right_to_left(&mut self) -> Result<(), FixtureError> {
        self.start_right_to_left(true, None)
    }

    fn start_left_to_right(&mut self, restart: bool) -> Result<(), FixtureError> {
        let left = Arc::clone(&self.left);
        let right = Arc::clone(&self.right);
        self.left_to_right.start(restart, move |stop| {
            spawn_direction(
                left,
                right,
                stop,
                PumpDirection::LeftToRight,
                None,
                "calcifer-terminal-output",
            )
        })
    }

    fn start_right_to_left(
        &mut self,
        restart: bool,
        observation: Option<PumpObservation>,
    ) -> Result<(), FixtureError> {
        let left = Arc::clone(&self.left);
        let right = Arc::clone(&self.right);
        self.right_to_left.start(restart, move |stop| {
            spawn_direction(
                left,
                right,
                stop,
                PumpDirection::RightToLeft,
                observation,
                "calcifer-terminal-input",
            )
        })
    }

    fn is_finished(&self) -> bool {
        self.left_to_right.observed_terminal_exit() || self.right_to_left.observed_terminal_exit()
    }

    fn join_finished(mut self) -> Result<PumpExit, Self> {
        if !self.is_finished() {
            return Err(self);
        }
        self.request_stop();
        let deadline = phase_deadline();
        while !self.all_finished() && Instant::now() < deadline {
            thread::sleep(EVENT_POLL);
        }
        if !self.all_finished() {
            return Err(self);
        }
        Ok(self.join_all())
    }

    fn stop(mut self) -> Result<PumpExit, Self> {
        self.request_stop();
        let deadline = phase_deadline();
        while !self.all_finished() && Instant::now() < deadline {
            thread::sleep(EVENT_POLL);
        }
        if !self.all_finished() {
            return Err(self);
        }
        Ok(self.join_all())
    }

    fn request_stop(&self) {
        self.left_to_right.request_stop();
        self.right_to_left.request_stop();
    }

    fn all_finished(&self) -> bool {
        self.left_to_right.thread_finished() && self.right_to_left.thread_finished()
    }

    fn join_all(&mut self) -> PumpExit {
        let output = self
            .left_to_right
            .join_after_stop()
            .unwrap_or(PumpExit::Failed);
        let input = self.right_to_left.join_after_stop();
        combine_pump_exits(output, input)
    }
}

impl<L: PumpIo, R: PumpIo> Drop for PumpCore<L, R> {
    fn drop(&mut self) {
        self.request_stop();
        let deadline = phase_deadline();
        while !self.all_finished() && Instant::now() < deadline {
            thread::sleep(EVENT_POLL);
        }
        if !self.all_finished() {
            // Every authority-bearing caller must route a timed-out pump into
            // an explicit retained state. Reaching Drop with a live worker is
            // therefore an invariant breach; aborting is safer than either an
            // unbounded join or detaching a thread that still owns terminal
            // descriptors.
            std::process::abort();
        }
        let _ = self.left_to_right.join_after_stop();
        let _ = self.right_to_left.join_after_stop();
    }
}

fn combine_pump_exits(output: PumpExit, input: Option<PumpExit>) -> PumpExit {
    for exit in input.into_iter().chain(std::iter::once(output)) {
        if exit != PumpExit::Stopped {
            return exit;
        }
    }
    PumpExit::Stopped
}

fn spawn_direction<L: PumpIo, R: PumpIo>(
    left: Arc<L>,
    right: Arc<R>,
    stop: Arc<AtomicBool>,
    direction: PumpDirection,
    observation: Option<PumpObservation>,
    name: &str,
) -> Result<JoinHandle<PumpExit>, FixtureError> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || match direction {
            PumpDirection::LeftToRight => run_direction(
                left.as_ref(),
                right.as_ref(),
                &stop,
                PumpExit::LeftEof,
                observation,
            ),
            PumpDirection::RightToLeft => run_direction(
                right.as_ref(),
                left.as_ref(),
                &stop,
                PumpExit::RightEof,
                observation,
            ),
        })
        .map_err(|_| FixtureError::Worker)
}

fn run_direction<S: PumpIo, D: PumpIo>(
    source: &S,
    destination: &D,
    stop: &AtomicBool,
    eof: PumpExit,
    mut observation: Option<PumpObservation>,
) -> PumpExit {
    let mut buffer = TerminalBuffer::new();
    loop {
        if stop.load(Ordering::Acquire) {
            return PumpExit::Stopped;
        }
        let read = source.read_into(&mut buffer);
        let mut chunk = match read {
            Ok(TerminalRead::Data(chunk)) => chunk,
            Ok(TerminalRead::EndOfStream) => return eof,
            Ok(TerminalRead::WouldBlock) => {
                if poll_endpoint(source, rustix::event::PollFlags::IN).is_err() {
                    return PumpExit::Failed;
                }
                continue;
            }
            Err(_) => return PumpExit::Failed,
        };
        while chunk.remaining() != 0 {
            if stop.load(Ordering::Acquire) {
                return PumpExit::Stopped;
            }
            let write = destination.try_write(&mut chunk);
            match write {
                Ok(TerminalWrite::Complete) => break,
                Ok(TerminalWrite::Progress { .. }) => {}
                Ok(TerminalWrite::WouldBlock) => {
                    if let Some(observation) = observation.take() {
                        if observation.record().is_err() {
                            return PumpExit::Failed;
                        }
                    }
                    if poll_endpoint(destination, rustix::event::PollFlags::OUT).is_err() {
                        return PumpExit::Failed;
                    }
                }
                Err(_) => return PumpExit::Failed,
            }
        }
    }
}

fn poll_endpoint<T: PumpIo>(
    endpoint: &T,
    interest: rustix::event::PollFlags,
) -> Result<(), FixtureError> {
    let timeout =
        rustix::event::Timespec::try_from(EVENT_POLL).map_err(|_| FixtureError::Deadline)?;
    let mut descriptors = [rustix::event::PollFd::new(endpoint, interest)];
    match rustix::event::poll(&mut descriptors, Some(&timeout)) {
        Ok(_) => {
            let events = descriptors[0].revents();
            if events.contains(rustix::event::PollFlags::NVAL) {
                Err(FixtureError::Process)
            } else {
                Ok(())
            }
        }
        Err(rustix::io::Errno::INTR) => Ok(()),
        Err(_) => Err(FixtureError::Process),
    }
}

struct CoordinatorPump(PumpCore<TerminalTty, TerminalEndpoint>);

impl CoordinatorPump {
    fn start(
        _gate: InputGate<GateOpen>,
        terminal: TerminalEndpoint,
        scenario: Scenario,
    ) -> Result<Self, FixtureError> {
        let tty =
            TerminalTty::open_independent(io::stdin()).map_err(|_| FixtureError::Descriptor)?;
        let mut pump = PumpCore::start_output(tty, terminal)?;
        if scenario == Scenario::PtyOutputBackpressure {
            pump.start_input_with_observation(PumpObservation::OuterOutputBackpressure)?;
        } else {
            pump.start_input()?;
        }
        Ok(Self(pump))
    }

    fn stop(self) -> Result<PumpExit, Self> {
        self.0.stop().map_err(Self)
    }

    fn quiesce_input_for_restore(&mut self) -> Result<(), FixtureError> {
        self.0.left_to_right.quiesce()
    }

    fn shutdown_terminal_channel(&self) -> Result<(), FixtureError> {
        self.0
            .right
            .shutdown(TerminalShutdown::Both)
            .map_err(|_| FixtureError::Channel)
    }

    /// Quiesces outer-terminal ingress while terminal output remains live.
    fn pause_input(&mut self) -> Result<(), FixtureError> {
        self.0.pause_left_to_right()
    }

    /// Restarts outer-terminal ingress only after the caller supplies a fresh
    /// private open-gate capability.
    fn restart_input(&mut self, _gate: InputGate<GateOpen>) -> Result<(), FixtureError> {
        self.0.restart_left_to_right()
    }

    fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
}

struct GuardianOutputPump(PumpCore<PtyMaster, TerminalEndpoint>);
struct GuardianReadyPump(PumpCore<PtyMaster, TerminalEndpoint>);
struct GuardianDuplexPump(PumpCore<PtyMaster, TerminalEndpoint>);

trait GuardianGateWaitPump {
    fn gate_wait_finished(&self) -> bool;
}

enum GuardianPumpState {
    Output(GuardianOutputPump),
    Ready(GuardianReadyPump),
    Duplex(GuardianDuplexPump),
}

struct VerifiedTuiReadiness {
    _private: (),
}

struct GuardianOpenGate {
    _private: (),
}

impl GuardianOutputPump {
    fn start(master: PtyMaster, terminal: TerminalEndpoint) -> Result<Self, FixtureError> {
        PumpCore::start_output(master, terminal).map(Self)
    }

    fn mark_ready(self, _readiness: VerifiedTuiReadiness) -> GuardianReadyPump {
        GuardianReadyPump(self.0)
    }

    fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    fn stop(self) -> Result<PumpExit, Self> {
        self.0.stop().map_err(Self)
    }
}

impl GuardianReadyPump {
    fn open_input(mut self, _gate: GuardianOpenGate) -> Result<GuardianDuplexPump, Self> {
        if self.0.start_input().is_err() {
            return Err(self);
        }
        Ok(GuardianDuplexPump(self.0))
    }

    fn stop(self) -> Result<PumpExit, Self> {
        self.0.stop().map_err(Self)
    }
}

impl GuardianGateWaitPump for GuardianReadyPump {
    fn gate_wait_finished(&self) -> bool {
        self.0.is_finished()
    }
}

impl GuardianDuplexPump {
    fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    fn join_finished(self) -> Result<PumpExit, Self> {
        self.0.join_finished().map_err(Self)
    }

    fn set_pty_size(&self, size: TerminalSize) -> Result<(), FixtureError> {
        self.0
            .left
            .set_size(size)
            .map_err(|_| FixtureError::Process)
    }

    /// Quiesces terminal-channel ingress into the PTY while PTY output stays
    /// live on the independent left-to-right worker.
    fn pause_input(&mut self) -> Result<(), FixtureError> {
        self.0.pause_right_to_left()
    }

    /// Discards every byte already queued before the lifecycle suspend
    /// barrier. The sole terminal reader is joined before this call, so
    /// reaching `WouldBlock` proves a fresh resume gate cannot replay stale
    /// socket ingress.
    fn discard_pending_input(&mut self) -> Result<(), FixtureError> {
        let mut buffer = TerminalBuffer::new();
        loop {
            let read = self
                .0
                .right
                .read_into(&mut buffer)
                .map_err(|_| FixtureError::Channel)?;
            match read {
                TerminalRead::Data(chunk) => drop(chunk),
                TerminalRead::WouldBlock => return Ok(()),
                TerminalRead::EndOfStream => return Err(FixtureError::Channel),
            }
        }
    }

    /// Restarts PTY ingress only after the caller supplies a fresh private
    /// guardian gate capability.
    fn restart_input(&mut self, _gate: GuardianOpenGate) -> Result<(), FixtureError> {
        self.0.restart_right_to_left()
    }

    fn stop(self) -> Result<PumpExit, Self> {
        self.0.stop().map_err(Self)
    }

    fn shutdown_terminal_channel(&self) -> Result<(), FixtureError> {
        self.0
            .right
            .shutdown(TerminalShutdown::Both)
            .map_err(|_| FixtureError::Channel)
    }
}

impl GuardianGateWaitPump for GuardianDuplexPump {
    fn gate_wait_finished(&self) -> bool {
        self.0.is_finished()
    }
}

impl GuardianPumpState {
    fn stop(self) -> Result<PumpExit, Self> {
        match self {
            Self::Output(pump) => pump.stop().map_err(Self::Output),
            Self::Ready(pump) => pump.stop().map_err(Self::Ready),
            Self::Duplex(pump) => pump.stop().map_err(Self::Duplex),
        }
    }

    fn shutdown_terminal_channel(&self) -> Result<(), FixtureError> {
        let endpoint = match self {
            Self::Output(pump) => &pump.0.right,
            Self::Ready(pump) => &pump.0.right,
            Self::Duplex(pump) => &pump.0.right,
        };
        endpoint
            .shutdown(TerminalShutdown::Both)
            .map_err(|_| FixtureError::Channel)
    }
}

#[cfg(test)]
mod signal_flag_tests {
    use super::*;

    #[test]
    fn bounded_wait_accepts_a_continue_flag_published_after_the_thread_resumes()
    -> Result<(), Box<dyn std::error::Error>> {
        let pending = Arc::new(AtomicBool::new(false));
        let flag = SignalFlag {
            pending: Arc::clone(&pending),
            registration: None,
        };
        assert!(!flag.take());

        let publisher = thread::spawn(move || {
            thread::sleep(Duration::from_millis(25));
            pending.store(true, Ordering::Release);
        });
        assert!(flag.wait_until(Instant::now() + Duration::from_millis(250)));
        publisher
            .join()
            .map_err(|_| io::Error::other("signal flag publisher panicked"))?;
        assert!(!flag.take());
        Ok(())
    }
}

#[cfg(test)]
mod pump_tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicU64;

    static NEXT_MARKER_TEST: AtomicU64 = AtomicU64::new(0);

    fn duplex_endpoint_pump() -> Result<
        (
            PumpCore<TerminalEndpoint, TerminalEndpoint>,
            TerminalEndpoint,
            TerminalEndpoint,
        ),
        FixtureError,
    > {
        let (left, left_peer) = TerminalChannelPair::new()
            .map_err(|_| FixtureError::Channel)?
            .split();
        let (right, right_peer) = TerminalChannelPair::new()
            .map_err(|_| FixtureError::Channel)?
            .split();
        Ok((PumpCore::start_duplex(left, right)?, left_peer, right_peer))
    }

    fn write_test_byte(endpoint: &TerminalEndpoint, byte: u8) -> Result<(), FixtureError> {
        endpoint
            .enable_nonblocking()
            .map_err(|_| FixtureError::Channel)?;
        let mut buffer = TerminalBuffer::new();
        let mut chunk = buffer.load(&[byte]).map_err(|_| FixtureError::Channel)?;
        let deadline = phase_deadline();
        while chunk.remaining() != 0 {
            match endpoint
                .try_write(&mut chunk)
                .map_err(|_| FixtureError::Channel)?
            {
                TerminalWrite::Complete => break,
                TerminalWrite::Progress { .. } => {}
                TerminalWrite::WouldBlock if Instant::now() < deadline => {
                    thread::sleep(EVENT_POLL);
                }
                TerminalWrite::WouldBlock => return Err(FixtureError::Deadline),
            }
        }
        Ok(())
    }

    fn wait_for_test_byte(endpoint: &TerminalEndpoint, expected: u8) -> Result<(), FixtureError> {
        endpoint
            .enable_nonblocking()
            .map_err(|_| FixtureError::Channel)?;
        let deadline = phase_deadline();
        loop {
            let mut buffer = TerminalBuffer::new();
            match endpoint
                .read_into(&mut buffer)
                .map_err(|_| FixtureError::Channel)?
            {
                TerminalRead::Data(chunk) if chunk.matches(&[expected]) => return Ok(()),
                TerminalRead::Data(_) | TerminalRead::EndOfStream => {
                    return Err(FixtureError::Invariant);
                }
                TerminalRead::WouldBlock if Instant::now() < deadline => {
                    thread::sleep(EVENT_POLL);
                }
                TerminalRead::WouldBlock => return Err(FixtureError::Deadline),
            }
        }
    }

    fn assert_test_endpoint_empty(endpoint: &TerminalEndpoint) -> Result<(), FixtureError> {
        endpoint
            .enable_nonblocking()
            .map_err(|_| FixtureError::Channel)?;
        let mut buffer = TerminalBuffer::new();
        match endpoint
            .read_into(&mut buffer)
            .map_err(|_| FixtureError::Channel)?
        {
            TerminalRead::WouldBlock => Ok(()),
            TerminalRead::Data(_) | TerminalRead::EndOfStream => Err(FixtureError::Invariant),
        }
    }

    fn wait_for_test_eof(endpoint: &TerminalEndpoint) -> Result<(), FixtureError> {
        endpoint
            .enable_nonblocking()
            .map_err(|_| FixtureError::Channel)?;
        let deadline = phase_deadline();
        loop {
            let mut buffer = TerminalBuffer::new();
            match endpoint
                .read_into(&mut buffer)
                .map_err(|_| FixtureError::Channel)?
            {
                TerminalRead::EndOfStream => return Ok(()),
                TerminalRead::Data(_) => return Err(FixtureError::Invariant),
                TerminalRead::WouldBlock if Instant::now() < deadline => {
                    thread::sleep(EVENT_POLL);
                }
                TerminalRead::WouldBlock => return Err(FixtureError::Deadline),
            }
        }
    }

    #[test]
    fn left_to_right_can_pause_and_restart_while_right_to_left_stays_live()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut pump, left_peer, right_peer) = duplex_endpoint_pump()?;
        pump.pause_left_to_right()?;

        write_test_byte(&right_peer, 0x41)?;
        wait_for_test_byte(&left_peer, 0x41)?;
        write_test_byte(&left_peer, 0x42)?;
        assert_test_endpoint_empty(&right_peer)?;

        pump.restart_left_to_right()?;
        wait_for_test_byte(&right_peer, 0x42)?;
        assert_eq!(
            pump.stop().map_err(|_| FixtureError::Worker)?,
            PumpExit::Stopped
        );
        Ok(())
    }

    #[test]
    fn right_to_left_can_pause_and_restart_while_left_to_right_stays_live()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut pump, left_peer, right_peer) = duplex_endpoint_pump()?;
        pump.pause_right_to_left()?;

        write_test_byte(&left_peer, 0x43)?;
        wait_for_test_byte(&right_peer, 0x43)?;
        write_test_byte(&right_peer, 0x44)?;
        assert_test_endpoint_empty(&left_peer)?;

        pump.restart_right_to_left()?;
        wait_for_test_byte(&left_peer, 0x44)?;
        assert_eq!(
            pump.stop().map_err(|_| FixtureError::Worker)?,
            PumpExit::Stopped
        );
        Ok(())
    }

    #[test]
    fn dropping_duplex_pump_joins_workers_and_releases_both_endpoints()
    -> Result<(), Box<dyn std::error::Error>> {
        let (pump, left_peer, right_peer) = duplex_endpoint_pump()?;

        drop(pump);

        wait_for_test_eof(&left_peer)?;
        wait_for_test_eof(&right_peer)?;
        Ok(())
    }

    #[test]
    fn concurrent_restore_marker_writers_accept_one_exact_proof()
    -> Result<(), Box<dyn std::error::Error>> {
        let sequence = NEXT_MARKER_TEST.fetch_add(1, Ordering::Relaxed);
        let directory = env::temp_dir().join(format!(
            "calcifer-restored-marker-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory)?;
        let path = Arc::new(directory.join("terminal.restored"));
        let barrier = Arc::new(Barrier::new(2));
        let mut writers = Vec::with_capacity(2);
        for _ in 0..2 {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            writers.push(thread::spawn(move || {
                barrier.wait();
                write_exact_idempotent_marker(&path, b"restored\n", phase_deadline())
            }));
        }
        for writer in writers {
            writer
                .join()
                .map_err(|_| io::Error::other("restore marker writer panicked"))?
                .map_err(|_| io::Error::other("restore marker writer rejected exact proof"))?;
        }
        assert_eq!(fs::read(path.as_ref())?, b"restored\n");
        fs::remove_file(path.as_ref())?;
        fs::remove_dir(directory)?;
        Ok(())
    }
}

fn restore_outer_terminal(snapshot: &TerminalSnapshot) -> Result<(), FixtureError> {
    if restore_snapshot_with_sigttou_block(snapshot, io::stdin()).is_err() {
        return Err(FixtureError::Process);
    }
    // Normal and guardian fallback recovery deliberately target the same
    // immutable snapshot. Their externally visible proof must therefore be
    // idempotent as well: an exact existing marker is success, while any
    // other payload remains a hard storage failure.
    write_restored_marker_idempotent()?;
    write_exact_idempotent_marker(
        &marker_path("coordinator.terminal-restored")?,
        b"restored\n",
        phase_deadline(),
    )
}

fn reject_mismatched_outer_terminal_restore(
    snapshot: &TerminalSnapshot,
) -> Result<(), FixtureError> {
    let guard = calcifer_unix_child_fd::block_sigttou_for_current_thread()
        .map_err(|_| FixtureError::Process)?;
    let result = snapshot.restore_with_identity_mismatch_for_fixture(io::stdin());
    drop(guard);
    if result.is_ok() {
        return Err(FixtureError::Invariant);
    }
    write_marker("coordinator.restore-identity-mismatch", b"rejected\n")?;
    Err(FixtureError::Process)
}

enum GuardedRestoreError {
    SignalMask,
    Terminal(TerminalError),
}

fn restore_snapshot_with_sigttou_block<Fd: AsFd>(
    snapshot: &TerminalSnapshot,
    descriptor: Fd,
) -> Result<(), GuardedRestoreError> {
    let guard = calcifer_unix_child_fd::block_sigttou_for_current_thread()
        .map_err(|_| GuardedRestoreError::SignalMask)?;
    let restored = snapshot.restore(descriptor);
    // `SigttouBlockGuard` aborts on an impossible same-thread mask-restore
    // failure. No restored proof or marker can cross that boundary.
    drop(guard);
    restored
        .map(|_proof| ())
        .map_err(GuardedRestoreError::Terminal)
}

impl GuardedRestoreError {
    const fn code(&self) -> &'static str {
        match self {
            Self::SignalMask => "signal_mask",
            Self::Terminal(error) => error.code(),
        }
    }
}

enum CoordinatorControlOutcome {
    Continue,
    BeginShutdown,
    Quiesced,
    FailedAwaitQuiescence,
}

fn handle_coordinator_control(
    action: TerminalSignalAction,
    receiver: &mut CoordinatorReceiver<&LifecycleEndpoint>,
    lifecycle: &LifecycleEndpoint,
) -> Result<CoordinatorControlOutcome, FixtureError> {
    match action {
        TerminalSignalAction::Forward(signal) => {
            let command = CoordinatorCommand::Signal { signal };
            receiver
                .record_command(command)
                .map_err(|_| FixtureError::Protocol)?;
            send_coordinator_command(&mut &*lifecycle, command, phase_deadline())
                .map_err(|_| FixtureError::Channel)?;
            let response = receiver
                .receive(phase_deadline())
                .map_err(|_| FixtureError::Protocol)?;
            match response {
                GuardianEvent::SignalForwarded { signal: forwarded } if forwarded == signal => {}
                GuardianEvent::TerminalQuiesced
                    if matches!(signal, UnixSignal::Int | UnixSignal::Quit) =>
                {
                    return Ok(CoordinatorControlOutcome::Quiesced);
                }
                GuardianEvent::Failed { .. }
                    if matches!(signal, UnixSignal::Int | UnixSignal::Quit) =>
                {
                    return Ok(CoordinatorControlOutcome::FailedAwaitQuiescence);
                }
                _ => return Err(FixtureError::Protocol),
            }
            let marker = match signal {
                UnixSignal::Hup => "coordinator.signal-hup",
                UnixSignal::Int => "coordinator.signal-int",
                UnixSignal::Quit => "coordinator.signal-quit",
                UnixSignal::Term => "coordinator.signal-term",
            };
            write_marker(marker, b"forwarded\n")?;
            Ok(if matches!(signal, UnixSignal::Hup | UnixSignal::Term) {
                CoordinatorControlOutcome::BeginShutdown
            } else {
                CoordinatorControlOutcome::Continue
            })
        }
        TerminalSignalAction::Resize => {
            let size = terminal_size(io::stdin()).map_err(|_| FixtureError::Process)?;
            if size.rows() == 0 || size.columns() == 0 {
                return Err(FixtureError::Invariant);
            }
            let command = CoordinatorCommand::Resize {
                rows: size.rows(),
                cols: size.columns(),
            };
            receiver
                .record_command(command)
                .map_err(|_| FixtureError::Protocol)?;
            send_coordinator_command(&mut &*lifecycle, command, phase_deadline())
                .map_err(|_| FixtureError::Channel)?;
            let response = receiver
                .receive(phase_deadline())
                .map_err(|_| FixtureError::Protocol)?;
            match response {
                GuardianEvent::ResizeApplied { rows, cols }
                    if rows == size.rows() && cols == size.columns() => {}
                GuardianEvent::TerminalQuiesced => {
                    return Ok(CoordinatorControlOutcome::Quiesced);
                }
                GuardianEvent::Failed { .. } => {
                    return Ok(CoordinatorControlOutcome::FailedAwaitQuiescence);
                }
                _ => return Err(FixtureError::Protocol),
            }
            write_terminal_size_marker_idempotent("coordinator.resize", size)?;
            Ok(CoordinatorControlOutcome::Continue)
        }
        TerminalSignalAction::Suspend | TerminalSignalAction::Continue => {
            Err(FixtureError::Invariant)
        }
    }
}

fn suspend_and_resume_coordinator(
    flags: &TerminalSignalFlags,
    pump: &mut CoordinatorPump,
    snapshot: &TerminalSnapshot,
    receiver: &mut CoordinatorReceiver<&LifecycleEndpoint>,
    lifecycle: &LifecycleEndpoint,
    scenario: Scenario,
) -> Result<CoordinatorControlOutcome, FixtureError> {
    pump.pause_input()?;

    receiver
        .record_command(CoordinatorCommand::Suspend)
        .map_err(|_| FixtureError::Protocol)?;
    send_coordinator_command(
        &mut &*lifecycle,
        CoordinatorCommand::Suspend,
        phase_deadline(),
    )
    .map_err(|_| FixtureError::Channel)?;
    if receiver
        .receive(phase_deadline())
        .map_err(|_| FixtureError::Protocol)?
        != GuardianEvent::Suspended
    {
        return Err(FixtureError::Protocol);
    }

    restore_snapshot_with_sigttou_block(snapshot, io::stdin())
        .map_err(|_| FixtureError::Process)?;
    write_marker("terminal.suspended-restored", b"restored\n")?;
    flags.clear_continue();
    signal_hook::low_level::emulate_default_handler(signal_hook::consts::signal::SIGTSTP)
        .map_err(|_| FixtureError::Process)?;

    // Returning from the default stop handler proves that the process was
    // continued, but the SIGCONT flag handler may run a few scheduler turns
    // later. Wait for its bounded typed proof instead of sampling once and
    // misclassifying a valid resume as an invariant failure.
    if !flags.wait_for_continue(phase_deadline()) {
        return Err(FixtureError::Invariant);
    }
    if rustix::termios::tcgetpgrp(io::stdin()).map_err(|_| FixtureError::Process)?
        != rustix::process::getpgrp()
    {
        return Err(FixtureError::Invariant);
    }

    let raw = snapshot
        .enter_raw_after_input_flush(io::stdin())
        .map_err(|_| FixtureError::Process)?;
    let size = terminal_size(io::stdin()).map_err(|_| FixtureError::Process)?;
    if size.rows() == 0 || size.columns() == 0 {
        return Err(FixtureError::Invariant);
    }
    let resume = CoordinatorCommand::Resume {
        rows: size.rows(),
        cols: size.columns(),
    };
    receiver
        .record_command(resume)
        .map_err(|_| FixtureError::Protocol)?;
    send_coordinator_command(&mut &*lifecycle, resume, phase_deadline())
        .map_err(|_| FixtureError::Channel)?;
    match receiver
        .receive(phase_deadline())
        .map_err(|_| FixtureError::Protocol)?
    {
        GuardianEvent::Resumed { rows, cols } if rows == size.rows() && cols == size.columns() => {}
        GuardianEvent::Failed { .. } => {
            // `Failed` is a valid transition from AwaitResumed. Keep the fresh
            // input gate closed and let the normal terminal-quiescence path
            // perform exact cleanup instead of retaining the coordinator as a
            // false protocol-invariant failure.
            write_marker("coordinator.resume-failed-accepted", b"accepted\n")?;
            drop(raw);
            return Ok(CoordinatorControlOutcome::FailedAwaitQuiescence);
        }
        _ => return Err(FixtureError::Protocol),
    }
    let readiness = receiver
        .take_verified_ready()
        .map_err(|_| FixtureError::Protocol)?;
    let gate = InputGate::closed().mark_ready(readiness);

    if scenario == Scenario::PtyTuiExitBeforeResumeGate {
        write_marker("coordinator.resume-gate-held", b"held\n")?;
        wait_for_exact_marker("guardian.pre-resume-gate-failure", b"observed\n")?;
        receiver
            .record_command(CoordinatorCommand::OpenInputGate)
            .map_err(|_| FixtureError::Protocol)?;
        send_coordinator_command(
            &mut &*lifecycle,
            CoordinatorCommand::OpenInputGate,
            phase_deadline(),
        )
        .map_err(|_| FixtureError::Channel)?;
        let event = receiver
            .receive(bounded_deadline(PHASE_TIMEOUT.saturating_mul(2)))
            .map_err(|_| FixtureError::Protocol)?;
        if event
            != (GuardianEvent::Failed {
                phase: Phase::Readiness,
                code: FailureCode::EarlyExit,
            })
        {
            return Err(FixtureError::Protocol);
        }
        drop(gate);
        drop(raw);
        return Ok(CoordinatorControlOutcome::FailedAwaitQuiescence);
    }

    receiver
        .record_command(CoordinatorCommand::OpenInputGate)
        .map_err(|_| FixtureError::Protocol)?;
    send_coordinator_command(
        &mut &*lifecycle,
        CoordinatorCommand::OpenInputGate,
        phase_deadline(),
    )
    .map_err(|_| FixtureError::Channel)?;
    if receiver
        .receive(phase_deadline())
        .map_err(|_| FixtureError::Protocol)?
        != GuardianEvent::InputGateOpened
    {
        return Err(FixtureError::Protocol);
    }
    let acknowledgement = receiver
        .take_verified_open_gate_ack()
        .map_err(|_| FixtureError::Protocol)?;
    let gate = gate.acknowledge_open(raw, acknowledgement);
    pump.restart_input(gate)?;
    write_marker("gate.reopened", b"open\n")?;
    Ok(CoordinatorControlOutcome::Continue)
}

fn write_terminal_size_marker(name: &str, size: TerminalSize) -> Result<(), FixtureError> {
    let encoded = format!("{}x{}\n", size.rows(), size.columns());
    write_marker(name, encoded.as_bytes())
}

fn write_terminal_size_marker_idempotent(
    name: &str,
    size: TerminalSize,
) -> Result<(), FixtureError> {
    let encoded = format!("{}x{}\n", size.rows(), size.columns());
    let path = marker_path(name)?;
    match fs::read(path) {
        Ok(value) if value == encoded.as_bytes() => Ok(()),
        Ok(_) => Err(FixtureError::Storage),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            write_marker(name, encoded.as_bytes())
        }
        Err(_) => Err(FixtureError::Storage),
    }
}

fn lifecycle_readable(
    endpoint: &LifecycleEndpoint,
    timeout: Duration,
) -> Result<bool, FixtureError> {
    let timeout = rustix::event::Timespec::try_from(timeout).map_err(|_| FixtureError::Deadline)?;
    let mut descriptors = [rustix::event::PollFd::new(
        endpoint,
        rustix::event::PollFlags::IN,
    )];
    match rustix::event::poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Ok(false),
        Ok(_) => {
            let events = descriptors[0].revents();
            if events.contains(rustix::event::PollFlags::NVAL) {
                Err(FixtureError::Channel)
            } else {
                Ok(events.intersects(
                    rustix::event::PollFlags::IN
                        | rustix::event::PollFlags::HUP
                        | rustix::event::PollFlags::ERR,
                ))
            }
        }
        Err(rustix::io::Errno::INTR) => Ok(false),
        Err(_) => Err(FixtureError::Channel),
    }
}

struct RetainedTerminalCoordinatorState {
    authority: RetainedCoordinatorLease,
    guardian: Option<Child>,
    guardian_status: Option<ExitStatus>,
    lifecycle: LifecycleEndpoint,
    transfer: TransferChannelPair,
    snapshot: TerminalSnapshot,
    pump: Option<CoordinatorPump>,
}

impl RetainedTerminalCoordinatorState {
    /// Polls and reaps the exact direct guardian without ever signaling it.
    ///
    /// Retention is an authority state, not permission to leave a naturally
    /// exited direct child as a zombie. Keeping the cached status lets the
    /// cleanup-resolution branch prove the same exit contract after the reap.
    fn poll_guardian_exit(&mut self) {
        if self.guardian_status.is_some() {
            return;
        }
        let Some(guardian) = self.guardian.as_mut() else {
            return;
        };
        if let Ok(Some(status)) = guardian.try_wait() {
            self.guardian_status = Some(status);
            self.guardian = None;
            let _ = write_marker("coordinator.retained-guardian-reaped", b"exact\n");
        }
    }

    fn park(mut self) -> ! {
        let _ = (
            &self.authority,
            self.guardian.as_ref().map(Child::id),
            self.lifecycle.as_fd(),
            &self.transfer,
            self.snapshot.descriptor_identity(),
            self.pump.is_some(),
        );
        let _ = write_fixture_stdout(b"RETAINED\n");
        let _ = write_marker("coordinator.retained", b"retained\n");
        let _ = write_marker(
            "coordinator.retention-reason",
            self.authority.reason().code().as_bytes(),
        );
        loop {
            self.poll_guardian_exit();
            if cleanup_resolution_requested()
                && matches!(
                    self.guardian_status,
                    Some(status) if status.code() == Some(i32::from(EXIT_FAILURE))
                )
                && write_marker("coordinator.cleanup-resolved", b"exact-child-reaped\n").is_ok()
            {
                let Self {
                    authority,
                    guardian,
                    guardian_status: _,
                    lifecycle,
                    transfer,
                    snapshot,
                    pump,
                } = self;
                drop(pump);
                drop(lifecycle);
                drop(guardian);
                drop(transfer);
                drop(authority);
                let _ = snapshot;
                std::process::exit(i32::from(EXIT_FAILURE));
            }
            thread::sleep(EVENT_POLL);
        }
    }
}

fn cleanup_resolution_requested() -> bool {
    let Ok(path) = marker_path("test.resolve-cleanup") else {
        return false;
    };
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return false;
    };
    metadata.file_type().is_file()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o600
        && metadata.nlink() == 1
        && metadata.len() == b"release\n".len() as u64
        && fs::read(path).is_ok_and(|value| value == b"release\n")
}

#[allow(clippy::too_many_arguments)]
fn park_retained_terminal_coordinator(
    coordinator_lease: CoordinatorProfileLease,
    guardian: Child,
    lifecycle: LifecycleEndpoint,
    transfer: TransferChannelPair,
    snapshot: TerminalSnapshot,
    pump: Option<CoordinatorPump>,
    reason: RetentionReason,
) -> ! {
    RetainedTerminalCoordinatorState {
        authority: RetainedCoordinatorLease::new(coordinator_lease, reason),
        guardian: Some(guardian),
        guardian_status: None,
        lifecycle,
        transfer,
        snapshot,
        pump,
    }
    .park()
}

#[allow(clippy::too_many_arguments)]
fn park_retained_terminal_coordinator_without_signal(
    coordinator_lease: CoordinatorProfileLease,
    guardian: Child,
    lifecycle: LifecycleEndpoint,
    transfer: TransferChannelPair,
    snapshot: TerminalSnapshot,
    pump: Option<CoordinatorPump>,
    reason: RetentionReason,
) -> ! {
    // The retained-state poll loop reaps this exact direct child if it exits,
    // but never signals a live guardian after terminal recovery. The guardian
    // may be deliberately retaining provider/runtime authority for an
    // unresolved post-quiescence failure.
    park_retained_terminal_coordinator(
        coordinator_lease,
        guardian,
        lifecycle,
        transfer,
        snapshot,
        pump,
        reason,
    )
}

#[allow(clippy::too_many_arguments)]
fn restore_and_retain(
    coordinator_lease: CoordinatorProfileLease,
    guardian: Child,
    lifecycle: LifecycleEndpoint,
    transfer: TransferChannelPair,
    snapshot: TerminalSnapshot,
    pump: Option<CoordinatorPump>,
    reason: RetentionReason,
) -> ! {
    let mut retained_pump = None;
    if let Some(mut pump) = pump {
        if pump.quiesce_input_for_restore().is_err() {
            let reason = reason.after_unconfirmed_input_quiescence();
            let _ = pump.shutdown_terminal_channel();
            let _ = lifecycle.shutdown();
            retained_pump = pump.stop().err();
            // Restore remains mandatory even though the missing input
            // quiescence proof forces invariant-unconfirmed retention.
            let _ = restore_outer_terminal(&snapshot);
            park_retained_terminal_coordinator(
                coordinator_lease,
                guardian,
                lifecycle,
                transfer,
                snapshot,
                retained_pump,
                reason,
            )
        }
        let _ = pump.shutdown_terminal_channel();
        if let Err(pump) = pump.stop() {
            retained_pump = Some(pump);
        }
    }
    let restore_result = restore_outer_terminal(&snapshot);
    let reason = if restore_result.is_ok() {
        reason
    } else {
        RetentionReason::InvariantUnconfirmed
    };
    if restore_result.is_err() || retained_pump.is_some() {
        let _ = lifecycle.shutdown();
        let mut guardian = guardian;
        if restore_result.is_ok() {
            let _ = guardian.kill();
            let _ = wait_exact_child(&mut guardian, phase_deadline());
        }
        park_retained_terminal_coordinator(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            retained_pump,
            reason,
        )
    }
    retain_after_guardian_loss(coordinator_lease, guardian, lifecycle, transfer, reason)
}

#[allow(clippy::too_many_arguments)]
enum PreRawRejection {
    SnapshotMismatch,
    ProtocolInvalid,
}

#[derive(Clone, Copy)]
enum PostArmAckFailure {
    Timeout,
    Disconnect,
}

#[allow(clippy::too_many_arguments)]
fn reject_pre_raw_handshake(
    coordinator_lease: CoordinatorProfileLease,
    mut guardian: Child,
    lifecycle: LifecycleEndpoint,
    transfer: TransferChannelPair,
    snapshot: TerminalSnapshot,
    rejection: PreRawRejection,
) -> Result<ExitCode, FixtureError> {
    let _ = lifecycle.shutdown();
    if wait_exact_child(&mut guardian, phase_deadline()).is_err() {
        let _ = guardian.kill();
        if wait_exact_child(&mut guardian, phase_deadline()).is_err() {
            restore_and_retain(
                coordinator_lease,
                guardian,
                lifecycle,
                transfer,
                snapshot,
                None,
                RetentionReason::InvariantUnconfirmed,
            )
        }
    }
    if restore_outer_terminal(&snapshot).is_err() {
        park_retained_terminal_coordinator_without_signal(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            None,
            RetentionReason::InvariantUnconfirmed,
        )
    }

    match rejection {
        PreRawRejection::SnapshotMismatch => {
            write_marker("coordinator.snapshot-mismatch", b"rejected\n")?;
        }
        PreRawRejection::ProtocolInvalid => {
            write_marker("coordinator.protocol-rejected", b"rejected\n")?;
        }
    }
    write_marker("coordinator.failed", b"clean\n")?;
    write_fixture_stdout(b"FAILED_CLEAN\n")?;
    consume_terminal_snapshot(snapshot);
    drop(lifecycle);
    drop(guardian);
    drop(transfer);
    drop(coordinator_lease);
    Ok(ExitCode::from(EXIT_FAILURE))
}

/// Completes a deterministic failure after `TerminalArmed` but before raw
/// mode or any runtime/worker/PTY spawn is permitted.
///
/// The guardian owns the ACK deadline and exits by itself. The coordinator
/// never signals it: an exact direct-child reap with the documented failure
/// code is required before A can be released. Any ambiguity restores the
/// unchanged outer terminal and retains authority fail-closed.
#[allow(clippy::too_many_arguments)]
fn reject_post_arm_ack(
    coordinator_lease: CoordinatorProfileLease,
    mut guardian: Child,
    lifecycle: LifecycleEndpoint,
    transfer: TransferChannelPair,
    snapshot: TerminalSnapshot,
    failure: PostArmAckFailure,
) -> Result<ExitCode, FixtureError> {
    let payload: &[u8] = match failure {
        PostArmAckFailure::Timeout => b"timeout\n",
        PostArmAckFailure::Disconnect => b"disconnect\n",
    };
    // No fallible operation may unwind the live direct-child handle. Even a
    // marker/storage fault is converted into channel closure followed by the
    // same bounded natural-exit proof.
    let marker_ready = write_marker("coordinator.arm-ack-fault-ready", payload).is_ok();
    let released =
        marker_ready && wait_for_exact_marker("test.release-fault", b"release\n").is_ok();
    let coordination_ok = marker_ready && released;
    if matches!(failure, PostArmAckFailure::Disconnect) || !coordination_ok {
        let _ = lifecycle.shutdown();
    }

    let status = wait_exact_child(
        &mut guardian,
        bounded_deadline(PHASE_TIMEOUT.saturating_mul(2)),
    );
    if !matches!(status, Ok(status) if status.code() == Some(i32::from(EXIT_FAILURE))) {
        let _ = restore_outer_terminal(&snapshot);
        park_retained_terminal_coordinator_without_signal(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            None,
            RetentionReason::InvariantUnconfirmed,
        )
    }
    if restore_outer_terminal(&snapshot).is_err() {
        park_retained_terminal_coordinator_without_signal(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            None,
            RetentionReason::InvariantUnconfirmed,
        )
    }

    if !coordination_ok {
        consume_terminal_snapshot(snapshot);
        drop(lifecycle);
        drop(guardian);
        drop(transfer);
        drop(coordinator_lease);
        return Err(FixtureError::Storage);
    }

    let marker = match failure {
        PostArmAckFailure::Timeout => "coordinator.arm-ack-timeout",
        PostArmAckFailure::Disconnect => "coordinator.arm-ack-disconnect",
    };
    write_marker(marker, b"rejected\n")?;
    write_marker("coordinator.failed", b"clean\n")?;
    write_fixture_stdout(b"FAILED_CLEAN\n")?;
    consume_terminal_snapshot(snapshot);
    drop(lifecycle);
    drop(guardian);
    drop(transfer);
    drop(coordinator_lease);
    Ok(ExitCode::from(EXIT_FAILURE))
}

/// Consumes the immutable recovery target at the protocol's explicit disarm
/// boundary. `TerminalSnapshot` intentionally owns no descriptor, so using a
/// by-value helper documents the state transition without pretending that a
/// `Drop` implementation releases OS authority.
fn consume_terminal_snapshot(_snapshot: TerminalSnapshot) {}

// Implemented below in deliberately separate coordinator/guardian sections.
#[allow(
    clippy::drop_non_drop,
    reason = "explicit receiver consumption ends the protocol borrow before retained ownership moves"
)]
fn run_terminal_coordinator(scenario: Scenario) -> Result<ExitCode, FixtureError> {
    CLEANUP_RESOLUTION_ENABLED.store(scenario == Scenario::PtyCleanupMismatch, Ordering::Release);
    let anchored = env::var_os(COORDINATOR_FOREGROUND_ENV).is_some();
    let controlling = if anchored {
        wait_for_exact_marker("anchor.foreground", b"ready\n")?;
        let process = rustix::process::getpid();
        let process_session =
            rustix::process::getsid(Some(process)).map_err(|_| FixtureError::Process)?;
        let terminal_session =
            rustix::termios::tcgetsid(io::stdin()).map_err(|_| FixtureError::Process)?;
        if process_session != terminal_session {
            return Err(FixtureError::Invariant);
        }
        None
    } else {
        Some(claim_controlling_terminal_from_stdin().map_err(|_| FixtureError::Process)?)
    };
    let snapshot = TerminalSnapshot::capture(io::stdin()).map_err(|_| FixtureError::Process)?;
    let snapshot_fingerprint = snapshot.semantic_fingerprint();
    if controlling.is_some_and(|proof| snapshot.foreground_process_group() != proof.process_group())
    {
        return Err(FixtureError::Invariant);
    }

    let (registry, profile) = profile()?;
    let coordinator_lease = registry
        .lock_profile_coordinator(&profile)
        .map_err(|_| FixtureError::Profile)?;
    let coordinator_lock_identity = descriptor_identity(
        coordinator_lease
            .lock_file()
            .map_err(|_| FixtureError::Descriptor)?
            .as_fd(),
    )
    .map_err(|_| FixtureError::Descriptor)?;

    let transfer = TransferChannelPair::new().map_err(|_| FixtureError::Channel)?;
    let transfer_sender = transfer
        .sender_identity()
        .map_err(|_| FixtureError::Descriptor)?
        .for_scan();
    let transfer_receiver = transfer
        .receiver_identity()
        .map_err(|_| FixtureError::Descriptor)?
        .for_scan();
    let lifecycle_pair = LifecyclePair::new().map_err(|_| FixtureError::Channel)?;
    let lifecycle_coordinator = lifecycle_pair
        .coordinator_identity()
        .map_err(|_| FixtureError::Descriptor)?
        .for_scan();
    let lifecycle_guardian = lifecycle_pair
        .guardian_identity()
        .map_err(|_| FixtureError::Descriptor)?
        .for_scan();
    let terminal_pair = TerminalChannelPair::new().map_err(|_| FixtureError::Channel)?;
    let terminal_coordinator_identity = terminal_pair
        .coordinator_identity()
        .map_err(|_| FixtureError::Descriptor)?;
    let terminal_guardian_identity = terminal_pair
        .guardian_identity()
        .map_err(|_| FixtureError::Descriptor)?;
    let (terminal_coordinator, terminal_guardian) = terminal_pair.split();
    let recovery = RecoveryTty::duplicate(io::stdin()).map_err(|_| FixtureError::Descriptor)?;
    let recovery_identity = recovery.descriptor_identity();

    let expected_guardian_lifecycle = IdentitySet::encode(&[lifecycle_guardian])?;
    let expected_guardian_terminal = IdentitySet::encode(&[terminal_guardian_identity])?;
    let expected_guardian_recovery = IdentitySet::encode(&[recovery_identity])?;
    let guardian_forbidden = IdentitySet::encode(&[
        coordinator_lock_identity,
        lifecycle_coordinator,
        transfer_sender,
        transfer_receiver,
        terminal_coordinator_identity,
    ])?;

    let mut command = Command::new(current_fixture_executable()?);
    command
        .args(["guardian", scenario.as_str()])
        .env_clear()
        .env("CALCIFER_HOME", registry.managed_root())
        .env(MARKER_ROOT_ENV, marker_root()?)
        .env(PROFILE_ID_ENV, &profile.id)
        .env(GUARDIAN_FORBIDDEN_ENV, guardian_forbidden)
        .env(GUARDIAN_LIFECYCLE_ENV, expected_guardian_lifecycle)
        .env(GUARDIAN_TERMINAL_ENV, expected_guardian_terminal)
        .env(GUARDIAN_RECOVERY_ENV, expected_guardian_recovery)
        .env(
            GUARDIAN_FOREGROUND_ENV,
            snapshot.foreground_process_group().to_string(),
        )
        .stdout(
            terminal_guardian
                .into_stdio()
                .map_err(|_| FixtureError::Descriptor)?,
        )
        .stderr(
            recovery
                .into_stdio()
                .map_err(|_| FixtureError::Descriptor)?,
        )
        .process_group(0);

    let spawned = match spawn_guardian_with_lifecycle_stdin(command, lifecycle_pair) {
        Ok(spawned) => spawned,
        Err(failure) => {
            let (lifecycle, guardian, _error) = failure.into_parts();
            let Some(guardian) = guardian else {
                return Err(FixtureError::Channel);
            };
            drop(terminal_coordinator);
            restore_and_retain(
                coordinator_lease,
                guardian,
                lifecycle,
                transfer,
                snapshot,
                None,
                RetentionReason::InvariantUnconfirmed,
            )
        }
    };
    let (mut guardian, lifecycle) = spawned.into_parts();
    if configure_endpoint(&lifecycle).is_err() || !child_is_own_process_group(&guardian) {
        drop(terminal_coordinator);
        restore_and_retain(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            None,
            RetentionReason::InvariantUnconfirmed,
        )
    }

    let mut receiver = CoordinatorReceiver::new_terminal(&lifecycle);
    let lease_event = receiver.receive(phase_deadline());
    if !matches!(lease_event, Ok(GuardianEvent::LeaseCommitted)) {
        let reason = match lease_event {
            Err(error) => retention_reason_for_receive_failure(&guardian, error),
            Ok(_) => RetentionReason::ProtocolInvalid,
        };
        drop(receiver);
        drop(terminal_coordinator);
        restore_and_retain(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            None,
            reason,
        )
    }

    let phase_barrier_clean = phase_barrier_has_no_spawn_activity().is_ok_and(|clean| clean);
    if !phase_barrier_clean
        || !matches!(
            registry.lock_profile_provider(&profile),
            Err(error) if error.code() == "profile_busy"
        )
        || write_marker("coordinator.lease", b"committed\n").is_err()
    {
        drop(receiver);
        drop(terminal_coordinator);
        restore_and_retain(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            None,
            RetentionReason::InvariantUnconfirmed,
        )
    }
    if receiver.record_command(CoordinatorCommand::Start).is_err()
        || send_coordinator_command(&mut &lifecycle, CoordinatorCommand::Start, phase_deadline())
            .is_err()
    {
        drop(receiver);
        drop(terminal_coordinator);
        restore_and_retain(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            None,
            RetentionReason::LifecycleLost,
        )
    }

    let mut reported_groups = Vec::with_capacity(2);
    let mut session_failed = false;
    let ready = loop {
        let event = match receiver.receive(phase_deadline()) {
            Ok(event) => event,
            Err(error) => {
                if scenario.is_pre_arm_protocol_fault() {
                    drop(receiver);
                    drop(terminal_coordinator);
                    return reject_pre_raw_handshake(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        PreRawRejection::ProtocolInvalid,
                    );
                }
                let reason = retention_reason_for_receive_failure(&guardian, error);
                drop(receiver);
                drop(terminal_coordinator);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    reason,
                )
            }
        };
        match event {
            GuardianEvent::TerminalArmed {
                snapshot: guardian_snapshot,
            } => {
                if !snapshot_fingerprint.matches(guardian_snapshot) {
                    drop(receiver);
                    drop(terminal_coordinator);
                    return reject_pre_raw_handshake(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        PreRawRejection::SnapshotMismatch,
                    );
                }
                if scenario.is_post_arm_ack_fault() {
                    let failure = match scenario {
                        Scenario::PtyArmAckTimeout => PostArmAckFailure::Timeout,
                        Scenario::PtyArmAckDisconnect => PostArmAckFailure::Disconnect,
                        _ => return Err(FixtureError::Invariant),
                    };
                    drop(receiver);
                    drop(terminal_coordinator);
                    return reject_post_arm_ack(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        failure,
                    );
                }
                let command = CoordinatorCommand::TerminalArmAccepted;
                if receiver.record_command(command).is_err()
                    || send_coordinator_command(&mut &lifecycle, command, phase_deadline()).is_err()
                {
                    drop(receiver);
                    drop(terminal_coordinator);
                    restore_and_retain(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        None,
                        RetentionReason::LifecycleLost,
                    )
                }
            }
            GuardianEvent::ChildStarted { pid, pgid, .. } => {
                if reported_groups.len() == 2
                    || !reported_group_is_safe(&guardian, pid, pgid)
                    || reported_groups.contains(&pgid)
                {
                    drop(receiver);
                    drop(terminal_coordinator);
                    restore_and_retain(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        None,
                        RetentionReason::ProtocolInvalid,
                    )
                }
                reported_groups.push(pgid);
            }
            GuardianEvent::Ready => match receiver.take_verified_ready() {
                Ok(readiness) => break Some(readiness),
                Err(_) => {
                    drop(receiver);
                    drop(terminal_coordinator);
                    restore_and_retain(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        None,
                        RetentionReason::ProtocolInvalid,
                    )
                }
            },
            GuardianEvent::Failed { .. } => {
                session_failed = true;
                break None;
            }
            _ => {
                drop(receiver);
                drop(terminal_coordinator);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    RetentionReason::ProtocolInvalid,
                )
            }
        }
    };

    let mut pump = None;
    let mut signal_flags = None;
    let ready = match (scenario, ready) {
        (Scenario::PtyTuiExitBeforeGate, Some(readiness)) => {
            signal_flags = match TerminalSignalFlags::install() {
                Ok(flags) => Some(flags),
                Err(_) => {
                    drop(receiver);
                    drop(terminal_coordinator);
                    restore_and_retain(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        None,
                        RetentionReason::InvariantUnconfirmed,
                    )
                }
            };
            if write_marker("coordinator.pre-gate-held", b"held\n").is_err() {
                drop(receiver);
                drop(terminal_coordinator);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    RetentionReason::InvariantUnconfirmed,
                )
            }
            let gate = CoordinatorCommand::OpenInputGate;
            if wait_for_exact_marker("guardian.pre-gate-failure", b"observed\n").is_err()
                || receiver.record_command(gate).is_err()
                || send_coordinator_command(&mut &lifecycle, gate, phase_deadline()).is_err()
            {
                drop(receiver);
                drop(terminal_coordinator);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    RetentionReason::InvariantUnconfirmed,
                )
            }
            match receiver.receive(bounded_deadline(PHASE_TIMEOUT.saturating_mul(2))) {
                Ok(GuardianEvent::Failed {
                    phase: Phase::Readiness,
                    code: FailureCode::EarlyExit,
                }) => {
                    session_failed = true;
                    if write_marker("coordinator.pre-gate-failed", b"failed\n").is_err()
                        || wait_for_exact_marker("anchor.winch-storm-sent", b"sent\n").is_err()
                    {
                        drop(signal_flags.take());
                        drop(receiver);
                        drop(terminal_coordinator);
                        restore_and_retain(
                            coordinator_lease,
                            guardian,
                            lifecycle,
                            transfer,
                            snapshot,
                            None,
                            RetentionReason::InvariantUnconfirmed,
                        )
                    }
                    drop(readiness);
                    None
                }
                Ok(_) => {
                    drop(receiver);
                    drop(terminal_coordinator);
                    restore_and_retain(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        None,
                        RetentionReason::ProtocolInvalid,
                    )
                }
                Err(error) => {
                    let reason = retention_reason_for_receive_failure(&guardian, error);
                    drop(receiver);
                    drop(terminal_coordinator);
                    restore_and_retain(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        None,
                        reason,
                    )
                }
            }
        }
        (_, ready) => ready,
    };

    if let Some(readiness) = ready {
        if write_marker("coordinator.ready", b"ready\n").is_err() {
            drop(receiver);
            drop(terminal_coordinator);
            restore_and_retain(
                coordinator_lease,
                guardian,
                lifecycle,
                transfer,
                snapshot,
                None,
                RetentionReason::InvariantUnconfirmed,
            )
        }
        signal_flags = match TerminalSignalFlags::install() {
            Ok(flags) => Some(flags),
            Err(_) => {
                drop(receiver);
                drop(terminal_coordinator);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    RetentionReason::InvariantUnconfirmed,
                )
            }
        };
        let gate = InputGate::closed().mark_ready(readiness);
        let raw = match snapshot.enter_raw_after_input_flush(io::stdin()) {
            Ok(raw) => raw,
            Err(_) => {
                drop(signal_flags.take());
                drop(receiver);
                drop(terminal_coordinator);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    RetentionReason::InvariantUnconfirmed,
                )
            }
        };
        if write_marker("terminal.raw", b"raw\n").is_err() {
            drop(signal_flags.take());
            drop(receiver);
            drop(terminal_coordinator);
            restore_and_retain(
                coordinator_lease,
                guardian,
                lifecycle,
                transfer,
                snapshot,
                None,
                RetentionReason::InvariantUnconfirmed,
            )
        }
        if receiver
            .record_command(CoordinatorCommand::OpenInputGate)
            .is_err()
            || send_coordinator_command(
                &mut &lifecycle,
                CoordinatorCommand::OpenInputGate,
                phase_deadline(),
            )
            .is_err()
        {
            drop(signal_flags.take());
            drop(receiver);
            drop(terminal_coordinator);
            restore_and_retain(
                coordinator_lease,
                guardian,
                lifecycle,
                transfer,
                snapshot,
                None,
                RetentionReason::LifecycleLost,
            )
        }
        let acknowledgement = match receiver.receive(phase_deadline()) {
            Ok(GuardianEvent::InputGateOpened) => match receiver.take_verified_open_gate_ack() {
                Ok(acknowledgement) => Some(acknowledgement),
                Err(_) => {
                    drop(signal_flags.take());
                    drop(receiver);
                    drop(terminal_coordinator);
                    restore_and_retain(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        None,
                        RetentionReason::ProtocolInvalid,
                    )
                }
            },
            Ok(GuardianEvent::Failed { .. }) => {
                session_failed = true;
                None
            }
            Ok(_) => {
                drop(signal_flags.take());
                drop(receiver);
                drop(terminal_coordinator);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    RetentionReason::ProtocolInvalid,
                )
            }
            Err(error) => {
                let reason = retention_reason_for_receive_failure(&guardian, error);
                drop(signal_flags.take());
                drop(receiver);
                drop(terminal_coordinator);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    reason,
                )
            }
        };
        if let Some(acknowledgement) = acknowledgement {
            let gate = gate.acknowledge_open(raw, acknowledgement);
            if write_marker("gate.open", b"open\n").is_err() {
                drop(signal_flags.take());
                drop(receiver);
                drop(terminal_coordinator);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    RetentionReason::InvariantUnconfirmed,
                )
            }
            pump = match CoordinatorPump::start(gate, terminal_coordinator, scenario) {
                Ok(pump) => Some(pump),
                Err(_) => {
                    drop(signal_flags.take());
                    drop(receiver);
                    restore_and_retain(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        snapshot,
                        None,
                        RetentionReason::InvariantUnconfirmed,
                    )
                }
            };
            if write_marker("coordinator.input-started", b"started\n").is_err() {
                drop(signal_flags.take());
                drop(receiver);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    pump,
                    RetentionReason::InvariantUnconfirmed,
                )
            }
        } else {
            drop(gate);
            drop(raw);
            drop(terminal_coordinator);
        }
    } else {
        drop(terminal_coordinator);
    }

    // Once the guardian has failed, no new foreground control may race its
    // terminal-quiescence proof. Pending signals stay latched until teardown.
    let mut signal_shutdown = session_failed;
    let mut pump_failure_deadline = None;
    let mut failure_controls_suppressed = false;
    loop {
        match lifecycle_readable(&lifecycle, EVENT_POLL) {
            Ok(false) => {
                if pump.as_ref().is_some_and(CoordinatorPump::is_finished) {
                    let deadline = pump_failure_deadline.get_or_insert_with(phase_deadline);
                    if Instant::now() >= *deadline {
                        drop(signal_flags.take());
                        drop(receiver);
                        restore_and_retain(
                            coordinator_lease,
                            guardian,
                            lifecycle,
                            transfer,
                            snapshot,
                            pump,
                            RetentionReason::InvariantUnconfirmed,
                        )
                    }
                } else {
                    pump_failure_deadline = None;
                }
                if !signal_shutdown {
                    if let Some(action) = signal_flags.as_ref().and_then(|flags| flags.next(false))
                    {
                        let handled = match action {
                            TerminalSignalAction::Suspend => {
                                match (signal_flags.as_ref(), pump.as_mut()) {
                                    (Some(flags), Some(pump)) => suspend_and_resume_coordinator(
                                        flags,
                                        pump,
                                        &snapshot,
                                        &mut receiver,
                                        &lifecycle,
                                        scenario,
                                    ),
                                    _ => Err(FixtureError::Invariant),
                                }
                            }
                            action => handle_coordinator_control(action, &mut receiver, &lifecycle),
                        };
                        match handled {
                            Ok(CoordinatorControlOutcome::Continue) => {}
                            Ok(CoordinatorControlOutcome::BeginShutdown) => {
                                signal_shutdown = true;
                            }
                            Ok(CoordinatorControlOutcome::Quiesced) => break,
                            Ok(CoordinatorControlOutcome::FailedAwaitQuiescence) => {
                                session_failed = true;
                                signal_shutdown = true;
                            }
                            Err(_) => {
                                drop(signal_flags.take());
                                drop(receiver);
                                restore_and_retain(
                                    coordinator_lease,
                                    guardian,
                                    lifecycle,
                                    transfer,
                                    snapshot,
                                    pump,
                                    RetentionReason::InvariantUnconfirmed,
                                )
                            }
                        }
                    }
                } else if scenario == Scenario::PtyTuiExitBeforeGate
                    && session_failed
                    && !failure_controls_suppressed
                {
                    if write_marker("coordinator.failed-controls-suppressed", b"suppressed\n")
                        .is_err()
                        || wait_for_exact_marker("test.release-quiescence", b"release\n").is_err()
                    {
                        drop(signal_flags.take());
                        drop(receiver);
                        restore_and_retain(
                            coordinator_lease,
                            guardian,
                            lifecycle,
                            transfer,
                            snapshot,
                            pump,
                            RetentionReason::InvariantUnconfirmed,
                        )
                    }
                    failure_controls_suppressed = true;
                }
                continue;
            }
            Ok(true) => {}
            Err(_) => {
                drop(signal_flags.take());
                drop(receiver);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    pump,
                    RetentionReason::LifecycleLost,
                )
            }
        }
        let event = match receiver.receive(phase_deadline()) {
            Ok(event) => event,
            Err(error) => {
                let reason = retention_reason_for_receive_failure(&guardian, error);
                drop(signal_flags.take());
                drop(receiver);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    pump,
                    reason,
                )
            }
        };
        match event {
            GuardianEvent::Failed { .. } if !session_failed => {
                session_failed = true;
                signal_shutdown = true;
            }
            GuardianEvent::TerminalQuiesced => break,
            _ => {
                drop(signal_flags.take());
                drop(receiver);
                restore_and_retain(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    pump,
                    RetentionReason::ProtocolInvalid,
                )
            }
        }
    }

    if let Some(pump) = pump {
        if let Err(pump) = pump.stop() {
            drop(signal_flags.take());
            drop(receiver);
            restore_and_retain(
                coordinator_lease,
                guardian,
                lifecycle,
                transfer,
                snapshot,
                Some(pump),
                RetentionReason::ShutdownDeadline,
            )
        }
    }
    let restore_result = if scenario == Scenario::PtyRestoreIdentityMismatch {
        reject_mismatched_outer_terminal_restore(&snapshot)
    } else {
        restore_outer_terminal(&snapshot)
    };
    if restore_result.is_err() {
        drop(signal_flags.take());
        drop(receiver);
        let _ = lifecycle.shutdown();
        park_retained_terminal_coordinator_without_signal(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            None,
            RetentionReason::InvariantUnconfirmed,
        )
    }
    if receiver
        .record_command(CoordinatorCommand::TerminalRestored)
        .is_err()
        || send_coordinator_command(
            &mut &lifecycle,
            CoordinatorCommand::TerminalRestored,
            phase_deadline(),
        )
        .is_err()
    {
        drop(signal_flags.take());
        drop(receiver);
        let _ = lifecycle.shutdown();
        park_retained_terminal_coordinator_without_signal(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            None,
            RetentionReason::LifecycleLost,
        )
    }
    if !matches!(
        receiver.receive(phase_deadline()),
        Ok(GuardianEvent::TerminalRecoveryDisarmed)
    ) {
        drop(signal_flags.take());
        drop(receiver);
        let _ = lifecycle.shutdown();
        park_retained_terminal_coordinator_without_signal(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            snapshot,
            None,
            RetentionReason::ProtocolInvalid,
        )
    }
    let (terminal_session, tui_disposition) = loop {
        match receiver.receive(phase_deadline()) {
            Ok(GuardianEvent::Failed { .. }) if !session_failed => session_failed = true,
            Ok(GuardianEvent::ChildrenReaped { session, tui, .. }) => break (session, tui),
            Ok(_) => {
                drop(signal_flags.take());
                drop(receiver);
                let _ = lifecycle.shutdown();
                park_retained_terminal_coordinator_without_signal(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    RetentionReason::ProtocolInvalid,
                )
            }
            Err(error) => {
                let reason = retention_reason_for_receive_failure(&guardian, error);
                drop(signal_flags.take());
                drop(receiver);
                let _ = lifecycle.shutdown();
                park_retained_terminal_coordinator_without_signal(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    snapshot,
                    None,
                    reason,
                )
            }
        }
    };
    let output_kill_contained = if scenario == Scenario::PtyOutputBackpressure {
        matches!(
            tui_disposition,
            ChildDisposition::Signaled {
                signal,
                stop_action: StopAction::Kill,
                ..
            } if i32::from(signal) == signal_hook::consts::signal::SIGKILL
        )
    } else {
        false
    };

    let (status, forced_guardian_stop) = match wait_exact_child(&mut guardian, phase_deadline()) {
        Ok(status) => (status, false),
        Err(_) => {
            let _ = guardian.kill();
            match wait_exact_child(&mut guardian, phase_deadline()) {
                Ok(status) => (status, true),
                Err(_) => {
                    drop(signal_flags.take());
                    drop(receiver);
                    retain_after_guardian_loss(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        RetentionReason::ShutdownDeadline,
                    )
                }
            }
        }
    };
    if receiver.verify_terminal_eof(phase_deadline()).is_err() {
        drop(signal_flags.take());
        drop(receiver);
        retain_after_reaped_guardian(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            RetentionReason::InvariantUnconfirmed,
        )
    }
    // This diagnostic may fail only after the live direct-child authority has
    // been consumed and lifecycle EOF has proved that no guardian writer
    // remains. A marker error therefore cannot release A ahead of containment.
    if output_kill_contained {
        write_marker("tui.kill-contained", b"killed\n")?;
    }

    drop(signal_flags.take());
    drop(receiver);
    drop(lifecycle);
    drop(guardian);
    drop(coordinator_lease);
    let operational_session = if forced_guardian_stop
        || session_failed != (terminal_session == SessionStatus::Failed)
        || !guardian_status_matches_terminal(status, terminal_session)
    {
        SessionStatus::Failed
    } else {
        terminal_session
    };
    match operational_session {
        SessionStatus::Completed => {
            write_marker("coordinator.completed", b"complete\n")?;
            write_fixture_stdout(b"COMPLETED\n")?;
            project_tui_disposition(tui_disposition)
        }
        SessionStatus::Failed => {
            write_marker("coordinator.failed", b"clean\n")?;
            write_fixture_stdout(b"FAILED_CLEAN\n")?;
            Ok(ExitCode::from(EXIT_FAILURE))
        }
    }
}

fn project_tui_disposition(disposition: ChildDisposition) -> Result<ExitCode, FixtureError> {
    match disposition {
        ChildDisposition::Exited {
            code,
            stop_action: StopAction::None,
        } => Ok(ExitCode::from(code)),
        ChildDisposition::Signaled {
            signal,
            stop_action: StopAction::None,
            ..
        } => {
            signal_hook::low_level::emulate_default_handler(i32::from(signal))
                .map_err(|_| FixtureError::Process)?;
            Err(FixtureError::Process)
        }
        ChildDisposition::NotStarted
        | ChildDisposition::Exited { .. }
        | ChildDisposition::Signaled { .. } => Err(FixtureError::Invariant),
    }
}

fn run_terminal_guardian(_scenario: Scenario) -> Result<ExitCode, FixtureError> {
    let scenario = _scenario;
    CLEANUP_RESOLUTION_ENABLED.store(scenario == Scenario::PtyCleanupMismatch, Ordering::Release);
    FOREGROUND_RECLAIM_RESOLUTION_ENABLED.store(
        scenario == Scenario::PtyForegroundReclaim,
        Ordering::Release,
    );
    let endpoint = bootstrap_guardian_from_stdin().map_err(|_| FixtureError::Channel)?;
    configure_endpoint(&endpoint)?;
    let terminal = TerminalEndpoint::bootstrap_from_inherited_stdout()
        .map_err(|_| FixtureError::Descriptor)?;
    let recovery =
        RecoveryTty::bootstrap_from_inherited_stderr().map_err(|_| FixtureError::Descriptor)?;

    let guardian_forbidden = IdentitySet::parse_environment(GUARDIAN_FORBIDDEN_ENV)?;
    guardian_forbidden.assert_absent()?;
    let expected_lifecycle = IdentitySet::parse_environment(GUARDIAN_LIFECYCLE_ENV)?;
    let expected_terminal = IdentitySet::parse_environment(GUARDIAN_TERMINAL_ENV)?;
    let expected_recovery = IdentitySet::parse_environment(GUARDIAN_RECOVERY_ENV)?;
    let lifecycle_identity = endpoint
        .descriptor_identity()
        .map_err(|_| FixtureError::Descriptor)?
        .for_scan();
    let terminal_identity = terminal
        .descriptor_identity()
        .map_err(|_| FixtureError::Descriptor)?;
    let recovery_identity = recovery.descriptor_identity();
    if expected_lifecycle.identities.as_slice() != [lifecycle_identity]
        || expected_terminal.identities.as_slice() != [terminal_identity]
        || expected_recovery.identities.as_slice() != [recovery_identity]
    {
        return Err(FixtureError::Descriptor);
    }
    let null_identities = [
        descriptor_identity(io::stdin().as_fd()).map_err(|_| FixtureError::Descriptor)?,
        descriptor_identity(io::stdout().as_fd()).map_err(|_| FixtureError::Descriptor)?,
        descriptor_identity(io::stderr().as_fd()).map_err(|_| FixtureError::Descriptor)?,
    ];
    if [lifecycle_identity, terminal_identity, recovery_identity]
        .into_iter()
        .any(|identity| {
            !matches!(
                calcifer_unix_child_fd::count_open_descriptors_with_identity(identity),
                Ok(1)
            ) || null_identities.contains(&identity)
        })
        || rustix::termios::isatty(io::stdin())
        || rustix::termios::isatty(io::stdout())
        || rustix::termios::isatty(io::stderr())
    {
        return Err(FixtureError::Descriptor);
    }
    write_marker("guardian.bootstrap-authority", b"single\n")?;
    let expected_foreground = parse_positive_process_group(GUARDIAN_FOREGROUND_ENV)?;
    let snapshot = TerminalSnapshot::capture_for_recovery(&recovery, expected_foreground)
        .map_err(|_| FixtureError::Process)?;
    if snapshot.descriptor_identity() != recovery_identity {
        return Err(FixtureError::Descriptor);
    }
    write_process_marker("guardian.pid", rustix::process::getpid().as_raw_pid())?;

    let (registry, profile) = guardian_profile()?;
    let provider_lease = registry
        .lock_profile_provider(&profile)
        .map_err(|_| FixtureError::Profile)?;
    let provider_identity = descriptor_identity(
        provider_lease
            .provider_lock_file()
            .map_err(|_| FixtureError::Descriptor)?
            .as_fd(),
    )
    .map_err(|_| FixtureError::Descriptor)?;

    let mut commands = GuardianCommandReceiver::new_terminal(&endpoint);
    if !emit_guardian_event(&mut commands, &endpoint, GuardianEvent::LeaseCommitted) {
        drop(provider_lease);
        return Ok(ExitCode::from(EXIT_FAILURE));
    }
    let start_authorization = match receive_start(&mut commands) {
        Ok(authorization) => authorization,
        Err(_) => {
            drop(provider_lease);
            return Ok(ExitCode::from(EXIT_FAILURE));
        }
    };
    let mut advertised_snapshot = snapshot.semantic_fingerprint();
    if scenario == Scenario::PtySnapshotMismatch {
        advertised_snapshot = advertised_snapshot.corrupted_for_fixture();
    }
    if (scenario == Scenario::PtySnapshotMismatch || scenario.is_pre_arm_protocol_fault())
        && (write_marker("guardian.pre-arm-fault-ready", b"ready\n").is_err()
            || wait_for_exact_marker("test.release-fault", b"release\n").is_err())
    {
        drop(provider_lease);
        return Ok(ExitCode::from(EXIT_FAILURE));
    }
    let pre_arm_fault = match scenario {
        Scenario::PtyWrongOrder => {
            send_guardian_event(&mut &endpoint, GuardianEvent::Ready, phase_deadline())
        }
        Scenario::PtyMalformedFrame => {
            send_fixture_malformed_guardian_frame(&mut &endpoint, phase_deadline())
        }
        Scenario::PtyTrailingFrame => send_fixture_trailing_terminal_armed(
            &mut &endpoint,
            advertised_snapshot,
            phase_deadline(),
        ),
        _ => Ok(()),
    };
    if scenario.is_pre_arm_protocol_fault() {
        let _ = pre_arm_fault;
        drop(provider_lease);
        return Ok(ExitCode::from(EXIT_FAILURE));
    }
    if !emit_guardian_event(
        &mut commands,
        &endpoint,
        GuardianEvent::TerminalArmed {
            snapshot: advertised_snapshot,
        },
    ) {
        drop(provider_lease);
        return Ok(ExitCode::from(EXIT_FAILURE));
    }
    if scenario.is_post_arm_ack_fault() {
        let payload: &[u8] = match scenario {
            Scenario::PtyArmAckTimeout => b"timeout\n",
            Scenario::PtyArmAckDisconnect => b"disconnect\n",
            _ => return Err(FixtureError::Invariant),
        };
        if write_marker("guardian.arm-ack-waiting", payload).is_err()
            || wait_for_exact_marker("test.release-fault", b"release\n").is_err()
        {
            drop(provider_lease);
            return Ok(ExitCode::from(EXIT_FAILURE));
        }
    }
    if !matches!(
        commands.receive(phase_deadline()),
        Ok(CoordinatorCommand::TerminalArmAccepted)
    ) {
        drop(provider_lease);
        return Ok(ExitCode::from(EXIT_FAILURE));
    }

    let runtime = match create_fixture_runtime(&start_authorization) {
        Ok(runtime) => runtime,
        Err(error) => {
            drop(provider_lease);
            return Err(error);
        }
    };
    let worker = match FixtureWorker::start(&start_authorization, scenario) {
        Ok(worker) => worker,
        Err(error) => match runtime.cleanup() {
            Ok(_) => {
                drop(provider_lease);
                return Err(error);
            }
            Err(cleanup) => RetainedGuardianCleanupState {
                provider_lease,
                cleanup,
            }
            .park(),
        },
    };
    if scenario == Scenario::PtyCleanupMismatch
        && fs::write(runtime.path().join("unexpected"), b"synthetic").is_err()
    {
        let _ = (&provider_lease, &worker);
        loop {
            thread::park();
        }
    }

    let pty_owner = match PtyOwner::open(snapshot.size()) {
        Ok(owner) => owner,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                None,
                None,
                Some((Phase::Terminal, FailureCode::Terminal)),
                true,
            );
        }
    };
    let (readiness_receiver, readiness_sender) = match tui_readiness_pair() {
        Ok(pair) => pair,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                None,
                None,
                Some((Phase::Readiness, FailureCode::Descriptor)),
                true,
            );
        }
    };
    let readiness_receiver_identity = match readiness_receiver.descriptor_identity() {
        Ok(identity) => identity,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                None,
                None,
                Some((Phase::Readiness, FailureCode::Descriptor)),
                true,
            );
        }
    };
    let readiness_sender_identity = match descriptor_identity(readiness_sender.as_fd()) {
        Ok(identity) => identity,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                None,
                None,
                Some((Phase::Readiness, FailureCode::Descriptor)),
                true,
            );
        }
    };

    let mut tui_command = match fake_child_command(ChildRole::Tui, scenario, "") {
        Ok(command) => command,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                None,
                None,
                Some((Phase::Tui, FailureCode::Spawn)),
                true,
            );
        }
    };
    let pty_master = match pty_owner.configure_child(&mut tui_command) {
        Ok(master) => master,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                None,
                None,
                Some((Phase::Terminal, FailureCode::Descriptor)),
                true,
            );
        }
    };
    let pty_master_identity = match pty_master.descriptor_identity() {
        Ok(identity) => identity,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                None,
                None,
                Some((Phase::Terminal, FailureCode::Descriptor)),
                true,
            );
        }
    };
    let mut base_child_identities = guardian_forbidden.identities.clone();
    base_child_identities.extend([
        provider_identity,
        lifecycle_identity,
        terminal_identity,
        recovery_identity,
        pty_master_identity,
    ]);
    let mut app_identities = base_child_identities.clone();
    app_identities.extend([readiness_receiver_identity, readiness_sender_identity]);
    let app_forbidden = match IdentitySet::encode(&app_identities) {
        Ok(encoded) => encoded,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                None,
                None,
                Some((Phase::AppServer, FailureCode::Descriptor)),
                true,
            );
        }
    };
    let mut tui_identities = base_child_identities;
    tui_identities.push(readiness_receiver_identity);
    let tui_forbidden = match IdentitySet::encode(&tui_identities) {
        Ok(encoded) => encoded,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                None,
                None,
                Some((Phase::Tui, FailureCode::Descriptor)),
                true,
            );
        }
    };
    tui_command.env(CHILD_FORBIDDEN_ENV, &tui_forbidden);

    let mut app = match spawn_managed_child(
        &start_authorization,
        ChildRole::AppServer,
        scenario,
        &app_forbidden,
    ) {
        Ok(app) => app,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                None,
                None,
                Some((Phase::AppServer, FailureCode::Spawn)),
                true,
            );
        }
    };
    let app_identity = app.containment();
    if !emit_guardian_event(
        &mut commands,
        &endpoint,
        GuardianEvent::ChildStarted {
            role: ChildRole::AppServer,
            pid: app_identity.pid(),
            pgid: app_identity.pgid(),
        },
    ) || app.await_ready(startup_deadline()).is_err()
    {
        return finish_terminal_guardian(
            &endpoint,
            &mut commands,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            Some(app),
            None,
            None,
            Some((Phase::Readiness, FailureCode::EarlyExit)),
            true,
        );
    }

    if write_marker("tui.spawn-requested", b"requested\n").is_err() {
        return finish_terminal_guardian(
            &endpoint,
            &mut commands,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            Some(app),
            None,
            None,
            Some((Phase::Tui, FailureCode::Spawn)),
            true,
        );
    }
    let mut tui = match ManagedGroupChild::spawn_session_leader_with_inherited_fd(
        ChildRole::Tui,
        tui_command,
        readiness_sender.as_fd(),
        startup_deadline(),
    ) {
        Ok(tui) => tui,
        Err(mut failure) => {
            drop(readiness_sender);
            if failure.state() != SpawnFailureState::NotStarted {
                failure.park()
            }
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                Some(app),
                None,
                None,
                Some((Phase::Tui, FailureCode::Spawn)),
                true,
            );
        }
    };
    drop(readiness_sender);
    let tui_identity = tui.containment();
    if !emit_guardian_event(
        &mut commands,
        &endpoint,
        GuardianEvent::ChildStarted {
            role: ChildRole::Tui,
            pid: tui_identity.pid(),
            pgid: tui_identity.pgid(),
        },
    ) {
        return finish_terminal_guardian(
            &endpoint,
            &mut commands,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            Some(app),
            Some(tui),
            None,
            Some((Phase::Protocol, FailureCode::InvalidControl)),
            false,
        );
    }
    let output_pump = match GuardianOutputPump::start(pty_master, terminal) {
        Ok(pump) => pump,
        Err(_) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                Some(app),
                Some(tui),
                None,
                Some((Phase::Pump, FailureCode::Pump)),
                true,
            );
        }
    };
    if scenario == Scenario::PtyReadinessTimeout
        && (write_marker("guardian.readiness-timeout-armed", b"armed\n").is_err()
            || wait_for_exact_marker("test.release-fault", b"release\n").is_err())
    {
        return finish_terminal_guardian(
            &endpoint,
            &mut commands,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some(GuardianPumpState::Output(output_pump)),
            Some((Phase::Readiness, FailureCode::Internal)),
            true,
        );
    }

    let (readiness, channel_live, readiness_failure) = await_tui_readiness(
        &endpoint,
        &mut commands,
        readiness_receiver,
        &mut app,
        &mut tui,
        &output_pump,
    );
    let Some(readiness) = readiness else {
        return finish_terminal_guardian(
            &endpoint,
            &mut commands,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some(GuardianPumpState::Output(output_pump)),
            Some(readiness_failure.unwrap_or((Phase::Readiness, FailureCode::Internal))),
            channel_live,
        );
    };
    let ready_pump = output_pump.mark_ready(readiness);
    if !emit_guardian_event(&mut commands, &endpoint, GuardianEvent::Ready) {
        return finish_terminal_guardian(
            &endpoint,
            &mut commands,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some(GuardianPumpState::Ready(ready_pump)),
            Some((Phase::Protocol, FailureCode::InvalidControl)),
            false,
        );
    }
    if scenario == Scenario::PtyGuardianDeath {
        if wait_for_exact_marker("test.release-fault", b"release\n").is_err() {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                Some(app),
                Some(tui),
                Some(GuardianPumpState::Ready(ready_pump)),
                Some((Phase::Protocol, FailureCode::InvalidControl)),
                true,
            );
        }
        let _ =
            rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::KILL);
        loop {
            thread::park();
        }
    }

    let open_gate = match await_guardian_open_input_gate(
        &endpoint,
        &mut commands,
        &mut app,
        &mut tui,
        &ready_pump,
    ) {
        Ok(gate) => gate,
        Err(failure) => {
            if scenario == Scenario::PtyTuiExitBeforeGate
                && write_marker("guardian.pre-gate-failure", b"observed\n").is_err()
            {
                return finish_terminal_guardian(
                    &endpoint,
                    &mut commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    Some(GuardianPumpState::Ready(ready_pump)),
                    Some((Phase::Readiness, FailureCode::Internal)),
                    failure.channel_live,
                );
            }
            return if scenario == Scenario::PtyTuiExitBeforeGate {
                finish_terminal_guardian_with_failure_quiescence_barrier(
                    &endpoint,
                    &mut commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    Some(GuardianPumpState::Ready(ready_pump)),
                    Some((failure.phase, failure.code)),
                    failure.channel_live,
                )
            } else {
                finish_terminal_guardian(
                    &endpoint,
                    &mut commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    Some(GuardianPumpState::Ready(ready_pump)),
                    Some((failure.phase, failure.code)),
                    failure.channel_live,
                )
            };
        }
    };
    if scenario == Scenario::PtyReadyNoAck {
        if write_marker("guardian.no-ack-armed", b"armed\n").is_err()
            || wait_for_exact_marker("test.release-fault", b"release\n").is_err()
        {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                Some(app),
                Some(tui),
                Some(GuardianPumpState::Ready(ready_pump)),
                Some((Phase::Protocol, FailureCode::InvalidControl)),
                true,
            );
        }
        return finish_terminal_guardian(
            &endpoint,
            &mut commands,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some(GuardianPumpState::Ready(ready_pump)),
            Some((Phase::Protocol, FailureCode::InvalidControl)),
            false,
        );
    }
    let duplex_pump = match ready_pump.open_input(open_gate) {
        Ok(pump) => pump,
        Err(pump) => {
            return finish_terminal_guardian(
                &endpoint,
                &mut commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                Some(app),
                Some(tui),
                Some(GuardianPumpState::Ready(pump)),
                Some((Phase::Pump, FailureCode::Pump)),
                true,
            );
        }
    };
    if write_marker("guardian.input-started", b"started\n").is_err() {
        return finish_terminal_guardian(
            &endpoint,
            &mut commands,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some(GuardianPumpState::Duplex(duplex_pump)),
            Some((Phase::Pump, FailureCode::Pump)),
            true,
        );
    }
    if !emit_guardian_event(&mut commands, &endpoint, GuardianEvent::InputGateOpened) {
        return finish_terminal_guardian(
            &endpoint,
            &mut commands,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some(GuardianPumpState::Duplex(duplex_pump)),
            Some((Phase::Protocol, FailureCode::InvalidControl)),
            false,
        );
    }
    if scenario == Scenario::PtyTerminalChannelEof
        && (wait_for_exact_marker("test.release-fault", b"release\n").is_err()
            || write_marker("terminal.channel-eof", b"injected\n").is_err()
            || duplex_pump.shutdown_terminal_channel().is_err())
    {
        return finish_terminal_guardian(
            &endpoint,
            &mut commands,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some(GuardianPumpState::Duplex(duplex_pump)),
            Some((Phase::Pump, FailureCode::Pump)),
            true,
        );
    }

    run_active_guardian(
        &endpoint,
        &mut commands,
        scenario,
        provider_lease,
        recovery,
        snapshot,
        runtime,
        worker,
        app,
        tui,
        duplex_pump,
    )
}

fn emit_guardian_event(
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    endpoint: &LifecycleEndpoint,
    event: GuardianEvent,
) -> bool {
    commands.record_event(event).is_ok()
        && send_guardian_event(&mut &*endpoint, event, phase_deadline()).is_ok()
}

fn await_tui_readiness(
    endpoint: &LifecycleEndpoint,
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    mut readiness: TuiReadinessReceiver,
    app: &mut ManagedGroupChild,
    tui: &mut ManagedGroupChild,
    output_pump: &GuardianOutputPump,
) -> (
    Option<VerifiedTuiReadiness>,
    bool,
    Option<(Phase, FailureCode)>,
) {
    let deadline = startup_deadline();
    loop {
        match readiness.poll() {
            Ok(Some(readiness)) => return (Some(readiness), true, None),
            Ok(None) => {}
            Err(_) => {
                return (
                    None,
                    true,
                    Some((Phase::Readiness, FailureCode::InvalidControl)),
                );
            }
        }
        if output_pump.is_finished() {
            return (None, true, Some((Phase::Readiness, FailureCode::EarlyExit)));
        }
        match (
            app.poll_liveness(phase_deadline()),
            tui.poll_liveness(phase_deadline()),
        ) {
            (Ok(ChildLiveness::Running), Ok(ChildLiveness::Running)) => {}
            (Ok(_), Ok(_)) => {
                return (None, true, Some((Phase::Readiness, FailureCode::EarlyExit)));
            }
            _ => {
                return (
                    None,
                    true,
                    Some((Phase::Readiness, FailureCode::Containment)),
                );
            }
        }
        match lifecycle_readable(endpoint, Duration::ZERO) {
            Ok(true) => {
                let command = commands.receive(phase_deadline());
                return (
                    None,
                    command.is_ok(),
                    Some((Phase::Protocol, FailureCode::InvalidControl)),
                );
            }
            Ok(false) => {}
            Err(_) => {
                return (
                    None,
                    false,
                    Some((Phase::Protocol, FailureCode::InvalidControl)),
                );
            }
        }
        if Instant::now() >= deadline {
            return (None, true, Some((Phase::Readiness, FailureCode::Timeout)));
        }
        thread::sleep(EVENT_POLL);
    }
}

#[derive(Clone, Copy)]
struct GuardianControlFailure {
    phase: Phase,
    code: FailureCode,
    channel_live: bool,
}

impl GuardianControlFailure {
    const fn app_early_exit() -> Self {
        Self {
            phase: Phase::AppServer,
            code: FailureCode::EarlyExit,
            channel_live: true,
        }
    }

    const fn readiness(code: FailureCode, channel_live: bool) -> Self {
        Self {
            phase: Phase::Readiness,
            code,
            channel_live,
        }
    }

    const fn containment() -> Self {
        Self {
            phase: Phase::Reap,
            code: FailureCode::Containment,
            channel_live: true,
        }
    }

    const fn pump() -> Self {
        Self {
            phase: Phase::Pump,
            code: FailureCode::Pump,
            channel_live: true,
        }
    }

    const fn signal(channel_live: bool) -> Self {
        Self {
            phase: Phase::Signal,
            code: FailureCode::Signal,
            channel_live,
        }
    }

    const fn protocol(channel_live: bool) -> Self {
        Self {
            phase: Phase::Protocol,
            code: FailureCode::InvalidControl,
            channel_live,
        }
    }
}

fn verify_guardian_gate_liveness<P: GuardianGateWaitPump>(
    app: &mut ManagedGroupChild,
    tui: &mut ManagedGroupChild,
    pump: &P,
) -> Result<(), GuardianControlFailure> {
    match app.poll_liveness(phase_deadline()) {
        Ok(ChildLiveness::Running) => {}
        Ok(ChildLiveness::Exited) => return Err(GuardianControlFailure::app_early_exit()),
        Err(_) => return Err(GuardianControlFailure::containment()),
    }
    match tui.poll_liveness(phase_deadline()) {
        Ok(ChildLiveness::Running) => {}
        Ok(ChildLiveness::Exited) => {
            return Err(GuardianControlFailure::readiness(
                FailureCode::EarlyExit,
                true,
            ));
        }
        Err(_) => return Err(GuardianControlFailure::containment()),
    }
    if pump.gate_wait_finished() {
        return Err(GuardianControlFailure::readiness(
            FailureCode::EarlyExit,
            true,
        ));
    }
    Ok(())
}

fn await_guardian_open_input_gate<P: GuardianGateWaitPump>(
    endpoint: &LifecycleEndpoint,
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    app: &mut ManagedGroupChild,
    tui: &mut ManagedGroupChild,
    pump: &P,
) -> Result<GuardianOpenGate, GuardianControlFailure> {
    let deadline = phase_deadline();
    loop {
        verify_guardian_gate_liveness(app, tui, pump)?;
        match lifecycle_readable(endpoint, Duration::ZERO) {
            Ok(true) => {
                match commands.receive(phase_deadline()) {
                    Ok(CoordinatorCommand::OpenInputGate) => {}
                    Ok(_) => return Err(GuardianControlFailure::protocol(true)),
                    Err(_) => return Err(GuardianControlFailure::protocol(false)),
                }
                // Receiving the command is not the gate linearization point.
                // Recheck exact child and pump liveness immediately before
                // minting the sole capability that can start terminal input.
                verify_guardian_gate_liveness(app, tui, pump)?;
                return Ok(GuardianOpenGate { _private: () });
            }
            Ok(false) => {}
            Err(_) => return Err(GuardianControlFailure::protocol(false)),
        }
        if Instant::now() >= deadline {
            return Err(GuardianControlFailure::readiness(
                FailureCode::Timeout,
                true,
            ));
        }
        thread::sleep(EVENT_POLL);
    }
}

fn suspend_active_guardian(
    endpoint: &LifecycleEndpoint,
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    tui: &mut ManagedGroupChild,
    pump: &mut GuardianDuplexPump,
) -> Result<(), GuardianControlFailure> {
    pump.pause_input()
        .map_err(|_| GuardianControlFailure::pump())?;
    pump.discard_pending_input()
        .map_err(|_| GuardianControlFailure::pump())?;

    let started_at = Instant::now();
    let graceful_deadline = started_at
        .checked_add(SHUTDOWN_GRACE)
        .ok_or_else(|| GuardianControlFailure::signal(true))?;
    let forced_deadline = graceful_deadline
        .checked_add(SHUTDOWN_FORCE)
        .ok_or_else(|| GuardianControlFailure::signal(true))?;
    tui.suspend(graceful_deadline, forced_deadline)
        .map_err(|_| GuardianControlFailure::signal(true))?;
    if !emit_guardian_event(commands, endpoint, GuardianEvent::Suspended) {
        return Err(GuardianControlFailure::signal(false));
    }
    Ok(())
}

fn resume_active_guardian(
    endpoint: &LifecycleEndpoint,
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    app: &mut ManagedGroupChild,
    tui: &mut ManagedGroupChild,
    pump: &mut GuardianDuplexPump,
    rows: u16,
    cols: u16,
) -> Result<(), GuardianControlFailure> {
    if rows == 0 || cols == 0 {
        return Err(GuardianControlFailure::protocol(true));
    }
    let size = TerminalSize::new(rows, cols);
    pump.set_pty_size(size)
        .map_err(|_| GuardianControlFailure::signal(true))?;
    tui.resume(phase_deadline())
        .map_err(|_| GuardianControlFailure::signal(true))?;
    if !emit_guardian_event(commands, endpoint, GuardianEvent::Resumed { rows, cols }) {
        return Err(GuardianControlFailure::signal(false));
    }
    let gate = await_guardian_open_input_gate(endpoint, commands, app, tui, pump)?;
    pump.restart_input(gate)
        .map_err(|_| GuardianControlFailure::pump())?;
    if !emit_guardian_event(commands, endpoint, GuardianEvent::InputGateOpened) {
        return Err(GuardianControlFailure::protocol(false));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_active_guardian(
    endpoint: &LifecycleEndpoint,
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    scenario: Scenario,
    provider_lease: ProfileLease,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    mut app: ManagedGroupChild,
    mut tui: ManagedGroupChild,
    pump: GuardianDuplexPump,
) -> Result<ExitCode, FixtureError> {
    let mut pump = Some(pump);
    let mut suspended = false;
    loop {
        if scenario == Scenario::PtyOutputBackpressure {
            match marker_exists("test.release-fault") {
                Ok(true) => {
                    let forwarded = match tui.forward_terminal_shutdown_signal(
                        TerminalShutdownSignal::Term,
                        phase_deadline(),
                    ) {
                        Ok(forwarded) => forwarded,
                        Err(_) => {
                            return finish_terminal_guardian(
                                endpoint,
                                commands,
                                provider_lease,
                                recovery,
                                snapshot,
                                runtime,
                                worker,
                                Some(app),
                                Some(tui),
                                pump.take().map(GuardianPumpState::Duplex),
                                Some((Phase::Signal, FailureCode::Signal)),
                                true,
                            );
                        }
                    };
                    if wait_for_exact_marker("tui.signal-term-ignored", b"ignored\n").is_err() {
                        return finish_terminal_guardian_after_forwarded_signal(
                            endpoint,
                            commands,
                            provider_lease,
                            recovery,
                            snapshot,
                            runtime,
                            worker,
                            Some(app),
                            tui,
                            forwarded,
                            pump.take().map(GuardianPumpState::Duplex),
                            Some((Phase::Signal, FailureCode::Signal)),
                            true,
                        );
                    }
                    return finish_terminal_guardian_after_forwarded_signal(
                        endpoint,
                        commands,
                        provider_lease,
                        recovery,
                        snapshot,
                        runtime,
                        worker,
                        Some(app),
                        tui,
                        forwarded,
                        pump.take().map(GuardianPumpState::Duplex),
                        Some((Phase::Pump, FailureCode::Pump)),
                        true,
                    );
                }
                Ok(false) => {}
                Err(_) => {
                    return finish_terminal_guardian(
                        endpoint,
                        commands,
                        provider_lease,
                        recovery,
                        snapshot,
                        runtime,
                        worker,
                        Some(app),
                        Some(tui),
                        pump.take().map(GuardianPumpState::Duplex),
                        Some((Phase::Protocol, FailureCode::Internal)),
                        true,
                    );
                }
            }
        }
        match (
            app.poll_liveness(phase_deadline()),
            tui.poll_liveness(phase_deadline()),
        ) {
            (Ok(ChildLiveness::Running), Ok(ChildLiveness::Running)) => {}
            (Ok(ChildLiveness::Running), Ok(ChildLiveness::Exited)) => {
                let drain_deadline = phase_deadline();
                while pump.as_ref().is_some_and(|pump| !pump.is_finished())
                    && Instant::now() < drain_deadline
                {
                    thread::sleep(EVENT_POLL);
                }
                let mut drain_failure = None;
                if pump.as_ref().is_some_and(GuardianDuplexPump::is_finished) {
                    let Some(finished) = pump.take() else {
                        return finish_terminal_guardian(
                            endpoint,
                            commands,
                            provider_lease,
                            recovery,
                            snapshot,
                            runtime,
                            worker,
                            Some(app),
                            Some(tui),
                            None,
                            Some((Phase::Pump, FailureCode::Pump)),
                            true,
                        );
                    };
                    match finished.join_finished() {
                        Ok(PumpExit::LeftEof | PumpExit::Stopped) => {}
                        Ok(PumpExit::RightEof | PumpExit::Failed) => {
                            drain_failure = Some((Phase::Pump, FailureCode::Pump));
                        }
                        Err(running) => pump = Some(running),
                    }
                } else {
                    drain_failure = Some((Phase::Pump, FailureCode::Timeout));
                }
                return finish_terminal_guardian(
                    endpoint,
                    commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    pump.take().map(GuardianPumpState::Duplex),
                    drain_failure,
                    true,
                );
            }
            (Ok(ChildLiveness::Exited), _) => {
                return finish_terminal_guardian(
                    endpoint,
                    commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    pump.take().map(GuardianPumpState::Duplex),
                    Some((Phase::AppServer, FailureCode::EarlyExit)),
                    true,
                );
            }
            _ => {
                return finish_terminal_guardian(
                    endpoint,
                    commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    pump.take().map(GuardianPumpState::Duplex),
                    Some((Phase::Reap, FailureCode::Containment)),
                    true,
                );
            }
        }

        if pump.as_ref().is_some_and(GuardianDuplexPump::is_finished) {
            let Some(finished) = pump.take() else {
                return finish_terminal_guardian(
                    endpoint,
                    commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    None,
                    Some((Phase::Pump, FailureCode::Pump)),
                    true,
                );
            };
            let exit = match finished.join_finished() {
                Ok(exit) => exit,
                Err(running_pump) => {
                    pump = Some(running_pump);
                    thread::sleep(EVENT_POLL);
                    continue;
                }
            };
            // Terminal-byte EOF is a pump failure, not lifecycle EOF. The two
            // sockets are independent capabilities, so keep the lifecycle
            // channel live long enough to publish FAILED -> QUIESCED ->
            // DISARMED -> REAPED even when either pump direction closes.
            let failure = match exit {
                PumpExit::LeftEof | PumpExit::RightEof | PumpExit::Failed | PumpExit::Stopped => {
                    Some((Phase::Pump, FailureCode::Pump))
                }
            };
            return finish_terminal_guardian(
                endpoint,
                commands,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                Some(app),
                Some(tui),
                None,
                failure,
                true,
            );
        }

        match lifecycle_readable(endpoint, EVENT_POLL) {
            Ok(false) => continue,
            Err(_) => {
                return finish_terminal_guardian(
                    endpoint,
                    commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    pump.take().map(GuardianPumpState::Duplex),
                    Some((Phase::Protocol, FailureCode::InvalidControl)),
                    false,
                );
            }
            Ok(true) => {}
        }
        match commands.receive(phase_deadline()) {
            Ok(CoordinatorCommand::Stop) => {
                return finish_terminal_guardian(
                    endpoint,
                    commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    pump.take().map(GuardianPumpState::Duplex),
                    None,
                    true,
                );
            }
            Ok(CoordinatorCommand::Signal { signal }) => {
                if let Some(shutdown_signal) = match signal {
                    UnixSignal::Hup => Some(TerminalShutdownSignal::Hup),
                    UnixSignal::Term => Some(TerminalShutdownSignal::Term),
                    UnixSignal::Int | UnixSignal::Quit => None,
                } {
                    let forwarded = match tui
                        .forward_terminal_shutdown_signal(shutdown_signal, phase_deadline())
                    {
                        Ok(forwarded) => forwarded,
                        Err(_) => {
                            return finish_terminal_guardian(
                                endpoint,
                                commands,
                                provider_lease,
                                recovery,
                                snapshot,
                                runtime,
                                worker,
                                Some(app),
                                Some(tui),
                                pump.take().map(GuardianPumpState::Duplex),
                                Some((Phase::Signal, FailureCode::Signal)),
                                true,
                            );
                        }
                    };
                    let channel_live = emit_guardian_event(
                        commands,
                        endpoint,
                        GuardianEvent::SignalForwarded { signal },
                    );
                    return finish_terminal_guardian_after_forwarded_signal(
                        endpoint,
                        commands,
                        provider_lease,
                        recovery,
                        snapshot,
                        runtime,
                        worker,
                        Some(app),
                        tui,
                        forwarded,
                        pump.take().map(GuardianPumpState::Duplex),
                        (!channel_live).then_some((Phase::Signal, FailureCode::Signal)),
                        channel_live,
                    );
                }

                let Some(interactive_signal) = InteractiveTerminalSignal::from_unix_signal(signal)
                else {
                    return finish_terminal_guardian(
                        endpoint,
                        commands,
                        provider_lease,
                        recovery,
                        snapshot,
                        runtime,
                        worker,
                        Some(app),
                        Some(tui),
                        pump.take().map(GuardianPumpState::Duplex),
                        Some((Phase::Signal, FailureCode::Signal)),
                        true,
                    );
                };
                let forwarded =
                    tui.forward_interactive_terminal_signal(interactive_signal, phase_deadline());
                let channel_live = forwarded.is_ok()
                    && emit_guardian_event(
                        commands,
                        endpoint,
                        GuardianEvent::SignalForwarded { signal },
                    );
                if !channel_live {
                    return finish_terminal_guardian(
                        endpoint,
                        commands,
                        provider_lease,
                        recovery,
                        snapshot,
                        runtime,
                        worker,
                        Some(app),
                        Some(tui),
                        pump.take().map(GuardianPumpState::Duplex),
                        Some((Phase::Signal, FailureCode::Signal)),
                        forwarded.is_err(),
                    );
                }
            }
            Ok(CoordinatorCommand::Suspend) if !suspended => {
                let outcome = match pump.as_mut() {
                    Some(pump) => suspend_active_guardian(endpoint, commands, &mut tui, pump),
                    None => Err(GuardianControlFailure::pump()),
                };
                if let Err(control_failure) = outcome {
                    return finish_terminal_guardian(
                        endpoint,
                        commands,
                        provider_lease,
                        recovery,
                        snapshot,
                        runtime,
                        worker,
                        Some(app),
                        Some(tui),
                        pump.take().map(GuardianPumpState::Duplex),
                        Some((control_failure.phase, control_failure.code)),
                        control_failure.channel_live,
                    );
                }
                suspended = true;
            }
            Ok(CoordinatorCommand::Resume { rows, cols }) if suspended => {
                if scenario == Scenario::PtyResumeFailure {
                    let failure = if write_marker("guardian.resume-failure-injected", b"injected\n")
                        .is_ok()
                    {
                        (Phase::Signal, FailureCode::Signal)
                    } else {
                        (Phase::Signal, FailureCode::Internal)
                    };
                    return finish_terminal_guardian_with_failure_quiescence_barrier(
                        endpoint,
                        commands,
                        provider_lease,
                        recovery,
                        snapshot,
                        runtime,
                        worker,
                        Some(app),
                        Some(tui),
                        pump.take().map(GuardianPumpState::Duplex),
                        Some(failure),
                        true,
                    );
                }
                let outcome = match pump.as_mut() {
                    Some(pump) => resume_active_guardian(
                        endpoint, commands, &mut app, &mut tui, pump, rows, cols,
                    ),
                    None => Err(GuardianControlFailure::pump()),
                };
                if let Err(mut control_failure) = outcome {
                    if scenario == Scenario::PtyTuiExitBeforeResumeGate
                        && control_failure.phase == Phase::Readiness
                        && control_failure.code == FailureCode::EarlyExit
                        && write_marker("guardian.pre-resume-gate-failure", b"observed\n").is_err()
                    {
                        control_failure.code = FailureCode::Internal;
                    }
                    return finish_terminal_guardian(
                        endpoint,
                        commands,
                        provider_lease,
                        recovery,
                        snapshot,
                        runtime,
                        worker,
                        Some(app),
                        Some(tui),
                        pump.take().map(GuardianPumpState::Duplex),
                        Some((control_failure.phase, control_failure.code)),
                        control_failure.channel_live,
                    );
                }
                suspended = false;
            }
            Ok(CoordinatorCommand::Resize { rows, cols }) => {
                let size = TerminalSize::new(rows, cols);
                let resized = pump
                    .as_ref()
                    .ok_or(FixtureError::Invariant)
                    .and_then(|pump| pump.set_pty_size(size))
                    .and_then(|()| {
                        tui.notify_terminal_resize(phase_deadline())
                            .map(|_liveness| ())
                            .map_err(|_| FixtureError::Process)
                    });
                if resized.is_err()
                    || !emit_guardian_event(
                        commands,
                        endpoint,
                        GuardianEvent::ResizeApplied { rows, cols },
                    )
                {
                    return finish_terminal_guardian(
                        endpoint,
                        commands,
                        provider_lease,
                        recovery,
                        snapshot,
                        runtime,
                        worker,
                        Some(app),
                        Some(tui),
                        pump.take().map(GuardianPumpState::Duplex),
                        Some((Phase::Signal, FailureCode::Signal)),
                        resized.is_ok(),
                    );
                }
            }
            Ok(_) => {
                return finish_terminal_guardian(
                    endpoint,
                    commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    pump.take().map(GuardianPumpState::Duplex),
                    Some((Phase::Signal, FailureCode::InvalidControl)),
                    true,
                );
            }
            Err(_) => {
                return finish_terminal_guardian(
                    endpoint,
                    commands,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    Some(app),
                    Some(tui),
                    pump.take().map(GuardianPumpState::Duplex),
                    Some((Phase::Protocol, FailureCode::InvalidControl)),
                    false,
                );
            }
        }
    }
}

enum GuardianTuiShutdown {
    Standard(Option<ManagedGroupChild>),
    SignalAlreadyForwarded {
        tui: ManagedGroupChild,
        proof: ForwardedTuiSignal,
    },
}

/// Linear proof that the optional duplex pump was either absent or consumed
/// by a successful bounded stop. A pump that retains a live join handle is
/// diverted to the generic fail-closed retained state before this can exist.
struct GuardianPumpsStopped {
    _private: (),
}

impl GuardianPumpsStopped {
    const fn new() -> Self {
        Self { _private: () }
    }
}

struct RetainedTerminalGuardianState<'endpoint> {
    endpoint: &'endpoint LifecycleEndpoint,
    provider_lease: ProfileLease,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    app: Option<ManagedGroupChild>,
    tui_shutdown: GuardianTuiShutdown,
    pump: Option<GuardianPumpState>,
}

impl RetainedTerminalGuardianState<'_> {
    fn park(self) -> ! {
        let _ = (
            self.endpoint.as_fd(),
            self.provider_lease.provider_lock_file(),
            self.recovery.descriptor_identity(),
            self.snapshot.descriptor_identity(),
            self.runtime.path(),
            self.worker.handle.is_some(),
            self.app.is_some(),
            &self.tui_shutdown,
            self.pump.is_some(),
        );
        std::mem::forget(self);
        loop {
            thread::park();
        }
    }
}

/// Move-only evidence for the sole fixture state where cooperative guardian
/// release is safe: the terminal restore was rejected because another living
/// process group owns the foreground, every direct app/TUI child was exactly
/// reaped, and no pump authority remains. The release marker is only a trigger
/// observed *after* this proof exists; it is never treated as authority.
/// `FixtureWorker` is currently an in-process, receive-blocked marker thread;
/// if it ever owns an external process or durable mutation, a bounded
/// stop/join proof must become another required field here before cooperative
/// release remains valid.
struct ForegroundReclaimRetentionProof {
    _pumps_stopped: GuardianPumpsStopped,
    reaped_children: ReapedChildren,
    _not_foreground: NotForegroundRestoreRefusal,
}

struct NotForegroundRestoreRefusal {
    _private: (),
}

struct RetainedForegroundReclaimGuardianState<'endpoint> {
    endpoint: &'endpoint LifecycleEndpoint,
    provider_lease: ProfileLease,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    proof: ForegroundReclaimRetentionProof,
}

impl RetainedForegroundReclaimGuardianState<'_> {
    fn park(self) -> ! {
        let _ = (
            self.endpoint.as_fd(),
            self.provider_lease.provider_lock_file(),
            self.recovery.descriptor_identity(),
            self.snapshot.descriptor_identity(),
            self.runtime.path(),
            self.worker.handle.is_some(),
            self.proof.reaped_children.app_server(),
            self.proof.reaped_children.tui(),
            &self.proof._pumps_stopped,
            &self.proof._not_foreground,
        );
        if write_marker("guardian.foreground-reclaim-retained", b"children-reaped\n").is_err() {
            std::mem::forget(self);
            loop {
                thread::park();
            }
        }
        loop {
            if test_capability_released("test.resolve-foreground-reclaim").unwrap_or(false)
                && write_marker("guardian.foreground-reclaim-resolved", b"self-exit\n").is_ok()
            {
                // The refusal proof intentionally remains on disk, but
                // process exit closes B and the sole recovery descriptor.
                // No recovery-disarmed/restored proof is fabricated.
                std::process::exit(i32::from(EXIT_FAILURE));
            }
            thread::sleep(EVENT_POLL);
        }
    }
}

struct RetainedTerminalUnreapedState<'endpoint> {
    endpoint: &'endpoint LifecycleEndpoint,
    provider_lease: ProfileLease,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    unreaped: Box<UnreapedChildren>,
}

impl RetainedTerminalUnreapedState<'_> {
    fn park(self) -> ! {
        let _ = (
            self.endpoint.as_fd(),
            self.provider_lease.provider_lock_file(),
            self.recovery.descriptor_identity(),
            self.snapshot.descriptor_identity(),
            self.runtime.path(),
            self.worker.handle.is_some(),
            &self.unreaped,
        );
        std::mem::forget(self);
        loop {
            thread::park();
        }
    }
}

struct RetainedRestoredTerminalWorkerState<'endpoint> {
    endpoint: &'endpoint LifecycleEndpoint,
    provider_lease: ProfileLease,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
}

/// Fail-closed state for an impossible post-drop recovery identity. The raw
/// descriptor, if one exists, remains in this parked process's fd table while
/// the semantic snapshot and every remaining lease/runtime authority stay
/// owned. No recovery-disarmed event can be emitted from this state.
struct RetainedLeakedRecoveryState<'endpoint> {
    endpoint: &'endpoint LifecycleEndpoint,
    provider_lease: ProfileLease,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
}

impl RetainedLeakedRecoveryState<'_> {
    fn park(self) -> ! {
        let _ = (
            self.endpoint.as_fd(),
            self.provider_lease.provider_lock_file(),
            self.snapshot.descriptor_identity(),
            self.runtime.path(),
            self.worker.handle.is_some(),
        );
        std::mem::forget(self);
        loop {
            thread::park();
        }
    }
}

enum RecoveryDisarmFailure {
    StillArmed(RecoveryTty),
    UnconfirmedAfterDrop,
}

fn disarm_recovery_tty(recovery: RecoveryTty) -> Result<(), RecoveryDisarmFailure> {
    let identity = recovery.descriptor_identity();
    if !matches!(
        calcifer_unix_child_fd::count_open_descriptors_with_identity(identity),
        Ok(1)
    ) {
        return Err(RecoveryDisarmFailure::StillArmed(recovery));
    }
    drop(recovery);
    if !matches!(
        calcifer_unix_child_fd::count_open_descriptors_with_identity(identity),
        Ok(0)
    ) || write_marker("guardian.recovery-disarmed", b"zero\n").is_err()
    {
        return Err(RecoveryDisarmFailure::UnconfirmedAfterDrop);
    }
    Ok(())
}

impl RetainedRestoredTerminalWorkerState<'_> {
    fn park(self) -> ! {
        let _ = (
            self.endpoint.as_fd(),
            self.provider_lease.provider_lock_file(),
            self.runtime.path(),
            self.worker.handle.is_some(),
        );
        std::mem::forget(self);
        loop {
            thread::park();
        }
    }
}

struct RetainedRestoredTerminalCleanupState<'endpoint> {
    endpoint: &'endpoint LifecycleEndpoint,
    provider_lease: ProfileLease,
    cleanup: Option<RuntimeCleanupFailure>,
}

impl RetainedRestoredTerminalCleanupState<'_> {
    fn park(mut self) -> ! {
        let _ = (
            self.endpoint.as_fd(),
            self.provider_lease.provider_lock_file(),
            self.cleanup.as_ref().map(RuntimeCleanupFailure::error),
        );
        let _ = write_marker("guardian.cleanup-retained", b"retained\n");
        if !CLEANUP_RESOLUTION_ENABLED.load(Ordering::Acquire) {
            std::mem::forget(self);
            loop {
                thread::park();
            }
        }
        loop {
            if cleanup_resolution_requested() {
                let Some(cleanup) = self.cleanup.take() else {
                    thread::park();
                    continue;
                };
                match cleanup.resolve_fixture_synthetic_unknown_entry() {
                    Ok(_clean) => {
                        if write_marker("guardian.cleanup-resolved", b"resolved\n").is_ok() {
                            let Self {
                                endpoint: _,
                                provider_lease,
                                cleanup: _,
                            } = self;
                            drop(provider_lease);
                            std::process::exit(i32::from(EXIT_FAILURE));
                        }
                    }
                    Err(cleanup) => self.cleanup = Some(cleanup),
                }
            }
            thread::sleep(EVENT_POLL);
        }
    }
}

struct RetainedRestoredTerminalProviderState<'endpoint> {
    endpoint: &'endpoint LifecycleEndpoint,
    provider_lease: ProfileLease,
}

impl RetainedRestoredTerminalProviderState<'_> {
    fn park(self) -> ! {
        let _ = (
            self.endpoint.as_fd(),
            self.provider_lease.provider_lock_file(),
        );
        std::mem::forget(self);
        loop {
            thread::park();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn restore_and_park_terminal_guardian(
    endpoint: &LifecycleEndpoint,
    provider_lease: ProfileLease,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    app: Option<ManagedGroupChild>,
    tui_shutdown: GuardianTuiShutdown,
    pump: Option<GuardianPumpState>,
) -> ! {
    if let Some(pump) = pump.as_ref() {
        let _ = pump.shutdown_terminal_channel();
    }
    let _ = endpoint.shutdown();
    match restore_snapshot_with_sigttou_block(&snapshot, &recovery) {
        Ok(()) => {
            let _ = write_restored_marker_idempotent();
        }
        Err(error) => {
            let _ = write_marker("terminal.restore-error", error.code().as_bytes());
        }
    }
    RetainedTerminalGuardianState {
        endpoint,
        provider_lease,
        recovery,
        snapshot,
        runtime,
        worker,
        app,
        tui_shutdown,
        pump,
    }
    .park()
}

#[allow(clippy::too_many_arguments)]
fn restore_and_park_unreaped_terminal_guardian(
    endpoint: &LifecycleEndpoint,
    provider_lease: ProfileLease,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    unreaped: Box<UnreapedChildren>,
) -> ! {
    let _ = endpoint.shutdown();
    match restore_snapshot_with_sigttou_block(&snapshot, &recovery) {
        Ok(()) => {
            let _ = write_restored_marker_idempotent();
        }
        Err(error) => {
            let _ = write_marker("terminal.restore-error", error.code().as_bytes());
        }
    }
    RetainedTerminalUnreapedState {
        endpoint,
        provider_lease,
        recovery,
        snapshot,
        runtime,
        worker,
        unreaped,
    }
    .park()
}

#[allow(clippy::too_many_arguments)]
fn finish_terminal_guardian(
    endpoint: &LifecycleEndpoint,
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    provider_lease: ProfileLease,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    app: Option<ManagedGroupChild>,
    tui: Option<ManagedGroupChild>,
    pump: Option<GuardianPumpState>,
    failure: Option<(Phase, FailureCode)>,
    channel_live: bool,
) -> Result<ExitCode, FixtureError> {
    finish_terminal_guardian_inner(
        endpoint,
        commands,
        provider_lease,
        recovery,
        snapshot,
        runtime,
        worker,
        app,
        GuardianTuiShutdown::Standard(tui),
        pump,
        failure,
        channel_live,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_terminal_guardian_with_failure_quiescence_barrier(
    endpoint: &LifecycleEndpoint,
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    provider_lease: ProfileLease,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    app: Option<ManagedGroupChild>,
    tui: Option<ManagedGroupChild>,
    pump: Option<GuardianPumpState>,
    failure: Option<(Phase, FailureCode)>,
    channel_live: bool,
) -> Result<ExitCode, FixtureError> {
    finish_terminal_guardian_inner(
        endpoint,
        commands,
        provider_lease,
        recovery,
        snapshot,
        runtime,
        worker,
        app,
        GuardianTuiShutdown::Standard(tui),
        pump,
        failure,
        channel_live,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_terminal_guardian_after_forwarded_signal(
    endpoint: &LifecycleEndpoint,
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    provider_lease: ProfileLease,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    app: Option<ManagedGroupChild>,
    tui: ManagedGroupChild,
    proof: ForwardedTuiSignal,
    pump: Option<GuardianPumpState>,
    failure: Option<(Phase, FailureCode)>,
    channel_live: bool,
) -> Result<ExitCode, FixtureError> {
    finish_terminal_guardian_inner(
        endpoint,
        commands,
        provider_lease,
        recovery,
        snapshot,
        runtime,
        worker,
        app,
        GuardianTuiShutdown::SignalAlreadyForwarded { tui, proof },
        pump,
        failure,
        channel_live,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_terminal_guardian_inner(
    endpoint: &LifecycleEndpoint,
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    provider_lease: ProfileLease,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    app: Option<ManagedGroupChild>,
    tui_shutdown: GuardianTuiShutdown,
    pump: Option<GuardianPumpState>,
    mut failure: Option<(Phase, FailureCode)>,
    mut channel_live: bool,
    hold_after_announced_failure: bool,
) -> Result<ExitCode, FixtureError> {
    let mut failure_announced = false;
    if channel_live {
        if let Some((phase, code)) = failure {
            if emit_guardian_event(commands, endpoint, GuardianEvent::Failed { phase, code }) {
                failure_announced = true;
            } else {
                channel_live = false;
            }
        }
    }
    if channel_live
        && failure_announced
        && hold_after_announced_failure
        && (write_marker("guardian.failure-announced-held", b"held\n").is_err()
            || wait_for_exact_marker("test.release-quiescence", b"release\n").is_err())
    {
        channel_live = false;
    }

    let pumps_stopped = match pump {
        Some(pump) => match pump.stop() {
            Ok(PumpExit::Failed | PumpExit::RightEof) => {
                if failure.is_none() {
                    failure = Some((Phase::Pump, FailureCode::Pump));
                }
                GuardianPumpsStopped::new()
            }
            Ok(PumpExit::Stopped | PumpExit::LeftEof) => GuardianPumpsStopped::new(),
            Err(pump) => {
                if channel_live && !failure_announced {
                    let _ = emit_guardian_event(
                        commands,
                        endpoint,
                        GuardianEvent::Failed {
                            phase: Phase::Pump,
                            code: FailureCode::Timeout,
                        },
                    );
                }
                restore_and_park_terminal_guardian(
                    endpoint,
                    provider_lease,
                    recovery,
                    snapshot,
                    runtime,
                    worker,
                    app,
                    tui_shutdown,
                    Some(pump),
                )
            }
        },
        None => GuardianPumpsStopped::new(),
    };

    let shutdown_result = match tui_shutdown {
        GuardianTuiShutdown::Standard(tui) => {
            shutdown_pair(tui, app, SHUTDOWN_GRACE, SHUTDOWN_FORCE)
        }
        GuardianTuiShutdown::SignalAlreadyForwarded { tui, proof } => {
            shutdown_pair_after_forwarded_tui_signal(
                tui,
                app,
                proof,
                SHUTDOWN_GRACE,
                SHUTDOWN_FORCE,
            )
        }
    };
    let shutdown = match shutdown_result {
        Ok(shutdown) => shutdown,
        Err(unreaped) => restore_and_park_unreaped_terminal_guardian(
            endpoint,
            provider_lease,
            recovery,
            snapshot,
            runtime,
            worker,
            unreaped,
        ),
    };
    if failure.is_none() && shutdown.failure().is_some() {
        failure = Some((Phase::Reap, FailureCode::Containment));
    }
    let children = shutdown.children();
    let natural_tui_exit = matches!(
        children.tui(),
        ChildDisposition::Exited {
            stop_action: StopAction::None,
            ..
        }
    );
    if failure.is_none()
        && [children.app_server(), children.tui()]
            .into_iter()
            .any(disposition_required_kill)
    {
        failure = Some((Phase::Shutdown, FailureCode::Containment));
    }

    if channel_live && failure.is_some() && !failure_announced {
        let (phase, code) = failure.unwrap_or((Phase::Pump, FailureCode::Pump));
        if emit_guardian_event(commands, endpoint, GuardianEvent::Failed { phase, code }) {
            failure_announced = true;
        } else {
            channel_live = false;
        }
    }

    // `TerminalQuiesced` is emitted only after the pumps are stopped and both
    // direct children have exact reap proof. Worker join and runtime cleanup
    // happen after recovery, because either may need permanent retention.
    if channel_live && !emit_guardian_event(commands, endpoint, GuardianEvent::TerminalQuiesced) {
        channel_live = false;
    }
    if channel_live {
        channel_live = receive_terminal_restored(commands, natural_tui_exit);
    }

    if channel_live {
        match disarm_recovery_tty(recovery) {
            Ok(()) => {}
            Err(RecoveryDisarmFailure::StillArmed(recovery)) => restore_and_park_terminal_guardian(
                endpoint,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                GuardianTuiShutdown::Standard(None),
                None,
            ),
            Err(RecoveryDisarmFailure::UnconfirmedAfterDrop) => {
                let _ = endpoint.shutdown();
                RetainedLeakedRecoveryState {
                    endpoint,
                    provider_lease,
                    snapshot,
                    runtime,
                    worker,
                }
                .park()
            }
        }
        consume_terminal_snapshot(snapshot);
        if !emit_guardian_event(commands, endpoint, GuardianEvent::TerminalRecoveryDisarmed) {
            channel_live = false;
        }
    } else {
        match restore_snapshot_with_sigttou_block(&snapshot, &recovery) {
            Ok(()) => {
                if write_restored_marker_idempotent().is_err()
                    || write_marker("guardian.fallback-restored", b"restored\n").is_err()
                {
                    // Child reap proof already exists, but the terminal
                    // recovery capability and every remaining authority must
                    // still be retained.
                    restore_and_park_terminal_guardian(
                        endpoint,
                        provider_lease,
                        recovery,
                        snapshot,
                        runtime,
                        worker,
                        None,
                        GuardianTuiShutdown::Standard(None),
                        None,
                    )
                }
            }
            Err(error) => {
                let error_marker_written =
                    write_marker("terminal.restore-error", error.code().as_bytes()).is_ok();
                match error {
                    GuardedRestoreError::Terminal(TerminalError::NotForegroundProcessGroup)
                        if error_marker_written
                            && FOREGROUND_RECLAIM_RESOLUTION_ENABLED.load(Ordering::Acquire) =>
                    {
                        RetainedForegroundReclaimGuardianState {
                            endpoint,
                            provider_lease,
                            recovery,
                            snapshot,
                            runtime,
                            worker,
                            proof: ForegroundReclaimRetentionProof {
                                _pumps_stopped: pumps_stopped,
                                reaped_children: children,
                                _not_foreground: NotForegroundRestoreRefusal { _private: () },
                            },
                        }
                        .park()
                    }
                    _ => {
                        // Every other restore refusal remains permanently
                        // fail-closed. In particular, a synthetic resolution
                        // marker cannot release live child or pump authority
                        // through the generic retained state.
                        restore_and_park_terminal_guardian(
                            endpoint,
                            provider_lease,
                            recovery,
                            snapshot,
                            runtime,
                            worker,
                            None,
                            GuardianTuiShutdown::Standard(None),
                            None,
                        )
                    }
                }
            }
        }
        match disarm_recovery_tty(recovery) {
            Ok(()) => {}
            Err(RecoveryDisarmFailure::StillArmed(recovery)) => restore_and_park_terminal_guardian(
                endpoint,
                provider_lease,
                recovery,
                snapshot,
                runtime,
                worker,
                None,
                GuardianTuiShutdown::Standard(None),
                None,
            ),
            Err(RecoveryDisarmFailure::UnconfirmedAfterDrop) => RetainedLeakedRecoveryState {
                endpoint,
                provider_lease,
                snapshot,
                runtime,
                worker,
            }
            .park(),
        }
        consume_terminal_snapshot(snapshot);
    }

    let worker_status = match worker.join_bounded() {
        Ok(status) => status,
        Err(worker) => {
            let _ = endpoint.shutdown();
            RetainedRestoredTerminalWorkerState {
                endpoint,
                provider_lease,
                runtime,
                worker,
            }
            .park()
        }
    };
    if failure.is_none() && worker_status != WorkerJoinStatus::JoinedClean {
        failure = Some((Phase::Worker, FailureCode::Worker));
    }
    let cleanup = match runtime.cleanup() {
        Ok(cleanup) => cleanup,
        Err(cleanup) => {
            let _ = endpoint.shutdown();
            RetainedRestoredTerminalCleanupState {
                endpoint,
                provider_lease,
                cleanup: Some(cleanup),
            }
            .park()
        }
    };
    let _cleanup_proof = cleanup;

    if channel_live && failure.is_some() && !failure_announced {
        let (phase, code) = failure.unwrap_or((Phase::Cleanup, FailureCode::Internal));
        if emit_guardian_event(commands, endpoint, GuardianEvent::Failed { phase, code }) {
            failure_announced = true;
        } else {
            channel_live = false;
        }
    }
    let _ = failure_announced;

    if write_marker("guardian.cleaned", b"complete\n").is_err() {
        let _ = endpoint.shutdown();
        RetainedRestoredTerminalProviderState {
            endpoint,
            provider_lease,
        }
        .park()
    }
    let session = if failure.is_some() {
        SessionStatus::Failed
    } else {
        SessionStatus::Completed
    };
    if !channel_live {
        drop(provider_lease);
        return Ok(ExitCode::from(EXIT_FAILURE));
    }
    if !emit_guardian_event(
        commands,
        endpoint,
        GuardianEvent::ChildrenReaped {
            app: children.app_server(),
            tui: children.tui(),
            worker: worker_status,
            cleanup: CleanupStatus::Complete,
            session,
        },
    ) {
        let _ = endpoint.shutdown();
        RetainedRestoredTerminalProviderState {
            endpoint,
            provider_lease,
        }
        .park()
    }
    drop(provider_lease);
    Ok(if session == SessionStatus::Completed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    })
}

fn receive_terminal_restored(
    commands: &mut GuardianCommandReceiver<&LifecycleEndpoint>,
    natural_tui_exit: bool,
) -> bool {
    let first = commands.receive(phase_deadline());
    if matches!(first, Ok(CoordinatorCommand::TerminalRestored)) {
        return true;
    }
    let superseded_interactive_control = matches!(
        first,
        Ok(CoordinatorCommand::Signal {
            signal: UnixSignal::Int | UnixSignal::Quit,
        } | CoordinatorCommand::Resize { .. })
    );
    // The validator accepts `OpenInputGate` here only when a failure left the
    // pre-gate state before a concurrently written command was consumed.
    // Unlike best-effort interactive controls, this drain does not depend on
    // which child triggered the failure.
    let superseded_pre_gate_control = matches!(first, Ok(CoordinatorCommand::OpenInputGate));
    (superseded_pre_gate_control || natural_tui_exit && superseded_interactive_control)
        && matches!(
            commands.receive(phase_deadline()),
            Ok(CoordinatorCommand::TerminalRestored)
        )
}

fn write_restored_marker_idempotent() -> Result<(), FixtureError> {
    let path = marker_path("terminal.restored")?;
    write_exact_idempotent_marker(&path, b"restored\n", phase_deadline())
}

fn write_exact_idempotent_marker(
    path: &Path,
    expected: &[u8],
    deadline: Instant,
) -> Result<(), FixtureError> {
    if expected.is_empty() || expected.len() > 32 {
        return Err(FixtureError::Invariant);
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(expected)
                .map_err(|_| FixtureError::Storage)?;
            file.sync_all().map_err(|_| FixtureError::Storage)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            wait_for_exact_idempotent_marker(path, expected, deadline)
        }
        Err(_) => Err(FixtureError::Storage),
    }
}

fn wait_for_exact_idempotent_marker(
    path: &Path,
    expected: &[u8],
    deadline: Instant,
) -> Result<(), FixtureError> {
    loop {
        match fs::read(path) {
            Ok(value) if value == expected => {
                let metadata = fs::symlink_metadata(path).map_err(|_| FixtureError::Storage)?;
                if metadata.file_type().is_file()
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.permissions().mode() & 0o777 == 0o600
                {
                    return Ok(());
                }
                return Err(FixtureError::Storage);
            }
            // The winning create-new writer may not have completed its fixed
            // payload yet. Only a strict prefix may converge; any other value
            // is a conflicting proof and fails immediately.
            Ok(value) if expected.starts_with(&value) && Instant::now() < deadline => {
                thread::sleep(EVENT_POLL);
            }
            Ok(_) => return Err(FixtureError::Storage),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) && Instant::now() < deadline =>
            {
                thread::sleep(EVENT_POLL);
            }
            Err(_) => return Err(FixtureError::Storage),
        }
    }
}
