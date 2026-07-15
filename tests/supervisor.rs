#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const MARKER_ROOT_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_MARKER_ROOT";
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(12);
const CONTENDER_TIMEOUT: Duration = Duration::from_secs(3);
const DROP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CAPTURE_BYTES: usize = 4 * 1024;
const MAX_OUTER_PTY_BYTES: usize = 4 * 1024;
const MAX_BACKPRESSURE_DISCARD_BYTES: usize = 256 * 1024;
const EXIT_FAILURE: i32 = 70;
const EXIT_BUSY: i32 = 75;
const PRE_READY_SENTINEL: &[u8] = b"calcifer-pre-ready-sentinel\n";
const POST_READY_SENTINEL: &[u8] = b"calcifer-post-ready-sentinel\n";
const SUSPENDED_SENTINEL: &[u8] = b"calcifer-suspended-sentinel\n";
const RELEASE_MARKER_PAYLOAD: &[u8] = b"release\n";
const TUI_EXIT_BYTE: &[u8] = b"\x04";
const OUTER_PTY_WINSIZE: rustix::termios::Winsize = rustix::termios::Winsize {
    ws_row: 37,
    ws_col: 111,
    ws_xpixel: 0,
    ws_ypixel: 0,
};

static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_SANDBOX: AtomicU64 = AtomicU64::new(0);
static NEXT_CAPTURE: AtomicU64 = AtomicU64::new(0);

struct ObservedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// A child whose output cannot hold the test open and whose process group is
/// always killed and polled during unwinding.
struct BoundedChild {
    child: Option<Child>,
    reaped: bool,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl BoundedChild {
    fn spawn(mut command: Command, capture_root: &Path, label: &str) -> TestResult<Self> {
        let capture_id = NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed);
        let stdout_path = capture_root.join(format!("{label}-{capture_id}.stdout"));
        let stderr_path = capture_root.join(format!("{label}-{capture_id}.stderr"));
        let stdout = private_output_file(&stdout_path)?;
        let stderr = private_output_file(&stderr_path)?;
        command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let child = command.spawn()?;
        Ok(Self {
            child: Some(child),
            reaped: false,
            stdout_path,
            stderr_path,
        })
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("the bounded child was already consumed"))?
            .try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    fn wait(mut self, timeout: Duration) -> TestResult<ObservedOutput> {
        let status = match wait_for_child(self.child_mut()?, timeout) {
            Ok(status) => status,
            Err(error) => {
                self.force_kill();
                if wait_for_child(self.child_mut()?, DROP_CLEANUP_TIMEOUT).is_ok() {
                    // The exact child has now been reaped. Record that before
                    // returning the original timeout so Drop cannot signal a
                    // numeric PID that the kernel is free to reuse.
                    self.reaped = true;
                }
                return Err(error.into());
            }
        };
        self.capture(status)
    }

    fn kill_and_wait(mut self) -> TestResult<ObservedOutput> {
        self.force_kill();
        let status = wait_for_child(self.child_mut()?, DROP_CLEANUP_TIMEOUT)?;
        self.capture(status)
    }

    fn child_mut(&mut self) -> io::Result<&mut Child> {
        if self.reaped {
            return Err(io::Error::other("the bounded child was already reaped"));
        }
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("the bounded child was already consumed"))
    }

    fn force_kill(&mut self) {
        if self.reaped {
            return;
        }
        if let Some(child) = self.child.as_mut() {
            signal_owned_process_group(child, rustix::process::Signal::KILL);
            let _ = child.kill();
        }
    }

    fn capture(mut self, status: ExitStatus) -> TestResult<ObservedOutput> {
        drop(self.child.take());
        Ok(ObservedOutput {
            status,
            stdout: read_bounded_capture(&self.stdout_path)?,
            stderr: read_bounded_capture(&self.stderr_path)?,
        })
    }
}

impl Drop for BoundedChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if self.reaped {
            return;
        }
        signal_owned_process_group(&child, rustix::process::Signal::KILL);
        let _ = child.kill();
        let _ = wait_for_child(&mut child, DROP_CLEANUP_TIMEOUT);
    }
}

struct FixedPtyCapture {
    bytes: [u8; MAX_OUTER_PTY_BYTES],
    len: usize,
}

impl FixedPtyCapture {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_OUTER_PTY_BYTES],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn occurrences(&self, needle: &[u8]) -> usize {
        if needle.is_empty() {
            return 0;
        }
        self.as_bytes()
            .windows(needle.len())
            .filter(|window| *window == needle)
            .count()
    }
}

enum PtyDrainState {
    Progress,
    Idle,
    Closed,
}

/// A fixture coordinator attached to a real outer PTY.
///
/// Unlike `BoundedChild`, this deliberately does not create a process group:
/// after exec the fixture coordinator must be free to call `setsid` and claim
/// the slave with `TIOCSCTTY`. The exact `Child` handle is the only signal
/// authority retained by the test.
struct OuterPtyChild {
    child: Option<Child>,
    reaped: bool,
    kill_marker: PathBuf,
    retained_resolution_marker: Option<PathBuf>,
    master: File,
    master_closed: bool,
    capture: FixedPtyCapture,
    original_termios: rustix::termios::Termios,
    expected_winsize: rustix::termios::Winsize,
}

impl OuterPtyChild {
    fn spawn(fixture: &SupervisorCase, scenario: &str) -> TestResult<Self> {
        let master =
            rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)?;
        rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC)?;
        if !rustix::io::fcntl_getfd(&master)?.contains(rustix::io::FdFlags::CLOEXEC) {
            return Err(io::Error::other("outer PTY master was not close-on-exec").into());
        }
        rustix::pty::grantpt(&master)?;
        rustix::pty::unlockpt(&master)?;
        let slave_name = rustix::pty::ptsname(&master, Vec::new())?;
        let slave_path = Path::new(OsStr::from_bytes(slave_name.to_bytes()));
        let slave = OpenOptions::new().read(true).write(true).open(slave_path)?;
        if !rustix::termios::isatty(&master) || !rustix::termios::isatty(&slave) {
            return Err(io::Error::other("outer PTY endpoints were not terminals").into());
        }

        // Keep the pre-ready sentinel out of the transcript while retaining a
        // canonical input queue for the gate to flush before raw mode.
        let mut initial_termios = rustix::termios::tcgetattr(&slave)?;
        initial_termios
            .local_modes
            .remove(rustix::termios::LocalModes::ECHO | rustix::termios::LocalModes::ECHONL);
        rustix::termios::tcsetattr(
            &slave,
            rustix::termios::OptionalActions::Now,
            &initial_termios,
        )?;
        rustix::termios::tcsetwinsize(&slave, OUTER_PTY_WINSIZE)?;
        let original_termios = rustix::termios::tcgetattr(&slave)?;
        let original_winsize = rustix::termios::tcgetwinsize(&slave)?;
        if original_winsize != OUTER_PTY_WINSIZE {
            return Err(io::Error::other("outer PTY did not retain its initial winsize").into());
        }

        let slave_stdout = slave.try_clone()?;
        let slave_stderr = slave.try_clone()?;
        let mut command = fixture.fixture_command();
        command
            .env("TERM", "xterm-256color")
            .args(["terminal-anchor", scenario])
            .stdin(Stdio::from(slave))
            .stdout(Stdio::from(slave_stdout))
            .stderr(Stdio::from(slave_stderr));

        // Complete every fallible PTY-master configuration step before the
        // anchor is spawned. Once `command.spawn()` succeeds, `OuterPtyChild`
        // must immediately become the exact direct-child authority; otherwise
        // a post-spawn `?` could leak an untracked anchor during test unwind.
        let flags = rustix::fs::fcntl_getfl(&master)?;
        rustix::fs::fcntl_setfl(&master, flags | rustix::fs::OFlags::NONBLOCK)?;
        if !rustix::fs::fcntl_getfl(&master)?.contains(rustix::fs::OFlags::NONBLOCK) {
            return Err(io::Error::other("outer PTY master was not nonblocking").into());
        }
        let master = File::from(master);

        // Do not add `.process_group(0)` here. The child must not be a process
        // group leader before its post-exec `setsid` call.
        let child = command.spawn()?;
        Ok(Self {
            child: Some(child),
            reaped: false,
            kill_marker: fixture.markers.join("test.kill-coordinator"),
            retained_resolution_marker: (scenario == "pty-foreground-reclaim")
                .then(|| fixture.markers.join("test.resolve-foreground-reclaim")),
            master,
            master_closed: false,
            capture: FixedPtyCapture::new(),
            original_termios,
            expected_winsize: original_winsize,
        })
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.reaped {
            return Err(io::Error::other("the outer PTY child was already reaped"));
        }
        let status = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("the outer PTY child was already consumed"))?
            .try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    fn write_bytes(&mut self, mut bytes: &[u8], timeout: Duration) -> TestResult {
        let deadline = deadline_after(timeout)?;
        while !bytes.is_empty() {
            match self.master.write(bytes) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "outer PTY write returned zero",
                    )
                    .into());
                }
                Ok(written) => bytes = &bytes[written..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.drain_once()?;
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "outer PTY write exceeded its deadline",
                        )
                        .into());
                    }
                    sleep_until_next_poll(deadline);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn wait_for_marker(
        &mut self,
        fixture: &SupervisorCase,
        name: &str,
        expected: &[u8],
        timeout: Duration,
    ) -> TestResult {
        let deadline = deadline_after(timeout)?;
        loop {
            self.drain_once()?;
            if let Some(value) = fixture.read_marker(name)? {
                if value == expected {
                    return Ok(());
                }
                // Fixture markers are bounded files written before `sync_all`.
                // A concurrent reader may observe the empty or partial file
                // between `create_new` and the completed write. Treat that as
                // transient while the producing process is still live; a
                // stable malformed value still fails at the same deadline.
            }
            if let Some(status) = self.try_wait()? {
                if fixture
                    .read_marker(name)?
                    .is_some_and(|value| value != expected)
                {
                    return Err(io::Error::other(format!(
                        "marker {name} contained an unexpected bounded value"
                    ))
                    .into());
                }
                return Err(io::Error::other(format!(
                    "outer PTY fixture exited as {status} before marker {name}"
                ))
                .into());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "timed out waiting for outer PTY marker {name}"
                ))
                .into());
            }
            sleep_until_next_poll(deadline);
        }
    }

    fn wait(&mut self, timeout: Duration) -> TestResult<ExitStatus> {
        let deadline = deadline_after(timeout)?;
        loop {
            self.drain_once()?;
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                self.force_kill_and_reap();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "outer PTY fixture exceeded its deadline",
                )
                .into());
            }
            sleep_until_next_poll(deadline);
        }
    }

    /// Drains a fixed, non-recording budget only after exact terminal restore.
    /// This is reserved for the output-backpressure fault: reading earlier
    /// would remove the condition under test, while retaining unbounded output
    /// would turn the harness itself into a memory sink.
    fn wait_discarding_after_restore(
        &mut self,
        timeout: Duration,
        discard_budget: usize,
    ) -> TestResult<ExitStatus> {
        if discard_budget == 0 || !self.termios_matches_original()? {
            return Err(io::Error::other(
                "outer PTY discard requires a positive bound after terminal restore",
            )
            .into());
        }
        let deadline = deadline_after(timeout)?;
        let mut discarded = 0_usize;
        let mut status = None;
        let mut buffer = [0_u8; 4096];
        loop {
            if !self.master_closed {
                match self.master.read(&mut buffer) {
                    Ok(0) => self.master_closed = true,
                    Ok(read) => {
                        discarded = discarded.checked_add(read).ok_or_else(|| {
                            io::Error::other("outer PTY discard counter overflowed")
                        })?;
                        if discarded > discard_budget {
                            return Err(io::Error::other(
                                "outer PTY output exceeded its fixed discard bound",
                            )
                            .into());
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error)
                        if error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) =>
                    {
                        self.master_closed = true;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if status.is_none() {
                status = self.try_wait()?;
            }
            if let Some(status) = status.filter(|_| self.master_closed) {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                self.force_kill_and_reap();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "outer PTY fixed discard exceeded its deadline",
                )
                .into());
            }
            sleep_until_next_poll(deadline);
        }
    }

    fn request_coordinator_kill(&self) -> TestResult {
        if self.reaped {
            return Err(io::Error::other("outer PTY fixture was already reaped").into());
        }
        write_private_release_marker_idempotent(&self.kill_marker).map_err(Into::into)
    }

    fn drain_until_closed(&mut self, timeout: Duration) -> TestResult {
        let deadline = deadline_after(timeout)?;
        loop {
            match self.drain_once()? {
                PtyDrainState::Closed => return Ok(()),
                PtyDrainState::Progress => {}
                PtyDrainState::Idle => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "outer PTY remained open after cleanup",
                        )
                        .into());
                    }
                    sleep_until_next_poll(deadline);
                }
            }
        }
    }

    fn wait_until_restored(&mut self, timeout: Duration) -> TestResult {
        let deadline = deadline_after(timeout)?;
        loop {
            self.drain_once()?;
            if self.termios_matches_original()? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let current = rustix::termios::tcgetattr(&self.master)?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "outer PTY termios was not restored: expected={}, current={}",
                        termios_fingerprint(&self.original_termios),
                        termios_fingerprint(&current)
                    ),
                )
                .into());
            }
            sleep_until_next_poll(deadline);
        }
    }

    fn assert_raw_transition(&self) -> TestResult {
        if self.termios_matches_original()? {
            Err(io::Error::other("terminal.raw preceded the real termios transition").into())
        } else {
            Ok(())
        }
    }

    fn assert_restored(&self) -> TestResult {
        if !self.termios_matches_original()? {
            return Err(io::Error::other("outer PTY termios did not match its snapshot").into());
        }
        if rustix::termios::tcgetwinsize(&self.master)? != self.expected_winsize {
            return Err(io::Error::other("outer PTY winsize changed unexpectedly").into());
        }
        Ok(())
    }

    fn resize(&mut self, rows: u16, cols: u16) -> TestResult {
        if rows == 0 || cols == 0 {
            return Err(io::Error::other("test PTY size must be nonzero").into());
        }
        let size = rustix::termios::Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        rustix::termios::tcsetwinsize(&self.master, size)?;
        if rustix::termios::tcgetwinsize(&self.master)? != size {
            return Err(io::Error::other("test PTY resize did not persist").into());
        }
        self.expected_winsize = size;
        Ok(())
    }

    fn termios_matches_original(&self) -> TestResult<bool> {
        let current = rustix::termios::tcgetattr(&self.master)?;
        Ok(termios_fingerprint(&current) == termios_fingerprint(&self.original_termios))
    }

    fn drain_once(&mut self) -> TestResult<PtyDrainState> {
        if self.master_closed {
            return Ok(PtyDrainState::Closed);
        }
        let was_full = self.capture.len == MAX_OUTER_PTY_BYTES;
        let mut overflow_probe = [0_u8; 1];
        let target = if was_full {
            &mut overflow_probe[..]
        } else {
            &mut self.capture.bytes[self.capture.len..]
        };
        loop {
            match self.master.read(target) {
                Ok(0) => {
                    self.master_closed = true;
                    return Ok(PtyDrainState::Closed);
                }
                Ok(read) if was_full => {
                    debug_assert!(read > 0);
                    return Err(
                        io::Error::other("outer PTY output exceeded its fixed bound").into(),
                    );
                }
                Ok(read) => {
                    self.capture.len += read;
                    return Ok(PtyDrainState::Progress);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(PtyDrainState::Idle);
                }
                // Linux PTY masters report EIO once every slave descriptor is
                // closed; macOS reports an ordinary zero-length read instead.
                Err(error)
                    if error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) =>
                {
                    self.master_closed = true;
                    return Ok(PtyDrainState::Closed);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn capture(&self) -> &FixedPtyCapture {
        &self.capture
    }

    fn force_kill_and_reap(&mut self) {
        if self.reaped {
            return;
        }
        let Some(child) = self.child.as_mut() else {
            return;
        };
        // Ask the terminal anchor to kill its exact direct coordinator child
        // first. This keeps the synthetic shell session alive for guardian
        // restoration and prevents a failed test from orphaning a retained
        // coordinator. The direct anchor is force-killed only if bounded
        // cooperative cleanup cannot finish.
        if let Some(resolution) = &self.retained_resolution_marker {
            let _ = write_private_release_marker_idempotent(resolution);
        }
        let _ = write_private_release_marker_idempotent(&self.kill_marker);
        if wait_for_child(child, DROP_CLEANUP_TIMEOUT).is_ok() {
            self.reaped = true;
            return;
        }
        let _ = child.kill();
        if wait_for_child(child, DROP_CLEANUP_TIMEOUT).is_ok() {
            self.reaped = true;
        }
    }
}

impl Drop for OuterPtyChild {
    fn drop(&mut self) {
        // Only the exact Child handle is authoritative. Marker PIDs are never
        // signalled, and this spawn intentionally owns no process group.
        self.force_kill_and_reap();
    }
}

struct SupervisorCase {
    sandbox: PathBuf,
    root: PathBuf,
    markers: PathBuf,
    captures: PathBuf,
    provider_log: PathBuf,
    provider_log_baseline: Vec<u8>,
}

impl SupervisorCase {
    fn new(label: &str) -> TestResult<Self> {
        let sandbox_id = NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed);
        let raw_sandbox = std::env::temp_dir().join(format!(
            "calcifer-supervisor-integration-{}-{sandbox_id}-{label}",
            std::process::id()
        ));
        create_private_directory(&raw_sandbox)?;
        let sandbox = fs::canonicalize(raw_sandbox)?;
        let markers = sandbox.join("markers");
        let captures = sandbox.join("captures");
        let root = sandbox.join("state");
        create_private_directory(&markers)?;
        create_private_directory(&captures)?;

        let mut fixture = Self {
            sandbox,
            root,
            markers: fs::canonicalize(markers)?,
            captures: fs::canonicalize(captures)?,
            provider_log: PathBuf::new(),
            provider_log_baseline: Vec::new(),
        };
        let (path, provider_log, fake_codex) = fixture.install_fake_codex()?;
        fixture.provider_log = provider_log;

        let mut add = Command::new(calcifer_binary()?);
        add.current_dir(&fixture.sandbox)
            .env_clear()
            .env("PATH", path)
            .env("CALCIFER_HOME", &fixture.root)
            .env("FAKE_CODEX_LOG", &fixture.provider_log)
            .args(["auth", "add", "codex", "work"]);
        let output =
            BoundedChild::spawn(add, &fixture.captures, "auth-add")?.wait(PROCESS_TIMEOUT)?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "failed to create the synthetic profile: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        if !output.stderr.is_empty() {
            return Err(io::Error::other("profile setup wrote unexpected stderr").into());
        }
        fixture.root = fs::canonicalize(&fixture.root)?;
        fixture.provider_log_baseline = fs::read(&fixture.provider_log)?;
        fs::remove_file(fake_codex)?;
        Ok(fixture)
    }

    fn install_fake_codex(&self) -> TestResult<(OsString, PathBuf, PathBuf)> {
        let bin = self.sandbox.join("bin");
        create_private_directory(&bin)?;
        let provider_log = self.sandbox.join("provider.log");
        drop(private_output_file(&provider_log)?);
        let fake_codex = bin.join("codex");
        fs::write(
            &fake_codex,
            r#"#!/bin/sh
set -eu
printf 'args=%s\n' "$*" >> "$FAKE_CODEX_LOG"
if [ "${1:-}" = "-c" ]; then
  [ "${2:-}" = 'cli_auth_credentials_store="file"' ]
  [ "${3:-}" = "-c" ]
  [ "${4:-}" = 'mcp_oauth_credentials_store="file"' ]
  shift 4
fi
case "${1:-}" in
  login)
    umask 077
    printf '{"auth_mode":"chatgpt","tokens":{"account_id":"synthetic-%s-%s"}}\n' "$PPID" "$$" > "$CODEX_HOME/auth.json"
    ;;
  app-server)
    IFS= read -r initialize
    case "$initialize" in
      *'"method":"initialize"'*'"experimentalApi":false'*) ;;
      *) exit 93 ;;
    esac
    printf '{"id":0,"result":{"userAgent":"calcifer/0.144.4 (test)","platformFamily":"unix","platformOs":"test","codexHome":"%s"}}\n' "$CODEX_HOME"
    while IFS= read -r request; do
      :
    done
    ;;
  *)
    exit 94
    ;;
esac
"#,
        )?;
        fs::set_permissions(&fake_codex, fs::Permissions::from_mode(0o700))?;

        let inherited_path = std::env::var_os("PATH").unwrap_or_default();
        let mut path_entries = vec![bin];
        path_entries.extend(std::env::split_paths(&inherited_path));
        Ok((
            std::env::join_paths(path_entries)?,
            provider_log,
            fake_codex,
        ))
    }

    fn spawn_coordinator(&self, scenario: &str) -> TestResult<BoundedChild> {
        let mut command = self.fixture_command();
        command.args(["coordinator", scenario]);
        BoundedChild::spawn(command, &self.captures, scenario)
    }

    fn fixture_command(&self) -> Command {
        let mut command = Command::new(fixture_binary_path());
        command
            .current_dir(&self.sandbox)
            .env_clear()
            .env("CALCIFER_HOME", &self.root)
            .env(MARKER_ROOT_ENV, &self.markers);
        command
    }

    fn wait_for_marker(
        &self,
        mut process: Option<&mut BoundedChild>,
        name: &str,
        expected: &[u8],
        timeout: Duration,
    ) -> TestResult {
        let deadline = deadline_after(timeout)?;
        let mut observed_incomplete = false;
        loop {
            if let Some(value) = self.read_marker(name)? {
                if value == expected {
                    return Ok(());
                }
                // `write_marker` publishes an owner-private inode before its
                // bounded payload and `sync_all` complete. Treat an empty or
                // partial read as transient; a stable mismatch still fails at
                // this same bounded deadline.
                observed_incomplete = true;
            }
            if let Some(process) = process.as_deref_mut() {
                if let Some(status) = process.try_wait()? {
                    return Err(io::Error::other(format!(
                        "fixture exited as {status} before marker {name}"
                    ))
                    .into());
                }
            }
            if Instant::now() >= deadline {
                if observed_incomplete {
                    return Err(io::Error::other(format!(
                        "marker {name} contained an unexpected bounded value"
                    ))
                    .into());
                }
                return Err(
                    io::Error::other(format!("timed out waiting for marker {name}")).into(),
                );
            }
            sleep_until_next_poll(deadline);
        }
    }

    fn assert_marker(&self, name: &str, expected: &[u8]) -> TestResult {
        let value = self
            .read_marker(name)?
            .ok_or_else(|| io::Error::other(format!("marker {name} was missing")))?;
        if value == expected {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "marker {name} contained an unexpected bounded value"
            ))
            .into())
        }
    }

    fn assert_marker_absent(&self, name: &str) -> TestResult {
        if self.read_marker(name)?.is_none() {
            Ok(())
        } else {
            Err(io::Error::other(format!("marker {name} unexpectedly existed")).into())
        }
    }

    fn read_marker(&self, name: &str) -> TestResult<Option<Vec<u8>>> {
        validate_marker_name(name)?;
        let path = self.markers.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() > 64
        {
            return Err(io::Error::other(format!("marker {name} had an unsafe identity")).into());
        }
        Ok(Some(fs::read(path)?))
    }

    fn read_pid_marker(&self, name: &str) -> TestResult<i32> {
        let value = self
            .read_marker(name)?
            .ok_or_else(|| io::Error::other(format!("PID marker {name} was missing")))?;
        parse_pid_marker(&value)
    }

    fn runtime_directories(&self) -> TestResult<Vec<PathBuf>> {
        let mut runtimes = Vec::new();
        for entry in fs::read_dir(&self.markers)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| io::Error::other("marker entry name was not UTF-8"))?;
            if name.starts_with(".calcifer-supervisor-") {
                let metadata = entry.metadata()?;
                if !metadata.file_type().is_dir() {
                    return Err(io::Error::other("supervisor runtime was not a directory").into());
                }
                runtimes.push(entry.path());
            }
        }
        runtimes.sort();
        Ok(runtimes)
    }

    fn assert_no_runtime(&self) -> TestResult {
        let runtimes = self.runtime_directories()?;
        if runtimes.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other("a private runtime remained after confirmed cleanup").into())
        }
    }

    fn assert_preserved_runtime(&self, expected_entry: Option<(&str, &[u8])>) -> TestResult {
        let runtimes = self.runtime_directories()?;
        if runtimes.len() != 1 {
            return Err(io::Error::other(format!(
                "expected one preserved runtime, observed {}",
                runtimes.len()
            ))
            .into());
        }
        let runtime = &runtimes[0];
        let metadata = fs::symlink_metadata(runtime)?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(io::Error::other("the preserved runtime was not owner-private").into());
        }
        let entries = fs::read_dir(runtime)?.collect::<Result<Vec<_>, _>>()?;
        match expected_entry {
            None if entries.is_empty() => Ok(()),
            Some((name, expected)) if entries.len() == 1 => {
                let entry = &entries[0];
                if entry.file_name() != name || fs::read(entry.path())? != expected {
                    return Err(io::Error::other(
                        "the preserved runtime did not retain the unknown entry",
                    )
                    .into());
                }
                Ok(())
            }
            _ => Err(io::Error::other("the preserved runtime had unexpected contents").into()),
        }
    }

    fn wait_for_contender(&self, expected_code: i32, timeout: Duration) -> TestResult {
        let deadline = deadline_after(timeout)?;
        loop {
            let mut command = self.fixture_command();
            command.arg("contender");
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::other(format!(
                    "timed out waiting for contender exit {expected_code}"
                ))
                .into());
            }
            let output = BoundedChild::spawn(command, &self.captures, "contender")?
                .wait(remaining.min(CONTENDER_TIMEOUT))?;
            if !output.stdout.is_empty() || !output.stderr.is_empty() {
                return Err(io::Error::other("contender produced unexpected output").into());
            }
            match output.status.code() {
                Some(code) if code == expected_code => return Ok(()),
                Some(EXIT_BUSY) if expected_code == 0 && Instant::now() < deadline => {
                    sleep_until_next_poll(deadline);
                }
                observed => {
                    return Err(io::Error::other(format!(
                        "expected contender exit {expected_code}, observed {observed:?}"
                    ))
                    .into());
                }
            }
        }
    }

    fn wait_for_provider_contender(&self, expected_code: i32, timeout: Duration) -> TestResult {
        let deadline = deadline_after(timeout)?;
        loop {
            let mut command = self.fixture_command();
            command.arg("provider-contender");
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::other(format!(
                    "timed out waiting for provider contender exit {expected_code}"
                ))
                .into());
            }
            let output = BoundedChild::spawn(command, &self.captures, "provider-contender")?
                .wait(remaining.min(CONTENDER_TIMEOUT))?;
            if !output.stdout.is_empty() || !output.stderr.is_empty() {
                return Err(
                    io::Error::other("provider contender produced unexpected output").into(),
                );
            }
            match output.status.code() {
                Some(code) if code == expected_code => return Ok(()),
                Some(EXIT_BUSY) if expected_code == 0 && Instant::now() < deadline => {
                    sleep_until_next_poll(deadline);
                }
                observed => {
                    return Err(io::Error::other(format!(
                        "expected provider contender exit {expected_code}, observed {observed:?}"
                    ))
                    .into());
                }
            }
        }
    }

    fn assert_provider_untouched(&self) -> TestResult {
        if fs::read(&self.provider_log)? == self.provider_log_baseline {
            Ok(())
        } else {
            Err(io::Error::other("the supervisor invoked the fake provider").into())
        }
    }

    fn release_test_capability(&self, name: &str) -> TestResult {
        if !matches!(
            name,
            "test.release-ready"
                | "test.release-fault"
                | "test.release-output"
                | "test.resolve-cleanup"
                | "test.resolve-foreground-reclaim"
                | "test.signal-hup"
                | "test.signal-int"
                | "test.signal-quit"
                | "test.signal-term"
                | "test.signal-winch-storm"
                | "test.signal-tstp"
                | "test.signal-cont"
        ) {
            return Err(io::Error::other("test release marker was not allowlisted").into());
        }
        validate_marker_name(name)?;
        let path = self.markers.join(name);
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        marker.write_all(b"release\n")?;
        marker.sync_all()?;
        let metadata = marker.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(io::Error::other("test release marker was not owner-private").into());
        }
        self.assert_marker(name, b"release\n")
    }

    fn assert_marker_payloads_exclude(&self, needles: &[&[u8]]) -> TestResult {
        for entry in fs::read_dir(&self.markers)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_file() {
                continue;
            }
            if metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o777 != 0o600
                || metadata.len() > 64
            {
                return Err(io::Error::other("marker had an unsafe bounded identity").into());
            }
            let value = fs::read(entry.path())?;
            if needles.iter().any(|needle| contains_bytes(&value, needle)) {
                return Err(io::Error::other("a sentinel leaked into a marker payload").into());
            }
        }
        Ok(())
    }

    fn observed_cleanup_identities(&self) -> TestResult<Vec<(i32, i32)>> {
        let mut identities = Vec::new();
        for marker in ["guardian.pid", "app.pid", "tui.pid"] {
            if let Some(value) = self.read_marker(marker)? {
                let pid = parse_pid_marker(&value)?;
                identities.push((pid, pid));
            }
        }
        if let Some(value) = self.read_marker("descendant.pid")? {
            let descendant = parse_pid_marker(&value)?;
            let tui = self
                .read_marker("tui.pid")?
                .ok_or_else(|| io::Error::other("descendant marker had no TUI group"))?;
            identities.push((descendant, parse_pid_marker(&tui)?));
        }
        Ok(identities)
    }
}

impl Drop for SupervisorCase {
    fn drop(&mut self) {
        // Marker PIDs are observation-only. They may already have been reaped
        // and reused, so test cleanup must never turn them into signal
        // authority. `BoundedChild` owns and reaps the exact coordinator, then
        // this bounded observation gives the separate guardian process group
        // time to finish lifecycle-EOF cleanup. Ambiguous/live identities
        // preserve the private sandbox rather than disrupting that cleanup.
        let Ok(identities) = self.observed_cleanup_identities() else {
            return;
        };
        let Ok(deadline) = deadline_after(DROP_CLEANUP_TIMEOUT) else {
            return;
        };
        loop {
            let all_gone = identities
                .iter()
                .all(|&(pid, group)| matches!(original_process_is_gone(pid, group), Ok(true)));
            if all_gone {
                let _ = fs::remove_dir_all(&self.sandbox);
                return;
            }
            if Instant::now() >= deadline {
                return;
            }
            sleep_until_next_poll(deadline);
        }
    }
}

#[derive(Clone, Copy)]
struct CleanFailureCase {
    scenario: &'static str,
    app_started: bool,
    tui_started: bool,
}

#[derive(Clone, Copy)]
enum RetainedRuntime {
    None,
    Empty,
    UnknownEntry,
}

#[derive(Clone, Copy)]
struct RetainedCase {
    scenario: &'static str,
    worker_started: bool,
    app_started: bool,
    tui_started: bool,
    ready: bool,
    cleaned: Option<&'static [u8]>,
    runtime: RetainedRuntime,
}

#[test]
fn normal_proves_barrier_fd_hygiene_terminal_wait_and_release() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("normal")?;
    let output = fixture.spawn_coordinator("normal")?.wait(PROCESS_TIMEOUT)?;

    assert_fixed_output(&output, Some(0), b"COMPLETED\n")?;
    fixture.assert_marker("coordinator.lease", b"committed\n")?;
    fixture.assert_marker("coordinator.ready", b"ready\n")?;
    fixture.assert_marker("worker.spawn-requested", b"requested\n")?;
    fixture.assert_marker("app.spawn-requested", b"requested\n")?;
    fixture.assert_marker("tui.spawn-requested", b"requested\n")?;
    fixture.assert_marker("worker.started", b"started\n")?;
    fixture.assert_marker("app.started", b"started\n")?;
    fixture.assert_marker("tui.started", b"started\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_marker("coordinator.completed", b"complete\n")?;
    fixture.assert_marker_absent("coordinator.failed")?;
    fixture.assert_marker_absent("coordinator.retained")?;
    assert_fixture_processes_gone(&fixture, true, true, None)?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn prestart_spawn_request_is_detected_before_authority_is_released() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("barrier-violation")?;
    let mut coordinator = fixture.spawn_coordinator("barrier-violation")?;
    fixture.wait_for_marker(
        Some(&mut coordinator),
        "coordinator.retained",
        b"retained\n",
        PROCESS_TIMEOUT,
    )?;

    if coordinator.try_wait()?.is_some() {
        return Err(io::Error::other("barrier violation released the coordinator").into());
    }
    fixture.assert_marker("worker.spawn-requested", b"requested\n")?;
    fixture.assert_marker_absent("worker.started")?;
    fixture.assert_marker_absent("app.spawn-requested")?;
    fixture.assert_marker_absent("app.started")?;
    fixture.assert_marker_absent("tui.spawn-requested")?;
    fixture.assert_marker_absent("tui.started")?;
    fixture.assert_marker_absent("coordinator.lease")?;
    fixture.assert_marker_absent("coordinator.ready")?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    assert_fixture_processes_gone(&fixture, false, false, None)?;

    let output = coordinator.kill_and_wait()?;
    assert_killed_output(&output, b"RETAINED\n")?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn live_guardian_failures_reap_cleanly_and_release() -> TestResult {
    let _serial = serial_guard();
    let cases = [
        CleanFailureCase {
            scenario: "app-early-exit",
            app_started: true,
            tui_started: false,
        },
        CleanFailureCase {
            scenario: "startup-timeout",
            app_started: true,
            tui_started: false,
        },
        CleanFailureCase {
            scenario: "tui-early-exit",
            app_started: true,
            tui_started: true,
        },
        CleanFailureCase {
            scenario: "worker-failure",
            app_started: false,
            tui_started: false,
        },
    ];

    for case in cases {
        let fixture = SupervisorCase::new(case.scenario)?;
        let output = fixture
            .spawn_coordinator(case.scenario)?
            .wait(PROCESS_TIMEOUT)?;
        assert_fixed_output(&output, Some(EXIT_FAILURE), b"FAILED_CLEAN\n")?;
        fixture.assert_marker("coordinator.lease", b"committed\n")?;
        fixture.assert_marker("worker.spawn-requested", b"requested\n")?;
        fixture.assert_marker("worker.started", b"started\n")?;
        assert_requested_marker(&fixture, "app.spawn-requested", case.app_started)?;
        assert_started_marker(&fixture, "app.started", case.app_started)?;
        assert_requested_marker(&fixture, "tui.spawn-requested", case.tui_started)?;
        assert_started_marker(&fixture, "tui.started", case.tui_started)?;
        fixture.assert_marker("guardian.cleaned", b"complete\n")?;
        fixture.assert_marker("coordinator.failed", b"clean\n")?;
        fixture.assert_marker_absent("coordinator.completed")?;
        fixture.assert_marker_absent("coordinator.retained")?;
        assert_fixture_processes_gone(&fixture, case.app_started, case.tui_started, None)?;
        fixture.assert_no_runtime()?;
        fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
        fixture.assert_provider_untouched()?;
    }
    Ok(())
}

#[test]
fn stuck_descendant_is_force_contained_and_reported_failed() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("stuck-descendant")?;
    let output = fixture
        .spawn_coordinator("stuck-descendant")?
        .wait(PROCESS_TIMEOUT)?;
    assert_fixed_output(&output, Some(EXIT_FAILURE), b"FAILED_CLEAN\n")?;
    fixture.assert_marker("coordinator.lease", b"committed\n")?;
    fixture.assert_marker("coordinator.ready", b"ready\n")?;
    fixture.assert_marker("worker.spawn-requested", b"requested\n")?;
    fixture.assert_marker("app.spawn-requested", b"requested\n")?;
    fixture.assert_marker("tui.spawn-requested", b"requested\n")?;
    fixture.assert_marker("worker.started", b"started\n")?;
    fixture.assert_marker("app.started", b"started\n")?;
    fixture.assert_marker("tui.started", b"started\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_marker("coordinator.failed", b"clean\n")?;
    let descendant = fixture.read_pid_marker("descendant.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_fixture_processes_gone(&fixture, true, true, Some((descendant, tui)))?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn untrusted_guardian_endings_retain_a_until_coordinator_exit() -> TestResult {
    let _serial = serial_guard();
    let cases = [
        RetainedCase {
            scenario: "cleanup-mismatch",
            worker_started: true,
            app_started: true,
            tui_started: true,
            ready: true,
            cleaned: Some(b"unconfirmed\n"),
            runtime: RetainedRuntime::UnknownEntry,
        },
        RetainedCase {
            scenario: "malformed-frame",
            worker_started: false,
            app_started: false,
            tui_started: false,
            ready: false,
            cleaned: None,
            runtime: RetainedRuntime::None,
        },
        RetainedCase {
            scenario: "guardian-death",
            worker_started: true,
            app_started: true,
            tui_started: true,
            ready: true,
            cleaned: None,
            runtime: RetainedRuntime::Empty,
        },
        RetainedCase {
            scenario: "trailing-frame",
            worker_started: true,
            app_started: true,
            tui_started: true,
            ready: true,
            cleaned: Some(b"complete\n"),
            runtime: RetainedRuntime::None,
        },
    ];

    for case in cases {
        let fixture = SupervisorCase::new(case.scenario)?;
        let mut coordinator = fixture.spawn_coordinator(case.scenario)?;
        fixture.wait_for_marker(
            Some(&mut coordinator),
            "coordinator.retained",
            b"retained\n",
            PROCESS_TIMEOUT,
        )?;
        if coordinator.try_wait()?.is_some() {
            return Err(io::Error::other("retained coordinator exited before recovery").into());
        }
        fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
        fixture.assert_marker("coordinator.lease", b"committed\n")?;
        assert_requested_marker(&fixture, "worker.spawn-requested", case.worker_started)?;
        assert_started_marker(&fixture, "worker.started", case.worker_started)?;
        assert_requested_marker(&fixture, "app.spawn-requested", case.app_started)?;
        assert_started_marker(&fixture, "app.started", case.app_started)?;
        assert_requested_marker(&fixture, "tui.spawn-requested", case.tui_started)?;
        assert_started_marker(&fixture, "tui.started", case.tui_started)?;
        if case.ready {
            fixture.assert_marker("coordinator.ready", b"ready\n")?;
        } else {
            fixture.assert_marker_absent("coordinator.ready")?;
        }
        match case.cleaned {
            Some(value) => fixture.assert_marker("guardian.cleaned", value)?,
            None => fixture.assert_marker_absent("guardian.cleaned")?,
        }
        assert_fixture_processes_gone(&fixture, case.app_started, case.tui_started, None)?;
        match case.runtime {
            RetainedRuntime::None => fixture.assert_no_runtime()?,
            RetainedRuntime::Empty => fixture.assert_preserved_runtime(None)?,
            RetainedRuntime::UnknownEntry => {
                fixture.assert_preserved_runtime(Some(("unexpected", b"synthetic")))?;
            }
        }

        let output = coordinator.kill_and_wait()?;
        assert_killed_output(&output, b"RETAINED\n")?;
        fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
        fixture.assert_provider_untouched()?;
    }
    Ok(())
}

#[test]
fn coordinator_death_lets_guardian_finish_and_releases_os_authority() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("coordinator-death")?;
    let mut coordinator = fixture.spawn_coordinator("coordinator-death")?;
    fixture.wait_for_marker(
        Some(&mut coordinator),
        "coordinator.ready",
        b"ready\n",
        PROCESS_TIMEOUT,
    )?;
    if coordinator.try_wait()?.is_some() {
        return Err(io::Error::other("coordinator-death fixture exited before injection").into());
    }
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.assert_marker("coordinator.lease", b"committed\n")?;
    fixture.assert_marker("worker.spawn-requested", b"requested\n")?;
    fixture.assert_marker("app.spawn-requested", b"requested\n")?;
    fixture.assert_marker("tui.spawn-requested", b"requested\n")?;
    fixture.assert_marker("worker.started", b"started\n")?;
    fixture.assert_marker("app.started", b"started\n")?;
    fixture.assert_marker("tui.started", b"started\n")?;

    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    if app == tui {
        return Err(io::Error::other("fake children shared a process identity").into());
    }
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;

    let output = coordinator.kill_and_wait()?;
    assert_killed_output(&output, b"")?;
    fixture.wait_for_marker(None, "guardian.cleaned", b"complete\n", PROCESS_TIMEOUT)?;
    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_marker_absent("coordinator.completed")?;
    fixture.assert_marker_absent("coordinator.failed")?;
    fixture.assert_marker_absent("coordinator.retained")?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_discards_pre_ready_input_and_restores_on_normal_exit() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-normal")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-normal")?;

    coordinator.write_bytes(PRE_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "terminal.raw", b"raw\n", PROCESS_TIMEOUT)?;
    coordinator.assert_raw_transition()?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(
        &fixture,
        "coordinator.input-started",
        b"started\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "guardian.input-started",
        b"started\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(&fixture, "app.fd-scan", b"verified\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(&fixture, "tui.tty", b"verified\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(&fixture, "tui.fd-scan", b"verified\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(&fixture, "tui.winsize", b"37x111\n", PROCESS_TIMEOUT)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;

    coordinator.write_bytes(POST_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    coordinator.write_bytes(TUI_EXIT_BYTE, CONTENDER_TIMEOUT)?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(0))?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;

    let pre_ready_occurrences = coordinator.capture().occurrences(PRE_READY_SENTINEL);
    let post_ready_occurrences = coordinator.capture().occurrences(POST_READY_SENTINEL);
    let exit_occurrences = coordinator.capture().occurrences(TUI_EXIT_BYTE);
    if pre_ready_occurrences != 0 || post_ready_occurrences != 1 || exit_occurrences != 0 {
        return Err(io::Error::other(format!(
            "the gate did not preserve byte boundaries (pre={pre_ready_occurrences}, post={post_ready_occurrences}, exit={exit_occurrences})"
        ))
        .into());
    }
    fixture.assert_marker("coordinator.ready", b"ready\n")?;
    fixture.assert_marker("guardian.bootstrap-authority", b"single\n")?;
    fixture.assert_marker("guardian.recovery-disarmed", b"zero\n")?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_marker("coordinator.completed", b"complete\n")?;
    fixture.assert_marker_absent("coordinator.failed")?;
    fixture.assert_marker_absent("coordinator.retained")?;
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_rejects_mismatched_pre_raw_snapshot_before_any_spawn() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-snapshot-mismatch")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-snapshot-mismatch")?;

    coordinator.write_bytes(PRE_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    coordinator.wait_for_marker(
        &fixture,
        "guardian.pre-arm-fault-ready",
        b"ready\n",
        PROCESS_TIMEOUT,
    )?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    assert_group_leader(guardian)?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-fault")?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(EXIT_FAILURE))?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;
    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;

    fixture.assert_marker("coordinator.snapshot-mismatch", b"rejected\n")?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("coordinator.failed", b"clean\n")?;
    for absent in [
        "terminal.raw",
        "gate.open",
        "coordinator.ready",
        "worker.spawn-requested",
        "app.spawn-requested",
        "tui.spawn-requested",
        "guardian.cleaned",
        "coordinator.completed",
        "coordinator.retained",
    ] {
        fixture.assert_marker_absent(absent)?;
    }
    if coordinator.capture().occurrences(PRE_READY_SENTINEL) != 0 {
        return Err(io::Error::other("snapshot mismatch opened the input gate").into());
    }
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

fn assert_terminal_arm_ack_failure(
    scenario: &str,
    payload: &[u8],
    outcome_marker: &str,
) -> TestResult {
    let fixture = SupervisorCase::new(scenario)?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, scenario)?;

    coordinator.write_bytes(PRE_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    coordinator.wait_for_marker(
        &fixture,
        "coordinator.arm-ack-fault-ready",
        payload,
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "guardian.arm-ack-waiting",
        payload,
        PROCESS_TIMEOUT,
    )?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    assert_group_leader(guardian)?;
    coordinator.assert_restored()?;
    fixture.assert_marker("guardian.bootstrap-authority", b"single\n")?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    for absent in [
        "terminal.raw",
        "gate.open",
        "coordinator.input-started",
        "guardian.input-started",
        "worker.spawn-requested",
        "app.spawn-requested",
        "tui.spawn-requested",
    ] {
        fixture.assert_marker_absent(absent)?;
    }

    fixture.release_test_capability("test.release-fault")?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(EXIT_FAILURE))?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;
    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;

    fixture.assert_marker(outcome_marker, b"rejected\n")?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("coordinator.terminal-restored", b"restored\n")?;
    fixture.assert_marker("coordinator.failed", b"clean\n")?;
    for absent in [
        "terminal.raw",
        "gate.open",
        "coordinator.ready",
        "worker.spawn-requested",
        "app.spawn-requested",
        "tui.spawn-requested",
        "guardian.cleaned",
        "guardian.recovery-disarmed",
        "coordinator.completed",
        "coordinator.retained",
    ] {
        fixture.assert_marker_absent(absent)?;
    }
    if coordinator.capture().occurrences(PRE_READY_SENTINEL) != 0 {
        return Err(io::Error::other("terminal-arm ACK failure opened the input gate").into());
    }
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_terminal_arm_ack_timeout_is_pre_spawn_and_exactly_reaped() -> TestResult {
    let _serial = serial_guard();
    assert_terminal_arm_ack_failure(
        "pty-arm-ack-timeout",
        b"timeout\n",
        "coordinator.arm-ack-timeout",
    )
}

#[test]
fn gated_pty_terminal_arm_ack_disconnect_is_pre_spawn_and_exactly_reaped() -> TestResult {
    let _serial = serial_guard();
    assert_terminal_arm_ack_failure(
        "pty-arm-ack-disconnect",
        b"disconnect\n",
        "coordinator.arm-ack-disconnect",
    )
}

#[test]
fn gated_pty_rejects_pre_arm_protocol_faults_before_any_spawn() -> TestResult {
    let _serial = serial_guard();
    for scenario in [
        "pty-wrong-order",
        "pty-malformed-frame",
        "pty-trailing-frame",
    ] {
        let fixture = SupervisorCase::new(scenario)?;
        let mut coordinator = OuterPtyChild::spawn(&fixture, scenario)?;

        coordinator.write_bytes(PRE_READY_SENTINEL, CONTENDER_TIMEOUT)?;
        coordinator.wait_for_marker(
            &fixture,
            "guardian.pre-arm-fault-ready",
            b"ready\n",
            PROCESS_TIMEOUT,
        )?;
        let guardian = fixture.read_pid_marker("guardian.pid")?;
        assert_group_leader(guardian)?;
        fixture.assert_no_runtime()?;
        fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
        fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
        fixture.release_test_capability("test.release-fault")?;
        let status = coordinator.wait(PROCESS_TIMEOUT)?;
        assert_status_code(status, Some(EXIT_FAILURE))?;
        coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
        coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
        coordinator.assert_restored()?;
        wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;

        fixture.assert_marker("coordinator.protocol-rejected", b"rejected\n")?;
        fixture.assert_marker("terminal.restored", b"restored\n")?;
        fixture.assert_marker("coordinator.failed", b"clean\n")?;
        for absent in [
            "terminal.raw",
            "gate.open",
            "coordinator.ready",
            "worker.spawn-requested",
            "app.spawn-requested",
            "tui.spawn-requested",
            "guardian.cleaned",
            "coordinator.completed",
            "coordinator.retained",
        ] {
            fixture.assert_marker_absent(absent)?;
        }
        if coordinator.capture().occurrences(PRE_READY_SENTINEL) != 0 {
            return Err(io::Error::other(format!(
                "pre-arm protocol fault {scenario} opened the input gate"
            ))
            .into());
        }
        fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
        fixture.assert_no_runtime()?;
        fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
        fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
        fixture.assert_provider_untouched()?;
    }
    Ok(())
}

#[test]
fn gated_pty_readiness_timeout_stays_closed_and_restores_terminal() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-readiness-timeout")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-readiness-timeout")?;

    coordinator.write_bytes(PRE_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    coordinator.wait_for_marker(
        &fixture,
        "guardian.readiness-timeout-armed",
        b"armed\n",
        PROCESS_TIMEOUT,
    )?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-fault")?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(EXIT_FAILURE))?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;
    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;

    fixture.assert_marker_absent("test.release-ready")?;
    fixture.assert_marker_absent("terminal.raw")?;
    fixture.assert_marker_absent("gate.open")?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("guardian.bootstrap-authority", b"single\n")?;
    fixture.assert_marker("guardian.recovery-disarmed", b"zero\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_marker("coordinator.failed", b"clean\n")?;
    fixture.assert_marker_absent("coordinator.ready")?;
    fixture.assert_marker_absent("coordinator.completed")?;
    fixture.assert_marker_absent("coordinator.retained")?;
    if coordinator.capture().occurrences(PRE_READY_SENTINEL) != 0 {
        return Err(io::Error::other("pre-ready input leaked while the gate was closed").into());
    }
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_tui_early_exit_before_readiness_stays_closed_and_reaps_exactly() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-tui-early-exit")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-tui-early-exit")?;

    coordinator.write_bytes(PRE_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    coordinator.wait_for_marker(
        &fixture,
        "tui.early-exit-armed",
        b"armed\n",
        PROCESS_TIMEOUT,
    )?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-fault")?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(EXIT_FAILURE))?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;

    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_marker("tui.early-exit", b"before-readiness\n")?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_marker("coordinator.failed", b"clean\n")?;
    for absent in [
        "test.release-ready",
        "tui.ready",
        "terminal.raw",
        "gate.open",
        "coordinator.ready",
        "coordinator.completed",
        "coordinator.retained",
    ] {
        fixture.assert_marker_absent(absent)?;
    }
    if coordinator.capture().occurrences(PRE_READY_SENTINEL) != 0 {
        return Err(io::Error::other("pre-readiness input reached the early-exit TUI").into());
    }
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_ready_without_gate_ack_restores_then_retains_authority() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-ready-no-ack")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-ready-no-ack")?;

    coordinator.write_bytes(PRE_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "terminal.raw", b"raw\n", PROCESS_TIMEOUT)?;
    coordinator.assert_raw_transition()?;
    coordinator.wait_for_marker(
        &fixture,
        "guardian.no-ack-armed",
        b"armed\n",
        PROCESS_TIMEOUT,
    )?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-fault")?;
    coordinator.wait_for_marker(&fixture, "guardian.cleaned", b"complete\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(
        &fixture,
        "coordinator.retained",
        b"retained\n",
        PROCESS_TIMEOUT,
    )?;
    if coordinator.try_wait()?.is_some() {
        return Err(io::Error::other("missing gate ACK released retained authority").into());
    }
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;

    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    for absent in [
        "guardian.input-started",
        "coordinator.input-started",
        "gate.open",
        "coordinator.completed",
        "coordinator.failed",
    ] {
        fixture.assert_marker_absent(absent)?;
    }
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    if coordinator.capture().occurrences(PRE_READY_SENTINEL) != 0 {
        return Err(io::Error::other("input crossed an unacknowledged gate").into());
    }
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;

    coordinator.request_coordinator_kill()?;
    coordinator.wait_for_marker(&fixture, "coordinator.killed", b"killed\n", PROCESS_TIMEOUT)?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    if status.success() {
        return Err(
            io::Error::other("retained coordinator exited successfully after teardown").into(),
        );
    }
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.assert_restored()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_worker_failure_is_joined_only_after_terminal_restore() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-worker-failure")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-worker-failure")?;

    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    coordinator.write_bytes(POST_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    coordinator.write_bytes(TUI_EXIT_BYTE, CONTENDER_TIMEOUT)?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(EXIT_FAILURE))?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;

    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("worker.restore-observed", b"restored-before-join\n")?;
    fixture.assert_marker("worker.joined-failed", b"joined-failed\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_marker("coordinator.failed", b"clean\n")?;
    fixture.assert_marker_absent("coordinator.completed")?;
    fixture.assert_marker_absent("coordinator.retained")?;
    if coordinator.capture().occurrences(POST_READY_SENTINEL) != 1 {
        return Err(io::Error::other("worker failure changed active input delivery").into());
    }
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_terminal_channel_eof_uses_typed_cleanup_sequence() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-terminal-channel-eof")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-terminal-channel-eof")?;

    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    coordinator.write_bytes(POST_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-fault")?;
    coordinator.wait_for_marker(
        &fixture,
        "terminal.channel-eof",
        b"injected\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "terminal.restored",
        b"restored\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(&fixture, "guardian.cleaned", b"complete\n", PROCESS_TIMEOUT)?;
    fixture.assert_marker_absent("coordinator.retained")?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(EXIT_FAILURE))?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;

    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_marker("terminal.channel-eof", b"injected\n")?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_marker("coordinator.failed", b"clean\n")?;
    fixture.assert_marker_absent("coordinator.completed")?;
    fixture.assert_marker_absent("coordinator.retained")?;
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_live_tui_slave_close_becomes_bounded_pump_failure() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-slave-close-while-live")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-slave-close-while-live")?;

    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    coordinator.write_bytes(POST_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-fault")?;
    coordinator.wait_for_marker(
        &fixture,
        "tui.slave-close",
        b"closed-while-live\n",
        PROCESS_TIMEOUT,
    )?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(EXIT_FAILURE))?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;

    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("guardian.bootstrap-authority", b"single\n")?;
    fixture.assert_marker("guardian.recovery-disarmed", b"zero\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_marker("coordinator.failed", b"clean\n")?;
    fixture.assert_marker_absent("coordinator.completed")?;
    fixture.assert_marker_absent("coordinator.retained")?;
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_output_backpressure_restores_before_fixed_discard_and_kill() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-output-backpressure")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-output-backpressure")?;

    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-output")?;
    // Deliberately use marker-only waits from this point until restoration.
    // Reading the outer master here would destroy the real backpressure fault.
    fixture.wait_for_marker(None, "tui.output-started", b"started\n", PROCESS_TIMEOUT)?;
    fixture.wait_for_marker(
        None,
        "terminal.output-backpressure",
        b"observed\n",
        PROCESS_TIMEOUT,
    )?;
    fixture.release_test_capability("test.release-fault")?;
    fixture.wait_for_marker(None, "terminal.restored", b"restored\n", PROCESS_TIMEOUT)?;
    fixture.wait_for_marker(
        None,
        "tui.signal-term-ignored",
        b"ignored\n",
        PROCESS_TIMEOUT,
    )?;
    fixture.wait_for_marker(
        None,
        "tui.output-channel-closed",
        b"closed\n",
        PROCESS_TIMEOUT,
    )?;
    fixture.wait_for_marker(None, "guardian.cleaned", b"complete\n", PROCESS_TIMEOUT)?;
    fixture.wait_for_marker(None, "tui.kill-contained", b"killed\n", PROCESS_TIMEOUT)?;

    let status = coordinator
        .wait_discarding_after_restore(PROCESS_TIMEOUT, MAX_BACKPRESSURE_DISCARD_BYTES)?;
    assert_status_code(status, Some(EXIT_FAILURE))?;
    coordinator.assert_restored()?;

    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_marker("tui.term-ignore-armed", b"armed\n")?;
    fixture.assert_marker("tui.output-channel-closed", b"closed\n")?;
    fixture.assert_marker("tui.kill-contained", b"killed\n")?;
    fixture.assert_marker("coordinator.failed", b"clean\n")?;
    fixture.assert_marker_absent("coordinator.completed")?;
    fixture.assert_marker_absent("coordinator.retained")?;
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_foreground_reclaim_rejects_stale_fallback_without_clobber() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-foreground-reclaim")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-foreground-reclaim")?;

    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    coordinator.assert_raw_transition()?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;

    coordinator.request_coordinator_kill()?;
    coordinator.wait_for_marker(
        &fixture,
        "anchor.coordinator-frozen",
        b"stopped\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "anchor.foreground-reclaimed",
        b"reclaimed\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(&fixture, "coordinator.killed", b"killed\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(
        &fixture,
        "terminal.restore-error",
        b"not_foreground_process_group",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "guardian.foreground-reclaim-retained",
        b"children-reaped\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "anchor.restore-refused-observed",
        b"observed\n",
        PROCESS_TIMEOUT,
    )?;
    if coordinator.try_wait()?.is_some() {
        return Err(io::Error::other("foreground reclaim released the living anchor").into());
    }

    // The guardian was forbidden to apply the stale canonical snapshot after
    // foreground moved to the anchor, so the deliberately raw sentinel must
    // remain byte-for-byte observable here.
    coordinator.assert_raw_transition()?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    if original_process_is_gone(guardian, guardian)? {
        return Err(io::Error::other("fallback refusal released guardian authority").into());
    }
    for absent in [
        "terminal.restored",
        "guardian.fallback-restored",
        "guardian.recovery-disarmed",
        "guardian.cleaned",
        "coordinator.terminal-restored",
        "coordinator.completed",
        "coordinator.failed",
    ] {
        fixture.assert_marker_absent(absent)?;
    }
    fixture.assert_preserved_runtime(None)?;
    // B remains the cross-role exclusion authority after the coordinator/A
    // owner dies, so both lock modes must stay closed until guardian teardown.
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;

    fixture.release_test_capability("test.resolve-foreground-reclaim")?;
    coordinator.wait_for_marker(
        &fixture,
        "guardian.foreground-reclaim-resolved",
        b"self-exit\n",
        PROCESS_TIMEOUT,
    )?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(EXIT_FAILURE))?;
    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker_absent("guardian.fallback-restored")?;
    fixture.assert_marker_absent("guardian.recovery-disarmed")?;
    fixture.assert_marker_absent("guardian.cleaned")?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_foreground_reclaim_drop_cooperatively_releases_retained_guardian() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-foreground-reclaim")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-foreground-reclaim")?;
    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    coordinator.request_coordinator_kill()?;

    // Exercise the earliest unwind path directly. Drop deliberately publishes
    // the cooperative trigger before the guardian can reach its retained
    // state. The pre-existing marker must remain inert until pump-stop,
    // exact-child-reap, and NotForeground proofs are all owned by the
    // dedicated retained type.
    drop(coordinator);
    fixture.wait_for_marker(
        None,
        "terminal.restore-error",
        b"not_foreground_process_group",
        PROCESS_TIMEOUT,
    )?;
    fixture.wait_for_marker(
        None,
        "guardian.foreground-reclaim-retained",
        b"children-reaped\n",
        PROCESS_TIMEOUT,
    )?;
    fixture.wait_for_marker(
        None,
        "guardian.foreground-reclaim-resolved",
        b"self-exit\n",
        PROCESS_TIMEOUT,
    )?;
    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker_absent("guardian.recovery-disarmed")?;
    fixture.assert_marker_absent("guardian.cleaned")?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_restore_identity_mismatch_uses_guardian_fallback_and_retains_a() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-restore-identity-mismatch")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-restore-identity-mismatch")?;

    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    coordinator.write_bytes(TUI_EXIT_BYTE, CONTENDER_TIMEOUT)?;
    coordinator.wait_for_marker(
        &fixture,
        "coordinator.restore-identity-mismatch",
        b"rejected\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "guardian.fallback-restored",
        b"restored\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "coordinator.retained",
        b"retained\n",
        PROCESS_TIMEOUT,
    )?;
    if coordinator.try_wait()?.is_some() {
        return Err(io::Error::other("restore identity mismatch released A").into());
    }
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;

    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("guardian.bootstrap-authority", b"single\n")?;
    fixture.assert_marker("guardian.recovery-disarmed", b"zero\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_marker_absent("coordinator.terminal-restored")?;
    fixture.assert_marker_absent("coordinator.completed")?;
    fixture.assert_marker_absent("coordinator.failed")?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;

    coordinator.request_coordinator_kill()?;
    coordinator.wait_for_marker(&fixture, "coordinator.killed", b"killed\n", PROCESS_TIMEOUT)?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    if status.success() {
        return Err(
            io::Error::other("retained coordinator exited successfully after teardown").into(),
        );
    }
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.assert_restored()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_cleanup_mismatch_retains_a_b_until_exact_resolution() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-cleanup-mismatch")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-cleanup-mismatch")?;

    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(Some(("unexpected", b"synthetic")))?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    coordinator.write_bytes(TUI_EXIT_BYTE, CONTENDER_TIMEOUT)?;
    coordinator.wait_for_marker(
        &fixture,
        "terminal.restored",
        b"restored\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "guardian.cleanup-retained",
        b"retained\n",
        PROCESS_TIMEOUT,
    )?;
    fixture.assert_marker("guardian.bootstrap-authority", b"single\n")?;
    fixture.assert_marker("guardian.recovery-disarmed", b"zero\n")?;
    coordinator.wait_for_marker(
        &fixture,
        "coordinator.retained",
        b"retained\n",
        PROCESS_TIMEOUT,
    )?;
    if coordinator.try_wait()?.is_some() {
        return Err(io::Error::other("cleanup mismatch released retained authority").into());
    }
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;

    if original_process_is_gone(guardian, guardian)? {
        return Err(io::Error::other("guardian released B before cleanup resolution").into());
    }
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_marker("coordinator.terminal-restored", b"restored\n")?;
    fixture.assert_marker_absent("guardian.fallback-restored")?;
    fixture.assert_marker_absent("coordinator.completed")?;
    fixture.assert_marker_absent("coordinator.failed")?;
    fixture.assert_marker_absent("guardian.cleaned")?;
    fixture.assert_preserved_runtime(Some(("unexpected", b"synthetic")))?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;

    fixture.release_test_capability("test.resolve-cleanup")?;
    coordinator.wait_for_marker(
        &fixture,
        "guardian.cleanup-resolved",
        b"resolved\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "coordinator.cleanup-resolved",
        b"exact-child-reaped\n",
        PROCESS_TIMEOUT,
    )?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(EXIT_FAILURE))?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.assert_restored()?;
    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_guardian_death_restores_before_retaining_authority() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-guardian-death")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-guardian-death")?;

    coordinator.write_bytes(PRE_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "terminal.raw", b"raw\n", PROCESS_TIMEOUT)?;
    coordinator.assert_raw_transition()?;
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-fault")?;
    coordinator.wait_for_marker(
        &fixture,
        "coordinator.retained",
        b"retained\n",
        PROCESS_TIMEOUT,
    )?;
    if coordinator.try_wait()?.is_some() {
        return Err(io::Error::other("guardian loss released the coordinator").into());
    }
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;

    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker_absent("gate.open")?;
    fixture.assert_marker_absent("guardian.cleaned")?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    fixture.assert_preserved_runtime(None)?;
    if coordinator.capture().occurrences(PRE_READY_SENTINEL) != 0 {
        return Err(io::Error::other("pre-ready input reached the fake TUI").into());
    }
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;

    coordinator.request_coordinator_kill()?;
    coordinator.wait_for_marker(&fixture, "coordinator.killed", b"killed\n", PROCESS_TIMEOUT)?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    if status.success() {
        return Err(io::Error::other("fault-injected coordinator exited successfully").into());
    }
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.assert_restored()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_coordinator_death_uses_guardian_fallback_and_releases() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-coordinator-death")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-coordinator-death")?;

    coordinator.write_bytes(PRE_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "terminal.raw", b"raw\n", PROCESS_TIMEOUT)?;
    coordinator.assert_raw_transition()?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(&fixture, "tui.tty", b"verified\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(&fixture, "tui.fd-scan", b"verified\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(&fixture, "tui.winsize", b"37x111\n", PROCESS_TIMEOUT)?;
    fixture.assert_preserved_runtime(None)?;
    fixture.wait_for_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;
    fixture.wait_for_provider_contender(EXIT_BUSY, CONTENDER_TIMEOUT)?;

    let guardian = fixture.read_pid_marker("guardian.pid")?;
    let app = fixture.read_pid_marker("app.pid")?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    assert_group_leader(guardian)?;
    assert_group_leader(app)?;
    assert_group_leader(tui)?;
    coordinator.request_coordinator_kill()?;
    coordinator.wait_for_marker(&fixture, "coordinator.killed", b"killed\n", PROCESS_TIMEOUT)?;

    fixture.wait_for_marker(None, "terminal.restored", b"restored\n", PROCESS_TIMEOUT)?;
    fixture.wait_for_marker(None, "guardian.cleaned", b"complete\n", PROCESS_TIMEOUT)?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    if status.success() {
        return Err(io::Error::other("SIGKILLed coordinator exited successfully").into());
    }
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;
    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;

    fixture.assert_no_runtime()?;
    fixture.wait_for_provider_contender(0, CONTENDER_TIMEOUT)?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_marker_absent("coordinator.completed")?;
    fixture.assert_marker_absent("coordinator.failed")?;
    fixture.assert_marker_absent("coordinator.retained")?;
    if coordinator.capture().occurrences(PRE_READY_SENTINEL) != 0 {
        return Err(io::Error::other("pre-ready input crossed the gate").into());
    }
    fixture.assert_marker_payloads_exclude(&[PRE_READY_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_forwards_handled_signals_and_coalesces_resize_storms() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-signals")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-signals")?;

    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;

    fixture.release_test_capability("test.signal-int")?;
    coordinator.wait_for_marker(
        &fixture,
        "coordinator.signal-int",
        b"forwarded\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(&fixture, "tui.signal-int", b"handled\n", PROCESS_TIMEOUT)?;

    fixture.release_test_capability("test.signal-quit")?;
    coordinator.wait_for_marker(
        &fixture,
        "coordinator.signal-quit",
        b"forwarded\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(&fixture, "tui.signal-quit", b"handled\n", PROCESS_TIMEOUT)?;

    coordinator.resize(41, 123)?;
    fixture.release_test_capability("test.signal-winch-storm")?;
    coordinator.wait_for_marker(&fixture, "coordinator.resize", b"41x123\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(&fixture, "tui.resized", b"41x123\n", PROCESS_TIMEOUT)?;

    coordinator.write_bytes(POST_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    coordinator.write_bytes(TUI_EXIT_BYTE, CONTENDER_TIMEOUT)?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    if !status.success() {
        return Err(io::Error::other("handled terminal signals changed the final status").into());
    }
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;
    if coordinator.capture().occurrences(POST_READY_SENTINEL) != 1 {
        return Err(io::Error::other("TUI stopped handling input after INT/QUIT/WINCH").into());
    }
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_marker_payloads_exclude(&[POST_READY_SENTINEL])?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_preserves_hup_and_term_dispositions_after_cleanup() -> TestResult {
    use signal_hook::consts::signal::{SIGHUP, SIGTERM};

    let _serial = serial_guard();
    for (scenario, request, expected_signal) in [
        ("pty-hup", "test.signal-hup", SIGHUP),
        ("pty-term", "test.signal-term", SIGTERM),
    ] {
        let fixture = SupervisorCase::new(scenario)?;
        let mut coordinator = OuterPtyChild::spawn(&fixture, scenario)?;
        fixture.release_test_capability("test.release-ready")?;
        coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
        fixture.release_test_capability(request)?;
        fixture.wait_for_marker(None, "terminal.restored", b"restored\n", PROCESS_TIMEOUT)?;
        fixture.wait_for_marker(None, "guardian.cleaned", b"complete\n", PROCESS_TIMEOUT)?;
        let status = coordinator.wait(PROCESS_TIMEOUT)?;
        if status.signal() != Some(expected_signal) {
            return Err(io::Error::other(
                "terminal signal disposition was flattened after checked cleanup",
            )
            .into());
        }
        coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
        coordinator.assert_restored()?;
        fixture.assert_no_runtime()?;
        fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
        fixture.assert_provider_untouched()?;
    }
    Ok(())
}

#[test]
fn gated_pty_preserves_nonzero_tui_exit_after_cleanup() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-exit-nonzero")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-exit-nonzero")?;
    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    coordinator.write_bytes(TUI_EXIT_BYTE, CONTENDER_TIMEOUT)?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    assert_status_code(status, Some(23))?;
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.assert_restored()?;
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

#[test]
fn gated_pty_suspend_restores_and_resume_requires_a_fresh_gate() -> TestResult {
    let _serial = serial_guard();
    let fixture = SupervisorCase::new("pty-suspend-resume")?;
    let mut coordinator = OuterPtyChild::spawn(&fixture, "pty-suspend-resume")?;
    fixture.release_test_capability("test.release-ready")?;
    coordinator.wait_for_marker(&fixture, "gate.open", b"open\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(&fixture, "tui.heartbeat-armed", b"armed\n", PROCESS_TIMEOUT)?;
    let tui = fixture.read_pid_marker("tui.pid")?;
    let descendant = fixture.read_pid_marker("descendant.pid")?;
    assert_process_group(descendant, tui)?;
    let heartbeat_before_suspend = read_heartbeat(&fixture)?;
    wait_for_heartbeat_after(&fixture, heartbeat_before_suspend, CONTENDER_TIMEOUT)?;

    fixture.release_test_capability("test.signal-tstp")?;
    coordinator.wait_for_marker(
        &fixture,
        "tui.leader-self-stop",
        b"stopping\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "anchor.coordinator-stopped",
        b"stopped\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.wait_for_marker(
        &fixture,
        "terminal.suspended-restored",
        b"restored\n",
        PROCESS_TIMEOUT,
    )?;
    coordinator.assert_restored()?;
    let suspended_heartbeat = read_heartbeat(&fixture)?;
    thread::sleep(Duration::from_millis(250));
    if read_heartbeat(&fixture)? != suspended_heartbeat {
        return Err(io::Error::other(
            "a TSTP-handling descendant kept running after the Suspended ACK",
        )
        .into());
    }
    coordinator.write_bytes(SUSPENDED_SENTINEL, CONTENDER_TIMEOUT)?;
    coordinator.resize(43, 125)?;

    fixture.release_test_capability("test.signal-cont")?;
    coordinator.wait_for_marker(&fixture, "gate.reopened", b"open\n", PROCESS_TIMEOUT)?;
    coordinator.wait_for_marker(&fixture, "tui.resumed", b"43x125\n", PROCESS_TIMEOUT)?;
    coordinator.assert_raw_transition()?;
    wait_for_heartbeat_after(&fixture, suspended_heartbeat, CONTENDER_TIMEOUT)?;

    coordinator.write_bytes(POST_READY_SENTINEL, CONTENDER_TIMEOUT)?;
    coordinator.write_bytes(TUI_EXIT_BYTE, CONTENDER_TIMEOUT)?;
    let status = coordinator.wait(PROCESS_TIMEOUT)?;
    if !status.success() {
        return Err(io::Error::other("resumed session did not complete cleanly").into());
    }
    coordinator.drain_until_closed(DROP_CLEANUP_TIMEOUT)?;
    coordinator.wait_until_restored(CONTENDER_TIMEOUT)?;
    coordinator.assert_restored()?;
    wait_pid_gone(descendant, tui, CONTENDER_TIMEOUT)?;
    if coordinator.capture().occurrences(SUSPENDED_SENTINEL) != 0 {
        return Err(io::Error::other("input typed while suspended replayed after resume").into());
    }
    if coordinator.capture().occurrences(POST_READY_SENTINEL) != 1 {
        return Err(io::Error::other(
            "post-resume input did not cross the fresh gate exactly once",
        )
        .into());
    }
    fixture.assert_marker("terminal.restored", b"restored\n")?;
    fixture.assert_marker("guardian.cleaned", b"complete\n")?;
    fixture.assert_marker_payloads_exclude(&[SUSPENDED_SENTINEL, POST_READY_SENTINEL])?;
    fixture.assert_no_runtime()?;
    fixture.wait_for_contender(0, CONTENDER_TIMEOUT)?;
    fixture.assert_provider_untouched()?;
    Ok(())
}

fn read_heartbeat(fixture: &SupervisorCase) -> TestResult<u64> {
    let bytes = fixture
        .read_marker("tui.heartbeat")?
        .ok_or_else(|| io::Error::other("TUI descendant heartbeat was missing"))?;
    let encoded: [u8; 8] = bytes
        .try_into()
        .map_err(|_| io::Error::other("TUI descendant heartbeat was malformed"))?;
    Ok(u64::from_be_bytes(encoded))
}

fn wait_for_heartbeat_after(
    fixture: &SupervisorCase,
    baseline: u64,
    timeout: Duration,
) -> TestResult<u64> {
    let deadline = deadline_after(timeout)?;
    loop {
        let heartbeat = read_heartbeat(fixture)?;
        if heartbeat > baseline {
            return Ok(heartbeat);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TUI descendant heartbeat did not advance",
            )
            .into());
        }
        sleep_until_next_poll(deadline);
    }
}

fn serial_guard() -> MutexGuard<'static, ()> {
    match PROCESS_TEST_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn calcifer_binary() -> TestResult<PathBuf> {
    Ok(fs::canonicalize(env!("CARGO_BIN_EXE_calcifer"))?)
}

fn fixture_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_calcifer-supervisor-fixture"))
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn private_output_file(path: &Path) -> io::Result<fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn write_private_release_marker_idempotent(path: &Path) -> io::Result<()> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut marker) => {
            marker.write_all(RELEASE_MARKER_PAYLOAD)?;
            marker.sync_all()?;
            validate_private_release_marker_file(&marker)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }

    // Re-open without following symlinks and validate the visible inode. This
    // makes an existing marker idempotent only when it is the exact bounded,
    // owner-private capability created by this harness; `exists()+write()`
    // would instead introduce a substitution window and follow symlinks.
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let mut marker = File::from(descriptor);
    validate_private_release_marker_file(&marker)?;
    let mut payload = [0_u8; RELEASE_MARKER_PAYLOAD.len()];
    marker.read_exact(&mut payload)?;
    if payload != RELEASE_MARKER_PAYLOAD {
        return Err(io::Error::other(
            "test release marker had an unexpected payload",
        ));
    }
    Ok(())
}

fn validate_private_release_marker_file(marker: &File) -> io::Result<()> {
    let metadata = marker.metadata()?;
    let expected_len = u64::try_from(RELEASE_MARKER_PAYLOAD.len())
        .map_err(|_| io::Error::other("test release marker length overflowed"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != expected_len
    {
        return Err(io::Error::other(
            "test release marker was not an exact owner-private file",
        ));
    }
    Ok(())
}

fn read_bounded_capture(path: &Path) -> TestResult<Vec<u8>> {
    let value = fs::read(path)?;
    if value.len() > MAX_CAPTURE_BYTES {
        Err(io::Error::other("fixture output exceeded its test bound").into())
    } else {
        Ok(value)
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn termios_fingerprint(termios: &rustix::termios::Termios) -> String {
    // rustix exposes every semantic termios field through Debug (including
    // every special code and both decoded speeds), but intentionally does not
    // implement PartialEq because the platform layouts vary. PENDIN is a
    // kernel-maintained reprocessing request rather than stable user state;
    // Darwin may set it while returning to canonical mode, so both production
    // restore readback and this independent harness deliberately mask it.
    let mut stable = termios.clone();
    stable
        .local_modes
        .remove(rustix::termios::LocalModes::PENDIN);
    format!("{stable:?}")
}

fn assert_status_code(status: ExitStatus, expected: Option<i32>) -> TestResult {
    if status.code() == expected {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "expected outer PTY fixture exit {expected:?}, observed {:?}",
            status.code()
        ))
        .into())
    }
}

fn deadline_after(timeout: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::other("test deadline overflowed"))
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = deadline_after(timeout)?;
    let mut attempted = false;
    loop {
        if attempted && Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture process exceeded its deadline",
            ));
        }
        attempted = true;
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => sleep_until_next_poll(deadline),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn sleep_until_next_poll(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if !remaining.is_zero() {
        thread::sleep(remaining.min(POLL_INTERVAL));
    }
}

fn signal_owned_process_group(child: &Child, signal: rustix::process::Signal) {
    let pid = rustix::process::Pid::from_child(child);
    if rustix::process::getpgid(Some(pid)).is_ok_and(|group| group == pid) {
        let _ = rustix::process::kill_process_group(pid, signal);
    }
}

fn validate_marker_name(name: &str) -> io::Result<()> {
    if !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'.' || byte == b'-')
    {
        Ok(())
    } else {
        Err(io::Error::other("test marker name was invalid"))
    }
}

fn parse_pid_marker(value: &[u8]) -> TestResult<i32> {
    let digits = if value.last() == Some(&b'\n') {
        &value[..value.len().saturating_sub(1)]
    } else {
        value
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(io::Error::other("PID marker was not a bounded decimal PID").into());
    }
    let text = std::str::from_utf8(digits)?;
    let pid: i32 = text.parse()?;
    if rustix::process::Pid::from_raw(pid).is_none() {
        return Err(io::Error::other("PID marker was not positive").into());
    }
    Ok(pid)
}

fn assert_group_leader(raw_pid: i32) -> TestResult {
    let pid = rustix::process::Pid::from_raw(raw_pid)
        .ok_or_else(|| io::Error::other("process-group PID was invalid"))?;
    match rustix::process::getpgid(Some(pid)) {
        Ok(group) if group == pid => Ok(()),
        Ok(_) => Err(io::Error::other("fixture process was not its process-group leader").into()),
        Err(error) => {
            Err(io::Error::other(format!("fixture process-group lookup failed: {error}")).into())
        }
    }
}

fn assert_process_group(raw_pid: i32, raw_group: i32) -> TestResult {
    let pid = rustix::process::Pid::from_raw(raw_pid)
        .ok_or_else(|| io::Error::other("fixture process PID was invalid"))?;
    let expected_group = rustix::process::Pid::from_raw(raw_group)
        .ok_or_else(|| io::Error::other("fixture process group was invalid"))?;
    match rustix::process::getpgid(Some(pid)) {
        Ok(group) if group == expected_group => Ok(()),
        Ok(_) => Err(io::Error::other("fixture descendant escaped its process group").into()),
        Err(error) => Err(error.into()),
    }
}

fn wait_pid_gone(raw_pid: i32, expected_group: i32, timeout: Duration) -> TestResult {
    let deadline = deadline_after(timeout)?;
    loop {
        if original_process_is_gone(raw_pid, expected_group)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "fixture PID {raw_pid} remained in process group {expected_group}"
            ))
            .into());
        }
        sleep_until_next_poll(deadline);
    }
}

fn original_process_is_gone(raw_pid: i32, expected_group: i32) -> TestResult<bool> {
    let pid = rustix::process::Pid::from_raw(raw_pid)
        .ok_or_else(|| io::Error::other("fixture PID was invalid"))?;
    match rustix::process::getpgid(Some(pid)) {
        Err(rustix::io::Errno::SRCH) => Ok(true),
        Ok(group) => Ok(group.as_raw_pid() != expected_group),
        Err(error) => {
            Err(io::Error::other(format!("fixture PID liveness lookup failed: {error}")).into())
        }
    }
}

fn assert_fixed_output(
    output: &ObservedOutput,
    expected_code: Option<i32>,
    expected_stdout: &[u8],
) -> TestResult {
    if output.status.code() != expected_code {
        return Err(io::Error::other(format!(
            "expected fixture exit {expected_code:?}, observed {:?}",
            output.status.code()
        ))
        .into());
    }
    if output.stdout != expected_stdout || !output.stderr.is_empty() {
        return Err(io::Error::other("fixture output was not fixed and redacted").into());
    }
    Ok(())
}

fn assert_killed_output(output: &ObservedOutput, expected_stdout: &[u8]) -> TestResult {
    if output.status.success() {
        return Err(io::Error::other("fault-injected coordinator exited successfully").into());
    }
    if output.stdout != expected_stdout || !output.stderr.is_empty() {
        return Err(io::Error::other("killed fixture output was not fixed and redacted").into());
    }
    Ok(())
}

fn assert_started_marker(fixture: &SupervisorCase, marker: &str, expected: bool) -> TestResult {
    if expected {
        fixture.assert_marker(marker, b"started\n")
    } else {
        fixture.assert_marker_absent(marker)
    }
}

fn assert_requested_marker(fixture: &SupervisorCase, marker: &str, expected: bool) -> TestResult {
    if expected {
        fixture.assert_marker(marker, b"requested\n")
    } else {
        fixture.assert_marker_absent(marker)
    }
}

fn assert_fixture_processes_gone(
    fixture: &SupervisorCase,
    app_started: bool,
    tui_started: bool,
    descendant: Option<(i32, i32)>,
) -> TestResult {
    let guardian = fixture.read_pid_marker("guardian.pid")?;
    wait_pid_gone(guardian, guardian, CONTENDER_TIMEOUT)?;
    if app_started {
        let app = fixture.read_pid_marker("app.pid")?;
        wait_pid_gone(app, app, CONTENDER_TIMEOUT)?;
    } else {
        fixture.assert_marker_absent("app.pid")?;
    }
    if tui_started {
        let tui = fixture.read_pid_marker("tui.pid")?;
        wait_pid_gone(tui, tui, CONTENDER_TIMEOUT)?;
    } else {
        fixture.assert_marker_absent("tui.pid")?;
    }
    if let Some((pid, group)) = descendant {
        wait_pid_gone(pid, group, CONTENDER_TIMEOUT)?;
    }
    Ok(())
}
