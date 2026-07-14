use std::ffi::OsString;
use std::process::{Command, ExitStatus};

#[cfg(unix)]
use std::io::{self, BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Child;
#[cfg(unix)]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};
#[cfg(unix)]
use uuid::Uuid;

use crate::cli::InternalProcessMode;
use crate::conversations::{ConversationError, ConversationRegistry};
use crate::error::AppError;
use crate::executable::resolve_codex;
use crate::profiles::{Provider, Registry};
use crate::project_config::verify_current_repository_config;
use crate::providers::codex::{managed_command, sanitize_managed_environment};

#[cfg(unix)]
use super::codex_conversation::{CaptureContext, validate_head_target};

#[cfg(unix)]
const GUARDIAN_START_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(unix)]
const CONTROL_LINE_LIMIT: usize = 128;

pub(crate) fn run_codex(
    alias: &str,
    untracked: bool,
    provider_args: &[OsString],
) -> Result<ExitStatus, AppError> {
    validate_provider_arguments(provider_args)?;
    let mode = if untracked {
        InternalProcessMode::RunUntracked
    } else {
        InternalProcessMode::Run
    };
    spawn_supervisor(alias, mode, None, provider_args)
}

pub(crate) fn resume_codex(
    alias: &str,
    session_id: Option<&str>,
    untracked: bool,
    provider_args: &[OsString],
) -> Result<ExitStatus, AppError> {
    validate_provider_arguments(provider_args)?;
    let mode = match (session_id, untracked) {
        (Some(_), false) => InternalProcessMode::ResumeExact,
        (None, false) => InternalProcessMode::ResumeLast,
        (None, true) => InternalProcessMode::ResumeLastUntracked,
        (Some(_), true) => return Err(AppError::ProviderArgumentRejected),
    };
    spawn_supervisor(alias, mode, session_id, provider_args)
}

pub(crate) fn resume_workspace_codex(provider_args: &[OsString]) -> Result<ExitStatus, AppError> {
    validate_provider_arguments(provider_args)?;
    let launch_context = verify_current_repository_config()?;
    let registry = Registry::discover()?;
    let conversations = ConversationRegistry::from_profiles(&registry);
    // resolve_head drops its short conversation lock before profile lookup and
    // the coordinator lease. The hidden coordinator revalidates the binding.
    let head = match conversations.resolve_head(launch_context.working_directory()) {
        Ok(head) => head,
        Err(ConversationError::Ambiguous) => {
            #[cfg(unix)]
            {
                let profile_id = conversations
                    .pending_profile_for_workspace(launch_context.working_directory())?
                    .ok_or(ConversationError::Ambiguous)?;
                let profile = registry.find_by_id(Provider::Codex, &profile_id)?;
                let lease = registry.lock_profile(&profile)?;
                let executable = resolve_codex()?;
                let home = registry.profile_home(&profile)?;
                let neutral_working_directory = registry.neutral_working_directory()?;
                CaptureContext::new(
                    &conversations,
                    &lease,
                    &executable,
                    &home,
                    &neutral_working_directory,
                    &profile.id,
                    launch_context.working_directory(),
                )
                .reconcile_pending_launch()?;
                drop(lease);
                conversations.resolve_head(launch_context.working_directory())?
            }
            #[cfg(not(unix))]
            {
                return Err(ConversationError::Ambiguous.into());
            }
        }
        Err(error) => return Err(error.into()),
    };
    let profile = registry.find_by_id(Provider::Codex, &head.profile_id)?;
    spawn_supervisor(
        &profile.alias,
        InternalProcessMode::ResumeHead,
        Some(&head.thread_id),
        provider_args,
    )
}

fn spawn_supervisor(
    alias: &str,
    mode: InternalProcessMode,
    session_id: Option<&str>,
    provider_args: &[OsString],
) -> Result<ExitStatus, AppError> {
    #[cfg(unix)]
    let _termination_guard = install_process_signal_guard()?;
    let registry = Registry::discover()?;
    let profile = registry.find(Provider::Codex, alias)?;
    let executable = std::env::current_exe()?;
    let mut command = internal_calcifer_command(&executable);
    command
        .arg("__internal-codex")
        .arg(&profile.id)
        .arg(format!("codex@{alias}"))
        .arg(match mode {
            InternalProcessMode::Run => "run",
            InternalProcessMode::RunUntracked => "run-untracked",
            InternalProcessMode::ResumeLast => "resume-last",
            InternalProcessMode::ResumeLastUntracked => "resume-last-untracked",
            InternalProcessMode::ResumeExact => "resume-exact",
            InternalProcessMode::ResumeHead => "resume-head",
        });
    if let Some(session_id) = session_id {
        command.arg(session_id);
    }
    if !provider_args.is_empty() {
        command.arg("--").args(provider_args);
    }
    command.status().map_err(AppError::from)
}

pub(crate) fn supervise_codex(
    profile_id: &str,
    expected_alias: &str,
    mode: InternalProcessMode,
    session_id: Option<&str>,
    provider_args: &[OsString],
    announce: impl FnOnce() -> std::io::Result<()>,
) -> Result<ExitStatus, AppError> {
    validate_provider_arguments(provider_args)?;
    let _arguments = provider_arguments(mode, session_id, provider_args)?;

    #[cfg(unix)]
    {
        let _termination_guard = install_process_signal_guard()?;
        // Resolve and validate everything before publishing the private socket.
        // The provider guardian repeats these checks immediately before spawn.
        let _executable = resolve_codex()?;
        let registry = Registry::discover()?;
        let profile = registry.find_by_id(Provider::Codex, profile_id)?;
        require_expected_alias(&profile, expected_alias)?;
        let _coordinator_lease = registry.lock_profile_coordinator(&profile)?;
        let profile = registry.find_by_id(Provider::Codex, profile_id)?;
        require_expected_alias(&profile, expected_alias)?;
        announce()?;
        let _home = registry.profile_home(&profile)?;
        let launch_context = verify_current_repository_config()?;
        if mode == InternalProcessMode::ResumeHead {
            let thread_id = session_id.ok_or(AppError::ProviderArgumentRejected)?;
            let conversations = ConversationRegistry::from_profiles(&registry);
            let head = conversations.resolve_head(launch_context.working_directory())?;
            validate_head_target(
                &head,
                &profile.id,
                thread_id,
                launch_context.working_directory(),
            )?;
        }
        let run_id = Uuid::new_v4();
        let socket_path = registry.supervisor_socket_path(&profile, &run_id)?;
        write_test_process_marker("coordinator.pid", std::process::id());
        let listener = UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        let _socket_cleanup = PathCleanup(socket_path);
        listener.set_nonblocking(true)?;

        let mut guardian = spawn_provider_guardian(
            &profile.id,
            &run_id,
            mode,
            session_id,
            provider_args,
            launch_context.working_directory(),
        )?;
        let control = match accept_provider_guardian(&listener, &mut guardian)? {
            GuardianAccept::Connected(control) => control,
            GuardianAccept::Exited(status) => return Ok(status),
        };
        // Some Unix kernels propagate O_NONBLOCK from the listener to the
        // accepted socket. The lifecycle channel itself must block while the
        // interactive provider is running.
        control.set_nonblocking(false)?;
        control.set_read_timeout(Some(GUARDIAN_START_TIMEOUT))?;
        let mut reader = BufReader::new(control);
        match read_control_line(&mut reader)? {
            ControlLine::Line(line) if line == "READY" => {}
            ControlLine::Line(_) | ControlLine::Eof => {
                terminate_before_provider_start(&mut guardian);
                return Err(io::Error::other("provider guardian handshake failed").into());
            }
        }
        reader.get_mut().write_all(b"GO\n")?;
        reader.get_mut().flush()?;
        reader.get_mut().set_read_timeout(None)?;
        monitor_provider_guardian(&mut guardian, &mut reader)
    }

    #[cfg(not(unix))]
    {
        if matches!(
            mode,
            InternalProcessMode::RunUntracked | InternalProcessMode::ResumeLastUntracked
        ) {
            return Err(crate::profiles::ProfileError::UnsupportedPlatform.into());
        }
        let executable = resolve_codex()?;
        let registry = Registry::discover()?;
        let profile = registry.find_by_id(Provider::Codex, profile_id)?;
        require_expected_alias(&profile, expected_alias)?;
        let _lease = registry.lock_profile(&profile)?;
        let profile = registry.find_by_id(Provider::Codex, profile_id)?;
        require_expected_alias(&profile, expected_alias)?;
        announce()?;
        let home = registry.profile_home(&profile)?;
        let launch_context = verify_current_repository_config()?;
        managed_command(&executable, &home)
            .args(_arguments)
            .current_dir(launch_context.working_directory())
            .status()
            .map_err(AppError::from)
    }
}

/// Runs the official Codex process while owning the provider half of a split
/// lease. The coordinator owns the other half and authorizes spawn over a
/// private, per-run Unix socket.
pub(crate) fn guard_codex(
    profile_id: &str,
    run_id: &str,
    mode: InternalProcessMode,
    session_id: Option<&str>,
    provider_args: &[OsString],
) -> Result<ExitStatus, AppError> {
    validate_provider_arguments(provider_args)?;
    let arguments = provider_arguments(mode, session_id, provider_args)?;

    #[cfg(unix)]
    {
        let termination_requested = install_process_signal_guard()?;
        let run_id = parse_run_id(run_id)?;
        let executable = resolve_codex()?;
        let registry = Registry::discover()?;
        let profile = registry.find_by_id(Provider::Codex, profile_id)?;
        let provider_lease = registry.lock_profile_provider(&profile)?;
        let home = registry.profile_home(&profile)?;
        let initial_launch_context = verify_current_repository_config()?;
        let socket_path = registry.supervisor_socket_path(&profile, &run_id)?;
        let mut control = UnixStream::connect(&socket_path)?;
        let _socket_cleanup = PathCleanup(socket_path);
        control.write_all(b"READY\n")?;
        control.flush()?;
        control.set_read_timeout(Some(GUARDIAN_START_TIMEOUT))?;
        let mut reader = BufReader::new(control);
        match read_control_line(&mut reader)? {
            ControlLine::Line(line) if line == "GO" => {}
            ControlLine::Line(_) | ControlLine::Eof => {
                return Err(io::Error::other("provider guardian was not authorized").into());
            }
        }
        reader.get_mut().set_read_timeout(None)?;

        if termination_requested.load(Ordering::SeqCst) {
            let _ = reader.get_mut().write_all(b"ABORT\n");
            let _ = reader.get_mut().flush();
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "provider launch was interrupted",
            )
            .into());
        }

        if let Err(error) = wait_for_final_preflight_test_barrier(&run_id) {
            send_guardian_abort(&mut reader);
            return Err(error);
        }

        let final_launch_context = match verify_current_repository_config() {
            Ok(context)
                if context.working_directory() == initial_launch_context.working_directory() =>
            {
                context
            }
            Ok(_) | Err(_) => {
                send_guardian_abort(&mut reader);
                return Err(crate::project_config::ProjectConfigError::Unsafe.into());
            }
        };

        let conversations = ConversationRegistry::from_profiles(&registry);
        let neutral_working_directory = registry.neutral_working_directory()?;
        let capture_context = CaptureContext::new(
            &conversations,
            &provider_lease,
            &executable,
            &home,
            &neutral_working_directory,
            &profile.id,
            final_launch_context.working_directory(),
        );
        let capture = match capture_context.prepare(mode, session_id) {
            Ok(capture) => capture,
            Err(error) => {
                send_guardian_abort(&mut reader);
                return Err(error);
            }
        };
        if let Err(error) = capture_context.authorize_provider_spawn(&capture) {
            send_guardian_abort(&mut reader);
            return Err(error);
        }

        let mut provider = match managed_command(&executable, &home)
            .args(arguments)
            .current_dir(final_launch_context.working_directory())
            .env_remove("CALCIFER_TEST_FINAL_PREFLIGHT_BARRIER")
            .env_remove("CALCIFER_TEST_MARKER_ID")
            .spawn()
        {
            Ok(provider) => provider,
            Err(error) => {
                send_guardian_abort(&mut reader);
                capture_context.provider_spawn_failed(&capture)?;
                return Err(error.into());
            }
        };

        // A failed control write means the coordinator died. Continue waiting:
        // this process still owns the provider lease and is now the sole guard.
        let _ = writeln!(reader.get_mut(), "START {}", provider.id());
        let _ = reader.get_mut().flush();
        if termination_requested.load(Ordering::SeqCst) {
            // The request may have arrived after the pre-spawn check but before
            // this child existed, so it could not have received the original
            // terminal signal. Terminate it explicitly without releasing B.
            let _ = provider.kill();
        }
        let status = provider.wait()?;
        capture_context.complete(&capture, status.success());
        let _ = reader.get_mut().write_all(b"DONE\n");
        let _ = reader.get_mut().flush();
        Ok(status)
    }

    #[cfg(not(unix))]
    {
        let _ = (profile_id, run_id, arguments);
        Err(crate::profiles::ProfileError::UnsupportedPlatform.into())
    }
}

fn require_expected_alias(
    profile: &crate::profiles::Profile,
    expected_alias: &str,
) -> Result<(), AppError> {
    if profile.alias == expected_alias {
        Ok(())
    } else {
        Err(crate::profiles::ProfileError::NotFound(format!(
            "{}@{expected_alias}",
            profile.provider.as_str()
        ))
        .into())
    }
}

fn provider_arguments(
    mode: InternalProcessMode,
    session_id: Option<&str>,
    provider_args: &[OsString],
) -> Result<Vec<OsString>, AppError> {
    let mut arguments = Vec::new();
    match (mode, session_id) {
        (InternalProcessMode::Run | InternalProcessMode::RunUntracked, None) => {
            arguments.extend(provider_args.iter().cloned());
        }
        (InternalProcessMode::ResumeLast | InternalProcessMode::ResumeLastUntracked, None) => {
            arguments.push(OsString::from("resume"));
            arguments.push(OsString::from("--last"));
            arguments.extend(provider_args.iter().cloned());
        }
        (InternalProcessMode::ResumeExact | InternalProcessMode::ResumeHead, Some(session_id)) => {
            validate_canonical_thread_id(session_id)?;
            arguments.push(OsString::from("resume"));
            arguments.push(OsString::from(session_id));
            arguments.extend(provider_args.iter().cloned());
        }
        _ => return Err(AppError::ProviderArgumentRejected),
    }
    Ok(arguments)
}

fn validate_canonical_thread_id(thread_id: &str) -> Result<(), AppError> {
    let parsed =
        uuid::Uuid::parse_str(thread_id).map_err(|_| AppError::ProviderArgumentRejected)?;
    if parsed.to_string() != thread_id {
        return Err(AppError::ProviderArgumentRejected);
    }
    Ok(())
}

#[cfg(unix)]
fn spawn_provider_guardian(
    profile_id: &str,
    run_id: &Uuid,
    mode: InternalProcessMode,
    session_id: Option<&str>,
    provider_args: &[OsString],
    working_directory: &std::path::Path,
) -> Result<Child, AppError> {
    let executable = std::env::current_exe()?;
    let mut command = internal_calcifer_command(&executable);
    command
        .arg("__internal-codex-provider")
        .arg(profile_id)
        .arg(run_id.to_string())
        .arg(match mode {
            InternalProcessMode::Run => "run",
            InternalProcessMode::RunUntracked => "run-untracked",
            InternalProcessMode::ResumeLast => "resume-last",
            InternalProcessMode::ResumeLastUntracked => "resume-last-untracked",
            InternalProcessMode::ResumeExact => "resume-exact",
            InternalProcessMode::ResumeHead => "resume-head",
        });
    if let Some(session_id) = session_id {
        command.arg(session_id);
    }
    if !provider_args.is_empty() {
        command.arg("--").args(provider_args);
    }
    command.current_dir(working_directory);
    command.spawn().map_err(AppError::from)
}

fn internal_calcifer_command(executable: &std::path::Path) -> Command {
    let mut command = Command::new(executable);
    sanitize_managed_environment(&mut command);
    // Calcifer itself does not use CODEX_HOME. The selected managed home is
    // reintroduced only on the final, validated official Codex command.
    command.env_remove("CODEX_HOME");
    command
}

#[cfg(unix)]
enum GuardianAccept {
    Connected(UnixStream),
    Exited(ExitStatus),
}

#[cfg(unix)]
fn accept_provider_guardian(
    listener: &UnixListener,
    guardian: &mut Child,
) -> Result<GuardianAccept, AppError> {
    let deadline = Instant::now()
        .checked_add(GUARDIAN_START_TIMEOUT)
        .ok_or_else(|| io::Error::other("guardian deadline overflow"))?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(GuardianAccept::Connected(stream)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => {
                terminate_before_provider_start(guardian);
                return Err(error.into());
            }
        }
        if let Some(status) = guardian.try_wait()? {
            return Ok(GuardianAccept::Exited(status));
        }
        if Instant::now() >= deadline {
            terminate_before_provider_start(guardian);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "provider guardian startup timed out",
            )
            .into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn monitor_provider_guardian(
    guardian: &mut Child,
    reader: &mut BufReader<UnixStream>,
) -> Result<ExitStatus, AppError> {
    let mut provider_pid = None;
    loop {
        let line = match read_control_line(reader) {
            Ok(ControlLine::Line(line)) => line,
            Ok(ControlLine::Eof) | Err(_) => {
                if let Some(pid) = provider_pid {
                    wait_for_process_exit(pid);
                    // The provider is gone, so releasing A is now safe even if
                    // the guardian cannot be reaped normally.
                    return guardian.wait().map_err(AppError::from);
                }
                hold_profile_fail_closed("control channel closed before START");
            }
        };

        if line == "ABORT" && provider_pid.is_none() {
            return guardian.wait().map_err(AppError::from);
        }
        if line == "DONE" && provider_pid.is_some() {
            return guardian.wait().map_err(AppError::from);
        }
        if provider_pid.is_none() {
            if let Some(raw_pid) = line.strip_prefix("START ") {
                provider_pid = raw_pid.parse::<u32>().ok();
                if let Some(pid) = provider_pid {
                    write_test_process_marker("provider-tracked", pid);
                    continue;
                }
            }
        }

        // Once GO has been sent, an unrecognized or missing START is
        // ambiguous: the provider may have been spawned just before a crash.
        hold_profile_fail_closed("invalid guardian control message");
    }
}

#[cfg(unix)]
fn wait_for_process_exit(raw_pid: u32) {
    let Ok(raw_pid) = i32::try_from(raw_pid) else {
        hold_profile_fail_closed("provider PID is out of range");
    };
    let Some(pid) = rustix::process::Pid::from_raw(raw_pid) else {
        hold_profile_fail_closed("provider PID is invalid");
    };
    loop {
        match rustix::process::test_kill_process(pid) {
            Err(rustix::io::Errno::SRCH) => return,
            Ok(()) | Err(rustix::io::Errno::PERM) => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => hold_profile_fail_closed("provider liveness check failed"),
        }
    }
}

#[cfg(unix)]
fn hold_profile_fail_closed(reason: &str) -> ! {
    eprintln!(
        "Calcifer: provider guardian failed during spawn ({reason}); holding the profile lease to prevent a second credential writer."
    );
    loop {
        thread::park_timeout(Duration::from_secs(3_600));
    }
}

#[cfg(unix)]
fn terminate_before_provider_start(guardian: &mut Child) {
    let _ = guardian.kill();
    let _ = guardian.wait();
}

#[cfg(unix)]
enum ControlLine {
    Line(String),
    Eof,
}

#[cfg(unix)]
fn read_control_line(reader: &mut impl BufRead) -> io::Result<ControlLine> {
    let mut bytes = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if bytes.is_empty() {
                Ok(ControlLine::Eof)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "guardian control line is incomplete",
                ))
            };
        }
        if let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
            if bytes.len().saturating_add(newline) > CONTROL_LINE_LIMIT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guardian control line exceeds limit",
                ));
            }
            bytes.extend_from_slice(&buffer[..newline]);
            reader.consume(newline + 1);
            let line = String::from_utf8(bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "guardian line is not UTF-8")
            })?;
            return Ok(ControlLine::Line(line));
        }
        if bytes.len().saturating_add(buffer.len()) > CONTROL_LINE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guardian control line exceeds limit",
            ));
        }
        bytes.extend_from_slice(buffer);
        let consumed = buffer.len();
        reader.consume(consumed);
    }
}

#[cfg(unix)]
fn parse_run_id(run_id: &str) -> Result<Uuid, AppError> {
    let parsed =
        Uuid::parse_str(run_id).map_err(|_| io::Error::other("invalid internal run identifier"))?;
    if parsed.to_string() != run_id {
        return Err(io::Error::other("non-canonical internal run identifier").into());
    }
    Ok(parsed)
}

#[cfg(unix)]
fn install_process_signal_guard() -> Result<Arc<AtomicBool>, AppError> {
    use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};

    let termination_requested = Arc::new(AtomicBool::new(false));
    for signal in [SIGHUP, SIGINT, SIGQUIT, SIGTERM] {
        signal_hook::flag::register(signal, Arc::clone(&termination_requested))?;
    }
    Ok(termination_requested)
}

#[cfg(unix)]
fn send_guardian_abort(reader: &mut BufReader<UnixStream>) {
    let _ = reader.get_mut().write_all(b"ABORT\n");
    let _ = reader.get_mut().flush();
}

#[cfg(unix)]
fn wait_for_final_preflight_test_barrier(run_id: &Uuid) -> Result<(), AppError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let Some(enabled) = std::env::var_os("CALCIFER_TEST_FINAL_PREFLIGHT_BARRIER") else {
        return Ok(());
    };
    if enabled != "1" {
        return Err(io::Error::other("invalid final preflight test barrier").into());
    }

    let ready_path = test_marker_path("final-preflight-ready")
        .ok_or_else(|| io::Error::other("missing final preflight test marker identifier"))?;
    let release_path = test_marker_path("final-preflight-release")
        .ok_or_else(|| io::Error::other("missing final preflight test marker identifier"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut ready = options.open(&ready_path)?;
    writeln!(ready, "{} {run_id}", std::process::id())?;
    ready.sync_all()?;
    let _barrier_cleanup = TestBarrierCleanup {
        ready: ready_path,
        release: release_path.clone(),
    };

    let deadline = Instant::now()
        .checked_add(GUARDIAN_START_TIMEOUT)
        .ok_or_else(|| io::Error::other("final preflight test deadline overflow"))?;
    loop {
        match std::fs::symlink_metadata(&release_path) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == rustix::process::getuid().as_raw()
                    && metadata.mode() & 0o777 == 0o600 =>
            {
                std::fs::remove_file(&release_path)?;
                return Ok(());
            }
            Ok(_) => {
                return Err(io::Error::other("unsafe final preflight test release marker").into());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "final preflight test barrier timed out",
            )
            .into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
// Integration tests use UUID-scoped, create-only markers in Calcifer's private
// runtime directory to observe otherwise hidden lifecycle barriers. An
// environment value can never select an arbitrary output path.
fn write_test_process_marker(kind: &str, value: u32) {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let Some(path) = test_marker_path(kind) else {
        return;
    };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    if let Ok(mut file) = options.open(path) {
        let _ = writeln!(file, "{value}");
    }
}

#[cfg(unix)]
fn test_marker_path(kind: &str) -> Option<PathBuf> {
    let marker_id = std::env::var_os("CALCIFER_TEST_MARKER_ID")?;
    let marker_id = marker_id.to_str()?;
    let marker_id = Uuid::parse_str(marker_id).ok()?;
    let runtime_root =
        PathBuf::from("/tmp").join(format!("calcifer-{}", rustix::process::getuid().as_raw()));
    Some(runtime_root.join(format!(".test-{marker_id}-{kind}")))
}

#[cfg(unix)]
struct PathCleanup(PathBuf);

#[cfg(unix)]
impl Drop for PathCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
struct TestBarrierCleanup {
    ready: PathBuf,
    release: PathBuf,
}

#[cfg(unix)]
impl Drop for TestBarrierCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.ready);
        let _ = std::fs::remove_file(&self.release);
    }
}

fn validate_provider_arguments(arguments: &[OsString]) -> Result<(), AppError> {
    for argument in arguments {
        let Some(argument) = argument.to_str() else {
            return Err(AppError::ProviderArgumentRejected);
        };
        let rejected = matches!(
            argument,
            "-c" | "--config"
                | "-p"
                | "--profile"
                | "-C"
                | "--cd"
                | "--enable"
                | "--disable"
                | "--oss"
                | "--local-provider"
                | "--remote"
                | "--remote-auth-token-env"
        ) || argument.starts_with("-c=")
            || (argument.starts_with("-c") && argument.len() > 2)
            || argument.starts_with("--config=")
            || argument.starts_with("-p=")
            || (argument.starts_with("-p") && argument.len() > 2)
            || argument.starts_with("--profile=")
            || (argument.starts_with("-C") && argument.len() > 2)
            || argument.starts_with("--cd=")
            || argument.starts_with("--enable=")
            || argument.starts_with("--disable=")
            || argument.starts_with("--local-provider=")
            || argument.starts_with("--remote=")
            || argument.starts_with("--remote-auth-token-env=");
        if rejected {
            return Err(AppError::ProviderArgumentRejected);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_calcifer_helpers_drop_explicit_provider_secrets() {
        let command = internal_calcifer_command(std::path::Path::new("/synthetic/calcifer"));

        for denied in [
            "OPENAI_API_KEY",
            "CODEX_ACCESS_TOKEN",
            "CODEX_CONNECTORS_TOKEN",
        ] {
            assert!(
                command
                    .get_envs()
                    .any(|(name, value)| name == denied && value.is_none()),
                "{denied} must be removed before the helper process starts"
            );
        }
    }

    #[test]
    fn rejects_arguments_that_can_bypass_managed_account_routing() {
        for argument in [
            "-c",
            "-cchatgpt_base_url=example",
            "--config=cli_auth_credentials_store=keyring",
            "-pwork",
            "--profile=work",
            "--oss",
            "--local-provider=ollama",
            "--remote=unix:///tmp/socket",
            "--remote-auth-token-env=TOKEN",
            "-C",
            "-C/synthetic/project",
            "-C=/synthetic/project",
            "--cd",
            "--cd=/synthetic/project",
            "--enable",
            "--enable=remote_plugin",
            "--disable",
            "--disable=secret_auth_storage",
        ] {
            assert!(
                validate_provider_arguments(&[OsString::from(argument)]).is_err(),
                "{argument} must be rejected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_provider_arguments() {
        use std::os::unix::ffi::OsStringExt;

        let argument = OsString::from_vec(vec![b'-', b'C', b'/', 0xff]);
        assert!(validate_provider_arguments(&[argument]).is_err());
    }

    #[test]
    fn permits_arguments_that_do_not_select_an_account_or_provider() {
        let arguments = [
            OsString::from("--no-alt-screen"),
            OsString::from("--untracked"),
            OsString::from("--sandbox"),
            OsString::from("workspace-write"),
        ];
        assert!(validate_provider_arguments(&arguments).is_ok());
    }
}
