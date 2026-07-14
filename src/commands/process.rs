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
use crate::error::AppError;
use crate::executable::resolve_codex;
use crate::profiles::{Provider, Registry};
use crate::providers::codex::FILE_CREDENTIALS_OVERRIDE;

#[cfg(unix)]
const GUARDIAN_START_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(unix)]
const CONTROL_LINE_LIMIT: usize = 128;

pub(crate) fn run_codex(alias: &str, provider_args: &[OsString]) -> Result<ExitStatus, AppError> {
    validate_provider_arguments(provider_args)?;
    spawn_supervisor(alias, InternalProcessMode::Run, None, provider_args)
}

pub(crate) fn resume_codex(
    alias: &str,
    session_id: Option<&str>,
    provider_args: &[OsString],
) -> Result<ExitStatus, AppError> {
    validate_provider_arguments(provider_args)?;
    let mode = if session_id.is_some() {
        InternalProcessMode::ResumeExact
    } else {
        InternalProcessMode::ResumeLast
    };
    spawn_supervisor(alias, mode, session_id, provider_args)
}

fn spawn_supervisor(
    alias: &str,
    mode: InternalProcessMode,
    session_id: Option<&str>,
    provider_args: &[OsString],
) -> Result<ExitStatus, AppError> {
    #[cfg(unix)]
    let _termination_guard = install_process_signal_guard()?;
    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("__internal-codex")
        .arg(format!("codex@{alias}"))
        .arg(match mode {
            InternalProcessMode::Run => "run",
            InternalProcessMode::ResumeLast => "resume-last",
            InternalProcessMode::ResumeExact => "resume-exact",
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
    alias: &str,
    mode: InternalProcessMode,
    session_id: Option<&str>,
    provider_args: &[OsString],
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
        let profile = registry.find(Provider::Codex, alias)?;
        let _coordinator_lease = registry.lock_profile_coordinator(&profile)?;
        let _home = registry.profile_home(&profile)?;
        let run_id = Uuid::new_v4();
        let socket_path = registry.supervisor_socket_path(&profile, &run_id)?;
        write_test_process_marker("coordinator.pid", std::process::id());
        let listener = UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        let _socket_cleanup = SocketCleanup(socket_path);
        listener.set_nonblocking(true)?;

        let mut guardian =
            spawn_provider_guardian(alias, &run_id, mode, session_id, provider_args)?;
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
        let executable = resolve_codex()?;
        let registry = Registry::discover()?;
        let profile = registry.find(Provider::Codex, alias)?;
        let _lease = registry.lock_profile(&profile)?;
        let home = registry.profile_home(&profile)?;
        Command::new(executable)
            .args(["-c", FILE_CREDENTIALS_OVERRIDE])
            .args(_arguments)
            .env("CODEX_HOME", home)
            .env_remove("CODEX_API_KEY")
            .env_remove("OPENAI_API_KEY")
            .status()
            .map_err(AppError::from)
    }
}

/// Runs the official Codex process while owning the provider half of a split
/// lease. The coordinator owns the other half and authorizes spawn over a
/// private, per-run Unix socket.
pub(crate) fn guard_codex(
    alias: &str,
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
        let profile = registry.find(Provider::Codex, alias)?;
        let _provider_lease = registry.lock_profile_provider(&profile)?;
        let home = registry.profile_home(&profile)?;
        let socket_path = registry.supervisor_socket_path(&profile, &run_id)?;
        let mut control = UnixStream::connect(&socket_path)?;
        let _socket_cleanup = SocketCleanup(socket_path);
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

        let mut provider = match Command::new(executable)
            .args(["-c", FILE_CREDENTIALS_OVERRIDE])
            .args(arguments)
            .env("CODEX_HOME", home)
            .env_remove("CODEX_API_KEY")
            .env_remove("OPENAI_API_KEY")
            .env_remove("CALCIFER_TEST_MARKER_ID")
            .spawn()
        {
            Ok(provider) => provider,
            Err(error) => {
                let _ = reader.get_mut().write_all(b"ABORT\n");
                let _ = reader.get_mut().flush();
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
        let _ = reader.get_mut().write_all(b"DONE\n");
        let _ = reader.get_mut().flush();
        Ok(status)
    }

    #[cfg(not(unix))]
    {
        let _ = (alias, run_id, arguments);
        Err(crate::profiles::ProfileError::UnsupportedPlatform.into())
    }
}

fn provider_arguments(
    mode: InternalProcessMode,
    session_id: Option<&str>,
    provider_args: &[OsString],
) -> Result<Vec<OsString>, AppError> {
    let mut arguments = Vec::new();
    match (mode, session_id) {
        (InternalProcessMode::Run, None) => arguments.extend(provider_args.iter().cloned()),
        (InternalProcessMode::ResumeLast, None) => {
            arguments.push(OsString::from("resume"));
            arguments.push(OsString::from("--last"));
            arguments.extend(provider_args.iter().cloned());
        }
        (InternalProcessMode::ResumeExact, Some(session_id)) => {
            arguments.push(OsString::from("resume"));
            arguments.push(OsString::from(session_id));
            arguments.extend(provider_args.iter().cloned());
        }
        _ => return Err(AppError::ProviderArgumentRejected),
    }
    Ok(arguments)
}

#[cfg(unix)]
fn spawn_provider_guardian(
    alias: &str,
    run_id: &Uuid,
    mode: InternalProcessMode,
    session_id: Option<&str>,
    provider_args: &[OsString],
) -> Result<Child, AppError> {
    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("__internal-codex-provider")
        .arg(format!("codex@{alias}"))
        .arg(run_id.to_string())
        .arg(match mode {
            InternalProcessMode::Run => "run",
            InternalProcessMode::ResumeLast => "resume-last",
            InternalProcessMode::ResumeExact => "resume-exact",
        });
    if let Some(session_id) = session_id {
        command.arg(session_id);
    }
    if !provider_args.is_empty() {
        command.arg("--").args(provider_args);
    }
    command.spawn().map_err(AppError::from)
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
// Integration tests use UUID-scoped, create-only markers in Calcifer's private
// runtime directory to observe otherwise hidden lifecycle barriers. An
// environment value can never select an arbitrary output path.
fn write_test_process_marker(kind: &str, value: u32) {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let Some(marker_id) = std::env::var_os("CALCIFER_TEST_MARKER_ID") else {
        return;
    };
    let Some(marker_id) = marker_id.to_str() else {
        return;
    };
    let Ok(marker_id) = Uuid::parse_str(marker_id) else {
        return;
    };
    let runtime_root =
        PathBuf::from("/tmp").join(format!("calcifer-{}", rustix::process::getuid().as_raw()));
    let path = runtime_root.join(format!(".test-{marker_id}-{kind}"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    if let Ok(mut file) = options.open(path) {
        let _ = writeln!(file, "{value}");
    }
}

#[cfg(unix)]
struct SocketCleanup(PathBuf);

#[cfg(unix)]
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn validate_provider_arguments(arguments: &[OsString]) -> Result<(), AppError> {
    for argument in arguments {
        let Some(argument) = argument.to_str() else {
            continue;
        };
        let rejected = matches!(
            argument,
            "-c" | "--config"
                | "-p"
                | "--profile"
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
        ] {
            assert!(
                validate_provider_arguments(&[OsString::from(argument)]).is_err(),
                "{argument} must be rejected"
            );
        }
    }

    #[test]
    fn permits_arguments_that_do_not_select_an_account_or_provider() {
        let arguments = [
            OsString::from("--no-alt-screen"),
            OsString::from("--sandbox"),
            OsString::from("workspace-write"),
        ];
        assert!(validate_provider_arguments(&arguments).is_ok());
    }
}
