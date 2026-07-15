#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
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
const EXIT_FAILURE: i32 = 70;
const EXIT_BUSY: i32 = 75;

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
        loop {
            if let Some(value) = self.read_marker(name)? {
                if value != expected {
                    return Err(io::Error::other(format!(
                        "marker {name} contained an unexpected bounded value"
                    ))
                    .into());
                }
                return Ok(());
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

    fn assert_provider_untouched(&self) -> TestResult {
        if fs::read(&self.provider_log)? == self.provider_log_baseline {
            Ok(())
        } else {
            Err(io::Error::other("the supervisor invoked the fake provider").into())
        }
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

fn read_bounded_capture(path: &Path) -> TestResult<Vec<u8>> {
    let value = fs::read(path)?;
    if value.len() > MAX_CAPTURE_BYTES {
        Err(io::Error::other("fixture output exceeded its test bound").into())
    } else {
        Ok(value)
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
