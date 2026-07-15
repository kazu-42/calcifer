//! Feature-gated real-exec harness for the guardian lifecycle contract.
//!
//! Every role and fault is closed over a fixed enum. This module cannot run an
//! arbitrary command, read a profile home, or carry provider/user payloads.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use calcifer_unix_child_fd::{
    DescriptorIdentity, count_open_descriptors_with_identity, descriptor_identity,
};

use super::authority::{RetainedCoordinatorLease, RetentionReason};
use super::channel::{
    LifecycleEndpoint, LifecyclePair, bootstrap_guardian_from_stdin,
    spawn_guardian_with_lifecycle_stdin,
};
use super::process::{ChildLiveness, ManagedGroupChild, SpawnFailureState, shutdown_pair};
use super::protocol::{
    ChildDisposition, ChildRole, CleanupStatus, CoordinatorCommand, CoordinatorReceiver,
    FailureCode, GuardianCommandReceiver, GuardianEvent, Phase, ProtocolError, SessionStatus,
    StopAction, WorkerJoinStatus, send_coordinator_command, send_guardian_event,
};
use super::runtime::{PrivateRuntime, RuntimeCleanupFailure};
use super::transfer::TransferChannelPair;
use crate::profiles::{CoordinatorProfileLease, Profile, ProfileLease, Provider, Registry};

const PROFILE_ALIAS: &str = "work";
const MARKER_ROOT_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_MARKER_ROOT";
const PROFILE_ID_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_PROFILE_ID";
const GUARDIAN_FORBIDDEN_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_GUARDIAN_FDS";
const GUARDIAN_LIFECYCLE_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_LIFECYCLE_FD";
const CHILD_FORBIDDEN_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_CHILD_FDS";
const DESCENDANT_MARKER_ENV: &str = "CALCIFER_SUPERVISOR_FIXTURE_DESCENDANT_MARKER";

const IO_TIMEOUT: Duration = Duration::from_millis(50);
const PHASE_TIMEOUT: Duration = Duration::from_secs(3);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(1);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(150);
const SHUTDOWN_FORCE: Duration = Duration::from_secs(1);
const WAIT_POLL: Duration = Duration::from_millis(10);

const EXIT_FAILURE: u8 = 70;
const EXIT_BUSY: u8 = 75;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Normal,
    GuardianDeath,
    CoordinatorDeath,
    AppEarlyExit,
    StartupTimeout,
    TuiEarlyExit,
    WorkerFailure,
    StuckDescendant,
    CleanupMismatch,
    MalformedFrame,
    BarrierViolation,
    TrailingFrame,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, FixtureError> {
        match value {
            "normal" => Ok(Self::Normal),
            "guardian-death" => Ok(Self::GuardianDeath),
            "coordinator-death" => Ok(Self::CoordinatorDeath),
            "app-early-exit" => Ok(Self::AppEarlyExit),
            "startup-timeout" => Ok(Self::StartupTimeout),
            "tui-early-exit" => Ok(Self::TuiEarlyExit),
            "worker-failure" => Ok(Self::WorkerFailure),
            "stuck-descendant" => Ok(Self::StuckDescendant),
            "cleanup-mismatch" => Ok(Self::CleanupMismatch),
            "malformed-frame" => Ok(Self::MalformedFrame),
            "barrier-violation" => Ok(Self::BarrierViolation),
            "trailing-frame" => Ok(Self::TrailingFrame),
            _ => Err(FixtureError::Arguments),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::GuardianDeath => "guardian-death",
            Self::CoordinatorDeath => "coordinator-death",
            Self::AppEarlyExit => "app-early-exit",
            Self::StartupTimeout => "startup-timeout",
            Self::TuiEarlyExit => "tui-early-exit",
            Self::WorkerFailure => "worker-failure",
            Self::StuckDescendant => "stuck-descendant",
            Self::CleanupMismatch => "cleanup-mismatch",
            Self::MalformedFrame => "malformed-frame",
            Self::BarrierViolation => "barrier-violation",
            Self::TrailingFrame => "trailing-frame",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureRole {
    Coordinator,
    Guardian,
    Child(ChildRole),
    Contender,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureError {
    Arguments,
    Environment,
    Storage,
    Profile,
    Descriptor,
    Channel,
    Protocol,
    Process,
    Worker,
    Deadline,
    Invariant,
}

impl std::fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Arguments => "fixture arguments are invalid",
            Self::Environment => "fixture environment is invalid",
            Self::Storage => "fixture storage is invalid",
            Self::Profile => "fixture profile operation failed",
            Self::Descriptor => "fixture descriptor invariant failed",
            Self::Channel => "fixture lifecycle channel failed",
            Self::Protocol => "fixture lifecycle protocol failed",
            Self::Process => "fixture process operation failed",
            Self::Worker => "fixture worker failed",
            Self::Deadline => "fixture deadline expired",
            Self::Invariant => "fixture invariant failed",
        })
    }
}

impl std::error::Error for FixtureError {}

pub(crate) fn run_internal_fixture(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    match dispatch(arguments) {
        Ok(code) => code,
        Err(_) => ExitCode::from(EXIT_FAILURE),
    }
}

fn dispatch(arguments: impl IntoIterator<Item = OsString>) -> Result<ExitCode, FixtureError> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next().ok_or(FixtureError::Arguments)?;
    let role = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(FixtureError::Arguments)?;
    let (role, scenario) = match role.as_str() {
        "coordinator" | "guardian" => {
            let scenario = arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or(FixtureError::Arguments)?;
            let role = if role == "coordinator" {
                FixtureRole::Coordinator
            } else {
                FixtureRole::Guardian
            };
            (role, Some(Scenario::parse(&scenario)?))
        }
        "app" => (FixtureRole::Child(ChildRole::AppServer), None),
        "tui" => (FixtureRole::Child(ChildRole::Tui), None),
        "contender" => (FixtureRole::Contender, None),
        _ => return Err(FixtureError::Arguments),
    };
    if arguments.next().is_some() {
        return Err(FixtureError::Arguments);
    }

    match (role, scenario) {
        (FixtureRole::Coordinator, Some(scenario)) => run_coordinator(scenario),
        (FixtureRole::Guardian, Some(scenario)) => run_guardian(scenario),
        (FixtureRole::Child(role), None) => run_fake_child(role),
        (FixtureRole::Contender, None) => run_contender(),
        _ => Err(FixtureError::Arguments),
    }
}

#[derive(Clone)]
struct IdentitySet {
    identities: Vec<DescriptorIdentity>,
}

impl std::fmt::Debug for IdentitySet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentitySet")
            .field("count", &self.identities.len())
            .finish_non_exhaustive()
    }
}

impl IdentitySet {
    fn parse_environment(name: &str) -> Result<Self, FixtureError> {
        let encoded = env::var(name).map_err(|_| FixtureError::Environment)?;
        if encoded.is_empty() {
            return Ok(Self {
                identities: Vec::new(),
            });
        }
        let mut identities = Vec::new();
        for item in encoded.split(';') {
            if identities.len() == 8 {
                return Err(FixtureError::Environment);
            }
            let (device, inode) = item.split_once(',').ok_or(FixtureError::Environment)?;
            let identity = DescriptorIdentity {
                device: device.parse().map_err(|_| FixtureError::Environment)?,
                inode: inode.parse().map_err(|_| FixtureError::Environment)?,
            };
            if identity.inode == 0 || identities.contains(&identity) {
                return Err(FixtureError::Environment);
            }
            identities.push(identity);
        }
        Ok(Self { identities })
    }

    fn encode(identities: &[DescriptorIdentity]) -> Result<String, FixtureError> {
        if identities.len() > 8 || identities.iter().any(|identity| identity.inode == 0) {
            return Err(FixtureError::Descriptor);
        }
        let mut encoded = String::new();
        for (index, identity) in identities.iter().enumerate() {
            if identities[..index].contains(identity) {
                return Err(FixtureError::Descriptor);
            }
            if index != 0 {
                encoded.push(';');
            }
            use std::fmt::Write as _;
            write!(&mut encoded, "{},{}", identity.device, identity.inode)
                .map_err(|_| FixtureError::Descriptor)?;
        }
        Ok(encoded)
    }

    fn assert_absent(&self) -> Result<(), FixtureError> {
        for identity in &self.identities {
            if count_open_descriptors_with_identity(*identity)
                .map_err(|_| FixtureError::Descriptor)?
                != 0
            {
                return Err(FixtureError::Descriptor);
            }
        }
        Ok(())
    }
}

fn marker_root() -> Result<PathBuf, FixtureError> {
    let root = env::var_os(MARKER_ROOT_ENV)
        .map(PathBuf::from)
        .ok_or(FixtureError::Environment)?;
    if !root.is_absolute() || fs::canonicalize(&root).map_err(|_| FixtureError::Storage)? != root {
        return Err(FixtureError::Storage);
    }
    let metadata = fs::symlink_metadata(&root).map_err(|_| FixtureError::Storage)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(FixtureError::Storage);
    }
    Ok(root)
}

fn marker_path(name: &str) -> Result<PathBuf, FixtureError> {
    if name.is_empty()
        || name.len() > 48
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'.' || byte == b'-')
    {
        return Err(FixtureError::Invariant);
    }
    Ok(marker_root()?.join(name))
}

fn write_marker(name: &str, value: &[u8]) -> Result<(), FixtureError> {
    if value.len() > 32 {
        return Err(FixtureError::Invariant);
    }
    let path = marker_path(name)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| FixtureError::Storage)?;
    file.write_all(value).map_err(|_| FixtureError::Storage)?;
    file.sync_all().map_err(|_| FixtureError::Storage)
}

fn write_process_marker(name: &str, pid: i32) -> Result<(), FixtureError> {
    if pid <= 0 {
        return Err(FixtureError::Process);
    }
    let mut encoded = [0_u8; 12];
    let value = encode_positive_i32(pid, &mut encoded)?;
    write_marker(name, value)
}

fn encode_positive_i32(value: i32, buffer: &mut [u8; 12]) -> Result<&[u8], FixtureError> {
    if value <= 0 {
        return Err(FixtureError::Process);
    }
    let mut value = value as u32;
    let mut cursor = buffer.len();
    while value != 0 {
        cursor -= 1;
        buffer[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    Ok(&buffer[cursor..])
}

fn marker_exists(name: &str) -> Result<bool, FixtureError> {
    match fs::symlink_metadata(marker_path(name)?) {
        Ok(metadata) => Ok(metadata.file_type().is_file()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.permissions().mode() & 0o077 == 0),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(FixtureError::Storage),
    }
}

const PRE_START_ACTIVITY_MARKERS: [&str; 6] = [
    "worker.spawn-requested",
    "app.spawn-requested",
    "tui.spawn-requested",
    "worker.started",
    "app.started",
    "tui.started",
];

fn phase_barrier_has_no_spawn_activity() -> Result<bool, FixtureError> {
    for marker in PRE_START_ACTIVITY_MARKERS {
        if marker_exists(marker)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn current_fixture_executable() -> Result<PathBuf, FixtureError> {
    let executable = env::current_exe().map_err(|_| FixtureError::Process)?;
    let canonical = fs::canonicalize(&executable).map_err(|_| FixtureError::Process)?;
    if executable != canonical {
        return Err(FixtureError::Process);
    }
    Ok(executable)
}

fn profile() -> Result<(Registry, Profile), FixtureError> {
    let registry = Registry::discover().map_err(|_| FixtureError::Profile)?;
    let profile = registry
        .find(Provider::Codex, PROFILE_ALIAS)
        .map_err(|_| FixtureError::Profile)?;
    Ok((registry, profile))
}

fn run_contender() -> Result<ExitCode, FixtureError> {
    let (registry, profile) = profile()?;
    match registry.lock_profile(&profile) {
        Ok(_lease) => Ok(ExitCode::SUCCESS),
        Err(error) if error.code() == "profile_busy" => Ok(ExitCode::from(EXIT_BUSY)),
        Err(_) => Err(FixtureError::Profile),
    }
}

fn run_fake_child(role: ChildRole) -> Result<ExitCode, FixtureError> {
    let scenario = env::var("CALCIFER_SUPERVISOR_FIXTURE_SCENARIO")
        .map_err(|_| FixtureError::Environment)
        .and_then(|value| Scenario::parse(&value))?;
    write_marker(
        match role {
            ChildRole::AppServer => "app.started",
            ChildRole::Tui => "tui.started",
        },
        b"started\n",
    )?;
    write_process_marker(
        match role {
            ChildRole::AppServer => "app.pid",
            ChildRole::Tui => "tui.pid",
        },
        rustix::process::getpid().as_raw_pid(),
    )?;
    IdentitySet::parse_environment(CHILD_FORBIDDEN_ENV)?.assert_absent()?;

    if (scenario == Scenario::AppEarlyExit && role == ChildRole::AppServer)
        || (scenario == Scenario::TuiEarlyExit && role == ChildRole::Tui)
    {
        return Ok(ExitCode::from(31));
    }
    if scenario == Scenario::StartupTimeout && role == ChildRole::AppServer {
        return exec_shell("exec >/dev/null; while IFS= read -r _; do :; done");
    }
    if scenario == Scenario::StuckDescendant && role == ChildRole::Tui {
        return exec_shell(
            "trap '' TERM; /bin/sh -c 'trap \"\" TERM; while :; do /bin/sleep 1; done' >/dev/null 2>&1 & printf '%s\\n' \"$!\" > \"$CALCIFER_SUPERVISOR_FIXTURE_DESCENDANT_MARKER\"; printf R; exec >/dev/null; wait",
        );
    }
    exec_shell("printf R; exec >/dev/null; while IFS= read -r _; do :; done")
}

fn exec_shell(script: &str) -> Result<ExitCode, FixtureError> {
    let error = Command::new("/bin/sh").args(["-c", script]).exec();
    let _ = error.kind();
    Err(FixtureError::Process)
}

/// All authority retained after an untrusted guardian ending.
///
/// Keeping the child handle and both private channels in the same parked
/// object makes it impossible for future refactors to release one capability
/// while lock A remains deliberately process-lifetime state.
struct RetainedCoordinatorState {
    authority: RetainedCoordinatorLease,
    guardian: Child,
    lifecycle: LifecycleEndpoint,
    transfer: TransferChannelPair,
}

impl RetainedCoordinatorState {
    fn park(self) -> ! {
        let _ = (
            self.authority.reason(),
            self.guardian.id(),
            &self.lifecycle,
            &self.transfer,
        );
        std::mem::forget(self);
        loop {
            thread::park();
        }
    }
}

// The explicit drops below are capability-boundary operations: they end the
// receiver's borrow before the lifecycle endpoint is moved into retained
// process-lifetime state. The receiver itself intentionally owns no resource.
#[allow(clippy::drop_non_drop)]
fn run_coordinator(scenario: Scenario) -> Result<ExitCode, FixtureError> {
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

    // The optional descriptor-transfer transport is deliberately distinct
    // from lifecycle traffic. Keeping it live through every exec proves that
    // neither endpoint leaks even though this slice never transfers a lease.
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
    let expected_guardian_lifecycle = IdentitySet::encode(&[lifecycle_guardian])?;
    let guardian_forbidden = IdentitySet::encode(&[
        coordinator_lock_identity,
        lifecycle_coordinator,
        transfer_sender,
        transfer_receiver,
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);

    let spawned = match spawn_guardian_with_lifecycle_stdin(command, lifecycle_pair) {
        Ok(spawned) => spawned,
        Err(failure) => {
            let (lifecycle, guardian, _error) = failure.into_parts();
            let Some(guardian) = guardian else {
                // No process crossed the spawn boundary, so no provider lease
                // can exist and ordinary release of A is unambiguous.
                return Err(FixtureError::Channel);
            };
            retain_after_guardian_loss(
                coordinator_lease,
                guardian,
                lifecycle,
                transfer,
                RetentionReason::InvariantUnconfirmed,
            )
        }
    };
    let (mut guardian, lifecycle) = spawned.into_parts();
    if configure_endpoint(&lifecycle).is_err() || !child_is_own_process_group(&guardian) {
        retain_after_guardian_loss(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            RetentionReason::InvariantUnconfirmed,
        )
    }

    let mut receiver = CoordinatorReceiver::new(&lifecycle);
    match receiver.receive(phase_deadline()) {
        Ok(GuardianEvent::LeaseCommitted) => {}
        Ok(_) => {
            drop(receiver);
            retain_after_guardian_loss(
                coordinator_lease,
                guardian,
                lifecycle,
                transfer,
                RetentionReason::ProtocolInvalid,
            )
        }
        Err(error) => {
            let reason = retention_reason_for_receive_failure(&guardian, error);
            drop(receiver);
            retain_after_guardian_loss(coordinator_lease, guardian, lifecycle, transfer, reason)
        }
    }

    // LEASE_COMMITTED is a phase barrier: B must already exclude another
    // provider holder while no runtime worker or provider child exists yet.
    let phase_barrier_clean = phase_barrier_has_no_spawn_activity().is_ok_and(|clean| clean);
    if !phase_barrier_clean {
        drop(receiver);
        retain_after_guardian_loss(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            RetentionReason::InvariantUnconfirmed,
        )
    }
    match registry.lock_profile_provider(&profile) {
        Err(error) if error.code() == "profile_busy" => {}
        _ => {
            drop(receiver);
            retain_after_guardian_loss(
                coordinator_lease,
                guardian,
                lifecycle,
                transfer,
                RetentionReason::InvariantUnconfirmed,
            )
        }
    }
    if write_marker("coordinator.lease", b"committed\n").is_err() {
        drop(receiver);
        retain_after_guardian_loss(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            RetentionReason::InvariantUnconfirmed,
        )
    }
    if send_coordinator_command(&mut &lifecycle, CoordinatorCommand::Start, phase_deadline())
        .is_err()
    {
        drop(receiver);
        retain_after_guardian_loss(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            RetentionReason::LifecycleLost,
        )
    }

    // Retain only the bounded group numbers needed to reject duplicates while
    // parsing the live channel. They are never carried into recovery state or
    // used as delayed signal authority.
    let mut reported_groups: Vec<i32> = Vec::with_capacity(2);
    let terminal_session = loop {
        let event = match receiver.receive(phase_deadline()) {
            Ok(event) => event,
            Err(error) => {
                let reason = retention_reason_for_receive_failure(&guardian, error);
                drop(receiver);
                retain_after_guardian_loss(coordinator_lease, guardian, lifecycle, transfer, reason)
            }
        };
        match event {
            GuardianEvent::ChildStarted { role: _, pid, pgid } => {
                if reported_groups.len() == 2
                    || !reported_group_is_safe(&guardian, pid, pgid)
                    || reported_groups.contains(&pgid)
                {
                    drop(receiver);
                    retain_after_guardian_loss(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        RetentionReason::ProtocolInvalid,
                    )
                }
                reported_groups.push(pgid);
            }
            GuardianEvent::Ready => {
                if write_marker("coordinator.ready", b"ready\n").is_err() {
                    drop(receiver);
                    retain_after_guardian_loss(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        RetentionReason::InvariantUnconfirmed,
                    )
                }
                if scenario == Scenario::CoordinatorDeath {
                    drop(receiver);
                    RetainedCoordinatorState {
                        authority: RetainedCoordinatorLease::new(
                            coordinator_lease,
                            RetentionReason::LifecycleLost,
                        ),
                        guardian,
                        lifecycle,
                        transfer,
                    }
                    .park()
                }
                if send_coordinator_command(
                    &mut &lifecycle,
                    CoordinatorCommand::Stop,
                    phase_deadline(),
                )
                .is_err()
                {
                    drop(receiver);
                    retain_after_guardian_loss(
                        coordinator_lease,
                        guardian,
                        lifecycle,
                        transfer,
                        RetentionReason::LifecycleLost,
                    )
                }
            }
            GuardianEvent::Failed { .. } => {}
            GuardianEvent::ChildrenReaped { session, .. } => break session,
            GuardianEvent::LeaseCommitted => {
                drop(receiver);
                retain_after_guardian_loss(
                    coordinator_lease,
                    guardian,
                    lifecycle,
                    transfer,
                    RetentionReason::ProtocolInvalid,
                )
            }
        }
    };

    // The terminal frame is necessary but not sufficient. A is releasable
    // only after the guardian is an exactly-waited direct child and the stream
    // contains no trailing lifecycle data.
    let (status, forced_guardian_stop) = match wait_exact_child(&mut guardian, phase_deadline()) {
        Ok(status) => (status, false),
        Err(_) => {
            let _ = guardian.kill();
            match wait_exact_child(&mut guardian, phase_deadline()) {
                Ok(status) => (status, true),
                Err(_) => {
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
        drop(receiver);
        retain_after_reaped_guardian(
            coordinator_lease,
            guardian,
            lifecycle,
            transfer,
            RetentionReason::InvariantUnconfirmed,
        )
    }

    let _ = &transfer;
    drop(receiver);
    drop(lifecycle);
    drop(guardian);
    drop(coordinator_lease);
    let operational_session =
        if forced_guardian_stop || !guardian_status_matches_terminal(status, terminal_session) {
            SessionStatus::Failed
        } else {
            terminal_session
        };
    match operational_session {
        SessionStatus::Completed => {
            write_marker("coordinator.completed", b"complete\n")?;
            write_fixture_stdout(b"COMPLETED\n")?;
            Ok(ExitCode::SUCCESS)
        }
        SessionStatus::Failed => {
            write_marker("coordinator.failed", b"clean\n")?;
            write_fixture_stdout(b"FAILED_CLEAN\n")?;
            Ok(ExitCode::from(EXIT_FAILURE))
        }
    }
}

fn child_is_own_process_group(child: &Child) -> bool {
    let pid = rustix::process::Pid::from_child(child);
    rustix::process::getpgid(Some(pid)).is_ok_and(|pgid| pgid == pid)
}

fn reported_group_is_safe(guardian: &Child, pid: i32, pgid: i32) -> bool {
    if pid <= 0 || pid != pgid {
        return false;
    }
    let coordinator_pid = rustix::process::getpid().as_raw_pid();
    let coordinator_pgid = rustix::process::getpgrp().as_raw_pid();
    let Ok(guardian_pid) = i32::try_from(guardian.id()) else {
        return false;
    };
    if [coordinator_pid, coordinator_pgid, guardian_pid].contains(&pgid) {
        return false;
    }
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return false;
    };
    match rustix::process::getpgid(Some(pid)) {
        Ok(observed) => observed == pid,
        Err(rustix::io::Errno::SRCH) => false,
        Err(_) => false,
    }
}

fn retention_reason_for_receive_failure(guardian: &Child, error: ProtocolError) -> RetentionReason {
    match error {
        ProtocolError::Timeout | ProtocolError::UnexpectedEof | ProtocolError::Io => {
            // Observe without reaping. Calling `Child::try_wait` here would
            // make the numeric PID reusable before the retained-state path
            // invokes `kill`, turning even a direct-child handle into stale
            // signal authority.
            let pid = rustix::process::Pid::from_child(guardian);
            if rustix::process::waitid(
                rustix::process::WaitId::Pid(pid),
                rustix::process::WaitIdOptions::EXITED
                    | rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT,
            )
            .is_ok_and(|status| status.is_some())
            {
                RetentionReason::GuardianExited
            } else {
                RetentionReason::LifecycleLost
            }
        }
        _ => RetentionReason::ProtocolInvalid,
    }
}

fn wait_exact_child(child: &mut Child, deadline: Instant) -> Result<ExitStatus, FixtureError> {
    let mut attempted = false;
    loop {
        if attempted && Instant::now() >= deadline {
            return Err(FixtureError::Deadline);
        }
        attempted = true;
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(FixtureError::Deadline);
                }
                thread::sleep(remaining.min(WAIT_POLL));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(FixtureError::Process),
        }
    }
}

fn guardian_status_matches_terminal(status: ExitStatus, session: SessionStatus) -> bool {
    match session {
        SessionStatus::Completed => status.success(),
        SessionStatus::Failed => status.code() == Some(i32::from(EXIT_FAILURE)),
    }
}

fn retain_after_guardian_loss(
    coordinator_lease: CoordinatorProfileLease,
    mut guardian: Child,
    lifecycle: LifecycleEndpoint,
    transfer: TransferChannelPair,
    reason: RetentionReason,
) -> ! {
    // Lifecycle-reported PIDs and PGIDs are metadata, never signal authority.
    // Once the guardian is untrusted there is no portable process-birth handle
    // with which to distinguish a still-owned group from a reused numeric PID.
    // Kill and reap only the exact direct guardian child, then retain A. Fixed
    // synthetic children use a guardian-liveness pipe so an abrupt guardian
    // death cannot leave them behind.
    let _ = guardian.kill();
    let _ = wait_exact_child(&mut guardian, phase_deadline());
    park_retained_coordinator(coordinator_lease, guardian, lifecycle, transfer, reason)
}

fn retain_after_reaped_guardian(
    coordinator_lease: CoordinatorProfileLease,
    guardian: Child,
    lifecycle: LifecycleEndpoint,
    transfer: TransferChannelPair,
    reason: RetentionReason,
) -> ! {
    // The caller already consumed exact wait authority. Never signal this
    // `Child` again: its numeric PID is now reusable even though the Rust
    // handle can still return its cached exit status.
    park_retained_coordinator(coordinator_lease, guardian, lifecycle, transfer, reason)
}

fn park_retained_coordinator(
    coordinator_lease: CoordinatorProfileLease,
    guardian: Child,
    lifecycle: LifecycleEndpoint,
    transfer: TransferChannelPair,
    reason: RetentionReason,
) -> ! {
    let _ = write_fixture_stdout(b"RETAINED\n");
    // The marker is the external fault-injection synchronization point. It is
    // published only after fixed output is flushed so killing the deliberately
    // parked coordinator cannot observe a partial diagnostic.
    let _ = write_marker("coordinator.retained", b"retained\n");
    RetainedCoordinatorState {
        authority: RetainedCoordinatorLease::new(coordinator_lease, reason),
        guardian,
        lifecycle,
        transfer,
    }
    .park()
}

fn write_fixture_stdout(value: &[u8]) -> Result<(), FixtureError> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout
        .write_all(value)
        .and_then(|()| stdout.flush())
        .map_err(|_| FixtureError::Process)
}

// Guardian implementation follows below. Keeping every role behind the same
// fixed executable makes the real exec boundary directly testable.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerResult {
    Clean,
    Failed,
}

struct FixtureWorker {
    stop: Sender<()>,
    handle: Option<JoinHandle<WorkerResult>>,
}

struct RetainedGuardianWorkerState {
    provider_lease: ProfileLease,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
}

impl RetainedGuardianWorkerState {
    fn park(self) -> ! {
        let _ = (
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

struct RetainedGuardianCleanupState {
    provider_lease: ProfileLease,
    cleanup: RuntimeCleanupFailure,
}

impl RetainedGuardianCleanupState {
    fn park(self) -> ! {
        let _ = (
            self.provider_lease.provider_lock_file(),
            self.cleanup.error(),
        );
        std::mem::forget(self);
        loop {
            thread::park();
        }
    }
}

impl FixtureWorker {
    fn start(
        _authorization: &StartAuthorization,
        scenario: Scenario,
    ) -> Result<Self, FixtureError> {
        // This synchronous marker precedes `thread::spawn`, so the coordinator
        // cannot miss an early spawn request merely because the new worker has
        // not been scheduled yet.
        write_marker("worker.spawn-requested", b"requested\n")?;
        let (stop_sender, stop_receiver) = mpsc::channel();
        let (started_sender, started_receiver) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("calcifer-fixture-worker".to_owned())
            .spawn(move || {
                let marker = write_marker("worker.started", b"started\n");
                let _ = started_sender.send(marker.is_ok());
                if marker.is_err() || scenario == Scenario::WorkerFailure {
                    WorkerResult::Failed
                } else if stop_receiver.recv().is_ok() {
                    WorkerResult::Clean
                } else {
                    WorkerResult::Failed
                }
            })
            .map_err(|_| FixtureError::Worker)?;
        if !started_receiver
            .recv_timeout(PHASE_TIMEOUT)
            .map_err(|_| FixtureError::Worker)?
        {
            return Err(FixtureError::Worker);
        }
        Ok(Self {
            stop: stop_sender,
            handle: Some(handle),
        })
    }

    fn join_bounded(mut self) -> Result<WorkerJoinStatus, Self> {
        let _ = self.stop.send(());
        let deadline = phase_deadline();
        let mut attempted = false;
        loop {
            if attempted && Instant::now() >= deadline {
                return Err(self);
            }
            attempted = true;
            if self.handle.as_ref().is_none_or(JoinHandle::is_finished) {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(self);
            }
            thread::sleep(remaining.min(WAIT_POLL));
        }
        let Some(handle) = self.handle.take() else {
            return Ok(WorkerJoinStatus::JoinedPanicked);
        };
        Ok(match handle.join() {
            Ok(WorkerResult::Clean) => WorkerJoinStatus::JoinedClean,
            Ok(WorkerResult::Failed) => WorkerJoinStatus::JoinedFailed,
            Err(_) => WorkerJoinStatus::JoinedPanicked,
        })
    }
}

fn configure_endpoint(endpoint: &LifecycleEndpoint) -> Result<(), FixtureError> {
    endpoint
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| FixtureError::Channel)?;
    endpoint
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| FixtureError::Channel)
}

fn phase_deadline() -> Instant {
    bounded_deadline(PHASE_TIMEOUT)
}

fn startup_deadline() -> Instant {
    bounded_deadline(STARTUP_TIMEOUT)
}

fn bounded_deadline(duration: Duration) -> Instant {
    match Instant::now().checked_add(duration) {
        Some(deadline) => deadline,
        // An Instant overflow cannot be represented as a recoverable protocol
        // error. Parking preserves every authority already in the caller's
        // stack and avoids unwinding through a lease-bearing process.
        None => loop {
            thread::park();
        },
    }
}

fn guardian_profile() -> Result<(Registry, Profile), FixtureError> {
    let profile_id = env::var(PROFILE_ID_ENV).map_err(|_| FixtureError::Environment)?;
    let registry = Registry::discover().map_err(|_| FixtureError::Profile)?;
    let profile = registry
        .find_by_id(Provider::Codex, &profile_id)
        .map_err(|_| FixtureError::Profile)?;
    if profile.alias != PROFILE_ALIAS {
        return Err(FixtureError::Profile);
    }
    Ok((registry, profile))
}

/// Capability produced only after the guardian receives the coordinator's
/// post-commit `START` command.
///
/// Worker and child spawn entrypoints require this token, making the phase
/// barrier a call-site invariant in addition to a fault-injection assertion.
struct StartAuthorization {
    _private: (),
}

fn receive_start<R: io::Read>(
    commands: &mut GuardianCommandReceiver<R>,
) -> Result<StartAuthorization, FixtureError> {
    if commands
        .receive(phase_deadline())
        .map_err(|_| FixtureError::Protocol)?
        != CoordinatorCommand::Start
    {
        return Err(FixtureError::Protocol);
    }
    Ok(StartAuthorization { _private: () })
}

fn create_fixture_runtime(
    _authorization: &StartAuthorization,
) -> Result<PrivateRuntime, FixtureError> {
    PrivateRuntime::create(&marker_root()?).map_err(|_| FixtureError::Storage)
}

fn fake_child_command(
    role: ChildRole,
    scenario: Scenario,
    forbidden: &str,
) -> Result<Command, FixtureError> {
    let mut command = Command::new(current_fixture_executable()?);
    command
        .arg(match role {
            ChildRole::AppServer => "app",
            ChildRole::Tui => "tui",
        })
        .env("CALCIFER_SUPERVISOR_FIXTURE_SCENARIO", scenario.as_str())
        .env(CHILD_FORBIDDEN_ENV, forbidden)
        .env(DESCENDANT_MARKER_ENV, marker_path("descendant.pid")?);
    Ok(command)
}

fn spawn_managed_child(
    _authorization: &StartAuthorization,
    role: ChildRole,
    scenario: Scenario,
    forbidden: &str,
) -> Result<ManagedGroupChild, FixtureError> {
    // Record the guardian's request synchronously before `Command::spawn`.
    // Child-side `*.started` markers remain a separate real-exec proof.
    write_marker(
        match role {
            ChildRole::AppServer => "app.spawn-requested",
            ChildRole::Tui => "tui.spawn-requested",
        },
        b"requested\n",
    )?;
    let command = fake_child_command(role, scenario, forbidden)?;
    match ManagedGroupChild::spawn_with_parent_liveness_pipe(role, command, true) {
        Ok(child) => Ok(child),
        Err(mut failure) => {
            if failure.state() == SpawnFailureState::NotStarted {
                return Err(FixtureError::Process);
            }
            failure.park()
        }
    }
}

fn run_guardian(scenario: Scenario) -> Result<ExitCode, FixtureError> {
    let endpoint = bootstrap_guardian_from_stdin().map_err(|_| FixtureError::Channel)?;
    configure_endpoint(&endpoint)?;
    let guardian_forbidden = IdentitySet::parse_environment(GUARDIAN_FORBIDDEN_ENV)?;
    guardian_forbidden.assert_absent()?;
    let expected_lifecycle = IdentitySet::parse_environment(GUARDIAN_LIFECYCLE_ENV)?;
    let observed_lifecycle = endpoint
        .descriptor_identity()
        .map_err(|_| FixtureError::Descriptor)?
        .for_scan();
    if expected_lifecycle.identities.as_slice() != [observed_lifecycle] {
        return Err(FixtureError::Descriptor);
    }
    write_process_marker("guardian.pid", rustix::process::getpid().as_raw_pid())?;

    let (registry, profile) = guardian_profile()?;
    if scenario == Scenario::BarrierViolation {
        // Fault injection: model a synchronous worker-spawn request before B
        // is acquired. The coordinator must reject the marker after the
        // guardian later publishes B ownership, without authorizing a worker.
        write_marker("worker.spawn-requested", b"requested\n")?;
    }
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
    let lifecycle_identity = endpoint
        .descriptor_identity()
        .map_err(|_| FixtureError::Descriptor)?
        .for_scan();
    let mut child_identities = guardian_forbidden.identities.clone();
    child_identities.push(provider_identity);
    child_identities.push(lifecycle_identity);
    let child_forbidden = IdentitySet::encode(&child_identities)?;

    send_guardian_event(
        &mut &endpoint,
        GuardianEvent::LeaseCommitted,
        phase_deadline(),
    )
    .map_err(|_| FixtureError::Protocol)?;
    let mut commands = GuardianCommandReceiver::new(&endpoint);
    let start_authorization = receive_start(&mut commands)?;

    if scenario == Scenario::MalformedFrame {
        (&endpoint)
            .write_all(b"invalid-lifecycle-frame")
            .map_err(|_| FixtureError::Protocol)?;
        return Err(FixtureError::Protocol);
    }

    let runtime = create_fixture_runtime(&start_authorization)?;
    let worker = match FixtureWorker::start(&start_authorization, scenario) {
        Ok(worker) => worker,
        Err(error) => match runtime.cleanup() {
            Ok(_) => return Err(error),
            Err(cleanup) => RetainedGuardianCleanupState {
                provider_lease,
                cleanup,
            }
            .park(),
        },
    };
    if scenario == Scenario::WorkerFailure {
        return finish_guardian(
            &endpoint,
            provider_lease,
            runtime,
            worker,
            None,
            None,
            Some((Phase::Worker, FailureCode::Worker)),
            true,
            scenario,
        );
    }

    let mut app = match spawn_managed_child(
        &start_authorization,
        ChildRole::AppServer,
        scenario,
        &child_forbidden,
    ) {
        Ok(app) => app,
        Err(_) => {
            return finish_guardian(
                &endpoint,
                provider_lease,
                runtime,
                worker,
                None,
                None,
                Some((Phase::AppServer, FailureCode::Spawn)),
                true,
                scenario,
            );
        }
    };
    let app_identity = app.containment();
    if send_guardian_event(
        &mut &endpoint,
        GuardianEvent::ChildStarted {
            role: ChildRole::AppServer,
            pid: app_identity.pid(),
            pgid: app_identity.pgid(),
        },
        phase_deadline(),
    )
    .is_err()
    {
        return finish_guardian(
            &endpoint,
            provider_lease,
            runtime,
            worker,
            Some(app),
            None,
            Some((Phase::Protocol, FailureCode::InvalidControl)),
            false,
            scenario,
        );
    }
    if app.await_ready(startup_deadline()).is_err() {
        return finish_guardian(
            &endpoint,
            provider_lease,
            runtime,
            worker,
            Some(app),
            None,
            Some((Phase::Readiness, readiness_failure_code(scenario))),
            true,
            scenario,
        );
    }

    let mut tui = match spawn_managed_child(
        &start_authorization,
        ChildRole::Tui,
        scenario,
        &child_forbidden,
    ) {
        Ok(tui) => tui,
        Err(_) => {
            return finish_guardian(
                &endpoint,
                provider_lease,
                runtime,
                worker,
                Some(app),
                None,
                Some((Phase::Tui, FailureCode::Spawn)),
                true,
                scenario,
            );
        }
    };
    let tui_identity = tui.containment();
    if send_guardian_event(
        &mut &endpoint,
        GuardianEvent::ChildStarted {
            role: ChildRole::Tui,
            pid: tui_identity.pid(),
            pgid: tui_identity.pgid(),
        },
        phase_deadline(),
    )
    .is_err()
    {
        return finish_guardian(
            &endpoint,
            provider_lease,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some((Phase::Protocol, FailureCode::InvalidControl)),
            false,
            scenario,
        );
    }
    if tui.await_ready(startup_deadline()).is_err() {
        return finish_guardian(
            &endpoint,
            provider_lease,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some((Phase::Readiness, readiness_failure_code(scenario))),
            true,
            scenario,
        );
    }
    let liveness_failure = match (
        app.poll_liveness(phase_deadline()),
        tui.poll_liveness(phase_deadline()),
    ) {
        (Ok(ChildLiveness::Running), Ok(ChildLiveness::Running)) => None,
        (Ok(_), Ok(_)) => Some(FailureCode::EarlyExit),
        _ => Some(FailureCode::Containment),
    };
    if let Some(code) = liveness_failure {
        return finish_guardian(
            &endpoint,
            provider_lease,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some((Phase::Readiness, code)),
            true,
            scenario,
        );
    }

    if send_guardian_event(&mut &endpoint, GuardianEvent::Ready, phase_deadline()).is_err() {
        return finish_guardian(
            &endpoint,
            provider_lease,
            runtime,
            worker,
            Some(app),
            Some(tui),
            Some((Phase::Protocol, FailureCode::InvalidControl)),
            false,
            scenario,
        );
    }
    if scenario == Scenario::GuardianDeath {
        let _ =
            rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::KILL);
        loop {
            thread::park();
        }
    }

    let stop = commands.receive(phase_deadline());
    let channel_live = matches!(stop, Ok(CoordinatorCommand::Stop));
    finish_guardian(
        &endpoint,
        provider_lease,
        runtime,
        worker,
        Some(app),
        Some(tui),
        if channel_live {
            None
        } else {
            Some((Phase::Protocol, FailureCode::InvalidControl))
        },
        channel_live,
        scenario,
    )
}

const fn readiness_failure_code(scenario: Scenario) -> FailureCode {
    match scenario {
        Scenario::StartupTimeout => FailureCode::Timeout,
        _ => FailureCode::EarlyExit,
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_guardian(
    endpoint: &LifecycleEndpoint,
    provider_lease: ProfileLease,
    runtime: PrivateRuntime,
    worker: FixtureWorker,
    app: Option<ManagedGroupChild>,
    tui: Option<ManagedGroupChild>,
    mut failure: Option<(Phase, FailureCode)>,
    mut channel_live: bool,
    scenario: Scenario,
) -> Result<ExitCode, FixtureError> {
    let mut failure_announced = false;
    if channel_live {
        if let Some((phase, code)) = failure {
            if send_guardian_event(
                &mut &*endpoint,
                GuardianEvent::Failed { phase, code },
                phase_deadline(),
            )
            .is_ok()
            {
                failure_announced = true;
            } else {
                channel_live = false;
            }
        }
    }

    let shutdown = match shutdown_pair(tui, app, SHUTDOWN_GRACE, SHUTDOWN_FORCE) {
        Ok(outcome) => outcome,
        Err(mut unreaped) => {
            let _ = &provider_lease;
            unreaped.park()
        }
    };
    if failure.is_none() && shutdown.failure().is_some() {
        failure = Some((Phase::Reap, FailureCode::Containment));
    }
    let children = shutdown.children();
    if failure.is_none()
        && [children.app_server(), children.tui()]
            .into_iter()
            .any(disposition_required_kill)
    {
        failure = Some((Phase::Shutdown, FailureCode::Containment));
    }
    let worker_status = match worker.join_bounded() {
        Ok(status) => status,
        Err(worker) => RetainedGuardianWorkerState {
            provider_lease,
            runtime,
            worker,
        }
        .park(),
    };
    if failure.is_none() && worker_status != WorkerJoinStatus::JoinedClean {
        failure = Some((Phase::Worker, FailureCode::Worker));
    }

    if scenario == Scenario::CleanupMismatch
        && fs::write(runtime.path().join("unexpected"), b"synthetic").is_err()
    {
        let _ = &provider_lease;
        loop {
            thread::park();
        }
    }
    let cleanup = match runtime.cleanup() {
        Ok(cleanup) => cleanup,
        Err(cleanup) => {
            if channel_live && !failure_announced {
                let _ = send_guardian_event(
                    &mut &*endpoint,
                    GuardianEvent::Failed {
                        phase: Phase::Cleanup,
                        code: FailureCode::CleanupMismatch,
                    },
                    phase_deadline(),
                );
            }
            let _ = write_marker("guardian.cleaned", b"unconfirmed\n");
            RetainedGuardianCleanupState {
                provider_lease,
                cleanup,
            }
            .park()
        }
    };
    let _ = cleanup;
    write_marker("guardian.cleaned", b"complete\n")?;

    if !channel_live {
        drop(provider_lease);
        return Ok(ExitCode::from(EXIT_FAILURE));
    }
    if let Some((phase, code)) = failure {
        // A shutdown/worker failure discovered after the initial notification
        // needs its one allowed FAILED event before terminal authority.
        if !failure_announced {
            send_guardian_event(
                &mut &*endpoint,
                GuardianEvent::Failed { phase, code },
                phase_deadline(),
            )
            .map_err(|_| FixtureError::Protocol)?;
        }
    }
    let session = if failure.is_some() {
        SessionStatus::Failed
    } else {
        SessionStatus::Completed
    };
    send_guardian_event(
        &mut &*endpoint,
        GuardianEvent::ChildrenReaped {
            app: children.app_server(),
            tui: children.tui(),
            worker: worker_status,
            cleanup: CleanupStatus::Complete,
            session,
        },
        phase_deadline(),
    )
    .map_err(|_| FixtureError::Protocol)?;
    if scenario == Scenario::TrailingFrame {
        (&*endpoint)
            .write_all(b"x")
            .map_err(|_| FixtureError::Protocol)?;
    }
    drop(provider_lease);
    Ok(if session == SessionStatus::Completed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    })
}

const fn disposition_required_kill(disposition: ChildDisposition) -> bool {
    matches!(
        disposition,
        ChildDisposition::Exited {
            stop_action: StopAction::Kill,
            ..
        } | ChildDisposition::Signaled {
            stop_action: StopAction::Kill,
            ..
        }
    )
}
