//! Sealed command plans for the default-off supervised Codex provider.
//!
//! This slice deliberately creates no socket or child. It binds both future
//! commands to one compatibility-proven private executable stage and makes the
//! post-terminal-arm authorization a linear prerequisite.

use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::super::handoff_compat::{
    CodexHandoffCapability, CodexHandoffError, CodexHandoffFailure, CodexHandoffResolution,
    PinnedExecutableStage, PinnedStageError, verify_codex_handoff_compatibility,
};
#[cfg(test)]
use super::super::handoff_compat::{PinnedStageCleanupFault, PinnedStageCreateFailure};
#[cfg(test)]
use super::process::ShutdownOutcome;
use super::process::{
    ContainmentMetadata, ManagedGroupChild, PinnedAppGracefulDrain, ProcessError, SpawnFailure,
    SpawnFailureState, UnreapedChildren, shutdown_app_server_child,
};
use super::protocol::{ChildRole, CoordinatorCommand, GuardianCommandReceiver, ProtocolError};
use super::runtime::{
    AppSocketCleanupAuthority, AppSocketCleanupFailure, AppSocketError, AppSocketReservation,
    AppSocketReservationFailure, CleanRuntime, ExactRelayRoute, OwnedAppSocket, PrivateRuntime,
    RuntimeCleanupFailure, RuntimeError,
};
use crate::profiles::{Registry, TargetGuardianLease};
use crate::providers::codex::remote::{
    ExactResumeProbe, ReadinessProxy, ReadinessProxyError, ReadinessProxyStartFailure,
};

const MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES: usize = 103;
const APP_PLAN_MINTED: u8 = 1 << 0;
const TUI_PLAN_MINTED: u8 = 1 << 1;
#[cfg(test)]
const MONITOR_CAPABILITY_MINTED: u8 = 1 << 2;
const EXACT_RELAY_PLAN_MINTED: u8 = 1 << 3;
static NEXT_SESSION_BRAND: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Eq, PartialEq)]
struct SessionBrand(u64);

impl SessionBrand {
    fn next() -> Self {
        match NEXT_SESSION_BRAND.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        }) {
            Ok(value) => Self(value),
            Err(_) => std::process::abort(),
        }
    }
}

enum GuardianLeaseOwner {
    Production(TargetGuardianLease),
    #[cfg(test)]
    Test,
    /// Fixed negative-test authority used to prove that the guardian half of
    /// the split denyset independently rejects a leaked B descriptor.
    #[cfg(test)]
    InjectedTestDescriptor(File),
}

struct SessionLifetime {
    lease: GuardianLeaseOwner,
}

pub(super) struct SessionRuntimeGuard {
    lifetime: Arc<SessionLifetime>,
}

impl SessionRuntimeGuard {
    fn retain(build: &PinnedSessionBuild) -> Self {
        Self {
            lifetime: Arc::clone(&build.lifetime),
        }
    }

    fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        match &self.lifetime.lease {
            GuardianLeaseOwner::Production(lease) => lease.append_forbidden_descriptor(forbidden),
            #[cfg(test)]
            GuardianLeaseOwner::Test => Ok(()),
            #[cfg(test)]
            GuardianLeaseOwner::InjectedTestDescriptor(descriptor) => {
                forbidden.capture(descriptor.as_fd())
            }
        }
    }
}

impl fmt::Debug for SessionRuntimeGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.lifetime;
        formatter.write_str("SessionRuntimeGuard(<redacted>)")
    }
}

impl fmt::Debug for SessionLifetime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.lease {
            GuardianLeaseOwner::Production(lease) => {
                let _ = lease;
            }
            #[cfg(test)]
            GuardianLeaseOwner::Test => {}
            #[cfg(test)]
            GuardianLeaseOwner::InjectedTestDescriptor(descriptor) => {
                let _ = descriptor;
            }
        }
        formatter.write_str("SessionLifetime(<redacted>)")
    }
}

/// One guardian-owned immutable session before terminal-arm acceptance.
///
/// The selected lease, home identity, working directory, thread UUID, and
/// process-local brand are minted together. They cannot be recombined from
/// values belonging to different sessions at the provider boundary.
#[must_use = "guardian session authority retains the selected provider lease"]
pub(super) struct GuardianSessionAuthority {
    lease: GuardianLeaseOwner,
    spec: VerifiedSessionSpec,
    brand: SessionBrand,
}

impl fmt::Debug for GuardianSessionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.lease, &self.spec, self.brand);
        formatter.write_str("GuardianSessionAuthority(<redacted>)")
    }
}

/// Admits one production session from the provider lease already owned by the
/// target guardian. No production constructor accepts a raw CODEX_HOME.
pub(super) fn admit_guardian_session(
    guardian_lease: TargetGuardianLease,
    registry: &Registry,
    working_directory: &Path,
    thread_id: &str,
) -> Result<GuardianSessionAuthority, Box<GuardianSessionAdmissionFailure>> {
    let selected_home = match registry.profile_home(guardian_lease.profile()) {
        Ok(home) => home,
        Err(_) => {
            return Err(Box::new(GuardianSessionAdmissionFailure {
                guardian_lease,
                error: ProviderLaunchError::InvalidArgument,
            }));
        }
    };
    let spec = match VerifiedSessionSpec::capture(&selected_home, working_directory, thread_id) {
        Ok(spec) => spec,
        Err(error) => {
            return Err(Box::new(GuardianSessionAdmissionFailure {
                guardian_lease,
                error,
            }));
        }
    };
    Ok(GuardianSessionAuthority {
        lease: GuardianLeaseOwner::Production(guardian_lease),
        spec,
        brand: SessionBrand::next(),
    })
}

#[must_use = "admission failure retains the target guardian lease"]
pub(super) struct GuardianSessionAdmissionFailure {
    guardian_lease: TargetGuardianLease,
    error: ProviderLaunchError,
}

impl GuardianSessionAdmissionFailure {
    pub(super) const fn error(&self) -> ProviderLaunchError {
        self.error
    }
}

impl fmt::Debug for GuardianSessionAdmissionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.guardian_lease;
        formatter
            .debug_struct("GuardianSessionAdmissionFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for GuardianSessionAdmissionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for GuardianSessionAdmissionFailure {}

/// Linear authority reserved for the exact transition after the guardian has
/// accepted the coordinator's terminal-arm acknowledgement.
///
/// Its only mint consumes that accepted transition from the guardian's sealed
/// lifecycle validator; lower type states cannot manufacture it.
pub(in crate::providers::codex) struct ProviderLaunchAuthorization {
    session: GuardianSessionAuthority,
}

/// Consumes the guardian validator's exact post-`TerminalArmed` acceptance
/// frame. Neither `START` nor an unvalidated command value can mint launch
/// authority.
pub(super) fn accept_provider_launch_authorization<R: Read>(
    session: GuardianSessionAuthority,
    receiver: &mut GuardianCommandReceiver<R>,
    deadline: Instant,
) -> Result<ProviderLaunchAuthorization, Box<ProviderArmFailure>> {
    let command = match receiver.receive(deadline) {
        Ok(command) => command,
        Err(error) => return Err(Box::new(ProviderArmFailure { session, error })),
    };
    match command {
        CoordinatorCommand::TerminalArmAccepted => Ok(ProviderLaunchAuthorization { session }),
        _ => Err(Box::new(ProviderArmFailure {
            session,
            error: ProtocolError::UnexpectedState,
        })),
    }
}

#[must_use = "arm failure retains the guardian session and provider lease"]
pub(super) struct ProviderArmFailure {
    session: GuardianSessionAuthority,
    error: ProtocolError,
}

impl ProviderArmFailure {
    #[cfg(test)]
    pub(super) const fn error(&self) -> ProtocolError {
        self.error
    }

    #[cfg(test)]
    pub(super) fn into_session(self) -> GuardianSessionAuthority {
        self.session
    }
}

impl fmt::Debug for ProviderArmFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.session;
        formatter
            .debug_struct("ProviderArmFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ProviderArmFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for ProviderArmFailure {}

impl fmt::Debug for ProviderLaunchAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderLaunchAuthorization(<redacted>)")
    }
}

/// Runs every process-spawning compatibility proof only after the exact
/// terminal-arm acknowledgement has been accepted. Failure returns both the
/// post-arm authority and any filesystem/process ownership retained by the
/// compatibility gate.
pub(super) fn verify_authorized_compatibility(
    authorization: ProviderLaunchAuthorization,
    codex_executable: &Path,
    timeout: Duration,
) -> Result<PinnedSessionBuild, Box<AuthorizedCompatibilityFailure>> {
    match verify_codex_handoff_compatibility(&authorization, codex_executable, timeout) {
        Ok(capability) => Ok(PinnedSessionBuild::from_compatibility(
            authorization,
            capability,
        )),
        Err(failure) => Err(Box::new(AuthorizedCompatibilityFailure {
            authorization,
            failure,
        })),
    }
}

/// Test-only post-arm compatibility seam used by the deterministic packaged
/// process matrix. It skips provider protocol probing but still captures and
/// stages the exact fixture executable, retains partial stage construction,
/// and returns the same linear build/failure owners consumed by production
/// startup and shutdown.
#[cfg(test)]
pub(super) fn verify_authorized_test_compatibility(
    authorization: ProviderLaunchAuthorization,
    codex_executable: &Path,
    stage_parent: &Path,
    timeout: Duration,
) -> Result<PinnedSessionBuild, Box<AuthorizedCompatibilityFailure>> {
    let capability =
        match super::super::handoff_compat::TestCompatibilityCapability::capture_and_pin_authorized(
            codex_executable,
            stage_parent,
            timeout,
        ) {
            Ok(capability) => capability,
            Err(failure) => {
                return Err(Box::new(AuthorizedCompatibilityFailure {
                    authorization,
                    failure,
                }));
            }
        };
    Ok(PinnedSessionBuild::from_compatibility(
        authorization,
        capability,
    ))
}

#[must_use = "compatibility failure retains post-arm and probe ownership"]
pub(super) struct AuthorizedCompatibilityFailure {
    authorization: ProviderLaunchAuthorization,
    failure: CodexHandoffFailure,
}

impl AuthorizedCompatibilityFailure {
    pub(super) const fn error(&self) -> CodexHandoffError {
        self.failure.error()
    }

    pub(super) const fn has_retained_probe_ownership(&self) -> bool {
        self.failure.has_retained_ownership()
    }

    pub(super) const fn cleanup_error(&self) -> Option<CodexHandoffError> {
        self.failure.cleanup_error()
    }

    #[cfg(test)]
    pub(super) fn into_parts(self) -> (ProviderLaunchAuthorization, CodexHandoffFailure) {
        (self.authorization, self.failure)
    }

    /// Resolves retained probe/stage/scratch authority without releasing the
    /// already-accepted post-arm authorization. A failed retry reconstructs
    /// this complete owner, so terminal recovery can remain ordered outside
    /// the compatibility subsystem.
    pub(super) fn resolve(
        self: Box<Self>,
        deadline: Instant,
    ) -> Result<AuthorizedCompatibilityResolution, Box<Self>> {
        let Self {
            authorization,
            failure,
        } = *self;
        match Box::new(failure).resolve(deadline) {
            Ok(resolution) => Ok(AuthorizedCompatibilityResolution {
                authorization,
                resolution,
            }),
            Err(failure) => Err(Box::new(Self {
                authorization,
                failure: *failure,
            })),
        }
    }
}

impl fmt::Debug for AuthorizedCompatibilityFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.authorization, &self.failure);
        formatter
            .debug_struct("AuthorizedCompatibilityFailure")
            .field("error", &self.error())
            .field("cleanup_error", &self.cleanup_error())
            .field("retained", &self.has_retained_probe_ownership())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AuthorizedCompatibilityFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.failure.fmt(formatter)
    }
}

impl std::error::Error for AuthorizedCompatibilityFailure {}

/// Compatibility cleanup proof that deliberately keeps post-arm authority
/// alive until the surrounding startup failure restores/disarms the terminal.
#[must_use = "authorized compatibility resolution must release post-arm authority in order"]
pub(super) struct AuthorizedCompatibilityResolution {
    authorization: ProviderLaunchAuthorization,
    resolution: CodexHandoffResolution,
}

impl AuthorizedCompatibilityResolution {
    pub(super) const fn error(&self) -> CodexHandoffError {
        self.resolution.error()
    }

    pub(super) const fn cleanup_error(&self) -> Option<CodexHandoffError> {
        self.resolution.cleanup_error()
    }

    pub(super) fn release(self) -> CodexHandoffError {
        let Self {
            authorization,
            resolution,
        } = self;
        drop(authorization);
        resolution.release()
    }
}

impl fmt::Debug for AuthorizedCompatibilityResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.authorization;
        formatter
            .debug_struct("AuthorizedCompatibilityResolution")
            .field("error", &self.error())
            .field("cleanup_error", &self.cleanup_error())
            .finish_non_exhaustive()
    }
}

/// A lexically valid, portable Unix socket command address.
///
/// This does not prove that a socket exists. The later socket-owner type must
/// allocate below a short owner-private root and verify mode, owner, and inode
/// before minting this address. Raw paths are not accepted by command plans.
pub(super) struct VerifiedProviderSocketAddress {
    address: String,
    path: PathBuf,
}

impl VerifiedProviderSocketAddress {
    #[cfg(test)]
    fn for_test(path: &Path) -> Result<Self, ProviderLaunchError> {
        Self::from_verified_path(path)
    }

    fn from_verified_path(path: &Path) -> Result<Self, ProviderLaunchError> {
        if !path.is_absolute()
            || path.as_os_str().as_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES
        {
            return Err(ProviderLaunchError::InvalidArgument);
        }
        let rendered = path.to_str().ok_or(ProviderLaunchError::InvalidArgument)?;
        if rendered.chars().any(char::is_control) {
            return Err(ProviderLaunchError::InvalidArgument);
        }
        Ok(Self {
            address: format!("unix://{rendered}"),
            path: path.to_path_buf(),
        })
    }

    fn as_str(&self) -> &str {
        &self.address
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for VerifiedProviderSocketAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.address, &self.path);
        formatter.write_str("VerifiedProviderSocketAddress(<redacted>)")
    }
}

/// One sealed exact-resume route bound to the same immutable provider build,
/// thread, workspace, and guardian lease as the App Server/TUI plans.
///
/// The route itself was minted with the App reservation from one private
/// runtime layout. No caller can supply a downstream or upstream pathname.
#[must_use = "the exact relay plan must be spawned or deliberately retained"]
pub(super) struct ExactRelayPlan<'build> {
    route: ExactRelayRoute,
    build: &'build PinnedSessionBuild,
}

impl<'build> ExactRelayPlan<'build> {
    /// Mints the official remote-TUI command against this plan's fixed
    /// downstream socket. The returned command retains the same build borrow.
    pub(super) fn remote_tui_command(
        &self,
        deadline: Instant,
    ) -> Result<RemoteTuiCommand<'build>, ProviderLaunchError> {
        let address = VerifiedProviderSocketAddress::from_verified_path(Path::new(
            self.route.relay_address(),
        ))?;
        self.build.remote_tui_command(&address, deadline)
    }

    /// Binds the exact-resume relay with the build-owned canonical thread and
    /// descriptor-revalidated workspace. The raw probe inputs never cross the
    /// provider boundary.
    ///
    /// The App socket must already be adopted and its monitor connected. While
    /// this relay is live, no App-socket path revalidation or cleanup may run:
    /// the runtime checker intentionally treats `tui.sock` as an unknown entry.
    /// Ordered shutdown first resolves this relay, then cleans App/runtime.
    pub(super) fn spawn(
        self,
        timeout: Duration,
        deadline: Instant,
    ) -> Result<ExactRelaySession, Box<ExactRelayStartFailure>> {
        let runtime_guard = self.build.retain_runtime();
        let brand = self.build.brand;
        let route = self.route;
        if let Err(error) = self.build.revalidate_session_inputs(deadline) {
            return Err(Box::new(ExactRelayStartFailure {
                owner: ExactRelayStartOwner::Terminal {
                    route,
                    runtime_guard,
                    brand,
                },
                remote: None,
                error: ExactRelayStartError::Provider(error),
            }));
        }
        let working_directory = match self.build.working_directory.duplicate() {
            Ok(working_directory) => working_directory,
            Err(error) => {
                return Err(Box::new(ExactRelayStartFailure {
                    owner: ExactRelayStartOwner::Terminal {
                        route,
                        runtime_guard,
                        brand,
                    },
                    remote: None,
                    error: ExactRelayStartError::Provider(error),
                }));
            }
        };
        OwnedExactRelayStartPlan {
            route,
            target_thread_id: self.build.thread_id.clone(),
            working_directory,
            runtime_guard,
            brand,
        }
        .spawn(timeout)
    }

    #[cfg(test)]
    const fn session_brand_for_test(&self) -> u64 {
        self.build.brand_for_test()
    }
}

impl fmt::Debug for ExactRelayPlan<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.route, self.build.brand);
        formatter.write_str("ExactRelayPlan(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExactRelayStartError {
    Provider(ProviderLaunchError),
    Relay(ReadinessProxyError),
}

impl fmt::Display for ExactRelayStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => error.fmt(formatter),
            Self::Relay(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ExactRelayStartError {}

struct OwnedExactRelayStartPlan {
    route: ExactRelayRoute,
    target_thread_id: String,
    working_directory: VerifiedLaunchDirectory,
    runtime_guard: SessionRuntimeGuard,
    brand: SessionBrand,
}

impl OwnedExactRelayStartPlan {
    fn spawn(self, timeout: Duration) -> Result<ExactRelaySession, Box<ExactRelayStartFailure>> {
        match self.route.spawn_exact(
            ExactResumeProbe::new(&self.target_thread_id, self.working_directory.path()),
            timeout,
        ) {
            Ok(proxy) => Ok(ExactRelaySession {
                proxy,
                runtime_guard: self.runtime_guard,
                brand: self.brand,
            }),
            Err(remote) => {
                let error = remote.error();
                Err(Box::new(ExactRelayStartFailure {
                    owner: ExactRelayStartOwner::Retry(self),
                    remote: Some(remote),
                    error: ExactRelayStartError::Relay(error),
                }))
            }
        }
    }
}

enum ExactRelayStartOwner {
    Retry(OwnedExactRelayStartPlan),
    Terminal {
        route: ExactRelayRoute,
        runtime_guard: SessionRuntimeGuard,
        brand: SessionBrand,
    },
}

impl ExactRelayStartOwner {
    fn into_guard(self) -> SessionRuntimeGuard {
        match self {
            Self::Retry(plan) => plan.runtime_guard,
            Self::Terminal {
                route,
                runtime_guard,
                brand,
            } => {
                drop((route, brand));
                runtime_guard
            }
        }
    }
}

/// Running exact relay with an owned guardian-session guard. It has no borrow
/// back into `PinnedSessionBuild`, so partial-start owners can be aggregated
/// with that build without creating a self-reference.
#[must_use = "an exact relay session must be checked and explicitly shut down"]
pub(super) struct ExactRelaySession {
    proxy: ReadinessProxy,
    runtime_guard: SessionRuntimeGuard,
    brand: SessionBrand,
}

impl ExactRelaySession {
    /// Appends the exact relay listener and guardian-only lease retained by
    /// this session to one source-pinned child denyset.
    pub(super) fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        self.proxy.append_forbidden_descriptor(forbidden)?;
        self.runtime_guard.append_forbidden_descriptors(forbidden)
    }

    pub(super) fn poll_ready(
        &mut self,
    ) -> Result<Option<crate::providers::codex::remote::EffectiveThreadSettings>, ReadinessProxyError>
    {
        self.proxy.poll_ready()
    }

    pub(super) fn ensure_connected(&mut self) -> Result<(), ReadinessProxyError> {
        self.proxy.ensure_connected()
    }

    pub(super) fn shutdown(
        self,
        deadline: Instant,
    ) -> Result<ExactRelayShutdownComplete, Box<ExactRelayShutdownFailure>> {
        let Self {
            proxy,
            runtime_guard,
            brand,
        } = self;
        match proxy.shutdown(deadline) {
            Ok(remote) => Ok(ExactRelayShutdownComplete {
                remote,
                runtime_guard,
                brand,
            }),
            Err(remote) => Err(Box::new(ExactRelayShutdownFailure::from_remote(
                remote,
                runtime_guard,
                brand,
                None,
                None,
            ))),
        }
    }

    #[cfg(test)]
    const fn brand_for_test(&self) -> u64 {
        self.brand.0
    }
}

impl fmt::Debug for ExactRelaySession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.proxy, &self.runtime_guard, self.brand);
        formatter.write_str("ExactRelaySession(<redacted>)")
    }
}

#[must_use = "relay shutdown proof must release its guardian-session guard in order"]
pub(super) struct ExactRelayShutdownComplete {
    remote: crate::providers::codex::remote::ReadinessProxyShutdownComplete,
    runtime_guard: SessionRuntimeGuard,
    brand: SessionBrand,
}

impl ExactRelayShutdownComplete {
    pub(super) fn release(self) {
        let Self {
            remote,
            runtime_guard,
            brand,
        } = self;
        drop((remote, runtime_guard, brand));
    }
}

#[must_use = "relay shutdown failure retains ordered release or retry authority"]
pub(super) struct ExactRelayShutdownFailure {
    proxy: Option<ReadinessProxy>,
    operation_error: Option<ReadinessProxyError>,
    cleanup_error: Option<ReadinessProxyError>,
    runtime_guard: SessionRuntimeGuard,
    brand: SessionBrand,
}

impl ExactRelayShutdownFailure {
    fn from_remote(
        remote: crate::providers::codex::remote::ReadinessProxyShutdownFailure,
        runtime_guard: SessionRuntimeGuard,
        brand: SessionBrand,
        prior_operation: Option<ReadinessProxyError>,
        prior_cleanup: Option<ReadinessProxyError>,
    ) -> Self {
        let operation_error = prior_operation.or(remote.operation_error());
        let cleanup_error = prior_cleanup.or(remote.cleanup_error());
        Self {
            proxy: remote.into_proxy(),
            operation_error,
            cleanup_error,
            runtime_guard,
            brand,
        }
    }

    pub(super) fn error(&self) -> ReadinessProxyError {
        self.operation_error
            .or(self.cleanup_error)
            .unwrap_or(ReadinessProxyError::Worker)
    }

    pub(super) const fn operation_error(&self) -> Option<ReadinessProxyError> {
        self.operation_error
    }

    pub(super) const fn cleanup_error(&self) -> Option<ReadinessProxyError> {
        self.cleanup_error
    }

    /// Converts a completed remote shutdown error into its ordered release
    /// proof without consuming another retry budget. A missing proxy proves
    /// that worker join and socket cleanup already completed; only the
    /// operation error and guardian-session guard remain to be released.
    pub(super) fn try_resolve_without_retry(
        self: Box<Self>,
    ) -> Result<ExactRelayShutdownResolution, Box<Self>> {
        if self.proxy.is_some() {
            return Err(self);
        }
        let Self {
            proxy: _,
            operation_error,
            cleanup_error,
            runtime_guard,
            brand,
        } = *self;
        Ok(ExactRelayShutdownResolution {
            operation_error,
            cleanup_error,
            runtime_guard,
            brand,
        })
    }

    pub(super) fn resolve(
        self: Box<Self>,
        deadline: Instant,
    ) -> Result<ExactRelayShutdownResolution, Box<Self>> {
        let Self {
            proxy,
            operation_error,
            cleanup_error,
            runtime_guard,
            brand,
        } = *self;
        let Some(proxy) = proxy else {
            return Ok(ExactRelayShutdownResolution {
                operation_error,
                cleanup_error,
                runtime_guard,
                brand,
            });
        };
        match proxy.shutdown(deadline) {
            Ok(_) => Ok(ExactRelayShutdownResolution {
                operation_error,
                cleanup_error,
                runtime_guard,
                brand,
            }),
            Err(remote) => Box::new(Self::from_remote(
                remote,
                runtime_guard,
                brand,
                operation_error,
                cleanup_error,
            ))
            .try_resolve_without_retry(),
        }
    }
}

impl fmt::Debug for ExactRelayShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.proxy, &self.runtime_guard, self.brand);
        formatter
            .debug_struct("ExactRelayShutdownFailure")
            .field("operation_error", &self.operation_error)
            .field("cleanup_error", &self.cleanup_error)
            .field("retained", &self.proxy.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ExactRelayShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error().fmt(formatter)
    }
}

impl std::error::Error for ExactRelayShutdownFailure {}

#[must_use = "resolved relay shutdown must release its guardian-session guard in order"]
pub(super) struct ExactRelayShutdownResolution {
    operation_error: Option<ReadinessProxyError>,
    cleanup_error: Option<ReadinessProxyError>,
    runtime_guard: SessionRuntimeGuard,
    brand: SessionBrand,
}

impl ExactRelayShutdownResolution {
    pub(super) const fn operation_error(&self) -> Option<ReadinessProxyError> {
        self.operation_error
    }

    pub(super) const fn cleanup_error(&self) -> Option<ReadinessProxyError> {
        self.cleanup_error
    }

    pub(super) fn error(&self) -> Option<ReadinessProxyError> {
        self.operation_error.or(self.cleanup_error)
    }

    pub(super) fn release(self) -> Option<ReadinessProxyError> {
        let error = self.error();
        drop((self.runtime_guard, self.brand));
        error
    }
}

/// Exact relay start failure retaining both the branded plan and any bound
/// socket identity/listener cleanup authority.
#[must_use = "an exact relay start failure must resolve its bound socket owner"]
pub(super) struct ExactRelayStartFailure {
    owner: ExactRelayStartOwner,
    remote: Option<Box<ReadinessProxyStartFailure>>,
    error: ExactRelayStartError,
}

impl ExactRelayStartFailure {
    #[cfg(test)]
    pub(super) const fn error(&self) -> ExactRelayStartError {
        self.error
    }

    #[expect(
        clippy::boxed_local,
        reason = "the linear failure API keeps the large retry owner boxed across every failure edge"
    )]
    pub(super) fn resolve(self: Box<Self>) -> Result<ExactRelayStartResolution, Box<Self>> {
        let Self {
            owner,
            remote,
            error,
        } = *self;
        let Some(remote) = remote else {
            return Ok(ExactRelayStartResolution { owner, error });
        };
        match remote.cleanup() {
            Ok(_) => Ok(ExactRelayStartResolution { owner, error }),
            Err(remote) => Err(Box::new(Self {
                owner,
                remote: Some(remote),
                error,
            })),
        }
    }

    /// Normalizes a retained relay-start edge for a unified startup abort.
    /// The exact bound socket is resolved first; only then is the branded
    /// route abandoned and its guardian runtime guard released. Failure keeps
    /// this same `'static` owner for a later retry.
    pub(super) fn resolve_for_startup_abort(
        self: Box<Self>,
    ) -> Result<ExactRelayStartAbortResolution, Box<Self>> {
        let resolution = self.resolve()?;
        Ok(ExactRelayStartAbortResolution {
            error: resolution.abandon().release(),
        })
    }
}

impl fmt::Debug for ExactRelayStartFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bound_socket_retained = self
            .remote
            .as_deref()
            .is_some_and(ReadinessProxyStartFailure::has_bound_socket);
        formatter
            .debug_struct("ExactRelayStartFailure")
            .field("error", &self.error)
            .field("bound_socket_retained", &bound_socket_retained)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ExactRelayStartFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for ExactRelayStartFailure {}

/// Proof that a failed exact relay never became live and retains no bound
/// socket, route, or guardian runtime guard.
#[must_use = "relay start abort proof must be projected to startup"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExactRelayStartAbortResolution {
    error: ExactRelayStartError,
}

impl ExactRelayStartAbortResolution {
    #[cfg(test)]
    pub(super) const fn error(&self) -> ExactRelayStartError {
        self.error
    }

    pub(super) const fn release(self) -> ExactRelayStartError {
        self.error
    }
}

/// Resolved start failure. The plan can be retried or deliberately dropped
/// before App socket/runtime cleanup.
#[must_use = "a resolved relay start failure retains the branded retry plan"]
pub(super) struct ExactRelayStartResolution {
    owner: ExactRelayStartOwner,
    error: ExactRelayStartError,
}

impl ExactRelayStartResolution {
    #[cfg(test)]
    pub(super) const fn error(&self) -> ExactRelayStartError {
        self.error
    }

    #[cfg(test)]
    pub(super) fn retry(
        self,
        timeout: Duration,
    ) -> Result<ExactRelaySession, Box<ExactRelayStartFailure>> {
        match self.owner {
            ExactRelayStartOwner::Retry(plan) => plan.spawn(timeout),
            owner @ ExactRelayStartOwner::Terminal { .. } => {
                Err(Box::new(ExactRelayStartFailure {
                    owner,
                    remote: None,
                    error: self.error,
                }))
            }
        }
    }

    /// Deliberately abandons retry after socket cleanup and returns a terminal
    /// proof that still retains the guardian session until explicitly released.
    pub(super) fn abandon(self) -> ExactRelayStartAbandoned {
        ExactRelayStartAbandoned {
            runtime_guard: self.owner.into_guard(),
            error: self.error,
        }
    }
}

#[must_use = "abandoned relay startup must explicitly release its session guard"]
pub(super) struct ExactRelayStartAbandoned {
    runtime_guard: SessionRuntimeGuard,
    error: ExactRelayStartError,
}

impl ExactRelayStartAbandoned {
    pub(super) fn release(self) -> ExactRelayStartError {
        let Self {
            runtime_guard,
            error,
        } = self;
        drop(runtime_guard);
        error
    }
}

/// One exact, compatibility-proven Codex build authorized for a single
/// supervised session.
#[must_use = "a pinned session build must be explicitly cleaned or retained"]
pub(super) struct PinnedSessionBuild {
    executable: PinnedExecutableStage,
    lifetime: Arc<SessionLifetime>,
    selected_profile: SelectedProfileLaunch,
    working_directory: VerifiedLaunchDirectory,
    thread_id: String,
    brand: SessionBrand,
    minted_authorities: std::cell::Cell<u8>,
}

/// Opaque selected-profile authority retained for both provider children.
///
/// There is deliberately no production raw-path constructor. The guardian
/// integration must mint this from its selected profile reservation and lease.
pub(super) struct SelectedProfileLaunch {
    codex_home: VerifiedLaunchDirectory,
}

/// Immutable inputs shared by both provider children.
pub(super) struct VerifiedSessionSpec {
    selected_profile: SelectedProfileLaunch,
    working_directory: VerifiedLaunchDirectory,
    thread_id: String,
}

impl VerifiedSessionSpec {
    fn capture(
        codex_home: &Path,
        working_directory: &Path,
        thread_id: &str,
    ) -> Result<Self, ProviderLaunchError> {
        let codex_home = VerifiedLaunchDirectory::capture(codex_home, true)?;
        let working_directory = VerifiedLaunchDirectory::capture(working_directory, false)?;
        let thread_id = validate_thread_id(thread_id)?;
        Ok(Self {
            selected_profile: SelectedProfileLaunch { codex_home },
            working_directory,
            thread_id,
        })
    }
}

impl GuardianSessionAuthority {
    #[cfg(test)]
    pub(super) fn for_test(
        codex_home: &Path,
        working_directory: &Path,
        thread_id: &str,
    ) -> Result<Self, ProviderLaunchError> {
        Ok(Self {
            lease: GuardianLeaseOwner::Test,
            spec: VerifiedSessionSpec::capture(codex_home, working_directory, thread_id)?,
            brand: SessionBrand::next(),
        })
    }

    #[cfg(test)]
    pub(super) fn for_test_with_guardian_descriptor(
        codex_home: &Path,
        working_directory: &Path,
        thread_id: &str,
        descriptor: File,
    ) -> Result<Self, ProviderLaunchError> {
        Ok(Self {
            lease: GuardianLeaseOwner::InjectedTestDescriptor(descriptor),
            spec: VerifiedSessionSpec::capture(codex_home, working_directory, thread_id)?,
            brand: SessionBrand::next(),
        })
    }
}

struct VerifiedLaunchDirectory {
    path: PathBuf,
    descriptor: File,
    identity: LaunchDirectoryIdentity,
    private: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LaunchDirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl VerifiedLaunchDirectory {
    fn capture(path: &Path, private: bool) -> Result<Self, ProviderLaunchError> {
        if !path.is_absolute() {
            return Err(ProviderLaunchError::InvalidArgument);
        }
        let canonical = fs::canonicalize(path).map_err(|_| ProviderLaunchError::InvalidArgument)?;
        if canonical != path {
            return Err(ProviderLaunchError::InvalidArgument);
        }
        let visible =
            fs::symlink_metadata(&canonical).map_err(|_| ProviderLaunchError::InvalidArgument)?;
        let identity = launch_directory_identity(&visible, private)?;
        let descriptor = rustix::fs::open(
            &canonical,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| ProviderLaunchError::InvalidArgument)?;
        if launch_directory_identity(
            &descriptor
                .metadata()
                .map_err(|_| ProviderLaunchError::InvalidArgument)?,
            private,
        )? != identity
            || !launch_directory_acl_is_empty(&descriptor)
        {
            return Err(ProviderLaunchError::InvalidArgument);
        }
        Ok(Self {
            path: canonical,
            descriptor,
            identity,
            private,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn revalidate(&self) -> Result<(), ProviderLaunchError> {
        if fs::canonicalize(&self.path).map_err(|_| ProviderLaunchError::SessionChanged)?
            != self.path
        {
            return Err(ProviderLaunchError::SessionChanged);
        }
        let visible =
            fs::symlink_metadata(&self.path).map_err(|_| ProviderLaunchError::SessionChanged)?;
        let opened = self
            .descriptor
            .metadata()
            .map_err(|_| ProviderLaunchError::Storage)?;
        if launch_directory_identity(&visible, self.private)
            .map_err(|_| ProviderLaunchError::SessionChanged)?
            != self.identity
            || launch_directory_identity(&opened, self.private)
                .map_err(|_| ProviderLaunchError::SessionChanged)?
                != self.identity
            || !launch_directory_acl_is_empty(&self.descriptor)
        {
            return Err(ProviderLaunchError::SessionChanged);
        }
        Ok(())
    }

    fn duplicate(&self) -> Result<Self, ProviderLaunchError> {
        self.revalidate()?;
        let descriptor = self
            .descriptor
            .try_clone()
            .map_err(|_| ProviderLaunchError::Storage)?;
        if launch_directory_identity(
            &descriptor
                .metadata()
                .map_err(|_| ProviderLaunchError::Storage)?,
            self.private,
        )
        .map_err(|_| ProviderLaunchError::SessionChanged)?
            != self.identity
            || !launch_directory_acl_is_empty(&descriptor)
        {
            return Err(ProviderLaunchError::SessionChanged);
        }
        self.revalidate()?;
        Ok(Self {
            path: self.path.clone(),
            descriptor,
            identity: self.identity,
            private: self.private,
        })
    }
}

fn launch_directory_identity(
    metadata: &fs::Metadata,
    private: bool,
) -> Result<LaunchDirectoryIdentity, ProviderLaunchError> {
    let unsafe_mode = if private {
        metadata.mode() & 0o077 != 0
    } else {
        metadata.mode() & 0o022 != 0
    };
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || unsafe_mode
    {
        return Err(ProviderLaunchError::InvalidArgument);
    }
    Ok(LaunchDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
    })
}

#[cfg(target_os = "macos")]
fn launch_directory_acl_is_empty(descriptor: &File) -> bool {
    calcifer_macos_acl::read_acl(descriptor.as_fd()).is_ok_and(|acl| acl.is_empty())
}

#[cfg(not(target_os = "macos"))]
fn launch_directory_acl_is_empty(_descriptor: &File) -> bool {
    true
}

/// Opaque, one-shot monitor target minted only from a pinned session build.
///
/// It retains a duplicate of the already-captured managed-home descriptor and
/// the exact canonical thread UUID. The monitor cannot substitute either
/// value during construction.
#[must_use = "monitor session capability must be consumed by MonitorProtocol"]
pub(in crate::providers::codex) struct MonitorSessionCapability {
    selected_codex_home: VerifiedLaunchDirectory,
    target_thread_id: String,
    brand: SessionBrand,
    lifetime: Arc<SessionLifetime>,
}

/// Private pre-spawn monitor identity. It cannot leave the App launch plan and
/// becomes a protocol capability only after the exact App socket is adopted.
struct MonitorSessionSeed {
    selected_codex_home: VerifiedLaunchDirectory,
    target_thread_id: String,
    brand: SessionBrand,
    lifetime: Arc<SessionLifetime>,
}

impl MonitorSessionSeed {
    fn into_capability(self) -> MonitorSessionCapability {
        MonitorSessionCapability {
            selected_codex_home: self.selected_codex_home,
            target_thread_id: self.target_thread_id,
            brand: self.brand,
            lifetime: self.lifetime,
        }
    }
}

impl MonitorSessionCapability {
    pub(in crate::providers::codex) fn selected_codex_home(&self) -> &Path {
        self.selected_codex_home.path()
    }

    pub(in crate::providers::codex) fn target_thread_id(&self) -> &str {
        &self.target_thread_id
    }

    pub(in crate::providers::codex) fn revalidate(&self) -> Result<(), ProviderLaunchError> {
        self.selected_codex_home.revalidate()
    }

    #[cfg(test)]
    pub(in crate::providers::codex) fn for_test(
        selected_codex_home: &Path,
        target_thread_id: &str,
    ) -> Result<Self, ProviderLaunchError> {
        Ok(Self {
            selected_codex_home: VerifiedLaunchDirectory::capture(selected_codex_home, true)?,
            target_thread_id: validate_thread_id(target_thread_id)?,
            brand: SessionBrand::next(),
            lifetime: Arc::new(SessionLifetime {
                lease: GuardianLeaseOwner::Test,
            }),
        })
    }

    #[cfg(test)]
    pub(in crate::providers::codex) const fn brand_for_test(&self) -> u64 {
        self.brand.0
    }
}

impl fmt::Debug for MonitorSessionCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.selected_codex_home,
            &self.target_thread_id,
            self.brand,
            &self.lifetime,
        );
        formatter.write_str("MonitorSessionCapability(<redacted>)")
    }
}

impl PinnedSessionBuild {
    /// Appends the guardian-only lease and every descriptor pinning the
    /// executable/profile/workspace build to one child denyset.
    pub(super) fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        self.executable.append_forbidden_descriptors(forbidden)?;
        match &self.lifetime.lease {
            GuardianLeaseOwner::Production(lease) => {
                lease.append_forbidden_descriptor(forbidden)?;
            }
            #[cfg(test)]
            GuardianLeaseOwner::Test => {}
            #[cfg(test)]
            GuardianLeaseOwner::InjectedTestDescriptor(descriptor) => {
                forbidden.capture(descriptor.as_fd())?;
            }
        }
        forbidden.capture(self.selected_profile.codex_home.descriptor.as_fd())?;
        forbidden.capture(self.working_directory.descriptor.as_fd())
    }

    /// Retains the guardian lease and pinned stage for any authority that can
    /// outlive a synchronous provider call (child, worker, or failure owner).
    pub(super) fn retain_runtime(&self) -> SessionRuntimeGuard {
        SessionRuntimeGuard::retain(self)
    }

    fn from_compatibility(
        authorization: ProviderLaunchAuthorization,
        capability: CodexHandoffCapability,
    ) -> Self {
        let GuardianSessionAuthority { lease, spec, brand } = authorization.session;
        Self {
            executable: capability.into_pinned_executable(),
            lifetime: Arc::new(SessionLifetime { lease }),
            selected_profile: spec.selected_profile,
            working_directory: spec.working_directory,
            thread_id: spec.thread_id,
            brand,
            minted_authorities: std::cell::Cell::new(0),
        }
    }

    #[cfg(test)]
    pub(super) fn from_test_capability(
        authorization: ProviderLaunchAuthorization,
        capability: super::super::handoff_compat::TestCompatibilityCapability,
        stage_parent: &Path,
    ) -> Result<Self, TestBuildFailure> {
        let capability = capability
            .pin_in(stage_parent)
            .map_err(TestBuildFailure::from)?;
        Ok(Self::from_compatibility(authorization, capability))
    }

    pub(super) fn app_server_command<'build>(
        &'build self,
        socket: &VerifiedProviderSocketAddress,
        deadline: Instant,
    ) -> Result<AppServerCommand<'build>, ProviderLaunchError> {
        self.ensure_authority_available(APP_PLAN_MINTED)?;
        self.revalidate_session_inputs(deadline)?;
        let monitor_seed = self.monitor_session_seed()?;
        let command = self.executable.app_server_command(
            self.selected_profile.codex_home.path(),
            self.working_directory.path(),
            socket.as_str(),
            deadline,
        )?;
        self.record_authority_minted(APP_PLAN_MINTED);
        Ok(AppServerCommand {
            command,
            build: self,
            expected_socket_path: socket.path().to_path_buf(),
            monitor_seed,
        })
    }

    /// Binds the App Server command to the one owner-private reservation that
    /// must later be consumed by [`AppServerChild::adopt_socket`].
    pub(super) fn app_server_command_for_reservation<'build>(
        &'build self,
        reservation: &AppSocketReservation,
        deadline: Instant,
    ) -> Result<AppServerCommand<'build>, ProviderLaunchError> {
        let address = VerifiedProviderSocketAddress::from_verified_path(reservation.path())?;
        self.app_server_command(&address, deadline)
    }

    /// Brands a sealed runtime route with this exact build/thread/workspace.
    pub(super) fn exact_relay_plan(
        &self,
        route: ExactRelayRoute,
        deadline: Instant,
    ) -> Result<ExactRelayPlan<'_>, ProviderLaunchError> {
        self.ensure_authority_available(EXACT_RELAY_PLAN_MINTED)?;
        self.revalidate_session_inputs(deadline)?;
        self.record_authority_minted(EXACT_RELAY_PLAN_MINTED);
        Ok(ExactRelayPlan { route, build: self })
    }

    pub(super) fn remote_tui_command<'build>(
        &'build self,
        socket: &VerifiedProviderSocketAddress,
        deadline: Instant,
    ) -> Result<RemoteTuiCommand<'build>, ProviderLaunchError> {
        self.ensure_authority_available(TUI_PLAN_MINTED)?;
        self.revalidate_session_inputs(deadline)?;
        let command = self.executable.remote_tui_command(
            self.selected_profile.codex_home.path(),
            self.working_directory.path(),
            socket.as_str(),
            &self.thread_id,
            deadline,
        )?;
        self.record_authority_minted(TUI_PLAN_MINTED);
        Ok(RemoteTuiCommand {
            command,
            build: self,
        })
    }

    fn monitor_session_seed(&self) -> Result<MonitorSessionSeed, ProviderLaunchError> {
        Ok(MonitorSessionSeed {
            selected_codex_home: self.selected_profile.codex_home.duplicate()?,
            target_thread_id: self.thread_id.clone(),
            brand: self.brand,
            lifetime: Arc::clone(&self.lifetime),
        })
    }

    #[cfg(test)]
    fn monitor_session_capability(
        &self,
        deadline: Instant,
    ) -> Result<MonitorSessionCapability, ProviderLaunchError> {
        self.ensure_authority_available(MONITOR_CAPABILITY_MINTED)?;
        self.revalidate_session_inputs(deadline)?;
        let seed = self.monitor_session_seed()?;
        self.record_authority_minted(MONITOR_CAPABILITY_MINTED);
        Ok(seed.into_capability())
    }

    pub(super) fn cleanup(
        self,
        deadline: Instant,
    ) -> Result<ProviderCleanupComplete, Box<ProviderCleanupFailure>> {
        if Arc::strong_count(&self.lifetime) != 1 {
            return Err(Box::new(ProviderCleanupFailure {
                build: self,
                error: ProviderLaunchError::SessionInUse,
            }));
        }
        let Self {
            executable,
            lifetime,
            selected_profile,
            working_directory,
            thread_id,
            brand,
            minted_authorities,
        } = self;
        match executable.cleanup(deadline) {
            Ok(_) => Ok(ProviderCleanupComplete { _private: () }),
            Err(failure) => {
                let failure = *failure;
                let error = ProviderLaunchError::from(failure.error());
                Err(Box::new(ProviderCleanupFailure {
                    build: Self {
                        executable: failure.into_stage(),
                        lifetime,
                        selected_profile,
                        working_directory,
                        thread_id,
                        brand,
                        minted_authorities,
                    },
                    error,
                }))
            }
        }
    }

    fn revalidate_session_inputs(&self, deadline: Instant) -> Result<(), ProviderLaunchError> {
        if Instant::now() >= deadline {
            return Err(ProviderLaunchError::Timeout);
        }
        self.selected_profile.codex_home.revalidate()?;
        self.working_directory.revalidate()?;
        if Instant::now() >= deadline {
            return Err(ProviderLaunchError::Timeout);
        }
        Ok(())
    }

    /// Performs the provider-owned full identity and digest check before the
    /// relay readiness deadline is armed.
    ///
    /// Keeping this seam on the pinned build prevents `launcher.rs` from
    /// reconstructing profile or working-directory authority from raw paths.
    pub(super) fn revalidate_remote_tui_launch(
        &self,
        deadline: Instant,
    ) -> Result<(), ProviderLaunchError> {
        self.revalidate_session_inputs(deadline)?;
        self.executable.revalidate(deadline).map_err(Into::into)
    }

    /// Performs the cheap exact-identity check at the launcher spawn boundary.
    /// The preceding prepared-launch proof already checked the full digest;
    /// this check deliberately compares the private stage path, device, inode,
    /// length, ownership, mode, link count, mtime, and ctime without hashing.
    pub(super) fn revalidate_remote_tui_spawn_identity(
        &self,
        deadline: Instant,
    ) -> Result<(), ProviderLaunchError> {
        self.revalidate_session_inputs(deadline)?;
        self.executable.revalidate_metadata().map_err(Into::into)
    }

    fn ensure_authority_available(&self, bit: u8) -> Result<(), ProviderLaunchError> {
        if self.minted_authorities.get() & bit == 0 {
            Ok(())
        } else {
            Err(ProviderLaunchError::AuthorityConsumed)
        }
    }

    fn record_authority_minted(&self, bit: u8) {
        self.minted_authorities
            .set(self.minted_authorities.get() | bit);
    }

    #[cfg(test)]
    pub(super) fn executable_path_for_test(&self) -> &Path {
        self.executable.executable_path_for_test()
    }

    #[cfg(test)]
    pub(super) fn runtime_path_for_test(&self) -> &Path {
        self.executable.root_path()
    }

    #[cfg(test)]
    fn fail_next_cleanup_for_test(&mut self) {
        self.executable.fail_next_cleanup_for_test();
    }

    #[cfg(test)]
    fn fail_cleanup_at_for_test(&mut self, fault: PinnedStageCleanupFault) {
        self.executable.fail_cleanup_at_for_test(fault);
    }

    #[cfg(test)]
    const fn brand_for_test(&self) -> u64 {
        self.brand.0
    }
}

impl fmt::Debug for PinnedSessionBuild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.executable, &self.lifetime, self.brand);
        formatter.write_str("PinnedSessionBuild(<redacted>)")
    }
}

impl fmt::Debug for VerifiedSessionSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.selected_profile,
            &self.working_directory,
            &self.thread_id,
        );
        formatter.write_str("VerifiedSessionSpec(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProviderCleanupComplete {
    _private: (),
}

#[must_use = "cleanup failure retains the pinned build and must be handled"]
pub(super) struct ProviderCleanupFailure {
    build: PinnedSessionBuild,
    error: ProviderLaunchError,
}

impl ProviderCleanupFailure {
    #[cfg(test)]
    pub(super) const fn error(&self) -> ProviderLaunchError {
        self.error
    }

    pub(super) fn into_build(self) -> PinnedSessionBuild {
        self.build
    }
}

impl fmt::Debug for ProviderCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.build;
        formatter
            .debug_struct("ProviderCleanupFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ProviderCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for ProviderCleanupFailure {}

#[cfg(test)]
pub(super) struct TestBuildFailure {
    error: ProviderLaunchError,
    retained_stage: Option<PinnedStageCreateFailure>,
}

#[cfg(test)]
impl TestBuildFailure {
    const fn error(&self) -> ProviderLaunchError {
        self.error
    }
}

#[cfg(test)]
impl From<ProviderLaunchError> for TestBuildFailure {
    fn from(error: ProviderLaunchError) -> Self {
        Self {
            error,
            retained_stage: None,
        }
    }
}

#[cfg(test)]
impl From<PinnedStageCreateFailure> for TestBuildFailure {
    fn from(failure: PinnedStageCreateFailure) -> Self {
        Self {
            error: ProviderLaunchError::from(failure.error()),
            retained_stage: Some(failure),
        }
    }
}

#[cfg(test)]
impl fmt::Debug for TestBuildFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.retained_stage;
        formatter
            .debug_struct("TestBuildFailure")
            .field("error", &self.error)
            .field("retained", &self.retained_stage.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl fmt::Display for TestBuildFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

#[cfg(test)]
impl std::error::Error for TestBuildFailure {}

pub(super) struct AppServerCommand<'build> {
    command: Command,
    build: &'build PinnedSessionBuild,
    expected_socket_path: PathBuf,
    monitor_seed: MonitorSessionSeed,
}

impl AppServerCommand<'_> {
    fn revalidate_for_launch(&self, deadline: Instant) -> Result<(), ProviderLaunchError> {
        self.build.revalidate_session_inputs(deadline)?;
        self.build
            .executable
            .revalidate(deadline)
            .map_err(Into::into)
    }

    /// Consumes the only App Server plan, performs the final identity checks,
    /// and immediately crosses the guardian-owned spawn boundary. No raw
    /// `Command` is exposed to production callers between those operations.
    pub(super) fn launch(
        self,
        deadline: Instant,
    ) -> Result<AppServerChild, Box<AppServerLaunchFailure>> {
        if let Err(error) = self.revalidate_for_launch(deadline) {
            return Err(Box::new(AppServerLaunchFailure {
                failure: AppServerLaunchFailureKind::Provider(error),
                lifetime: Arc::clone(&self.build.lifetime),
            }));
        }
        let child = ManagedGroupChild::spawn(ChildRole::AppServer, self.command, false).map_err(
            |failure| {
                Box::new(AppServerLaunchFailure {
                    failure: AppServerLaunchFailureKind::Spawn(failure),
                    lifetime: Arc::clone(&self.build.lifetime),
                })
            },
        )?;
        Ok(AppServerChild {
            child,
            runtime_guard: self.build.retain_runtime(),
            expected_socket_path: self.expected_socket_path,
            monitor_seed: Some(self.monitor_seed),
        })
    }

    /// Crosses the App launch boundary while retaining the exact socket/runtime
    /// reservation in the same failure owner. This is the startup-orchestrator
    /// entry point: even an unannounced child that bound `app.sock` before a
    /// spawn readback failure can be contained and have its pathname resolved.
    pub(super) fn launch_with_reservation(
        self,
        mut reservation: AppSocketReservation,
        deadline: Instant,
    ) -> Result<(AppServerChild, AppSocketReservation), Box<AppServerLaunchReservationFailure>>
    {
        if !reservation.is_unbound_from_app_child() {
            // A bound reservation belongs to an already-launched App child.
            // It must never be projected as an ordinary pre-spawn provider
            // failure because that projection authorizes absent/ready socket
            // cleanup without the exact child's graceful-drain proof.
            let failure = AppServerLaunchFailure {
                failure: AppServerLaunchFailureKind::BoundReservation,
                lifetime: Arc::clone(&self.build.lifetime),
            };
            return Err(Box::new(AppServerLaunchReservationFailure::new(
                failure,
                reservation,
            )));
        }
        if reservation.path() != self.expected_socket_path {
            let failure = AppServerLaunchFailure {
                failure: AppServerLaunchFailureKind::Provider(ProviderLaunchError::InvalidArgument),
                lifetime: Arc::clone(&self.build.lifetime),
            };
            return Err(Box::new(AppServerLaunchReservationFailure::new(
                failure,
                reservation,
            )));
        }
        match self.launch(deadline) {
            Ok(child) => {
                if reservation
                    .bind_app_child(child.child.child_authority())
                    .is_err()
                {
                    // The unbound precondition above and the linear reservation
                    // make this unreachable. Continuing would detach a live App
                    // child from its sole cleanup brand.
                    std::process::abort();
                }
                Ok((child, reservation))
            }
            Err(failure) => Err(Box::new(AppServerLaunchReservationFailure::new(
                *failure,
                reservation,
            ))),
        }
    }

    #[cfg(test)]
    fn command_for_test(&self) -> &Command {
        &self.command
    }

    #[cfg(test)]
    const fn session_brand_for_test(&self) -> u64 {
        self.build.brand_for_test()
    }
}

/// A running App Server whose direct-child authority borrows the exact pinned
/// build and guardian lease used for exec. The build cannot be cleaned while
/// this value is alive.
#[must_use = "the App Server child must remain supervised and exactly reaped"]
pub(super) struct AppServerChild {
    child: ManagedGroupChild,
    runtime_guard: SessionRuntimeGuard,
    expected_socket_path: PathBuf,
    monitor_seed: Option<MonitorSessionSeed>,
}

impl fmt::Debug for AppServerChild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.child,
            &self.runtime_guard.lifetime,
            &self.expected_socket_path,
            &self.monitor_seed,
        );
        formatter.write_str("AppServerChild(<redacted>)")
    }
}

/// Move-only proof that the exact App process group passed descriptor
/// isolation while every forbidden source object remained pinned.
#[must_use = "App descriptor isolation must be consumed by socket adoption"]
pub(super) struct VerifiedAppDescriptorIsolation {
    containment: ContainmentMetadata,
    proof: calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
}

impl fmt::Debug for VerifiedAppDescriptorIsolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (self.containment, self.proof);
        formatter.write_str("VerifiedAppDescriptorIsolation(<redacted>)")
    }
}

impl AppServerChild {
    /// Read-only identity published from the still-owned direct child handle.
    /// It carries no numeric signal authority.
    pub(super) const fn containment(&self) -> ContainmentMetadata {
        self.child.containment()
    }

    #[cfg(test)]
    pub(super) fn observe_forbidden_descriptors_absent(
        &self,
        forbidden: &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
        deadline: Instant,
    ) -> Result<
        calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
        calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    > {
        self.child
            .observe_forbidden_descriptors_absent(forbidden, deadline)
    }

    pub(super) fn verify_descriptor_isolation(
        &mut self,
        forbidden: &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
        deadline: Instant,
    ) -> Result<
        VerifiedAppDescriptorIsolation,
        calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    > {
        Ok(VerifiedAppDescriptorIsolation {
            containment: self.containment(),
            proof: self
                .child
                .observe_forbidden_descriptors_absent_while_live(forbidden, deadline)?,
        })
    }

    /// Retains an unadopted child and its exact runtime reservation when the
    /// descriptor-isolation barrier fails before socket adoption.
    pub(super) fn retain_descriptor_isolation_failure(
        self,
        mut reservation: AppSocketReservation,
        error: calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    ) -> Box<AppServerSocketAdoptionFailure> {
        let topology_error = if reservation.path() != self.expected_socket_path {
            AppServerTopologyError::CrossSessionSocket
        } else if let Err(error) = reservation.bind_app_child(self.child.child_authority()) {
            AppServerTopologyError::Socket(error)
        } else {
            AppServerTopologyError::DescriptorIsolation(error)
        };
        Box::new(AppServerSocketAdoptionFailure {
            child: self,
            socket: AppServerSocketAuthority::Reservation(reservation),
            error: topology_error,
        })
    }

    pub(super) fn shutdown(
        self,
        graceful: Duration,
        forced: Duration,
    ) -> Result<AppServerShutdownComplete, Box<AppServerShutdownFailure>> {
        let Self {
            child,
            runtime_guard,
            expected_socket_path,
            monitor_seed,
        } = self;
        match shutdown_app_server_child(child, graceful, forced) {
            Ok(drain) => Ok(AppServerShutdownComplete {
                drain,
                runtime_guard,
            }),
            Err(unreaped) => Err(Box::new(AppServerShutdownFailure {
                unreaped,
                runtime_guard,
                expected_socket_path,
                monitor_seed,
            })),
        }
    }

    /// Adopts only the exact socket reservation named by this child's sealed
    /// launch command. The monitor seed is minted after both the direct child
    /// and descriptor-backed socket have been revalidated.
    pub(super) fn adopt_socket(
        self,
        reservation: AppSocketReservation,
        descriptor_isolation: VerifiedAppDescriptorIsolation,
        deadline: Instant,
    ) -> Result<AppServerSession, Box<AppServerSocketAdoptionFailure>> {
        self.adopt_socket_inner(reservation, descriptor_isolation, deadline, |_| {})
    }

    #[cfg(test)]
    fn adopt_socket_with_wait<F>(
        self,
        reservation: AppSocketReservation,
        descriptor_isolation: VerifiedAppDescriptorIsolation,
        deadline: Instant,
        on_wait: F,
    ) -> Result<AppServerSession, Box<AppServerSocketAdoptionFailure>>
    where
        F: FnMut(&Path),
    {
        self.adopt_socket_inner(reservation, descriptor_isolation, deadline, on_wait)
    }

    fn adopt_socket_inner<F>(
        mut self,
        reservation: AppSocketReservation,
        descriptor_isolation: VerifiedAppDescriptorIsolation,
        deadline: Instant,
        mut on_wait: F,
    ) -> Result<AppServerSession, Box<AppServerSocketAdoptionFailure>>
    where
        F: FnMut(&Path),
    {
        if reservation.path() != self.expected_socket_path {
            return Err(Box::new(AppServerSocketAdoptionFailure {
                child: self,
                socket: AppServerSocketAuthority::Reservation(reservation),
                error: AppServerTopologyError::CrossSessionSocket,
            }));
        }
        let mut reservation = reservation;
        if let Err(error) = reservation.bind_app_child(self.child.child_authority()) {
            return Err(Box::new(AppServerSocketAdoptionFailure {
                child: self,
                socket: AppServerSocketAuthority::Reservation(reservation),
                error: AppServerTopologyError::Socket(error),
            }));
        }
        if descriptor_isolation.containment != self.containment() {
            return Err(Box::new(AppServerSocketAdoptionFailure {
                child: self,
                socket: AppServerSocketAuthority::Reservation(reservation),
                error: AppServerTopologyError::DescriptorIsolation(
                    calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessChanged,
                ),
            }));
        }
        let socket = loop {
            if let Err(error) = self.child.confirm_running_after_readiness(deadline) {
                return Err(Box::new(AppServerSocketAdoptionFailure {
                    child: self,
                    socket: AppServerSocketAuthority::Reservation(reservation),
                    error: AppServerTopologyError::Process(error),
                }));
            }
            match reservation.adopt() {
                Ok(socket) => break socket,
                Err(failure)
                    if failure.error() == AppSocketError::SocketNotReady
                        && Instant::now() < deadline =>
                {
                    reservation = failure.into_reservation();
                    on_wait(reservation.path());
                    std::thread::sleep(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_millis(5)),
                    );
                }
                Err(failure) => {
                    let error = if failure.error() == AppSocketError::SocketNotReady {
                        AppSocketError::AdoptionTimeout
                    } else {
                        failure.error()
                    };
                    return Err(Box::new(AppServerSocketAdoptionFailure {
                        child: self,
                        socket: AppServerSocketAuthority::Reservation(failure.into_reservation()),
                        error: AppServerTopologyError::Socket(error),
                    }));
                }
            }
        };
        if socket.visible_path() != self.expected_socket_path {
            return Err(Box::new(AppServerSocketAdoptionFailure {
                child: self,
                socket: AppServerSocketAuthority::Owned(socket),
                error: AppServerTopologyError::CrossSessionSocket,
            }));
        }
        if let Err(error) = socket.revalidate() {
            return Err(Box::new(AppServerSocketAdoptionFailure {
                child: self,
                socket: AppServerSocketAuthority::Owned(socket),
                error: AppServerTopologyError::Socket(error),
            }));
        }
        let monitor = match self.monitor_seed.take() {
            Some(seed) => seed.into_capability(),
            None => {
                return Err(Box::new(AppServerSocketAdoptionFailure {
                    child: self,
                    socket: AppServerSocketAuthority::Owned(socket),
                    error: AppServerTopologyError::Provider(ProviderLaunchError::AuthorityConsumed),
                }));
            }
        };
        Ok(AppServerSession {
            child: self,
            socket,
            monitor,
            descriptor_isolation,
        })
    }
}

#[must_use = "App Server shutdown proof must be projected before releasing the lease"]
pub(super) struct AppServerShutdownComplete {
    drain: PinnedAppGracefulDrain,
    runtime_guard: SessionRuntimeGuard,
}

impl fmt::Debug for AppServerShutdownComplete {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.runtime_guard;
        formatter
            .debug_struct("AppServerShutdownComplete")
            .field("outcome", self.drain.outcome())
            .finish_non_exhaustive()
    }
}

#[must_use = "unreaped App Server retains its guardian session lease"]
pub(super) struct AppServerShutdownFailure {
    unreaped: Box<UnreapedChildren>,
    runtime_guard: SessionRuntimeGuard,
    expected_socket_path: PathBuf,
    monitor_seed: Option<MonitorSessionSeed>,
}

impl AppServerShutdownFailure {
    pub(super) fn error(&self) -> ProcessError {
        self.unreaped.error()
    }

    pub(super) fn retry(
        mut self: Box<Self>,
        graceful: Duration,
        forced: Duration,
    ) -> Result<AppServerShutdownComplete, Box<Self>> {
        match self.unreaped.retry_app_server(graceful, forced) {
            Ok(drain) => {
                let Self { runtime_guard, .. } = *self;
                Ok(AppServerShutdownComplete {
                    drain,
                    runtime_guard,
                })
            }
            Err(_) => Err(self),
        }
    }
}

impl fmt::Debug for AppServerShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.runtime_guard,
            &self.expected_socket_path,
            &self.monitor_seed,
        );
        formatter
            .debug_struct("AppServerShutdownFailure")
            .field("error", &self.error())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AppServerTopologyError {
    CrossSessionSocket,
    DescriptorIsolation(calcifer_unix_child_fd::ProcessGroupDescriptorScanError),
    Provider(ProviderLaunchError),
    Socket(AppSocketError),
    Process(ProcessError),
}

impl fmt::Display for AppServerTopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrossSessionSocket => {
                formatter.write_str("the App Server socket belongs to another session")
            }
            Self::DescriptorIsolation(error) => error.fmt(formatter),
            Self::Provider(error) => error.fmt(formatter),
            Self::Socket(error) => error.fmt(formatter),
            Self::Process(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AppServerTopologyError {}

enum AppServerSocketAuthority {
    Reservation(AppSocketReservation),
    Owned(OwnedAppSocket),
}

#[must_use = "socket adoption failure retains child and socket ownership"]
pub(super) struct AppServerSocketAdoptionFailure {
    child: AppServerChild,
    socket: AppServerSocketAuthority,
    error: AppServerTopologyError,
}

impl AppServerSocketAdoptionFailure {
    #[cfg(test)]
    pub(super) const fn error(&self) -> AppServerTopologyError {
        self.error
    }

    pub(super) fn contain_child(
        self,
        graceful: Duration,
        forced: Duration,
    ) -> Result<AppServerAdoptionContainmentComplete, Box<AppServerAdoptionContainmentFailure>>
    {
        let Self { child, socket, .. } = self;
        match child.shutdown(graceful, forced) {
            Ok(child) => Ok(AppServerAdoptionContainmentComplete { child, socket }),
            Err(child) => Err(Box::new(AppServerAdoptionContainmentFailure {
                child,
                socket,
            })),
        }
    }
}

impl fmt::Debug for AppServerSocketAdoptionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.child, &self.socket);
        formatter
            .debug_struct("AppServerSocketAdoptionFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AppServerSocketAdoptionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for AppServerSocketAdoptionFailure {}

#[must_use = "contained App child still retains its socket/runtime cleanup authority"]
pub(super) struct AppServerAdoptionContainmentComplete {
    child: AppServerShutdownComplete,
    socket: AppServerSocketAuthority,
}

impl AppServerAdoptionContainmentComplete {
    pub(super) fn cleanup_socket(
        self,
        deadline: Instant,
    ) -> Result<AppServerTeardownComplete, Box<AppServerTeardownFailure>> {
        let AppServerShutdownComplete {
            drain,
            runtime_guard,
        } = self.child;
        match self.socket {
            AppServerSocketAuthority::Reservation(reservation) => {
                finish_reservation_teardown(drain, reservation, runtime_guard, deadline)
            }
            AppServerSocketAuthority::Owned(socket) => {
                finish_socket_teardown(drain, socket, runtime_guard, deadline)
            }
        }
    }
}

#[must_use = "failed App containment retains child, socket, and guardian lease"]
pub(super) struct AppServerAdoptionContainmentFailure {
    child: Box<AppServerShutdownFailure>,
    socket: AppServerSocketAuthority,
}

impl AppServerAdoptionContainmentFailure {
    pub(super) fn error(&self) -> ProcessError {
        self.child.error()
    }

    pub(super) fn retry(
        self,
        graceful: Duration,
        forced: Duration,
    ) -> Result<AppServerAdoptionContainmentComplete, Box<Self>> {
        match self.child.retry(graceful, forced) {
            Ok(child) => Ok(AppServerAdoptionContainmentComplete {
                child,
                socket: self.socket,
            }),
            Err(child) => Err(Box::new(Self {
                child,
                socket: self.socket,
            })),
        }
    }
}

impl fmt::Debug for AppServerAdoptionContainmentFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.socket;
        formatter
            .debug_struct("AppServerAdoptionContainmentFailure")
            .field("error", &self.error())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AppServerAdoptionContainmentFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error().fmt(formatter)
    }
}

impl std::error::Error for AppServerAdoptionContainmentFailure {}

/// Exact running App Server plus the identity-validated socket it bound.
/// No monitor stream can be connected before this aggregate exists.
#[must_use = "the App Server session must be connected, shut down, or retained"]
pub(super) struct AppServerSession {
    child: AppServerChild,
    socket: OwnedAppSocket,
    monitor: MonitorSessionCapability,
    descriptor_isolation: VerifiedAppDescriptorIsolation,
}

impl AppServerSession {
    #[cfg(test)]
    pub(super) const fn containment(&self) -> ContainmentMetadata {
        self.child.containment()
    }

    #[cfg(test)]
    pub(super) fn observe_forbidden_descriptors_absent(
        &self,
        forbidden: &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
        deadline: Instant,
    ) -> Result<
        calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
        calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    > {
        self.child
            .observe_forbidden_descriptors_absent(forbidden, deadline)
    }

    pub(super) fn connect_monitor(
        mut self,
        deadline: Instant,
    ) -> Result<ConnectedMonitorSession, Box<MonitorConnectFailure>> {
        if let Err(error) = self.child.child.confirm_running_after_readiness(deadline) {
            return Err(Box::new(MonitorConnectFailure {
                session: self,
                error: AppServerTopologyError::Process(error),
            }));
        }
        let stream = loop {
            match self.socket.connect(deadline) {
                Ok(stream) => break stream,
                Err(AppSocketError::SocketNotReady) if Instant::now() < deadline => {
                    if let Err(error) = self.child.child.confirm_running_after_readiness(deadline) {
                        return Err(Box::new(MonitorConnectFailure {
                            session: self,
                            error: AppServerTopologyError::Process(error),
                        }));
                    }
                    std::thread::sleep(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_millis(5)),
                    );
                }
                Err(error) => {
                    return Err(Box::new(MonitorConnectFailure {
                        session: self,
                        error: AppServerTopologyError::Socket(error),
                    }));
                }
            }
        };
        Ok(ConnectedMonitorSession {
            stream: Some(stream),
            monitor: Some(self.monitor),
            child: self.child,
            socket: self.socket,
            descriptor_isolation: self.descriptor_isolation,
        })
    }

    pub(super) fn stop(
        self,
        graceful: Duration,
        forced: Duration,
    ) -> Result<StoppedAppServer, Box<AppServerStopFailure>> {
        let Self {
            child,
            socket,
            monitor,
            descriptor_isolation,
        } = self;
        drop((monitor, descriptor_isolation));
        stop_app_server(child, socket, graceful, forced)
    }
}

impl fmt::Debug for AppServerSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.child,
            &self.socket,
            &self.monitor,
            &self.descriptor_isolation,
        );
        formatter.write_str("AppServerSession(<redacted>)")
    }
}

#[must_use = "monitor connection failure retains the complete App Server session"]
pub(super) struct MonitorConnectFailure {
    session: AppServerSession,
    error: AppServerTopologyError,
}

impl MonitorConnectFailure {
    pub(super) fn into_session(self) -> AppServerSession {
        self.session
    }
}

impl fmt::Debug for MonitorConnectFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.session;
        formatter
            .debug_struct("MonitorConnectFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for MonitorConnectFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for MonitorConnectFailure {}

/// Sealed topology capability consumed by the monitor transport. It owns the
/// App child, exact socket, stream opened through that socket, and branded
/// protocol target for the entire worker lifetime.
#[must_use = "connected monitor session must be consumed by MonitorWorker"]
pub(in crate::providers::codex) struct ConnectedMonitorSession {
    stream: Option<UnixStream>,
    monitor: Option<MonitorSessionCapability>,
    child: AppServerChild,
    socket: OwnedAppSocket,
    descriptor_isolation: VerifiedAppDescriptorIsolation,
}

impl ConnectedMonitorSession {
    #[cfg(test)]
    pub(super) const fn containment(&self) -> ContainmentMetadata {
        self.child.containment()
    }

    #[cfg(test)]
    pub(super) fn observe_forbidden_descriptors_absent(
        &self,
        forbidden: &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
        deadline: Instant,
    ) -> Result<
        calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
        calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    > {
        self.child
            .observe_forbidden_descriptors_absent(forbidden, deadline)
    }

    /// Appends every guardian-side descriptor retained by the connected App
    /// aggregate. The transport may already have moved to the monitor worker;
    /// in that state the worker's control duplicate represents the same kernel
    /// socket and is appended by `SessionMonitor`.
    pub(in crate::providers::codex) fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        self.child
            .runtime_guard
            .append_forbidden_descriptors(forbidden)?;
        self.socket.append_forbidden_descriptors(forbidden)?;
        if let Some(stream) = self.stream.as_ref() {
            forbidden.capture(stream.as_fd())?;
        }
        Ok(())
    }

    pub(in crate::providers::codex) fn ensure_app_live(
        &mut self,
        deadline: Instant,
    ) -> Result<(), ProviderLaunchError> {
        self.child
            .child
            .confirm_running_after_readiness(deadline)
            .map_err(|_| ProviderLaunchError::SessionChanged)
    }

    pub(in crate::providers::codex) fn take_transport(
        &mut self,
    ) -> Result<(UnixStream, MonitorSessionCapability), ProviderLaunchError> {
        let stream = self
            .stream
            .take()
            .ok_or(ProviderLaunchError::AuthorityConsumed)?;
        let monitor = self
            .monitor
            .take()
            .ok_or(ProviderLaunchError::AuthorityConsumed)?;
        Ok((stream, monitor))
    }

    /// Closes the monitor transport and exactly reaps the App Server while
    /// retaining its socket/runtime owner for later ordered cleanup. This lets
    /// the session restore the terminal and disarm recovery between process
    /// quiescence and namespace mutation.
    pub(super) fn stop_app_server(
        mut self,
        graceful: Duration,
        forced: Duration,
    ) -> Result<StoppedAppServer, Box<AppServerStopFailure>> {
        drop(self.stream.take());
        drop(self.monitor.take());
        stop_app_server(self.child, self.socket, graceful, forced)
    }

    #[cfg(test)]
    fn brand_for_test(&self) -> u64 {
        self.monitor.as_ref().map_or(
            self.child
                .monitor_seed
                .as_ref()
                .map_or(0, |seed| seed.brand.0),
            |monitor| monitor.brand.0,
        )
    }
}

impl fmt::Debug for ConnectedMonitorSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.stream,
            &self.monitor,
            &self.child,
            &self.socket,
            &self.descriptor_isolation,
        );
        formatter.write_str("ConnectedMonitorSession(<redacted>)")
    }
}

/// Exact App child reap proof that deliberately retains socket/runtime
/// ownership until terminal restoration and recovery disarm are complete.
#[must_use = "a stopped App Server must clean its exact socket and runtime"]
pub(super) struct StoppedAppServer {
    drain: PinnedAppGracefulDrain,
    socket: OwnedAppSocket,
    runtime_guard: SessionRuntimeGuard,
}

impl StoppedAppServer {
    #[cfg(test)]
    pub(super) const fn outcome(&self) -> &ShutdownOutcome {
        self.drain.outcome()
    }

    pub(super) fn cleanup_socket_runtime(
        self,
        deadline: Instant,
    ) -> Result<AppServerTeardownComplete, Box<AppServerTeardownFailure>> {
        finish_socket_teardown(self.drain, self.socket, self.runtime_guard, deadline)
    }
}

impl fmt::Debug for StoppedAppServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.socket, &self.runtime_guard);
        formatter
            .debug_struct("StoppedAppServer")
            .field("outcome", self.drain.outcome())
            .finish_non_exhaustive()
    }
}

/// Retryable exact-child stop failure. The App socket/runtime and guardian
/// lease remain owned while the direct wait authority is unresolved.
#[must_use = "an App Server stop failure retains child and runtime authority"]
pub(super) struct AppServerStopFailure {
    unreaped: Box<UnreapedChildren>,
    socket: OwnedAppSocket,
    runtime_guard: SessionRuntimeGuard,
}

impl AppServerStopFailure {
    pub(super) fn error(&self) -> ProcessError {
        self.unreaped.error()
    }

    pub(super) fn retry(
        mut self: Box<Self>,
        graceful: Duration,
        forced: Duration,
    ) -> Result<StoppedAppServer, Box<Self>> {
        match self.unreaped.retry_app_server(graceful, forced) {
            Ok(drain) => {
                let Self {
                    socket,
                    runtime_guard,
                    ..
                } = *self;
                Ok(StoppedAppServer {
                    drain,
                    socket,
                    runtime_guard,
                })
            }
            Err(_) => Err(self),
        }
    }
}

impl fmt::Debug for AppServerStopFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.socket, &self.runtime_guard);
        formatter
            .debug_struct("AppServerStopFailure")
            .field("error", &self.error())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AppServerStopFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error().fmt(formatter)
    }
}

impl std::error::Error for AppServerStopFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AppServerTeardownError {
    Process(ProcessError),
    Socket(AppSocketError),
    Runtime(RuntimeError),
}

impl fmt::Display for AppServerTeardownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process(error) => error.fmt(formatter),
            Self::Socket(error) => error.fmt(formatter),
            Self::Runtime(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AppServerTeardownError {}

/// Clean proof for the full App topology: exact child reaped, socket identity
/// removed, and the owner-private runtime durably cleaned.
#[must_use = "App Server teardown proof must be projected to the lifecycle"]
pub(super) struct AppServerTeardownComplete {
    drain: PinnedAppGracefulDrain,
    runtime: CleanRuntime,
    runtime_guard: SessionRuntimeGuard,
}

impl AppServerTeardownComplete {
    pub(super) fn into_drain(self) -> PinnedAppGracefulDrain {
        self.drain
    }
}

impl fmt::Debug for AppServerTeardownComplete {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.runtime, &self.runtime_guard);
        formatter
            .debug_struct("AppServerTeardownComplete")
            .field("outcome", self.drain.outcome())
            .finish_non_exhaustive()
    }
}

enum AppServerTeardownPhase {
    Socket {
        drain: PinnedAppGracefulDrain,
        failure: AppSocketCleanupFailure,
        runtime_guard: SessionRuntimeGuard,
    },
    Reservation {
        drain: PinnedAppGracefulDrain,
        failure: AppSocketReservationFailure,
        runtime_guard: SessionRuntimeGuard,
    },
    Runtime {
        drain: PinnedAppGracefulDrain,
        failure: RuntimeCleanupFailure,
        runtime_guard: SessionRuntimeGuard,
    },
}

/// Retryable owner for every mutating teardown boundary. No phase releases the
/// guardian lease until all earlier child/socket/runtime ownership is clean.
#[must_use = "App Server teardown failure retains cleanup and guardian ownership"]
pub(super) struct AppServerTeardownFailure {
    phase: AppServerTeardownPhase,
    error: AppServerTeardownError,
}

impl AppServerTeardownFailure {
    pub(super) fn retry(
        self,
        socket_deadline: Instant,
    ) -> Result<AppServerTeardownComplete, Box<Self>> {
        match self.phase {
            AppServerTeardownPhase::Socket {
                drain,
                failure,
                runtime_guard,
            } => finish_cleanup_socket_teardown(
                drain,
                failure.into_socket(),
                runtime_guard,
                socket_deadline,
            ),
            AppServerTeardownPhase::Reservation {
                drain,
                failure,
                runtime_guard,
            } => finish_reservation_teardown(
                drain,
                failure.into_reservation(),
                runtime_guard,
                socket_deadline,
            ),
            AppServerTeardownPhase::Runtime {
                drain,
                failure,
                runtime_guard,
            } => finish_runtime_teardown(drain, failure.into_runtime(), runtime_guard),
        }
    }

    #[cfg(test)]
    fn into_reservation_for_test(
        self,
    ) -> Result<
        (
            PinnedAppGracefulDrain,
            AppSocketReservation,
            SessionRuntimeGuard,
        ),
        Box<Self>,
    > {
        match self.phase {
            AppServerTeardownPhase::Reservation {
                drain,
                failure,
                runtime_guard,
            } => Ok((drain, failure.into_reservation(), runtime_guard)),
            phase => Err(Box::new(Self {
                phase,
                error: self.error,
            })),
        }
    }
}

impl fmt::Debug for AppServerTeardownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.phase;
        formatter
            .debug_struct("AppServerTeardownFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AppServerTeardownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for AppServerTeardownFailure {}

fn stop_app_server(
    child: AppServerChild,
    socket: OwnedAppSocket,
    graceful: Duration,
    forced: Duration,
) -> Result<StoppedAppServer, Box<AppServerStopFailure>> {
    let AppServerChild {
        child,
        runtime_guard,
        expected_socket_path,
        monitor_seed,
    } = child;
    drop((expected_socket_path, monitor_seed));
    match shutdown_app_server_child(child, graceful, forced) {
        Ok(drain) => Ok(StoppedAppServer {
            drain,
            socket,
            runtime_guard,
        }),
        Err(unreaped) => Err(Box::new(AppServerStopFailure {
            unreaped,
            socket,
            runtime_guard,
        })),
    }
}

fn finish_socket_teardown(
    drain: PinnedAppGracefulDrain,
    socket: OwnedAppSocket,
    runtime_guard: SessionRuntimeGuard,
    deadline: Instant,
) -> Result<AppServerTeardownComplete, Box<AppServerTeardownFailure>> {
    match socket.cleanup(deadline) {
        Ok(runtime) => finish_runtime_teardown(drain, runtime, runtime_guard),
        Err(failure) => {
            let error = failure.error();
            Err(Box::new(AppServerTeardownFailure {
                phase: AppServerTeardownPhase::Socket {
                    drain,
                    failure,
                    runtime_guard,
                },
                error: AppServerTeardownError::Socket(error),
            }))
        }
    }
}

fn finish_cleanup_socket_teardown(
    drain: PinnedAppGracefulDrain,
    socket: AppSocketCleanupAuthority,
    runtime_guard: SessionRuntimeGuard,
    deadline: Instant,
) -> Result<AppServerTeardownComplete, Box<AppServerTeardownFailure>> {
    match socket.cleanup(deadline) {
        Ok(runtime) => finish_runtime_teardown(drain, runtime, runtime_guard),
        Err(failure) => {
            let error = failure.error();
            Err(Box::new(AppServerTeardownFailure {
                phase: AppServerTeardownPhase::Socket {
                    drain,
                    failure,
                    runtime_guard,
                },
                error: AppServerTeardownError::Socket(error),
            }))
        }
    }
}

fn finish_reservation_teardown(
    drain: PinnedAppGracefulDrain,
    reservation: AppSocketReservation,
    runtime_guard: SessionRuntimeGuard,
    deadline: Instant,
) -> Result<AppServerTeardownComplete, Box<AppServerTeardownFailure>> {
    let reservation = match reservation.require_matching_reaped_child(&drain) {
        Ok(reservation) => reservation,
        Err(failure) => {
            let error = failure.error();
            return Err(Box::new(AppServerTeardownFailure {
                phase: AppServerTeardownPhase::Reservation {
                    drain,
                    failure,
                    runtime_guard,
                },
                error: AppServerTeardownError::Socket(error),
            }));
        }
    };
    match reservation.release_if_absent() {
        Ok(runtime) => finish_runtime_teardown(drain, runtime, runtime_guard),
        Err(failure) if failure.error() == AppSocketError::SocketStillPresent => {
            match failure.into_reservation().adopt() {
                Ok(socket) => finish_socket_teardown(drain, socket, runtime_guard, deadline),
                Err(failure) if failure.error() == AppSocketError::SocketNotReady => {
                    match failure
                        .into_reservation()
                        .claim_socket_for_cleanup_after_child_exit(&drain)
                    {
                        Ok(socket) => {
                            finish_cleanup_socket_teardown(drain, socket, runtime_guard, deadline)
                        }
                        Err(failure) => {
                            let error = failure.error();
                            Err(Box::new(AppServerTeardownFailure {
                                phase: AppServerTeardownPhase::Reservation {
                                    drain,
                                    failure,
                                    runtime_guard,
                                },
                                error: AppServerTeardownError::Socket(error),
                            }))
                        }
                    }
                }
                Err(failure) => {
                    let error = failure.error();
                    Err(Box::new(AppServerTeardownFailure {
                        phase: AppServerTeardownPhase::Reservation {
                            drain,
                            failure,
                            runtime_guard,
                        },
                        error: AppServerTeardownError::Socket(error),
                    }))
                }
            }
        }
        Err(failure) => {
            let error = failure.error();
            Err(Box::new(AppServerTeardownFailure {
                phase: AppServerTeardownPhase::Reservation {
                    drain,
                    failure,
                    runtime_guard,
                },
                error: AppServerTeardownError::Socket(error),
            }))
        }
    }
}

fn finish_runtime_teardown(
    drain: PinnedAppGracefulDrain,
    runtime: PrivateRuntime,
    runtime_guard: SessionRuntimeGuard,
) -> Result<AppServerTeardownComplete, Box<AppServerTeardownFailure>> {
    match runtime.cleanup() {
        Ok(runtime) => Ok(AppServerTeardownComplete {
            drain,
            runtime,
            runtime_guard,
        }),
        Err(failure) => {
            let error = failure.error();
            Err(Box::new(AppServerTeardownFailure {
                phase: AppServerTeardownPhase::Runtime {
                    drain,
                    failure,
                    runtime_guard,
                },
                error: AppServerTeardownError::Runtime(error),
            }))
        }
    }
}

impl fmt::Debug for AppServerCommand<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.command;
        formatter.write_str("AppServerCommand(<redacted>)")
    }
}

pub(super) struct RemoteTuiCommand<'build> {
    command: Command,
    build: &'build PinnedSessionBuild,
}

impl<'build> RemoteTuiCommand<'build> {
    fn revalidate_for_launch(&self, deadline: Instant) -> Result<(), ProviderLaunchError> {
        self.build.revalidate_session_inputs(deadline)?;
        self.build
            .executable
            .revalidate(deadline)
            .map_err(Into::into)
    }

    #[cfg(feature = "internal-supervisor-fixture")]
    pub(super) fn into_launch_command(
        self,
        deadline: Instant,
    ) -> Result<super::launcher::RemoteTuiLaunchCommand<'build>, ProviderLaunchError> {
        self.revalidate_for_launch(deadline)?;
        Ok(super::launcher::RemoteTuiLaunchCommand::from_verified(
            self.command,
            self.build,
        ))
    }

    #[cfg(test)]
    fn command_for_test(&self) -> &Command {
        &self.command
    }

    #[cfg(test)]
    const fn session_brand_for_test(&self) -> u64 {
        self.build.brand_for_test()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AppServerLaunchError {
    Provider(ProviderLaunchError),
    Spawn(super::process::ProcessError),
}

impl fmt::Display for AppServerLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => error.fmt(formatter),
            Self::Spawn(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AppServerLaunchError {}

enum AppServerLaunchFailureKind {
    Provider(ProviderLaunchError),
    Spawn(SpawnFailure),
    /// The supplied reservation is already branded to another App child.
    /// This is outwardly an invalid argument, but unlike a true provider-only
    /// failure it can never authorize pre-spawn namespace cleanup.
    BoundReservation,
}

#[must_use = "launch failure can retain a live child or its bound socket/runtime reservation"]
pub(super) struct AppServerLaunchFailure {
    failure: AppServerLaunchFailureKind,
    lifetime: Arc<SessionLifetime>,
}

impl AppServerLaunchFailure {
    pub(super) fn error(&self) -> AppServerLaunchError {
        match &self.failure {
            AppServerLaunchFailureKind::Provider(error) => AppServerLaunchError::Provider(*error),
            AppServerLaunchFailureKind::Spawn(failure) => {
                AppServerLaunchError::Spawn(failure.error())
            }
            AppServerLaunchFailureKind::BoundReservation => {
                AppServerLaunchError::Provider(ProviderLaunchError::InvalidArgument)
            }
        }
    }

    #[cfg(test)]
    pub(super) fn has_spawn_failure(&self) -> bool {
        matches!(self.failure, AppServerLaunchFailureKind::Spawn(_))
    }

    /// Resolves only failures known to be pre-spawn.
    ///
    /// Once an App process existed, process-group KILL/reap cannot establish
    /// the pinned App graceful-drain contract because official tool children
    /// may have detached into another session. A reservation already branded
    /// to an App child is equally non-resolvable without that child's exact
    /// proof. Such failures remain owned with their runtime reservation and
    /// guardian lifetime; retries perform no signal or namespace mutation.
    pub(super) fn resolve(self, deadline: Instant) -> Result<AppServerLaunchResolution, Self> {
        let Self { failure, lifetime } = self;
        match failure {
            AppServerLaunchFailureKind::Provider(_) => Ok(AppServerLaunchResolution { lifetime }),
            AppServerLaunchFailureKind::Spawn(failure)
                if failure.state() == SpawnFailureState::NotStarted =>
            {
                let _ = deadline;
                Ok(AppServerLaunchResolution { lifetime })
            }
            AppServerLaunchFailureKind::Spawn(failure) => Err(Self {
                failure: AppServerLaunchFailureKind::Spawn(failure),
                lifetime,
            }),
            AppServerLaunchFailureKind::BoundReservation => Err(Self {
                failure: AppServerLaunchFailureKind::BoundReservation,
                lifetime,
            }),
        }
    }
}

#[must_use = "launch resolution retains the session guard until deliberately dropped"]
pub(super) struct AppServerLaunchResolution {
    lifetime: Arc<SessionLifetime>,
}

impl AppServerLaunchResolution {
    const fn terminal_reportable(&self) -> bool {
        true
    }
}

impl fmt::Debug for AppServerLaunchResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.lifetime;
        formatter.write_str("AppServerLaunchResolution(<redacted>)")
    }
}

enum AppServerLaunchReservationPhase {
    Launch {
        failure: AppServerLaunchFailure,
        reservation: AppSocketReservation,
    },
    Cleanup {
        launch: AppServerLaunchResolution,
        owner: AppServerLaunchRuntimeOwner,
    },
}

enum AppServerLaunchRuntimeOwner {
    Reservation(AppSocketReservation),
    ReadySocket(OwnedAppSocket),
    CleanupSocket(AppSocketCleanupAuthority),
    Runtime(PrivateRuntime),
}

/// Failed App launch plus the sole reservation capable of resolving any
/// pathname the unannounced child created before its spawn failure surfaced.
#[must_use = "App launch failure retains child and socket/runtime cleanup authority"]
pub(super) struct AppServerLaunchReservationFailure {
    phase: AppServerLaunchReservationPhase,
    error: AppServerLaunchError,
    cleanup_error: Option<AppServerTeardownError>,
}

impl AppServerLaunchReservationFailure {
    fn new(failure: AppServerLaunchFailure, reservation: AppSocketReservation) -> Self {
        let error = failure.error();
        Self {
            phase: AppServerLaunchReservationPhase::Launch {
                failure,
                reservation,
            },
            error,
            cleanup_error: None,
        }
    }

    #[cfg(test)]
    pub(super) const fn error(&self) -> AppServerLaunchError {
        self.error
    }

    #[cfg(test)]
    pub(super) const fn cleanup_error(&self) -> Option<AppServerTeardownError> {
        self.cleanup_error
    }

    /// Contains only a possibly-unannounced App child. The exact socket and
    /// runtime namespace deliberately remain owned by the returned proof so
    /// the startup coordinator can restore the terminal and disarm recovery
    /// before performing any namespace mutation.
    #[expect(
        clippy::boxed_local,
        reason = "the linear failure retains child, socket, runtime, and guardian ownership"
    )]
    pub(super) fn contain_child(
        self: Box<Self>,
        deadline: Instant,
    ) -> Result<AppServerLaunchContainmentComplete, Box<Self>> {
        let Self {
            phase,
            error,
            cleanup_error,
        } = *self;
        match phase {
            AppServerLaunchReservationPhase::Launch {
                failure,
                reservation,
            } => match failure.resolve(deadline) {
                Ok(launch) => Ok(AppServerLaunchContainmentComplete {
                    launch,
                    owner: AppServerLaunchRuntimeOwner::Reservation(reservation),
                    error,
                    cleanup_error,
                }),
                Err(failure) => {
                    let current = match failure.error() {
                        AppServerLaunchError::Spawn(error) => {
                            Some(AppServerTeardownError::Process(error))
                        }
                        AppServerLaunchError::Provider(_) => None,
                    };
                    Err(Box::new(Self {
                        phase: AppServerLaunchReservationPhase::Launch {
                            failure,
                            reservation,
                        },
                        error,
                        cleanup_error: cleanup_error.or(current),
                    }))
                }
            },
            AppServerLaunchReservationPhase::Cleanup { launch, owner } => {
                Ok(AppServerLaunchContainmentComplete {
                    launch,
                    owner,
                    error,
                    cleanup_error,
                })
            }
        }
    }

    #[cfg(test)]
    pub(super) fn resolve(
        self: Box<Self>,
        deadline: Instant,
    ) -> Result<AppServerLaunchReservationResolution, Box<Self>> {
        self.contain_child(deadline)?.cleanup_runtime(deadline)
    }
}

/// Proof that an App launch failure has no live or unreaped child while the
/// exact reservation/socket/runtime owner remains intentionally unmodified.
#[must_use = "contained App launch must clean its socket/runtime namespace in order"]
pub(super) struct AppServerLaunchContainmentComplete {
    launch: AppServerLaunchResolution,
    owner: AppServerLaunchRuntimeOwner,
    error: AppServerLaunchError,
    cleanup_error: Option<AppServerTeardownError>,
}

impl AppServerLaunchContainmentComplete {
    #[cfg(test)]
    pub(super) const fn error(&self) -> AppServerLaunchError {
        self.error
    }

    #[cfg(test)]
    pub(super) const fn cleanup_error(&self) -> Option<AppServerTeardownError> {
        self.cleanup_error
    }

    /// Cleans the retained namespace after terminal restoration and recovery
    /// disarm. Every failure reconstructs the same exact phase owner.
    pub(super) fn cleanup_runtime(
        self,
        deadline: Instant,
    ) -> Result<AppServerLaunchReservationResolution, Box<AppServerLaunchReservationFailure>> {
        resolve_app_launch_runtime(
            self.launch,
            self.owner,
            self.error,
            self.cleanup_error,
            deadline,
        )
    }
}

impl fmt::Debug for AppServerLaunchContainmentComplete {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.launch, &self.owner);
        formatter
            .debug_struct("AppServerLaunchContainmentComplete")
            .field("error", &self.error)
            .field("cleanup_error", &self.cleanup_error)
            .finish_non_exhaustive()
    }
}

fn resolve_app_launch_runtime(
    launch: AppServerLaunchResolution,
    mut owner: AppServerLaunchRuntimeOwner,
    error: AppServerLaunchError,
    cleanup_error: Option<AppServerTeardownError>,
    deadline: Instant,
) -> Result<AppServerLaunchReservationResolution, Box<AppServerLaunchReservationFailure>> {
    loop {
        owner = match owner {
            AppServerLaunchRuntimeOwner::Reservation(reservation) => {
                match reservation.release_if_absent() {
                    Ok(runtime) => AppServerLaunchRuntimeOwner::Runtime(runtime),
                    Err(failure) if failure.error() == AppSocketError::SocketStillPresent => {
                        match failure.into_reservation().adopt() {
                            Ok(socket) => AppServerLaunchRuntimeOwner::ReadySocket(socket),
                            Err(failure) => {
                                let current = AppServerTeardownError::Socket(failure.error());
                                return Err(Box::new(AppServerLaunchReservationFailure {
                                    phase: AppServerLaunchReservationPhase::Cleanup {
                                        launch,
                                        owner: AppServerLaunchRuntimeOwner::Reservation(
                                            failure.into_reservation(),
                                        ),
                                    },
                                    error,
                                    cleanup_error: cleanup_error.or(Some(current)),
                                }));
                            }
                        }
                    }
                    Err(failure) => {
                        let current = AppServerTeardownError::Socket(failure.error());
                        return Err(Box::new(AppServerLaunchReservationFailure {
                            phase: AppServerLaunchReservationPhase::Cleanup {
                                launch,
                                owner: AppServerLaunchRuntimeOwner::Reservation(
                                    failure.into_reservation(),
                                ),
                            },
                            error,
                            cleanup_error: cleanup_error.or(Some(current)),
                        }));
                    }
                }
            }
            AppServerLaunchRuntimeOwner::ReadySocket(socket) => match socket.cleanup(deadline) {
                Ok(runtime) => AppServerLaunchRuntimeOwner::Runtime(runtime),
                Err(failure) => {
                    let current = AppServerTeardownError::Socket(failure.error());
                    return Err(Box::new(AppServerLaunchReservationFailure {
                        phase: AppServerLaunchReservationPhase::Cleanup {
                            launch,
                            owner: AppServerLaunchRuntimeOwner::CleanupSocket(
                                failure.into_socket(),
                            ),
                        },
                        error,
                        cleanup_error: cleanup_error.or(Some(current)),
                    }));
                }
            },
            AppServerLaunchRuntimeOwner::CleanupSocket(socket) => match socket.cleanup(deadline) {
                Ok(runtime) => AppServerLaunchRuntimeOwner::Runtime(runtime),
                Err(failure) => {
                    let current = AppServerTeardownError::Socket(failure.error());
                    return Err(Box::new(AppServerLaunchReservationFailure {
                        phase: AppServerLaunchReservationPhase::Cleanup {
                            launch,
                            owner: AppServerLaunchRuntimeOwner::CleanupSocket(
                                failure.into_socket(),
                            ),
                        },
                        error,
                        cleanup_error: cleanup_error.or(Some(current)),
                    }));
                }
            },
            AppServerLaunchRuntimeOwner::Runtime(runtime) => match runtime.cleanup() {
                Ok(runtime) => {
                    return Ok(AppServerLaunchReservationResolution {
                        launch,
                        runtime,
                        error,
                        cleanup_error,
                    });
                }
                Err(failure) => {
                    let current = AppServerTeardownError::Runtime(failure.error());
                    return Err(Box::new(AppServerLaunchReservationFailure {
                        phase: AppServerLaunchReservationPhase::Cleanup {
                            launch,
                            owner: AppServerLaunchRuntimeOwner::Runtime(failure.into_runtime()),
                        },
                        error,
                        cleanup_error: cleanup_error.or(Some(current)),
                    }));
                }
            },
        };
    }
}

impl fmt::Debug for AppServerLaunchReservationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerLaunchReservationFailure")
            .field("error", &self.error)
            .field("cleanup_error", &self.cleanup_error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AppServerLaunchReservationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for AppServerLaunchReservationFailure {}

/// Proof that an App launch failed, every unannounced child was resolved, and
/// its exact socket/runtime namespace is clean.
#[must_use = "App launch resolution must release its guardian-session guard"]
pub(super) struct AppServerLaunchReservationResolution {
    launch: AppServerLaunchResolution,
    runtime: CleanRuntime,
    error: AppServerLaunchError,
    cleanup_error: Option<AppServerTeardownError>,
}

impl AppServerLaunchReservationResolution {
    #[cfg(test)]
    pub(super) const fn error(&self) -> AppServerLaunchError {
        self.error
    }

    #[cfg(test)]
    pub(super) const fn cleanup_error(&self) -> Option<AppServerTeardownError> {
        self.cleanup_error
    }

    /// Whether every direct child owned by this failed launch can be
    /// represented by the public lifecycle transcript. A child reaped before
    /// `ChildStarted` remains deliberately unreportable.
    pub(super) const fn terminal_reportable(&self) -> bool {
        self.launch.terminal_reportable()
    }

    pub(super) fn release(self) -> AppServerLaunchError {
        let Self {
            launch,
            runtime,
            error,
            cleanup_error: _,
        } = self;
        drop((launch, runtime));
        error
    }
}

impl fmt::Debug for AppServerLaunchReservationResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.launch, &self.runtime);
        formatter
            .debug_struct("AppServerLaunchReservationResolution")
            .field("error", &self.error)
            .field("cleanup_error", &self.cleanup_error)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AppServerLaunchFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppServerLaunchFailure")
            .field("error", &self.error())
            .field("retains_session", &true)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AppServerLaunchFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.error() {
            AppServerLaunchError::Provider(error) => error.fmt(formatter),
            AppServerLaunchError::Spawn(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AppServerLaunchFailure {}

impl fmt::Debug for RemoteTuiCommand<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.command;
        formatter.write_str("RemoteTuiCommand(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::providers::codex) enum ProviderLaunchError {
    InvalidArgument,
    AuthorityConsumed,
    SessionInUse,
    ExecutableChanged,
    SessionChanged,
    Storage,
    Timeout,
}

impl fmt::Display for ProviderLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "the supervised Codex launch plan is invalid",
            Self::AuthorityConsumed => "the supervised Codex launch authority was already consumed",
            Self::SessionInUse => "the supervised Codex session is still in use",
            Self::ExecutableChanged => "the verified Codex executable changed",
            Self::SessionChanged => "the verified Codex session inputs changed",
            Self::Storage => "the private Codex executable stage is unsafe",
            Self::Timeout => "the verified Codex executable stage timed out",
        })
    }
}

impl std::error::Error for ProviderLaunchError {}

impl From<PinnedStageError> for ProviderLaunchError {
    fn from(error: PinnedStageError) -> Self {
        match error {
            PinnedStageError::ExecutableChanged => Self::ExecutableChanged,
            PinnedStageError::Storage => Self::Storage,
            PinnedStageError::Timeout => Self::Timeout,
        }
    }
}

fn validate_thread_id(thread_id: &str) -> Result<String, ProviderLaunchError> {
    let parsed =
        uuid::Uuid::parse_str(thread_id).map_err(|_| ProviderLaunchError::InvalidArgument)?;
    if parsed.to_string() != thread_id {
        return Err(ProviderLaunchError::InvalidArgument);
    }
    Ok(thread_id.to_owned())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{self, Cursor, Read};
    use std::os::fd::AsFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::providers::codex::handoff_compat::TestCompatibilityCapability;
    use crate::providers::codex::monitor::MonitorProtocol;

    use super::super::protocol::{
        GuardianEvent, TerminalSnapshotFingerprint, send_coordinator_command,
    };
    use super::*;

    const THREAD_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const TEST_APP_READY_TIMEOUT: Duration = Duration::from_secs(3);
    const TEST_APP_READY_TIMEOUT_ERROR: &str =
        "test App did not install its TERM handler before the deadline";
    const TEST_COOPERATIVE_APP_HELPER_ENV: &str = "CALCIFER_PROVIDER_COOPERATIVE_APP_HELPER";
    const TEST_COOPERATIVE_APP_READY_ENV: &str = "CALCIFER_PROVIDER_COOPERATIVE_APP_READY";
    const TEST_COOPERATIVE_APP_HELPER_TEST: &str =
        "providers::codex::supervisor::provider::tests::cooperative_app_child_helper";
    const TEST_FORGOTTEN_RUNTIME_HELPER_ENV: &str = "CALCIFER_PROVIDER_FORGOTTEN_RUNTIME_HELPER";
    const TEST_FORGOTTEN_RUNTIME_HELPER_TEST: &str = "providers::codex::supervisor::provider::tests::forgotten_runtime_authority_cannot_release_the_session_lease";

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    fn test_launch_authorization(
        codex_home: &Path,
        working_directory: &Path,
        thread_id: &str,
    ) -> Result<ProviderLaunchAuthorization, Box<dyn std::error::Error>> {
        let session = GuardianSessionAuthority::for_test(codex_home, working_directory, thread_id)?;
        let mut wire = Vec::new();
        send_coordinator_command(&mut wire, CoordinatorCommand::Start, deadline())?;
        send_coordinator_command(
            &mut wire,
            CoordinatorCommand::TerminalArmAccepted,
            deadline(),
        )?;
        let mut receiver = GuardianCommandReceiver::new_terminal(Cursor::new(wire));
        receiver.record_event(GuardianEvent::LeaseCommitted)?;
        if receiver.receive(deadline())? != CoordinatorCommand::Start {
            return Err(ProtocolError::UnexpectedState.into());
        }
        receiver.record_event(GuardianEvent::TerminalArmed {
            snapshot: TerminalSnapshotFingerprint::from_digest([0x5a; 32]),
        })?;
        Ok(accept_provider_launch_authorization(
            session,
            &mut receiver,
            deadline(),
        )?)
    }

    struct Sandbox(PathBuf);

    struct ShortRuntimeParent(PathBuf);

    impl ShortRuntimeParent {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let path = PathBuf::from(format!(
                "/tmp/cf-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(Self(fs::canonicalize(path)?))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ShortRuntimeParent {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl Sandbox {
        fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!(
                "calcifer-provider-{name}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(Self(fs::canonicalize(path)?))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_executable(path: &Path, body: &[u8]) -> std::io::Result<()> {
        fs::write(path, body)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }

    fn test_cooperative_app_executable(
        path: &Path,
        ready_marker: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let helper = fs::canonicalize(std::env::current_exe()?)?;
        let helper = shell_quote_test_value(
            helper
                .to_str()
                .ok_or("cooperative App helper path is not UTF-8")?,
        )?;
        let ready_marker = ready_marker
            .to_str()
            .ok_or("test App readiness marker is not UTF-8")?;
        let quoted_marker = shell_quote_test_value(ready_marker)?;
        let helper_test = shell_quote_test_value(TEST_COOPERATIVE_APP_HELPER_TEST)?;
        let body = format!(
            "#!/bin/sh\n{TEST_COOPERATIVE_APP_HELPER_ENV}=1 {TEST_COOPERATIVE_APP_READY_ENV}={quoted_marker} exec {helper} --exact {helper_test} --nocapture --test-threads=1\n"
        );
        test_executable(path, body.as_bytes())?;
        Ok(())
    }

    fn shell_quote_test_value(value: &str) -> Result<String, Box<dyn std::error::Error>> {
        if value.contains(['\n', '\r', '\0']) {
            return Err("test helper shell value contained a control byte".into());
        }
        Ok(format!("'{}'", value.replace('\'', "'\"'\"'")))
    }

    #[test]
    fn cooperative_app_child_helper() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(TEST_COOPERATIVE_APP_HELPER_ENV).is_none() {
            return Ok(());
        }
        let ready = std::env::var_os(TEST_COOPERATIVE_APP_READY_ENV)
            .ok_or("cooperative App helper ready path is missing")?;
        let mut signals =
            signal_hook::iterator::Signals::new([signal_hook::consts::signal::SIGTERM])?;
        fs::write(ready, b"ready")?;
        for signal in signals.forever() {
            if signal == signal_hook::consts::signal::SIGTERM {
                return Ok(());
            }
        }
        Err("cooperative App signal iterator ended".into())
    }

    fn wait_for_test_app_ready(
        ready_marker: &Path,
        deadline: Instant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        while !ready_marker.exists() {
            if Instant::now() >= deadline {
                return Err(TEST_APP_READY_TIMEOUT_ERROR.into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    fn wait_for_test_process_and_group_absent(
        process: rustix::process::Pid,
        deadline: Instant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let process_absent = match rustix::process::getpgid(Some(process)) {
                Err(rustix::io::Errno::SRCH) => true,
                Ok(_) | Err(rustix::io::Errno::INTR) => false,
                Err(error) => return Err(std::io::Error::from(error).into()),
            };
            let group_absent = match rustix::process::test_kill_process_group(process) {
                Err(rustix::io::Errno::SRCH) => true,
                Ok(()) | Err(rustix::io::Errno::INTR) => false,
                Err(error) => return Err(std::io::Error::from(error).into()),
            };
            if process_absent && group_absent {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("test App process or process group remained live after cleanup".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn retain_test_cleanup_owner<T: fmt::Debug>(owner: T, context: &str) -> String {
        let diagnostic = format!("{context}: {owner:?}");
        // These fixed process tests must report exhausted cleanup without
        // dropping the sole direct-child wait owner. App ownership is
        // deliberately fail-closed, so an accidental Drop aborts the complete
        // parallel libtest process and strands unrelated fixture children.
        std::mem::forget(owner);
        diagnostic
    }

    fn retry_test_app_stop_failure(
        failure: Box<AppServerStopFailure>,
    ) -> Result<StoppedAppServer, Box<dyn std::error::Error>> {
        const RETRY_BOUND: Duration = Duration::from_secs(2);

        match failure.retry(RETRY_BOUND, RETRY_BOUND) {
            Ok(stopped) => Ok(stopped),
            Err(failure) => {
                let diagnostic = retain_test_cleanup_owner(
                    failure,
                    "App stop retry exhausted while retaining exact child authority",
                );
                Err(diagnostic.into())
            }
        }
    }

    fn retry_test_app_adoption_containment_failure(
        failure: AppServerAdoptionContainmentFailure,
    ) -> Result<AppServerAdoptionContainmentComplete, Box<dyn std::error::Error>> {
        const RETRY_BOUND: Duration = Duration::from_secs(2);

        match failure.retry(RETRY_BOUND, RETRY_BOUND) {
            Ok(contained) => Ok(contained),
            Err(failure) => {
                let diagnostic = retain_test_cleanup_owner(
                    failure,
                    "App adoption containment retry exhausted while retaining exact child authority",
                );
                Err(diagnostic.into())
            }
        }
    }

    fn cleanup_test_app_adoption_failure(
        failure: Box<AppServerSocketAdoptionFailure>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let contained =
            match (*failure).contain_child(Duration::from_secs(1), Duration::from_secs(1)) {
                Ok(contained) => contained,
                Err(failure) => retry_test_app_adoption_containment_failure(*failure)?,
            };
        let complete = match contained.cleanup_socket(deadline()) {
            Ok(complete) => complete,
            Err(failure) => failure.retry(deadline())?,
        };
        let _drain = complete.into_drain();
        Ok(())
    }

    fn cleanup_test_unadopted_app(
        child: AppServerChild,
        reservation: AppSocketReservation,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Bind the reservation to the exact child authority before teardown,
        // just as the production descriptor-failure projection does. A raw
        // synthetic aggregate would lack that identity edge and correctly
        // fail closed with `IdentityMismatch` after reaping the child.
        let failure = child.retain_descriptor_isolation_failure(
            reservation,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ObservationFailed,
        );
        cleanup_test_app_adoption_failure(failure)
    }

    fn wait_for_test_app_ready_with_owner(
        child: AppServerChild,
        reservation: AppSocketReservation,
        ready_marker: &Path,
    ) -> Result<(AppServerChild, AppSocketReservation), Box<dyn std::error::Error>> {
        wait_for_test_app_ready_with_owner_before(
            child,
            reservation,
            ready_marker,
            TEST_APP_READY_TIMEOUT,
        )
    }

    fn wait_for_test_app_ready_with_owner_before(
        child: AppServerChild,
        reservation: AppSocketReservation,
        ready_marker: &Path,
        ready_timeout: Duration,
    ) -> Result<(AppServerChild, AppSocketReservation), Box<dyn std::error::Error>> {
        let ready = if ready_timeout.is_zero() {
            Err(TEST_APP_READY_TIMEOUT_ERROR.into())
        } else {
            wait_for_test_app_ready(ready_marker, Instant::now() + ready_timeout)
        };
        match ready {
            Ok(()) => Ok((child, reservation)),
            Err(error) => {
                // Keep the assertion bound independent from recovery. If the
                // heavily loaded fixture missed it, give the synthetic shell
                // one cleanup-only chance to install its TERM handler before
                // exercising the production graceful-containment path.
                let _ =
                    wait_for_test_app_ready(ready_marker, Instant::now() + TEST_APP_READY_TIMEOUT);
                cleanup_test_unadopted_app(child, reservation)?;
                Err(error)
            }
        }
    }

    fn verify_test_app_descriptor_isolation_with_owner(
        mut child: AppServerChild,
        reservation: AppSocketReservation,
        forbidden: &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
    ) -> Result<
        (
            AppServerChild,
            AppSocketReservation,
            VerifiedAppDescriptorIsolation,
        ),
        Box<dyn std::error::Error>,
    > {
        match child.verify_descriptor_isolation(forbidden, deadline()) {
            Ok(proof) => Ok((child, reservation, proof)),
            Err(error) => {
                let failure = child.retain_descriptor_isolation_failure(reservation, error);
                cleanup_test_app_adoption_failure(failure)?;
                Err(error.into())
            }
        }
    }

    fn cleanup_test_app_session(
        session: AppServerSession,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stopped = match session.stop(Duration::from_secs(1), Duration::from_secs(1)) {
            Ok(stopped) => stopped,
            Err(failure) => retry_test_app_stop_failure(failure)?,
        };
        let complete = match stopped.cleanup_socket_runtime(deadline()) {
            Ok(complete) => complete,
            Err(failure) => failure.retry(deadline())?,
        };
        let _drain = complete.into_drain();
        Ok(())
    }

    #[test]
    fn test_cleanup_diagnostic_retains_authority_bearing_owner() {
        use std::cell::Cell;
        use std::rc::Rc;

        #[derive(Debug)]
        struct DropProbe(Rc<Cell<bool>>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let dropped = Rc::new(Cell::new(false));
        let diagnostic = retain_test_cleanup_owner(
            DropProbe(Rc::clone(&dropped)),
            "fixed test cleanup exhausted",
        );

        assert!(!dropped.get());
        assert_eq!(
            diagnostic,
            "fixed test cleanup exhausted: DropProbe(Cell { value: false })"
        );
    }

    #[test]
    fn readiness_timeout_contains_app_child_and_cleans_exact_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("app-readiness-timeout-cleanup")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        let ready_marker = sandbox.path().join("app-ready");
        test_cooperative_app_executable(&installed, &ready_marker)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let runtime_parent = ShortRuntimeParent::new()?;
        let reservation = PrivateRuntime::create(runtime_parent.path())?.reserve_app_socket()?;
        let socket_path = reservation.path().to_path_buf();
        let runtime_path = socket_path
            .parent()
            .ok_or("App socket must have a runtime parent")?
            .to_path_buf();
        let app = build
            .app_server_command_for_reservation(&reservation, deadline())?
            .launch(deadline())?;

        let error = match wait_for_test_app_ready_with_owner_before(
            app,
            reservation,
            &ready_marker,
            Duration::ZERO,
        ) {
            Err(error) => error,
            Ok((app, reservation)) => {
                cleanup_test_unadopted_app(app, reservation)?;
                build.cleanup(deadline())?;
                return Err("an expired test readiness bound was accepted".into());
            }
        };

        assert_eq!(error.to_string(), TEST_APP_READY_TIMEOUT_ERROR);
        assert!(!socket_path.exists());
        assert!(!runtime_path.exists());
        build.cleanup(deadline())?;
        Ok(())
    }

    struct AlwaysWouldBlock;

    impl Read for AlwaysWouldBlock {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    fn command_env<'a>(
        command: &'a std::process::Command,
        name: &str,
    ) -> Option<Option<&'a OsStr>> {
        command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(name))
            .map(|(_, value)| value)
    }

    #[test]
    fn launch_authorization_requires_validated_terminal_arm_acceptance()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("arm-acceptance")?;
        let verification_attempts =
            crate::providers::codex::handoff_compat::compatibility_verification_attempts_for_test();
        let mut start_wire = Vec::new();
        send_coordinator_command(&mut start_wire, CoordinatorCommand::Start, deadline())?;
        let mut start_only = GuardianCommandReceiver::new_terminal(Cursor::new(start_wire));
        start_only.record_event(GuardianEvent::LeaseCommitted)?;
        let start_failure = accept_provider_launch_authorization(
            GuardianSessionAuthority::for_test(sandbox.path(), sandbox.path(), THREAD_ID)?,
            &mut start_only,
            deadline(),
        )
        .err()
        .ok_or("START alone must not mint provider launch authority")?;
        assert_eq!(start_failure.error(), ProtocolError::UnexpectedState);
        drop(start_failure.into_session());

        let mut wrong_order_wire = Vec::new();
        send_coordinator_command(
            &mut wrong_order_wire,
            CoordinatorCommand::TerminalArmAccepted,
            deadline(),
        )?;
        let mut wrong_order = GuardianCommandReceiver::new_terminal(Cursor::new(wrong_order_wire));
        wrong_order.record_event(GuardianEvent::LeaseCommitted)?;
        let wrong_order_failure = accept_provider_launch_authorization(
            GuardianSessionAuthority::for_test(sandbox.path(), sandbox.path(), THREAD_ID)?,
            &mut wrong_order,
            deadline(),
        )
        .err()
        .ok_or("the validator's wrong-order path must mint nothing")?;
        assert_eq!(wrong_order_failure.error(), ProtocolError::UnexpectedState);
        drop(wrong_order_failure.into_session());

        let mut timeout = GuardianCommandReceiver::new_terminal(AlwaysWouldBlock);
        timeout.record_event(GuardianEvent::LeaseCommitted)?;
        let timeout_failure = accept_provider_launch_authorization(
            GuardianSessionAuthority::for_test(sandbox.path(), sandbox.path(), THREAD_ID)?,
            &mut timeout,
            Instant::now(),
        )
        .err()
        .ok_or("the validator's timeout path must mint nothing")?;
        assert_eq!(timeout_failure.error(), ProtocolError::Timeout);
        drop(timeout_failure.into_session());

        assert_eq!(
            crate::providers::codex::handoff_compat::compatibility_verification_attempts_for_test(),
            verification_attempts,
            "no process-spawning compatibility proof may run before terminal-arm acceptance"
        );

        assert!(
            format!(
                "{:?}",
                test_launch_authorization(sandbox.path(), sandbox.path(), THREAD_ID)?
            )
            .contains("<redacted>")
        );
        Ok(())
    }

    #[test]
    fn authorized_compatibility_failure_returns_post_arm_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("authorized-compatibility")?;
        let authorization = test_launch_authorization(sandbox.path(), sandbox.path(), THREAD_ID)?;
        let attempts =
            crate::providers::codex::handoff_compat::compatibility_verification_attempts_for_test();

        let failure = verify_authorized_compatibility(
            authorization,
            &sandbox.path().join("missing-codex"),
            Duration::from_secs(1),
        )
        .err()
        .ok_or("a missing executable must fail after consuming post-arm authority")?;

        assert_eq!(failure.error(), CodexHandoffError::Spawn);
        assert_eq!(
            crate::providers::codex::handoff_compat::compatibility_verification_attempts_for_test(),
            attempts + 1
        );
        let (authorization, probe_failure) = failure.into_parts();
        assert_eq!(
            format!("{authorization:?}"),
            "ProviderLaunchAuthorization(<redacted>)"
        );
        assert!(!probe_failure.has_retained_ownership());
        Ok(())
    }

    #[test]
    fn socket_address_enforces_portable_unix_path_limits() {
        let exact = PathBuf::from(format!("/{}", "a".repeat(102)));
        let overlong = PathBuf::from(format!("/{}", "a".repeat(103)));

        assert_eq!(exact.as_os_str().as_bytes().len(), 103);
        assert!(VerifiedProviderSocketAddress::for_test(&exact).is_ok());
        assert!(matches!(
            VerifiedProviderSocketAddress::for_test(&overlong),
            Err(ProviderLaunchError::InvalidArgument)
        ));

        for invalid in [
            PathBuf::from("relative.sock"),
            PathBuf::from("/tmp/control\nsock"),
            PathBuf::from("/tmp/nul\0sock"),
            PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', 0xff])),
        ] {
            assert!(matches!(
                VerifiedProviderSocketAddress::for_test(&invalid),
                Err(ProviderLaunchError::InvalidArgument)
            ));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn session_directories_reject_and_recheck_extended_acl()
    -> Result<(), Box<dyn std::error::Error>> {
        use exacl::{AclEntry, AclOption, Flag, Perm};

        let sandbox = Sandbox::new("session-acl")?;
        let home = sandbox.path().join("home");
        let workspace = sandbox.path().join("workspace");
        fs::create_dir(&home)?;
        fs::create_dir(&workspace)?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        let other_uid = if rustix::process::geteuid().as_raw() == 89 {
            "1"
        } else {
            "89"
        };
        let acl = [AclEntry::allow_user(other_uid, Perm::READ, Flag::empty())];
        let options = Some(AclOption::SYMLINK_ACL);

        exacl::setfacl(&[&home], &acl, options)?;
        assert!(matches!(
            GuardianSessionAuthority::for_test(&home, &workspace, THREAD_ID),
            Err(ProviderLaunchError::InvalidArgument)
        ));
        exacl::setfacl(&[&home], &[], options)?;

        let session = GuardianSessionAuthority::for_test(&home, &workspace, THREAD_ID)?;
        exacl::setfacl(&[&workspace], &acl, options)?;
        assert_eq!(
            session.spec.working_directory.revalidate(),
            Err(ProviderLaunchError::SessionChanged)
        );
        exacl::setfacl(&[&workspace], &[], options)?;
        Ok(())
    }

    #[test]
    fn invalid_session_inputs_fail_before_executable_pinning()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("invalid-session-spec")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let error = GuardianSessionAuthority::for_test(
            Path::new("relative-home"),
            &stage_parent,
            THREAD_ID,
        )
        .err()
        .ok_or("invalid session inputs minted guardian authority")?;

        assert_eq!(error, ProviderLaunchError::InvalidArgument);
        assert_eq!(fs::read_dir(&stage_parent)?.count(), 0);
        Ok(())
    }

    #[test]
    fn only_post_terminal_arm_authorization_can_pin_a_session_build()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("authorization")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;

        let capability = TestCompatibilityCapability::capture(&installed)?;
        let authorization = test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?;
        let build =
            PinnedSessionBuild::from_test_capability(authorization, capability, &stage_parent)?;

        assert_eq!(format!("{build:?}"), "PinnedSessionBuild(<redacted>)");
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn authorized_fixture_seam_stages_exact_build_without_running_protocol_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("authorized-fixture-seam")?;
        let installed = sandbox.path().join("installed-codex");
        let home = sandbox.path().join("home");
        let workspace = sandbox.path().join("workspace");
        let stage_parent = sandbox.path().join("stage-parent");
        for directory in [&home, &workspace, &stage_parent] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let attempts =
            crate::providers::codex::handoff_compat::compatibility_verification_attempts_for_test();

        let build = verify_authorized_test_compatibility(
            test_launch_authorization(&home, &workspace, THREAD_ID)?,
            &installed,
            &stage_parent,
            Duration::from_secs(2),
        )?;

        assert_eq!(
            crate::providers::codex::handoff_compat::compatibility_verification_attempts_for_test(),
            attempts,
            "the deterministic process fixture must not impersonate a provider protocol proof"
        );
        assert!(build.executable_path_for_test().starts_with(&stage_parent));
        assert!(build.runtime_path_for_test().starts_with(&stage_parent));
        build.cleanup(deadline())?;
        assert_eq!(fs::read_dir(&stage_parent)?.count(), 0);
        Ok(())
    }

    #[test]
    fn authorized_fixture_seam_preserves_capture_errors_and_one_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("authorized-fixture-failures")?;
        let home = sandbox.path().join("home");
        let workspace = sandbox.path().join("workspace");
        let stage_parent = sandbox.path().join("stage-parent");
        for directory in [&home, &workspace, &stage_parent] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }

        let missing = sandbox.path().join("missing-codex");
        let failure = verify_authorized_test_compatibility(
            test_launch_authorization(&home, &workspace, THREAD_ID)?,
            &missing,
            &stage_parent,
            Duration::from_secs(2),
        )
        .err()
        .ok_or("a missing fixture executable minted a session build")?;
        assert_eq!(failure.error(), CodexHandoffError::Spawn);
        assert!(!failure.has_retained_probe_ownership());
        drop(failure);

        let installed = sandbox.path().join("installed-codex");
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let failure = verify_authorized_test_compatibility(
            test_launch_authorization(&home, &workspace, THREAD_ID)?,
            &installed,
            &stage_parent,
            Duration::ZERO,
        )
        .err()
        .ok_or("an exhausted fixture compatibility budget minted a session build")?;
        assert_eq!(failure.error(), CodexHandoffError::Timeout);
        assert!(!failure.has_retained_probe_ownership());
        drop(failure);
        assert_eq!(fs::read_dir(&stage_parent)?.count(), 0);
        Ok(())
    }

    #[test]
    fn install_replacement_between_compatibility_and_pin_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("install-replacement")?;
        let installed = sandbox.path().join("installed-codex");
        let original = sandbox.path().join("installed-codex-original");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let capability = TestCompatibilityCapability::capture(&installed)?;

        fs::rename(&installed, &original)?;
        test_executable(&installed, b"#!/bin/sh\nexit 42\n")?;

        let error = match PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            capability,
            &stage_parent,
        ) {
            Err(error) => error,
            Ok(_) => return Err("a replaced install path minted a session build".into()),
        };
        assert_eq!(error.error(), ProviderLaunchError::ExecutableChanged);
        assert!(installed.exists());
        assert!(original.exists());
        assert_eq!(fs::read_dir(&stage_parent)?.count(), 0);
        Ok(())
    }

    #[test]
    fn app_server_and_tui_plans_share_one_exact_sanitized_build()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("plans")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        let home = sandbox.path().join("home");
        let workspace = sandbox.path().join("workspace");
        fs::create_dir(&stage_parent)?;
        fs::create_dir(&home)?;
        fs::create_dir(&workspace)?;
        for directory in [&stage_parent, &home, &workspace] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let capability = TestCompatibilityCapability::capture(&installed)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&home, &workspace, THREAD_ID)?,
            capability,
            &stage_parent,
        )?;
        let app_socket = PathBuf::from("/tmp/cf-provider-app.sock");
        let relay_socket = PathBuf::from("/tmp/cf-provider-relay.sock");

        let app_socket = VerifiedProviderSocketAddress::for_test(&app_socket)?;
        let relay_socket = VerifiedProviderSocketAddress::for_test(&relay_socket)?;
        assert!(matches!(
            build.app_server_command(&app_socket, Instant::now()),
            Err(ProviderLaunchError::Timeout)
        ));
        let app_plan = build.app_server_command(&app_socket, deadline())?;
        let tui_plan = build.remote_tui_command(&relay_socket, deadline())?;
        let app = app_plan.command_for_test();
        let tui = tui_plan.command_for_test();

        assert_eq!(app.get_program(), tui.get_program());
        assert_ne!(app.get_program(), installed.as_os_str());
        assert_eq!(app.get_current_dir(), Some(workspace.as_path()));
        assert_eq!(tui.get_current_dir(), Some(workspace.as_path()));
        assert_eq!(command_env(app, "CODEX_HOME"), Some(Some(home.as_os_str())));
        assert_eq!(command_env(tui, "CODEX_HOME"), Some(Some(home.as_os_str())));
        // After `env_clear`, `env_remove` may omit a key instead of retaining
        // `Some(None)` in `Command::get_envs`. Both representations satisfy
        // the build invariant: no forbidden key has a concrete value. The
        // real-exec environment fixture separately verifies ambient keys are
        // absent from the App and wrapped TUI processes.
        assert!(command_env(app, "OPENAI_API_KEY").flatten().is_none());
        assert!(command_env(tui, "CODEX_API_KEY").flatten().is_none());
        for variable in ["RUST_LOG", "LOG_FORMAT"] {
            assert!(command_env(app, variable).flatten().is_none());
            assert!(command_env(tui, variable).flatten().is_none());
        }

        let app_args = app
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let tui_args = tui
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            app_args,
            [
                "-c",
                "cli_auth_credentials_store=\"file\"",
                "-c",
                "mcp_oauth_credentials_store=\"file\"",
                "app-server",
                "--listen",
                app_socket.as_str(),
            ]
        );
        assert_eq!(
            tui_args,
            [
                "-c",
                "cli_auth_credentials_store=\"file\"",
                "-c",
                "mcp_oauth_credentials_store=\"file\"",
                "resume",
                "--no-alt-screen",
                "--remote",
                relay_socket.as_str(),
                THREAD_ID,
            ]
        );
        assert!(!tui_args.iter().any(|argument| argument == "--last"));
        let _ = (app, tui);
        drop((app_plan, tui_plan));
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn command_plans_and_monitor_share_one_immutable_branded_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("branded-session")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        let home = sandbox.path().join("home");
        let workspace = sandbox.path().join("workspace");
        for directory in [&stage_parent, &home, &workspace] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let capability = TestCompatibilityCapability::capture(&installed)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&home, &workspace, THREAD_ID)?,
            capability,
            &stage_parent,
        )?;
        let app_socket =
            VerifiedProviderSocketAddress::for_test(Path::new("/tmp/cf-brand-app.sock"))?;
        let tui_socket =
            VerifiedProviderSocketAddress::for_test(Path::new("/tmp/cf-brand-tui.sock"))?;

        let app = build.app_server_command(&app_socket, deadline())?;
        let tui = build.remote_tui_command(&tui_socket, deadline())?;
        let monitor_capability = build.monitor_session_capability(deadline())?;
        let brand = build.brand_for_test();
        assert_eq!(app.session_brand_for_test(), brand);
        assert_eq!(tui.session_brand_for_test(), brand);
        assert_eq!(monitor_capability.brand_for_test(), brand);

        assert!(matches!(
            build.app_server_command(&app_socket, deadline()),
            Err(ProviderLaunchError::AuthorityConsumed)
        ));
        assert!(matches!(
            build.remote_tui_command(&tui_socket, deadline()),
            Err(ProviderLaunchError::AuthorityConsumed)
        ));
        assert!(matches!(
            build.monitor_session_capability(deadline()),
            Err(ProviderLaunchError::AuthorityConsumed)
        ));

        let (monitor, _) = MonitorProtocol::start_pinned(monitor_capability)?;
        assert_eq!(
            monitor.session_target_for_test(),
            (home.as_path(), THREAD_ID)
        );
        assert_eq!(monitor.session_brand_for_test(), brand);

        drop((app, tui));
        let failure = build
            .cleanup(deadline())
            .err()
            .ok_or("a live monitor guard allowed build and lease cleanup")?;
        assert_eq!(failure.error(), ProviderLaunchError::SessionInUse);
        let build = (*failure).into_build();
        drop(monitor);
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn sealed_runtime_route_shares_the_exact_app_tui_and_session_brand()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("sealed-runtime-route")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        let home = sandbox.path().join("home");
        let workspace = sandbox.path().join("workspace");
        for directory in [&stage_parent, &home, &workspace] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&home, &workspace, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let runtime_parent = ShortRuntimeParent::new()?;
        let runtime = PrivateRuntime::create(runtime_parent.path())?;
        let runtime_path = runtime.path().to_path_buf();
        let (app_reservation, route) = runtime.reserve_supervised_layout()?.into_parts();

        let app = build.app_server_command_for_reservation(&app_reservation, deadline())?;
        let exact_relay = build.exact_relay_plan(route, deadline())?;
        let tui = exact_relay.remote_tui_command(deadline())?;
        let brand = build.brand_for_test();
        assert_eq!(app.session_brand_for_test(), brand);
        assert_eq!(exact_relay.session_brand_for_test(), brand);
        assert_eq!(tui.session_brand_for_test(), brand);
        let tui_args = tui
            .command_for_test()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(tui_args.windows(2).any(|pair| {
            pair == [
                "--remote".to_owned(),
                format!("unix://{}", runtime_path.join("tui.sock").display()),
            ]
        }));
        assert!(!tui_args.iter().any(|argument| argument == "--last"));

        drop((app, tui, exact_relay));
        let runtime = app_reservation.release_if_absent()?;
        let _ = runtime.cleanup().map_err(|failure| failure.error())?;
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn exact_relay_start_failure_retains_and_resolves_the_branded_route()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("exact-relay-start-failure")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let runtime_parent = ShortRuntimeParent::new()?;
        let runtime = PrivateRuntime::create(runtime_parent.path())?;
        let relay_path = runtime.path().join("tui.sock");
        let (app_reservation, route) = runtime.reserve_supervised_layout()?.into_parts();
        let app = build.app_server_command_for_reservation(&app_reservation, deadline())?;
        let exact = build.exact_relay_plan(route, deadline())?;
        let tui = exact.remote_tui_command(deadline())?;
        ReadinessProxy::fail_next_exact_start_after_bind_for_test();

        let failure = exact
            .spawn(Duration::from_secs(1), deadline())
            .err()
            .ok_or("injected exact relay start fault unexpectedly succeeded")?;
        fn assert_static<T: 'static>(_: &T) {}
        assert_static(&failure);
        assert_eq!(
            failure.error(),
            ExactRelayStartError::Relay(ReadinessProxyError::Worker)
        );
        assert!(relay_path.exists());
        assert_eq!(
            format!("{failure:?}"),
            "ExactRelayStartFailure { error: Relay(Worker), bound_socket_retained: true, .. }"
        );
        let resolution = match failure.resolve() {
            Ok(resolution) => resolution,
            Err(_) => panic!("recorded exact relay socket did not resolve"),
        };
        assert_eq!(
            resolution.error(),
            ExactRelayStartError::Relay(ReadinessProxyError::Worker)
        );
        assert!(!relay_path.exists());
        let failure = resolution
            .retry(Duration::ZERO)
            .err()
            .ok_or("a zero-timeout relay retry unexpectedly succeeded")?;
        assert_eq!(
            failure.error(),
            ExactRelayStartError::Relay(ReadinessProxyError::InvalidArgument)
        );
        assert_eq!(
            format!("{failure:?}"),
            "ExactRelayStartFailure { error: Relay(InvalidArgument), bound_socket_retained: false, .. }"
        );
        let abort = match failure.resolve_for_startup_abort() {
            Ok(abort) => abort,
            Err(_) => panic!("an unbound relay start failure did not resolve"),
        };
        assert_eq!(
            abort.error(),
            ExactRelayStartError::Relay(ReadinessProxyError::InvalidArgument)
        );
        assert_eq!(
            abort.release(),
            ExactRelayStartError::Relay(ReadinessProxyError::InvalidArgument)
        );

        drop((app, tui));
        let runtime = app_reservation.release_if_absent()?;
        let _ = runtime.cleanup().map_err(|failure| failure.error())?;
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn exact_relay_shutdown_timeout_retains_owned_retry_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("exact-relay-shutdown-timeout")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let runtime_parent = ShortRuntimeParent::new()?;
        let runtime = PrivateRuntime::create(runtime_parent.path())?;
        let (app_reservation, route) = runtime.reserve_supervised_layout()?.into_parts();
        let mut relay = build
            .exact_relay_plan(route, deadline())?
            .spawn(Duration::from_secs(1), deadline())?;
        assert_eq!(relay.brand_for_test(), build.brand_for_test());
        assert_eq!(relay.poll_ready(), Ok(None));

        let failure = relay
            .shutdown(Instant::now())
            .err()
            .ok_or("expired relay shutdown unexpectedly completed")?;
        assert_eq!(failure.error(), ReadinessProxyError::Timeout);
        fn assert_static<T: 'static>(_: &T) {}
        assert_static(&failure);
        let in_use = build
            .cleanup(deadline())
            .err()
            .ok_or("relay shutdown failure released its session guard")?;
        let build = (*in_use).into_build();
        let resolution = failure.resolve(deadline())?;
        assert_eq!(resolution.release(), Some(ReadinessProxyError::Timeout));

        let runtime = app_reservation.release_if_absent()?;
        let _ = runtime.cleanup().map_err(|failure| failure.error())?;
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn exact_relay_shutdown_preserves_replacement_and_retains_cleanup_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("exact-relay-shutdown-replacement")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let runtime_parent = ShortRuntimeParent::new()?;
        let runtime = PrivateRuntime::create(runtime_parent.path())?;
        let relay_path = runtime.path().join("tui.sock");
        let (app_reservation, route) = runtime.reserve_supervised_layout()?.into_parts();
        let relay = build
            .exact_relay_plan(route, deadline())?
            .spawn(Duration::from_secs(1), deadline())?;
        fs::remove_file(&relay_path)?;
        fs::write(&relay_path, b"preserve-relay-replacement")?;

        let failure = relay
            .shutdown(deadline())
            .err()
            .ok_or("replacement unexpectedly satisfied relay cleanup")?;
        assert_eq!(failure.error(), ReadinessProxyError::Cleanup);
        assert_eq!(fs::read(&relay_path)?, b"preserve-relay-replacement");
        fs::remove_file(&relay_path)?;
        let resolution = failure.resolve(deadline())?;
        assert_eq!(resolution.release(), Some(ReadinessProxyError::Cleanup));

        let runtime = app_reservation.release_if_absent()?;
        let _ = runtime.cleanup().map_err(|failure| failure.error())?;
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn forgotten_runtime_authority_cannot_release_the_session_lease()
    -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(TEST_FORGOTTEN_RUNTIME_HELPER_ENV).is_none() {
            let status = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    TEST_FORGOTTEN_RUNTIME_HELPER_TEST,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(TEST_FORGOTTEN_RUNTIME_HELPER_ENV, "1")
                .status()?;
            if !status.success() {
                return Err(format!(
                    "isolated forgotten-runtime authority test exited with {status:?}"
                )
                .into());
            }
            return Ok(());
        }

        let sandbox = Sandbox::new("forgotten-runtime-authority")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;

        let leaked = build.retain_runtime();
        std::mem::forget(leaked);
        let failure = build
            .cleanup(deadline())
            .err()
            .ok_or("forgotten live authority released its guardian lease")?;
        assert_eq!(failure.error(), ProviderLaunchError::SessionInUse);
        drop(failure);
        Ok(())
    }

    #[test]
    fn app_socket_adoption_waits_for_the_exact_async_bind_and_tears_down_in_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("app-socket-async-bind")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        let ready_marker = sandbox.path().join("app-ready");
        test_cooperative_app_executable(&installed, &ready_marker)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let runtime_parent = ShortRuntimeParent::new()?;
        let reservation = PrivateRuntime::create(runtime_parent.path())?.reserve_app_socket()?;
        let app_socket_path = reservation.path().to_path_buf();
        let (forbidden, _forbidden_peer) = UnixStream::pair()?;
        let mut forbidden_identities = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        forbidden_identities.capture(forbidden.as_fd())?;
        let app = build
            .app_server_command_for_reservation(&reservation, deadline())?
            .launch(deadline())?;
        let (mut app, reservation) =
            wait_for_test_app_ready_with_owner(app, reservation, &ready_marker)?;
        let containment = app.containment();
        assert_eq!(containment.role(), ChildRole::AppServer);
        assert!(containment.pid() > 0);
        assert_eq!(containment.pid(), containment.pgid());
        assert!(matches!(
            app.verify_descriptor_isolation(&forbidden_identities, Instant::now()),
            Err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::Deadline)
        ));
        assert_eq!(app.containment(), containment);
        let (app, reservation, descriptor_isolation) =
            verify_test_app_descriptor_isolation_with_owner(
                app,
                reservation,
                &forbidden_identities,
            )?;
        let mut listener = None;
        let mut adoption_wait_steps = 0_usize;
        let session = match app.adopt_socket_with_wait(
            reservation,
            descriptor_isolation,
            deadline(),
            |path| {
                match adoption_wait_steps {
                    0 => {
                        listener = UnixListener::bind(path).ok();
                        if listener.is_some() {
                            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
                        }
                    }
                    1 => {
                        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
                    }
                    _ => {}
                }
                adoption_wait_steps = adoption_wait_steps.saturating_add(1);
            },
        ) {
            Ok(session) => session,
            Err(failure) => {
                let error = failure.error();
                drop(listener);
                cleanup_test_app_adoption_failure(failure)?;
                build.cleanup(deadline())?;
                return Err(error.into());
            }
        };
        assert_eq!(adoption_wait_steps, 2);
        assert_eq!(session.containment(), containment);
        assert_eq!(
            session
                .observe_forbidden_descriptors_absent(&forbidden_identities, deadline())?
                .member_count(),
            1
        );
        let connected = session.connect_monitor(deadline())?;
        assert_eq!(connected.containment(), containment);
        assert_eq!(
            connected
                .observe_forbidden_descriptors_absent(&forbidden_identities, deadline())?
                .member_count(),
            1
        );
        assert_ne!(connected.brand_for_test(), 0);

        let in_use = build
            .cleanup(deadline())
            .err()
            .ok_or("connected monitor topology released the guardian lease")?;
        assert_eq!(in_use.error(), ProviderLaunchError::SessionInUse);
        let build = (*in_use).into_build();

        let stopped = connected.stop_app_server(Duration::from_secs(1), Duration::from_secs(1));
        let stopped = match stopped {
            Ok(stopped) => stopped,
            Err(failure) => retry_test_app_stop_failure(failure)?,
        };
        assert!(stopped.outcome().failure().is_none());
        assert!(app_socket_path.exists());
        drop(listener);
        let complete = stopped.cleanup_socket_runtime(deadline())?;
        let _drain = complete.into_drain();
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn reaped_app_child_cleans_its_exact_socket_when_bind_never_reaches_chmod()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("app-socket-bind-before-chmod-exit")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        let ready_marker = sandbox.path().join("app-ready");
        test_cooperative_app_executable(&installed, &ready_marker)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let runtime_parent = ShortRuntimeParent::new()?;
        let reservation = PrivateRuntime::create(runtime_parent.path())?.reserve_app_socket()?;
        let socket_path = reservation.path().to_path_buf();
        let runtime_path = socket_path
            .parent()
            .ok_or("App socket must have a runtime parent")?
            .to_path_buf();
        let app = build
            .app_server_command_for_reservation(&reservation, deadline())?
            .launch(deadline())?;
        let (app, reservation) =
            wait_for_test_app_ready_with_owner(app, reservation, &ready_marker)?;
        let empty_forbidden = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        let (app, reservation, descriptor_isolation) =
            verify_test_app_descriptor_isolation_with_owner(app, reservation, &empty_forbidden)?;
        let listener = match UnixListener::bind(reservation.path()) {
            Ok(listener) => listener,
            Err(error) => {
                cleanup_test_unadopted_app(app, reservation)?;
                build.cleanup(deadline())?;
                return Err(error.into());
            }
        };
        if let Err(error) =
            fs::set_permissions(reservation.path(), fs::Permissions::from_mode(0o755))
        {
            drop(listener);
            cleanup_test_unadopted_app(app, reservation)?;
            build.cleanup(deadline())?;
            return Err(error.into());
        }
        let failure = match app.adopt_socket(reservation, descriptor_isolation, Instant::now()) {
            Err(failure) => failure,
            Ok(session) => {
                drop(listener);
                cleanup_test_app_session(session)?;
                build.cleanup(deadline())?;
                return Err("a socket that never reached private mode was adopted".into());
            }
        };
        assert!(matches!(
            failure.error(),
            AppServerTopologyError::Socket(AppSocketError::AdoptionTimeout)
                | AppServerTopologyError::Process(ProcessError::Deadline)
        ));
        assert!(socket_path.exists());
        assert!(runtime_path.exists());

        let in_use = build
            .cleanup(deadline())
            .err()
            .ok_or("adoption failure released its live App child lease")?;
        let build = (*in_use).into_build();
        let contained = (*failure).contain_child(Duration::from_secs(1), Duration::from_secs(1));
        let contained = match contained {
            Ok(contained) => contained,
            Err(failure) => retry_test_app_adoption_containment_failure(*failure)?,
        };
        drop(listener);
        let cleanup_failure = contained
            .cleanup_socket(Instant::now())
            .err()
            .ok_or("expired pre-chmod cleanup unexpectedly released authority")?;
        assert_eq!(
            cleanup_failure.error,
            AppServerTeardownError::Socket(AppSocketError::Timeout)
        );
        assert!(socket_path.exists());
        assert!(runtime_path.exists());
        let complete = cleanup_failure.retry(deadline())?;
        assert!(!socket_path.exists());
        assert!(!runtime_path.exists());
        let _drain = complete.into_drain();
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn cross_session_socket_is_rejected_and_all_owners_remain_containable()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("cross-session-socket")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        let ready_marker = sandbox.path().join("app-ready");
        test_cooperative_app_executable(&installed, &ready_marker)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let runtime_parent = ShortRuntimeParent::new()?;
        let expected = PrivateRuntime::create(runtime_parent.path())?.reserve_app_socket()?;
        let substituted = PrivateRuntime::create(runtime_parent.path())?.reserve_app_socket()?;
        let substituted_path = substituted.path().to_path_buf();
        let app = build
            .app_server_command_for_reservation(&expected, deadline())?
            .launch(deadline())?;
        let (app, expected) = wait_for_test_app_ready_with_owner(app, expected, &ready_marker)?;
        let empty_forbidden = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        let (app, expected, descriptor_isolation) =
            verify_test_app_descriptor_isolation_with_owner(app, expected, &empty_forbidden)?;
        let listener = match UnixListener::bind(substituted.path()) {
            Ok(listener) => listener,
            Err(error) => {
                cleanup_test_unadopted_app(app, expected)?;
                build.cleanup(deadline())?;
                return Err(error.into());
            }
        };
        if let Err(error) =
            fs::set_permissions(substituted.path(), fs::Permissions::from_mode(0o600))
        {
            drop(listener);
            cleanup_test_unadopted_app(app, expected)?;
            build.cleanup(deadline())?;
            return Err(error.into());
        }

        let failure = match app.adopt_socket(substituted, descriptor_isolation, deadline()) {
            Err(failure) => failure,
            Ok(session) => {
                drop(listener);
                cleanup_test_app_session(session)?;
                let runtime = expected.release_if_absent()?;
                let _ = runtime.cleanup().map_err(|failure| failure.error())?;
                build.cleanup(deadline())?;
                return Err("another session's socket reservation was accepted".into());
            }
        };
        assert_eq!(failure.error(), AppServerTopologyError::CrossSessionSocket);
        let in_use = build
            .cleanup(deadline())
            .err()
            .ok_or("adoption failure released the running App child lease")?;
        let build = (*in_use).into_build();

        let contained = (*failure).contain_child(Duration::from_secs(1), Duration::from_secs(1));
        let contained = match contained {
            Ok(contained) => contained,
            Err(failure) => retry_test_app_adoption_containment_failure(*failure)?,
        };
        let teardown = contained
            .cleanup_socket(deadline())
            .err()
            .ok_or("another session's reservation was cleaned by this App child")?;
        assert_eq!(
            teardown.error,
            AppServerTeardownError::Socket(AppSocketError::IdentityMismatch)
        );
        assert!(substituted_path.exists());
        let (drain, substituted, runtime_guard) = teardown
            .into_reservation_for_test()
            .map_err(|failure| format!("cross-session teardown lost reservation: {failure:?}"))?;
        drop(listener);
        fs::remove_file(&substituted_path)?;
        let runtime = substituted.release_if_absent()?;
        let _ = runtime.cleanup().map_err(|failure| failure.error())?;
        drop((drain, runtime_guard));
        let runtime = expected.release_if_absent()?;
        let _ = runtime.cleanup().map_err(|failure| failure.error())?;
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn app_launch_rejects_replacement_before_its_final_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("app-final-validation")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let capability = TestCompatibilityCapability::capture(&installed)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            capability,
            &stage_parent,
        )?;
        let staged = build.executable_path_for_test().to_path_buf();
        let socket = VerifiedProviderSocketAddress::for_test(Path::new("/tmp/cf-final-app.sock"))?;
        let plan = build.app_server_command(&socket, deadline())?;

        let original = staged.with_extension("verified-original");
        fs::rename(&staged, &original)?;
        test_executable(&staged, b"#!/bin/sh\nexit 97\n")?;

        let failure = plan
            .launch(deadline())
            .err()
            .ok_or("replacement bytes crossed the final App Server validation")?;
        assert_eq!(
            failure.error(),
            AppServerLaunchError::Provider(ProviderLaunchError::ExecutableChanged)
        );
        assert!(!failure.has_spawn_failure());
        let in_use = build
            .cleanup(deadline())
            .err()
            .ok_or("unresolved launch failure released the session lifetime")?;
        assert_eq!(in_use.error(), ProviderLaunchError::SessionInUse);
        let build = (*in_use).into_build();
        let resolution = failure
            .resolve(deadline())
            .map_err(|_| "provider-only launch failure did not resolve")?;
        drop(resolution);
        let cleanup = build
            .cleanup(deadline())
            .err()
            .ok_or("ambiguous replacement was cleaned")?;
        assert_eq!(cleanup.error(), ProviderLaunchError::ExecutableChanged);
        drop(cleanup);
        Ok(())
    }

    #[test]
    fn bound_app_reservation_never_becomes_pre_spawn_cleanup_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("bound-reservation-launch-rejection")?;

        for socket_is_ready in [false, true] {
            let case = if socket_is_ready { "ready" } else { "absent" };
            let installed = sandbox.path().join(format!("installed-codex-{case}"));
            let owner_stage = sandbox.path().join(format!("owner-stage-{case}"));
            let rejected_stage = sandbox.path().join(format!("rejected-stage-{case}"));
            fs::create_dir(&owner_stage)?;
            fs::create_dir(&rejected_stage)?;
            fs::set_permissions(&owner_stage, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&rejected_stage, fs::Permissions::from_mode(0o700))?;
            let ready_marker = sandbox.path().join(format!("app-ready-{case}"));
            test_cooperative_app_executable(&installed, &ready_marker)?;

            let owner_build = PinnedSessionBuild::from_test_capability(
                test_launch_authorization(&owner_stage, &owner_stage, THREAD_ID)?,
                TestCompatibilityCapability::capture(&installed)?,
                &owner_stage,
            )?;
            let rejected_build = PinnedSessionBuild::from_test_capability(
                test_launch_authorization(&rejected_stage, &rejected_stage, THREAD_ID)?,
                TestCompatibilityCapability::capture(&installed)?,
                &rejected_stage,
            )?;
            let runtime_parent = ShortRuntimeParent::new()?;
            let reservation =
                PrivateRuntime::create(runtime_parent.path())?.reserve_app_socket()?;
            let socket_path = reservation.path().to_path_buf();
            let runtime_path = socket_path
                .parent()
                .ok_or("App socket must have a runtime parent")?
                .to_path_buf();

            let (app, reservation) = owner_build
                .app_server_command_for_reservation(&reservation, deadline())?
                .launch_with_reservation(reservation, deadline())?;
            let (app, reservation) =
                wait_for_test_app_ready_with_owner(app, reservation, &ready_marker)?;
            let containment = app.containment();
            let listener = if socket_is_ready {
                let listener = UnixListener::bind(&socket_path)?;
                fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
                Some(listener)
            } else {
                None
            };
            let expected_socket_presence = socket_path.exists();

            let failure = rejected_build
                .app_server_command_for_reservation(&reservation, deadline())?
                .launch_with_reservation(reservation, deadline())
                .err()
                .ok_or("a reservation already bound to child A launched child B")?;
            assert_eq!(
                failure.error(),
                AppServerLaunchError::Provider(ProviderLaunchError::InvalidArgument)
            );
            let app_pid = rustix::process::Pid::from_raw(containment.pid())
                .ok_or("invalid owning App PID")?;
            assert_eq!(rustix::process::getpgid(Some(app_pid))?, app_pid);

            let failure = failure
                .contain_child(deadline())
                .err()
                .ok_or("bound reservation minted child-containment cleanup authority")?;
            assert_eq!(socket_path.exists(), expected_socket_presence);
            assert!(runtime_path.exists());
            assert_eq!(rustix::process::getpgid(Some(app_pid))?, app_pid);
            let failure = failure
                .resolve(deadline())
                .err()
                .ok_or("bound reservation resolved as a pre-spawn launch failure")?;
            assert_eq!(socket_path.exists(), expected_socket_presence);
            assert!(runtime_path.exists());
            assert_eq!(rustix::process::getpgid(Some(app_pid))?, app_pid);

            // Recover the exact linear owners only inside this module's test.
            // Production has no projection from this fail-closed state to a
            // namespace-cleanup capability.
            let AppServerLaunchReservationFailure { phase, .. } = *failure;
            let AppServerLaunchReservationPhase::Launch {
                failure,
                reservation,
            } = phase
            else {
                return Err("bound launch rejection changed cleanup phase".into());
            };
            let AppServerLaunchFailure { failure, lifetime } = failure;
            if !matches!(failure, AppServerLaunchFailureKind::BoundReservation) {
                return Err("bound launch rejection changed failure class".into());
            }
            drop(lifetime);

            let adoption_failure = AppServerSocketAdoptionFailure {
                child: app,
                socket: AppServerSocketAuthority::Reservation(reservation),
                error: AppServerTopologyError::Socket(AppSocketError::IdentityMismatch),
            };
            let contained =
                adoption_failure.contain_child(Duration::from_secs(1), Duration::from_secs(1));
            let contained = match contained {
                Ok(contained) => contained,
                Err(failure) => retry_test_app_adoption_containment_failure(*failure)?,
            };
            drop(listener);
            let complete = contained.cleanup_socket(deadline())?;
            assert!(!socket_path.exists());
            assert!(!runtime_path.exists());
            let _drain = complete.into_drain();
            wait_for_test_process_and_group_absent(app_pid, deadline())?;
            owner_build.cleanup(deadline())?;
            rejected_build.cleanup(deadline())?;
        }

        Ok(())
    }

    #[test]
    fn app_launch_failure_resolves_a_residual_reserved_socket_and_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("app-launch-residual-socket")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let runtime_parent = ShortRuntimeParent::new()?;
        let runtime = PrivateRuntime::create(runtime_parent.path())?;
        let runtime_path = runtime.path().to_path_buf();
        let (reservation, route) = runtime.reserve_supervised_layout()?.into_parts();
        drop(route);
        let socket_path = reservation.path().to_path_buf();
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let launch = AppServerLaunchFailure {
            failure: AppServerLaunchFailureKind::Provider(ProviderLaunchError::SessionChanged),
            lifetime: Arc::clone(&build.lifetime),
        };
        let failure = Box::new(AppServerLaunchReservationFailure::new(launch, reservation));
        fn assert_static<T: 'static>(_: &T) {}
        assert_static(&failure);

        let contained = failure
            .contain_child(deadline())
            .map_err(|failure| format!("provider-only child containment failed: {failure:?}"))?;
        assert_eq!(
            contained.error(),
            AppServerLaunchError::Provider(ProviderLaunchError::SessionChanged)
        );
        assert_eq!(contained.cleanup_error(), None);
        assert!(
            socket_path.exists(),
            "child containment must defer socket namespace mutation"
        );
        assert!(
            runtime_path.exists(),
            "child containment must retain the exact runtime owner"
        );
        let failure = contained
            .cleanup_runtime(Instant::now())
            .err()
            .ok_or("expired namespace cleanup unexpectedly resolved")?;
        assert_eq!(
            failure.error(),
            AppServerLaunchError::Provider(ProviderLaunchError::SessionChanged)
        );
        assert_eq!(
            failure.cleanup_error(),
            Some(AppServerTeardownError::Socket(AppSocketError::Timeout))
        );
        assert!(socket_path.exists());
        assert!(runtime_path.exists());
        let in_use = build
            .cleanup(deadline())
            .err()
            .ok_or("launch cleanup failure released its guardian session guard")?;
        let build = (*in_use).into_build();

        let resolution = failure
            .resolve(deadline())
            .map_err(|failure| format!("residual socket cleanup did not resolve: {failure:?}"))?;
        assert_eq!(
            resolution.error(),
            AppServerLaunchError::Provider(ProviderLaunchError::SessionChanged)
        );
        assert_eq!(
            resolution.cleanup_error(),
            Some(AppServerTeardownError::Socket(AppSocketError::Timeout))
        );
        assert_eq!(
            resolution.release(),
            AppServerLaunchError::Provider(ProviderLaunchError::SessionChanged)
        );
        assert!(!socket_path.exists());
        assert!(!runtime_path.exists());
        drop(listener);
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn started_unannounced_app_launch_retries_without_signal_or_namespace_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("app-launch-started-unannounced")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let runtime_parent = ShortRuntimeParent::new()?;
        let runtime = PrivateRuntime::create(runtime_parent.path())?;
        let runtime_path = runtime.path().to_path_buf();
        let (reservation, route) = runtime.reserve_supervised_layout()?.into_parts();
        drop(route);
        let socket_path = reservation.path().to_path_buf();
        fs::write(&socket_path, b"must-remain-owned")?;

        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("30");
        let (spawn, containment) = SpawnFailure::live_unannounced_app_for_test(command)?;
        let launch = AppServerLaunchFailure {
            failure: AppServerLaunchFailureKind::Spawn(spawn),
            lifetime: Arc::clone(&build.lifetime),
        };
        let failure = Box::new(AppServerLaunchReservationFailure::new(launch, reservation));

        let in_use = build
            .cleanup(deadline())
            .err()
            .ok_or("started-unannounced App released its session lifetime")?;
        let build = (*in_use).into_build();
        let failure = failure
            .contain_child(deadline())
            .err()
            .ok_or("started-unannounced App minted pre-spawn containment proof")?;
        assert_eq!(fs::read(&socket_path)?, b"must-remain-owned");
        assert!(runtime_path.exists());
        let pid = rustix::process::Pid::from_raw(containment.pid())
            .ok_or("invalid started-unannounced App PID")?;
        assert_eq!(rustix::process::getpgid(Some(pid))?, pid);

        let failure = failure
            .contain_child(deadline())
            .err()
            .ok_or("retry minted started-unannounced App containment proof")?;
        assert_eq!(fs::read(&socket_path)?, b"must-remain-owned");
        assert!(runtime_path.exists());
        assert_eq!(rustix::process::getpgid(Some(pid))?, pid);

        // Recover only the synthetic test child through lower-level test
        // authority. Production never converts this App state with KILL/reap.
        let AppServerLaunchReservationFailure { phase, .. } = *failure;
        let AppServerLaunchReservationPhase::Launch {
            failure,
            reservation,
        } = phase
        else {
            return Err("started-unannounced retry mutated the namespace phase".into());
        };
        let AppServerLaunchFailure { failure, lifetime } = failure;
        let AppServerLaunchFailureKind::Spawn(spawn) = failure else {
            return Err("started-unannounced spawn changed failure class".into());
        };
        let cleanup =
            spawn
                .cleanup(deadline())
                .map_err(|failure| -> Box<dyn std::error::Error> {
                    format!("synthetic started child cleanup failed: {failure}").into()
                })?;
        assert!(cleanup.started_unannounced());
        drop(lifetime);
        fs::remove_file(&socket_path)?;
        let runtime = reservation.release_if_absent()?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn root_sync_failure_is_storage_and_preserves_staged_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("root-sync-failure")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;

        let capability = TestCompatibilityCapability::capture(&installed)?;
        let failure = match capability.pin_in_with_root_sync_failure(&stage_parent) {
            Ok(_) => panic!("a root sync failure must not mint a capability"),
            Err(failure) => failure,
        };

        assert_eq!(
            ProviderLaunchError::from(failure.error()),
            ProviderLaunchError::Storage
        );
        let roots = fs::read_dir(&stage_parent)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(roots.len(), 1);
        assert_eq!(failure.retained_path(), Some(roots[0].path().as_path()));
        drop(failure);
        Ok(())
    }

    #[test]
    fn parent_sync_failure_is_storage_and_preserves_created_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("parent-sync-failure")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;

        let capability = TestCompatibilityCapability::capture(&installed)?;
        let failure = match capability.pin_in_with_parent_sync_failure(&stage_parent) {
            Ok(_) => panic!("a parent sync failure must not mint a capability"),
            Err(failure) => failure,
        };

        assert_eq!(
            ProviderLaunchError::from(failure.error()),
            ProviderLaunchError::Storage
        );
        let roots = fs::read_dir(&stage_parent)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(roots.len(), 1);
        assert_eq!(failure.retained_path(), Some(roots[0].path().as_path()));
        assert_eq!(fs::read_dir(roots[0].path())?.count(), 0);
        drop(failure);
        Ok(())
    }

    #[test]
    fn borrowed_plans_revalidate_the_exact_build_at_launch_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("plan-revalidation")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        let home = sandbox.path().join("home");
        let workspace = sandbox.path().join("workspace");
        for directory in [&stage_parent, &home, &workspace] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let capability = TestCompatibilityCapability::capture(&installed)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&home, &workspace, THREAD_ID)?,
            capability,
            &stage_parent,
        )?;
        let staged = build.executable_path_for_test().to_path_buf();
        let app_socket =
            VerifiedProviderSocketAddress::for_test(Path::new("/tmp/cf-plan-app.sock"))?;
        let relay_socket =
            VerifiedProviderSocketAddress::for_test(Path::new("/tmp/cf-plan-relay.sock"))?;
        let app = build.app_server_command(&app_socket, deadline())?;
        let tui = build.remote_tui_command(&relay_socket, deadline())?;

        let moved = staged.with_extension("verified-original");
        fs::rename(&staged, &moved)?;
        test_executable(&staged, b"#!/bin/sh\nexit 82\n")?;

        assert_eq!(
            app.revalidate_for_launch(deadline()),
            Err(ProviderLaunchError::ExecutableChanged)
        );
        assert_eq!(
            tui.revalidate_for_launch(deadline()),
            Err(ProviderLaunchError::ExecutableChanged)
        );

        // Each plan borrows `build`, so moving it into cleanup is impossible
        // until all plans have been dropped.
        drop((app, tui));
        let failure = match build.cleanup(deadline()) {
            Err(failure) => failure,
            Ok(_) => return Err("a replaced staged path was cleaned".into()),
        };
        assert_eq!(failure.error(), ProviderLaunchError::ExecutableChanged);
        drop(failure);
        assert!(staged.exists());
        assert!(moved.exists());
        Ok(())
    }

    #[cfg(feature = "internal-supervisor-fixture")]
    #[test]
    fn remote_tui_bridge_revalidates_the_stage_before_the_relay_deadline_is_armed()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("tui-bridge-final-validation")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        let home = sandbox.path().join("home");
        let workspace = sandbox.path().join("workspace");
        for directory in [&stage_parent, &home, &workspace] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&home, &workspace, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let staged = build.executable_path_for_test().to_path_buf();
        let relay_socket =
            VerifiedProviderSocketAddress::for_test(Path::new("/tmp/cf-final-tui.sock"))?;
        let launcher = build
            .remote_tui_command(&relay_socket, deadline())?
            .into_launch_command(deadline())?;

        let original = staged.with_extension("verified-original");
        fs::rename(&staged, &original)?;
        test_executable(&staged, b"#!/bin/sh\nexit 82\n")?;

        let launch_failure = launcher
            .prepare(deadline())
            .err()
            .ok_or("a bridge-to-prepare executable replacement was accepted")?;
        assert_eq!(
            launch_failure.error(),
            super::super::launcher::RemoteTuiLauncherError::Provider(
                ProviderLaunchError::ExecutableChanged,
            )
        );

        let in_use = build
            .cleanup(deadline())
            .err()
            .ok_or("the unresolved launch failure released its runtime guard")?;
        assert_eq!(in_use.error(), ProviderLaunchError::SessionInUse);
        let build = (*in_use).into_build();

        let resolution = launch_failure
            .resolve(deadline())
            .map_err(|failure| format!("pre-spawn failure did not resolve: {failure:?}"))?;
        assert!(!resolution.started_child_for_test());
        drop(resolution);

        let changed = build
            .cleanup(deadline())
            .err()
            .ok_or("the replaced executable was accepted after runtime release")?;
        assert_eq!(changed.error(), ProviderLaunchError::ExecutableChanged);
        drop(changed);
        assert!(staged.exists());
        assert!(original.exists());
        Ok(())
    }

    #[cfg(feature = "internal-supervisor-fixture")]
    #[test]
    fn prepared_remote_tui_rejects_stage_replacement_before_spawning_a_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("prepared-tui-spawn-identity")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        let home = sandbox.path().join("home");
        let workspace = sandbox.path().join("workspace");
        for directory in [&stage_parent, &home, &workspace] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&home, &workspace, THREAD_ID)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?;
        let staged = build.executable_path_for_test().to_path_buf();
        let relay_socket =
            VerifiedProviderSocketAddress::for_test(Path::new("/tmp/cf-prepared-tui.sock"))?;
        let launcher = build
            .remote_tui_command(&relay_socket, deadline())?
            .into_launch_command(deadline())?;
        let prepared = match launcher.prepare(deadline()) {
            Ok(prepared) => prepared,
            Err(failure) => {
                return Err(format!("valid TUI preparation failed: {:?}", failure.error()).into());
            }
        };

        let original = staged.with_extension("verified-original");
        fs::rename(&staged, &original)?;
        test_executable(&staged, b"#!/bin/sh\nexit 82\n")?;

        let pty = super::super::terminal::PtyOwner::open(
            super::super::terminal::TerminalSize::new(24, 80),
        )?;
        let launch_failure = prepared
            .launch(pty, deadline())
            .err()
            .ok_or("a post-prepare executable replacement started a child")?;
        assert_eq!(
            launch_failure.error(),
            super::super::launcher::RemoteTuiLauncherError::Provider(
                ProviderLaunchError::ExecutableChanged,
            )
        );
        assert_eq!(
            launch_failure.packaged_classification().state_marker(),
            "startup-failure.tui-launch.state.before-spawn"
        );

        let in_use = build
            .cleanup(deadline())
            .err()
            .ok_or("the unresolved spawn-boundary failure released its runtime guard")?;
        assert_eq!(in_use.error(), ProviderLaunchError::SessionInUse);
        let build = (*in_use).into_build();
        let resolution = launch_failure
            .resolve(deadline())
            .map_err(|failure| format!("spawn-boundary failure did not resolve: {failure:?}"))?;
        assert!(!resolution.started_child_for_test());
        drop(resolution);

        let changed = build
            .cleanup(deadline())
            .err()
            .ok_or("the replaced executable was accepted after runtime release")?;
        assert_eq!(changed.error(), ProviderLaunchError::ExecutableChanged);
        drop(changed);
        assert!(staged.exists());
        assert!(original.exists());
        Ok(())
    }

    #[test]
    fn borrowed_plan_rejects_workspace_path_replacement() -> Result<(), Box<dyn std::error::Error>>
    {
        let sandbox = Sandbox::new("workspace-revalidation")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        let home = sandbox.path().join("home");
        let workspace = sandbox.path().join("workspace");
        for directory in [&stage_parent, &home, &workspace] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let capability = TestCompatibilityCapability::capture(&installed)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&home, &workspace, THREAD_ID)?,
            capability,
            &stage_parent,
        )?;
        let socket = VerifiedProviderSocketAddress::for_test(Path::new("/tmp/cf-workspace.sock"))?;
        let app = build.app_server_command(&socket, deadline())?;

        let original_workspace = workspace.with_extension("verified-original");
        fs::rename(&workspace, &original_workspace)?;
        fs::create_dir(&workspace)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;

        assert_eq!(
            app.revalidate_for_launch(deadline()),
            Err(ProviderLaunchError::SessionChanged)
        );
        drop(app);
        build.cleanup(deadline())?;
        Ok(())
    }

    #[test]
    fn explicit_cleanup_failure_is_not_retried_by_drop() -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("cleanup-no-retry")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let capability = TestCompatibilityCapability::capture(&installed)?;
        let mut build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            capability,
            &stage_parent,
        )?;
        let staged = build.executable_path_for_test().to_path_buf();
        let staged_directory = build.runtime_path_for_test().to_path_buf();
        build.fail_next_cleanup_for_test();

        let failure = match build.cleanup(deadline()) {
            Err(failure) => failure,
            Ok(_) => return Err("the injected first cleanup attempt succeeded".into()),
        };

        assert_eq!(failure.error(), ProviderLaunchError::Storage);
        drop(failure);
        assert!(
            staged.exists(),
            "Drop must not retry the staged file removal"
        );
        assert!(
            staged_directory.exists(),
            "Drop must preserve the staged directory after an explicit failure"
        );
        Ok(())
    }

    #[test]
    fn cleanup_failure_returns_a_retryable_build_owner() -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("cleanup-retry-owner")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let capability = TestCompatibilityCapability::capture(&installed)?;
        let mut build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            capability,
            &stage_parent,
        )?;
        let staged = build.executable_path_for_test().to_path_buf();
        let staged_directory = build.runtime_path_for_test().to_path_buf();
        build.fail_next_cleanup_for_test();

        let failure = match build.cleanup(deadline()) {
            Err(failure) => failure,
            Ok(_) => return Err("the injected first cleanup attempt succeeded".into()),
        };
        assert_eq!(failure.error(), ProviderLaunchError::Storage);
        assert!(staged.exists());

        let retryable_build = (*failure).into_build();
        retryable_build.cleanup(deadline())?;
        assert!(!staged.exists());
        assert!(!staged_directory.exists());
        Ok(())
    }

    #[test]
    fn cleanup_retries_from_every_durable_mutation_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("cleanup-phases")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;

        for fault in [
            PinnedStageCleanupFault::AfterExecutableRemove,
            PinnedStageCleanupFault::AfterDirectorySync,
            PinnedStageCleanupFault::AfterDirectoryRemove,
            PinnedStageCleanupFault::AfterRootSync,
            PinnedStageCleanupFault::AfterRootRemove,
        ] {
            let capability = TestCompatibilityCapability::capture(&installed)?;
            let mut build = PinnedSessionBuild::from_test_capability(
                test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
                capability,
                &stage_parent,
            )?;
            let staged_directory = build.runtime_path_for_test().to_path_buf();
            build.fail_cleanup_at_for_test(fault);

            let failure = build
                .cleanup(deadline())
                .err()
                .ok_or("the selected mutation-boundary fault must interrupt cleanup")?;
            assert_eq!(failure.error(), ProviderLaunchError::Storage);
            let build = (*failure).into_build();
            build.cleanup(deadline())?;
            assert!(
                !staged_directory.exists(),
                "retry did not finish cleanup after {fault:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn cleanup_timeout_returns_the_unchanged_build_owner() -> Result<(), Box<dyn std::error::Error>>
    {
        let sandbox = Sandbox::new("cleanup-timeout-owner")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let capability = TestCompatibilityCapability::capture(&installed)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            capability,
            &stage_parent,
        )?;
        let staged = build.executable_path_for_test().to_path_buf();

        let failure = match build.cleanup(Instant::now()) {
            Err(failure) => failure,
            Ok(_) => return Err("an expired cleanup deadline minted completion".into()),
        };
        assert_eq!(failure.error(), ProviderLaunchError::Timeout);
        let retained_build = (*failure).into_build();
        assert!(staged.exists());
        drop(retained_build);
        assert!(staged.exists(), "Drop must not run an unbounded cleanup");
        Ok(())
    }

    #[test]
    fn staged_path_replacement_is_preserved_and_reported_during_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new("stage-replacement")?;
        let installed = sandbox.path().join("installed-codex");
        let stage_parent = sandbox.path().join("stage-parent");
        fs::create_dir(&stage_parent)?;
        fs::set_permissions(&stage_parent, fs::Permissions::from_mode(0o700))?;
        test_executable(&installed, b"#!/bin/sh\nexit 0\n")?;
        let capability = TestCompatibilityCapability::capture(&installed)?;
        let build = PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&stage_parent, &stage_parent, THREAD_ID)?,
            capability,
            &stage_parent,
        )?;
        let staged = build.executable_path_for_test().to_path_buf();
        let moved = staged.with_extension("verified-original");
        fs::rename(&staged, &moved)?;
        test_executable(&staged, b"#!/bin/sh\nexit 93\n")?;

        let failure = match build.cleanup(deadline()) {
            Err(failure) => failure,
            Ok(_) => return Err("ambiguous staged identity was removed".into()),
        };
        assert_eq!(failure.error(), ProviderLaunchError::ExecutableChanged);
        drop(failure);
        assert_eq!(fs::read(&staged)?, b"#!/bin/sh\nexit 93\n");
        assert_eq!(fs::read(&moved)?, b"#!/bin/sh\nexit 0\n");
        Ok(())
    }
}
