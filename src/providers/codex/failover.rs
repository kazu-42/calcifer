//! Public, bounded Codex failover orchestration.
//!
//! The shell-facing process owns one invocation-wide pool traversal. Each
//! provider generation still runs through the reviewed production supervisor;
//! this layer acts only after that exact tree has stopped and returned the
//! typed usage-exhaustion status.

#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::path::Path;
use std::process::ExitStatus;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use super::handoff_transaction::{
    ForkCandidate, HandoffExecutionError, HandoffRuntime, HandoffStep, prepare_codex_handoff,
    resume_handoff_once,
};
use super::remote::EffectiveThreadSettings;
use super::rollout_handoff::{
    CodexRolloutHandoff, ValidatedForkRollout, VerifiedSourceRollout, mint_profile_rollout_handoff,
    validate_handoff_fork_result, validate_handoff_inventory_candidate,
};
use super::selection_runtime::CodexSelectionRuntime;
use super::{
    APP_SERVER_CLIENT_NAME, AppServerProcess, CodexThreadRead, INITIALIZE_REQUEST_ID,
    MAX_THREAD_PAGES_PER_STATE, THREAD_PAGE_SIZE, read_account_usage, read_handoff_thread,
    validate_canonical_uuid, validate_initialize_result, verify_codex_identity_adapter,
};
use crate::conversations::{ConversationRegistry, HandoffTransition, HeadBinding};
use crate::profiles::{Profile, ProfileError, Provider, Registry, VerifiedTargetReservation};
use crate::provider_identity::IdentityError;
use crate::routing::selection::{
    HandoffSelection, SelectionError, SelectionOutcome, SelectionStop, SelectionTrigger,
    select_once,
};
use crate::routing::{DefinitionError, Definitions, EnabledPool, RoutingError};
use crate::usage_observations::{ObservationError, ObservationSource, ObservationStore};

const PROVIDER_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const APP_SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HANDOFF_STEPS: usize = 8;
const USAGE_EXHAUSTED_EXIT_CODE: i32 = 75;

#[cfg(feature = "internal-failover-scorecard")]
mod scorecard;

#[derive(Debug)]
pub(crate) enum CodexFailoverError {
    Conversation(crate::conversations::ConversationError),
    Definition(DefinitionError),
    Handoff,
    Observation(ObservationError),
    PoolUnavailable(PoolStopKind),
    Profile(ProfileError),
    Protocol,
    Routing(RoutingError),
    Selection,
    Spawn(std::io::Error),
    Trigger,
}

impl CodexFailoverError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::Conversation(error) => error.code(),
            Self::Definition(error) => error.code(),
            Self::Handoff => "codex_handoff_failed",
            Self::Observation(_) => "usage_observation_unavailable",
            Self::PoolUnavailable(kind) => kind.code(),
            Self::Profile(error) => error.code(),
            Self::Protocol => "codex_handoff_protocol_invalid",
            Self::Routing(error) => error.code(),
            Self::Selection => "codex_failover_selection_failed",
            Self::Spawn(_) => "process_io_error",
            Self::Trigger => "codex_exhaustion_revalidation_failed",
        }
    }

    pub(crate) fn safe_message(&self) -> &'static str {
        match self {
            Self::Conversation(error) => error.safe_message(),
            Self::Definition(error) => error.safe_message(),
            Self::Handoff => {
                "The cross-profile Codex handoff could not be completed safely. The source rollout was preserved."
            }
            Self::Observation(_) => {
                "Calcifer could not persist a safe usage observation for failover. No target profile was started."
            }
            Self::PoolUnavailable(kind) => kind.safe_message(),
            Self::Profile(error) => {
                let _ = error.code();
                "A failover profile changed or is busy. No unverified profile was selected."
            }
            Self::Protocol => {
                "Codex did not satisfy the pinned cross-profile handoff protocol. The source rollout was preserved."
            }
            Self::Routing(error) => error.safe_message(),
            Self::Selection => {
                "Calcifer could not complete the guarded one-pass profile selection. No candidate was retried."
            }
            Self::Spawn(error) => {
                let _ = error.kind();
                "Calcifer could not start or wait for the supervised Codex process."
            }
            Self::Trigger => {
                "The stopped Codex generation did not revalidate as authoritatively exhausted. Automatic failover was not authorized."
            }
        }
    }
}

impl fmt::Display for CodexFailoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for CodexFailoverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Conversation(error) => Some(error),
            Self::Definition(error) => Some(error),
            Self::Observation(error) => Some(error),
            Self::Profile(error) => Some(error),
            Self::Routing(error) => Some(error),
            Self::Spawn(error) => Some(error),
            Self::Handoff
            | Self::PoolUnavailable(_)
            | Self::Protocol
            | Self::Selection
            | Self::Trigger => None,
        }
    }
}

impl From<crate::conversations::ConversationError> for CodexFailoverError {
    fn from(error: crate::conversations::ConversationError) -> Self {
        Self::Conversation(error)
    }
}

impl From<ProfileError> for CodexFailoverError {
    fn from(error: ProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RoutingError> for CodexFailoverError {
    fn from(error: RoutingError) -> Self {
        Self::Routing(error)
    }
}

impl From<ObservationError> for CodexFailoverError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

impl From<std::io::Error> for CodexFailoverError {
    fn from(error: std::io::Error) -> Self {
        Self::Spawn(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PoolStopKind {
    Exhausted,
    AllUnknown,
    Busy,
    NoEligible,
}

impl PoolStopKind {
    const fn code(self) -> &'static str {
        match self {
            Self::Exhausted => "codex_failover_pool_exhausted",
            Self::AllUnknown => "codex_failover_pool_unknown",
            Self::Busy => "codex_failover_pool_busy",
            Self::NoEligible => "codex_failover_pool_no_eligible_profile",
        }
    }

    const fn safe_message(self) -> &'static str {
        match self {
            Self::Exhausted => {
                "Every eligible profile in the selected failover pool is authoritatively exhausted."
            }
            Self::AllUnknown => {
                "Every remaining profile in the selected failover pool has unknown or stale availability."
            }
            Self::Busy => {
                "A remaining profile in the selected failover pool is busy. Calcifer stopped instead of looping."
            }
            Self::NoEligible => {
                "The selected failover pool has no unused eligible profile in this invocation."
            }
        }
    }
}

/// Runs exact supervised generations until one exits normally or the selected
/// pool reaches one of its bounded terminal outcomes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resume_supervised_with_failover(
    registry: &Registry,
    initial_profile: &Profile,
    working_directory: &Path,
    initial_thread_id: &str,
    codex_executable: &Path,
    pool_provider: Option<Provider>,
    pool_reference: &str,
) -> Result<ExitStatus, CodexFailoverError> {
    let definitions = crate::routing::storage::Store::from_profiles(registry).read()?;
    let pool_id = definitions
        .resolve_pool_id(pool_provider, pool_reference)
        .map_err(CodexFailoverError::Definition)?;
    #[cfg(feature = "internal-failover-scorecard")]
    if let Some(result) =
        scorecard::run_if_requested(registry, initial_profile, &definitions, &pool_id)
    {
        return result;
    }
    let conversations = ConversationRegistry::from_profiles(registry);
    let (mut current_profile, mut current_thread_id, mut cooldown, mut completed_status) =
        match conversations.current_handoff_context()? {
            Some((transition, source_head)) => {
                let requested = conversations
                    .find_bound_thread(&initial_profile.id, initial_thread_id, working_directory)?
                    .filter(|binding| binding.conversation_id == transition.conversation_id)
                    .ok_or(crate::conversations::ConversationError::Ambiguous)?;
                let recovered = recover_handoff(
                    registry,
                    &conversations,
                    &definitions,
                    codex_executable,
                    working_directory,
                    &pool_id,
                    transition,
                    source_head,
                )?;
                eprintln!(
                    "Calcifer: recovered and attached failover generation {} under {}.",
                    recovered.generation,
                    recovered.profile.reference()
                );
                let cooldown = conversations.conversation_profile_ids_from_generation(
                    &recovered.conversation_id,
                    requested.generation,
                )?;
                (
                    recovered.profile,
                    recovered.thread_id,
                    cooldown,
                    Some(recovered.status),
                )
            }
            None => {
                let initial_head = conversations.resolve_head(working_directory)?;
                require_exact_head(
                    &initial_head,
                    initial_profile,
                    initial_thread_id,
                    working_directory,
                )?;
                let cooldown = conversations.conversation_profile_ids_from_generation(
                    &initial_head.conversation_id,
                    initial_head.generation,
                )?;
                (
                    initial_profile.clone(),
                    initial_thread_id.to_owned(),
                    cooldown,
                    None,
                )
            }
        };

    loop {
        let status = match completed_status.take() {
            Some(status) => status,
            None => spawn_supervised_generation(
                registry,
                &current_profile,
                working_directory,
                &current_thread_id,
                codex_executable,
            )?,
        };
        if status.code() != Some(USAGE_EXHAUSTED_EXIT_CODE) {
            return Ok(status);
        }

        let signal_observed_at = unix_timestamp()?;
        let source_lease = registry.lock_profile(&current_profile)?;
        let current = registry.refetch_by_id_under_lease(Provider::Codex, &current_profile.id)?;
        if current != current_profile {
            return Err(CodexFailoverError::Profile(ProfileError::UnsafeState(
                "failover source changed after supervised shutdown".to_owned(),
            )));
        }
        let head = conversations.resolve_head(working_directory)?;
        require_exact_head(&head, &current, &current_thread_id, working_directory)?;

        let observations = ObservationStore::from_profiles(registry);
        observations.require_revalidation(&current.id, signal_observed_at)?;
        let home = registry.profile_home(&current)?;
        let neutral_working_directory = registry.neutral_working_directory()?;
        let provider_lease = source_lease.provider_lock_for_probe()?;
        let usage = read_account_usage(
            codex_executable,
            &home,
            &neutral_working_directory,
            PROVIDER_OPERATION_TIMEOUT,
            provider_lease,
        )
        .map_err(|_| CodexFailoverError::Trigger)?;
        let observed_at = unix_timestamp()?;
        let usage_view = observations.observe_usage(
            &current.id,
            ObservationSource::IdleRead,
            &usage.codex_version,
            usage.usage,
            observed_at,
        )?;
        let trigger =
            SelectionTrigger::revalidated_usage_limit(&current.id, signal_observed_at, &usage_view)
                .map_err(|_| CodexFailoverError::Trigger)?;
        // Activation and membership are user-level security policy. Refresh
        // the immutable-ID pool snapshot after every potentially long-running
        // provider generation so a concurrent disable takes effect before any
        // rollout is exposed to a target profile.
        let current_definitions = crate::routing::storage::Store::from_profiles(registry).read()?;
        let pool = current_definitions
            .enabled_pool_for_source(&pool_id, &current.id, Provider::Codex)
            .map_err(CodexFailoverError::Definition)?;

        let source_read = read_handoff_thread(
            codex_executable,
            &home,
            &neutral_working_directory,
            working_directory,
            &current_thread_id,
            PROVIDER_OPERATION_TIMEOUT,
            source_lease.provider_lock_for_probe()?,
        )
        .map_err(|_| CodexFailoverError::Protocol)?;
        if source_read.thread.codex_version != head.codex_version {
            return Err(CodexFailoverError::Protocol);
        }
        let source_rollout = mint_profile_rollout_handoff(registry, &current, &source_read.thread)
            .map_err(|_| CodexFailoverError::Protocol)?;
        let source_thread = source_read.thread;

        let mut attached_status = None;
        let mut attached_profile = None;
        let mut attached_thread = None;
        let mut source_rollout = Some(source_rollout);
        let mut source_thread = Some(source_thread);
        let source_settings = source_read.settings;
        let mut selection_runtime = CodexSelectionRuntime::new(
            registry,
            codex_executable,
            &neutral_working_directory,
            |selection| {
                let rollout = source_rollout.take().ok_or(CodexFailoverError::Handoff)?;
                let thread = source_thread.take().ok_or(CodexFailoverError::Handoff)?;
                let result = execute_handoff(
                    registry,
                    &conversations,
                    &current_definitions,
                    codex_executable,
                    &neutral_working_directory,
                    working_directory,
                    &head,
                    rollout,
                    thread,
                    source_settings.clone(),
                    selection,
                )?;
                attached_status = Some(result.status);
                attached_profile = Some(result.profile);
                attached_thread = Some(result.thread_id);
                Ok::<u64, CodexFailoverError>(result.generation)
            },
        );
        let outcome = select_once(
            &current_definitions,
            &pool,
            &current,
            trigger,
            &cooldown,
            &mut selection_runtime,
        )
        .map_err(map_selection_error)?;
        drop(selection_runtime);
        drop(source_lease);

        match outcome {
            SelectionOutcome::Selected(_) => {
                let profile = attached_profile.take().ok_or(CodexFailoverError::Handoff)?;
                let thread_id = attached_thread.take().ok_or(CodexFailoverError::Handoff)?;
                let status = attached_status.take().ok_or(CodexFailoverError::Handoff)?;
                cooldown.insert(profile.id.clone());
                current_profile = profile;
                current_thread_id = thread_id;
                if status.code() != Some(USAGE_EXHAUSTED_EXIT_CODE) {
                    return Ok(status);
                }
                // The target generation already ran while the durable attach
                // step owned the terminal. Revalidate that exact completion;
                // never launch the exhausted target a second time.
                completed_status = Some(status);
            }
            SelectionOutcome::Exhausted(stop) => {
                report_pool_stop(&stop);
                return Err(CodexFailoverError::PoolUnavailable(PoolStopKind::Exhausted));
            }
            SelectionOutcome::AllUnknown(stop) => {
                report_pool_stop(&stop);
                return Err(CodexFailoverError::PoolUnavailable(
                    PoolStopKind::AllUnknown,
                ));
            }
            SelectionOutcome::Busy(stop) => {
                report_pool_stop(&stop);
                return Err(CodexFailoverError::PoolUnavailable(PoolStopKind::Busy));
            }
            SelectionOutcome::NoEligible(stop) => {
                report_pool_stop(&stop);
                return Err(CodexFailoverError::PoolUnavailable(
                    PoolStopKind::NoEligible,
                ));
            }
        }
    }
}

fn report_pool_stop(stop: &SelectionStop) {
    eprintln!(
        "Calcifer: pool {} stopped after one pass (exhausted={}, unknown={}, busy={}, cooldown={}).",
        stop.pool, stop.exhausted, stop.unknown, stop.busy, stop.cooldown
    );
}

fn require_exact_head(
    head: &HeadBinding,
    profile: &Profile,
    thread_id: &str,
    working_directory: &Path,
) -> Result<(), CodexFailoverError> {
    if head.profile_id != profile.id
        || head.thread_id != thread_id
        || head.canonical_cwd != working_directory.to_string_lossy()
    {
        return Err(CodexFailoverError::Conversation(
            crate::conversations::ConversationError::Ambiguous,
        ));
    }
    Ok(())
}

fn map_selection_error<RuntimeError>(error: SelectionError<RuntimeError>) -> CodexFailoverError {
    match error {
        SelectionError::Policy(error) => CodexFailoverError::Definition(error),
        SelectionError::Runtime(_) | SelectionError::RuntimeInvariant => {
            CodexFailoverError::Selection
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn recover_handoff(
    registry: &Registry,
    conversations: &ConversationRegistry,
    definitions: &Definitions,
    codex_executable: &Path,
    working_directory: &Path,
    pool_id: &str,
    transition: HandoffTransition,
    source_head: HeadBinding,
) -> Result<HandoffResult, CodexFailoverError> {
    if source_head.conversation_id != transition.conversation_id
        || source_head.generation != transition.source_generation
        || source_head.profile_id != transition.source_profile_id
        || source_head.canonical_cwd != transition.canonical_cwd
        || working_directory.to_str() != Some(transition.canonical_cwd.as_str())
    {
        return Err(CodexFailoverError::Conversation(
            crate::conversations::ConversationError::Ambiguous,
        ));
    }
    let pool = definitions
        .enabled_pool_for_source(pool_id, &transition.source_profile_id, Provider::Codex)
        .map_err(CodexFailoverError::Definition)?;
    validate_recovery_pool(&pool, &transition)?;
    definitions
        .authorize_handoff(
            &transition.trust_domain_id,
            &transition.source_profile_id,
            &transition.target_profile_id,
            Provider::Codex,
        )
        .map_err(CodexFailoverError::Definition)?;

    let source_profile = registry.find_by_id(Provider::Codex, &transition.source_profile_id)?;
    let source_lease = registry.lock_profile(&source_profile)?;
    let current_source = registry.refetch_by_id_under_lease(Provider::Codex, &source_profile.id)?;
    if current_source != source_profile {
        return Err(CodexFailoverError::Profile(ProfileError::UnsafeState(
            "handoff source changed during recovery".to_owned(),
        )));
    }
    let neutral_working_directory = registry.neutral_working_directory()?;
    let source_home = registry.profile_home(&current_source)?;
    let source_read = read_handoff_thread(
        codex_executable,
        &source_home,
        &neutral_working_directory,
        working_directory,
        &source_head.thread_id,
        PROVIDER_OPERATION_TIMEOUT,
        source_lease.provider_lock_for_probe()?,
    )
    .map_err(|_| CodexFailoverError::Protocol)?;
    if source_read.thread.codex_version != source_head.codex_version {
        return Err(CodexFailoverError::Protocol);
    }
    let source_rollout =
        mint_profile_rollout_handoff(registry, &current_source, &source_read.thread)
            .map_err(|_| CodexFailoverError::Protocol)?;

    let target = registry.find_by_id(Provider::Codex, &transition.target_profile_id)?;
    let reservation = reserve_recovery_target(
        registry,
        &target,
        codex_executable,
        &neutral_working_directory,
    )?;
    let mut runtime = ProductionHandoffRuntime {
        registry,
        codex_executable,
        neutral_working_directory: &neutral_working_directory,
        working_directory,
        target: target.clone(),
        reservation: Some(reservation),
        source_profile: current_source,
        source_rollout: Some(source_rollout),
        source_thread: source_read.thread,
        source_settings: source_read.settings,
        pool_alias: pool.alias().to_owned(),
        trust_domain_alias: pool.trust_domain_alias().to_owned(),
        selection_reason: crate::routing::selection::SelectionReason::RevalidatedUsageLimit,
        verified_source: None,
        direct_target: None,
        attached_status: None,
    };
    let result = drive_handoff(conversations, &mut runtime, target)?;
    drop(source_lease);
    Ok(result)
}

fn validate_recovery_pool(
    pool: &EnabledPool,
    transition: &HandoffTransition,
) -> Result<(), CodexFailoverError> {
    if pool.trust_domain_id() != transition.trust_domain_id
        || !pool
            .profile_ids()
            .iter()
            .any(|profile_id| profile_id == &transition.target_profile_id)
    {
        return Err(CodexFailoverError::Definition(
            DefinitionError::InvalidMembership,
        ));
    }
    Ok(())
}

fn reserve_recovery_target(
    registry: &Registry,
    target: &Profile,
    codex_executable: &Path,
    neutral_working_directory: &Path,
) -> Result<VerifiedTargetReservation, CodexFailoverError> {
    registry
        .reserve_verified_codex_target(target, |home, provider_lease| {
            verify_codex_identity_adapter(
                codex_executable,
                home,
                neutral_working_directory,
                PROVIDER_OPERATION_TIMEOUT,
                provider_lease,
            )
            .map_err(|_| ProfileError::from(IdentityError::Unsupported))
        })
        .map_err(CodexFailoverError::Profile)
}

struct HandoffResult {
    conversation_id: String,
    generation: u64,
    profile: Profile,
    thread_id: String,
    status: ExitStatus,
}

#[allow(clippy::too_many_arguments)]
fn execute_handoff(
    registry: &Registry,
    conversations: &ConversationRegistry,
    definitions: &Definitions,
    codex_executable: &Path,
    neutral_working_directory: &Path,
    working_directory: &Path,
    expected_source: &HeadBinding,
    source_rollout: CodexRolloutHandoff,
    source_thread: CodexThreadRead,
    source_settings: EffectiveThreadSettings,
    selection: HandoffSelection<VerifiedTargetReservation>,
) -> Result<HandoffResult, CodexFailoverError> {
    let (source, target, authorization, pool_id, reason, _observed_at, reservation) =
        selection.into_parts();
    if source.id != expected_source.profile_id || target.id != reservation.profile().id {
        return Err(CodexFailoverError::Handoff);
    }
    prepare_codex_handoff(
        conversations,
        definitions,
        expected_source.clone(),
        &target,
        authorization.trust_domain_id(),
        reason.handoff_reason(),
        &source_rollout,
    )
    .map_err(|_| CodexFailoverError::Handoff)?;
    let pool = definitions
        .enabled_pool_for_source(&pool_id, &source.id, Provider::Codex)
        .map_err(CodexFailoverError::Definition)?;

    let mut runtime = ProductionHandoffRuntime {
        registry,
        codex_executable,
        neutral_working_directory,
        working_directory,
        target: target.clone(),
        reservation: Some(reservation),
        source_profile: source,
        source_rollout: Some(source_rollout),
        source_thread,
        source_settings,
        pool_alias: pool.alias().to_owned(),
        trust_domain_alias: pool.trust_domain_alias().to_owned(),
        selection_reason: reason,
        verified_source: None,
        direct_target: None,
        attached_status: None,
    };
    drive_handoff(conversations, &mut runtime, target)
}

fn drive_handoff(
    conversations: &ConversationRegistry,
    runtime: &mut ProductionHandoffRuntime<'_>,
    target: Profile,
) -> Result<HandoffResult, CodexFailoverError> {
    for _ in 0..MAX_HANDOFF_STEPS {
        match resume_handoff_once(conversations, runtime).map_err(map_handoff_execution_error)? {
            HandoffStep::Advanced(_) => {}
            HandoffStep::RequiresExplicitReconciliation(reason) => {
                let _ = reason;
                return Err(CodexFailoverError::Handoff);
            }
            HandoffStep::Attached(head) => {
                let status = runtime
                    .attached_status
                    .take()
                    .ok_or(CodexFailoverError::Handoff)?;
                return Ok(HandoffResult {
                    conversation_id: head.conversation_id,
                    generation: u64::from(head.generation),
                    profile: target,
                    thread_id: head.thread_id,
                    status,
                });
            }
        }
    }
    Err(CodexFailoverError::Handoff)
}

fn map_handoff_execution_error<RuntimeError>(
    error: HandoffExecutionError<RuntimeError>,
) -> CodexFailoverError {
    let _ = error;
    CodexFailoverError::Handoff
}

struct ProductionHandoffRuntime<'a> {
    registry: &'a Registry,
    codex_executable: &'a Path,
    neutral_working_directory: &'a Path,
    working_directory: &'a Path,
    target: Profile,
    reservation: Option<VerifiedTargetReservation>,
    source_profile: Profile,
    source_rollout: Option<CodexRolloutHandoff>,
    source_thread: CodexThreadRead,
    source_settings: EffectiveThreadSettings,
    pool_alias: String,
    trust_domain_alias: String,
    selection_reason: crate::routing::selection::SelectionReason,
    verified_source: Option<VerifiedSourceRollout>,
    direct_target: Option<ValidatedForkRollout>,
    attached_status: Option<ExitStatus>,
}

impl ProductionHandoffRuntime<'_> {
    fn provider_lease(&self) -> Result<Option<&File>, CodexFailoverError> {
        self.reservation
            .as_ref()
            .ok_or(CodexFailoverError::Handoff)?
            .provider_lock_for_probe()
            .map_err(CodexFailoverError::Profile)
    }

    fn ensure_verified_source(&mut self) -> Result<&VerifiedSourceRollout, CodexFailoverError> {
        if self.verified_source.is_none() {
            let source = self
                .source_rollout
                .take()
                .ok_or(CodexFailoverError::Handoff)?;
            self.verified_source = Some(
                source
                    .begin_import()
                    .and_then(|import| import.finish())
                    .map_err(|_| CodexFailoverError::Protocol)?,
            );
        }
        self.verified_source
            .as_ref()
            .ok_or(CodexFailoverError::Handoff)
    }

    fn take_or_remint_source(&mut self) -> Result<CodexRolloutHandoff, CodexFailoverError> {
        if let Some(source) = self.source_rollout.take() {
            return Ok(source);
        }
        mint_profile_rollout_handoff(self.registry, &self.source_profile, &self.source_thread)
            .map_err(|_| CodexFailoverError::Protocol)
    }
}

impl HandoffRuntime for ProductionHandoffRuntime<'_> {
    type Error = CodexFailoverError;

    fn stop_and_reap_source(&mut self, _transition: &HandoffTransition) -> Result<(), Self::Error> {
        // Construction is reachable only after the exact supervised source
        // anchor returned its verified completion and typed exhaustion code.
        Ok(())
    }

    fn capture_target_baseline(
        &mut self,
        transition: &HandoffTransition,
    ) -> Result<Vec<String>, Self::Error> {
        if transition.target_profile_id != self.target.id {
            return Err(CodexFailoverError::Handoff);
        }
        let inventory = read_handoff_inventory(
            self.registry,
            &self.target,
            self.codex_executable,
            self.neutral_working_directory,
            self.working_directory,
            self.provider_lease()?,
        )?;
        Ok(inventory
            .into_iter()
            .filter_map(|entry| entry.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect())
    }

    fn request_fork(&mut self, transition: &HandoffTransition) -> Result<(), Self::Error> {
        if transition.target_profile_id != self.target.id || self.direct_target.is_some() {
            return Err(CodexFailoverError::Handoff);
        }
        let source = self.take_or_remint_source()?;
        let (verified, target) = fork_handoff_rollout(
            self.registry,
            &self.target,
            self.codex_executable,
            self.neutral_working_directory,
            self.working_directory,
            self.provider_lease()?,
            source,
            &self.source_settings,
        )?;
        self.verified_source = Some(verified);
        self.direct_target = Some(target);
        Ok(())
    }

    fn reconcile_target_inventory(
        &mut self,
        transition: &HandoffTransition,
    ) -> Result<Vec<ForkCandidate<crate::conversations::HandoffTarget>>, Self::Error> {
        let verified = self.ensure_verified_source()?.clone();
        if let Some(target) = self.direct_target.take() {
            let thread_id = target.thread_id().to_owned();
            return Ok(vec![ForkCandidate::from_validated_rollout(
                thread_id, target, &verified,
            )]);
        }
        let observed_at = unix_timestamp()?;
        let requested_at = transition
            .fork_requested_at
            .ok_or(CodexFailoverError::Handoff)?;
        let baseline: BTreeSet<_> = transition
            .target_baseline_thread_ids
            .iter()
            .cloned()
            .collect();
        let inventory = read_handoff_inventory(
            self.registry,
            &self.target,
            self.codex_executable,
            self.neutral_working_directory,
            self.working_directory,
            self.provider_lease()?,
        )?;
        Ok(inventory
            .into_iter()
            .filter_map(|candidate| {
                let thread_id = candidate.get("id")?.as_str()?.to_owned();
                if baseline.contains(&thread_id) {
                    return None;
                }
                Some(
                    match validate_handoff_inventory_candidate(
                        self.registry,
                        &self.target,
                        &verified,
                        &candidate,
                        requested_at,
                        observed_at,
                    ) {
                        Ok(rollout) => {
                            ForkCandidate::from_validated_rollout(thread_id, rollout, &verified)
                        }
                        Err(_) => ForkCandidate::mismatch(thread_id),
                    },
                )
            })
            .collect())
    }

    fn attach_committed_target(
        &mut self,
        transition: &HandoffTransition,
    ) -> Result<(), Self::Error> {
        let observed = transition
            .observed_target
            .as_ref()
            .ok_or(CodexFailoverError::Handoff)?;
        if transition.target_profile_id != self.target.id
            || observed.canonical_cwd != self.working_directory.to_string_lossy()
        {
            return Err(CodexFailoverError::Handoff);
        }
        let reservation = self.reservation.take().ok_or(CodexFailoverError::Handoff)?;
        eprintln!(
            "{}",
            handoff_notice(
                &self.source_profile,
                &self.target,
                &self.pool_alias,
                &self.trust_domain_alias,
                self.selection_reason,
            )
        );
        self.attached_status = Some(spawn_promoted_supervised_generation(
            self.registry,
            reservation,
            self.working_directory,
            &observed.thread_id,
            self.codex_executable,
        )?);
        Ok(())
    }
}

fn handoff_notice(
    source: &Profile,
    target: &Profile,
    pool_alias: &str,
    trust_domain_alias: &str,
    reason: crate::routing::selection::SelectionReason,
) -> String {
    format!(
        "Calcifer: switching {} -> {} in pool {} / trust domain {} ({}); the failed turn will not be replayed.",
        source.reference(),
        target.reference(),
        pool_alias,
        trust_domain_alias,
        reason.label(),
    )
}

#[cfg(target_os = "linux")]
fn spawn_promoted_supervised_generation(
    registry: &Registry,
    reservation: VerifiedTargetReservation,
    working_directory: &Path,
    thread_id: &str,
    codex_executable: &Path,
) -> std::io::Result<ExitStatus> {
    super::spawn_supervised_exact_resume_with_reservation(
        registry,
        reservation,
        working_directory,
        thread_id,
        codex_executable,
    )
}

#[cfg(target_os = "macos")]
fn spawn_promoted_supervised_generation(
    _registry: &Registry,
    _reservation: VerifiedTargetReservation,
    _working_directory: &Path,
    _thread_id: &str,
    _codex_executable: &Path,
) -> std::io::Result<ExitStatus> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the production Codex supervisor is Linux-only",
    ))
}

#[cfg(target_os = "linux")]
fn spawn_supervised_generation(
    registry: &Registry,
    profile: &Profile,
    working_directory: &Path,
    thread_id: &str,
    codex_executable: &Path,
) -> std::io::Result<ExitStatus> {
    super::spawn_supervised_exact_resume(
        registry,
        profile,
        working_directory,
        thread_id,
        codex_executable,
    )
}

#[cfg(target_os = "macos")]
fn spawn_supervised_generation(
    _registry: &Registry,
    _profile: &Profile,
    _working_directory: &Path,
    _thread_id: &str,
    _codex_executable: &Path,
) -> std::io::Result<ExitStatus> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the production Codex supervisor is Linux-only",
    ))
}

#[allow(clippy::too_many_arguments)]
fn fork_handoff_rollout(
    registry: &Registry,
    target: &Profile,
    codex_executable: &Path,
    neutral_working_directory: &Path,
    working_directory: &Path,
    provider_lease: Option<&File>,
    source: CodexRolloutHandoff,
    source_settings: &EffectiveThreadSettings,
) -> Result<(VerifiedSourceRollout, ValidatedForkRollout), CodexFailoverError> {
    let target_home = registry.profile_home(target)?;
    let deadline = Instant::now()
        .checked_add(PROVIDER_OPERATION_TIMEOUT)
        .ok_or(CodexFailoverError::Protocol)?;
    let mut process = initialize_handoff_client(
        codex_executable,
        &target_home,
        neutral_working_directory,
        provider_lease,
        deadline,
    )?;
    let import = source
        .begin_import()
        .map_err(|_| CodexFailoverError::Protocol)?;
    let params = source_settings
        .fork_params(import.source_path())
        .ok_or(CodexFailoverError::Protocol)?;
    if params.get("cwd").and_then(Value::as_str) != working_directory.to_str() {
        return Err(CodexFailoverError::Protocol);
    }
    process
        .send(&json!({
            "id": 1,
            "method": "thread/fork",
            "params": params
        }))
        .map_err(|_| CodexFailoverError::Protocol)?;
    let result = process
        .receive_result(1, deadline)
        .map_err(|_| CodexFailoverError::Protocol)?;
    let shutdown_deadline = Instant::now()
        .checked_add(APP_SERVER_SHUTDOWN_TIMEOUT)
        .ok_or(CodexFailoverError::Protocol)?
        .min(deadline);
    process
        .shutdown_after_completed_request_until(shutdown_deadline)
        .map_err(|_| CodexFailoverError::Protocol)?;
    let verified = import.finish().map_err(|_| CodexFailoverError::Protocol)?;
    let returned_settings = super::remote::parse_thread_settings(&result)
        .map_err(|_| CodexFailoverError::Protocol)?
        .ok_or(CodexFailoverError::Protocol)?;
    if &returned_settings != source_settings {
        return Err(CodexFailoverError::Protocol);
    }
    let target_rollout = validate_handoff_fork_result(registry, target, &verified, &result)
        .map_err(|_| CodexFailoverError::Protocol)?;
    Ok((verified, target_rollout))
}

fn initialize_handoff_client(
    codex_executable: &Path,
    codex_home: &Path,
    working_directory: &Path,
    provider_lease: Option<&File>,
    deadline: Instant,
) -> Result<AppServerProcess, CodexFailoverError> {
    let mut process = AppServerProcess::spawn(
        codex_executable,
        codex_home,
        working_directory,
        provider_lease,
    )
    .map_err(|_| CodexFailoverError::Protocol)?;
    process
        .send(&json!({
            "id": INITIALIZE_REQUEST_ID,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": APP_SERVER_CLIENT_NAME,
                    "title": "Calcifer",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": { "experimentalApi": true }
            }
        }))
        .map_err(|_| CodexFailoverError::Protocol)?;
    let initialize = process
        .receive_result(INITIALIZE_REQUEST_ID, deadline)
        .map_err(|_| CodexFailoverError::Protocol)?;
    let version = validate_initialize_result(initialize, codex_home)
        .map_err(|_| CodexFailoverError::Protocol)?;
    if version != "0.144.4" {
        return Err(CodexFailoverError::Protocol);
    }
    process
        .send(&json!({ "method": "initialized", "params": {} }))
        .map_err(|_| CodexFailoverError::Protocol)?;
    Ok(process)
}

fn read_handoff_inventory(
    registry: &Registry,
    target: &Profile,
    codex_executable: &Path,
    neutral_working_directory: &Path,
    canonical_cwd: &Path,
    provider_lease: Option<&File>,
) -> Result<Vec<Value>, CodexFailoverError> {
    let target_home = registry.profile_home(target)?;
    let deadline = Instant::now()
        .checked_add(PROVIDER_OPERATION_TIMEOUT)
        .ok_or(CodexFailoverError::Protocol)?;
    let mut process = initialize_handoff_client(
        codex_executable,
        &target_home,
        neutral_working_directory,
        provider_lease,
        deadline,
    )?;
    let canonical_cwd = canonical_cwd.to_str().ok_or(CodexFailoverError::Protocol)?;
    let mut entries = Vec::new();
    let mut cursor = None;
    let mut seen_cursors = BTreeSet::new();
    for page_index in 0..MAX_THREAD_PAGES_PER_STATE {
        let request_id = u64::try_from(page_index + 1).map_err(|_| CodexFailoverError::Protocol)?;
        process
            .send(&json!({
                "id": request_id,
                "method": "thread/list",
                "params": {
                    "cursor": cursor,
                    "limit": THREAD_PAGE_SIZE,
                    "sortKey": "updated_at",
                    "sortDirection": "asc",
                    "sourceKinds": ["cli"],
                    "archived": false,
                    "cwd": canonical_cwd,
                    "useStateDbOnly": false
                }
            }))
            .map_err(|_| CodexFailoverError::Protocol)?;
        let result = process
            .receive_result(request_id, deadline)
            .map_err(|_| CodexFailoverError::Protocol)?;
        let object = result.as_object().ok_or(CodexFailoverError::Protocol)?;
        let page = object
            .get("data")
            .and_then(Value::as_array)
            .ok_or(CodexFailoverError::Protocol)?;
        for entry in page {
            validate_inventory_entry(entry, canonical_cwd)?;
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .ok_or(CodexFailoverError::Protocol)?;
            if entries
                .iter()
                .any(|existing: &Value| existing.get("id").and_then(Value::as_str) == Some(id))
            {
                return Err(CodexFailoverError::Protocol);
            }
            entries.push(entry.clone());
        }
        match object.get("nextCursor") {
            None | Some(Value::Null) => break,
            Some(value) if page_index + 1 == MAX_THREAD_PAGES_PER_STATE => {
                let _ = value;
                return Err(CodexFailoverError::Protocol);
            }
            Some(value) => {
                let next = value
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or(CodexFailoverError::Protocol)?
                    .to_owned();
                if !seen_cursors.insert(next.clone()) {
                    return Err(CodexFailoverError::Protocol);
                }
                cursor = Some(next);
            }
        }
    }
    let shutdown_deadline = Instant::now()
        .checked_add(APP_SERVER_SHUTDOWN_TIMEOUT)
        .ok_or(CodexFailoverError::Protocol)?
        .min(deadline);
    process
        .shutdown_after_completed_request_until(shutdown_deadline)
        .map_err(|_| CodexFailoverError::Protocol)?;
    Ok(entries)
}

fn validate_inventory_entry(entry: &Value, expected_cwd: &str) -> Result<(), CodexFailoverError> {
    let entry = entry.as_object().ok_or(CodexFailoverError::Protocol)?;
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .ok_or(CodexFailoverError::Protocol)?;
    validate_canonical_uuid(id).map_err(|_| CodexFailoverError::Protocol)?;
    if let Some(parent) = entry.get("parentThreadId") {
        if !parent.is_null() {
            let parent = parent.as_str().ok_or(CodexFailoverError::Protocol)?;
            validate_canonical_uuid(parent).map_err(|_| CodexFailoverError::Protocol)?;
            if parent == id {
                return Err(CodexFailoverError::Protocol);
            }
        }
    }
    if entry.get("ephemeral").and_then(Value::as_bool).is_none()
        || entry.get("updatedAt").and_then(Value::as_i64).is_none()
        || entry.get("cliVersion").and_then(Value::as_str) != Some("0.144.4")
        || entry.get("source").and_then(Value::as_str) != Some("cli")
        || entry.get("cwd").and_then(Value::as_str) != Some(expected_cwd)
    {
        return Err(CodexFailoverError::Protocol);
    }
    Ok(())
}

fn unix_timestamp() -> Result<i64, CodexFailoverError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CodexFailoverError::Protocol)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| CodexFailoverError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_stop_codes_and_messages_are_actionable_and_distinct() {
        let kinds = [
            PoolStopKind::Exhausted,
            PoolStopKind::AllUnknown,
            PoolStopKind::Busy,
            PoolStopKind::NoEligible,
        ];
        let codes: BTreeSet<_> = kinds.iter().map(|kind| kind.code()).collect();
        assert_eq!(codes.len(), kinds.len());
        assert!(kinds.iter().all(|kind| !kind.safe_message().is_empty()));
    }

    #[test]
    fn inventory_entry_accepts_a_fork_parent_but_rejects_self_parent() {
        let id = "01900000-0000-7000-8000-000000000401";
        let parent = "01900000-0000-7000-8000-000000000402";
        let entry = json!({
            "id": id,
            "parentThreadId": parent,
            "ephemeral": false,
            "updatedAt": 10,
            "cliVersion": "0.144.4",
            "source": "cli",
            "cwd": "/tmp"
        });
        assert!(validate_inventory_entry(&entry, "/tmp").is_ok());
        let mut invalid = entry;
        invalid["parentThreadId"] = json!(id);
        assert!(validate_inventory_entry(&invalid, "/tmp").is_err());
    }

    #[test]
    fn handoff_notice_uses_only_local_aliases_and_a_fixed_reason() {
        let source = Profile {
            id: "01900000-0000-7000-8000-000000000411".to_owned(),
            alias: "work".to_owned(),
            provider: Provider::Codex,
            created_at: 1,
        };
        let target = Profile {
            id: "01900000-0000-7000-8000-000000000412".to_owned(),
            alias: "personal".to_owned(),
            provider: Provider::Codex,
            created_at: 2,
        };
        let notice = handoff_notice(
            &source,
            &target,
            "fallback",
            "accounts",
            crate::routing::selection::SelectionReason::RevalidatedUsageLimit,
        );
        assert_eq!(
            notice,
            "Calcifer: switching codex@work -> codex@personal in pool fallback / trust domain accounts (revalidated_usage_limit); the failed turn will not be replayed."
        );
        assert!(!notice.contains(&source.id));
        assert!(!notice.contains(&target.id));
    }
}
