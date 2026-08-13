//! Crash-recovery decisions for one cross-profile Codex handoff.
//!
//! Provider I/O is intentionally absent from this module. It projects the
//! durable journal into one closed next action and reconciles a complete
//! target inventory without granting signal, wait, retry, fork, attach, or
//! cleanup authority. The concrete supervisor consumes these decisions while
//! retaining its linear source, target, and rollout capabilities.

#![cfg_attr(not(test), allow(dead_code))] // Activated by the selector in issue #36.

use std::fmt;

use uuid::Uuid;

use super::rollout_handoff::{
    CodexRolloutHandoff, CodexRolloutHandoffError, ValidatedForkRollout, VerifiedSourceRollout,
};
use crate::conversations::{
    ConversationError, ConversationRegistry, HandoffPhase, HandoffPreparation, HandoffReason,
    HandoffTarget, HandoffTransition, HeadBinding,
};
use crate::profiles::{Profile, Provider};
use crate::routing::{DefinitionError, Definitions};

const MAX_RECONCILIATION_THREADS: usize = 1_600;

/// Validates source rollout provenance and trust-domain policy before the
/// first durable transition record is published.
///
/// The rollout capability has no raw-path constructor and was minted from the
/// current managed source profile. The target row is revalidated again when
/// its no-gap reservation is acquired by the runtime.
pub(crate) fn prepare_codex_handoff(
    registry: &ConversationRegistry,
    definitions: &Definitions,
    expected_source: HeadBinding,
    target: &Profile,
    trust_domain_id: &str,
    reason: HandoffReason,
    source: &CodexRolloutHandoff,
) -> Result<HandoffTransition, HandoffPreparationError> {
    let _coordinator = registry
        .try_lock_handoff_coordinator()
        .map_err(HandoffPreparationError::Journal)?;
    if target.provider != Provider::Codex
        || source.profile_id() != expected_source.profile_id
        || source.thread_id() != expected_source.thread_id
        || source.codex_version() != expected_source.codex_version
        || source.canonical_cwd().to_str() != Some(expected_source.canonical_cwd.as_str())
    {
        return Err(HandoffPreparationError::SourceBinding);
    }
    let authorization = definitions
        .authorize_handoff(
            trust_domain_id,
            &expected_source.profile_id,
            &target.id,
            Provider::Codex,
        )
        .map_err(HandoffPreparationError::Policy)?;
    let source_rollout = source
        .journal_rollout()
        .map_err(HandoffPreparationError::Rollout)?;
    registry
        .prepare_handoff(HandoffPreparation {
            expected_source,
            target_profile_id: target.id.clone(),
            trust_domain_id: authorization.trust_domain_id().to_owned(),
            reason,
            source_rollout,
        })
        .map_err(HandoffPreparationError::Journal)
}

pub(crate) enum HandoffPreparationError {
    SourceBinding,
    Policy(DefinitionError),
    Rollout(CodexRolloutHandoffError),
    Journal(ConversationError),
}

impl fmt::Debug for HandoffPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceBinding => "HandoffPreparationError::SourceBinding",
            Self::Policy(_) => "HandoffPreparationError::Policy",
            Self::Rollout(_) => "HandoffPreparationError::Rollout",
            Self::Journal(_) => "HandoffPreparationError::Journal",
        })
    }
}

impl fmt::Display for HandoffPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceBinding => {
                formatter.write_str("the handoff source no longer matches the active generation")
            }
            Self::Policy(error) => {
                let _ = error.code();
                formatter.write_str("the handoff profiles are not authorized by one trust domain")
            }
            Self::Rollout(error) => {
                let _ = error;
                formatter.write_str("the handoff source rollout is no longer safe")
            }
            Self::Journal(error) => {
                let _ = error.code();
                formatter.write_str("the handoff transition could not be prepared durably")
            }
        }
    }
}

impl std::error::Error for HandoffPreparationError {}

/// The sole crash-recovery action authorized by the current durable phase.
///
/// No variant represents replaying a prompt, command, approval, tool action,
/// or already-committed fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandoffResumeAction {
    PersistSourceStopIntent,
    StopAndReapSource,
    CaptureTargetBaselineAndFork,
    ReconcileFork,
    CommitObservedTarget,
    AttachCommittedTarget,
}

/// Provider operations available to the transaction driver.
///
/// The interface deliberately has no prompt, command, approval, or transcript
/// input. Implementations must scope each call to the exact profiles and
/// rollout recorded by `transition`; stop, fork reconciliation, and attach
/// are idempotent recovery operations.
pub(crate) trait HandoffRuntime {
    type Error;

    fn stop_and_reap_source(&mut self, transition: &HandoffTransition) -> Result<(), Self::Error>;

    fn capture_target_baseline(
        &mut self,
        transition: &HandoffTransition,
    ) -> Result<Vec<String>, Self::Error>;

    fn request_fork(&mut self, transition: &HandoffTransition) -> Result<(), Self::Error>;

    fn reconcile_target_inventory(
        &mut self,
        transition: &HandoffTransition,
    ) -> Result<Vec<ForkCandidate<HandoffTarget>>, Self::Error>;

    fn attach_committed_target(
        &mut self,
        transition: &HandoffTransition,
    ) -> Result<(), Self::Error>;
}

pub(crate) enum HandoffExecutionError<RuntimeError> {
    NoTransition,
    Journal(ConversationError),
    Decision(HandoffTransactionError),
    Runtime(RuntimeError),
}

impl<RuntimeError> fmt::Debug for HandoffExecutionError<RuntimeError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoTransition => "HandoffExecutionError::NoTransition",
            Self::Journal(_) => "HandoffExecutionError::Journal",
            Self::Decision(_) => "HandoffExecutionError::Decision",
            Self::Runtime(_) => "HandoffExecutionError::Runtime",
        })
    }
}

impl<RuntimeError> fmt::Display for HandoffExecutionError<RuntimeError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTransition => formatter.write_str("no handoff transition is active"),
            Self::Journal(error) => write!(formatter, "handoff journal: {error}"),
            Self::Decision(error) => write!(formatter, "handoff decision: {error}"),
            Self::Runtime(error) => {
                let _ = error;
                formatter.write_str("handoff runtime operation failed")
            }
        }
    }
}

impl<RuntimeError> std::error::Error for HandoffExecutionError<RuntimeError> {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HandoffStep {
    Advanced(HandoffPhase),
    RequiresExplicitReconciliation(ExplicitReconciliationReason),
    Attached(HeadBinding),
}

/// Advances at most one crash-safe external or journal boundary.
///
/// The process-wide coordinator lease remains held across the selected
/// provider operation, but no short registry transaction lock does. Every
/// non-idempotent provider request is preceded by its durable intent marker.
#[cfg(unix)]
pub(crate) fn resume_handoff_once<Runtime: HandoffRuntime>(
    registry: &ConversationRegistry,
    runtime: &mut Runtime,
) -> Result<HandoffStep, HandoffExecutionError<Runtime::Error>> {
    let _coordinator = registry
        .try_lock_handoff_coordinator()
        .map_err(HandoffExecutionError::Journal)?;
    let transition = registry
        .current_handoff()
        .map_err(HandoffExecutionError::Journal)?
        .ok_or(HandoffExecutionError::NoTransition)?;
    let transition_id = transition.transition_id.clone();

    match resume_action(&transition).map_err(HandoffExecutionError::Decision)? {
        HandoffResumeAction::PersistSourceStopIntent => registry
            .mark_source_stop_requested(&transition_id)
            .map(|next| HandoffStep::Advanced(next.phase))
            .map_err(HandoffExecutionError::Journal),
        HandoffResumeAction::StopAndReapSource => {
            runtime
                .stop_and_reap_source(&transition)
                .map_err(HandoffExecutionError::Runtime)?;
            registry
                .mark_source_stopped(&transition_id)
                .map(|next| HandoffStep::Advanced(next.phase))
                .map_err(HandoffExecutionError::Journal)
        }
        HandoffResumeAction::CaptureTargetBaselineAndFork => {
            let baseline = runtime
                .capture_target_baseline(&transition)
                .map_err(HandoffExecutionError::Runtime)?;
            let requested = registry
                .record_fork_intent(&transition_id, baseline)
                .map_err(HandoffExecutionError::Journal)?;
            runtime
                .request_fork(&requested)
                .map_err(HandoffExecutionError::Runtime)?;
            Ok(HandoffStep::Advanced(requested.phase))
        }
        HandoffResumeAction::ReconcileFork => {
            let inventory = runtime
                .reconcile_target_inventory(&transition)
                .map_err(HandoffExecutionError::Runtime)?;
            match reconcile_fork_candidates(&transition, inventory)
                .map_err(HandoffExecutionError::Decision)?
            {
                ForkReconciliation::Adopt(target) => registry
                    .observe_handoff_target(&transition_id, target)
                    .map(|next| HandoffStep::Advanced(next.phase))
                    .map_err(HandoffExecutionError::Journal),
                ForkReconciliation::RetryOnce => {
                    let retry = registry
                        .record_bounded_fork_retry(&transition_id)
                        .map_err(HandoffExecutionError::Journal)?;
                    runtime
                        .request_fork(&retry)
                        .map_err(HandoffExecutionError::Runtime)?;
                    Ok(HandoffStep::Advanced(retry.phase))
                }
                ForkReconciliation::Explicit(reason) => {
                    Ok(HandoffStep::RequiresExplicitReconciliation(reason))
                }
            }
        }
        HandoffResumeAction::CommitObservedTarget => registry
            .commit_handoff(&transition_id)
            .map(|_| HandoffStep::Advanced(HandoffPhase::CommittedUnattached))
            .map_err(HandoffExecutionError::Journal),
        HandoffResumeAction::AttachCommittedTarget => {
            runtime
                .attach_committed_target(&transition)
                .map_err(HandoffExecutionError::Runtime)?;
            registry
                .finish_handoff_attachment(&transition_id)
                .map(HandoffStep::Attached)
                .map_err(HandoffExecutionError::Journal)
        }
    }
}

/// Projects one validated journal snapshot into its only legal next action.
pub(crate) fn resume_action(
    transition: &HandoffTransition,
) -> Result<HandoffResumeAction, HandoffTransactionError> {
    if transition.reason == HandoffReason::UnknownLegacy {
        return Err(HandoffTransactionError::UnknownReason);
    }
    match transition.phase {
        HandoffPhase::Prepared => Ok(HandoffResumeAction::PersistSourceStopIntent),
        HandoffPhase::SourceStopRequested => Ok(HandoffResumeAction::StopAndReapSource),
        HandoffPhase::SourceStopped => Ok(HandoffResumeAction::CaptureTargetBaselineAndFork),
        HandoffPhase::ForkRequested if matches!(transition.fork_attempts, 1 | 2) => {
            Ok(HandoffResumeAction::ReconcileFork)
        }
        HandoffPhase::ForkRequested => Err(HandoffTransactionError::InvalidTransition),
        HandoffPhase::ForkObserved => Ok(HandoffResumeAction::CommitObservedTarget),
        HandoffPhase::CommittedUnattached => Ok(HandoffResumeAction::AttachCommittedTarget),
    }
}

/// Provider-free assessment of one target thread observed after the baseline.
pub(crate) enum ForkCandidateProjection<T> {
    Matching(T),
    Mismatch,
}

/// One bounded target inventory entry.
pub(crate) struct ForkCandidate<T> {
    thread_id: String,
    projection: ForkCandidateProjection<T>,
}

impl<T> ForkCandidate<T> {
    #[cfg(any(test, feature = "internal-failover-scorecard"))]
    pub(crate) fn matching(thread_id: String, target: T) -> Self {
        Self {
            thread_id,
            projection: ForkCandidateProjection::Matching(target),
        }
    }

    pub(crate) fn mismatch(thread_id: String) -> Self {
        Self {
            thread_id,
            projection: ForkCandidateProjection::Mismatch,
        }
    }
}

impl ForkCandidate<HandoffTarget> {
    /// Converts only the sealed target-rollout proof into an adoptable journal
    /// candidate. Production callers cannot label an arbitrary target as a
    /// match; validation failure or a cross-wired thread ID stays fail-closed.
    pub(crate) fn from_validated_rollout(
        thread_id: String,
        rollout: ValidatedForkRollout,
        source: &VerifiedSourceRollout,
    ) -> Self {
        if rollout.thread_id() != thread_id {
            return Self::mismatch(thread_id);
        }
        match rollout.into_handoff_target(source) {
            Ok(target) => Self {
                thread_id,
                projection: ForkCandidateProjection::Matching(target),
            },
            Err(_) => Self::mismatch(thread_id),
        }
    }

    #[cfg(test)]
    pub(crate) fn matching_target_for_test(&self) -> Option<&HandoffTarget> {
        match &self.projection {
            ForkCandidateProjection::Matching(target) => Some(target),
            ForkCandidateProjection::Mismatch => None,
        }
    }
}

/// Fail-closed result when no single target can be adopted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExplicitReconciliationReason {
    MismatchedCandidate,
    MultipleCandidates,
    RetryExhausted,
}

/// A decision is not execution authority. `RetryOnce` must first be converted
/// into the journal's durable second-attempt marker before a provider request.
pub(crate) enum ForkReconciliation<T> {
    Adopt(T),
    RetryOnce,
    Explicit(ExplicitReconciliationReason),
}

/// Reconciles a complete target inventory against the pre-fork baseline.
///
/// Baseline entries are ignored. Every newly observed thread must be a strict
/// matching candidate, and exactly one may be adopted. Zero new candidates
/// permits one retry only while the durable attempt count is one.
pub(crate) fn reconcile_fork_candidates<T>(
    transition: &HandoffTransition,
    mut inventory: Vec<ForkCandidate<T>>,
) -> Result<ForkReconciliation<T>, HandoffTransactionError> {
    if transition.reason == HandoffReason::UnknownLegacy {
        return Err(HandoffTransactionError::UnknownReason);
    }
    if transition.phase != HandoffPhase::ForkRequested
        || !matches!(transition.fork_attempts, 1 | 2)
        || transition.fork_requested_at.is_none()
        || inventory.len() > MAX_RECONCILIATION_THREADS
    {
        return Err(HandoffTransactionError::InvalidTransition);
    }
    validate_sorted_thread_ids(&transition.target_baseline_thread_ids)?;
    inventory.sort_by(|left, right| left.thread_id.cmp(&right.thread_id));
    for (index, candidate) in inventory.iter().enumerate() {
        validate_thread_id(&candidate.thread_id)?;
        if index > 0 && inventory[index - 1].thread_id == candidate.thread_id {
            return Err(HandoffTransactionError::InvalidInventory);
        }
    }

    let mut new_candidates = inventory.into_iter().filter(|candidate| {
        transition
            .target_baseline_thread_ids
            .binary_search(&candidate.thread_id)
            .is_err()
    });
    let Some(first) = new_candidates.next() else {
        return Ok(if transition.fork_attempts == 1 {
            ForkReconciliation::RetryOnce
        } else {
            ForkReconciliation::Explicit(ExplicitReconciliationReason::RetryExhausted)
        });
    };
    if new_candidates.next().is_some() {
        return Ok(ForkReconciliation::Explicit(
            ExplicitReconciliationReason::MultipleCandidates,
        ));
    }
    match first.projection {
        ForkCandidateProjection::Matching(target) => Ok(ForkReconciliation::Adopt(target)),
        ForkCandidateProjection::Mismatch => Ok(ForkReconciliation::Explicit(
            ExplicitReconciliationReason::MismatchedCandidate,
        )),
    }
}

/// Redacted user-visible handoff metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HandoffNotice {
    pub(crate) source_alias: String,
    pub(crate) target_alias: String,
    pub(crate) reason: HandoffReason,
    pub(crate) generation: u32,
}

pub(crate) fn project_notice(
    transition: &HandoffTransition,
    source: &Profile,
    target: &Profile,
) -> Result<HandoffNotice, HandoffTransactionError> {
    if transition.reason == HandoffReason::UnknownLegacy {
        return Err(HandoffTransactionError::UnknownReason);
    }
    if source.provider != Provider::Codex
        || target.provider != Provider::Codex
        || source.id != transition.source_profile_id
        || target.id != transition.target_profile_id
        || source.id == target.id
        || source.alias.is_empty()
        || target.alias.is_empty()
    {
        return Err(HandoffTransactionError::InvalidProfiles);
    }
    Ok(HandoffNotice {
        source_alias: source.alias.clone(),
        target_alias: target.alias.clone(),
        reason: transition.reason,
        generation: transition.target_generation,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandoffTransactionError {
    UnknownReason,
    InvalidTransition,
    InvalidInventory,
    InvalidProfiles,
}

impl HandoffTransactionError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::UnknownReason => "codex_handoff_reason_unknown",
            Self::InvalidTransition => "codex_handoff_transition_invalid",
            Self::InvalidInventory => "codex_handoff_inventory_invalid",
            Self::InvalidProfiles => "codex_handoff_profiles_invalid",
        }
    }
}

impl fmt::Display for HandoffTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownReason => "the handoff reason requires explicit reconciliation",
            Self::InvalidTransition => "the handoff transition is invalid",
            Self::InvalidInventory => "the target handoff inventory is invalid",
            Self::InvalidProfiles => "the handoff profiles no longer match the transition",
        })
    }
}

impl std::error::Error for HandoffTransactionError {}

fn validate_thread_id(thread_id: &str) -> Result<(), HandoffTransactionError> {
    let parsed =
        Uuid::parse_str(thread_id).map_err(|_| HandoffTransactionError::InvalidInventory)?;
    if parsed.to_string() != thread_id {
        return Err(HandoffTransactionError::InvalidInventory);
    }
    Ok(())
}

fn validate_sorted_thread_ids(thread_ids: &[String]) -> Result<(), HandoffTransactionError> {
    if thread_ids.len() > MAX_RECONCILIATION_THREADS {
        return Err(HandoffTransactionError::InvalidTransition);
    }
    for (index, thread_id) in thread_ids.iter().enumerate() {
        validate_thread_id(thread_id).map_err(|_| HandoffTransactionError::InvalidTransition)?;
        if index > 0 && thread_ids[index - 1].as_str() >= thread_id.as_str() {
            return Err(HandoffTransactionError::InvalidTransition);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};

    use super::*;

    use crate::conversations::{
        BindingInput, ConversationLifecycle, GenerationRollout, HandoffPreparation,
        ObservedHandoffTarget, RolloutFingerprint, RolloutLocator, RolloutRoot,
    };

    fn rollout(seed: u64) -> GenerationRollout {
        GenerationRollout {
            locator: RolloutLocator {
                root: RolloutRoot::Sessions,
                relative_path: format!("2026/08/07/rollout-{seed}.jsonl"),
            },
            fingerprint: RolloutFingerprint {
                device: 1,
                inode: seed + 1,
                length: seed,
                mode: 0o100600,
                owner: rustix::process::getuid().as_raw(),
                link_count: 1,
                modified_seconds: 1_786_086_000,
                modified_nanoseconds: 1,
                changed_seconds: 1_786_086_000,
                changed_nanoseconds: 2,
                sha256: format!("{seed:064x}"),
            },
        }
    }

    fn transition(phase: HandoffPhase, attempts: u8) -> HandoffTransition {
        HandoffTransition {
            transition_id: Uuid::new_v4().to_string(),
            conversation_id: Uuid::new_v4().to_string(),
            source_generation: 3,
            target_generation: 4,
            source_profile_id: Uuid::new_v4().to_string(),
            target_profile_id: Uuid::new_v4().to_string(),
            canonical_cwd: "/tmp/calcifer-handoff-workspace".to_owned(),
            trust_domain_id: Uuid::new_v4().to_string(),
            reason: HandoffReason::ConfirmedUsageExhaustion,
            source_rollout: rollout(10),
            phase,
            target_baseline_thread_ids: if matches!(
                phase,
                HandoffPhase::ForkRequested
                    | HandoffPhase::ForkObserved
                    | HandoffPhase::CommittedUnattached
            ) {
                vec![Uuid::new_v4().to_string()]
            } else {
                Vec::new()
            },
            fork_attempts: attempts,
            fork_requested_at: (attempts > 0).then_some(101),
            observed_target: matches!(
                phase,
                HandoffPhase::ForkObserved | HandoffPhase::CommittedUnattached
            )
            .then(|| ObservedHandoffTarget {
                thread_id: Uuid::new_v4().to_string(),
                canonical_cwd: "/tmp/calcifer-handoff-workspace".to_owned(),
                codex_version: "0.144.4".to_owned(),
                adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
                rollout: rollout(20),
                observed_at: 102,
            }),
            prepared_at: 100,
            updated_at: 102,
        }
    }

    fn test_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "calcifer-handoff-transaction-{name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        Ok(root)
    }

    fn prepared_registry(
        name: &str,
    ) -> Result<
        (PathBuf, PathBuf, ConversationRegistry, HandoffTransition),
        Box<dyn std::error::Error>,
    > {
        let root = test_root(name)?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let canonical_cwd = fs::canonicalize(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(BindingInput {
            profile_id: Uuid::new_v4().to_string(),
            thread_id: Uuid::new_v4().to_string(),
            canonical_cwd: canonical_cwd.to_string_lossy().into_owned(),
            codex_version: "0.144.4".to_owned(),
            lifecycle: ConversationLifecycle::Clean,
        })?;
        let transition = registry.prepare_handoff(HandoffPreparation {
            expected_source: source,
            target_profile_id: Uuid::new_v4().to_string(),
            trust_domain_id: Uuid::new_v4().to_string(),
            reason: HandoffReason::ConfirmedUsageExhaustion,
            source_rollout: rollout(100),
        })?;
        Ok((root, workspace, registry, transition))
    }

    fn target(cwd: &Path, seed: u64) -> Result<HandoffTarget, Box<dyn std::error::Error>> {
        Ok(HandoffTarget {
            thread_id: Uuid::new_v4().to_string(),
            canonical_cwd: fs::canonicalize(cwd)?.to_string_lossy().into_owned(),
            codex_version: "0.144.4".to_owned(),
            rollout: rollout(seed),
        })
    }

    #[derive(Default)]
    struct FakeRuntime {
        baseline: Vec<String>,
        inventories: VecDeque<Vec<ForkCandidate<HandoffTarget>>>,
        events: Vec<String>,
        fail_stop_after_effect: bool,
        fail_fork_after_effect: bool,
        fail_attach_after_effect: bool,
    }

    impl HandoffRuntime for FakeRuntime {
        type Error = &'static str;

        fn stop_and_reap_source(
            &mut self,
            _transition: &HandoffTransition,
        ) -> Result<(), Self::Error> {
            self.events.push("stop-and-reap".to_owned());
            if std::mem::take(&mut self.fail_stop_after_effect) {
                return Err("crash-after-stop");
            }
            Ok(())
        }

        fn capture_target_baseline(
            &mut self,
            _transition: &HandoffTransition,
        ) -> Result<Vec<String>, Self::Error> {
            self.events.push("capture-baseline".to_owned());
            Ok(self.baseline.clone())
        }

        fn request_fork(&mut self, transition: &HandoffTransition) -> Result<(), Self::Error> {
            self.events
                .push(format!("request-fork:{}", transition.fork_attempts));
            if std::mem::take(&mut self.fail_fork_after_effect) {
                return Err("crash-after-fork");
            }
            Ok(())
        }

        fn reconcile_target_inventory(
            &mut self,
            transition: &HandoffTransition,
        ) -> Result<Vec<ForkCandidate<HandoffTarget>>, Self::Error> {
            self.events
                .push(format!("reconcile:{}", transition.fork_attempts));
            Ok(self.inventories.pop_front().unwrap_or_default())
        }

        fn attach_committed_target(
            &mut self,
            transition: &HandoffTransition,
        ) -> Result<(), Self::Error> {
            assert!(transition.observed_target.is_some());
            self.events.push("attach-exact-target".to_owned());
            if std::mem::take(&mut self.fail_attach_after_effect) {
                return Err("crash-after-attach");
            }
            Ok(())
        }
    }

    #[test]
    fn every_crash_phase_projects_to_one_non_replay_action() {
        let cases = [
            (
                HandoffPhase::Prepared,
                0,
                HandoffResumeAction::PersistSourceStopIntent,
            ),
            (
                HandoffPhase::SourceStopRequested,
                0,
                HandoffResumeAction::StopAndReapSource,
            ),
            (
                HandoffPhase::SourceStopped,
                0,
                HandoffResumeAction::CaptureTargetBaselineAndFork,
            ),
            (
                HandoffPhase::ForkRequested,
                1,
                HandoffResumeAction::ReconcileFork,
            ),
            (
                HandoffPhase::ForkObserved,
                1,
                HandoffResumeAction::CommitObservedTarget,
            ),
            (
                HandoffPhase::CommittedUnattached,
                1,
                HandoffResumeAction::AttachCommittedTarget,
            ),
        ];
        for (phase, attempts, expected) in cases {
            assert_eq!(resume_action(&transition(phase, attempts)), Ok(expected));
        }

        let mut legacy = transition(HandoffPhase::Prepared, 0);
        legacy.reason = HandoffReason::UnknownLegacy;
        assert_eq!(
            resume_action(&legacy),
            Err(HandoffTransactionError::UnknownReason)
        );
        assert_eq!(
            HandoffTransactionError::UnknownReason.code(),
            "codex_handoff_reason_unknown"
        );
    }

    #[test]
    fn reconciliation_adopts_exactly_one_new_match_and_ignores_the_baseline() {
        let state = transition(HandoffPhase::ForkRequested, 1);
        let baseline = state.target_baseline_thread_ids[0].clone();
        let target = Uuid::new_v4().to_string();
        let decision = reconcile_fork_candidates(
            &state,
            vec![
                ForkCandidate::mismatch(baseline.clone()),
                ForkCandidate::matching(target, 42_u8),
            ],
        );
        assert!(matches!(decision, Ok(ForkReconciliation::Adopt(42))));
    }

    #[test]
    fn zero_candidates_retry_once_then_require_explicit_reconciliation() {
        let first = transition(HandoffPhase::ForkRequested, 1);
        assert!(matches!(
            reconcile_fork_candidates::<()>(&first, Vec::new()),
            Ok(ForkReconciliation::RetryOnce)
        ));

        let second = transition(HandoffPhase::ForkRequested, 2);
        assert!(matches!(
            reconcile_fork_candidates::<()>(&second, Vec::new()),
            Ok(ForkReconciliation::Explicit(
                ExplicitReconciliationReason::RetryExhausted
            ))
        ));
    }

    #[test]
    fn multiple_mismatch_duplicate_and_malformed_candidates_fail_closed() {
        let state = transition(HandoffPhase::ForkRequested, 1);
        let one = Uuid::new_v4().to_string();
        let two = Uuid::new_v4().to_string();
        assert!(matches!(
            reconcile_fork_candidates(
                &state,
                vec![
                    ForkCandidate::matching(one.clone(), 1_u8),
                    ForkCandidate::matching(two, 2_u8),
                ]
            ),
            Ok(ForkReconciliation::Explicit(
                ExplicitReconciliationReason::MultipleCandidates
            ))
        ));
        assert!(matches!(
            reconcile_fork_candidates(&state, vec![ForkCandidate::<u8>::mismatch(one.clone())]),
            Ok(ForkReconciliation::Explicit(
                ExplicitReconciliationReason::MismatchedCandidate
            ))
        ));
        assert!(matches!(
            reconcile_fork_candidates(
                &state,
                vec![
                    ForkCandidate::matching(one.clone(), 1_u8),
                    ForkCandidate::matching(one, 2_u8),
                ]
            ),
            Err(HandoffTransactionError::InvalidInventory)
        ));
        assert!(matches!(
            reconcile_fork_candidates(
                &state,
                vec![ForkCandidate::matching("not-a-uuid".to_owned(), 1_u8)]
            ),
            Err(HandoffTransactionError::InvalidInventory)
        ));
    }

    #[test]
    fn notice_contains_only_current_local_aliases_reason_and_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = transition(HandoffPhase::CommittedUnattached, 1);
        let source = Profile {
            id: state.source_profile_id.clone(),
            alias: "work-a".to_owned(),
            provider: Provider::Codex,
            created_at: 1,
        };
        let target = Profile {
            id: state.target_profile_id.clone(),
            alias: "work-b".to_owned(),
            provider: Provider::Codex,
            created_at: 2,
        };
        let notice = project_notice(&state, &source, &target)?;
        assert_eq!(
            notice,
            HandoffNotice {
                source_alias: "work-a".to_owned(),
                target_alias: "work-b".to_owned(),
                reason: HandoffReason::ConfirmedUsageExhaustion,
                generation: 4,
            }
        );
        let rendered = format!("{notice:?}");
        assert!(!rendered.contains(&source.id));
        assert!(!rendered.contains(&target.id));
        Ok(())
    }

    #[test]
    fn transaction_orders_durable_intents_before_fork_and_attaches_one_new_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, workspace, registry, transition) = prepared_registry("ordered")?;
        let baseline = Uuid::new_v4().to_string();
        let expected_target = target(&workspace, 200)?;
        let expected_thread = expected_target.thread_id.clone();
        let mut runtime = FakeRuntime {
            baseline: vec![baseline.clone()],
            inventories: VecDeque::from([vec![
                ForkCandidate::mismatch(baseline.clone()),
                ForkCandidate::matching(expected_thread.clone(), expected_target),
            ]]),
            ..FakeRuntime::default()
        };

        assert_eq!(
            resume_handoff_once(&registry, &mut runtime)?,
            HandoffStep::Advanced(HandoffPhase::SourceStopRequested)
        );
        assert_eq!(
            resume_handoff_once(&registry, &mut runtime)?,
            HandoffStep::Advanced(HandoffPhase::SourceStopped)
        );
        assert_eq!(
            resume_handoff_once(&registry, &mut runtime)?,
            HandoffStep::Advanced(HandoffPhase::ForkRequested)
        );
        let requested = registry.current_handoff()?.ok_or("missing handoff")?;
        assert_eq!(requested.fork_attempts, 1);
        assert_eq!(requested.target_baseline_thread_ids, [baseline]);
        assert_eq!(
            resume_handoff_once(&registry, &mut runtime)?,
            HandoffStep::Advanced(HandoffPhase::ForkObserved)
        );
        assert_eq!(
            resume_handoff_once(&registry, &mut runtime)?,
            HandoffStep::Advanced(HandoffPhase::CommittedUnattached)
        );
        let attached = resume_handoff_once(&registry, &mut runtime)?;
        let HandoffStep::Attached(head) = attached else {
            return Err("handoff did not attach".into());
        };
        assert_eq!(head.conversation_id, transition.conversation_id);
        assert_eq!(head.generation, transition.target_generation);
        assert_eq!(head.thread_id, expected_thread);
        assert!(registry.current_handoff()?.is_none());
        assert_eq!(
            runtime.events,
            [
                "stop-and-reap",
                "capture-baseline",
                "request-fork:1",
                "reconcile:1",
                "attach-exact-target",
            ]
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn crash_after_fork_recovers_by_inventory_without_replaying_the_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, workspace, registry, _) = prepared_registry("fork-crash")?;
        let mut first_runtime = FakeRuntime {
            fail_fork_after_effect: true,
            ..FakeRuntime::default()
        };
        resume_handoff_once(&registry, &mut first_runtime)?;
        resume_handoff_once(&registry, &mut first_runtime)?;
        assert!(matches!(
            resume_handoff_once(&registry, &mut first_runtime),
            Err(HandoffExecutionError::Runtime("crash-after-fork"))
        ));
        let durable = registry.current_handoff()?.ok_or("missing handoff")?;
        assert_eq!(durable.phase, HandoffPhase::ForkRequested);
        assert_eq!(durable.fork_attempts, 1);

        let expected_target = target(&workspace, 300)?;
        let target_thread = expected_target.thread_id.clone();
        let mut recovered_runtime = FakeRuntime {
            inventories: VecDeque::from([vec![ForkCandidate::matching(
                target_thread,
                expected_target,
            )]]),
            ..FakeRuntime::default()
        };
        assert_eq!(
            resume_handoff_once(&registry, &mut recovered_runtime)?,
            HandoffStep::Advanced(HandoffPhase::ForkObserved)
        );
        assert_eq!(recovered_runtime.events, ["reconcile:1"]);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn zero_candidates_persist_one_retry_before_fork_then_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _workspace, registry, _) = prepared_registry("bounded-retry")?;
        let mut runtime = FakeRuntime {
            inventories: VecDeque::from([Vec::new(), Vec::new()]),
            ..FakeRuntime::default()
        };
        resume_handoff_once(&registry, &mut runtime)?;
        resume_handoff_once(&registry, &mut runtime)?;
        resume_handoff_once(&registry, &mut runtime)?;

        assert_eq!(
            resume_handoff_once(&registry, &mut runtime)?,
            HandoffStep::Advanced(HandoffPhase::ForkRequested)
        );
        let retry = registry.current_handoff()?.ok_or("missing handoff")?;
        assert_eq!(retry.fork_attempts, 2);
        assert_eq!(
            resume_handoff_once(&registry, &mut runtime)?,
            HandoffStep::RequiresExplicitReconciliation(
                ExplicitReconciliationReason::RetryExhausted
            )
        );
        assert_eq!(
            runtime.events,
            [
                "stop-and-reap",
                "capture-baseline",
                "request-fork:1",
                "reconcile:1",
                "request-fork:2",
                "reconcile:2",
            ]
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stop_and_attach_crashes_repeat_only_the_idempotent_current_action()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, workspace, registry, _) = prepared_registry("idempotent-recovery")?;
        let mut runtime = FakeRuntime {
            fail_stop_after_effect: true,
            ..FakeRuntime::default()
        };
        resume_handoff_once(&registry, &mut runtime)?;
        assert!(matches!(
            resume_handoff_once(&registry, &mut runtime),
            Err(HandoffExecutionError::Runtime("crash-after-stop"))
        ));
        assert_eq!(
            registry.current_handoff()?.ok_or("missing handoff")?.phase,
            HandoffPhase::SourceStopRequested
        );
        resume_handoff_once(&registry, &mut runtime)?;

        let expected_target = target(&workspace, 400)?;
        let expected_thread = expected_target.thread_id.clone();
        runtime.inventories.push_back(vec![ForkCandidate::matching(
            expected_thread,
            expected_target,
        )]);
        resume_handoff_once(&registry, &mut runtime)?;
        resume_handoff_once(&registry, &mut runtime)?;
        resume_handoff_once(&registry, &mut runtime)?;
        assert_eq!(
            registry.current_handoff()?.ok_or("missing handoff")?.phase,
            HandoffPhase::CommittedUnattached
        );

        runtime.fail_attach_after_effect = true;
        assert!(matches!(
            resume_handoff_once(&registry, &mut runtime),
            Err(HandoffExecutionError::Runtime("crash-after-attach"))
        ));
        assert_eq!(
            registry.current_handoff()?.ok_or("missing handoff")?.phase,
            HandoffPhase::CommittedUnattached
        );
        assert!(matches!(
            resume_handoff_once(&registry, &mut runtime)?,
            HandoffStep::Attached(_)
        ));
        assert_eq!(
            runtime
                .events
                .iter()
                .filter(|event| event.starts_with("request-fork"))
                .count(),
            1,
            "recovery must never re-fork a committed target"
        );
        assert_eq!(
            runtime
                .events
                .iter()
                .filter(|event| event.as_str() == "attach-exact-target")
                .count(),
            2
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }
}
