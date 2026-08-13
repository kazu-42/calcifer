//! Crash-safe bindings between Calcifer workspaces and provider-owned threads.
//!
//! This registry deliberately contains only local opaque identifiers and
//! bounded metadata. Provider payloads, prompts, previews, arbitrary absolute
//! rollout paths, and credentials never enter this document.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::profiles::{Provider, Registry};

const SCHEMA_VERSION_V1: u8 = 1;
const SCHEMA_VERSION_V2: u8 = 2;
const REGISTRY_FILE: &str = "conversations.json";
#[cfg_attr(not(test), allow(dead_code))] // Consumed by transactional handoff in issue #34.
const PRE_MIGRATION_BACKUP_FILE: &str = "conversations.v1.pre-v2.json";
const LOCK_FILE: &str = "conversations.lock";
#[cfg(unix)]
const HANDOFF_COORDINATOR_LOCK_FILE: &str = "conversation-handoff.lock";
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_INVENTORY_THREADS: usize = 1_600;
const MAX_LINEAGE_GENERATIONS: usize = 256;
const MAX_ROLLOUT_RELATIVE_BYTES: usize = 512;
const MAX_ROLLOUT_COMPONENTS: usize = 8;
const MAX_ROLLOUT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConversationLifecycle {
    Clean,
    Interrupted,
    UnknownCrash,
    Missing,
    Archived,
    Incompatible,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LaunchMode {
    Run,
    ResumeLast,
    RunUntracked,
    ResumeLastUntracked,
}

impl LaunchMode {
    pub(crate) const fn is_untracked(self) -> bool {
        matches!(self, Self::RunUntracked | Self::ResumeLastUntracked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PendingPhase {
    Prepared,
    ProviderStarted,
    CaptureFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryThread {
    pub(crate) thread_id: String,
    pub(crate) updated_at: i64,
    pub(crate) recency_at: Option<i64>,
    pub(crate) archived: bool,
    pub(crate) rollout_device: u64,
    pub(crate) rollout_inode: u64,
    pub(crate) rollout_length: u64,
    pub(crate) rollout_modified_seconds: i64,
    pub(crate) rollout_modified_nanoseconds: i64,
    pub(crate) rollout_changed_seconds: i64,
    pub(crate) rollout_changed_nanoseconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingLaunch {
    pub(crate) launch_id: String,
    pub(crate) profile_id: String,
    pub(crate) canonical_cwd: String,
    pub(crate) mode: LaunchMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) codex_version: Option<String>,
    pub(crate) adapter_version: String,
    pub(crate) pre_inventory: Vec<InventoryThread>,
    pub(crate) phase: PendingPhase,
    pub(crate) started_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BindingInput {
    pub(crate) profile_id: String,
    pub(crate) thread_id: String,
    pub(crate) canonical_cwd: String,
    pub(crate) codex_version: String,
    pub(crate) lifecycle: ConversationLifecycle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeadBinding {
    pub(crate) conversation_id: String,
    pub(crate) generation: u32,
    pub(crate) profile_id: String,
    pub(crate) thread_id: String,
    pub(crate) canonical_cwd: String,
    pub(crate) codex_version: String,
    pub(crate) lifecycle: ConversationLifecycle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RolloutRoot {
    Sessions,
    ArchivedSessions,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RolloutLocator {
    pub(crate) root: RolloutRoot,
    pub(crate) relative_path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RolloutFingerprint {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) length: u64,
    pub(crate) mode: u32,
    pub(crate) owner: u32,
    pub(crate) link_count: u64,
    pub(crate) modified_seconds: i64,
    pub(crate) modified_nanoseconds: i64,
    pub(crate) changed_seconds: i64,
    pub(crate) changed_nanoseconds: i64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationRollout {
    pub(crate) locator: RolloutLocator,
    pub(crate) fingerprint: RolloutFingerprint,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HandoffPhase {
    Prepared,
    SourceStopRequested,
    SourceStopped,
    ForkRequested,
    ForkObserved,
    CommittedUnattached,
}

/// Closed, provider-free reason retained across crash recovery.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HandoffReason {
    ConfirmedUsageExhaustion,
    ExplicitRecovery,
    /// Schema-v2 transition written before reason persistence existed.
    /// Recovery may display and reconcile it, but it cannot infer exhaustion.
    #[default]
    UnknownLegacy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))] // Consumed by transactional handoff in issue #34.
pub(crate) struct HandoffPreparation {
    pub(crate) expected_source: HeadBinding,
    pub(crate) target_profile_id: String,
    pub(crate) trust_domain_id: String,
    pub(crate) reason: HandoffReason,
    pub(crate) source_rollout: GenerationRollout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))] // Consumed by transactional handoff in issue #34.
pub(crate) struct HandoffTarget {
    pub(crate) thread_id: String,
    pub(crate) canonical_cwd: String,
    pub(crate) codex_version: String,
    pub(crate) rollout: GenerationRollout,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservedHandoffTarget {
    pub(crate) thread_id: String,
    pub(crate) canonical_cwd: String,
    pub(crate) codex_version: String,
    pub(crate) adapter_version: String,
    pub(crate) rollout: GenerationRollout,
    pub(crate) observed_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HandoffTransition {
    pub(crate) transition_id: String,
    pub(crate) conversation_id: String,
    pub(crate) source_generation: u32,
    pub(crate) target_generation: u32,
    pub(crate) source_profile_id: String,
    pub(crate) target_profile_id: String,
    pub(crate) canonical_cwd: String,
    pub(crate) trust_domain_id: String,
    #[serde(default)]
    pub(crate) reason: HandoffReason,
    pub(crate) source_rollout: GenerationRollout,
    pub(crate) phase: HandoffPhase,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) target_baseline_thread_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub(crate) fork_attempts: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fork_requested_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observed_target: Option<ObservedHandoffTarget>,
    pub(crate) prepared_at: i64,
    pub(crate) updated_at: i64,
}

pub(crate) enum LaunchResolution {
    Bind(BindingInput),
    NoThread,
    Ambiguous,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConversationDocument {
    schema_version: u8,
    revision: u64,
    conversations: Vec<Conversation>,
    workspace_heads: Vec<WorkspaceHead>,
    pending_launches: Vec<PendingLaunch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pre_migration_backup: Option<PreMigrationBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_transition: Option<HandoffTransition>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PreMigrationBackup {
    schema_version: u8,
    revision: u64,
    sha256: String,
}

impl Default for ConversationDocument {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            revision: 0,
            conversations: Vec::new(),
            workspace_heads: Vec::new(),
            pending_launches: Vec::new(),
            pre_migration_backup: None,
            active_transition: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Conversation {
    conversation_id: String,
    provider: Provider,
    generations: Vec<ConversationGeneration>,
    active_generation: u32,
    last_safe_lifecycle: ConversationLifecycle,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConversationGeneration {
    generation: u32,
    profile_id: String,
    thread_id: String,
    canonical_cwd: String,
    codex_version: String,
    adapter_version: String,
    bound_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trust_domain_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollout: Option<GenerationRollout>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum HeadState {
    Ready,
    NeedsSelection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceHead {
    provider: Provider,
    canonical_cwd: String,
    state: HeadState,
    conversation_id: Option<String>,
    generation: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
enum WriteFault {
    BeforeFileSync,
    BeforeRename,
    AfterRename,
    DirectorySync,
}

#[derive(Clone, Debug)]
pub(crate) struct ConversationRegistry {
    root: PathBuf,
    #[cfg(test)]
    fault: Option<WriteFault>,
}

/// Process-lifetime serialization for one crash-sensitive handoff.
///
/// This is deliberately distinct from the short registry transaction lock:
/// provider shutdown, fork, and attachment may take seconds, while unrelated
/// conversation registry updates must remain available. The descriptor is
/// close-on-exec and never grants provider, signal, wait, or cleanup authority.
#[cfg(unix)]
#[must_use = "dropping the handoff coordinator lease releases global handoff serialization"]
pub(crate) struct HandoffCoordinatorLease {
    _lock: File,
}

impl ConversationRegistry {
    pub(crate) fn from_profiles(registry: &Registry) -> Self {
        Self {
            root: registry.managed_root().to_owned(),
            #[cfg(test)]
            fault: None,
        }
    }

    /// Acquires the global handoff coordinator without waiting.
    ///
    /// Recovery invokes the same operation. A live transaction therefore
    /// wins deterministically; callers never block while retaining a source
    /// or target profile lease.
    #[cfg(unix)]
    pub(crate) fn try_lock_handoff_coordinator(
        &self,
    ) -> Result<HandoffCoordinatorLease, ConversationError> {
        verify_private_directory(&self.root)?;
        let path = self.root.join(HANDOFF_COORDINATOR_LOCK_FILE);
        let lock = open_private_handoff_lock(&path)?;
        match FileExt::try_lock_exclusive(&lock) {
            Ok(()) => Ok(HandoffCoordinatorLease { _lock: lock }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Err(ConversationError::TransitionBusy)
            }
            Err(error) => Err(ConversationError::Io(error)),
        }
    }

    pub(crate) fn begin_launch(
        &self,
        profile_id: &str,
        canonical_cwd: &Path,
        mode: LaunchMode,
        codex_version: &str,
        mut pre_inventory: Vec<InventoryThread>,
    ) -> Result<String, ConversationError> {
        validate_uuid(profile_id, "profile id")?;
        if mode.is_untracked() {
            return Err(ConversationError::RegistryInvalid(
                "tracked launch preparation requires a capture mode".to_owned(),
            ));
        }
        let canonical_cwd = canonical_path_string(canonical_cwd)?;
        validate_codex_version(codex_version)?;
        normalize_inventory(&mut pre_inventory)?;
        let launch_id = Uuid::new_v4().to_string();
        let started_at = unix_timestamp()?;
        let pending = PendingLaunch {
            launch_id: launch_id.clone(),
            profile_id: profile_id.to_owned(),
            canonical_cwd: canonical_cwd.clone(),
            mode,
            codex_version: Some(codex_version.to_owned()),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            pre_inventory,
            phase: PendingPhase::Prepared,
            started_at,
        };

        let overlapping = self.transact(|document| {
            ensure_workspace_not_transitioning(document, &canonical_cwd)?;
            let overlapping = document.pending_launches.iter().any(|existing| {
                existing.canonical_cwd == canonical_cwd && existing.launch_id != launch_id
            });
            if overlapping {
                mark_head_needs_selection(document, &canonical_cwd);
            } else {
                document.pending_launches.push(pending);
            }
            Ok(overlapping)
        })?;
        if overlapping {
            return Err(ConversationError::Ambiguous);
        }
        Ok(launch_id)
    }

    pub(crate) fn mark_provider_started(&self, launch_id: &str) -> Result<(), ConversationError> {
        validate_uuid(launch_id, "launch id")?;
        self.transact(|document| {
            let pending = find_pending_mut(document, launch_id)?;
            pending.phase = PendingPhase::ProviderStarted;
            Ok(())
        })
    }

    pub(crate) fn mark_capture_failed(&self, launch_id: &str) -> Result<(), ConversationError> {
        validate_uuid(launch_id, "launch id")?;
        self.transact(|document| {
            let pending = find_pending_mut(document, launch_id)?;
            pending.phase = PendingPhase::CaptureFailed;
            Ok(())
        })
    }

    pub(crate) fn pending_for(
        &self,
        profile_id: &str,
        canonical_cwd: &Path,
    ) -> Result<Option<PendingLaunch>, ConversationError> {
        validate_uuid(profile_id, "profile id")?;
        let canonical_cwd = canonical_path_string(canonical_cwd)?;
        self.read(|document| {
            let mut matches = document.pending_launches.iter().filter(|pending| {
                pending.profile_id == profile_id && pending.canonical_cwd == canonical_cwd
            });
            let first = matches.next().cloned();
            if matches.next().is_some() {
                return Err(ConversationError::Ambiguous);
            }
            Ok(first)
        })
    }

    /// Returns only the immutable profile owner needed to reconcile a crashed
    /// launch. This never selects a provider thread: the caller must release
    /// the conversation lock and acquire that profile's coordinator/provider
    /// lease. Tracked ownership then requires a fresh inventory; untracked
    /// ownership can only be removed while preserving `NeedsSelection`.
    pub(crate) fn pending_profile_for_workspace(
        &self,
        canonical_cwd: &Path,
    ) -> Result<Option<String>, ConversationError> {
        let canonical_cwd = canonical_path_string(canonical_cwd)?;
        self.read(|document| {
            let mut matches = document
                .pending_launches
                .iter()
                .filter(|pending| pending.canonical_cwd == canonical_cwd);
            let first = matches.next().map(|pending| pending.profile_id.clone());
            if matches.next().is_some() {
                return Err(ConversationError::Ambiguous);
            }
            Ok(first)
        })
    }

    /// Returns a durable no-capture owner without treating tracked launches as
    /// equivalent. A caller may clear a matching owner only while holding both
    /// halves of that profile's process lease; a different owner remains live
    /// or crash-uncertain and must block exact adoption.
    pub(crate) fn untracked_for_workspace(
        &self,
        canonical_cwd: &Path,
    ) -> Result<Option<PendingLaunch>, ConversationError> {
        let canonical_cwd = canonical_path_string(canonical_cwd)?;
        self.read(|document| {
            Ok(document
                .pending_launches
                .iter()
                .find(|pending| {
                    pending.canonical_cwd == canonical_cwd && pending.mode.is_untracked()
                })
                .cloned())
        })
    }

    pub(crate) fn finish_launch(
        &self,
        launch_id: &str,
        resolution: LaunchResolution,
    ) -> Result<Option<HeadBinding>, ConversationError> {
        validate_uuid(launch_id, "launch id")?;
        self.transact(|document| {
            let index = document
                .pending_launches
                .iter()
                .position(|pending| pending.launch_id == launch_id)
                .ok_or(ConversationError::NotFound)?;
            let pending = document.pending_launches.remove(index);
            if pending.mode.is_untracked() {
                mark_head_needs_selection(document, &pending.canonical_cwd);
                return Ok(None);
            }
            if document.workspace_heads.iter().any(|head| {
                head.canonical_cwd == pending.canonical_cwd
                    && head.state == HeadState::NeedsSelection
            }) {
                return Ok(None);
            }

            match resolution {
                LaunchResolution::Bind(binding) => {
                    if binding.profile_id != pending.profile_id
                        || binding.canonical_cwd != pending.canonical_cwd
                        || pending.codex_version.as_deref() != Some(binding.codex_version.as_str())
                    {
                        mark_head_needs_selection(document, &pending.canonical_cwd);
                        return Ok(None);
                    }
                    bind_document(document, binding).map(Some)
                }
                LaunchResolution::NoThread => Ok(None),
                LaunchResolution::Ambiguous => {
                    mark_head_needs_selection(document, &pending.canonical_cwd);
                    Ok(None)
                }
            }
        })
    }

    /// Adopts an exact binding only while no launch owns the workspace.
    /// Same-profile recovery must resolve its pending launch before this write.
    pub(crate) fn adopt(&self, binding: BindingInput) -> Result<HeadBinding, ConversationError> {
        validate_binding_input(&binding)?;
        self.transact(|document| {
            ensure_workspace_not_transitioning(document, &binding.canonical_cwd)?;
            if document
                .pending_launches
                .iter()
                .any(|pending| pending.canonical_cwd == binding.canonical_cwd)
            {
                return Err(ConversationError::Ambiguous);
            }
            bind_document(document, binding)
        })
    }

    /// Refreshes lifecycle metadata only while the exact head adopted before
    /// provider spawn is still authoritative. A concurrent tracked or
    /// untracked launch may make the workspace ambiguous and then finish
    /// before this provider exits; checking the durable head prevents that
    /// older exact process from restoring `Ready` afterward.
    pub(crate) fn refresh_adopted(
        &self,
        expected: &HeadBinding,
        binding: BindingInput,
    ) -> Result<HeadBinding, ConversationError> {
        validate_binding_input(&binding)?;
        if expected.profile_id != binding.profile_id
            || expected.thread_id != binding.thread_id
            || expected.canonical_cwd != binding.canonical_cwd
            || expected.codex_version != binding.codex_version
        {
            return Err(ConversationError::Ambiguous);
        }
        self.transact(|document| {
            let current = resolve_head_document(document, &binding.canonical_cwd)?;
            if current.conversation_id != expected.conversation_id
                || current.generation != expected.generation
                || current.profile_id != expected.profile_id
                || current.thread_id != expected.thread_id
                || current.codex_version != expected.codex_version
            {
                return Err(ConversationError::Ambiguous);
            }
            bind_document(document, binding)
        })
    }

    pub(crate) fn resolve_head(
        &self,
        canonical_cwd: &Path,
    ) -> Result<HeadBinding, ConversationError> {
        let canonical_cwd = canonical_path_string(canonical_cwd)?;
        self.read(|document| resolve_head_document(document, &canonical_cwd))
    }

    /// Finds one exact immutable binding without consulting mutable workspace
    /// selection or launch state. Explicit recovery already names the profile,
    /// thread, and cwd, so it may use this only to retain persisted lifecycle
    /// metadata while a pending launch or `needs_selection` hides the head.
    pub(crate) fn find_bound_thread(
        &self,
        profile_id: &str,
        thread_id: &str,
        canonical_cwd: &Path,
    ) -> Result<Option<HeadBinding>, ConversationError> {
        validate_uuid(profile_id, "profile id")?;
        validate_uuid(thread_id, "thread id")?;
        let canonical_cwd = canonical_path_string(canonical_cwd)?;
        self.read(|document| {
            let binding = document.conversations.iter().find_map(|conversation| {
                let generation = conversation.generations.iter().find(|generation| {
                    generation.profile_id == profile_id
                        && generation.thread_id == thread_id
                        && generation.canonical_cwd == canonical_cwd
                })?;
                Some(HeadBinding {
                    conversation_id: conversation.conversation_id.clone(),
                    generation: generation.generation,
                    profile_id: generation.profile_id.clone(),
                    thread_id: generation.thread_id.clone(),
                    canonical_cwd: generation.canonical_cwd.clone(),
                    codex_version: generation.codex_version.clone(),
                    lifecycle: conversation.last_safe_lifecycle,
                })
            });
            Ok(binding)
        })
    }

    pub(crate) fn mark_workspace_ambiguous(
        &self,
        canonical_cwd: &Path,
    ) -> Result<(), ConversationError> {
        let canonical_cwd = canonical_path_string(canonical_cwd)?;
        self.transact(|document| {
            ensure_workspace_not_transitioning(document, &canonical_cwd)?;
            mark_head_needs_selection(document, &canonical_cwd);
            Ok(())
        })
    }

    /// Durably opts one workspace out of automatic conversation capture.
    ///
    /// The selected profile is validated at the boundary, while pending
    /// ownership is intentionally checked by canonical workspace regardless
    /// of profile. An unresolved launch must be reconciled before another
    /// provider can make that workspace's thread history more ambiguous.
    pub(crate) fn prepare_untracked(
        &self,
        profile_id: &str,
        canonical_cwd: &Path,
        mode: LaunchMode,
    ) -> Result<String, ConversationError> {
        validate_uuid(profile_id, "profile id")?;
        if !mode.is_untracked() {
            return Err(ConversationError::RegistryInvalid(
                "untracked preparation requires an untracked mode".to_owned(),
            ));
        }
        let canonical_cwd = canonical_path_string(canonical_cwd)?;
        let launch_id = Uuid::new_v4().to_string();
        let pending = PendingLaunch {
            launch_id: launch_id.clone(),
            profile_id: profile_id.to_owned(),
            canonical_cwd: canonical_cwd.clone(),
            mode,
            codex_version: None,
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            pre_inventory: Vec::new(),
            phase: PendingPhase::Prepared,
            started_at: unix_timestamp()?,
        };
        self.transact(|document| {
            ensure_workspace_not_transitioning(document, &canonical_cwd)?;
            if document
                .pending_launches
                .iter()
                .any(|pending| pending.canonical_cwd == canonical_cwd)
            {
                return Err(ConversationError::Ambiguous);
            }
            mark_head_needs_selection(document, &canonical_cwd);
            document.pending_launches.push(pending);
            Ok(launch_id)
        })
    }

    /// Starts the only durable cross-profile transition in the registry.
    ///
    /// The caller supplies already-validated, provider-free metadata. No
    /// provider process or filesystem rollout is opened while the short
    /// conversation lock is held.
    #[cfg_attr(not(test), allow(dead_code))] // Wired by issue #34.
    pub(crate) fn prepare_handoff(
        &self,
        preparation: HandoffPreparation,
    ) -> Result<HandoffTransition, ConversationError> {
        validate_uuid(
            &preparation.expected_source.conversation_id,
            "conversation id",
        )?;
        validate_uuid(&preparation.expected_source.profile_id, "source profile id")?;
        validate_uuid(&preparation.expected_source.thread_id, "source thread id")?;
        validate_stored_path(&preparation.expected_source.canonical_cwd)?;
        validate_codex_version(&preparation.expected_source.codex_version)?;
        validate_uuid(&preparation.target_profile_id, "target profile id")?;
        validate_uuid(&preparation.trust_domain_id, "trust domain id")?;
        validate_rollout(&preparation.source_rollout)?;
        if preparation.reason == HandoffReason::UnknownLegacy {
            return Err(ConversationError::RegistryInvalid(
                "a new handoff requires an explicit reason".to_owned(),
            ));
        }
        if preparation.expected_source.profile_id == preparation.target_profile_id {
            return Err(ConversationError::RegistryInvalid(
                "handoff target must use a different profile".to_owned(),
            ));
        }

        self.transact_v2(|document| {
            if document.active_transition.is_some() {
                return Err(ConversationError::TransitionBusy);
            }
            if document
                .pending_launches
                .iter()
                .any(|pending| pending.canonical_cwd == preparation.expected_source.canonical_cwd)
            {
                return Err(ConversationError::Ambiguous);
            }
            let current =
                resolve_head_document(document, &preparation.expected_source.canonical_cwd)?;
            if current != preparation.expected_source {
                return Err(ConversationError::Ambiguous);
            }

            let conversation = document
                .conversations
                .iter_mut()
                .find(|conversation| {
                    conversation.conversation_id == preparation.expected_source.conversation_id
                })
                .ok_or(ConversationError::NotFound)?;
            if conversation.active_generation != preparation.expected_source.generation {
                return Err(ConversationError::Ambiguous);
            }
            let source = conversation
                .generations
                .iter_mut()
                .find(|generation| generation.generation == conversation.active_generation)
                .ok_or_else(|| {
                    ConversationError::RegistryInvalid(
                        "active handoff source generation is missing".to_owned(),
                    )
                })?;
            if source.profile_id != preparation.expected_source.profile_id
                || source.thread_id != preparation.expected_source.thread_id
                || source.canonical_cwd != preparation.expected_source.canonical_cwd
            {
                return Err(ConversationError::Ambiguous);
            }
            match (&source.trust_domain_id, &source.rollout) {
                (None, None) => {
                    source.trust_domain_id = Some(preparation.trust_domain_id.clone());
                    source.rollout = Some(preparation.source_rollout.clone());
                }
                (Some(trust_domain_id), Some(rollout))
                    if trust_domain_id == &preparation.trust_domain_id
                        && rollout == &preparation.source_rollout => {}
                _ => {
                    return Err(ConversationError::RegistryInvalid(
                        "handoff source metadata conflicts with its lineage".to_owned(),
                    ));
                }
            }

            let target_generation = source.generation.checked_add(1).ok_or_else(|| {
                ConversationError::RegistryInvalid("generation overflow".to_owned())
            })?;
            let now = unix_timestamp()?;
            let transition = HandoffTransition {
                transition_id: Uuid::new_v4().to_string(),
                conversation_id: conversation.conversation_id.clone(),
                source_generation: source.generation,
                target_generation,
                source_profile_id: source.profile_id.clone(),
                target_profile_id: preparation.target_profile_id,
                canonical_cwd: source.canonical_cwd.clone(),
                trust_domain_id: preparation.trust_domain_id,
                reason: preparation.reason,
                source_rollout: preparation.source_rollout,
                phase: HandoffPhase::Prepared,
                target_baseline_thread_ids: Vec::new(),
                fork_attempts: 0,
                fork_requested_at: None,
                observed_target: None,
                prepared_at: now,
                updated_at: now,
            };
            document.active_transition = Some(transition.clone());
            Ok(transition)
        })
    }

    #[cfg_attr(not(test), allow(dead_code))] // Wired by issue #34 recovery.
    pub(crate) fn current_handoff(&self) -> Result<Option<HandoffTransition>, ConversationError> {
        self.read(|document| Ok(document.active_transition.clone()))
    }

    #[cfg_attr(not(test), allow(dead_code))] // Wired by issue #34.
    pub(crate) fn mark_source_stop_requested(
        &self,
        transition_id: &str,
    ) -> Result<HandoffTransition, ConversationError> {
        self.advance_handoff_phase(
            transition_id,
            HandoffPhase::Prepared,
            HandoffPhase::SourceStopRequested,
        )
    }

    #[cfg_attr(not(test), allow(dead_code))] // Wired by issue #34.
    pub(crate) fn mark_source_stopped(
        &self,
        transition_id: &str,
    ) -> Result<HandoffTransition, ConversationError> {
        self.advance_handoff_phase(
            transition_id,
            HandoffPhase::SourceStopRequested,
            HandoffPhase::SourceStopped,
        )
    }

    #[cfg_attr(not(test), allow(dead_code))] // Wired by issue #34.
    pub(crate) fn record_fork_intent(
        &self,
        transition_id: &str,
        target_baseline_thread_ids: Vec<String>,
    ) -> Result<HandoffTransition, ConversationError> {
        validate_uuid(transition_id, "transition id")?;
        validate_thread_baseline(&target_baseline_thread_ids)?;
        self.transact_v2(|document| {
            let transition =
                exact_transition_mut(document, transition_id, HandoffPhase::SourceStopped)?;
            if transition.fork_attempts != 0
                || transition.fork_requested_at.is_some()
                || !transition.target_baseline_thread_ids.is_empty()
            {
                return Err(ConversationError::TransitionPhaseInvalid);
            }
            let now = unix_timestamp()?;
            transition.phase = HandoffPhase::ForkRequested;
            transition.target_baseline_thread_ids = target_baseline_thread_ids;
            transition.fork_attempts = 1;
            transition.fork_requested_at = Some(now);
            transition.updated_at = now;
            Ok(transition.clone())
        })
    }

    /// Persists the only retry authorization before a second fork request.
    ///
    /// A crash after this write but before the request leaves attempt two
    /// consumed. Recovery may reconcile candidates but must never mint a third
    /// request from an ambiguous absence.
    #[cfg_attr(not(test), allow(dead_code))] // Consumed by issue #34 recovery.
    pub(crate) fn record_bounded_fork_retry(
        &self,
        transition_id: &str,
    ) -> Result<HandoffTransition, ConversationError> {
        validate_uuid(transition_id, "transition id")?;
        self.transact_v2(|document| {
            let transition =
                exact_transition_mut(document, transition_id, HandoffPhase::ForkRequested)?;
            if transition.fork_attempts != 1
                || transition.fork_requested_at.is_none()
                || transition.observed_target.is_some()
            {
                return Err(ConversationError::TransitionPhaseInvalid);
            }
            let now = unix_timestamp()?;
            transition.fork_attempts = 2;
            transition.fork_requested_at = Some(now);
            transition.updated_at = now;
            Ok(transition.clone())
        })
    }

    #[cfg_attr(not(test), allow(dead_code))] // Wired by issue #34.
    pub(crate) fn observe_handoff_target(
        &self,
        transition_id: &str,
        target: HandoffTarget,
    ) -> Result<HandoffTransition, ConversationError> {
        validate_uuid(transition_id, "transition id")?;
        validate_uuid(&target.thread_id, "target thread id")?;
        validate_stored_path(&target.canonical_cwd)?;
        validate_codex_version(&target.codex_version)?;
        validate_rollout(&target.rollout)?;
        self.transact_v2(|document| {
            let transition_snapshot = document
                .active_transition
                .as_ref()
                .filter(|transition| transition.transition_id == transition_id)
                .cloned()
                .ok_or(ConversationError::NotFound)?;
            if transition_snapshot.phase != HandoffPhase::ForkRequested {
                return Err(ConversationError::TransitionPhaseInvalid);
            }
            if target.canonical_cwd != transition_snapshot.canonical_cwd
                || same_rollout_file(&target.rollout, &transition_snapshot.source_rollout)
            {
                return Err(ConversationError::RegistryInvalid(
                    "observed handoff target conflicts with the source".to_owned(),
                ));
            }
            let source_thread = document
                .conversations
                .iter()
                .find(|conversation| {
                    conversation.conversation_id == transition_snapshot.conversation_id
                })
                .and_then(|conversation| {
                    conversation.generations.iter().find(|generation| {
                        generation.generation == transition_snapshot.source_generation
                    })
                })
                .map(|generation| generation.thread_id.as_str())
                .ok_or_else(|| {
                    ConversationError::RegistryInvalid(
                        "handoff source generation is missing".to_owned(),
                    )
                })?;
            if target.thread_id == source_thread
                || document.conversations.iter().any(|conversation| {
                    conversation
                        .generations
                        .iter()
                        .any(|generation| generation.thread_id == target.thread_id)
                })
            {
                return Err(ConversationError::RegistryInvalid(
                    "observed handoff target thread is not new".to_owned(),
                ));
            }
            let now = unix_timestamp()?;
            let transition = document
                .active_transition
                .as_mut()
                .ok_or(ConversationError::NotFound)?;
            transition.observed_target = Some(ObservedHandoffTarget {
                thread_id: target.thread_id,
                canonical_cwd: target.canonical_cwd,
                codex_version: target.codex_version,
                adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
                rollout: target.rollout,
                observed_at: now,
            });
            transition.phase = HandoffPhase::ForkObserved;
            transition.updated_at = now;
            Ok(transition.clone())
        })
    }

    #[cfg_attr(not(test), allow(dead_code))] // Wired by issue #34.
    pub(crate) fn commit_handoff(
        &self,
        transition_id: &str,
    ) -> Result<HeadBinding, ConversationError> {
        validate_uuid(transition_id, "transition id")?;
        self.transact_v2(|document| {
            let transition = document
                .active_transition
                .as_ref()
                .filter(|transition| transition.transition_id == transition_id)
                .cloned()
                .ok_or(ConversationError::NotFound)?;
            if transition.phase != HandoffPhase::ForkObserved {
                return Err(ConversationError::TransitionPhaseInvalid);
            }
            let target = transition.observed_target.clone().ok_or_else(|| {
                ConversationError::RegistryInvalid("observed handoff target is missing".to_owned())
            })?;
            if document.conversations.iter().any(|conversation| {
                conversation
                    .generations
                    .iter()
                    .any(|generation| generation.thread_id == target.thread_id)
            }) {
                return Err(ConversationError::RegistryInvalid(
                    "handoff target thread is already bound".to_owned(),
                ));
            }

            let conversation = document
                .conversations
                .iter_mut()
                .find(|conversation| conversation.conversation_id == transition.conversation_id)
                .ok_or(ConversationError::NotFound)?;
            if conversation.active_generation != transition.source_generation
                || conversation.generations.len() >= MAX_LINEAGE_GENERATIONS
            {
                return Err(ConversationError::TransitionPhaseInvalid);
            }
            conversation.generations.push(ConversationGeneration {
                generation: transition.target_generation,
                profile_id: transition.target_profile_id.clone(),
                thread_id: target.thread_id.clone(),
                canonical_cwd: target.canonical_cwd.clone(),
                codex_version: target.codex_version.clone(),
                adapter_version: target.adapter_version,
                bound_at: target.observed_at,
                trust_domain_id: Some(transition.trust_domain_id.clone()),
                rollout: Some(target.rollout),
            });
            conversation.active_generation = transition.target_generation;
            conversation.last_safe_lifecycle = ConversationLifecycle::Interrupted;

            let head = document
                .workspace_heads
                .iter_mut()
                .find(|head| {
                    head.provider == conversation.provider
                        && head.canonical_cwd == transition.canonical_cwd
                })
                .ok_or_else(|| {
                    ConversationError::RegistryInvalid(
                        "handoff workspace head is missing".to_owned(),
                    )
                })?;
            if head.state != HeadState::Ready
                || head.conversation_id.as_deref() != Some(transition.conversation_id.as_str())
                || head.generation != Some(transition.source_generation)
            {
                return Err(ConversationError::TransitionPhaseInvalid);
            }
            head.generation = Some(transition.target_generation);

            let now = unix_timestamp()?;
            let current = document
                .active_transition
                .as_mut()
                .ok_or(ConversationError::NotFound)?;
            current.phase = HandoffPhase::CommittedUnattached;
            current.updated_at = now;

            Ok(HeadBinding {
                conversation_id: transition.conversation_id,
                generation: transition.target_generation,
                profile_id: transition.target_profile_id,
                thread_id: target.thread_id,
                canonical_cwd: target.canonical_cwd,
                codex_version: target.codex_version,
                lifecycle: ConversationLifecycle::Interrupted,
            })
        })
    }

    #[cfg_attr(not(test), allow(dead_code))] // Wired by issue #34.
    pub(crate) fn finish_handoff_attachment(
        &self,
        transition_id: &str,
    ) -> Result<HeadBinding, ConversationError> {
        validate_uuid(transition_id, "transition id")?;
        self.transact_v2(|document| {
            let transition = document
                .active_transition
                .as_ref()
                .filter(|transition| transition.transition_id == transition_id)
                .ok_or(ConversationError::NotFound)?;
            if transition.phase != HandoffPhase::CommittedUnattached {
                return Err(ConversationError::TransitionPhaseInvalid);
            }
            let canonical_cwd = transition.canonical_cwd.clone();
            document.active_transition = None;
            resolve_head_document(document, &canonical_cwd)
        })
    }

    #[cfg_attr(not(test), allow(dead_code))] // Wired by issue #34.
    fn advance_handoff_phase(
        &self,
        transition_id: &str,
        expected: HandoffPhase,
        next: HandoffPhase,
    ) -> Result<HandoffTransition, ConversationError> {
        validate_uuid(transition_id, "transition id")?;
        self.transact_v2(|document| {
            let transition = exact_transition_mut(document, transition_id, expected)?;
            transition.phase = next;
            transition.updated_at = unix_timestamp()?;
            Ok(transition.clone())
        })
    }

    fn read<T>(
        &self,
        operation: impl FnOnce(&ConversationDocument) -> Result<T, ConversationError>,
    ) -> Result<T, ConversationError> {
        if !self.root.exists() {
            return Err(ConversationError::NotFound);
        }
        verify_private_directory(&self.root)?;
        let lock = open_lock(&self.root.join(LOCK_FILE))?;
        FileExt::lock_exclusive(&lock)?;
        let document = self.load()?;
        operation(&document)
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut ConversationDocument) -> Result<T, ConversationError>,
    ) -> Result<T, ConversationError> {
        verify_private_directory(&self.root)?;
        let lock = open_lock(&self.root.join(LOCK_FILE))?;
        FileExt::lock_exclusive(&lock)?;
        let mut document = self.load()?;
        let result = operation(&mut document)?;
        document.revision = document
            .revision
            .checked_add(1)
            .ok_or_else(|| ConversationError::RegistryInvalid("revision overflow".to_owned()))?;
        self.save(&document)?;
        Ok(result)
    }

    #[cfg_attr(not(test), allow(dead_code))] // Called only by staged handoff APIs.
    fn transact_v2<T>(
        &self,
        operation: impl FnOnce(&mut ConversationDocument) -> Result<T, ConversationError>,
    ) -> Result<T, ConversationError> {
        verify_private_directory(&self.root)?;
        let lock = open_lock(&self.root.join(LOCK_FILE))?;
        FileExt::lock_exclusive(&lock)?;
        let original = self.load()?;
        let mut document = original.clone();
        let migrated = document.schema_version == SCHEMA_VERSION_V1;
        if migrated {
            let backup_bytes = serialize_v1_document(&original)?;
            document.schema_version = SCHEMA_VERSION_V2;
            document.pre_migration_backup = Some(PreMigrationBackup {
                schema_version: SCHEMA_VERSION_V1,
                revision: original.revision,
                sha256: sha256_hex(&backup_bytes),
            });
        }
        let result = operation(&mut document)?;
        document.revision = document
            .revision
            .checked_add(1)
            .ok_or_else(|| ConversationError::RegistryInvalid("revision overflow".to_owned()))?;
        validate_document(&document)?;
        if migrated {
            self.save_pre_migration_backup(
                &original,
                document.pre_migration_backup.as_ref().ok_or_else(|| {
                    ConversationError::RegistryInvalid(
                        "v2 pre-migration backup metadata is missing".to_owned(),
                    )
                })?,
            )?;
        }
        self.save(&document)?;
        Ok(result)
    }

    fn load(&self) -> Result<ConversationDocument, ConversationError> {
        let path = self.root.join(REGISTRY_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => verify_private_regular_file(&path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ConversationDocument::default());
            }
            Err(error) => return Err(error.into()),
        }
        let mut bytes = Vec::new();
        File::open(&path)?
            .take((MAX_REGISTRY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(ConversationError::RegistryInvalid(
                "registry exceeds its size limit".to_owned(),
            ));
        }
        let document: ConversationDocument = serde_json::from_slice(&bytes).map_err(|_| {
            ConversationError::RegistryInvalid(
                "registry is not valid conversation schema JSON".to_owned(),
            )
        })?;
        if !matches!(
            document.schema_version,
            SCHEMA_VERSION_V1 | SCHEMA_VERSION_V2
        ) {
            return Err(ConversationError::RegistryInvalid(format!(
                "unsupported conversation registry schema {}",
                document.schema_version
            )));
        }
        validate_document(&document)?;
        if let Some(metadata) = &document.pre_migration_backup {
            self.verify_pre_migration_backup(metadata)?;
        }
        Ok(document)
    }

    #[cfg_attr(not(test), allow(dead_code))] // Called only by staged handoff APIs.
    fn save_pre_migration_backup(
        &self,
        document: &ConversationDocument,
        metadata: &PreMigrationBackup,
    ) -> Result<(), ConversationError> {
        let bytes = serialize_v1_document(document)?;
        if metadata.schema_version != SCHEMA_VERSION_V1
            || metadata.revision != document.revision
            || metadata.sha256 != sha256_hex(&bytes)
        {
            return Err(ConversationError::RegistryInvalid(
                "pre-migration backup metadata does not match schema v1".to_owned(),
            ));
        }

        let destination = self.root.join(PRE_MIGRATION_BACKUP_FILE);
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                verify_private_regular_file(&destination)?;
                let mut existing = Vec::new();
                File::open(&destination)?
                    .take((MAX_REGISTRY_BYTES + 1) as u64)
                    .read_to_end(&mut existing)?;
                if existing.len() > MAX_REGISTRY_BYTES {
                    return Err(ConversationError::RegistryInvalid(
                        "pre-migration backup exceeds its size limit".to_owned(),
                    ));
                }
                let existing_document: ConversationDocument = serde_json::from_slice(&existing)
                    .map_err(|_| {
                        ConversationError::RegistryInvalid(
                            "pre-migration backup is invalid".to_owned(),
                        )
                    })?;
                validate_v1_document(&existing_document)?;
                if existing_document == *document && sha256_hex(&existing) == metadata.sha256 {
                    return sync_directory(&self.root)
                        .map_err(|_| ConversationError::CommitUncertain);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let temporary_name = format!(".{PRE_MIGRATION_BACKUP_FILE}.{}.tmp", Uuid::new_v4());
        let temporary = self.root.join(&temporary_name);
        let publication = (|| {
            let mut options = private_open_options();
            let mut file = options.write(true).create_new(true).open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            verify_private_regular_file(&temporary)?;
            drop(file);
            fs::rename(&temporary, &destination)?;
            Ok::<(), ConversationError>(())
        })();
        if let Err(error) = publication {
            if fs::symlink_metadata(&temporary).is_ok() {
                let _ =
                    remove_exact_temporary(&temporary, PRE_MIGRATION_BACKUP_FILE, &temporary_name);
            }
            return Err(error);
        }
        if sync_directory(&self.root).is_err() {
            return Err(ConversationError::CommitUncertain);
        }
        Ok(())
    }

    fn verify_pre_migration_backup(
        &self,
        metadata: &PreMigrationBackup,
    ) -> Result<(), ConversationError> {
        let path = self.root.join(PRE_MIGRATION_BACKUP_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => verify_private_regular_file(&path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ConversationError::RegistryInvalid(
                    "schema v2 pre-migration backup is missing".to_owned(),
                ));
            }
            Err(error) => return Err(error.into()),
        }
        let mut bytes = Vec::new();
        File::open(&path)?
            .take((MAX_REGISTRY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_REGISTRY_BYTES || sha256_hex(&bytes) != metadata.sha256 {
            return Err(ConversationError::RegistryInvalid(
                "schema v2 pre-migration backup does not match its digest".to_owned(),
            ));
        }
        let backup: ConversationDocument = serde_json::from_slice(&bytes).map_err(|_| {
            ConversationError::RegistryInvalid(
                "schema v2 pre-migration backup is invalid".to_owned(),
            )
        })?;
        validate_v1_document(&backup)?;
        if metadata.schema_version != backup.schema_version || metadata.revision != backup.revision
        {
            return Err(ConversationError::RegistryInvalid(
                "schema v2 pre-migration backup revision is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    fn save(&self, document: &ConversationDocument) -> Result<(), ConversationError> {
        validate_document(document)?;
        let bytes = serde_json::to_vec_pretty(document).map_err(|_| {
            ConversationError::RegistryInvalid("registry serialization failed".to_owned())
        })?;
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(ConversationError::RegistryInvalid(
                "registry exceeds its size limit".to_owned(),
            ));
        }
        let temporary_name = format!(".{REGISTRY_FILE}.{}.tmp", Uuid::new_v4());
        let temporary = self.root.join(&temporary_name);
        let destination = self.root.join(REGISTRY_FILE);
        let publication = (|| {
            let mut options = private_open_options();
            let mut file = options.write(true).create_new(true).open(&temporary)?;
            file.write_all(&bytes)?;

            #[cfg(test)]
            if self.fault == Some(WriteFault::BeforeFileSync) {
                return Err(ConversationError::Io(io::Error::other(
                    "injected failure before file sync",
                )));
            }

            file.sync_all()?;
            verify_private_regular_file(&temporary)?;
            drop(file);

            #[cfg(test)]
            if self.fault == Some(WriteFault::BeforeRename) {
                return Err(ConversationError::Io(io::Error::other(
                    "injected failure before rename",
                )));
            }

            fs::rename(&temporary, &destination)?;
            Ok::<(), ConversationError>(())
        })();
        if let Err(error) = publication {
            if fs::symlink_metadata(&temporary).is_ok() {
                let _ = remove_exact_temporary(&temporary, REGISTRY_FILE, &temporary_name);
            }
            return Err(error);
        }

        #[cfg(test)]
        if self.fault == Some(WriteFault::AfterRename) {
            return Err(self.confirm_uncertain_commit(document.revision));
        }

        #[cfg(test)]
        if self.fault == Some(WriteFault::DirectorySync) {
            return Err(self.confirm_uncertain_commit(document.revision));
        }

        if sync_directory(&self.root).is_err() {
            return Err(self.confirm_uncertain_commit(document.revision));
        }
        Ok(())
    }

    /// A failed directory fsync happens after the atomic rename. Read back the
    /// exact intended revision so callers know that retrying the provider
    /// launch would risk duplication, while still reporting durability as
    /// uncertain. Readback failure is deliberately collapsed to the same safe
    /// state: neither outcome authorizes a second launch.
    fn confirm_uncertain_commit(&self, intended_revision: u64) -> ConversationError {
        let _intended_revision_is_visible = self
            .load()
            .is_ok_and(|document| document.revision == intended_revision);
        ConversationError::CommitUncertain
    }

    #[cfg(test)]
    pub(crate) fn at(root: PathBuf) -> Self {
        Self { root, fault: None }
    }

    #[cfg(test)]
    fn with_fault(&self, fault: WriteFault) -> Self {
        Self {
            root: self.root.clone(),
            fault: Some(fault),
        }
    }
}

fn serialize_v1_document(document: &ConversationDocument) -> Result<Vec<u8>, ConversationError> {
    validate_v1_document(document)?;
    let bytes = serde_json::to_vec_pretty(document).map_err(|_| {
        ConversationError::RegistryInvalid("registry serialization failed".to_owned())
    })?;
    if bytes.len() > MAX_REGISTRY_BYTES {
        return Err(ConversationError::RegistryInvalid(
            "registry exceeds its size limit".to_owned(),
        ));
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn bind_document(
    document: &mut ConversationDocument,
    binding: BindingInput,
) -> Result<HeadBinding, ConversationError> {
    validate_binding_input(&binding)?;
    ensure_workspace_not_transitioning(document, &binding.canonical_cwd)?;

    if document.conversations.iter().any(|conversation| {
        conversation.generations.iter().any(|generation| {
            generation.thread_id == binding.thread_id && generation.profile_id != binding.profile_id
        })
    }) {
        return Err(ConversationError::ProfileMismatch);
    }

    let existing = document.conversations.iter_mut().find(|conversation| {
        conversation.generations.iter().any(|generation| {
            generation.profile_id == binding.profile_id && generation.thread_id == binding.thread_id
        })
    });

    let (conversation_id, generation) = if let Some(conversation) = existing {
        let generation = conversation
            .generations
            .iter()
            .find(|generation| {
                generation.profile_id == binding.profile_id
                    && generation.thread_id == binding.thread_id
            })
            .ok_or_else(|| ConversationError::RegistryInvalid("missing generation".to_owned()))?;
        if generation.generation != conversation.active_generation {
            return Err(ConversationError::Ambiguous);
        }
        if generation.canonical_cwd != binding.canonical_cwd {
            return Err(ConversationError::CwdMismatch);
        }
        conversation.last_safe_lifecycle = binding.lifecycle;
        (conversation.conversation_id.clone(), generation.generation)
    } else {
        let conversation_id = Uuid::new_v4().to_string();
        let generation = ConversationGeneration {
            generation: 0,
            profile_id: binding.profile_id.clone(),
            thread_id: binding.thread_id.clone(),
            canonical_cwd: binding.canonical_cwd.clone(),
            codex_version: binding.codex_version.clone(),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            bound_at: unix_timestamp()?,
            trust_domain_id: None,
            rollout: None,
        };
        document.conversations.push(Conversation {
            conversation_id: conversation_id.clone(),
            provider: Provider::Codex,
            generations: vec![generation],
            active_generation: 0,
            last_safe_lifecycle: binding.lifecycle,
        });
        (conversation_id, 0)
    };

    document.workspace_heads.retain(|head| {
        !(head.provider == Provider::Codex && head.canonical_cwd == binding.canonical_cwd)
    });
    document.workspace_heads.push(WorkspaceHead {
        provider: Provider::Codex,
        canonical_cwd: binding.canonical_cwd.clone(),
        state: HeadState::Ready,
        conversation_id: Some(conversation_id.clone()),
        generation: Some(generation),
    });

    Ok(HeadBinding {
        conversation_id,
        generation,
        profile_id: binding.profile_id,
        thread_id: binding.thread_id,
        canonical_cwd: binding.canonical_cwd,
        codex_version: binding.codex_version,
        lifecycle: binding.lifecycle,
    })
}

fn resolve_head_document(
    document: &ConversationDocument,
    canonical_cwd: &str,
) -> Result<HeadBinding, ConversationError> {
    if document
        .active_transition
        .as_ref()
        .is_some_and(|transition| transition.canonical_cwd == canonical_cwd)
    {
        return Err(ConversationError::TransitionBusy);
    }
    if document
        .pending_launches
        .iter()
        .any(|pending| pending.canonical_cwd == canonical_cwd)
    {
        return Err(ConversationError::Ambiguous);
    }
    let head = document
        .workspace_heads
        .iter()
        .find(|head| head.provider == Provider::Codex && head.canonical_cwd == canonical_cwd)
        .ok_or(ConversationError::NotFound)?;
    if head.state != HeadState::Ready {
        return Err(ConversationError::Ambiguous);
    }
    let conversation_id = head.conversation_id.as_deref().ok_or_else(|| {
        ConversationError::RegistryInvalid("ready head has no conversation".to_owned())
    })?;
    let generation_number = head.generation.ok_or_else(|| {
        ConversationError::RegistryInvalid("ready head has no generation".to_owned())
    })?;
    let conversation = document
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == conversation_id)
        .ok_or_else(|| {
            ConversationError::RegistryInvalid("head conversation is missing".to_owned())
        })?;
    let generation = conversation
        .generations
        .iter()
        .find(|generation| generation.generation == generation_number)
        .ok_or_else(|| {
            ConversationError::RegistryInvalid("head generation is missing".to_owned())
        })?;
    Ok(HeadBinding {
        conversation_id: conversation.conversation_id.clone(),
        generation: generation.generation,
        profile_id: generation.profile_id.clone(),
        thread_id: generation.thread_id.clone(),
        canonical_cwd: generation.canonical_cwd.clone(),
        codex_version: generation.codex_version.clone(),
        lifecycle: conversation.last_safe_lifecycle,
    })
}

fn mark_head_needs_selection(document: &mut ConversationDocument, canonical_cwd: &str) {
    if let Some(head) = document
        .workspace_heads
        .iter_mut()
        .find(|head| head.provider == Provider::Codex && head.canonical_cwd == canonical_cwd)
    {
        head.state = HeadState::NeedsSelection;
        return;
    }
    document.workspace_heads.push(WorkspaceHead {
        provider: Provider::Codex,
        canonical_cwd: canonical_cwd.to_owned(),
        state: HeadState::NeedsSelection,
        conversation_id: None,
        generation: None,
    });
}

fn find_pending_mut<'a>(
    document: &'a mut ConversationDocument,
    launch_id: &str,
) -> Result<&'a mut PendingLaunch, ConversationError> {
    document
        .pending_launches
        .iter_mut()
        .find(|pending| pending.launch_id == launch_id)
        .ok_or(ConversationError::NotFound)
}

#[cfg_attr(not(test), allow(dead_code))] // Called only by staged handoff APIs.
fn exact_transition_mut<'a>(
    document: &'a mut ConversationDocument,
    transition_id: &str,
    expected: HandoffPhase,
) -> Result<&'a mut HandoffTransition, ConversationError> {
    let transition = document
        .active_transition
        .as_mut()
        .filter(|transition| transition.transition_id == transition_id)
        .ok_or(ConversationError::NotFound)?;
    if transition.phase != expected {
        return Err(ConversationError::TransitionPhaseInvalid);
    }
    Ok(transition)
}

fn ensure_workspace_not_transitioning(
    document: &ConversationDocument,
    canonical_cwd: &str,
) -> Result<(), ConversationError> {
    if document
        .active_transition
        .as_ref()
        .is_some_and(|transition| transition.canonical_cwd == canonical_cwd)
    {
        return Err(ConversationError::TransitionBusy);
    }
    Ok(())
}

fn validate_binding_input(binding: &BindingInput) -> Result<(), ConversationError> {
    validate_uuid(&binding.profile_id, "profile id")?;
    validate_uuid(&binding.thread_id, "thread id")?;
    validate_stored_path(&binding.canonical_cwd)?;
    validate_codex_version(&binding.codex_version)?;
    if matches!(
        binding.lifecycle,
        ConversationLifecycle::Missing
            | ConversationLifecycle::Archived
            | ConversationLifecycle::Incompatible
            | ConversationLifecycle::Ambiguous
    ) {
        return Err(ConversationError::RegistryInvalid(
            "an unusable lifecycle cannot become a ready head".to_owned(),
        ));
    }
    Ok(())
}

fn validate_document(document: &ConversationDocument) -> Result<(), ConversationError> {
    if !matches!(
        document.schema_version,
        SCHEMA_VERSION_V1 | SCHEMA_VERSION_V2
    ) {
        return Err(ConversationError::RegistryInvalid(
            "unsupported conversation registry schema".to_owned(),
        ));
    }

    if document.schema_version == SCHEMA_VERSION_V1 {
        return validate_v1_document(document);
    }

    validate_v2_document(document)
}

fn validate_v1_document(document: &ConversationDocument) -> Result<(), ConversationError> {
    if document.schema_version != SCHEMA_VERSION_V1
        || document.pre_migration_backup.is_some()
        || document.active_transition.is_some()
    {
        return Err(ConversationError::RegistryInvalid(
            "schema v1 contains v2 state".to_owned(),
        ));
    }

    validate_document_contents(document, true)
}

fn validate_v2_document(document: &ConversationDocument) -> Result<(), ConversationError> {
    if document.schema_version != SCHEMA_VERSION_V2 {
        return Err(ConversationError::RegistryInvalid(
            "schema v2 version is invalid".to_owned(),
        ));
    }

    let backup = document.pre_migration_backup.as_ref().ok_or_else(|| {
        ConversationError::RegistryInvalid(
            "schema v2 pre-migration backup metadata is missing".to_owned(),
        )
    })?;
    if backup.schema_version != SCHEMA_VERSION_V1
        || backup.revision > document.revision
        || backup.sha256.len() != 64
        || !backup
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConversationError::RegistryInvalid(
            "schema v2 pre-migration backup metadata is invalid".to_owned(),
        ));
    }

    validate_document_contents(document, false)?;
    validate_active_transition(document)
}

fn validate_document_contents(
    document: &ConversationDocument,
    schema_v1: bool,
) -> Result<(), ConversationError> {
    for (conversation_index, conversation) in document.conversations.iter().enumerate() {
        validate_uuid(&conversation.conversation_id, "conversation id")?;
        if conversation.provider != Provider::Codex
            || conversation.generations.is_empty()
            || conversation.generations.len() > MAX_LINEAGE_GENERATIONS
            || (schema_v1
                && (conversation.generations.len() != 1 || conversation.active_generation != 0))
        {
            return Err(ConversationError::RegistryInvalid(format!(
                "conversation {conversation_index} violates lineage bounds"
            )));
        }
        if !matches!(
            conversation.last_safe_lifecycle,
            ConversationLifecycle::Clean
                | ConversationLifecycle::Interrupted
                | ConversationLifecycle::UnknownCrash
        ) {
            return Err(ConversationError::RegistryInvalid(format!(
                "conversation {conversation_index} has an unusable lifecycle"
            )));
        }
        if conversation
            .generations
            .last()
            .map(|generation| generation.generation)
            != Some(conversation.active_generation)
        {
            return Err(ConversationError::RegistryInvalid(
                "active generation is not the ordered lineage tail".to_owned(),
            ));
        }
        let lineage_trust_domain = conversation
            .generations
            .iter()
            .find_map(|generation| generation.trust_domain_id.as_deref());
        for (generation_index, generation) in conversation.generations.iter().enumerate() {
            if generation.generation != u32::try_from(generation_index).unwrap_or(u32::MAX) {
                return Err(ConversationError::RegistryInvalid(
                    "lineage generations are duplicated or skipped".to_owned(),
                ));
            }
            validate_uuid(&generation.profile_id, "profile id")?;
            validate_uuid(&generation.thread_id, "thread id")?;
            validate_stored_path(&generation.canonical_cwd)?;
            validate_codex_version(&generation.codex_version)?;
            validate_adapter_version(&generation.adapter_version)?;
            if generation.bound_at < 0 {
                return Err(ConversationError::RegistryInvalid(
                    "binding timestamp is invalid".to_owned(),
                ));
            }
            if generation.canonical_cwd != conversation.generations[0].canonical_cwd {
                return Err(ConversationError::RegistryInvalid(
                    "lineage generations disagree on canonical cwd".to_owned(),
                ));
            }
            match (&generation.trust_domain_id, &generation.rollout) {
                (None, None) => {}
                (Some(trust_domain_id), Some(rollout)) if !schema_v1 => {
                    validate_uuid(trust_domain_id, "trust domain id")?;
                    validate_rollout(rollout)?;
                    if lineage_trust_domain != Some(trust_domain_id.as_str()) {
                        return Err(ConversationError::RegistryInvalid(
                            "lineage generations cross trust domains".to_owned(),
                        ));
                    }
                }
                _ => {
                    return Err(ConversationError::RegistryInvalid(
                        "generation handoff metadata is incomplete".to_owned(),
                    ));
                }
            }
            if !schema_v1
                && conversation.generations.len() > 1
                && (generation.trust_domain_id.is_none() || generation.rollout.is_none())
            {
                return Err(ConversationError::RegistryInvalid(
                    "multi-generation lineage lacks handoff metadata".to_owned(),
                ));
            }
            if schema_v1 && (generation.trust_domain_id.is_some() || generation.rollout.is_some()) {
                return Err(ConversationError::RegistryInvalid(
                    "schema v1 contains generation handoff metadata".to_owned(),
                ));
            }
        }
        for previous in document.conversations.iter().take(conversation_index) {
            if previous.conversation_id == conversation.conversation_id {
                return Err(ConversationError::RegistryInvalid(
                    "registry contains a duplicate conversation binding".to_owned(),
                ));
            }
        }
        for generation in &conversation.generations {
            if document
                .conversations
                .iter()
                .take(conversation_index)
                .flat_map(|previous| &previous.generations)
                .any(|previous| previous.thread_id == generation.thread_id)
                || conversation
                    .generations
                    .iter()
                    .take(generation.generation as usize)
                    .any(|previous| previous.thread_id == generation.thread_id)
            {
                return Err(ConversationError::RegistryInvalid(
                    "registry contains a duplicate conversation binding".to_owned(),
                ));
            }
        }
    }

    for (head_index, head) in document.workspace_heads.iter().enumerate() {
        validate_stored_path(&head.canonical_cwd)?;
        if document
            .workspace_heads
            .iter()
            .take(head_index)
            .any(|previous| {
                previous.provider == head.provider && previous.canonical_cwd == head.canonical_cwd
            })
        {
            return Err(ConversationError::RegistryInvalid(
                "registry contains duplicate workspace heads".to_owned(),
            ));
        }
        match head.state {
            HeadState::Ready => {
                let conversation_id = head.conversation_id.as_deref().ok_or_else(|| {
                    ConversationError::RegistryInvalid("ready head is incomplete".to_owned())
                })?;
                validate_uuid(conversation_id, "conversation id")?;
                let generation_number = head.generation.ok_or_else(|| {
                    ConversationError::RegistryInvalid("ready head is incomplete".to_owned())
                })?;
                let conversation = document
                    .conversations
                    .iter()
                    .find(|conversation| conversation.conversation_id == conversation_id)
                    .ok_or_else(|| {
                        ConversationError::RegistryInvalid(
                            "head references an unknown conversation".to_owned(),
                        )
                    })?;
                let generation = conversation
                    .generations
                    .iter()
                    .find(|generation| generation.generation == generation_number)
                    .ok_or_else(|| {
                        ConversationError::RegistryInvalid(
                            "head references an unknown generation".to_owned(),
                        )
                    })?;
                if conversation.provider != head.provider
                    || generation.canonical_cwd != head.canonical_cwd
                    || generation.generation != conversation.active_generation
                {
                    return Err(ConversationError::RegistryInvalid(
                        "head does not match its immutable generation".to_owned(),
                    ));
                }
            }
            HeadState::NeedsSelection => {
                if head.conversation_id.is_some() != head.generation.is_some() {
                    return Err(ConversationError::RegistryInvalid(
                        "ambiguous head is partially populated".to_owned(),
                    ));
                }
            }
        }
    }

    for (pending_index, pending) in document.pending_launches.iter().enumerate() {
        validate_uuid(&pending.launch_id, "launch id")?;
        validate_uuid(&pending.profile_id, "profile id")?;
        validate_stored_path(&pending.canonical_cwd)?;
        validate_adapter_version(&pending.adapter_version)?;
        if pending.started_at < 0 || pending.pre_inventory.len() > MAX_INVENTORY_THREADS {
            return Err(ConversationError::RegistryInvalid(
                "pending launch metadata is out of bounds".to_owned(),
            ));
        }
        if pending.mode.is_untracked() {
            if pending.codex_version.is_some() || !pending.pre_inventory.is_empty() {
                return Err(ConversationError::RegistryInvalid(
                    "untracked ownership contains capture metadata".to_owned(),
                ));
            }
        } else {
            validate_codex_version(pending.codex_version.as_deref().ok_or_else(|| {
                ConversationError::RegistryInvalid(
                    "tracked pending launch has no Codex version".to_owned(),
                )
            })?)?;
        }
        let mut inventory = pending.pre_inventory.clone();
        normalize_inventory(&mut inventory)?;
        if inventory != pending.pre_inventory {
            return Err(ConversationError::RegistryInvalid(
                "pending inventory is not canonical".to_owned(),
            ));
        }
        if document
            .pending_launches
            .iter()
            .take(pending_index)
            .any(|previous| {
                previous.launch_id == pending.launch_id
                    || previous.canonical_cwd == pending.canonical_cwd
            })
        {
            return Err(ConversationError::RegistryInvalid(
                "registry contains overlapping pending launches".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_active_transition(document: &ConversationDocument) -> Result<(), ConversationError> {
    let Some(transition) = &document.active_transition else {
        return Ok(());
    };
    validate_uuid(&transition.transition_id, "transition id")?;
    validate_uuid(&transition.conversation_id, "conversation id")?;
    validate_uuid(&transition.source_profile_id, "source profile id")?;
    validate_uuid(&transition.target_profile_id, "target profile id")?;
    validate_uuid(&transition.trust_domain_id, "trust domain id")?;
    validate_stored_path(&transition.canonical_cwd)?;
    validate_rollout(&transition.source_rollout)?;
    if transition.source_profile_id == transition.target_profile_id
        || transition.target_generation
            != transition.source_generation.checked_add(1).ok_or_else(|| {
                ConversationError::RegistryInvalid("generation overflow".to_owned())
            })?
        || transition.prepared_at < 0
        || transition.updated_at < transition.prepared_at
    {
        return Err(ConversationError::RegistryInvalid(
            "handoff transition metadata is invalid".to_owned(),
        ));
    }
    validate_thread_baseline(&transition.target_baseline_thread_ids)?;
    let fork_started = matches!(
        transition.phase,
        HandoffPhase::ForkRequested
            | HandoffPhase::ForkObserved
            | HandoffPhase::CommittedUnattached
    );
    if fork_started {
        let fork_requested_at = transition.fork_requested_at.ok_or_else(|| {
            ConversationError::RegistryInvalid(
                "handoff fork intent has no request timestamp".to_owned(),
            )
        })?;
        if !(1..=2).contains(&transition.fork_attempts)
            || fork_requested_at < transition.prepared_at
            || fork_requested_at > transition.updated_at
        {
            return Err(ConversationError::RegistryInvalid(
                "handoff fork intent metadata is invalid".to_owned(),
            ));
        }
    } else if transition.fork_attempts != 0
        || transition.fork_requested_at.is_some()
        || !transition.target_baseline_thread_ids.is_empty()
    {
        return Err(ConversationError::RegistryInvalid(
            "pre-fork handoff contains fork intent metadata".to_owned(),
        ));
    }

    let conversation = document
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == transition.conversation_id)
        .ok_or_else(|| {
            ConversationError::RegistryInvalid(
                "handoff transition conversation is missing".to_owned(),
            )
        })?;
    let source = conversation
        .generations
        .iter()
        .find(|generation| generation.generation == transition.source_generation)
        .ok_or_else(|| {
            ConversationError::RegistryInvalid("handoff source generation is missing".to_owned())
        })?;
    if source.profile_id != transition.source_profile_id
        || source.canonical_cwd != transition.canonical_cwd
        || source.trust_domain_id.as_deref() != Some(transition.trust_domain_id.as_str())
        || source.rollout.as_ref() != Some(&transition.source_rollout)
    {
        return Err(ConversationError::RegistryInvalid(
            "handoff source does not match its lineage".to_owned(),
        ));
    }

    let observed_required = matches!(
        transition.phase,
        HandoffPhase::ForkObserved | HandoffPhase::CommittedUnattached
    );
    if transition.observed_target.is_some() != observed_required {
        return Err(ConversationError::RegistryInvalid(
            "handoff target observation does not match its phase".to_owned(),
        ));
    }
    if let Some(target) = &transition.observed_target {
        validate_observed_target(target)?;
        if target.canonical_cwd != transition.canonical_cwd
            || target.thread_id == source.thread_id
            || same_rollout_file(&target.rollout, &transition.source_rollout)
            || target.observed_at < transition.prepared_at
            || transition
                .fork_requested_at
                .is_some_and(|requested_at| target.observed_at < requested_at)
            || target.observed_at > transition.updated_at
        {
            return Err(ConversationError::RegistryInvalid(
                "observed handoff target conflicts with the source".to_owned(),
            ));
        }
    }

    let committed = transition.phase == HandoffPhase::CommittedUnattached;
    let expected_active = if committed {
        transition.target_generation
    } else {
        transition.source_generation
    };
    if conversation.active_generation != expected_active {
        return Err(ConversationError::RegistryInvalid(
            "handoff transition does not match the active generation".to_owned(),
        ));
    }
    if committed {
        let target = transition.observed_target.as_ref().ok_or_else(|| {
            ConversationError::RegistryInvalid("committed handoff target is missing".to_owned())
        })?;
        let generation = conversation
            .generations
            .iter()
            .find(|generation| generation.generation == transition.target_generation)
            .ok_or_else(|| {
                ConversationError::RegistryInvalid(
                    "committed handoff generation is missing".to_owned(),
                )
            })?;
        if generation.profile_id != transition.target_profile_id
            || generation.thread_id != target.thread_id
            || generation.canonical_cwd != target.canonical_cwd
            || generation.codex_version != target.codex_version
            || generation.adapter_version != target.adapter_version
            || generation.trust_domain_id.as_deref() != Some(transition.trust_domain_id.as_str())
            || generation.rollout.as_ref() != Some(&target.rollout)
        {
            return Err(ConversationError::RegistryInvalid(
                "committed handoff target does not match its lineage".to_owned(),
            ));
        }
    } else if conversation
        .generations
        .iter()
        .any(|generation| generation.generation == transition.target_generation)
    {
        return Err(ConversationError::RegistryInvalid(
            "uncommitted handoff already has a target generation".to_owned(),
        ));
    }
    let head = document
        .workspace_heads
        .iter()
        .find(|head| {
            head.provider == conversation.provider && head.canonical_cwd == transition.canonical_cwd
        })
        .ok_or_else(|| {
            ConversationError::RegistryInvalid("handoff workspace head is missing".to_owned())
        })?;
    if head.state != HeadState::Ready
        || head.conversation_id.as_deref() != Some(transition.conversation_id.as_str())
        || head.generation != Some(expected_active)
    {
        return Err(ConversationError::RegistryInvalid(
            "handoff workspace head does not match its phase".to_owned(),
        ));
    }
    if document
        .pending_launches
        .iter()
        .any(|pending| pending.canonical_cwd == transition.canonical_cwd)
    {
        return Err(ConversationError::RegistryInvalid(
            "handoff overlaps a pending launch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_rollout(rollout: &GenerationRollout) -> Result<(), ConversationError> {
    let relative = Path::new(&rollout.locator.relative_path);
    let components = relative.components().collect::<Vec<_>>();
    let lexical_components = rollout.locator.relative_path.split('/').collect::<Vec<_>>();
    if rollout.locator.relative_path.is_empty()
        || rollout.locator.relative_path.len() > MAX_ROLLOUT_RELATIVE_BYTES
        || relative.is_absolute()
        || components.len() > MAX_ROLLOUT_COMPONENTS
        || lexical_components.len() != components.len()
        || lexical_components.iter().any(|component| {
            component.is_empty()
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ConversationError::RegistryInvalid(
            "rollout locator is not a bounded root-relative path".to_owned(),
        ));
    }
    let fingerprint = &rollout.fingerprint;
    if fingerprint.inode == 0
        || fingerprint.length > MAX_ROLLOUT_BYTES
        || fingerprint.link_count != 1
        || fingerprint.modified_seconds < 0
        || fingerprint.changed_seconds < 0
        || !(0..1_000_000_000).contains(&fingerprint.modified_nanoseconds)
        || !(0..1_000_000_000).contains(&fingerprint.changed_nanoseconds)
        || fingerprint.sha256.len() != 64
        || !fingerprint
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConversationError::RegistryInvalid(
            "rollout fingerprint is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn same_rollout_file(left: &GenerationRollout, right: &GenerationRollout) -> bool {
    left.fingerprint.device == right.fingerprint.device
        && left.fingerprint.inode == right.fingerprint.inode
}

fn validate_observed_target(target: &ObservedHandoffTarget) -> Result<(), ConversationError> {
    validate_uuid(&target.thread_id, "target thread id")?;
    validate_stored_path(&target.canonical_cwd)?;
    validate_codex_version(&target.codex_version)?;
    validate_adapter_version(&target.adapter_version)?;
    validate_rollout(&target.rollout)?;
    if target.observed_at < 0 {
        return Err(ConversationError::RegistryInvalid(
            "target observation timestamp is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_thread_baseline(thread_ids: &[String]) -> Result<(), ConversationError> {
    if thread_ids.len() > MAX_INVENTORY_THREADS {
        return Err(ConversationError::RegistryInvalid(
            "target baseline exceeds its thread limit".to_owned(),
        ));
    }
    for (index, thread_id) in thread_ids.iter().enumerate() {
        validate_uuid(thread_id, "target baseline thread id")?;
        if index > 0 && thread_ids[index - 1].as_str() >= thread_id.as_str() {
            return Err(ConversationError::RegistryInvalid(
                "target baseline thread ids are not canonical and unique".to_owned(),
            ));
        }
    }
    Ok(())
}

const fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

fn normalize_inventory(inventory: &mut [InventoryThread]) -> Result<(), ConversationError> {
    if inventory.len() > MAX_INVENTORY_THREADS {
        return Err(ConversationError::RegistryInvalid(
            "inventory exceeds its thread limit".to_owned(),
        ));
    }
    inventory.sort_by(|left, right| left.thread_id.cmp(&right.thread_id));
    for (index, thread) in inventory.iter().enumerate() {
        validate_uuid(&thread.thread_id, "thread id")?;
        if thread.updated_at < 0 || thread.recency_at.is_some_and(|timestamp| timestamp < 0) {
            return Err(ConversationError::RegistryInvalid(
                "inventory timestamp is invalid".to_owned(),
            ));
        }
        if thread.rollout_length > 64 * 1024 * 1024
            || !(0..1_000_000_000).contains(&thread.rollout_modified_nanoseconds)
            || !(0..1_000_000_000).contains(&thread.rollout_changed_nanoseconds)
        {
            return Err(ConversationError::RegistryInvalid(
                "inventory rollout fingerprint is invalid".to_owned(),
            ));
        }
        if inventory
            .iter()
            .take(index)
            .any(|previous| previous.thread_id == thread.thread_id)
        {
            return Err(ConversationError::RegistryInvalid(
                "inventory contains duplicate thread ids".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_uuid(value: &str, label: &str) -> Result<(), ConversationError> {
    let parsed = Uuid::parse_str(value).map_err(|_| {
        ConversationError::RegistryInvalid(format!("{label} is not a canonical UUID"))
    })?;
    if parsed.to_string() != value {
        return Err(ConversationError::RegistryInvalid(format!(
            "{label} is not canonical"
        )));
    }
    Ok(())
}

fn validate_codex_version(version: &str) -> Result<(), ConversationError> {
    if version != "0.144.4" {
        return Err(ConversationError::SessionSchemaUnsupported);
    }
    Ok(())
}

fn validate_adapter_version(version: &str) -> Result<(), ConversationError> {
    if version.is_empty() || version.len() > 64 || !version.is_ascii() {
        return Err(ConversationError::RegistryInvalid(
            "adapter version is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_path_string(path: &Path) -> Result<String, ConversationError> {
    let canonical = fs::canonicalize(path).map_err(|_| ConversationError::CwdMismatch)?;
    if !canonical.is_dir() {
        return Err(ConversationError::CwdMismatch);
    }
    canonical
        .to_str()
        .map(str::to_owned)
        .ok_or(ConversationError::CwdMismatch)
}

fn validate_stored_path(path: &str) -> Result<(), ConversationError> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ConversationError::RegistryInvalid(
            "canonical cwd is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn unix_timestamp() -> Result<i64, ConversationError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConversationError::RegistryInvalid("system clock is invalid".to_owned()))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| ConversationError::RegistryInvalid("system clock is invalid".to_owned()))
}

#[cfg(unix)]
fn private_open_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.mode(0o600);
    options
}

#[cfg(not(unix))]
fn private_open_options() -> OpenOptions {
    OpenOptions::new()
}

fn open_lock(path: &Path) -> Result<File, ConversationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_private_regular_file(path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = private_open_options();
    let file = options.read(true).write(true).create(true).open(path)?;
    verify_private_regular_file(path)?;
    Ok(file)
}

#[cfg(unix)]
fn open_private_handoff_lock(path: &Path) -> Result<File, ConversationError> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{Mode, OFlags};
    use rustix::io::{FdFlags, fcntl_getfd};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(io::Error::from)?;
    let opened = descriptor.metadata()?;
    let visible = fs::symlink_metadata(path)?;
    let safe = opened.file_type().is_file()
        && !visible.file_type().is_symlink()
        && visible.file_type().is_file()
        && opened.uid() == rustix::process::getuid().as_raw()
        && visible.uid() == opened.uid()
        && opened.mode() & 0o077 == 0
        && visible.mode() == opened.mode()
        && opened.nlink() == 1
        && visible.nlink() == 1
        && visible.dev() == opened.dev()
        && visible.ino() == opened.ino()
        && fcntl_getfd(&descriptor)
            .map_err(io::Error::from)?
            .contains(FdFlags::CLOEXEC);
    if !safe {
        return Err(ConversationError::RegistryInvalid(
            "managed handoff coordinator lock is unsafe".to_owned(),
        ));
    }
    Ok(descriptor)
}

#[cfg(unix)]
fn verify_private_directory(path: &Path) -> Result<(), ConversationError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() < 1
    {
        return Err(ConversationError::RegistryInvalid(
            "managed conversation directory is unsafe".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_directory(_path: &Path) -> Result<(), ConversationError> {
    Err(ConversationError::SessionSchemaUnsupported)
}

#[cfg(unix)]
fn verify_private_regular_file(path: &Path) -> Result<(), ConversationError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(ConversationError::RegistryInvalid(
            "managed conversation file is unsafe".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_regular_file(_path: &Path) -> Result<(), ConversationError> {
    Err(ConversationError::SessionSchemaUnsupported)
}

fn remove_exact_temporary(
    path: &Path,
    base_name: &str,
    expected_name: &str,
) -> Result<(), ConversationError> {
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name)
        || !expected_name.starts_with(&format!(".{base_name}."))
        || !expected_name.ends_with(".tmp")
    {
        return Err(ConversationError::RegistryInvalid(
            "refused unexpected temporary cleanup".to_owned(),
        ));
    }
    verify_private_regular_file(path)?;
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[derive(Debug)]
pub(crate) enum ConversationError {
    NotFound,
    Ambiguous,
    ProfileMismatch,
    CwdMismatch,
    RolloutMissing,
    Archived,
    RegistryInvalid(String),
    CommitUncertain,
    TransitionBusy,
    #[cfg_attr(not(test), allow(dead_code))] // Emitted by staged handoff APIs.
    TransitionPhaseInvalid,
    CodexVersionUnsupported,
    SessionSchemaUnsupported,
    ThreadProtocolInvalid,
    ThreadMetadataUnavailable,
    Io(io::Error),
}

impl ConversationError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "conversation_not_found",
            Self::Ambiguous => "conversation_ambiguous",
            Self::ProfileMismatch => "conversation_profile_mismatch",
            Self::CwdMismatch => "conversation_cwd_mismatch",
            Self::RolloutMissing => "conversation_rollout_missing",
            Self::Archived => "conversation_archived",
            Self::RegistryInvalid(_) => "conversation_registry_invalid",
            Self::CommitUncertain => "conversation_commit_uncertain",
            Self::TransitionBusy => "conversation_handoff_in_progress",
            Self::TransitionPhaseInvalid => "conversation_handoff_phase_invalid",
            Self::CodexVersionUnsupported => "codex_session_schema_unsupported",
            Self::SessionSchemaUnsupported => "codex_session_schema_unsupported",
            Self::ThreadProtocolInvalid => "codex_thread_protocol_invalid",
            Self::ThreadMetadataUnavailable => "codex_thread_metadata_unavailable",
            Self::Io(_) => "conversation_registry_invalid",
        }
    }

    pub(crate) fn safe_message(&self) -> &'static str {
        match self {
            Self::NotFound => "No tracked Codex conversation exists for this workspace.",
            Self::Ambiguous => {
                "The workspace conversation is ambiguous and requires explicit selection."
            }
            Self::ProfileMismatch => {
                "The selected Codex thread belongs to a different managed profile."
            }
            Self::CwdMismatch => {
                "The selected Codex thread belongs to a different working directory."
            }
            Self::RolloutMissing => "The tracked Codex rollout no longer exists.",
            Self::Archived => {
                "The tracked Codex conversation is archived and cannot be resumed automatically."
            }
            Self::RegistryInvalid(reason) => {
                let _ = reason.len();
                "Calcifer's conversation registry is invalid or unsafe."
            }
            Self::Io(error) => {
                let _ = error.kind();
                "Calcifer's conversation registry is invalid or unsafe."
            }
            Self::CommitUncertain => {
                "The conversation update became visible, but durability could not be confirmed. Inspect the registry before retrying."
            }
            Self::TransitionBusy => {
                "A conversation handoff is already in progress and must be reconciled first."
            }
            Self::TransitionPhaseInvalid => {
                "The conversation handoff phase changed and must be reconciled before retrying."
            }
            Self::CodexVersionUnsupported => {
                "The installed Codex version is not supported for automatic resume."
            }
            Self::SessionSchemaUnsupported => {
                "The Codex session metadata is not supported or is unsafe for automatic resume."
            }
            Self::ThreadProtocolInvalid => "Codex returned an invalid thread metadata response.",
            Self::ThreadMetadataUnavailable => {
                "Codex thread metadata is temporarily unavailable; retry the command."
            }
        }
    }
}

impl fmt::Display for ConversationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for ConversationError {}

impl From<io::Error> for ConversationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::sync::{Arc, Barrier};

    use super::*;

    type JsonCorruption = fn(&mut serde_json::Value);

    #[test]
    fn sha256_hex_matches_the_stable_known_answer() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn test_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "calcifer-conversations-{name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        Ok(root)
    }

    fn binding(cwd: &Path, profile: Uuid, thread: Uuid) -> BindingInput {
        BindingInput {
            profile_id: profile.to_string(),
            thread_id: thread.to_string(),
            canonical_cwd: fs::canonicalize(cwd)
                .ok()
                .and_then(|path| path.to_str().map(str::to_owned))
                .unwrap_or_default(),
            codex_version: "0.144.4".to_owned(),
            lifecycle: ConversationLifecycle::Clean,
        }
    }

    fn test_rollout(relative_path: &str, seed: u64) -> GenerationRollout {
        GenerationRollout {
            locator: RolloutLocator {
                root: RolloutRoot::Sessions,
                relative_path: relative_path.to_owned(),
            },
            fingerprint: RolloutFingerprint {
                device: 1,
                inode: seed + 1,
                length: seed,
                mode: 0o100600,
                owner: rustix::process::getuid().as_raw(),
                link_count: 1,
                modified_seconds: 1_786_086_000,
                modified_nanoseconds: 123,
                changed_seconds: 1_786_086_000,
                changed_nanoseconds: 456,
                sha256: format!("{seed:064x}"),
            },
        }
    }

    fn handoff_preparation(
        source: &HeadBinding,
        target_profile: Uuid,
        trust_domain: Uuid,
        seed: u64,
    ) -> HandoffPreparation {
        HandoffPreparation {
            expected_source: source.clone(),
            target_profile_id: target_profile.to_string(),
            trust_domain_id: trust_domain.to_string(),
            reason: HandoffReason::ConfirmedUsageExhaustion,
            source_rollout: test_rollout(&format!("2026/08/07/rollout-source-{seed}.jsonl"), seed),
        }
    }

    fn handoff_target(cwd: &Path, thread: Uuid, seed: u64) -> HandoffTarget {
        HandoffTarget {
            thread_id: thread.to_string(),
            canonical_cwd: fs::canonicalize(cwd)
                .ok()
                .and_then(|path| path.to_str().map(str::to_owned))
                .unwrap_or_default(),
            codex_version: "0.144.4".to_owned(),
            rollout: test_rollout(&format!("2026/08/07/rollout-target-{seed}.jsonl"), seed),
        }
    }

    fn apply_handoff_step(
        registry: &ConversationRegistry,
        step: usize,
        preparation: &HandoffPreparation,
        target: &HandoffTarget,
        transition_id: &mut Option<String>,
    ) -> Result<(), ConversationError> {
        match step {
            0 => registry
                .prepare_handoff(preparation.clone())
                .map(|transition| {
                    *transition_id = Some(transition.transition_id);
                }),
            1 => registry
                .mark_source_stop_requested(
                    transition_id
                        .as_deref()
                        .ok_or(ConversationError::NotFound)?,
                )
                .map(|_| ()),
            2 => registry
                .mark_source_stopped(
                    transition_id
                        .as_deref()
                        .ok_or(ConversationError::NotFound)?,
                )
                .map(|_| ()),
            3 => registry
                .record_fork_intent(
                    transition_id
                        .as_deref()
                        .ok_or(ConversationError::NotFound)?,
                    Vec::new(),
                )
                .map(|_| ()),
            4 => registry
                .observe_handoff_target(
                    transition_id
                        .as_deref()
                        .ok_or(ConversationError::NotFound)?,
                    target.clone(),
                )
                .map(|_| ()),
            5 => registry
                .commit_handoff(
                    transition_id
                        .as_deref()
                        .ok_or(ConversationError::NotFound)?,
                )
                .map(|_| ()),
            _ => Err(ConversationError::RegistryInvalid(
                "unknown test handoff step".to_owned(),
            )),
        }
    }

    #[test]
    fn exact_binding_round_trips_without_prompt_data() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("round-trip")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let profile = Uuid::new_v4();
        let thread = Uuid::new_v4();

        let adopted = registry.adopt(binding(&workspace, profile, thread))?;
        let resolved = registry.resolve_head(&workspace)?;

        assert_eq!(adopted, resolved);
        assert_eq!(resolved.profile_id, profile.to_string());
        assert_eq!(resolved.thread_id, thread.to_string());
        let serialized = fs::read_to_string(root.join(REGISTRY_FILE))?;
        for forbidden in [
            "prompt sentinel",
            "response sentinel",
            "tool arguments sentinel",
            "preview sentinel",
            "auth.json",
            "rollout-",
        ] {
            assert!(!serialized.contains(forbidden));
        }
        assert_eq!(
            fs::metadata(root.join(REGISTRY_FILE))?.mode() & 0o777,
            0o600
        );
        assert_eq!(fs::metadata(root.join(REGISTRY_FILE))?.nlink(), 1);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn no_thread_preserves_the_previous_head_and_ambiguity_blocks_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("capture-outcomes")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let profile = Uuid::new_v4();
        let original = registry.adopt(binding(&workspace, profile, Uuid::new_v4()))?;

        let launch = registry.begin_launch(
            &profile.to_string(),
            &workspace,
            LaunchMode::Run,
            "0.144.4",
            Vec::new(),
        )?;
        assert!(
            registry
                .finish_launch(&launch, LaunchResolution::NoThread)?
                .is_none()
        );
        assert_eq!(registry.resolve_head(&workspace)?, original);

        let launch = registry.begin_launch(
            &profile.to_string(),
            &workspace,
            LaunchMode::Run,
            "0.144.4",
            Vec::new(),
        )?;
        assert!(
            registry
                .finish_launch(&launch, LaunchResolution::Ambiguous)?
                .is_none()
        );
        assert_eq!(
            registry
                .resolve_head(&workspace)
                .err()
                .map(|error| error.code()),
            Some("conversation_ambiguous")
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn retryable_capture_failure_blocks_then_allows_a_successful_rebind()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("retryable-capture")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let profile = Uuid::new_v4();
        let original = registry.adopt(binding(&workspace, profile, Uuid::new_v4()))?;
        let replacement = binding(&workspace, profile, Uuid::new_v4());

        let launch = registry.begin_launch(
            &profile.to_string(),
            &workspace,
            LaunchMode::Run,
            "0.144.4",
            Vec::new(),
        )?;
        registry.mark_provider_started(&launch)?;
        registry.mark_capture_failed(&launch)?;

        assert_eq!(
            registry
                .resolve_head(&workspace)
                .err()
                .map(|error| error.code()),
            Some("conversation_ambiguous"),
            "a pending retry must block the old head"
        );
        let document = registry.load()?;
        let head = document
            .workspace_heads
            .iter()
            .find(|head| head.canonical_cwd == original.canonical_cwd)
            .ok_or_else(|| io::Error::other("workspace head is missing"))?;
        assert_eq!(head.state, HeadState::Ready);
        assert_eq!(
            head.conversation_id.as_deref(),
            Some(original.conversation_id.as_str())
        );

        let rebound = registry
            .finish_launch(&launch, LaunchResolution::Bind(replacement.clone()))?
            .ok_or_else(|| io::Error::other("retryable capture could not rebind"))?;
        assert_eq!(rebound.thread_id, replacement.thread_id);
        assert_eq!(registry.resolve_head(&workspace)?, rebound);
        assert!(
            registry
                .pending_for(&profile.to_string(), &workspace)?
                .is_none()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn immutable_thread_ownership_rejects_profile_and_cwd_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("immutable-binding")?;
        let workspace = root.join("workspace");
        let other_workspace = root.join("other-workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        fs::DirBuilder::new().mode(0o700).create(&other_workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let profile = Uuid::new_v4();
        let thread = Uuid::new_v4();
        let original = registry.adopt(binding(&workspace, profile, thread))?;

        let profile_error = registry
            .adopt(binding(&workspace, Uuid::new_v4(), thread))
            .err()
            .ok_or_else(|| io::Error::other("profile ownership change was accepted"))?;
        assert_eq!(profile_error.code(), "conversation_profile_mismatch");
        let cwd_error = registry
            .adopt(binding(&other_workspace, profile, thread))
            .err()
            .ok_or_else(|| io::Error::other("cwd ownership change was accepted"))?;
        assert_eq!(cwd_error.code(), "conversation_cwd_mismatch");
        assert_eq!(registry.resolve_head(&workspace)?, original);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn untracked_transition_marks_new_and_existing_heads_for_selection()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("untracked-heads")?;
        let new_workspace = root.join("new-workspace");
        let existing_workspace = root.join("existing-workspace");
        fs::DirBuilder::new().mode(0o700).create(&new_workspace)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&existing_workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let profile = Uuid::new_v4();
        let thread = Uuid::new_v4();
        registry.adopt(binding(&existing_workspace, profile, thread))?;

        registry.prepare_untracked(
            &profile.to_string(),
            &new_workspace,
            LaunchMode::RunUntracked,
        )?;
        registry.prepare_untracked(
            &profile.to_string(),
            &existing_workspace,
            LaunchMode::ResumeLastUntracked,
        )?;

        for workspace in [&new_workspace, &existing_workspace] {
            assert_eq!(
                registry
                    .resolve_head(workspace)
                    .err()
                    .map(|error| error.code()),
                Some("conversation_ambiguous")
            );
        }
        assert!(
            registry
                .find_bound_thread(
                    &profile.to_string(),
                    &thread.to_string(),
                    &existing_workspace
                )?
                .is_some(),
            "untracked mode must retain immutable recovery metadata"
        );
        assert!(
            registry
                .find_bound_thread(
                    &profile.to_string(),
                    &Uuid::new_v4().to_string(),
                    &new_workspace
                )?
                .is_none(),
            "a new untracked workspace must not invent a binding"
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn active_untracked_transition_blocks_exact_head_adoption()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("untracked-blocks-adoption")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let untracked_profile = Uuid::new_v4();
        let exact_profile = Uuid::new_v4();

        let launch_id = registry.prepare_untracked(
            &untracked_profile.to_string(),
            &workspace,
            LaunchMode::RunUntracked,
        )?;
        let pending = registry
            .untracked_for_workspace(&workspace)?
            .ok_or_else(|| io::Error::other("untracked ownership was not durable"))?;
        assert_eq!(pending.launch_id, launch_id);
        assert_eq!(pending.mode, LaunchMode::RunUntracked);
        assert!(pending.codex_version.is_none());
        assert!(pending.pre_inventory.is_empty());

        let error = registry
            .adopt(binding(&workspace, exact_profile, Uuid::new_v4()))
            .err()
            .ok_or_else(|| io::Error::other("active untracked launch allowed exact adoption"))?;

        assert_eq!(error.code(), "conversation_ambiguous");
        assert_eq!(
            registry
                .resolve_head(&workspace)
                .err()
                .map(|error| error.code()),
            Some("conversation_ambiguous")
        );

        let _ = registry.finish_launch(&launch_id, LaunchResolution::Ambiguous)?;
        assert!(registry.untracked_for_workspace(&workspace)?.is_none());
        let exact_thread = Uuid::new_v4();
        registry.adopt(binding(&workspace, exact_profile, exact_thread))?;
        assert_eq!(
            registry.resolve_head(&workspace)?.thread_id,
            exact_thread.to_string()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn completed_untracked_transition_blocks_stale_exact_refresh()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("untracked-blocks-stale-refresh")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let exact_profile = Uuid::new_v4();
        let exact_thread = Uuid::new_v4();
        let exact_binding = binding(&workspace, exact_profile, exact_thread);
        let expected = registry.adopt(exact_binding.clone())?;

        let launch_id = registry.prepare_untracked(
            &Uuid::new_v4().to_string(),
            &workspace,
            LaunchMode::RunUntracked,
        )?;
        let _ = registry.finish_launch(&launch_id, LaunchResolution::Ambiguous)?;
        let error = registry
            .refresh_adopted(&expected, exact_binding)
            .err()
            .ok_or_else(|| io::Error::other("stale exact refresh restored a ready head"))?;

        assert_eq!(error.code(), "conversation_ambiguous");
        assert_eq!(
            registry
                .resolve_head(&workspace)
                .err()
                .map(|error| error.code()),
            Some("conversation_ambiguous")
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn untracked_transition_refuses_any_pending_launch_in_the_workspace()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("untracked-pending")?;
        let requested_workspace = root.join("requested-workspace");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&requested_workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let pending_profile = Uuid::new_v4();
        let selected_profile = Uuid::new_v4();
        let launch_id = registry.begin_launch(
            &pending_profile.to_string(),
            &requested_workspace,
            LaunchMode::Run,
            "0.144.4",
            Vec::new(),
        )?;

        let error = registry
            .prepare_untracked(
                &selected_profile.to_string(),
                &requested_workspace,
                LaunchMode::RunUntracked,
            )
            .err()
            .ok_or_else(|| io::Error::other("untracked mode ignored a prior pending launch"))?;
        assert_eq!(error.code(), "conversation_ambiguous");
        assert!(
            registry
                .pending_for(&pending_profile.to_string(), &requested_workspace)?
                .is_some_and(|pending| pending.launch_id == launch_id)
        );
        assert!(
            registry.load()?.workspace_heads.is_empty(),
            "refusal must not add a workspace-head mutation"
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn uncertain_untracked_transition_never_authorizes_spawn()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("untracked-uncertain")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let profile = Uuid::new_v4();

        let error = registry
            .with_fault(WriteFault::AfterRename)
            .prepare_untracked(&profile.to_string(), &workspace, LaunchMode::RunUntracked)
            .err()
            .ok_or_else(|| io::Error::other("uncertain commit was reported as durable"))?;
        assert_eq!(error.code(), "conversation_commit_uncertain");
        assert_eq!(
            registry
                .resolve_head(&workspace)
                .err()
                .map(|error| error.code()),
            Some("conversation_ambiguous"),
            "the visible marker must remain fail-closed after uncertain durability"
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn atomic_faults_expose_only_old_or_new_complete_documents()
    -> Result<(), Box<dyn std::error::Error>> {
        for fault in [
            WriteFault::BeforeFileSync,
            WriteFault::BeforeRename,
            WriteFault::AfterRename,
            WriteFault::DirectorySync,
        ] {
            let root = test_root("atomic-fault")?;
            let workspace = root.join("workspace");
            fs::DirBuilder::new().mode(0o700).create(&workspace)?;
            let registry = ConversationRegistry::at(root.clone());
            let profile = Uuid::new_v4();
            let old = registry.adopt(binding(&workspace, profile, Uuid::new_v4()))?;
            let faulting = registry.with_fault(fault);
            let replacement = binding(&workspace, profile, Uuid::new_v4());
            let result = faulting.adopt(replacement.clone());

            let visible = registry.resolve_head(&workspace)?;
            match fault {
                WriteFault::BeforeFileSync | WriteFault::BeforeRename => {
                    assert_eq!(
                        result.err().map(|error| error.code()),
                        Some("conversation_registry_invalid")
                    );
                    assert_eq!(visible, old);
                }
                WriteFault::AfterRename | WriteFault::DirectorySync => {
                    assert_eq!(
                        result.err().map(|error| error.code()),
                        Some("conversation_commit_uncertain")
                    );
                    assert_eq!(visible.thread_id, replacement.thread_id);
                }
            }
            let document: ConversationDocument =
                serde_json::from_slice(&fs::read(root.join(REGISTRY_FILE))?)?;
            validate_document(&document)?;
            let stale_temps = fs::read_dir(&root)?
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count();
            assert_eq!(stale_temps, 0);
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn concurrent_transactions_do_not_lose_updates_or_deadlock()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("concurrent")?;
        let registry = ConversationRegistry::at(root.clone());
        let barrier = Arc::new(Barrier::new(9));
        let mut workers = Vec::new();
        for index in 0..8 {
            let worker_registry = registry.clone();
            let worker_barrier = Arc::clone(&barrier);
            let workspace = root.join(format!("workspace-{index}"));
            fs::DirBuilder::new().mode(0o700).create(&workspace)?;
            workers.push(std::thread::spawn(move || {
                worker_barrier.wait();
                worker_registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))
            }));
        }
        barrier.wait();
        for worker in workers {
            let result = worker
                .join()
                .map_err(|_| io::Error::other("registry worker panicked"))?;
            assert!(result.is_ok());
        }
        let document = registry.load()?;
        assert_eq!(document.conversations.len(), 8);
        assert_eq!(document.workspace_heads.len(), 8);
        assert_eq!(document.revision, 8);
        validate_document(&document)?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn corrupt_newer_or_linked_registry_never_selects() -> Result<(), Box<dyn std::error::Error>> {
        for contents in [
            b"not-json".as_slice(),
            br#"{"schema_version":3,"revision":0,"conversations":[],"workspace_heads":[],"pending_launches":[]}"#,
        ] {
            let root = test_root("invalid")?;
            let path = root.join(REGISTRY_FILE);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options.open(&path)?.write_all(contents)?;
            let registry = ConversationRegistry::at(root.clone());
            assert_eq!(
                registry.load().err().map(|error| error.code()),
                Some("conversation_registry_invalid")
            );
            fs::remove_dir_all(root)?;
        }

        let root = test_root("invalid-lifecycle")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        let mut document = registry.load()?;
        document.conversations[0].last_safe_lifecycle = ConversationLifecycle::Missing;
        fs::write(
            root.join(REGISTRY_FILE),
            serde_json::to_vec_pretty(&document)?,
        )?;
        assert_eq!(
            registry.load().err().map(|error| error.code()),
            Some("conversation_registry_invalid"),
            "a ready head with an unusable lifecycle must never resolve"
        );
        fs::remove_dir_all(root)?;

        let root = test_root("linked")?;
        let path = root.join(REGISTRY_FILE);
        let outside = root.join("outside.json");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options.open(&outside)?.write_all(b"{}")?;
        fs::hard_link(&outside, &path)?;
        let registry = ConversationRegistry::at(root.clone());
        assert_eq!(
            registry.load().err().map(|error| error.code()),
            Some("conversation_registry_invalid")
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn first_handoff_mutation_migrates_v1_losslessly_and_preserves_recovery_copy()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("lazy-v2-migration")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source_profile = Uuid::new_v4();
        let source_thread = Uuid::new_v4();
        let source = registry.adopt(binding(&workspace, source_profile, source_thread))?;
        let original_bytes = fs::read(root.join(REGISTRY_FILE))?;

        assert_eq!(registry.resolve_head(&workspace)?, source);
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, original_bytes);
        assert!(!root.join(PRE_MIGRATION_BACKUP_FILE).exists());

        let transition = registry.prepare_handoff(HandoffPreparation {
            expected_source: source.clone(),
            target_profile_id: Uuid::new_v4().to_string(),
            trust_domain_id: Uuid::new_v4().to_string(),
            reason: HandoffReason::ConfirmedUsageExhaustion,
            source_rollout: test_rollout("2026/08/07/rollout-source.jsonl", 11),
        })?;

        assert_eq!(transition.phase, HandoffPhase::Prepared);
        assert_eq!(transition.source_generation, source.generation);
        assert_eq!(transition.target_generation, source.generation + 1);
        let migrated = registry.load()?;
        assert_eq!(migrated.schema_version, SCHEMA_VERSION_V2);
        assert_eq!(migrated.conversations.len(), 1);
        assert_eq!(
            migrated.conversations[0].conversation_id,
            source.conversation_id
        );
        assert_eq!(
            migrated.conversations[0].generations[0].thread_id,
            source.thread_id
        );

        let backup: ConversationDocument =
            serde_json::from_slice(&fs::read(root.join(PRE_MIGRATION_BACKUP_FILE))?)?;
        assert_eq!(backup.schema_version, SCHEMA_VERSION_V1);
        assert_eq!(
            backup.conversations[0].conversation_id,
            source.conversation_id
        );
        assert_eq!(
            backup.conversations[0].generations[0].thread_id,
            source.thread_id
        );
        assert_eq!(
            fs::read(root.join(PRE_MIGRATION_BACKUP_FILE))?,
            original_bytes
        );

        let mut projected_v1 = migrated;
        projected_v1.schema_version = SCHEMA_VERSION_V1;
        projected_v1.revision = backup.revision;
        projected_v1.pre_migration_backup = None;
        projected_v1.active_transition = None;
        projected_v1.conversations[0].generations[0].trust_domain_id = None;
        projected_v1.conversations[0].generations[0].rollout = None;
        assert_eq!(projected_v1, backup);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn ordinary_same_profile_resume_mutations_keep_schema_v1()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("same-profile-stays-v1")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let profile = Uuid::new_v4();
        let thread = Uuid::new_v4();
        let exact = binding(&workspace, profile, thread);
        let expected = registry.adopt(exact.clone())?;

        assert_eq!(registry.resolve_head(&workspace)?, expected);
        registry.refresh_adopted(&expected, exact)?;
        let document = registry.load()?;

        assert_eq!(document.schema_version, SCHEMA_VERSION_V1);
        assert!(document.active_transition.is_none());
        assert!(!root.join(PRE_MIGRATION_BACKUP_FILE).exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn failed_v2_publication_refreshes_a_stale_pre_migration_backup_before_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("refresh-v1-backup")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let exact = binding(&workspace, Uuid::new_v4(), Uuid::new_v4());
        let source = registry.adopt(exact.clone())?;
        let preparation = handoff_preparation(&source, Uuid::new_v4(), Uuid::new_v4(), 11);

        assert_eq!(
            registry
                .with_fault(WriteFault::BeforeFileSync)
                .prepare_handoff(preparation.clone())
                .err()
                .map(|error| error.code()),
            Some("conversation_registry_invalid")
        );
        let stale_backup: ConversationDocument =
            serde_json::from_slice(&fs::read(root.join(PRE_MIGRATION_BACKUP_FILE))?)?;
        assert_eq!(registry.load()?.schema_version, SCHEMA_VERSION_V1);

        registry.refresh_adopted(&source, exact)?;
        let v1_before_retry = registry.load()?;
        assert!(v1_before_retry.revision > stale_backup.revision);
        registry.prepare_handoff(preparation)?;

        let refreshed_backup: ConversationDocument =
            serde_json::from_slice(&fs::read(root.join(PRE_MIGRATION_BACKUP_FILE))?)?;
        assert_eq!(refreshed_backup, v1_before_retry);
        assert_eq!(
            fs::metadata(root.join(PRE_MIGRATION_BACKUP_FILE))?.mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.join(PRE_MIGRATION_BACKUP_FILE))?.nlink(),
            1
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn unsafe_pre_migration_backup_blocks_v2_without_rewriting_any_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("unsafe-v1-backup")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        let v1_bytes = fs::read(root.join(REGISTRY_FILE))?;
        let outside = root.join("outside-sentinel");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options.open(&outside)?.write_all(b"outside sentinel")?;
        std::os::unix::fs::symlink(&outside, root.join(PRE_MIGRATION_BACKUP_FILE))?;

        assert_eq!(
            registry
                .prepare_handoff(handoff_preparation(
                    &source,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    12,
                ))
                .err()
                .map(|error| error.code()),
            Some("conversation_registry_invalid")
        );
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, v1_bytes);
        assert_eq!(fs::read(&outside)?, b"outside sentinel");
        assert!(
            fs::symlink_metadata(root.join(PRE_MIGRATION_BACKUP_FILE))?
                .file_type()
                .is_symlink()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn arbitrary_or_unbounded_rollout_metadata_never_triggers_v2_migration()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("invalid-rollout-metadata")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        let v1_bytes = fs::read(root.join(REGISTRY_FILE))?;
        let base = handoff_preparation(&source, Uuid::new_v4(), Uuid::new_v4(), 13);
        let mut invalid = Vec::new();

        let mut absolute = base.clone();
        absolute.source_rollout.locator.relative_path = "/tmp/rollout.jsonl".to_owned();
        invalid.push(absolute);

        let mut traversal = base.clone();
        traversal.source_rollout.locator.relative_path =
            "2026/08/07/../../outside.jsonl".to_owned();
        invalid.push(traversal);

        let mut noncanonical = base.clone();
        noncanonical.source_rollout.locator.relative_path = "2026//08/07/rollout.jsonl".to_owned();
        invalid.push(noncanonical);

        let mut oversized_path = base.clone();
        oversized_path.source_rollout.locator.relative_path =
            format!("{}.jsonl", "x".repeat(MAX_ROLLOUT_RELATIVE_BYTES));
        invalid.push(oversized_path);

        let mut oversized_file = base.clone();
        oversized_file.source_rollout.fingerprint.length = MAX_ROLLOUT_BYTES + 1;
        invalid.push(oversized_file);

        let mut linked_file = base.clone();
        linked_file.source_rollout.fingerprint.link_count = 2;
        invalid.push(linked_file);

        let mut invalid_digest = base;
        invalid_digest.source_rollout.fingerprint.sha256 = "A".repeat(64);
        invalid.push(invalid_digest);

        for preparation in invalid {
            assert_eq!(
                registry
                    .prepare_handoff(preparation)
                    .err()
                    .map(|error| error.code()),
                Some("conversation_registry_invalid")
            );
            assert_eq!(fs::read(root.join(REGISTRY_FILE))?, v1_bytes);
            assert!(!root.join(PRE_MIGRATION_BACKUP_FILE).exists());
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn target_rollout_must_have_a_distinct_file_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = test_root("distinct-target-rollout")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        let preparation = handoff_preparation(&source, Uuid::new_v4(), Uuid::new_v4(), 14);
        let source_identity = preparation.source_rollout.fingerprint.clone();
        let transition = registry.prepare_handoff(preparation)?;
        registry.mark_source_stop_requested(&transition.transition_id)?;
        registry.mark_source_stopped(&transition.transition_id)?;
        registry.record_fork_intent(&transition.transition_id, Vec::new())?;
        let mut target = handoff_target(&workspace, Uuid::new_v4(), 15);
        target.rollout.fingerprint.device = source_identity.device;
        target.rollout.fingerprint.inode = source_identity.inode;

        assert_eq!(
            registry
                .observe_handoff_target(&transition.transition_id, target)
                .err()
                .map(|error| error.code()),
            Some("conversation_registry_invalid")
        );
        assert_eq!(
            registry
                .current_handoff()?
                .map(|transition| transition.phase),
            Some(HandoffPhase::ForkRequested)
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn v2_fails_closed_when_the_hash_bound_v1_backup_is_missing_or_tampered()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("v2-backup-integrity")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        registry.prepare_handoff(handoff_preparation(
            &source,
            Uuid::new_v4(),
            Uuid::new_v4(),
            16,
        ))?;
        let backup_path = root.join(PRE_MIGRATION_BACKUP_FILE);
        let backup_bytes = fs::read(&backup_path)?;

        fs::write(&backup_path, b"tampered")?;
        assert_eq!(
            registry.load().err().map(|error| error.code()),
            Some("conversation_registry_invalid")
        );
        fs::write(&backup_path, &backup_bytes)?;
        fs::remove_file(&backup_path)?;
        assert_eq!(
            registry.load().err().map(|error| error.code()),
            Some("conversation_registry_invalid")
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn ordered_handoff_generations_resolve_only_the_attached_active_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("ordered-generations")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        let trust_domain = Uuid::new_v4();

        let first = registry.prepare_handoff(handoff_preparation(
            &source,
            Uuid::new_v4(),
            trust_domain,
            21,
        ))?;
        assert_eq!(
            registry
                .resolve_head(&workspace)
                .err()
                .map(|error| error.code()),
            Some("conversation_handoff_in_progress")
        );
        assert_eq!(
            registry
                .prepare_handoff(handoff_preparation(
                    &source,
                    Uuid::new_v4(),
                    trust_domain,
                    22,
                ))
                .err()
                .map(|error| error.code()),
            Some("conversation_handoff_in_progress")
        );

        assert_eq!(
            registry
                .mark_source_stop_requested(&first.transition_id)?
                .phase,
            HandoffPhase::SourceStopRequested
        );
        assert_eq!(
            registry.mark_source_stopped(&first.transition_id)?.phase,
            HandoffPhase::SourceStopped
        );
        assert_eq!(
            registry
                .record_fork_intent(&first.transition_id, Vec::new())?
                .phase,
            HandoffPhase::ForkRequested
        );
        let first_target_thread = Uuid::new_v4();
        let first_target_observation = handoff_target(&workspace, first_target_thread, 31);
        assert_eq!(
            registry
                .observe_handoff_target(&first.transition_id, first_target_observation.clone(),)?
                .phase,
            HandoffPhase::ForkObserved
        );
        let first_target = registry.commit_handoff(&first.transition_id)?;
        assert_eq!(first_target.generation, 1);
        assert_eq!(first_target.thread_id, first_target_thread.to_string());
        assert_eq!(
            registry
                .current_handoff()?
                .map(|transition| transition.phase),
            Some(HandoffPhase::CommittedUnattached)
        );
        assert_eq!(
            registry
                .resolve_head(&workspace)
                .err()
                .map(|error| error.code()),
            Some("conversation_handoff_in_progress"),
            "a committed generation must remain unavailable until official TUI attachment"
        );
        assert_eq!(
            registry.finish_handoff_attachment(&first.transition_id)?,
            first_target
        );
        assert_eq!(registry.resolve_head(&workspace)?, first_target);

        let mut second_preparation =
            handoff_preparation(&first_target, Uuid::new_v4(), trust_domain, 41);
        second_preparation.source_rollout = first_target_observation.rollout;
        let second = registry.prepare_handoff(second_preparation)?;
        registry.mark_source_stop_requested(&second.transition_id)?;
        registry.mark_source_stopped(&second.transition_id)?;
        registry.record_fork_intent(&second.transition_id, Vec::new())?;
        let second_target_thread = Uuid::new_v4();
        registry.observe_handoff_target(
            &second.transition_id,
            handoff_target(&workspace, second_target_thread, 51),
        )?;
        let second_target = registry.commit_handoff(&second.transition_id)?;
        registry.finish_handoff_attachment(&second.transition_id)?;

        assert_eq!(second_target.conversation_id, source.conversation_id);
        assert_eq!(second_target.generation, 2);
        assert_eq!(registry.resolve_head(&workspace)?, second_target);
        let document = registry.load()?;
        assert_eq!(document.conversations[0].generations.len(), 3);
        assert_eq!(document.conversations[0].active_generation, 2);
        assert_eq!(
            document.conversations[0]
                .generations
                .iter()
                .map(|generation| generation.generation)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn active_handoff_blocks_its_workspace_but_not_unrelated_conversation_updates()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("scoped-transition-blocking")?;
        let source_workspace = root.join("source-workspace");
        let unrelated_workspace = root.join("unrelated-workspace");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&source_workspace)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&unrelated_workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source_profile = Uuid::new_v4();
        let source_thread = Uuid::new_v4();
        let source = registry.adopt(binding(&source_workspace, source_profile, source_thread))?;
        registry.prepare_handoff(handoff_preparation(
            &source,
            Uuid::new_v4(),
            Uuid::new_v4(),
            55,
        ))?;
        let revision_before = registry.load()?.revision;

        assert_eq!(
            registry
                .adopt(binding(&source_workspace, source_profile, source_thread,))
                .err()
                .map(|error| error.code()),
            Some("conversation_handoff_in_progress")
        );
        let unrelated = registry.adopt(binding(
            &unrelated_workspace,
            Uuid::new_v4(),
            Uuid::new_v4(),
        ))?;

        assert_eq!(registry.resolve_head(&unrelated_workspace)?, unrelated);
        assert_eq!(
            registry
                .resolve_head(&source_workspace)
                .err()
                .map(|error| error.code()),
            Some("conversation_handoff_in_progress")
        );
        assert_eq!(registry.load()?.revision, revision_before + 1);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn handoff_phase_skips_and_duplicate_advances_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("phase-order")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        let transition = registry.prepare_handoff(handoff_preparation(
            &source,
            Uuid::new_v4(),
            Uuid::new_v4(),
            61,
        ))?;

        assert_eq!(
            registry
                .mark_source_stopped(&transition.transition_id)
                .err()
                .map(|error| error.code()),
            Some("conversation_handoff_phase_invalid")
        );
        registry.mark_source_stop_requested(&transition.transition_id)?;
        assert_eq!(
            registry
                .mark_source_stop_requested(&transition.transition_id)
                .err()
                .map(|error| error.code()),
            Some("conversation_handoff_phase_invalid")
        );
        assert_eq!(
            registry
                .current_handoff()?
                .map(|transition| transition.phase),
            Some(HandoffPhase::SourceStopRequested)
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn fork_intent_persists_a_canonical_baseline_and_allows_only_one_bounded_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("fork-intent-retry")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        let transition = registry.prepare_handoff(handoff_preparation(
            &source,
            Uuid::new_v4(),
            Uuid::new_v4(),
            67,
        ))?;
        registry.mark_source_stop_requested(&transition.transition_id)?;
        registry.mark_source_stopped(&transition.transition_id)?;
        let first = Uuid::new_v4().to_string();
        let second = Uuid::new_v4().to_string();
        let mut baseline = vec![second, first];
        baseline.sort_unstable();

        let requested = registry.record_fork_intent(&transition.transition_id, baseline.clone())?;
        assert_eq!(requested.phase, HandoffPhase::ForkRequested);
        assert_eq!(requested.target_baseline_thread_ids, baseline);
        assert_eq!(requested.fork_attempts, 1);
        assert!(requested.fork_requested_at.is_some());
        assert_eq!(registry.current_handoff()?, Some(requested.clone()));

        let retried = registry.record_bounded_fork_retry(&transition.transition_id)?;
        assert_eq!(retried.fork_attempts, 2);
        assert!(retried.fork_requested_at >= requested.fork_requested_at);
        assert_eq!(retried.target_baseline_thread_ids, baseline);
        assert_eq!(
            registry
                .record_bounded_fork_retry(&transition.transition_id)
                .err()
                .map(|error| error.code()),
            Some("conversation_handoff_phase_invalid")
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn fork_intent_rejects_noncanonical_or_duplicate_target_baselines()
    -> Result<(), Box<dyn std::error::Error>> {
        for baseline in [
            vec![Uuid::new_v4().to_string(), "not-a-thread".to_owned()],
            {
                let duplicate = Uuid::new_v4().to_string();
                vec![duplicate.clone(), duplicate]
            },
        ] {
            let root = test_root("fork-intent-invalid-baseline")?;
            let workspace = root.join("workspace");
            fs::DirBuilder::new().mode(0o700).create(&workspace)?;
            let registry = ConversationRegistry::at(root.clone());
            let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
            let transition = registry.prepare_handoff(handoff_preparation(
                &source,
                Uuid::new_v4(),
                Uuid::new_v4(),
                68,
            ))?;
            registry.mark_source_stop_requested(&transition.transition_id)?;
            registry.mark_source_stopped(&transition.transition_id)?;

            assert_eq!(
                registry
                    .record_fork_intent(&transition.transition_id, baseline)
                    .err()
                    .map(|error| error.code()),
                Some("conversation_registry_invalid")
            );
            assert_eq!(
                registry.current_handoff()?.map(|handoff| handoff.phase),
                Some(HandoffPhase::SourceStopped)
            );
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn handoff_coordinator_lease_is_exclusive_nonblocking_and_separate_from_registry_updates()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("handoff-coordinator-lease")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let first = registry.try_lock_handoff_coordinator()?;

        assert_eq!(
            registry
                .try_lock_handoff_coordinator()
                .err()
                .map(|error| error.code()),
            Some("conversation_handoff_in_progress")
        );

        let binding = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        assert_eq!(registry.resolve_head(&workspace)?, binding);

        drop(first);
        let second = registry.try_lock_handoff_coordinator()?;
        drop(second);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn handoff_coordinator_lease_rejects_unsafe_visible_lock_nodes()
    -> Result<(), Box<dyn std::error::Error>> {
        for kind in ["symlink", "hardlink", "permissive"] {
            let root = test_root("unsafe-handoff-coordinator-lease")?;
            let registry = ConversationRegistry::at(root.clone());
            let lock = root.join(HANDOFF_COORDINATOR_LOCK_FILE);
            let other = root.join("other.lock");
            let mut options = OpenOptions::new();
            options.mode(0o600).write(true).create_new(true);
            options.open(&other)?;
            match kind {
                "symlink" => std::os::unix::fs::symlink(&other, &lock)?,
                "hardlink" => fs::hard_link(&other, &lock)?,
                "permissive" => {
                    fs::copy(&other, &lock)?;
                    let mut permissions = fs::metadata(&lock)?.permissions();
                    permissions.set_mode(0o666);
                    fs::set_permissions(&lock, permissions)?;
                }
                _ => unreachable!(),
            }

            assert_eq!(
                registry
                    .try_lock_handoff_coordinator()
                    .err()
                    .map(|error| error.code()),
                Some("conversation_registry_invalid"),
                "unsafe {kind} handoff lock was accepted"
            );
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn malformed_lineage_order_heads_and_transition_shape_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("malformed-v2")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        let preparation = handoff_preparation(&source, Uuid::new_v4(), Uuid::new_v4(), 71);
        let transition = registry.prepare_handoff(preparation)?;

        let prepared_bytes = fs::read(root.join(REGISTRY_FILE))?;
        let mut multiple: serde_json::Value = serde_json::from_slice(&prepared_bytes)?;
        multiple["active_transitions"] = serde_json::json!([
            multiple["active_transition"].clone(),
            multiple["active_transition"].clone()
        ]);
        fs::write(
            root.join(REGISTRY_FILE),
            serde_json::to_vec_pretty(&multiple)?,
        )?;
        assert_eq!(
            registry.load().err().map(|error| error.code()),
            Some("conversation_registry_invalid"),
            "an array-shaped multiple-transition document must not be accepted"
        );
        fs::write(root.join(REGISTRY_FILE), &prepared_bytes)?;

        registry.mark_source_stop_requested(&transition.transition_id)?;
        registry.mark_source_stopped(&transition.transition_id)?;
        registry.record_fork_intent(&transition.transition_id, Vec::new())?;
        registry.observe_handoff_target(
            &transition.transition_id,
            handoff_target(&workspace, Uuid::new_v4(), 81),
        )?;
        registry.commit_handoff(&transition.transition_id)?;
        registry.finish_handoff_attachment(&transition.transition_id)?;
        let valid_bytes = fs::read(root.join(REGISTRY_FILE))?;

        let corruptions: [(&str, JsonCorruption); 5] = [
            ("duplicate", |document: &mut serde_json::Value| {
                document["conversations"][0]["generations"][1]["generation"] = serde_json::json!(0);
            }),
            ("skipped", |document: &mut serde_json::Value| {
                document["conversations"][0]["generations"][1]["generation"] = serde_json::json!(2);
            }),
            ("mismatched head", |document: &mut serde_json::Value| {
                document["workspace_heads"][0]["generation"] = serde_json::json!(0);
            }),
            (
                "cross-domain generation",
                |document: &mut serde_json::Value| {
                    document["conversations"][0]["generations"][1]["trust_domain_id"] =
                        serde_json::json!("00000000-0000-4000-8000-000000000001");
                },
            ),
            (
                "missing rollout metadata",
                |document: &mut serde_json::Value| {
                    document["conversations"][0]["generations"][1]["rollout"] =
                        serde_json::Value::Null;
                },
            ),
        ];
        for (label, mutate) in corruptions {
            let mut document: serde_json::Value = serde_json::from_slice(&valid_bytes)?;
            mutate(&mut document);
            fs::write(
                root.join(REGISTRY_FILE),
                serde_json::to_vec_pretty(&document)?,
            )?;
            assert_eq!(
                registry.load().err().map(|error| error.code()),
                Some("conversation_registry_invalid"),
                "{label} lineage corruption was accepted"
            );
        }

        fs::write(root.join(REGISTRY_FILE), valid_bytes)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn every_handoff_phase_write_is_atomic_across_injected_faults()
    -> Result<(), Box<dyn std::error::Error>> {
        for step in 0..6 {
            for fault in [
                WriteFault::BeforeFileSync,
                WriteFault::BeforeRename,
                WriteFault::AfterRename,
                WriteFault::DirectorySync,
            ] {
                let root = test_root("handoff-phase-fault")?;
                let workspace = root.join("workspace");
                fs::DirBuilder::new().mode(0o700).create(&workspace)?;
                let registry = ConversationRegistry::at(root.clone());
                let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
                let preparation =
                    handoff_preparation(&source, Uuid::new_v4(), Uuid::new_v4(), 100 + step as u64);
                let target = handoff_target(&workspace, Uuid::new_v4(), 200 + step as u64);
                let mut transition_id = None;
                for completed in 0..step {
                    apply_handoff_step(
                        &registry,
                        completed,
                        &preparation,
                        &target,
                        &mut transition_id,
                    )?;
                }
                let old_bytes = fs::read(root.join(REGISTRY_FILE))?;

                let result = apply_handoff_step(
                    &registry.with_fault(fault),
                    step,
                    &preparation,
                    &target,
                    &mut transition_id,
                );
                let visible_bytes = fs::read(root.join(REGISTRY_FILE))?;
                match fault {
                    WriteFault::BeforeFileSync | WriteFault::BeforeRename => {
                        assert_eq!(
                            result.err().map(|error| error.code()),
                            Some("conversation_registry_invalid")
                        );
                        assert_eq!(visible_bytes, old_bytes);
                    }
                    WriteFault::AfterRename | WriteFault::DirectorySync => {
                        assert_eq!(
                            result.err().map(|error| error.code()),
                            Some("conversation_commit_uncertain")
                        );
                        assert_ne!(visible_bytes, old_bytes);
                    }
                }
                let visible: ConversationDocument = serde_json::from_slice(&visible_bytes)?;
                validate_document(&visible)?;
                let stale_temps = fs::read_dir(&root)?
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                    .count();
                assert_eq!(stale_temps, 0);
                fs::remove_dir_all(root)?;
            }
        }
        Ok(())
    }

    #[test]
    fn concurrent_phase_transactions_publish_one_complete_successor()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("concurrent-handoff")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        let transition = registry.prepare_handoff(handoff_preparation(
            &source,
            Uuid::new_v4(),
            Uuid::new_v4(),
            301,
        ))?;
        let revision_before = registry.load()?.revision;
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let worker_registry = registry.clone();
            let worker_barrier = Arc::clone(&barrier);
            let transition_id = transition.transition_id.clone();
            workers.push(std::thread::spawn(move || {
                worker_barrier.wait();
                worker_registry.mark_source_stop_requested(&transition_id)
            }));
        }
        barrier.wait();
        let mut codes = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| io::Error::other("handoff worker panicked"))
                    .map(|result| result.map(|_| "ok").unwrap_or_else(|error| error.code()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        codes.sort_unstable();
        assert_eq!(codes, vec!["conversation_handoff_phase_invalid", "ok"]);
        let document = registry.load()?;
        assert_eq!(document.revision, revision_before + 1);
        assert_eq!(
            document
                .active_transition
                .as_ref()
                .map(|transition| transition.phase),
            Some(HandoffPhase::SourceStopRequested)
        );
        validate_document(&document)?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn v2_journal_persists_only_local_bounded_metadata_and_rejects_downgrade()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("v2-redaction-downgrade")?;
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let registry = ConversationRegistry::at(root.clone());
        let source = registry.adopt(binding(&workspace, Uuid::new_v4(), Uuid::new_v4()))?;
        registry.prepare_handoff(handoff_preparation(
            &source,
            Uuid::new_v4(),
            Uuid::new_v4(),
            401,
        ))?;

        let serialized = fs::read_to_string(root.join(REGISTRY_FILE))?;
        assert!(serialized.contains("\"relative_path\""));
        assert!(!serialized.contains("/sessions/rollout-"));
        for forbidden in [
            "\"alias\"",
            "\"token\"",
            "\"provider_account_id\"",
            "\"provider_workspace_id\"",
            "\"transcript\"",
            "\"prompt\"",
            "\"response\"",
            "\"tool_payload\"",
            "\"rollout_path\"",
        ] {
            assert!(!serialized.contains(forbidden), "persisted {forbidden}");
        }
        let v2 = registry.load()?;
        assert_eq!(v2.schema_version, SCHEMA_VERSION_V2);
        assert_eq!(
            validate_v1_document(&v2).err().map(|error| error.code()),
            Some("conversation_registry_invalid")
        );
        let backup: ConversationDocument =
            serde_json::from_slice(&fs::read(root.join(PRE_MIGRATION_BACKUP_FILE))?)?;
        validate_v1_document(&backup)?;

        fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;

    #[test]
    fn unverified_private_acl_boundaries_fail_closed() {
        for result in [
            verify_private_directory(Path::new("unused")),
            verify_private_regular_file(Path::new("unused")),
        ] {
            assert_eq!(
                result.err().map(|error| error.code()),
                Some("codex_session_schema_unsupported")
            );
        }
    }
}
