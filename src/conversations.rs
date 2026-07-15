//! Crash-safe bindings between Calcifer workspaces and provider-owned threads.
//!
//! This registry deliberately contains only local opaque identifiers and
//! bounded metadata. Provider payloads, prompts, previews, rollout paths, and
//! credentials never enter this document.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::profiles::{Provider, Registry};

const SCHEMA_VERSION: u8 = 1;
const REGISTRY_FILE: &str = "conversations.json";
const LOCK_FILE: &str = "conversations.lock";
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_INVENTORY_THREADS: usize = 1_600;

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
}

impl Default for ConversationDocument {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            conversations: Vec::new(),
            workspace_heads: Vec::new(),
            pending_launches: Vec::new(),
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
}

#[derive(Clone, Debug)]
pub(crate) struct ConversationRegistry {
    root: PathBuf,
    #[cfg(test)]
    fault: Option<WriteFault>,
}

impl ConversationRegistry {
    pub(crate) fn from_profiles(registry: &Registry) -> Self {
        Self {
            root: registry.managed_root().to_owned(),
            #[cfg(test)]
            fault: None,
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
            ConversationError::RegistryInvalid("registry is not valid schema v1 JSON".to_owned())
        })?;
        if document.schema_version != SCHEMA_VERSION {
            return Err(ConversationError::RegistryInvalid(format!(
                "unsupported conversation registry schema {}",
                document.schema_version
            )));
        }
        validate_document(&document)?;
        Ok(document)
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
        let mut options = private_open_options();
        let mut file = options.write(true).create_new(true).open(&temporary)?;
        file.write_all(&bytes)?;

        #[cfg(test)]
        if self.fault == Some(WriteFault::BeforeFileSync) {
            drop(file);
            remove_exact_temporary(&temporary, &temporary_name)?;
            return Err(ConversationError::Io(io::Error::other(
                "injected failure before file sync",
            )));
        }

        file.sync_all()?;
        verify_private_regular_file(&temporary)?;
        drop(file);

        #[cfg(test)]
        if self.fault == Some(WriteFault::BeforeRename) {
            remove_exact_temporary(&temporary, &temporary_name)?;
            return Err(ConversationError::Io(io::Error::other(
                "injected failure before rename",
            )));
        }

        if let Err(error) = fs::rename(&temporary, &destination) {
            let _ = remove_exact_temporary(&temporary, &temporary_name);
            return Err(error.into());
        }

        #[cfg(test)]
        if self.fault == Some(WriteFault::AfterRename) {
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
    fn at(root: PathBuf) -> Self {
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

fn bind_document(
    document: &mut ConversationDocument,
    binding: BindingInput,
) -> Result<HeadBinding, ConversationError> {
    validate_binding_input(&binding)?;

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
            .first()
            .ok_or_else(|| ConversationError::RegistryInvalid("missing generation".to_owned()))?;
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
    if document.schema_version != SCHEMA_VERSION {
        return Err(ConversationError::RegistryInvalid(
            "unsupported conversation registry schema".to_owned(),
        ));
    }

    for (conversation_index, conversation) in document.conversations.iter().enumerate() {
        validate_uuid(&conversation.conversation_id, "conversation id")?;
        if conversation.provider != Provider::Codex
            || conversation.generations.len() != 1
            || conversation.active_generation != 0
        {
            return Err(ConversationError::RegistryInvalid(format!(
                "conversation {conversation_index} violates schema v1 lineage"
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
        let generation = &conversation.generations[0];
        if generation.generation != 0 {
            return Err(ConversationError::RegistryInvalid(
                "schema v1 generation must be zero".to_owned(),
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
        for previous in document.conversations.iter().take(conversation_index) {
            if previous.conversation_id == conversation.conversation_id
                || previous.generations.iter().any(|previous_generation| {
                    previous_generation.profile_id == generation.profile_id
                        && previous_generation.thread_id == generation.thread_id
                })
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

fn remove_exact_temporary(path: &Path, expected_name: &str) -> Result<(), ConversationError> {
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name)
        || !expected_name.starts_with(&format!(".{REGISTRY_FILE}."))
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
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::sync::{Arc, Barrier};

    use super::*;

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
                WriteFault::AfterRename => {
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
            br#"{"schema_version":2,"revision":0,"conversations":[],"workspace_heads":[],"pending_launches":[]}"#,
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
