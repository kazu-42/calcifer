//! Same-profile Codex thread capture and crash reconciliation.
//!
//! Every App Server call in this module runs while the caller owns the
//! profile's coordinator/provider lease. Registry transactions are deliberately
//! short and never span provider I/O.

#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use crate::cli::InternalProcessMode;
use crate::conversations::{
    BindingInput, ConversationError, ConversationLifecycle, ConversationRegistry, HeadBinding,
    InventoryThread, LaunchMode, LaunchResolution, PendingLaunch, PendingPhase,
};
use crate::error::AppError;
use crate::profiles::ProfileLease;
use crate::providers::codex::{
    CodexThreadError, CodexThreadInventory, CodexThreadLifecycle, CodexThreadRead,
    SUPPORTED_CODEX_STATUS_VERSIONS, probe_codex_version, read_thread_inventory,
    read_thread_metadata,
};

const THREAD_METADATA_TIMEOUT: Duration = Duration::from_secs(10);
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) enum GuardianCapture {
    /// Derive the exact thread from a bounded before/after inventory.
    Tracked { launch_id: String },
    /// The exact thread was authoritative and adopted before provider start.
    Bound { thread_id: String },
    /// Keep stable exact resume available outside the pinned metadata adapter.
    UnsupportedExplicit,
}

impl GuardianCapture {
    pub(super) fn launch_id(&self) -> Option<&str> {
        match self {
            Self::Tracked { launch_id } => Some(launch_id),
            Self::Bound { .. } | Self::UnsupportedExplicit => None,
        }
    }
}

/// All resources required for a capture generation. Construction itself does
/// no I/O; the caller controls the profile-lock lifetime.
pub(super) struct CaptureContext<'a> {
    conversations: &'a ConversationRegistry,
    provider_lease: &'a ProfileLease,
    executable: &'a Path,
    home: &'a Path,
    neutral_working_directory: &'a Path,
    profile_id: &'a str,
    working_directory: &'a Path,
}

impl<'a> CaptureContext<'a> {
    pub(super) fn new(
        conversations: &'a ConversationRegistry,
        provider_lease: &'a ProfileLease,
        executable: &'a Path,
        home: &'a Path,
        neutral_working_directory: &'a Path,
        profile_id: &'a str,
        working_directory: &'a Path,
    ) -> Self {
        Self {
            conversations,
            provider_lease,
            executable,
            home,
            neutral_working_directory,
            profile_id,
            working_directory,
        }
    }

    pub(super) fn prepare(
        &self,
        mode: InternalProcessMode,
        session_id: Option<&str>,
    ) -> Result<GuardianCapture, AppError> {
        match mode {
            InternalProcessMode::Run | InternalProcessMode::ResumeLast => {
                self.reconcile_pending_launch()?;
                let inventory = self.inventory()?;
                if !inventory.complete {
                    self.conversations
                        .mark_workspace_ambiguous(self.working_directory)?;
                    return Err(ConversationError::Ambiguous.into());
                }
                let launch_mode = match mode {
                    InternalProcessMode::Run => LaunchMode::Run,
                    InternalProcessMode::ResumeLast => LaunchMode::ResumeLast,
                    InternalProcessMode::ResumeExact | InternalProcessMode::ResumeHead => {
                        unreachable!("exact modes are handled separately")
                    }
                };
                let launch_id = self.conversations.begin_launch(
                    self.profile_id,
                    self.working_directory,
                    launch_mode,
                    &inventory.codex_version,
                    inventory_projection(&inventory),
                )?;
                Ok(GuardianCapture::Tracked { launch_id })
            }
            InternalProcessMode::ResumeExact | InternalProcessMode::ResumeHead => {
                self.prepare_exact(mode, session_id)
            }
        }
    }

    /// Durably crosses the non-idempotent spawn boundary. Once this returns,
    /// crash recovery must assume that a provider may have existed even if no
    /// thread was materialized. Keeping `Prepared` strictly pre-spawn makes a
    /// zero-candidate prepared launch safe to discard.
    pub(super) fn authorize_provider_spawn(
        &self,
        capture: &GuardianCapture,
    ) -> Result<(), AppError> {
        if let Some(launch_id) = capture.launch_id() {
            self.conversations.mark_provider_started(launch_id)?;
        }
        Ok(())
    }

    /// `Command::spawn` returned an error, so no interactive child can be
    /// waited on. Remove the conservative spawn marker without changing an
    /// existing workspace head.
    pub(super) fn provider_spawn_failed(&self, capture: &GuardianCapture) -> Result<(), AppError> {
        if let Some(launch_id) = capture.launch_id() {
            let _ = self
                .conversations
                .finish_launch(launch_id, LaunchResolution::NoThread)?;
        }
        Ok(())
    }

    fn prepare_exact(
        &self,
        mode: InternalProcessMode,
        session_id: Option<&str>,
    ) -> Result<GuardianCapture, AppError> {
        let thread_id = session_id.ok_or(AppError::ProviderArgumentRejected)?;
        if mode == InternalProcessMode::ResumeHead {
            let head = self.conversations.resolve_head(self.working_directory)?;
            validate_head_target(&head, self.profile_id, thread_id, self.working_directory)?;
        }

        if mode == InternalProcessMode::ResumeExact {
            let codex_version = self.probe_version()?;
            if !SUPPORTED_CODEX_STATUS_VERSIONS.contains(&codex_version.as_str()) {
                eprintln!(
                    "Calcifer: the installed Codex version is outside the tracked-session adapter; continuing with explicit exact resume without changing the conversation registry."
                );
                return Ok(GuardianCapture::UnsupportedExplicit);
            }
        }

        let read = self.read_thread(thread_id)?;

        if mode == InternalProcessMode::ResumeHead {
            let head = self.conversations.resolve_head(self.working_directory)?;
            validate_head_target(&head, self.profile_id, thread_id, self.working_directory)?;
            if head.codex_version != read.codex_version {
                return Err(ConversationError::SessionSchemaUnsupported.into());
            }
        }

        let binding = self.binding_from_read(read)?;
        if let Some(pending) = self
            .conversations
            .pending_for(self.profile_id, self.working_directory)?
        {
            // Explicit selection is authoritative recovery. Adoption below
            // clears an older needs_selection head after pending removal.
            let _ = self
                .conversations
                .finish_launch(&pending.launch_id, LaunchResolution::Bind(binding.clone()))?;
        }
        let adopted = self.conversations.adopt(binding)?;
        warn_if_unclean_resume(adopted.lifecycle);
        Ok(GuardianCapture::Bound {
            thread_id: thread_id.to_owned(),
        })
    }

    /// Capture never changes the official provider status and never retries a
    /// provider launch. Failure only marks later automatic selection unsafe.
    pub(super) fn complete(&self, capture: &GuardianCapture, provider_succeeded: bool) {
        let result = match capture {
            GuardianCapture::Tracked { launch_id } => {
                self.complete_tracked(launch_id, provider_succeeded)
            }
            GuardianCapture::Bound { thread_id } => {
                self.refresh_bound_lifecycle(thread_id, provider_succeeded)
            }
            GuardianCapture::UnsupportedExplicit => Ok(()),
        };

        if let Err(error) = result {
            if let GuardianCapture::Tracked { launch_id } = capture {
                let _ = self.conversations.mark_capture_failed(launch_id);
            } else if matches!(capture, GuardianCapture::Bound { .. }) {
                let _ = self
                    .conversations
                    .mark_workspace_ambiguous(self.working_directory);
            }
            eprintln!(
                "Calcifer: the provider exited, but its conversation checkpoint could not be confirmed ({}). The provider was not launched again.",
                error.code()
            );
        }
    }

    fn complete_tracked(&self, launch_id: &str, provider_succeeded: bool) -> Result<(), AppError> {
        let pending = self
            .conversations
            .pending_for(self.profile_id, self.working_directory)?
            .ok_or(ConversationError::NotFound)?;
        if pending.launch_id != launch_id {
            return Err(ConversationError::Ambiguous.into());
        }
        let inventory = match self.inventory() {
            Ok(inventory) => inventory,
            Err(error) => {
                return finish_reconciliation_failure(self.conversations, launch_id, error);
            }
        };
        if !inventory.complete {
            let _ = self
                .conversations
                .finish_launch(launch_id, LaunchResolution::Ambiguous)?;
            return Err(ConversationError::Ambiguous.into());
        }
        if inventory.codex_version != pending.codex_version {
            return finish_reconciliation_failure(
                self.conversations,
                launch_id,
                ConversationError::SessionSchemaUnsupported.into(),
            );
        }

        match inventory_candidate(&pending.pre_inventory, &inventory_projection(&inventory)) {
            InventoryCandidate::None => {
                let _ = self
                    .conversations
                    .finish_launch(launch_id, LaunchResolution::NoThread)?;
                Ok(())
            }
            InventoryCandidate::One(thread_id) => {
                let read = match self.read_thread(&thread_id) {
                    Ok(read) => read,
                    Err(error) => {
                        return finish_reconciliation_failure(self.conversations, launch_id, error);
                    }
                };
                if read.codex_version != pending.codex_version {
                    return finish_reconciliation_failure(
                        self.conversations,
                        launch_id,
                        ConversationError::SessionSchemaUnsupported.into(),
                    );
                }
                let mut binding = match self.binding_from_read(read) {
                    Ok(binding) => binding,
                    Err(error) => {
                        return finish_reconciliation_failure(self.conversations, launch_id, error);
                    }
                };
                if !provider_succeeded && binding.lifecycle == ConversationLifecycle::Clean {
                    binding.lifecycle = ConversationLifecycle::UnknownCrash;
                }
                let resolved = self
                    .conversations
                    .finish_launch(launch_id, LaunchResolution::Bind(binding))?;
                if resolved.is_none() {
                    return Err(ConversationError::Ambiguous.into());
                }
                Ok(())
            }
            InventoryCandidate::Ambiguous => {
                let _ = self
                    .conversations
                    .finish_launch(launch_id, LaunchResolution::Ambiguous)?;
                Err(ConversationError::Ambiguous.into())
            }
        }
    }

    fn refresh_bound_lifecycle(
        &self,
        thread_id: &str,
        provider_succeeded: bool,
    ) -> Result<(), AppError> {
        let read = self.read_thread(thread_id)?;
        let mut binding = self.binding_from_read(read)?;
        if !provider_succeeded && binding.lifecycle == ConversationLifecycle::Clean {
            binding.lifecycle = ConversationLifecycle::UnknownCrash;
        }
        self.conversations.adopt(binding)?;
        Ok(())
    }

    pub(super) fn reconcile_pending_launch(&self) -> Result<(), AppError> {
        let Some(pending) = self
            .conversations
            .pending_for(self.profile_id, self.working_directory)?
        else {
            return Ok(());
        };
        let inventory = match self.inventory() {
            Ok(inventory) => inventory,
            Err(error) => {
                return finish_reconciliation_failure(
                    self.conversations,
                    &pending.launch_id,
                    error,
                );
            }
        };
        if !inventory.complete {
            let _ = self
                .conversations
                .finish_launch(&pending.launch_id, LaunchResolution::Ambiguous)?;
            return Err(ConversationError::Ambiguous.into());
        }
        if inventory.codex_version != pending.codex_version {
            return finish_reconciliation_failure(
                self.conversations,
                &pending.launch_id,
                ConversationError::SessionSchemaUnsupported.into(),
            );
        }

        match inventory_candidate(&pending.pre_inventory, &inventory_projection(&inventory)) {
            InventoryCandidate::None => match pending.phase {
                PendingPhase::Prepared => {
                    let _ = self
                        .conversations
                        .finish_launch(&pending.launch_id, LaunchResolution::NoThread)?;
                    Ok(())
                }
                PendingPhase::ProviderStarted | PendingPhase::CaptureFailed => {
                    let _ = self
                        .conversations
                        .finish_launch(&pending.launch_id, LaunchResolution::Ambiguous)?;
                    Err(ConversationError::Ambiguous.into())
                }
            },
            InventoryCandidate::One(thread_id) => {
                require_started_candidate(self.conversations, &pending)?;
                let read = match self.read_thread(&thread_id) {
                    Ok(read) => read,
                    Err(error) => {
                        return finish_reconciliation_failure(
                            self.conversations,
                            &pending.launch_id,
                            error,
                        );
                    }
                };
                if read.codex_version != pending.codex_version {
                    return finish_reconciliation_failure(
                        self.conversations,
                        &pending.launch_id,
                        ConversationError::SessionSchemaUnsupported.into(),
                    );
                }
                let mut binding = match self.binding_from_read(read) {
                    Ok(binding) => binding,
                    Err(error) => {
                        return finish_reconciliation_failure(
                            self.conversations,
                            &pending.launch_id,
                            error,
                        );
                    }
                };
                binding.lifecycle = match binding.lifecycle {
                    ConversationLifecycle::Interrupted => ConversationLifecycle::Interrupted,
                    ConversationLifecycle::Clean | ConversationLifecycle::UnknownCrash => {
                        ConversationLifecycle::UnknownCrash
                    }
                    ConversationLifecycle::Missing
                    | ConversationLifecycle::Archived
                    | ConversationLifecycle::Incompatible
                    | ConversationLifecycle::Ambiguous => {
                        return finish_reconciliation_failure(
                            self.conversations,
                            &pending.launch_id,
                            ConversationError::SessionSchemaUnsupported.into(),
                        );
                    }
                };
                let resolved = self
                    .conversations
                    .finish_launch(&pending.launch_id, LaunchResolution::Bind(binding))?;
                if resolved.is_none() {
                    return Err(ConversationError::Ambiguous.into());
                }
                Ok(())
            }
            InventoryCandidate::Ambiguous => {
                let _ = self
                    .conversations
                    .finish_launch(&pending.launch_id, LaunchResolution::Ambiguous)?;
                Err(ConversationError::Ambiguous.into())
            }
        }
    }

    fn inventory(&self) -> Result<CodexThreadInventory, AppError> {
        let _inheritance = self.provider_lease.inherit_provider_lock()?;
        read_thread_inventory(
            self.executable,
            self.home,
            self.neutral_working_directory,
            self.working_directory,
            THREAD_METADATA_TIMEOUT,
        )
        .map_err(map_thread_error)
        .map_err(AppError::from)
    }

    fn probe_version(&self) -> Result<String, AppError> {
        let _inheritance = self.provider_lease.inherit_provider_lock()?;
        probe_codex_version(
            self.executable,
            self.home,
            self.neutral_working_directory,
            VERSION_PROBE_TIMEOUT,
        )
        .map_err(map_thread_error)
        .map_err(AppError::from)
    }

    fn read_thread(&self, thread_id: &str) -> Result<CodexThreadRead, AppError> {
        let _inheritance = self.provider_lease.inherit_provider_lock()?;
        read_thread_metadata(
            self.executable,
            self.home,
            self.neutral_working_directory,
            self.working_directory,
            thread_id,
            THREAD_METADATA_TIMEOUT,
        )
        .map_err(map_thread_error)
        .map_err(AppError::from)
    }

    fn binding_from_read(&self, read: CodexThreadRead) -> Result<BindingInput, AppError> {
        let canonical_cwd = std::fs::canonicalize(self.working_directory)
            .map_err(|_| ConversationError::CwdMismatch)?;
        if canonical_cwd != read.metadata.canonical_cwd {
            return Err(ConversationError::CwdMismatch.into());
        }
        let canonical_cwd = canonical_cwd
            .to_str()
            .ok_or(ConversationError::CwdMismatch)?
            .to_owned();
        Ok(BindingInput {
            profile_id: self.profile_id.to_owned(),
            thread_id: read.metadata.thread_id,
            canonical_cwd,
            codex_version: read.codex_version,
            lifecycle: map_thread_lifecycle(read.lifecycle),
        })
    }
}

fn require_started_candidate(
    conversations: &ConversationRegistry,
    pending: &PendingLaunch,
) -> Result<(), AppError> {
    if pending.phase != PendingPhase::Prepared {
        return Ok(());
    }
    let _ = conversations.finish_launch(&pending.launch_id, LaunchResolution::Ambiguous)?;
    Err(ConversationError::Ambiguous.into())
}

fn finish_reconciliation_failure(
    conversations: &ConversationRegistry,
    launch_id: &str,
    error: AppError,
) -> Result<(), AppError> {
    let terminal = matches!(
        &error,
        AppError::Conversation(
            ConversationError::RolloutMissing
                | ConversationError::Archived
                | ConversationError::SessionSchemaUnsupported
                | ConversationError::CodexVersionUnsupported
                | ConversationError::CwdMismatch
                | ConversationError::ThreadProtocolInvalid
        )
    );
    if terminal {
        let _ = conversations.finish_launch(launch_id, LaunchResolution::Ambiguous)?;
    } else {
        conversations.mark_capture_failed(launch_id)?;
    }
    Err(error)
}

pub(super) fn validate_head_target(
    head: &HeadBinding,
    profile_id: &str,
    thread_id: &str,
    working_directory: &Path,
) -> Result<(), AppError> {
    if head.profile_id != profile_id {
        return Err(ConversationError::ProfileMismatch.into());
    }
    if head.thread_id != thread_id {
        return Err(ConversationError::Ambiguous.into());
    }
    let canonical_cwd =
        std::fs::canonicalize(working_directory).map_err(|_| ConversationError::CwdMismatch)?;
    if canonical_cwd.to_str() != Some(head.canonical_cwd.as_str()) {
        return Err(ConversationError::CwdMismatch.into());
    }
    Ok(())
}

fn map_thread_error(error: CodexThreadError) -> ConversationError {
    match error {
        CodexThreadError::UnsupportedVersion => ConversationError::CodexVersionUnsupported,
        CodexThreadError::SessionSchema => ConversationError::SessionSchemaUnsupported,
        CodexThreadError::CwdMismatch => ConversationError::CwdMismatch,
        CodexThreadError::Missing => ConversationError::RolloutMissing,
        CodexThreadError::Archived => ConversationError::Archived,
        CodexThreadError::Protocol => ConversationError::ThreadProtocolInvalid,
        CodexThreadError::Authentication
        | CodexThreadError::Timeout
        | CodexThreadError::Transport
        | CodexThreadError::Provider
        | CodexThreadError::Spawn => ConversationError::ThreadMetadataUnavailable,
    }
}

const fn map_thread_lifecycle(lifecycle: CodexThreadLifecycle) -> ConversationLifecycle {
    match lifecycle {
        CodexThreadLifecycle::Clean => ConversationLifecycle::Clean,
        CodexThreadLifecycle::Interrupted => ConversationLifecycle::Interrupted,
        CodexThreadLifecycle::UnknownCrash => ConversationLifecycle::UnknownCrash,
    }
}

fn warn_if_unclean_resume(lifecycle: ConversationLifecycle) {
    match lifecycle {
        ConversationLifecycle::Interrupted => eprintln!(
            "Calcifer: the tracked Codex conversation ended at an interrupted turn boundary; reopening its exact history without submitting a prompt."
        ),
        ConversationLifecycle::UnknownCrash => eprintln!(
            "Calcifer: the tracked Codex conversation did not have a provably clean boundary; reopening its exact history without submitting a prompt."
        ),
        ConversationLifecycle::Clean
        | ConversationLifecycle::Missing
        | ConversationLifecycle::Archived
        | ConversationLifecycle::Incompatible
        | ConversationLifecycle::Ambiguous => {}
    }
}

fn inventory_projection(inventory: &CodexThreadInventory) -> Vec<InventoryThread> {
    inventory
        .threads
        .iter()
        .map(|thread| InventoryThread {
            thread_id: thread.thread_id.clone(),
            updated_at: thread.updated_at,
            recency_at: thread.recency_at,
            archived: thread.archived,
            rollout_device: thread.rollout_fingerprint.device,
            rollout_inode: thread.rollout_fingerprint.inode,
            rollout_length: thread.rollout_fingerprint.length,
            rollout_modified_seconds: thread.rollout_fingerprint.modified_seconds,
            rollout_modified_nanoseconds: thread.rollout_fingerprint.modified_nanoseconds,
            rollout_changed_seconds: thread.rollout_fingerprint.changed_seconds,
            rollout_changed_nanoseconds: thread.rollout_fingerprint.changed_nanoseconds,
        })
        .collect()
}

#[derive(Debug, Eq, PartialEq)]
enum InventoryCandidate {
    None,
    One(String),
    Ambiguous,
}

fn inventory_candidate(
    baseline: &[InventoryThread],
    current: &[InventoryThread],
) -> InventoryCandidate {
    let baseline: BTreeMap<&str, &InventoryThread> = baseline
        .iter()
        .map(|thread| (thread.thread_id.as_str(), thread))
        .collect();
    let current_ids: BTreeSet<&str> = current
        .iter()
        .map(|thread| thread.thread_id.as_str())
        .collect();
    if baseline
        .keys()
        .any(|thread_id| !current_ids.contains(thread_id))
    {
        return InventoryCandidate::Ambiguous;
    }
    let mut candidates = current.iter().filter(|thread| {
        baseline
            .get(thread.thread_id.as_str())
            .is_none_or(|baseline| *baseline != *thread)
    });
    let first = candidates.next().map(|thread| thread.thread_id.clone());
    match (first, candidates.next()) {
        (None, _) => InventoryCandidate::None,
        (Some(thread_id), None) => InventoryCandidate::One(thread_id),
        (Some(_), Some(_)) => InventoryCandidate::Ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::*;
    use crate::profiles::Registry;

    struct PendingFixture {
        root: PathBuf,
        workspace: PathBuf,
        conversations: ConversationRegistry,
        profile_id: String,
        launch_id: String,
    }

    fn registry_fixture(
        name: &str,
        provider_started: bool,
    ) -> Result<PendingFixture, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "calcifer-reconcile-{name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let workspace = root.join("workspace");
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        fs::DirBuilder::new().mode(0o700).create(&workspace)?;
        let profiles = Registry::at(root.clone());
        let conversations = ConversationRegistry::from_profiles(&profiles);
        let profile_id = Uuid::new_v4().to_string();
        let launch_id = conversations.begin_launch(
            &profile_id,
            &workspace,
            LaunchMode::Run,
            "0.144.4",
            Vec::new(),
        )?;
        if provider_started {
            conversations.mark_provider_started(&launch_id)?;
        }
        Ok(PendingFixture {
            root,
            workspace,
            conversations,
            profile_id,
            launch_id,
        })
    }

    fn pending_registry(name: &str) -> Result<PendingFixture, Box<dyn std::error::Error>> {
        registry_fixture(name, true)
    }

    fn inventory_thread(thread_id: &str, updated_at: i64) -> InventoryThread {
        InventoryThread {
            thread_id: thread_id.to_owned(),
            updated_at,
            recency_at: Some(updated_at),
            archived: false,
            rollout_device: 1,
            rollout_inode: 2,
            rollout_length: 3,
            rollout_modified_seconds: 4,
            rollout_modified_nanoseconds: 5,
            rollout_changed_seconds: 6,
            rollout_changed_nanoseconds: 7,
        }
    }

    #[test]
    fn inventory_diff_never_guesses_between_new_changed_or_archived_threads() {
        let first = inventory_thread("01900000-0000-7000-8000-000000000001", 10);
        let second = inventory_thread("01900000-0000-7000-8000-000000000002", 20);

        assert_eq!(
            inventory_candidate(std::slice::from_ref(&first), std::slice::from_ref(&first)),
            InventoryCandidate::None
        );
        assert_eq!(
            inventory_candidate(std::slice::from_ref(&first), &[]),
            InventoryCandidate::Ambiguous,
            "a deleted baseline thread must never preserve a stale head"
        );
        assert_eq!(
            inventory_candidate(std::slice::from_ref(&first), std::slice::from_ref(&second)),
            InventoryCandidate::Ambiguous,
            "a deletion plus a new thread is not a unique launch candidate"
        );
        let mut changed = first.clone();
        changed.updated_at += 1;
        assert_eq!(
            inventory_candidate(std::slice::from_ref(&first), std::slice::from_ref(&changed)),
            InventoryCandidate::One(first.thread_id.clone())
        );
        assert_eq!(
            inventory_candidate(std::slice::from_ref(&first), &[changed, second]),
            InventoryCandidate::Ambiguous
        );
        let mut archived = first.clone();
        archived.archived = true;
        assert_eq!(
            inventory_candidate(std::slice::from_ref(&first), &[archived]),
            InventoryCandidate::One(first.thread_id)
        );
    }

    #[test]
    fn inventory_diff_detects_same_second_rollout_changes() {
        let original = inventory_thread("01900000-0000-7000-8000-000000000001", 10);

        let mut length_changed = original.clone();
        length_changed.rollout_length += 1;
        assert_eq!(
            inventory_candidate(
                std::slice::from_ref(&original),
                std::slice::from_ref(&length_changed)
            ),
            InventoryCandidate::One(original.thread_id.clone())
        );

        let mut nanoseconds_changed = original.clone();
        nanoseconds_changed.rollout_modified_nanoseconds += 1;
        assert_eq!(
            inventory_candidate(
                std::slice::from_ref(&original),
                std::slice::from_ref(&nanoseconds_changed)
            ),
            InventoryCandidate::One(original.thread_id.clone())
        );

        let mut renamed = original.clone();
        renamed.rollout_changed_nanoseconds += 1;
        assert_eq!(
            inventory_candidate(
                std::slice::from_ref(&original),
                std::slice::from_ref(&renamed)
            ),
            InventoryCandidate::One(original.thread_id.clone()),
            "a path-free ctime fingerprint must detect a same-inode rename"
        );
    }

    #[test]
    fn thread_error_mapping_separates_terminal_schema_from_retryable_availability() {
        assert!(matches!(
            map_thread_error(CodexThreadError::Protocol),
            ConversationError::ThreadProtocolInvalid
        ));
        for retryable in [
            CodexThreadError::Authentication,
            CodexThreadError::Timeout,
            CodexThreadError::Transport,
            CodexThreadError::Provider,
            CodexThreadError::Spawn,
        ] {
            assert!(matches!(
                map_thread_error(retryable),
                ConversationError::ThreadMetadataUnavailable
            ));
        }
    }

    #[test]
    fn archive_transition_is_detected_but_cannot_be_bound_automatically()
    -> Result<(), Box<dyn std::error::Error>> {
        let active = inventory_thread("01900000-0000-7000-8000-000000000001", 10);
        let mut archived = active.clone();
        archived.archived = true;
        assert_eq!(
            inventory_candidate(std::slice::from_ref(&active), &[archived]),
            InventoryCandidate::One(active.thread_id)
        );

        let fixture = pending_registry("archive-transition")?;
        let error = finish_reconciliation_failure(
            &fixture.conversations,
            &fixture.launch_id,
            ConversationError::Archived.into(),
        )
        .err()
        .ok_or_else(|| std::io::Error::other("archived read unexpectedly succeeded"))?;
        assert_eq!(error.code(), "conversation_archived");
        assert!(
            fixture
                .conversations
                .pending_for(&fixture.profile_id, &fixture.workspace)?
                .is_none()
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn terminal_candidate_failures_remove_pending_and_require_selection()
    -> Result<(), Box<dyn std::error::Error>> {
        for failure in [
            ConversationError::RolloutMissing,
            ConversationError::Archived,
            ConversationError::SessionSchemaUnsupported,
            ConversationError::CodexVersionUnsupported,
            ConversationError::CwdMismatch,
            ConversationError::ThreadProtocolInvalid,
        ] {
            let expected_code = failure.code();
            let fixture = pending_registry(expected_code)?;

            let error = finish_reconciliation_failure(
                &fixture.conversations,
                &fixture.launch_id,
                failure.into(),
            )
            .err()
            .ok_or_else(|| std::io::Error::other("terminal failure unexpectedly succeeded"))?;

            assert_eq!(error.code(), expected_code);
            assert!(
                fixture
                    .conversations
                    .pending_for(&fixture.profile_id, &fixture.workspace)?
                    .is_none(),
                "terminal failure {expected_code} left a retry loop"
            );
            assert_eq!(
                fixture
                    .conversations
                    .resolve_head(&fixture.workspace)
                    .err()
                    .map(|error| error.code()),
                Some("conversation_ambiguous")
            );
            fs::remove_dir_all(fixture.root)?;
        }
        Ok(())
    }

    #[test]
    fn transient_candidate_failure_remains_retryable() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = pending_registry("transient")?;

        let error = finish_reconciliation_failure(
            &fixture.conversations,
            &fixture.launch_id,
            ConversationError::ThreadMetadataUnavailable.into(),
        )
        .err()
        .ok_or_else(|| std::io::Error::other("transient failure unexpectedly succeeded"))?;

        assert_eq!(error.code(), "codex_thread_metadata_unavailable");
        assert_eq!(
            fixture
                .conversations
                .pending_for(&fixture.profile_id, &fixture.workspace)?
                .map(|pending| pending.phase),
            Some(PendingPhase::CaptureFailed),
            "a retryable metadata failure must retain its pending launch"
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn transient_candidate_registry_failure_is_not_hidden() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = pending_registry("registry-failure")?;
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755))?;

        let error = finish_reconciliation_failure(
            &fixture.conversations,
            &fixture.launch_id,
            ConversationError::ThreadMetadataUnavailable.into(),
        )
        .err()
        .ok_or_else(|| std::io::Error::other("unsafe registry unexpectedly succeeded"))?;

        assert_eq!(error.code(), "conversation_registry_invalid");
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700))?;
        assert_eq!(
            fixture
                .conversations
                .pending_for(&fixture.profile_id, &fixture.workspace)?
                .map(|pending| pending.phase),
            Some(PendingPhase::ProviderStarted),
            "a failed registry mutation must not be reported as capture_failed"
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn prepared_launch_never_binds_a_later_candidate() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = registry_fixture("prepared-candidate", false)?;
        let pending = fixture
            .conversations
            .pending_for(&fixture.profile_id, &fixture.workspace)?
            .ok_or_else(|| std::io::Error::other("prepared launch is missing"))?;

        let error = require_started_candidate(&fixture.conversations, &pending)
            .err()
            .ok_or_else(|| std::io::Error::other("prepared candidate was accepted"))?;

        assert_eq!(error.code(), "conversation_ambiguous");
        assert!(
            fixture
                .conversations
                .pending_for(&fixture.profile_id, &fixture.workspace)?
                .is_none()
        );
        assert_eq!(
            fixture
                .conversations
                .resolve_head(&fixture.workspace)
                .err()
                .map(|error| error.code()),
            Some("conversation_ambiguous")
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
