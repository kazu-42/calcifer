//! Same-profile Codex thread capture and crash reconciliation.
//!
//! Every App Server call in this module runs while the caller owns the
//! profile's coordinator/provider lease. Registry transactions are deliberately
//! short and never span provider I/O.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use crate::cli::InternalProcessMode;
use crate::conversations::{
    BindingInput, ConversationError, ConversationLifecycle, ConversationRegistry, HeadBinding,
    InventoryThread, LaunchMode, LaunchResolution, PendingPhase,
};
use crate::error::AppError;
use crate::profiles::ProfileLease;
use crate::providers::codex::{
    CodexThreadError, CodexThreadInventory, CodexThreadLifecycle, CodexThreadRead,
    read_thread_inventory, read_thread_metadata,
};

const THREAD_METADATA_TIMEOUT: Duration = Duration::from_secs(10);

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

        let read = match self.read_thread(thread_id) {
            Ok(read) => read,
            Err(AppError::Conversation(ConversationError::SessionSchemaUnsupported))
                if mode == InternalProcessMode::ResumeExact =>
            {
                eprintln!(
                    "Calcifer: the installed Codex version is outside the tracked-session adapter; continuing with explicit exact resume without changing the conversation registry."
                );
                return Ok(GuardianCapture::UnsupportedExplicit);
            }
            Err(error) => return Err(error),
        };

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
        let inventory = self.inventory()?;
        if !inventory.complete {
            let _ = self
                .conversations
                .finish_launch(launch_id, LaunchResolution::Ambiguous)?;
            return Err(ConversationError::Ambiguous.into());
        }
        if inventory.codex_version != pending.codex_version {
            return Err(ConversationError::SessionSchemaUnsupported.into());
        }

        match inventory_candidate(&pending.pre_inventory, &inventory_projection(&inventory)) {
            InventoryCandidate::None => {
                let _ = self
                    .conversations
                    .finish_launch(launch_id, LaunchResolution::NoThread)?;
                Ok(())
            }
            InventoryCandidate::One(thread_id) => {
                let read = self.read_thread(&thread_id)?;
                if read.codex_version != pending.codex_version {
                    return Err(ConversationError::SessionSchemaUnsupported.into());
                }
                let mut binding = self.binding_from_read(read)?;
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
                let _ = self.conversations.mark_capture_failed(&pending.launch_id);
                return Err(error);
            }
        };
        if !inventory.complete {
            let _ = self
                .conversations
                .finish_launch(&pending.launch_id, LaunchResolution::Ambiguous)?;
            return Err(ConversationError::Ambiguous.into());
        }
        if inventory.codex_version != pending.codex_version {
            let _ = self.conversations.mark_capture_failed(&pending.launch_id);
            return Err(ConversationError::SessionSchemaUnsupported.into());
        }

        match inventory_candidate(&pending.pre_inventory, &inventory_projection(&inventory)) {
            InventoryCandidate::None => {
                let _ = self
                    .conversations
                    .finish_launch(&pending.launch_id, LaunchResolution::NoThread)?;
                if pending.phase == PendingPhase::CaptureFailed {
                    return Err(ConversationError::Ambiguous.into());
                }
                Ok(())
            }
            InventoryCandidate::One(thread_id) => {
                let read = match self.read_thread(&thread_id) {
                    Ok(read) => read,
                    Err(error) => {
                        let _ = self.conversations.mark_capture_failed(&pending.launch_id);
                        return Err(error);
                    }
                };
                if read.codex_version != pending.codex_version {
                    let _ = self.conversations.mark_capture_failed(&pending.launch_id);
                    return Err(ConversationError::SessionSchemaUnsupported.into());
                }
                let mut binding = self.binding_from_read(read)?;
                binding.lifecycle = match binding.lifecycle {
                    ConversationLifecycle::Interrupted => ConversationLifecycle::Interrupted,
                    ConversationLifecycle::Clean | ConversationLifecycle::UnknownCrash => {
                        ConversationLifecycle::UnknownCrash
                    }
                    ConversationLifecycle::Missing
                    | ConversationLifecycle::Archived
                    | ConversationLifecycle::Incompatible
                    | ConversationLifecycle::Ambiguous => {
                        return Err(ConversationError::SessionSchemaUnsupported.into());
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
        CodexThreadError::UnsupportedVersion | CodexThreadError::SessionSchema => {
            ConversationError::SessionSchemaUnsupported
        }
        CodexThreadError::CwdMismatch => ConversationError::CwdMismatch,
        CodexThreadError::Missing => ConversationError::RolloutMissing,
        CodexThreadError::Archived => ConversationError::Archived,
        CodexThreadError::Protocol
        | CodexThreadError::Authentication
        | CodexThreadError::Timeout
        | CodexThreadError::Transport
        | CodexThreadError::Provider
        | CodexThreadError::Spawn => ConversationError::ThreadProtocolInvalid,
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
    let baseline: BTreeMap<&str, (i64, Option<i64>, bool)> = baseline
        .iter()
        .map(|thread| {
            (
                thread.thread_id.as_str(),
                (thread.updated_at, thread.recency_at, thread.archived),
            )
        })
        .collect();
    let mut candidates = current.iter().filter(|thread| {
        baseline.get(thread.thread_id.as_str()).copied()
            != Some((thread.updated_at, thread.recency_at, thread.archived))
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
    use super::*;

    #[test]
    fn inventory_diff_never_guesses_between_new_changed_or_archived_threads() {
        let first = InventoryThread {
            thread_id: "01900000-0000-7000-8000-000000000001".to_owned(),
            updated_at: 10,
            recency_at: Some(10),
            archived: false,
        };
        let second = InventoryThread {
            thread_id: "01900000-0000-7000-8000-000000000002".to_owned(),
            updated_at: 20,
            recency_at: Some(20),
            archived: false,
        };

        assert_eq!(
            inventory_candidate(std::slice::from_ref(&first), std::slice::from_ref(&first)),
            InventoryCandidate::None
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
}
