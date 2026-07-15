use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::provider_identity::{IdentityError, IdentityKey, IdentityStore, ProviderIdentity};
use crate::providers::codex::CodexIdentityAdapter;

const REGISTRY_SCHEMA_VERSION: u8 = 1;
const REGISTRY_FILE: &str = "profiles.json";
const MAX_REGISTRY_BYTES: usize = 1024 * 1024;
const LOCK_FILE: &str = "registry.lock";
const REMOVAL_LOCK_FILE: &str = "removal.lock";
const REMOVAL_JOURNAL_FILE: &str = "removal.json";
const REMOVAL_JOURNAL_SCHEMA_VERSION: u8 = 1;
const MAX_REMOVAL_JOURNAL_BYTES: usize = 16 * 1024;
const MAX_REMOVAL_TREE_ENTRIES: usize = 100_000;
const MAX_REMOVAL_TREE_DEPTH: usize = 128;
const OWNER_MARKER: &str = ".calcifer-profile";
const COORDINATOR_LOCK_FILE: &str = "profile.lock";
const PROVIDER_LOCK_FILE: &str = "provider.lock";
const MANAGED_CODEX_CONFIG: &[u8] = b"# Managed by Calcifer.\ncli_auth_credentials_store = \"file\"\nmcp_oauth_credentials_store = \"file\"\n";
const MAX_MANAGED_CODEX_CONFIG_BYTES: usize = 1024 * 1024;

// Version-scoped to Codex 0.144.4's published core/config.schema.json. Unknown
// top-level keys fail closed until the compatibility adapter is reviewed.
const CODEX_0_144_4_CONFIG_KEYS: &[&str] = &[
    "agents",
    "allow_login_shell",
    "analytics",
    "approval_policy",
    "approvals_reviewer",
    "apps",
    "apps_mcp_product_sku",
    "audio",
    "auto_review",
    "background_terminal_max_timeout",
    "chatgpt_base_url",
    "check_for_update_on_startup",
    "cli_auth_credentials_store",
    "compact_prompt",
    "debug",
    "default_permissions",
    "desktop",
    "developer_instructions",
    "disable_paste_burst",
    "experimental_compact_prompt_file",
    "experimental_realtime_start_instructions",
    "experimental_realtime_webrtc_call_base_url",
    "experimental_realtime_ws_backend_prompt",
    "experimental_realtime_ws_base_url",
    "experimental_realtime_ws_model",
    "experimental_realtime_ws_startup_context",
    "experimental_thread_config_endpoint",
    "experimental_thread_store",
    "experimental_use_unified_exec_tool",
    "features",
    "feedback",
    "file_opener",
    "forced_chatgpt_workspace_id",
    "forced_login_method",
    "ghost_snapshot",
    "hide_agent_reasoning",
    "history",
    "hooks",
    "include_apps_instructions",
    "include_collaboration_mode_instructions",
    "include_environment_context",
    "include_permissions_instructions",
    "instructions",
    "log_dir",
    "marketplaces",
    "mcp_oauth_callback_port",
    "mcp_oauth_callback_url",
    "mcp_oauth_credentials_store",
    "mcp_servers",
    "memories",
    "model",
    "model_auto_compact_token_limit",
    "model_auto_compact_token_limit_scope",
    "model_catalog_json",
    "model_context_window",
    "model_instructions_file",
    "model_provider",
    "model_providers",
    "model_reasoning_effort",
    "model_reasoning_summary",
    "model_supports_reasoning_summaries",
    "model_verbosity",
    "notice",
    "notify",
    "openai_base_url",
    "orchestrator",
    "oss_provider",
    "otel",
    "permissions",
    "personality",
    "plan_mode_reasoning_effort",
    "plugins",
    "profile",
    "profiles",
    "project_doc_fallback_filenames",
    "project_doc_max_bytes",
    "project_root_markers",
    "projects",
    "realtime",
    "review_model",
    "sandbox_mode",
    "sandbox_workspace_write",
    "service_tier",
    "shell_environment_policy",
    "show_raw_agent_reasoning",
    "skills",
    "sqlite_home",
    "suppress_unstable_features_warning",
    "tool_output_token_limit",
    "tool_suggest",
    "tools",
    "tui",
    "web_search",
    "windows",
];

// These supported Codex keys can redirect the selected account/provider or
// move managed session state outside its profile. Calcifer therefore owns them.
const MANAGED_CODEX_FORBIDDEN_CONFIG_KEYS: &[&str] = &[
    "agents",
    "apps_mcp_product_sku",
    "chatgpt_base_url",
    "debug",
    "experimental_realtime_webrtc_call_base_url",
    "experimental_realtime_ws_base_url",
    "experimental_thread_config_endpoint",
    "experimental_thread_store",
    "features",
    "forced_chatgpt_workspace_id",
    "forced_login_method",
    "log_dir",
    "marketplaces",
    "mcp_oauth_callback_port",
    "mcp_oauth_callback_url",
    "mcp_servers",
    "model_catalog_json",
    "model_provider",
    "model_providers",
    "openai_base_url",
    "oss_provider",
    "plugins",
    "profile",
    "profiles",
    "project_root_markers",
    "sqlite_home",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Provider {
    Codex,
}

impl Provider {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub(crate) id: String,
    pub(crate) alias: String,
    pub(crate) provider: Provider,
    pub(crate) created_at: i64,
}

impl Profile {
    pub(crate) fn reference(&self) -> String {
        format!("{}@{}", self.provider.as_str(), self.alias)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    schema_version: u8,
    #[serde(default)]
    revision: u64,
    profiles: Vec<Profile>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryWriteStep {
    TemporaryCreate,
    Write,
    FileSync,
    AtomicRename,
    DirectorySync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
enum RemovalFaultPoint {
    JournalTemporaryCreate,
    JournalWrite,
    JournalFileSync,
    JournalAtomicRename,
    JournalDirectorySync,
    TombstoneRename,
    ProviderRootSyncAfterRename,
    RegistryTemporaryCreate,
    RegistryWrite,
    RegistryFileSync,
    RegistryAtomicRename,
    RegistryDirectorySync,
    RecursiveCleanup,
    ProviderRootSyncAfterCleanup,
    JournalRemove,
    JournalRemoveDirectorySync,
}

#[cfg(test)]
type RemovalFault = RemovalFaultPoint;

#[cfg(test)]
struct RemovalPause {
    reached: std::sync::mpsc::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
impl fmt::Debug for RemovalPause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemovalPause")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FileSystemIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RemovalTreeSnapshot {
    root: FileSystemIdentity,
    entry_count: u64,
    manifest_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RemovalJournal {
    schema_version: u8,
    profile: Profile,
    expected_registry_revision: u64,
    removed_registry_revision: u64,
    expected_registry_digest: String,
    removed_registry_digest: String,
    data_root: FileSystemIdentity,
    profiles_root: FileSystemIdentity,
    provider_root: FileSystemIdentity,
    profile_tree: FileSystemIdentity,
    profile_tree_entry_count: u64,
    profile_tree_manifest_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RemovalRoots {
    data_root: FileSystemIdentity,
    profiles_root: FileSystemIdentity,
    provider_root: FileSystemIdentity,
}

impl Default for RegistryDocument {
    fn default() -> Self {
        Self {
            schema_version: REGISTRY_SCHEMA_VERSION,
            revision: 0,
            profiles: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Registry {
    root: PathBuf,
    #[cfg(test)]
    registry_write_fault: Option<RegistryWriteStep>,
    #[cfg(test)]
    fail_identity_marker_directory_sync: bool,
    #[cfg(test)]
    fail_identity_recovery_directory_sync: bool,
    #[cfg(test)]
    fail_identity_key_directory_sync: bool,
    #[cfg(test)]
    fail_identity_key_recovery_directory_sync: bool,
    #[cfg(test)]
    removal_fault: Option<RemovalFaultPoint>,
    #[cfg(test)]
    removal_pause_after_cleanup: Option<RemovalPause>,
    #[cfg(test)]
    registry_mutation_pause_after_preflight: Option<RemovalPause>,
}

impl Registry {
    pub(crate) fn discover() -> Result<Self, ProfileError> {
        Ok(Self {
            root: data_root()?,
            #[cfg(test)]
            registry_write_fault: None,
            #[cfg(test)]
            fail_identity_marker_directory_sync: false,
            #[cfg(test)]
            fail_identity_recovery_directory_sync: false,
            #[cfg(test)]
            fail_identity_key_directory_sync: false,
            #[cfg(test)]
            fail_identity_key_recovery_directory_sync: false,
            #[cfg(test)]
            removal_fault: None,
            #[cfg(test)]
            removal_pause_after_cleanup: None,
            #[cfg(test)]
            registry_mutation_pause_after_preflight: None,
        })
    }

    /// Returns the already validated Calcifer data-root location.
    ///
    /// Callers must still validate it immediately before opening their own
    /// managed files because filesystem state can change between operations.
    pub(crate) fn managed_root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn find_by_id(&self, provider: Provider, id: &str) -> Result<Profile, ProfileError> {
        validate_profile_id(id)?;
        self.recover_incomplete_removal()?;
        self.find_by_id_without_recovery(provider, id)
    }

    fn find_by_id_without_recovery(
        &self,
        provider: Provider,
        id: &str,
    ) -> Result<Profile, ProfileError> {
        self.load()?
            .profiles
            .into_iter()
            .find(|profile| profile.provider == provider && profile.id == id)
            .ok_or_else(|| ProfileError::NotFound(format!("{} profile", provider.as_str())))
    }

    /// Re-reads an immutable ID while its profile lease is already held.
    /// Callers must have run normal selection/recovery before taking the lease.
    pub(crate) fn refetch_by_id_under_lease(
        &self,
        provider: Provider,
        id: &str,
    ) -> Result<Profile, ProfileError> {
        validate_profile_id(id)?;
        self.find_by_id_without_recovery(provider, id)
    }

    #[cfg(test)]
    pub(crate) fn at(root: PathBuf) -> Self {
        Self {
            root,
            registry_write_fault: None,
            fail_identity_marker_directory_sync: false,
            fail_identity_recovery_directory_sync: false,
            fail_identity_key_directory_sync: false,
            fail_identity_key_recovery_directory_sync: false,
            removal_fault: None,
            removal_pause_after_cleanup: None,
            registry_mutation_pause_after_preflight: None,
        }
    }

    #[cfg(all(test, unix))]
    fn at_with_registry_sync_failure(root: PathBuf) -> Self {
        Self {
            root,
            registry_write_fault: Some(RegistryWriteStep::DirectorySync),
            fail_identity_marker_directory_sync: false,
            fail_identity_recovery_directory_sync: false,
            fail_identity_key_directory_sync: false,
            fail_identity_key_recovery_directory_sync: false,
            removal_fault: None,
            removal_pause_after_cleanup: None,
            registry_mutation_pause_after_preflight: None,
        }
    }

    #[cfg(all(test, unix))]
    fn at_with_identity_sync_failures(root: PathBuf, fail_recovery: bool) -> Self {
        Self {
            root,
            registry_write_fault: None,
            fail_identity_marker_directory_sync: true,
            fail_identity_recovery_directory_sync: fail_recovery,
            fail_identity_key_directory_sync: false,
            fail_identity_key_recovery_directory_sync: false,
            removal_fault: None,
            removal_pause_after_cleanup: None,
            registry_mutation_pause_after_preflight: None,
        }
    }

    #[cfg(all(test, unix))]
    fn at_with_identity_key_sync_failures(root: PathBuf, fail_recovery: bool) -> Self {
        Self {
            root,
            registry_write_fault: None,
            fail_identity_marker_directory_sync: false,
            fail_identity_recovery_directory_sync: false,
            fail_identity_key_directory_sync: true,
            fail_identity_key_recovery_directory_sync: fail_recovery,
            removal_fault: None,
            removal_pause_after_cleanup: None,
            registry_mutation_pause_after_preflight: None,
        }
    }

    #[cfg(all(test, unix))]
    fn at_with_registry_write_fault(root: PathBuf, fault: RegistryWriteStep) -> Self {
        Self {
            root,
            registry_write_fault: Some(fault),
            fail_identity_marker_directory_sync: false,
            fail_identity_recovery_directory_sync: false,
            fail_identity_key_directory_sync: false,
            fail_identity_key_recovery_directory_sync: false,
            removal_fault: None,
            removal_pause_after_cleanup: None,
            registry_mutation_pause_after_preflight: None,
        }
    }

    #[cfg(all(test, unix))]
    fn at_with_removal_fault(root: PathBuf, fault: RemovalFault) -> Self {
        Self {
            root,
            registry_write_fault: None,
            fail_identity_marker_directory_sync: false,
            fail_identity_recovery_directory_sync: false,
            fail_identity_key_directory_sync: false,
            fail_identity_key_recovery_directory_sync: false,
            removal_fault: Some(fault),
            removal_pause_after_cleanup: None,
            registry_mutation_pause_after_preflight: None,
        }
    }

    #[cfg(all(test, unix))]
    fn at_with_removal_pause(
        root: PathBuf,
        reached: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    ) -> Self {
        Self {
            root,
            registry_write_fault: None,
            fail_identity_marker_directory_sync: false,
            fail_identity_recovery_directory_sync: false,
            fail_identity_key_directory_sync: false,
            fail_identity_key_recovery_directory_sync: false,
            removal_fault: None,
            removal_pause_after_cleanup: Some(RemovalPause { reached, resume }),
            registry_mutation_pause_after_preflight: None,
        }
    }

    #[cfg(all(test, unix))]
    fn at_with_registry_mutation_pause(
        root: PathBuf,
        reached: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    ) -> Self {
        Self {
            root,
            registry_write_fault: None,
            fail_identity_marker_directory_sync: false,
            fail_identity_recovery_directory_sync: false,
            fail_identity_key_directory_sync: false,
            fail_identity_key_recovery_directory_sync: false,
            removal_fault: None,
            removal_pause_after_cleanup: None,
            registry_mutation_pause_after_preflight: Some(RemovalPause { reached, resume }),
        }
    }

    pub(crate) fn list(&self) -> Result<Vec<Profile>, ProfileError> {
        self.recover_incomplete_removal()?;
        let mut profiles = self.load()?.profiles;
        profiles.sort_by(|left, right| {
            left.provider
                .as_str()
                .cmp(right.provider.as_str())
                .then_with(|| left.alias.cmp(&right.alias))
        });
        Ok(profiles)
    }

    pub(crate) fn find(&self, provider: Provider, alias: &str) -> Result<Profile, ProfileError> {
        self.recover_incomplete_removal()?;
        self.find_without_recovery(provider, alias)
    }

    fn find_without_recovery(
        &self,
        provider: Provider,
        alias: &str,
    ) -> Result<Profile, ProfileError> {
        self.load()?
            .profiles
            .into_iter()
            .find(|profile| profile.provider == provider && profile.alias == alias)
            .ok_or_else(|| ProfileError::NotFound(format!("{}@{alias}", provider.as_str())))
    }

    /// Reads local removal metadata without performing recovery or mutation.
    /// This exists solely for the pre-confirmation TTY prompt.
    pub(crate) fn preview_remove(
        &self,
        provider: Provider,
        alias: &str,
    ) -> Result<Profile, ProfileError> {
        self.ensure_no_removal_artifacts_read_only()?;
        self.find_without_recovery(provider, alias)
    }

    /// Removes one published profile through a journaled tombstone transaction.
    ///
    /// The profile's coordinator and provider leases are acquired before either
    /// metadata lock. The registry rename that removes the immutable profile ID
    /// is the public visibility point. Credentials are recursively unlinked only
    /// after readback proves that visibility point completed.
    #[cfg(unix)]
    pub(crate) fn remove(
        &self,
        provider: Provider,
        alias: &str,
        confirmed_profile_id: Option<&str>,
    ) -> Result<Profile, ProfileError> {
        self.recover_incomplete_removal()?;
        ensure_registration_supported()?;
        let selected = self.find_without_recovery(provider, alias)?;
        if confirmed_profile_id.is_some_and(|expected_id| expected_id != selected.id) {
            return Err(ProfileError::NotFound(selected.reference()));
        }
        let _profile_lease = self.lock_profile(&selected)?;
        let removal_lock = self.lock_removal_exclusive()?;
        let registry_lock = self.lock_registry_mutation()?;

        let mut current = self.load()?;
        let profile_index = current
            .profiles
            .iter()
            .position(|profile| profile == &selected)
            .ok_or_else(|| ProfileError::NotFound(selected.reference()))?;
        let roots = self.validate_removal_roots(None)?;
        let original = self.profile_path(&selected)?;
        let tree = validate_owned_removal_tree(&self.root, &roots, &original, &selected.id, None)?;

        let expected_registry_revision = current.revision;
        let expected_registry_digest = registry_digest(&current)?;
        current.profiles.remove(profile_index);
        current.revision = next_registry_revision(current.revision)?;
        let removed_registry_revision = current.revision;
        let removed_registry_digest = registry_digest(&current)?;
        let journal = RemovalJournal {
            schema_version: REMOVAL_JOURNAL_SCHEMA_VERSION,
            profile: selected.clone(),
            expected_registry_revision,
            removed_registry_revision,
            expected_registry_digest,
            removed_registry_digest,
            data_root: roots.data_root,
            profiles_root: roots.profiles_root,
            provider_root: roots.provider_root,
            profile_tree: tree.root,
            profile_tree_entry_count: tree.entry_count,
            profile_tree_manifest_digest: tree.manifest_digest,
        };
        self.write_removal_journal(&journal)?;

        let tombstone = self.tombstone_path(&selected)?;
        if path_exists(&tombstone)? {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        self.inject_removal_fault(RemovalFaultPoint::TombstoneRename)?;
        fs::rename(&original, &tombstone)?;
        self.validate_removal_roots(Some(&journal))?;
        validate_owned_removal_tree(
            &self.root,
            &roots,
            &tombstone,
            &selected.id,
            Some(journal.tree_snapshot()),
        )?;
        self.inject_removal_fault(RemovalFaultPoint::ProviderRootSyncAfterRename)?;
        sync_directory(&self.provider_root(provider)?)?;

        let publication = self.save(&current);
        match publication {
            Ok(()) => {}
            Err(ProfileError::RegistryCommitUncertain(_)) => {
                let readback = self.load()?;
                if !journal.matches_removed_registry(&readback)? {
                    return Err(ProfileError::RemovalRecoveryRequired);
                }
                sync_directory(&self.root).map_err(|error| match error {
                    ProfileError::Io(error) => ProfileError::RemovalCommitUncertain(error),
                    other => other,
                })?;
            }
            Err(error) => return Err(error),
        }
        let readback = self.load()?;
        if !journal.matches_removed_registry(&readback)? {
            return Err(ProfileError::RemovalRecoveryRequired);
        }

        self.finish_visible_removal(&removal_lock, &registry_lock, &journal, &tombstone)?;
        Ok(selected)
    }

    #[cfg(not(unix))]
    pub(crate) fn remove(
        &self,
        _provider: Provider,
        _alias: &str,
        _confirmed_profile_id: Option<&str>,
    ) -> Result<Profile, ProfileError> {
        Err(ProfileError::UnsupportedPlatform)
    }

    /// Converges an interrupted removal to an unambiguously complete old or
    /// new state. It never republishes a profile after registry visibility.
    pub(crate) fn recover_incomplete_removal(&self) -> Result<(), ProfileError> {
        if !path_exists(&self.root)? {
            return Ok(());
        }
        verify_private_directory(&self.root)?;

        let first_journal = self.read_removal_journal()?;
        let tombstones = self.removal_tombstones()?;
        let temporaries = self.removal_temporaries()?;
        if first_journal.is_none() && tombstones.is_empty() && temporaries.is_empty() {
            return Ok(());
        }

        #[cfg(not(unix))]
        return Err(ProfileError::UnsupportedPlatform);

        #[cfg(unix)]
        self.recover_incomplete_removal_unix()
    }

    #[cfg(unix)]
    fn recover_incomplete_removal_unix(&self) -> Result<(), ProfileError> {
        // Wait for a live remover to finish before inspecting a tree that may
        // be changing through descriptor-relative cleanup. Release this gate
        // before taking a profile lease to preserve the global lock order.
        let quiescence_gate = self.lock_removal_exclusive()?;
        drop(quiescence_gate);

        let first_journal = self.read_removal_journal()?;
        let tombstones = self.removal_tombstones()?;
        let temporaries = self.removal_temporaries()?;
        if first_journal.is_none() {
            if !tombstones.is_empty() {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
            if temporaries.is_empty() {
                return Ok(());
            }
            private_directory_identity(&self.root)?;
            let _removal_lock = self.lock_removal_exclusive()?;
            if self.read_removal_journal()?.is_some() {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
            let current_tombstones = self.removal_tombstones()?;
            let current_temporaries = self.removal_temporaries()?;
            if !current_tombstones.is_empty() {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
            if current_temporaries.is_empty() {
                return Ok(());
            }
            self.remove_stale_removal_temporary(&current_temporaries)?;
            return Ok(());
        }
        let journal = first_journal.ok_or(ProfileError::RemovalRecoveryRequired)?;
        self.validate_removal_artifact_set(&journal, &tombstones, &temporaries)?;

        let roots = self.validate_removal_roots(Some(&journal))?;
        let original = self.profile_path(&journal.profile)?;
        let tombstone = self.tombstone_path(&journal.profile)?;
        let original_exists = path_exists(&original)?;
        let tombstone_exists = path_exists(&tombstone)?;
        if original_exists && tombstone_exists {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        let tree_path = if original_exists {
            Some(original.as_path())
        } else if tombstone_exists {
            Some(tombstone.as_path())
        } else {
            None
        };
        let profile_lease = match tree_path {
            Some(path)
                if validate_owned_removal_tree(
                    &self.root,
                    &roots,
                    path,
                    &journal.profile.id,
                    Some(journal.tree_snapshot()),
                )
                .is_ok() =>
            {
                match self.lock_removal_tree(path, &journal, &roots) {
                    Ok(lease) => Some(lease),
                    Err(error @ ProfileError::Busy(_)) => return Err(error),
                    Err(_) => None,
                }
            }
            _ => None,
        };
        let removal_lock = self.lock_removal_exclusive()?;
        let Some(current_journal) = self.read_removal_journal()? else {
            if self.removal_tombstones()?.is_empty() && self.removal_temporaries()?.is_empty() {
                return Ok(());
            }
            return Err(ProfileError::RemovalRecoveryRequired);
        };
        if current_journal != journal {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        let current_tombstones = self.removal_tombstones()?;
        let current_temporaries = self.removal_temporaries()?;
        self.validate_removal_artifact_set(
            &current_journal,
            &current_tombstones,
            &current_temporaries,
        )?;
        let roots = self.validate_removal_roots(Some(&journal))?;
        let original_exists = path_exists(&original)?;
        let tombstone_exists = path_exists(&tombstone)?;
        if original_exists && tombstone_exists {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        let registry_lock = self.lock_exclusive()?;
        let document = self.load()?;
        let old_visible = journal.matches_expected_registry(&document)?;
        let removed_visible = journal.matches_removed_registry(&document)?;
        if old_visible == removed_visible {
            return Err(ProfileError::RemovalRecoveryRequired);
        }

        if old_visible {
            if profile_lease.is_none() {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
            match (original_exists, tombstone_exists) {
                (true, false) => {
                    validate_owned_removal_tree(
                        &self.root,
                        &roots,
                        &original,
                        &journal.profile.id,
                        Some(journal.tree_snapshot()),
                    )?;
                }
                (false, true) => {
                    validate_owned_removal_tree(
                        &self.root,
                        &roots,
                        &tombstone,
                        &journal.profile.id,
                        Some(journal.tree_snapshot()),
                    )?;
                    fs::rename(&tombstone, &original)?;
                    self.validate_removal_roots(Some(&journal))?;
                    validate_owned_removal_tree(
                        &self.root,
                        &roots,
                        &original,
                        &journal.profile.id,
                        Some(journal.tree_snapshot()),
                    )?;
                    sync_directory(&self.provider_root(journal.profile.provider)?)?;
                }
                _ => return Err(ProfileError::RemovalRecoveryRequired),
            }
            self.remove_removal_journal(
                &removal_lock,
                &registry_lock,
                &journal,
                &current_temporaries,
            )?;
            return Ok(());
        }

        match (original_exists, tombstone_exists) {
            (false, true) => {
                validate_partial_owned_tombstone(
                    &self.root,
                    &roots,
                    &tombstone,
                    &journal.profile.id,
                    journal.profile_tree,
                )?;
                self.finish_visible_removal(&removal_lock, &registry_lock, &journal, &tombstone)
            }
            (false, false) => {
                sync_directory(&self.provider_root(journal.profile.provider)?)
                    .map_err(removal_commit_error)?;
                self.remove_removal_journal(
                    &removal_lock,
                    &registry_lock,
                    &journal,
                    &current_temporaries,
                )
            }
            _ => Err(ProfileError::RemovalRecoveryRequired),
        }
    }

    fn ensure_no_removal_artifacts_read_only(&self) -> Result<(), ProfileError> {
        if !path_exists(&self.root)? {
            return Ok(());
        }
        if self.read_removal_journal()?.is_some()
            || !self.removal_tombstones()?.is_empty()
            || !self.removal_temporaries()?.is_empty()
        {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        Ok(())
    }

    /// Changes only the display alias of one immutable profile.
    ///
    /// Published-profile operations acquire the profile lease before the
    /// registry lock. Identity verification and future lifecycle mutations
    /// must keep the same order to avoid deadlocks. Re-reading the registry
    /// after both locks are held makes a rename/launch race choose exactly one
    /// winner without touching provider-owned state.
    pub(crate) fn rename(
        &self,
        provider: Provider,
        old_alias: &str,
        new_alias: &str,
    ) -> Result<(Profile, bool), ProfileError> {
        self.recover_incomplete_removal()?;
        validate_alias(new_alias)?;
        ensure_registration_supported()?;

        let original = self.find_without_recovery(provider, old_alias)?;
        let _profile_lease = self.lock_profile(&original)?;
        #[cfg(test)]
        self.pause_registry_mutation_after_preflight()?;
        let _registry_lock = self.lock_registry_mutation()?;
        let mut document = self.load()?;
        let old_reference = format!("{}@{old_alias}", provider.as_str());
        let profile_index = document
            .profiles
            .iter()
            .position(|profile| {
                profile.id == original.id
                    && profile.provider == provider
                    && profile.alias == old_alias
            })
            .ok_or(ProfileError::NotFound(old_reference))?;

        if document.profiles[profile_index].alias == new_alias {
            return Ok((document.profiles[profile_index].clone(), false));
        }
        if document.profiles.iter().any(|profile| {
            profile.provider == provider && profile.alias == new_alias && profile.id != original.id
        }) {
            return Err(ProfileError::AlreadyExists(format!(
                "{}@{new_alias}",
                provider.as_str()
            )));
        }

        document.profiles[profile_index].alias = new_alias.to_owned();
        document.revision = next_registry_revision(document.revision)?;
        let renamed = document.profiles[profile_index].clone();
        self.save(&document)?;
        Ok((renamed, true))
    }

    pub(crate) fn begin_codex_registration(
        &self,
        alias: &str,
    ) -> Result<PendingProfile<'_>, ProfileError> {
        self.recover_incomplete_removal()?;
        validate_alias(alias)?;
        ensure_registration_supported()?;
        self.ensure_root()?;

        #[cfg(test)]
        self.pause_registry_mutation_after_preflight()?;
        // PendingProfile retains this guarded lock through provider login and
        // publication, so no remover can prepare a journal before commit.
        let lock = self.lock_registry_mutation()?;
        let document = self.load()?;
        if document
            .profiles
            .iter()
            .any(|profile| profile.provider == Provider::Codex && profile.alias == alias)
        {
            return Err(ProfileError::AlreadyExists(format!("codex@{alias}")));
        }

        let profiles_root = self.root.join("profiles");
        ensure_private_subdirectory(&profiles_root)?;
        let provider_root = profiles_root.join("codex");
        ensure_private_subdirectory(&provider_root)?;
        refuse_orphaned_staging(&provider_root)?;

        let id = Uuid::new_v4().to_string();
        let staging = provider_root.join(format!(".staging-{id}"));
        secure_create_dir(&staging)?;
        write_private_file(&staging.join(OWNER_MARKER), id.as_bytes())?;
        let home = staging.join("home");
        secure_create_dir(&home)?;
        write_private_file(&home.join("config.toml"), MANAGED_CODEX_CONFIG)?;

        Ok(PendingProfile {
            registry: self,
            _lock: lock,
            profile: Profile {
                id,
                alias: alias.to_owned(),
                provider: Provider::Codex,
                created_at: unix_timestamp()?,
            },
            staging,
            committed: false,
            preserve_staging: false,
        })
    }

    pub(crate) fn profile_home(&self, profile: &Profile) -> Result<PathBuf, ProfileError> {
        let directory = self.profile_directory(profile)?;
        let home = directory.join("home");
        verify_managed_codex_home(&home)?;
        Ok(home)
    }

    /// Returns a private working directory with its own project-root marker.
    ///
    /// Login and account-only App Server probes must not discover repository
    /// configuration through an ancestor of a user-selected `CALCIFER_HOME`.
    #[cfg(unix)]
    pub(crate) fn neutral_working_directory(&self) -> Result<PathBuf, ProfileError> {
        let runtime_root = managed_runtime_root()?;
        let neutral = runtime_root.join("neutral");
        ensure_private_subdirectory(&neutral)?;
        ensure_private_subdirectory(&neutral.join(".git"))?;
        Ok(neutral)
    }

    #[cfg(not(unix))]
    pub(crate) fn neutral_working_directory(&self) -> Result<PathBuf, ProfileError> {
        Err(ProfileError::UnsupportedPlatform)
    }

    fn profile_directory(&self, profile: &Profile) -> Result<PathBuf, ProfileError> {
        validate_profile_id(&profile.id)?;
        verify_private_directory(&self.root)?;
        let profiles_root = self.root.join("profiles");
        verify_private_directory(&profiles_root)?;
        let provider_root = profiles_root.join(profile.provider.as_str());
        verify_private_directory(&provider_root)?;
        let directory = provider_root.join(&profile.id);
        verify_owned_profile_directory(&directory, &profile.id)?;
        Ok(directory)
    }

    pub(crate) fn lock_profile(&self, profile: &Profile) -> Result<ProfileLease, ProfileError> {
        let profile_dir = self.profile_directory(profile)?;
        let coordinator = lock_profile_file(
            &profile_dir.join(COORDINATOR_LOCK_FILE),
            &profile.reference(),
        )?;
        let provider =
            lock_profile_file(&profile_dir.join(PROVIDER_LOCK_FILE), &profile.reference())?;
        Ok(ProfileLease {
            coordinator: Some(coordinator),
            provider: Some(provider),
        })
    }

    /// Creates or checks the private identity marker for a legacy profile.
    ///
    /// Lock order is profile lease, then registry lock. Registration holds only
    /// the registry lock while operating on an unpublished staging directory,
    /// so the two flows cannot deadlock. Future re-authentication must preserve
    /// this order for published profiles.
    pub(crate) fn verify_or_bind_codex_identity(
        &self,
        profile: &Profile,
        resolve_adapter: impl FnOnce(&Path) -> Result<CodexIdentityAdapter, ProfileError>,
    ) -> Result<VerifiedProviderIdentityLease, ProfileError> {
        let lease = self.lock_profile(profile)?;
        let home = self.profile_home(profile)?;
        let adapter = {
            // The version-only App Server probe receives the provider-side
            // lease. If the verifier is killed, its stdio EOF stops the probe
            // before another credential writer can acquire this profile.
            #[cfg(unix)]
            let _provider_lock_inheritance = lease.inherit_provider_lock()?;
            resolve_adapter(&home)?
        };
        let profile_directory = self.profile_directory(profile)?;
        let _registry_lock = self.lock_exclusive()?;
        let document = self.load()?;
        if !document
            .profiles
            .iter()
            .any(|registered| registered == profile)
        {
            return Err(ProfileError::NotFound(profile.reference()));
        }

        let store = IdentityStore::new(&self.root);
        let key = store.load_or_create_key(self.has_identity_bindings(&document, &store)?)?;
        let current = store.derive_codex_binding(&home, &key, adapter)?;
        let marker_exists = store.marker_exists(&profile_directory)?;
        if marker_exists {
            store.revalidate_marker(&profile_directory, &key, &current)?;
        }
        if let Some(conflict) =
            self.find_identity_conflict(&document, &store, &key, &current, Some(&profile.id))?
        {
            return Err(ProfileError::DuplicateProviderIdentity {
                requested: profile.reference(),
                existing: conflict.reference(),
            });
        }
        if !marker_exists {
            store.publish_marker(&profile_directory, &current)?;
        }

        Ok(VerifiedProviderIdentityLease {
            _lease: lease,
            profile: profile.clone(),
            identity: current,
        })
    }

    /// Revalidates a bound profile after acquiring its exclusive process lease.
    /// The returned guard keeps that lease alive until launch authorization is
    /// either consumed or abandoned.
    #[allow(dead_code)] // Consumed by the failover selector introduced in issue #4.
    pub(crate) fn revalidate_codex_identity(
        &self,
        profile: &Profile,
        resolve_adapter: impl FnOnce(&Path) -> Result<CodexIdentityAdapter, ProfileError>,
    ) -> Result<VerifiedProviderIdentityLease, ProfileError> {
        let lease = self.lock_profile(profile)?;
        let home = self.profile_home(profile)?;
        let adapter = {
            #[cfg(unix)]
            let _provider_lock_inheritance = lease.inherit_provider_lock()?;
            resolve_adapter(&home)?
        };
        let profile_directory = self.profile_directory(profile)?;
        let store = IdentityStore::new(&self.root);
        let key = store.load_key()?;
        let current = store.derive_codex_binding(&home, &key, adapter)?;
        store.revalidate_marker(&profile_directory, &key, &current)?;
        Ok(VerifiedProviderIdentityLease {
            _lease: lease,
            profile: profile.clone(),
            identity: current,
        })
    }

    /// Acquires both profile locks and reloads the alias while the lease is
    /// held. Callers selected through a public alias pass that alias as
    /// `expected_alias`; ID-based enumeration can accept the current alias by
    /// passing `None`.
    ///
    /// Rename takes these same locks before changing the registry, so the
    /// reload establishes a single winner: either this lease protects the old
    /// alias, or a completed rename makes that alias fail before provider work.
    pub(crate) fn lock_profile_current(
        &self,
        profile: &Profile,
        expected_alias: Option<&str>,
    ) -> Result<(Profile, ProfileLease), ProfileError> {
        let lease = self.lock_profile(profile)?;
        // Recovery is run before profile selection. Do not recursively acquire
        // another profile's recovery lease while this profile lease is held.
        let current = self.find_by_id_without_recovery(profile.provider, &profile.id)?;
        if let Some(expected_alias) = expected_alias {
            if current.alias != expected_alias {
                return Err(ProfileError::NotFound(format!(
                    "{}@{expected_alias}",
                    profile.provider.as_str()
                )));
            }
        }
        Ok((current, lease))
    }

    /// Acquires the coordinator side of the split process lease.
    ///
    /// A launch coordinator holds this lock while its provider guardian holds
    /// the provider side. New operations always acquire the coordinator side
    /// first, which prevents deadlocks and keeps a single surviving process
    /// sufficient to block a second writer.
    #[cfg(unix)]
    pub(crate) fn lock_profile_coordinator(
        &self,
        profile: &Profile,
    ) -> Result<ProfileLease, ProfileError> {
        let profile_dir = self.profile_directory(profile)?;
        let coordinator = lock_profile_file(
            &profile_dir.join(COORDINATOR_LOCK_FILE),
            &profile.reference(),
        )?;
        Ok(ProfileLease {
            coordinator: Some(coordinator),
            provider: None,
        })
    }

    /// Acquires only the provider side of the split process lease.
    ///
    /// This is reserved for the hidden provider guardian. It must never try to
    /// acquire the coordinator side, preserving the global A-then-B order.
    #[cfg(unix)]
    pub(crate) fn lock_profile_provider(
        &self,
        profile: &Profile,
    ) -> Result<ProfileLease, ProfileError> {
        let profile_dir = self.profile_directory(profile)?;
        let provider =
            lock_profile_file(&profile_dir.join(PROVIDER_LOCK_FILE), &profile.reference())?;
        Ok(ProfileLease {
            coordinator: None,
            provider: Some(provider),
        })
    }

    #[cfg(unix)]
    pub(crate) fn supervisor_socket_path(
        &self,
        profile: &Profile,
        run_id: &Uuid,
    ) -> Result<PathBuf, ProfileError> {
        // Revalidate the profile even though the socket uses a short runtime
        // path. Unix-domain socket paths are very small on macOS and a full
        // CALCIFER_HOME/profile UUID path can exceed the kernel limit.
        let _profile_dir = self.profile_directory(profile)?;
        let runtime_root = managed_runtime_root()?;
        Ok(runtime_root.join(format!("{run_id}.sock")))
    }

    fn load(&self) -> Result<RegistryDocument, ProfileError> {
        let path = self.root.join(REGISTRY_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => verify_private_regular_file(&path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(RegistryDocument::default());
            }
            Err(error) => return Err(ProfileError::Io(error)),
        }
        let mut bytes = Vec::new();
        File::open(&path)?
            .take((MAX_REGISTRY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(ProfileError::InvalidRegistry(
                "registry exceeds the supported size limit".to_owned(),
            ));
        }
        let document: RegistryDocument = serde_json::from_slice(&bytes)
            .map_err(|_| ProfileError::InvalidRegistry("registry is not valid JSON".to_owned()))?;
        if document.schema_version != REGISTRY_SCHEMA_VERSION {
            return Err(ProfileError::InvalidRegistry(format!(
                "unsupported registry schema {}",
                document.schema_version
            )));
        }
        validate_document(&document)?;
        Ok(document)
    }

    fn save(&self, document: &RegistryDocument) -> Result<(), ProfileError> {
        validate_document(document)?;
        let bytes = serde_json::to_vec_pretty(document).map_err(|_| {
            ProfileError::InvalidRegistry("registry serialization failed".to_owned())
        })?;
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(ProfileError::InvalidRegistry(
                "registry exceeds the supported size limit".to_owned(),
            ));
        }
        atomic_write_private(
            &self.root,
            REGISTRY_FILE,
            &bytes,
            |step| self.inject_registry_write_fault(step),
            sync_directory,
        )
    }

    fn ensure_root(&self) -> Result<(), ProfileError> {
        secure_create_dir_all(&self.root)?;
        verify_private_directory(&self.root)
    }

    fn lock_exclusive(&self) -> Result<RegistryLock, ProfileError> {
        let file = open_private_lock_file(&self.root.join(LOCK_FILE))?;
        FileExt::lock_exclusive(&file)?;
        Ok(RegistryLock { _file: file })
    }

    /// Acquires the registry mutation lock and closes the recovery-preflight
    /// TOCTOU before any revision or unpublished registration state changes.
    /// Recovery itself uses `lock_exclusive` because its journal must exist.
    fn lock_registry_mutation(&self) -> Result<RegistryLock, ProfileError> {
        let lock = self.lock_exclusive()?;
        self.ensure_no_removal_artifacts_read_only()?;
        Ok(lock)
    }

    fn lock_removal_exclusive(&self) -> Result<RegistryLock, ProfileError> {
        let file = open_private_lock_file(&self.root.join(REMOVAL_LOCK_FILE))?;
        FileExt::lock_exclusive(&file)?;
        Ok(RegistryLock { _file: file })
    }

    fn provider_root(&self, provider: Provider) -> Result<PathBuf, ProfileError> {
        validate_provider_root_components(&self.root)?;
        Ok(self.root.join("profiles").join(provider.as_str()))
    }

    fn profile_path(&self, profile: &Profile) -> Result<PathBuf, ProfileError> {
        validate_profile_id(&profile.id)?;
        Ok(self.provider_root(profile.provider)?.join(&profile.id))
    }

    fn tombstone_path(&self, profile: &Profile) -> Result<PathBuf, ProfileError> {
        validate_profile_id(&profile.id)?;
        Ok(self
            .provider_root(profile.provider)?
            .join(format!(".removing-{}", profile.id)))
    }

    fn validate_removal_roots(
        &self,
        expected: Option<&RemovalJournal>,
    ) -> Result<RemovalRoots, ProfileError> {
        let profiles_root = self.root.join("profiles");
        let provider_root = profiles_root.join("codex");
        let roots = RemovalRoots {
            data_root: private_directory_identity(&self.root)?,
            profiles_root: private_directory_identity(&profiles_root)?,
            provider_root: private_directory_identity(&provider_root)?,
        };
        if roots.data_root.device != roots.profiles_root.device
            || roots.data_root.device != roots.provider_root.device
        {
            return Err(ProfileError::UnsafeState(
                "managed removal roots are not on one filesystem".to_owned(),
            ));
        }
        if let Some(expected) = expected {
            if roots.data_root != expected.data_root
                || roots.profiles_root != expected.profiles_root
                || roots.provider_root != expected.provider_root
            {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
        }
        Ok(roots)
    }

    #[cfg(unix)]
    fn lock_removal_tree(
        &self,
        path: &Path,
        journal: &RemovalJournal,
        roots: &RemovalRoots,
    ) -> Result<ProfileLease, ProfileError> {
        validate_owned_removal_tree(
            &self.root,
            roots,
            path,
            &journal.profile.id,
            Some(journal.tree_snapshot()),
        )?;
        let coordinator = lock_existing_profile_file(
            &path.join(COORDINATOR_LOCK_FILE),
            &journal.profile.reference(),
        )?;
        let provider = lock_existing_profile_file(
            &path.join(PROVIDER_LOCK_FILE),
            &journal.profile.reference(),
        )?;
        validate_owned_removal_tree(
            &self.root,
            roots,
            path,
            &journal.profile.id,
            Some(journal.tree_snapshot()),
        )?;
        Ok(ProfileLease {
            coordinator: Some(coordinator),
            provider: Some(provider),
        })
    }

    fn read_removal_journal(&self) -> Result<Option<RemovalJournal>, ProfileError> {
        let path = self.root.join(REMOVAL_JOURNAL_FILE);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ProfileError::Io(error)),
            Ok(_) => {}
        }
        verify_private_single_link_regular_file(&path)
            .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
        let mut bytes = Vec::new();
        File::open(&path)?
            .take((MAX_REMOVAL_JOURNAL_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_REMOVAL_JOURNAL_BYTES {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        let journal: RemovalJournal =
            serde_json::from_slice(&bytes).map_err(|_| ProfileError::RemovalRecoveryRequired)?;
        journal.validate()?;
        Ok(Some(journal))
    }

    fn write_removal_journal(&self, journal: &RemovalJournal) -> Result<(), ProfileError> {
        journal.validate()?;
        let bytes = serde_json::to_vec_pretty(journal)
            .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
        if bytes.len() > MAX_REMOVAL_JOURNAL_BYTES {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        let temporary = self
            .root
            .join(format!(".{REMOVAL_JOURNAL_FILE}.{}.tmp", Uuid::new_v4()));
        let destination = self.root.join(REMOVAL_JOURNAL_FILE);
        let publication = (|| {
            self.inject_removal_fault(RemovalFaultPoint::JournalTemporaryCreate)?;
            let mut options = private_open_options();
            let mut file = options.write(true).create_new(true).open(&temporary)?;
            self.inject_removal_fault(RemovalFaultPoint::JournalWrite)?;
            file.write_all(&bytes)?;
            self.inject_removal_fault(RemovalFaultPoint::JournalFileSync)?;
            file.sync_all()?;
            verify_private_single_link_regular_file(&temporary)?;
            drop(file);
            self.inject_removal_fault(RemovalFaultPoint::JournalAtomicRename)?;
            fs::rename(&temporary, &destination)?;
            Ok(())
        })();
        if let Err(error) = publication {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = self
            .inject_removal_fault(RemovalFaultPoint::JournalDirectorySync)
            .and_then(|()| sync_directory(&self.root))
        {
            let readback = self.read_removal_journal();
            if readback
                .as_ref()
                .is_ok_and(|value| value.as_ref() == Some(journal))
            {
                return Err(match error {
                    ProfileError::Io(error) => ProfileError::RemovalCommitUncertain(error),
                    other => other,
                });
            }
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        Ok(())
    }

    fn removal_tombstones(&self) -> Result<Vec<(String, PathBuf)>, ProfileError> {
        let provider_root = self.root.join("profiles/codex");
        match fs::symlink_metadata(&provider_root) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(ProfileError::Io(error)),
            Ok(_) => verify_private_directory(&provider_root)?,
        }
        let mut tombstones = Vec::new();
        for entry in fs::read_dir(&provider_root)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
            let Some(id) = name.strip_prefix(".removing-") else {
                continue;
            };
            validate_profile_id(id).map_err(|_| ProfileError::RemovalRecoveryRequired)?;
            tombstones.push((id.to_owned(), entry.path()));
            if tombstones.len() > 1 {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
        }
        Ok(tombstones)
    }

    fn removal_temporaries(&self) -> Result<Vec<PathBuf>, ProfileError> {
        let prefix = format!(".{REMOVAL_JOURNAL_FILE}.");
        let mut temporaries = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
            let Some(uuid) = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix(".tmp"))
            else {
                continue;
            };
            validate_profile_id(uuid).map_err(|_| ProfileError::RemovalRecoveryRequired)?;
            verify_private_single_link_regular_file(&entry.path())
                .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
            if fs::metadata(entry.path())?.len() > MAX_REMOVAL_JOURNAL_BYTES as u64 {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
            temporaries.push(entry.path());
            if temporaries.len() > 1 {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
        }
        Ok(temporaries)
    }

    fn validate_removal_artifact_set(
        &self,
        journal: &RemovalJournal,
        tombstones: &[(String, PathBuf)],
        _temporaries: &[PathBuf],
    ) -> Result<(), ProfileError> {
        if tombstones.iter().any(|(id, _)| id != &journal.profile.id) {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn remove_stale_removal_temporary(&self, temporaries: &[PathBuf]) -> Result<(), ProfileError> {
        if temporaries.len() != 1 {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        verify_private_single_link_regular_file(&temporaries[0])
            .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
        fs::remove_file(&temporaries[0])?;
        sync_directory(&self.root)
    }

    #[cfg(unix)]
    fn finish_visible_removal(
        &self,
        _removal_lock: &RegistryLock,
        registry_lock: &RegistryLock,
        journal: &RemovalJournal,
        tombstone: &Path,
    ) -> Result<(), ProfileError> {
        let roots = self.validate_removal_roots(Some(journal))?;
        validate_partial_owned_tombstone(
            &self.root,
            &roots,
            tombstone,
            &journal.profile.id,
            journal.profile_tree,
        )?;
        self.inject_removal_fault(RemovalFaultPoint::RecursiveCleanup)?;
        remove_owned_tombstone_at(
            &self.provider_root(journal.profile.provider)?,
            tombstone,
            journal.provider_root,
            journal.profile_tree,
        )
        .map_err(removal_commit_error)?;
        self.validate_removal_roots(Some(journal))?;
        self.inject_removal_fault(RemovalFaultPoint::ProviderRootSyncAfterCleanup)
            .and_then(|()| sync_directory(&self.provider_root(journal.profile.provider)?))
            .map_err(|error| match error {
                ProfileError::Io(error) => ProfileError::RemovalCommitUncertain(error),
                other => other,
            })?;

        #[cfg(test)]
        self.pause_removal_after_cleanup()?;

        let current = self
            .read_removal_journal()?
            .ok_or(ProfileError::RemovalRecoveryRequired)?;
        if &current != journal {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        let temporaries = self.removal_temporaries()?;
        self.remove_removal_journal(_removal_lock, registry_lock, journal, &temporaries)
    }

    fn remove_removal_journal(
        &self,
        _removal_lock: &RegistryLock,
        _registry_lock: &RegistryLock,
        journal: &RemovalJournal,
        temporaries: &[PathBuf],
    ) -> Result<(), ProfileError> {
        let current = self
            .read_removal_journal()?
            .ok_or(ProfileError::RemovalRecoveryRequired)?;
        if &current != journal {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        if !temporaries.is_empty() {
            if temporaries.len() != 1 {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
            verify_private_single_link_regular_file(&temporaries[0])
                .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
            fs::remove_file(&temporaries[0]).map_err(ProfileError::RemovalCommitUncertain)?;
        }
        self.inject_removal_fault(RemovalFaultPoint::JournalRemove)
            .map_err(removal_commit_error)?;
        fs::remove_file(self.root.join(REMOVAL_JOURNAL_FILE))
            .map_err(ProfileError::RemovalCommitUncertain)?;
        self.inject_removal_fault(RemovalFaultPoint::JournalRemoveDirectorySync)
            .and_then(|()| sync_directory(&self.root))
            .map_err(|error| match error {
                ProfileError::Io(error) => ProfileError::RemovalCommitUncertain(error),
                other => other,
            })
    }

    fn inject_removal_fault(&self, _fault: RemovalFaultPoint) -> Result<(), ProfileError> {
        #[cfg(test)]
        if self.removal_fault == Some(_fault) {
            return Err(ProfileError::Io(io::Error::other(
                "injected removal failure",
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    fn pause_removal_after_cleanup(&self) -> Result<(), ProfileError> {
        let Some(pause) = &self.removal_pause_after_cleanup else {
            return Ok(());
        };
        pause.reached.send(()).map_err(|_| {
            ProfileError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "removal test observer disconnected",
            ))
        })?;
        pause.resume.recv().map_err(|_| {
            ProfileError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "removal test controller disconnected",
            ))
        })?;
        Ok(())
    }

    #[cfg(test)]
    fn pause_registry_mutation_after_preflight(&self) -> Result<(), ProfileError> {
        let Some(pause) = &self.registry_mutation_pause_after_preflight else {
            return Ok(());
        };
        pause.reached.send(()).map_err(|_| {
            ProfileError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "registry mutation test observer disconnected",
            ))
        })?;
        pause.resume.recv().map_err(|_| {
            ProfileError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "registry mutation test controller disconnected",
            ))
        })?;
        Ok(())
    }

    fn has_identity_bindings(
        &self,
        _document: &RegistryDocument,
        store: &IdentityStore<'_>,
    ) -> Result<bool, ProfileError> {
        let provider_root = self.root.join("profiles").join("codex");
        verify_private_directory(&provider_root)?;
        for entry in fs::read_dir(provider_root)? {
            let path = entry?.path();
            // Never traverse an untrusted entry to look for a marker. A
            // malformed orphan blocks key creation instead of being skipped.
            verify_private_directory(&path)?;
            if store.marker_exists(&path)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn find_identity_conflict<'a>(
        &self,
        document: &'a RegistryDocument,
        store: &IdentityStore<'_>,
        key: &IdentityKey,
        candidate: &ProviderIdentity,
        excluded_profile_id: Option<&str>,
    ) -> Result<Option<&'a Profile>, ProfileError> {
        for profile in &document.profiles {
            if excluded_profile_id == Some(profile.id.as_str()) {
                continue;
            }
            let profile_directory = self.profile_directory(profile)?;
            let Some(binding) = store.read_marker(&profile_directory, key)? else {
                continue;
            };
            if candidate.same_provider_identity(&binding) {
                return Ok(Some(profile));
            }
        }
        Ok(None)
    }

    fn inject_registry_write_fault(&self, _step: RegistryWriteStep) -> Result<(), ProfileError> {
        #[cfg(test)]
        if self.registry_write_fault == Some(_step)
            || self.removal_fault
                == Some(match _step {
                    RegistryWriteStep::TemporaryCreate => {
                        RemovalFaultPoint::RegistryTemporaryCreate
                    }
                    RegistryWriteStep::Write => RemovalFaultPoint::RegistryWrite,
                    RegistryWriteStep::FileSync => RemovalFaultPoint::RegistryFileSync,
                    RegistryWriteStep::AtomicRename => RemovalFaultPoint::RegistryAtomicRename,
                    RegistryWriteStep::DirectorySync => RemovalFaultPoint::RegistryDirectorySync,
                })
        {
            return Err(ProfileError::Io(io::Error::other(
                "injected registry write failure",
            )));
        }
        Ok(())
    }
}

impl RemovalJournal {
    fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != REMOVAL_JOURNAL_SCHEMA_VERSION {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        validate_profile_id(&self.profile.id).map_err(|_| ProfileError::RemovalRecoveryRequired)?;
        validate_alias(&self.profile.alias).map_err(|_| ProfileError::RemovalRecoveryRequired)?;
        if self.expected_registry_revision.checked_add(1) != Some(self.removed_registry_revision)
            || !is_sha256_hex(&self.expected_registry_digest)
            || !is_sha256_hex(&self.removed_registry_digest)
            || !is_sha256_hex(&self.profile_tree_manifest_digest)
            || self.expected_registry_digest == self.removed_registry_digest
            || self.profile_tree_entry_count == 0
            || self.profile_tree_entry_count
                > u64::try_from(MAX_REMOVAL_TREE_ENTRIES)
                    .map_err(|_| ProfileError::RemovalRecoveryRequired)?
        {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        for identity in [
            self.data_root,
            self.profiles_root,
            self.provider_root,
            self.profile_tree,
        ] {
            if identity.device == 0 || identity.inode == 0 {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
        }
        if self.data_root.device != self.profiles_root.device
            || self.data_root.device != self.provider_root.device
            || self.data_root.device != self.profile_tree.device
        {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        Ok(())
    }

    fn tree_snapshot(&self) -> RemovalTreeSnapshot {
        RemovalTreeSnapshot {
            root: self.profile_tree,
            entry_count: self.profile_tree_entry_count,
            manifest_digest: self.profile_tree_manifest_digest.clone(),
        }
    }

    fn matches_expected_registry(&self, document: &RegistryDocument) -> Result<bool, ProfileError> {
        Ok(document.revision == self.expected_registry_revision
            && registry_digest(document)? == self.expected_registry_digest
            && document
                .profiles
                .iter()
                .filter(|profile| *profile == &self.profile)
                .count()
                == 1)
    }

    fn matches_removed_registry(&self, document: &RegistryDocument) -> Result<bool, ProfileError> {
        Ok(document.revision == self.removed_registry_revision
            && registry_digest(document)? == self.removed_registry_digest
            && !document
                .profiles
                .iter()
                .any(|profile| profile.id == self.profile.id))
    }
}

fn registry_digest(document: &RegistryDocument) -> Result<String, ProfileError> {
    let bytes = serde_json::to_vec(document)
        .map_err(|_| ProfileError::InvalidRegistry("registry serialization failed".to_owned()))?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn next_registry_revision(revision: u64) -> Result<u64, ProfileError> {
    revision.checked_add(1).ok_or_else(|| {
        ProfileError::InvalidRegistry("registry revision is out of range".to_owned())
    })
}

fn removal_commit_error(error: ProfileError) -> ProfileError {
    match error {
        ProfileError::Io(error) => ProfileError::RemovalCommitUncertain(error),
        other => other,
    }
}

fn path_exists(path: &Path) -> Result<bool, ProfileError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ProfileError::Io(error)),
    }
}

fn validate_provider_root_components(root: &Path) -> Result<(), ProfileError> {
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ProfileError::UnsafeState(
            "managed removal root is invalid".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn private_directory_identity(path: &Path) -> Result<FileSystemIdentity, ProfileError> {
    use std::os::unix::fs::MetadataExt;

    verify_private_directory(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(ProfileError::UnsafeState(
            "managed directory has an unexpected owner".to_owned(),
        ));
    }
    Ok(FileSystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn private_directory_identity(path: &Path) -> Result<FileSystemIdentity, ProfileError> {
    verify_private_directory(path)?;
    Err(ProfileError::UnsupportedPlatform)
}

#[cfg(unix)]
fn verify_private_single_link_regular_file(path: &Path) -> Result<(), ProfileError> {
    use std::os::unix::fs::MetadataExt;

    verify_private_regular_file(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != rustix::process::getuid().as_raw() || metadata.nlink() != 1 {
        return Err(ProfileError::UnsafeState(
            "managed file ownership is unsafe".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_single_link_regular_file(path: &Path) -> Result<(), ProfileError> {
    verify_private_regular_file(path)
}

#[cfg(unix)]
fn validate_owned_removal_tree(
    data_root: &Path,
    roots: &RemovalRoots,
    path: &Path,
    profile_id: &str,
    expected: Option<RemovalTreeSnapshot>,
) -> Result<RemovalTreeSnapshot, ProfileError> {
    let expected_root = expected.as_ref().map(|snapshot| snapshot.root);
    let snapshot =
        validate_owned_removal_tree_inner(data_root, roots, path, profile_id, expected_root, true)?;
    if expected.is_some_and(|expected| expected != snapshot) {
        return Err(ProfileError::UnsafeState(
            "managed profile tree changed after removal preparation".to_owned(),
        ));
    }
    Ok(snapshot)
}

#[cfg(unix)]
fn validate_partial_owned_tombstone(
    data_root: &Path,
    roots: &RemovalRoots,
    path: &Path,
    profile_id: &str,
    expected: FileSystemIdentity,
) -> Result<FileSystemIdentity, ProfileError> {
    validate_owned_removal_tree_inner(data_root, roots, path, profile_id, Some(expected), false)
        .map(|snapshot| snapshot.root)
}

#[cfg(unix)]
fn validate_owned_removal_tree_inner(
    data_root: &Path,
    roots: &RemovalRoots,
    path: &Path,
    profile_id: &str,
    expected: Option<FileSystemIdentity>,
    require_marker: bool,
) -> Result<RemovalTreeSnapshot, ProfileError> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    validate_profile_id(profile_id)
        .map_err(|_| ProfileError::UnsafeState("profile removal ID is invalid".to_owned()))?;
    let expected_name = profile_id;
    let expected_tombstone = format!(".removing-{profile_id}");
    let name = path.file_name().and_then(|name| name.to_str());
    if path.parent() != Some(data_root.join("profiles/codex").as_path())
        || !path.starts_with(data_root)
        || !matches!(name, Some(value) if value == expected_name || value == expected_tombstone)
    {
        return Err(ProfileError::UnsafeState(
            "profile removal path is outside its managed provider root".to_owned(),
        ));
    }
    let identity = private_directory_identity(path)?;
    if identity.device != roots.provider_root.device
        || expected.is_some_and(|expected| expected != identity)
    {
        return Err(ProfileError::UnsafeState(
            "managed profile tree was replaced".to_owned(),
        ));
    }

    let mut manifest = Sha256::new();
    manifest.update(b"calcifer-removal-tree-manifest-v1\0");
    let root_metadata = fs::symlink_metadata(path)?;
    update_removal_manifest(&mut manifest, Path::new(""), &root_metadata)?;

    let mut pending = vec![(path.to_owned(), 0_usize)];
    let mut entry_count = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_REMOVAL_TREE_DEPTH {
            return Err(ProfileError::UnsafeState(
                "managed profile tree is too deep".to_owned(),
            ));
        }
        let directory_metadata = fs::symlink_metadata(&directory)?;
        if !directory_metadata.file_type().is_dir()
            || directory_metadata.file_type().is_symlink()
            || directory_metadata.uid() != rustix::process::getuid().as_raw()
            || directory_metadata.mode() & 0o077 != 0
            || directory_metadata.dev() != roots.provider_root.device
        {
            return Err(ProfileError::UnsafeState(
                "managed profile tree contains an unsafe directory".to_owned(),
            ));
        }
        let mut entries = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by(|left, right| {
            left.file_name()
                .as_bytes()
                .cmp(right.file_name().as_bytes())
        });
        let mut child_directories = Vec::new();
        for entry in entries {
            entry_count = entry_count.checked_add(1).ok_or_else(|| {
                ProfileError::UnsafeState("managed profile tree is too large".to_owned())
            })?;
            if entry_count > MAX_REMOVAL_TREE_ENTRIES {
                return Err(ProfileError::UnsafeState(
                    "managed profile tree is too large".to_owned(),
                ));
            }
            let entry_path = entry.path();
            let metadata = fs::symlink_metadata(&entry_path)?;
            let relative = entry_path.strip_prefix(path).map_err(|_| {
                ProfileError::UnsafeState(
                    "managed profile entry escaped its removal root".to_owned(),
                )
            })?;
            if metadata.file_type().is_symlink()
                || metadata.uid() != rustix::process::getuid().as_raw()
                || metadata.mode() & 0o077 != 0
                || metadata.dev() != roots.provider_root.device
            {
                return Err(ProfileError::UnsafeState(
                    "managed profile tree contains unsafe state".to_owned(),
                ));
            }
            update_removal_manifest(&mut manifest, relative, &metadata)?;
            if metadata.file_type().is_dir() {
                child_directories.push((entry_path, depth + 1));
            } else if !metadata.file_type().is_file() || metadata.nlink() != 1 {
                return Err(ProfileError::UnsafeState(
                    "managed profile tree contains a non-owned file".to_owned(),
                ));
            }
        }
        for child in child_directories.into_iter().rev() {
            pending.push(child);
        }
    }

    let marker = path.join(OWNER_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(_) => {
            verify_private_single_link_regular_file(&marker)?;
            let marker_metadata = fs::metadata(&marker)?;
            if marker_metadata.len() != profile_id.len() as u64 {
                return Err(ProfileError::UnsafeState(
                    "profile ownership marker does not match its registry entry".to_owned(),
                ));
            }
            let mut marker_value = String::new();
            File::open(marker)?.read_to_string(&mut marker_value)?;
            if marker_value != profile_id {
                return Err(ProfileError::UnsafeState(
                    "profile ownership marker does not match its registry entry".to_owned(),
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && !require_marker => {}
        Err(error) => return Err(ProfileError::Io(error)),
    }
    Ok(RemovalTreeSnapshot {
        root: identity,
        entry_count: u64::try_from(entry_count).map_err(|_| {
            ProfileError::UnsafeState("managed profile tree is too large".to_owned())
        })?,
        manifest_digest: format!("{:x}", manifest.finalize()),
    })
}

#[cfg(unix)]
fn update_removal_manifest(
    manifest: &mut Sha256,
    relative_path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ProfileError> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let path = relative_path.as_os_str().as_bytes();
    let path_len = u64::try_from(path.len()).map_err(|_| {
        ProfileError::UnsafeState("managed profile entry name is too large".to_owned())
    })?;
    manifest.update(path_len.to_le_bytes());
    manifest.update(path);
    manifest.update([if metadata.file_type().is_dir() { 1 } else { 2 }]);
    manifest.update(metadata.dev().to_le_bytes());
    manifest.update(metadata.ino().to_le_bytes());
    manifest.update(metadata.uid().to_le_bytes());
    manifest.update(metadata.mode().to_le_bytes());
    manifest.update(metadata.nlink().to_le_bytes());
    manifest.update(metadata.len().to_le_bytes());
    Ok(())
}

#[cfg(not(unix))]
fn validate_owned_removal_tree(
    _data_root: &Path,
    _roots: &RemovalRoots,
    _path: &Path,
    _profile_id: &str,
    _expected: Option<RemovalTreeSnapshot>,
) -> Result<RemovalTreeSnapshot, ProfileError> {
    Err(ProfileError::UnsupportedPlatform)
}

/// Recursively unlinks a validated tombstone through directory descriptors.
///
/// Every child lookup is `*at`-relative and `NOFOLLOW`; a symlink or replaced
/// directory therefore cannot redirect traversal outside the opened tree.
#[cfg(unix)]
fn remove_owned_tombstone_at(
    provider_root: &Path,
    tombstone: &Path,
    expected_provider: FileSystemIdentity,
    expected_tree: FileSystemIdentity,
) -> Result<(), ProfileError> {
    use rustix::fs::{AtFlags, Dir, Mode, OFlags, fstat, open, openat, statat, unlinkat};

    let tombstone_name = tombstone
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ProfileError::UnsafeState("invalid removal tombstone name".to_owned()))?;
    if tombstone.parent() != Some(provider_root) || !tombstone_name.starts_with(".removing-") {
        return Err(ProfileError::UnsafeState(
            "profile removal path is outside its managed provider root".to_owned(),
        ));
    }
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let provider_fd = open(provider_root, directory_flags, Mode::empty())
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    let provider_stat = fstat(&provider_fd)
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    if stat_identity(&provider_stat)? != expected_provider {
        return Err(ProfileError::RemovalRecoveryRequired);
    }
    let tree_fd = openat(&provider_fd, tombstone_name, directory_flags, Mode::empty())
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    let tree_stat = fstat(&tree_fd)
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    if stat_identity(&tree_stat)? != expected_tree {
        return Err(ProfileError::UnsafeState(
            "managed profile tree was replaced".to_owned(),
        ));
    }
    validate_removal_stat(&tree_stat, true, expected_provider.device)?;
    remove_owned_directory_entries(
        Dir::new(tree_fd).map_err(io::Error::from)?,
        expected_provider.device,
    )?;

    let final_stat = statat(&provider_fd, tombstone_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    if stat_identity(&final_stat)? != expected_tree {
        return Err(ProfileError::UnsafeState(
            "managed profile tree was replaced during cleanup".to_owned(),
        ));
    }
    unlinkat(&provider_fd, tombstone_name, AtFlags::REMOVEDIR)
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)
}

#[cfg(unix)]
fn remove_owned_directory_entries(
    mut directory: rustix::fs::Dir,
    expected_device: u64,
) -> Result<(), ProfileError> {
    use rustix::fs::{AtFlags, Mode, OFlags, fstat, openat, statat, unlinkat};

    let mut names = Vec::new();
    for entry in directory.by_ref() {
        let entry = entry.map_err(io::Error::from).map_err(ProfileError::Io)?;
        if entry.file_name().to_bytes() != b"." && entry.file_name().to_bytes() != b".." {
            names.push(entry.file_name().to_owned());
        }
    }
    for name in names {
        let stat = statat(
            directory.fd().map_err(io::Error::from)?,
            &name,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
        let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
        if file_type.is_dir() {
            validate_removal_stat(&stat, true, expected_device)?;
            let child = openat(
                directory.fd().map_err(io::Error::from)?,
                &name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)
            .map_err(ProfileError::Io)?;
            let opened_stat = fstat(&child)
                .map_err(io::Error::from)
                .map_err(ProfileError::Io)?;
            if stat_identity(&opened_stat)? != stat_identity(&stat)? {
                return Err(ProfileError::UnsafeState(
                    "managed profile directory was replaced during cleanup".to_owned(),
                ));
            }
            remove_owned_directory_entries(
                rustix::fs::Dir::new(child).map_err(io::Error::from)?,
                expected_device,
            )?;
            let final_stat = statat(
                directory.fd().map_err(io::Error::from)?,
                &name,
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)
            .map_err(ProfileError::Io)?;
            if stat_identity(&final_stat)? != stat_identity(&stat)? {
                return Err(ProfileError::UnsafeState(
                    "managed profile directory was replaced during cleanup".to_owned(),
                ));
            }
            unlinkat(
                directory.fd().map_err(io::Error::from)?,
                &name,
                AtFlags::REMOVEDIR,
            )
            .map_err(io::Error::from)
            .map_err(ProfileError::Io)?;
        } else {
            validate_removal_stat(&stat, false, expected_device)?;
            unlinkat(
                directory.fd().map_err(io::Error::from)?,
                &name,
                AtFlags::empty(),
            )
            .map_err(io::Error::from)
            .map_err(ProfileError::Io)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn stat_identity(stat: &rustix::fs::Stat) -> Result<FileSystemIdentity, ProfileError> {
    Ok(FileSystemIdentity {
        device: u64::try_from(stat.st_dev).map_err(|_| {
            ProfileError::UnsafeState("managed filesystem identity is invalid".to_owned())
        })?,
        inode: stat.st_ino,
    })
}

#[cfg(unix)]
fn validate_removal_stat(
    stat: &rustix::fs::Stat,
    directory: bool,
    expected_device: u64,
) -> Result<(), ProfileError> {
    let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    let expected_type = if directory {
        file_type.is_dir()
    } else {
        file_type.is_file() && stat.st_nlink == 1
    };
    if !expected_type
        || stat.st_uid != rustix::process::getuid().as_raw()
        || stat.st_mode & 0o077 != 0
        || u64::try_from(stat.st_dev).ok() != Some(expected_device)
    {
        return Err(ProfileError::UnsafeState(
            "managed profile tree changed during cleanup".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_partial_owned_tombstone(
    _data_root: &Path,
    _roots: &RemovalRoots,
    _path: &Path,
    _profile_id: &str,
    _expected: FileSystemIdentity,
) -> Result<FileSystemIdentity, ProfileError> {
    Err(ProfileError::UnsupportedPlatform)
}

pub(crate) struct PendingProfile<'a> {
    registry: &'a Registry,
    _lock: RegistryLock,
    profile: Profile,
    staging: PathBuf,
    committed: bool,
    preserve_staging: bool,
}

impl PendingProfile<'_> {
    pub(crate) fn home(&self) -> PathBuf {
        self.staging.join("home")
    }

    pub(crate) fn abort(mut self) -> Result<(), ProfileError> {
        safe_remove_staging(&self.staging, &self.profile.id)?;
        self.committed = true;
        Ok(())
    }

    pub(crate) fn commit(mut self, adapter: CodexIdentityAdapter) -> Result<Profile, ProfileError> {
        verify_managed_codex_home(&self.home())?;
        let document = self.registry.load()?;
        let store = IdentityStore::new(&self.registry.root);
        let existing_bindings = self.registry.has_identity_bindings(&document, &store)?;
        #[cfg(test)]
        let key_publication = if self.registry.fail_identity_key_directory_sync {
            store.load_or_create_key_with_sync_for_test(existing_bindings, |_| {
                Err(IdentityError::Io(io::Error::other(
                    "injected identity key directory sync failure",
                )))
            })
        } else {
            store.load_or_create_key(existing_bindings)
        };
        #[cfg(not(test))]
        let key_publication = store.load_or_create_key(existing_bindings);

        let key = match key_publication {
            Ok(key) => key,
            Err(IdentityError::CommitUncertain) => {
                // A newly generated key was completely renamed and read back,
                // but its parent sync failed. Re-open that exact private key
                // and retry only the idempotent data-root sync. Provider login
                // has already succeeded and must never be repeated blindly.
                let recovered_key = store.load_key();
                #[cfg(test)]
                let directory_synced = if self.registry.fail_identity_key_recovery_directory_sync {
                    false
                } else {
                    sync_directory(&self.registry.root).is_ok()
                };
                #[cfg(not(test))]
                let directory_synced = sync_directory(&self.registry.root).is_ok();

                match (recovered_key, directory_synced) {
                    (Ok(key), true) => key,
                    _ => {
                        self.preserve_staging = true;
                        return Err(ProfileError::from(IdentityError::CommitUncertain));
                    }
                }
            }
            Err(error) => return Err(ProfileError::from(error)),
        };
        let identity = store.derive_codex_binding(&self.home(), &key, adapter)?;
        if let Some(conflict) = self
            .registry
            .find_identity_conflict(&document, &store, &key, &identity, None)?
        {
            return Err(ProfileError::DuplicateProviderIdentity {
                requested: self.profile.reference(),
                existing: conflict.reference(),
            });
        }
        #[cfg(test)]
        let marker_publication = if self.registry.fail_identity_marker_directory_sync {
            store.publish_marker_with_sync_for_test(&self.staging, &identity, |_| {
                Err(IdentityError::Io(io::Error::other(
                    "injected identity marker directory sync failure",
                )))
            })
        } else {
            store.publish_marker(&self.staging, &identity)
        };
        #[cfg(not(test))]
        let marker_publication = store.publish_marker(&self.staging, &identity);

        match marker_publication {
            Ok(()) => {}
            Err(IdentityError::CommitUncertain) => {
                // The marker rename is already visible and its file contents
                // were synced. Revalidate those exact bytes and retry only the
                // idempotent parent-directory sync; never repeat provider login.
                // If durability remains unknown, preserve the complete staging
                // directory for explicit recovery instead of deleting credentials.
                let marker_is_complete = store
                    .revalidate_marker(&self.staging, &key, &identity)
                    .is_ok();
                #[cfg(test)]
                let directory_synced = if self.registry.fail_identity_recovery_directory_sync {
                    false
                } else {
                    sync_directory(&self.staging).is_ok()
                };
                #[cfg(not(test))]
                let directory_synced = sync_directory(&self.staging).is_ok();

                if !marker_is_complete || !directory_synced {
                    self.preserve_staging = true;
                    return Err(ProfileError::from(IdentityError::CommitUncertain));
                }
            }
            Err(error) => return Err(ProfileError::from(error)),
        }
        store.revalidate_marker(&self.staging, &key, &identity)?;

        let final_directory = self
            .staging
            .parent()
            .ok_or_else(|| ProfileError::UnsafeState("staging directory has no parent".to_owned()))?
            .join(&self.profile.id);
        if final_directory.exists() {
            return Err(ProfileError::UnsafeState(
                "generated profile directory already exists".to_owned(),
            ));
        }
        fs::rename(&self.staging, &final_directory)?;

        let provider_root = final_directory.parent().ok_or_else(|| {
            ProfileError::UnsafeState("profile directory has no provider root".to_owned())
        })?;
        if let Err(error) = sync_directory(provider_root) {
            return self.rollback_after_publication_failure(&final_directory, error);
        }

        let publish_result = (|| {
            let mut document = self.registry.load()?;
            if document.profiles.iter().any(|profile| {
                profile.id == self.profile.id
                    || (profile.provider == self.profile.provider
                        && profile.alias == self.profile.alias)
            }) {
                return Err(ProfileError::AlreadyExists(self.profile.reference()));
            }
            document.profiles.push(self.profile.clone());
            document.revision = next_registry_revision(document.revision)?;
            self.registry.save(&document)
        })();

        if let Err(error) = publish_result {
            if matches!(error, ProfileError::RegistryCommitUncertain(_)) {
                // The registry rename is the visibility point. Its new contents
                // may already be visible even when the parent fsync fails, so
                // deleting the credentials here would create a dangling entry.
                self.committed = true;
                return Err(error);
            }
            return self.rollback_after_publication_failure(&final_directory, error);
        }
        self.committed = true;
        Ok(self.profile.clone())
    }

    fn rollback_after_publication_failure(
        mut self,
        final_directory: &Path,
        original_error: ProfileError,
    ) -> Result<Profile, ProfileError> {
        match fs::rename(final_directory, &self.staging) {
            Ok(()) => {
                if let Some(provider_root) = self.staging.parent() {
                    let _ = sync_directory(provider_root);
                }
                Err(original_error)
            }
            Err(_) => {
                self.committed = true;
                Err(ProfileError::RegistrationRecoveryRequired)
            }
        }
    }
}

impl Drop for PendingProfile<'_> {
    fn drop(&mut self) {
        if self.committed || self.preserve_staging {
            return;
        }
        let _ = safe_remove_staging(&self.staging, &self.profile.id);
    }
}

struct RegistryLock {
    _file: File,
}

pub(crate) struct ProfileLease {
    coordinator: Option<File>,
    provider: Option<File>,
}

pub(crate) struct VerifiedProviderIdentityLease {
    _lease: ProfileLease,
    profile: Profile,
    identity: ProviderIdentity,
}

impl VerifiedProviderIdentityLease {
    pub(crate) const fn profile(&self) -> &Profile {
        &self.profile
    }

    #[allow(dead_code)] // Used by pool uniqueness validation in issue #4.
    pub(crate) fn same_provider_identity(&self, other: &Self) -> bool {
        self.identity.same_provider_identity(&other.identity)
    }
}

#[cfg(unix)]
impl ProfileLease {
    /// Temporarily allows the provider-side lock to survive one `exec`.
    ///
    /// This is used only by the one-shot account app-server. That process does
    /// not start turns or tools, so it cannot leak the descriptor to provider
    /// background jobs. If the status parent is killed, the app-server keeps
    /// the profile busy until its stdio closes and it exits.
    pub(crate) fn inherit_provider_lock(
        &self,
    ) -> Result<ProviderLockInheritance<'_>, ProfileError> {
        use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};

        let provider = self
            .provider
            .as_ref()
            .ok_or_else(|| ProfileError::UnsafeState("provider lock is not held".to_owned()))?;
        let original = fcntl_getfd(provider).map_err(io::Error::from)?;
        fcntl_setfd(provider, original.difference(FdFlags::CLOEXEC)).map_err(io::Error::from)?;
        Ok(ProviderLockInheritance { provider, original })
    }
}

impl Drop for ProfileLease {
    fn drop(&mut self) {
        if let Some(provider) = &self.provider {
            let _ = FileExt::unlock(provider);
        }
        if let Some(coordinator) = &self.coordinator {
            let _ = FileExt::unlock(coordinator);
        }
    }
}

#[cfg(unix)]
pub(crate) struct ProviderLockInheritance<'a> {
    provider: &'a File,
    original: rustix::io::FdFlags,
}

#[cfg(unix)]
impl Drop for ProviderLockInheritance<'_> {
    fn drop(&mut self) {
        let _ = rustix::io::fcntl_setfd(self.provider, self.original);
    }
}

#[derive(Debug)]
pub(crate) enum ProfileError {
    AlreadyExists(String),
    Busy(String),
    DuplicateProviderIdentity { requested: String, existing: String },
    Identity(IdentityError),
    InvalidAlias,
    InvalidRegistry(String),
    Io(io::Error),
    MissingDataRoot,
    NotFound(String),
    RegistrationRecoveryRequired,
    RemovalCommitUncertain(io::Error),
    RemovalRecoveryRequired,
    RegistryCommitUncertain(io::Error),
    UnsupportedPlatform,
    UnsafeState(String),
}

impl ProfileError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::AlreadyExists(_) => "profile_already_exists",
            Self::Busy(_) => "profile_busy",
            Self::DuplicateProviderIdentity { .. } => "duplicate_provider_identity",
            Self::Identity(error) => error.code(),
            Self::InvalidAlias => "invalid_profile_alias",
            Self::InvalidRegistry(_) => "invalid_registry",
            Self::Io(_) => "io_error",
            Self::MissingDataRoot => "missing_data_root",
            Self::NotFound(_) => "profile_not_found",
            Self::RegistrationRecoveryRequired => "registration_recovery_required",
            Self::RemovalCommitUncertain(_) => "removal_commit_uncertain",
            Self::RemovalRecoveryRequired => "removal_recovery_required",
            Self::RegistryCommitUncertain(_) => "registry_commit_uncertain",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::UnsafeState(_) => "unsafe_profile_state",
        }
    }

    pub(crate) fn safe_message(&self) -> String {
        match self {
            Self::AlreadyExists(reference) => format!("Profile {reference} already exists."),
            Self::Busy(reference) => format!("Profile {reference} is already in use."),
            Self::DuplicateProviderIdentity {
                requested,
                existing,
            } => format!(
                "Profiles {requested} and {existing} resolve to the same private provider identity. Choose a different provider account."
            ),
            Self::Identity(error) => error.safe_message().to_owned(),
            Self::InvalidAlias => "Profile aliases must be 1-64 ASCII letters, digits, '.', '_' or '-', and must start with a letter or digit.".to_owned(),
            Self::InvalidRegistry(reason) => format!("Calcifer's profile registry is invalid: {reason}."),
            Self::Io(_) => "Calcifer could not access its managed profile storage.".to_owned(),
            Self::MissingDataRoot => "Calcifer could not determine a user data directory. Set CALCIFER_HOME to an absolute path.".to_owned(),
            Self::NotFound(reference) => format!("Profile {reference} was not found."),
            Self::RegistrationRecoveryRequired => "Calcifer could not roll back a partially published profile. Do not retry registration until the managed state has been inspected.".to_owned(),
            Self::RemovalCommitUncertain(error) => {
                let _ = error.kind();
                "The local profile removal reached a commit boundary whose durability could not be confirmed. Run `calcifer auth list` to complete bounded recovery before retrying.".to_owned()
            }
            Self::RemovalRecoveryRequired => "Calcifer found an incomplete or ambiguous local profile removal. No unsafe path was deleted; run `calcifer auth list` to attempt bounded recovery.".to_owned(),
            Self::RegistryCommitUncertain(error) => {
                let _ = error.kind();
                "The profile registry became visible but its durability could not be confirmed. Run `calcifer auth list` before retrying; Calcifer preserved the profile credentials.".to_owned()
            }
            Self::UnsupportedPlatform => "Managed profiles are not supported on this platform yet because private ACL creation has not been verified.".to_owned(),
            Self::UnsafeState(reason) => format!("Calcifer refused unsafe profile storage: {reason}."),
        }
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.safe_message())
    }
}

impl std::error::Error for ProfileError {}

impl From<io::Error> for ProfileError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<IdentityError> for ProfileError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

fn data_root() -> Result<PathBuf, ProfileError> {
    if let Some(path) = env::var_os("CALCIFER_HOME") {
        return require_absolute_root(PathBuf::from(path));
    }

    #[cfg(target_os = "macos")]
    {
        return env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(ProfileError::MissingDataRoot)
            .and_then(require_absolute_root)
            .map(|home| {
                home.join("Library")
                    .join("Application Support")
                    .join("calcifer")
            });
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(path) = env::var_os("XDG_DATA_HOME") {
            return require_absolute_root(PathBuf::from(path)).map(|root| root.join("calcifer"));
        }
        return env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(ProfileError::MissingDataRoot)
            .and_then(require_absolute_root)
            .map(|home| home.join(".local").join("share").join("calcifer"));
    }

    #[cfg(target_os = "windows")]
    {
        return env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or(ProfileError::MissingDataRoot)
            .and_then(require_absolute_root)
            .map(|root| root.join("calcifer"));
    }

    #[allow(unreachable_code)]
    Err(ProfileError::UnsupportedPlatform)
}

fn require_absolute_root(path: PathBuf) -> Result<PathBuf, ProfileError> {
    if !path.is_absolute() {
        return Err(ProfileError::UnsafeState(
            "user data environment paths must be absolute".to_owned(),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ProfileError::UnsafeState(
            "user data environment paths must be lexically normalized".to_owned(),
        ));
    }
    Ok(path)
}

pub(crate) fn validate_alias(alias: &str) -> Result<(), ProfileError> {
    let bytes = alias.as_bytes();
    let starts_valid = bytes.first().is_some_and(u8::is_ascii_alphanumeric);
    let all_valid = bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if bytes.is_empty() || bytes.len() > 64 || !starts_valid || !all_valid {
        return Err(ProfileError::InvalidAlias);
    }
    Ok(())
}

fn validate_profile_id(id: &str) -> Result<(), ProfileError> {
    let parsed = Uuid::parse_str(id)
        .map_err(|_| ProfileError::InvalidRegistry("profile id is not a UUID".to_owned()))?;
    if parsed.to_string() != id {
        return Err(ProfileError::InvalidRegistry(
            "profile id is not canonical".to_owned(),
        ));
    }
    Ok(())
}

fn validate_document(document: &RegistryDocument) -> Result<(), ProfileError> {
    for (index, profile) in document.profiles.iter().enumerate() {
        validate_profile_id(&profile.id)?;
        validate_alias(&profile.alias).map_err(|_| {
            ProfileError::InvalidRegistry(format!("profile {index} has an invalid alias"))
        })?;
        if document.profiles.iter().take(index).any(|previous| {
            previous.id == profile.id
                || (previous.provider == profile.provider && previous.alias == profile.alias)
        }) {
            return Err(ProfileError::InvalidRegistry(
                "registry contains a duplicate profile".to_owned(),
            ));
        }
    }
    Ok(())
}

fn unix_timestamp() -> Result<i64, ProfileError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProfileError::UnsafeState("system clock is before Unix epoch".to_owned()))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| ProfileError::UnsafeState("system clock is out of range".to_owned()))
}

#[cfg(unix)]
fn ensure_registration_supported() -> Result<(), ProfileError> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_registration_supported() -> Result<(), ProfileError> {
    Err(ProfileError::UnsupportedPlatform)
}

#[cfg(unix)]
fn secure_create_dir(path: &Path) -> Result<(), ProfileError> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new().mode(0o700).create(path)?;
    verify_private_directory(path)
}

#[cfg(not(unix))]
fn secure_create_dir(path: &Path) -> Result<(), ProfileError> {
    fs::create_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn secure_create_dir_all(path: &Path) -> Result<(), ProfileError> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    verify_private_directory(path)
}

#[cfg(not(unix))]
fn secure_create_dir_all(path: &Path) -> Result<(), ProfileError> {
    fs::create_dir_all(path)?;
    Ok(())
}

fn ensure_private_subdirectory(path: &Path) -> Result<(), ProfileError> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => match secure_create_dir(path) {
            Ok(()) => Ok(()),
            Err(ProfileError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                verify_private_directory(path)
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(ProfileError::Io(error)),
    }
}

#[cfg(unix)]
fn managed_runtime_root() -> Result<PathBuf, ProfileError> {
    use std::os::unix::fs::MetadataExt;

    let runtime_root =
        PathBuf::from("/tmp").join(format!("calcifer-{}", rustix::process::getuid().as_raw()));
    ensure_private_subdirectory(&runtime_root)?;
    let metadata = fs::symlink_metadata(&runtime_root)?;
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(ProfileError::UnsafeState(
            "managed runtime directory has an unexpected owner".to_owned(),
        ));
    }
    Ok(runtime_root)
}

#[cfg(unix)]
fn verify_private_directory(path: &Path) -> Result<(), ProfileError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ProfileError::UnsafeState(
            "managed directory is not a real directory".to_owned(),
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(ProfileError::UnsafeState(
            "managed directory is accessible by another OS user".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_directory(path: &Path) -> Result<(), ProfileError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ProfileError::UnsafeState(
            "managed directory is not a real directory".to_owned(),
        ));
    }
    Ok(())
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

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ProfileError> {
    let mut options = private_open_options();
    let mut file = options.write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    verify_private_regular_file(path)
}

fn open_private_lock_file(path: &Path) -> Result<File, ProfileError> {
    let mut options = private_open_options();
    let file = options.read(true).write(true).create(true).open(path)?;
    verify_private_regular_file(path)?;
    Ok(file)
}

fn lock_profile_file(path: &Path, reference: &str) -> Result<File, ProfileError> {
    let file = open_private_lock_file(path)?;
    FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            ProfileError::Busy(reference.to_owned())
        } else {
            ProfileError::Io(error)
        }
    })?;
    Ok(file)
}

#[cfg(unix)]
fn lock_existing_profile_file(path: &Path, reference: &str) -> Result<File, ProfileError> {
    let mut options = private_open_options();
    let file = options.read(true).write(true).open(path)?;
    verify_private_single_link_regular_file(path)?;
    FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            ProfileError::Busy(reference.to_owned())
        } else {
            ProfileError::Io(error)
        }
    })?;
    Ok(file)
}

#[cfg(unix)]
fn verify_private_regular_file(path: &Path) -> Result<(), ProfileError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ProfileError::UnsafeState(
            "managed file is not a regular file".to_owned(),
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(ProfileError::UnsafeState(
            "managed file is accessible by another OS user".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_regular_file(path: &Path) -> Result<(), ProfileError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ProfileError::UnsafeState(
            "managed file is not a regular file".to_owned(),
        ));
    }
    Ok(())
}

fn verify_codex_auth_file(path: &Path) -> Result<(), ProfileError> {
    verify_private_regular_file(path).map_err(|error| match error {
        ProfileError::Io(io_error) if io_error.kind() == io::ErrorKind::NotFound => {
            ProfileError::UnsafeState(
                "managed Codex profile is missing a private auth.json".to_owned(),
            )
        }
        other => other,
    })
}

fn verify_managed_codex_home(home: &Path) -> Result<(), ProfileError> {
    verify_private_directory(home)?;
    verify_managed_codex_agents_absent(&home.join("agents"))?;
    verify_managed_codex_config(&home.join("config.toml"))?;
    verify_codex_auth_file(&home.join("auth.json"))
}

fn verify_managed_codex_agents_absent(path: &Path) -> Result<(), ProfileError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(managed_codex_config_policy_error()),
    }
}

fn verify_managed_codex_config(path: &Path) -> Result<(), ProfileError> {
    verify_private_regular_file(path).map_err(|error| match error {
        ProfileError::Io(io_error) if io_error.kind() == io::ErrorKind::NotFound => {
            ProfileError::UnsafeState("managed Codex profile is missing its config.toml".to_owned())
        }
        other => other,
    })?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take((MAX_MANAGED_CODEX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MANAGED_CODEX_CONFIG_BYTES {
        return Err(managed_codex_config_policy_error());
    }
    validate_managed_codex_config(&bytes)
}

fn validate_managed_codex_config(bytes: &[u8]) -> Result<(), ProfileError> {
    let text = std::str::from_utf8(bytes).map_err(|_| managed_codex_config_policy_error())?;
    let config =
        toml::from_str::<toml::Table>(text).map_err(|_| managed_codex_config_policy_error())?;

    for key in config.keys() {
        if !CODEX_0_144_4_CONFIG_KEYS.contains(&key.as_str())
            || MANAGED_CODEX_FORBIDDEN_CONFIG_KEYS.contains(&key.as_str())
        {
            return Err(managed_codex_config_policy_error());
        }
    }

    if config
        .get("cli_auth_credentials_store")
        .and_then(toml::Value::as_str)
        != Some("file")
    {
        return Err(managed_codex_config_policy_error());
    }

    if config
        .get("mcp_oauth_credentials_store")
        .is_some_and(|store| store.as_str() != Some("file"))
    {
        return Err(managed_codex_config_policy_error());
    }

    if let Some(projects) = config.get("projects") {
        let projects = projects
            .as_table()
            .ok_or_else(managed_codex_config_policy_error)?;
        for (project_path, project) in projects {
            if project_path.is_empty() || !Path::new(project_path).is_absolute() {
                return Err(managed_codex_config_policy_error());
            }
            let project = project
                .as_table()
                .ok_or_else(managed_codex_config_policy_error)?;
            if project.len() != 1
                || !matches!(
                    project.get("trust_level").and_then(toml::Value::as_str),
                    Some("trusted" | "untrusted")
                )
            {
                return Err(managed_codex_config_policy_error());
            }
        }
    }

    Ok(())
}

fn managed_codex_config_policy_error() -> ProfileError {
    ProfileError::UnsafeState(
        "managed Codex profile violates the supported compatibility policy".to_owned(),
    )
}

fn atomic_write_private(
    root: &Path,
    name: &str,
    bytes: &[u8],
    mut before_step: impl FnMut(RegistryWriteStep) -> Result<(), ProfileError>,
    sync_parent: impl FnOnce(&Path) -> Result<(), ProfileError>,
) -> Result<(), ProfileError> {
    let temporary_name = format!(".{name}.{}.tmp", Uuid::new_v4());
    let temporary = root.join(temporary_name);
    let destination = root.join(name);
    let publication = (|| {
        before_step(RegistryWriteStep::TemporaryCreate)?;
        let mut options = private_open_options();
        let mut file = options.write(true).create_new(true).open(&temporary)?;
        before_step(RegistryWriteStep::Write)?;
        file.write_all(bytes)?;
        before_step(RegistryWriteStep::FileSync)?;
        file.sync_all()?;
        verify_private_regular_file(&temporary)?;
        drop(file);
        before_step(RegistryWriteStep::AtomicRename)?;
        fs::rename(&temporary, &destination)?;
        Ok(())
    })();
    if let Err(error) = publication {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    before_step(RegistryWriteStep::DirectorySync)
        .and_then(|()| sync_parent(root))
        .map_err(|error| match error {
            ProfileError::Io(io_error) => ProfileError::RegistryCommitUncertain(io_error),
            other => other,
        })
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ProfileError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ProfileError> {
    Ok(())
}

fn verify_owned_profile_directory(path: &Path, id: &str) -> Result<(), ProfileError> {
    verify_private_directory(path)?;
    let marker = path.join(OWNER_MARKER);
    verify_private_regular_file(&marker)?;
    let value = fs::read_to_string(marker)?;
    if value != id {
        return Err(ProfileError::UnsafeState(
            "profile ownership marker does not match its registry entry".to_owned(),
        ));
    }
    Ok(())
}

fn safe_remove_staging(path: &Path, id: &str) -> Result<(), ProfileError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ProfileError::UnsafeState("invalid staging path".to_owned()))?;
    if name != format!(".staging-{id}")
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(ProfileError::UnsafeState(
            "refused to clean an unexpected staging path".to_owned(),
        ));
    }
    verify_owned_profile_directory(path, id)?;
    fs::remove_dir_all(path)?;
    Ok(())
}

fn refuse_orphaned_staging(provider_root: &Path) -> Result<(), ProfileError> {
    verify_private_directory(provider_root)?;
    for entry in fs::read_dir(provider_root)? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| {
            ProfileError::UnsafeState("managed profile entry name is invalid".to_owned())
        })?;
        let Some(id) = name.strip_prefix(".staging-") else {
            continue;
        };
        validate_profile_id(id).map_err(|_| {
            ProfileError::UnsafeState("managed staging entry name is invalid".to_owned())
        })?;
        verify_owned_profile_directory(&entry.path(), id)?;
        // The registry lock spans every live registration, so a staging
        // directory observed after acquiring it is necessarily crash-stale or
        // deliberately preserved after a commit-uncertain result. Starting a
        // second login could publish duplicate credentials while the first
        // transaction remains unresolved.
        return Err(ProfileError::RegistrationRecoveryRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(unix))]
    #[test]
    fn unsupported_platform_recovery_preserves_a_journal_temporary() {
        let root = env::temp_dir().join(format!(
            "calcifer-non-unix-removal-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("temporary root must be created");
        let temporary = root.join(format!(".{REMOVAL_JOURNAL_FILE}.{}.tmp", Uuid::new_v4()));
        let sentinel = b"non-unix-removal-artifact-must-survive";
        fs::write(&temporary, sentinel).expect("temporary journal must be written");

        let error = Registry::at(root.clone())
            .recover_incomplete_removal()
            .expect_err("unverified ACL platforms must fail closed");

        assert_eq!(error.code(), "unsupported_platform");
        assert_eq!(
            fs::read(&temporary).expect("temporary journal must remain readable"),
            sentinel
        );
        fs::remove_dir_all(root).expect("temporary root must be removed");
    }

    #[cfg(unix)]
    fn temporary_root(test_name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "calcifer-{test_name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ))
    }

    #[cfg(unix)]
    fn write_test_codex_auth(home: &Path) -> Result<(), ProfileError> {
        let account_scope = Uuid::new_v4().to_string();
        write_test_codex_auth_for_scope(home, &account_scope)
    }

    #[cfg(unix)]
    fn write_test_codex_auth_for_scope(
        home: &Path,
        account_scope: &str,
    ) -> Result<(), ProfileError> {
        let document = serde_json::json!({
            "auth_mode": "chatgpt",
            "tokens": { "account_id": account_scope }
        });
        let bytes = serde_json::to_vec(&document)
            .map_err(|_| ProfileError::UnsafeState("test auth serialization failed".to_owned()))?;
        write_private_file(&home.join("auth.json"), &bytes)
    }

    #[cfg(unix)]
    const fn test_identity_adapter() -> CodexIdentityAdapter {
        CodexIdentityAdapter::for_test()
    }

    #[cfg(unix)]
    fn register_test_profile(registry: &Registry, alias: &str) -> Result<Profile, ProfileError> {
        let pending = registry.begin_codex_registration(alias)?;
        write_test_codex_auth(&pending.home())?;
        pending.commit(test_identity_adapter())
    }

    #[test]
    fn alias_validation_rejects_paths_and_ambiguous_references() {
        for alias in ["", ".hidden", "../work", "work/personal", "a@b", "火"] {
            assert!(validate_alias(alias).is_err(), "{alias} must be rejected");
        }
        for alias in ["work", "personal-2", "team.prod", "team_prod"] {
            assert!(validate_alias(alias).is_ok(), "{alias} must be accepted");
        }
    }

    #[test]
    fn managed_codex_config_accepts_supported_provider_and_user_state() {
        let absolute_root = if cfg!(windows) {
            "C:/synthetic"
        } else {
            "/synthetic"
        };
        let supported = [
            r#"# Managed by Calcifer.
cli_auth_credentials_store = "file"
mcp_oauth_credentials_store = "file"
"#
            .to_owned(),
            format!(
                r#"# Comments, whitespace, and root-key order are not invariants.
model = "gpt-5.4"
cli_auth_credentials_store = "file"
mcp_oauth_credentials_store = "file"

[projects."{absolute_root}/first"]
trust_level = "trusted"

[projects."{absolute_root}/stale/nonexistent"]
trust_level = "untrusted"
"#
            ),
            format!(
                r#"cli_auth_credentials_store = "file"
projects = {{ "{absolute_root}/inline" = {{ trust_level = "trusted" }} }}
sandbox_mode = "workspace-write"
"#
            ),
        ];

        for config in supported {
            assert!(
                validate_managed_codex_config(config.as_bytes()).is_ok(),
                "supported semantic config must be accepted"
            );
        }
    }

    #[test]
    fn managed_codex_config_rejects_invalid_or_ambiguous_state() {
        let rejected = [
            "",
            "not valid = [toml",
            "model = \"gpt-5.4\"\n",
            "cli_auth_credentials_store = \"auto\"\n",
            "cli_auth_credentials_store = \"keyring\"\n",
            "cli_auth_credentials_store = \"ephemeral\"\n",
            "cli_auth_credentials_store = 1\n",
            "cli_auth_credentials_store = \"file\"\nmcp_oauth_credentials_store = \"auto\"\n",
            "cli_auth_credentials_store = \"file\"\nmcp_oauth_credentials_store = \"keyring\"\n",
            "cli_auth_credentials_store = \"file\"\nmcp_oauth_credentials_store = 1\n",
            "cli_auth_credentials_store = \"file\"\nfuture_provider_key = true\n",
            "cli_auth_credentials_store = \"file\"\nprojects = \"trusted\"\n",
            "cli_auth_credentials_store = \"file\"\nprojects = { \"/synthetic\" = \"trusted\" }\n",
            "cli_auth_credentials_store = \"file\"\nprojects = { \"/synthetic\" = { trust_level = \"maybe\" } }\n",
            "cli_auth_credentials_store = \"file\"\nprojects = { \"/synthetic\" = { trust_level = \"trusted\", extra = true } }\n",
            "cli_auth_credentials_store = \"file\"\nprojects = { \"\" = { trust_level = \"trusted\" } }\n",
            "cli_auth_credentials_store = \"file\"\nprojects = { \"relative/path\" = { trust_level = \"trusted\" } }\n",
        ];

        for config in rejected {
            assert!(
                validate_managed_codex_config(config.as_bytes()).is_err(),
                "unsupported semantic config must be rejected"
            );
        }

        let sensitive_path = "relative/account-owner@example.invalid";
        let config = format!(
            "cli_auth_credentials_store = \"file\"\nprojects = {{ \"{sensitive_path}\" = {{ trust_level = \"trusted\" }} }}\n"
        );
        let error = match validate_managed_codex_config(config.as_bytes()) {
            Ok(()) => panic!("sensitive project path was unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(!error.safe_message().contains(sensitive_path));
    }

    #[test]
    fn managed_codex_config_rejects_role_definitions_without_disclosure() {
        let sensitive_role = "account-owner@example.invalid";
        let sensitive_path = "/private/synthetic/role-config.toml";
        let config = format!(
            r#"cli_auth_credentials_store = "file"

[agents."{sensitive_role}"]
description = "synthetic role"
config_file = "{sensitive_path}"
"#
        );

        let error = match validate_managed_codex_config(config.as_bytes()) {
            Err(error) => error,
            Ok(()) => panic!("managed role definitions must fail closed"),
        };
        let message = error.safe_message();
        assert!(!message.contains("agents"));
        assert!(!message.contains(sensitive_role));
        assert!(!message.contains(sensitive_path));
    }

    #[test]
    fn managed_codex_config_rejects_oauth_callback_overrides_without_disclosure() {
        let sensitive_url = "https://account-owner@example.invalid/private/callback";
        let overrides = [
            (
                "mcp_oauth_callback_url",
                format!("mcp_oauth_callback_url = \"{sensitive_url}\"\n"),
                sensitive_url,
            ),
            (
                "mcp_oauth_callback_port",
                "mcp_oauth_callback_port = 48765\n".to_owned(),
                "48765",
            ),
        ];

        for (key, callback_override, sensitive_value) in overrides {
            let config = format!("cli_auth_credentials_store = \"file\"\n{callback_override}");
            let error = match validate_managed_codex_config(config.as_bytes()) {
                Err(error) => error,
                Ok(()) => panic!("managed OAuth callback override {key} must fail closed"),
            };
            assert_eq!(error.code(), "unsafe_profile_state");
            let message = error.safe_message();
            assert!(!message.contains(key));
            assert!(!message.contains(sensitive_value));
        }
    }

    #[test]
    fn managed_codex_config_rejects_owned_routing_and_state_keys() {
        assert_eq!(
            CODEX_0_144_4_CONFIG_KEYS.len(),
            94,
            "the pinned Codex 0.144.4 schema contains 94 top-level keys"
        );
        assert!(
            CODEX_0_144_4_CONFIG_KEYS
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "version-scoped schema keys must remain sorted and unique"
        );
        for key in MANAGED_CODEX_FORBIDDEN_CONFIG_KEYS {
            assert!(
                CODEX_0_144_4_CONFIG_KEYS.contains(key),
                "owned key {key} must exist in the pinned schema"
            );
            let config = format!("cli_auth_credentials_store = \"file\"\n{key} = true\n");
            assert!(
                validate_managed_codex_config(config.as_bytes()).is_err(),
                "Calcifer-owned key {key} must be rejected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn managed_codex_config_read_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("oversized-managed-config");
        secure_create_dir(&root)?;
        let config = root.join("config.toml");
        write_private_file(&config, &vec![b' '; MAX_MANAGED_CODEX_CONFIG_BYTES + 1])?;

        assert!(matches!(
            verify_managed_codex_config(&config),
            Err(ProfileError::UnsafeState(_))
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn pending_registration_is_private_and_rolls_back() -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("pending-registration");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        let staging = pending.staging.clone();
        assert_eq!(
            fs::read(pending.home().join("config.toml"))?,
            b"# Managed by Calcifer.\ncli_auth_credentials_store = \"file\"\nmcp_oauth_credentials_store = \"file\"\n"
        );
        assert!(staging.is_dir());
        drop(pending);
        assert!(!staging.exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registration_adopts_a_complete_marker_after_uncertain_parent_sync()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("identity-sync-recovered");
        let registry = Registry::at_with_identity_sync_failures(root.clone(), false);
        let pending = registry.begin_codex_registration("work")?;
        let staging = pending.staging.clone();
        write_test_codex_auth(&pending.home())?;

        let profile = pending.commit(test_identity_adapter())?;

        assert!(!staging.exists());
        assert_eq!(registry.list()?, vec![profile.clone()]);
        assert!(
            registry
                .profile_directory(&profile)?
                .join(crate::provider_identity::IDENTITY_MARKER_FILE)
                .is_file()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registration_preserves_credentials_when_marker_durability_remains_uncertain()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("identity-sync-persistent-failure");
        let registry = Registry::at_with_identity_sync_failures(root.clone(), true);
        let pending = registry.begin_codex_registration("work")?;
        let staging = pending.staging.clone();
        let home = pending.home();
        write_test_codex_auth(&home)?;

        let error = pending
            .commit(test_identity_adapter())
            .err()
            .ok_or("persistent identity sync failure must stop registration")?;

        assert_eq!(error.code(), "identity_commit_uncertain");
        assert!(staging.is_dir());
        assert!(home.join("auth.json").is_file());
        assert!(
            staging
                .join(crate::provider_identity::IDENTITY_MARKER_FILE)
                .is_file()
        );
        assert!(registry.list()?.is_empty());

        let retry_registry = Registry::at(root.clone());
        let retry_error = retry_registry
            .begin_codex_registration("retry")
            .err()
            .ok_or("orphaned marker staging must block a second login")?;
        assert_eq!(retry_error.code(), "registration_recovery_required");
        assert_eq!(
            fs::read_dir(root.join("profiles/codex"))?
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(".staging-"))
                })
                .count(),
            1
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registration_adopts_a_complete_key_after_uncertain_parent_sync()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("identity-key-sync-recovered");
        let registry = Registry::at_with_identity_key_sync_failures(root.clone(), false);
        let pending = registry.begin_codex_registration("work")?;
        let staging = pending.staging.clone();
        write_test_codex_auth(&pending.home())?;

        let profile = pending.commit(test_identity_adapter())?;

        assert!(!staging.exists());
        assert_eq!(registry.list()?, vec![profile]);
        assert!(
            root.join(crate::provider_identity::IDENTITY_KEY_FILE)
                .is_file()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registration_preserves_credentials_when_key_durability_remains_uncertain()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("identity-key-sync-persistent-failure");
        let registry = Registry::at_with_identity_key_sync_failures(root.clone(), true);
        let pending = registry.begin_codex_registration("work")?;
        let staging = pending.staging.clone();
        let home = pending.home();
        write_test_codex_auth(&home)?;

        let error = pending
            .commit(test_identity_adapter())
            .err()
            .ok_or("persistent identity key sync failure must stop registration")?;

        assert_eq!(error.code(), "identity_commit_uncertain");
        assert!(staging.is_dir());
        assert!(home.join("auth.json").is_file());
        assert!(
            root.join(crate::provider_identity::IDENTITY_KEY_FILE)
                .is_file()
        );
        assert!(registry.list()?.is_empty());

        let retry_registry = Registry::at(root.clone());
        let retry_error = retry_registry
            .begin_codex_registration("retry")
            .err()
            .ok_or("orphaned key staging must block a second login")?;
        assert_eq!(retry_error.code(), "registration_recovery_required");
        assert_eq!(
            fs::read_dir(root.join("profiles/codex"))?
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(".staging-"))
                })
                .count(),
            1
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registration_rejects_duplicate_provider_identity_and_cleans_staging()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("duplicate-provider-identity");
        let registry = Registry::at(root.clone());
        let account_scope = Uuid::new_v4().to_string();

        let first = registry.begin_codex_registration("work")?;
        write_test_codex_auth_for_scope(&first.home(), &account_scope)?;
        let first_profile = first.commit(test_identity_adapter())?;

        let second = registry.begin_codex_registration("personal")?;
        write_test_codex_auth_for_scope(&second.home(), &account_scope)?;
        let second_staging = second.staging.clone();
        let error = second
            .commit(test_identity_adapter())
            .err()
            .ok_or("duplicate identity must fail")?;

        assert_eq!(error.code(), "duplicate_provider_identity");
        let message = error.safe_message();
        assert!(message.contains("codex@work"));
        assert!(message.contains("codex@personal"));
        assert!(!message.contains(&account_scope));
        assert!(!second_staging.exists());
        assert_eq!(registry.list()?, vec![first_profile]);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registration_allows_distinct_provider_scopes() -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("distinct-provider-identities");
        let registry = Registry::at(root.clone());

        for alias in ["work", "personal"] {
            let pending = registry.begin_codex_registration(alias)?;
            write_test_codex_auth(&pending.home())?;
            pending.commit(test_identity_adapter())?;
        }

        assert_eq!(registry.list()?.len(), 2);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_duplicate_registrations_publish_at_most_one_profile()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let root = temporary_root("concurrent-duplicate-registration");
        let account_scope = Uuid::new_v4().to_string();
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for alias in ["work", "personal"] {
            let worker_root = root.clone();
            let worker_scope = account_scope.clone();
            let worker_barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                worker_barrier.wait();
                let registry = Registry::at(worker_root);
                let pending = registry
                    .begin_codex_registration(alias)
                    .map_err(|error| error.code())?;
                write_test_codex_auth_for_scope(&pending.home(), &worker_scope)
                    .map_err(|error| error.code())?;
                pending
                    .commit(test_identity_adapter())
                    .map(|profile| profile.reference())
                    .map_err(|error| error.code())
            }));
        }
        barrier.wait();

        let results = workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "registration worker panicked"))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(result, Err(code) if *code == "duplicate_provider_identity")
                })
                .count(),
            1
        );

        let registry = Registry::at(root.clone());
        assert_eq!(registry.list()?.len(), 1);
        assert!(!root.join("profiles/codex").read_dir()?.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.starts_with(".staging-"))
        }));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn identity_verification_respects_an_active_profile_lease()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::{AtomicBool, Ordering};

        let root = temporary_root("verify-active-lease");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        write_test_codex_auth(&pending.home())?;
        let profile = pending.commit(test_identity_adapter())?;
        let profile_directory = registry.profile_directory(&profile)?;
        fs::remove_file(profile_directory.join(crate::provider_identity::IDENTITY_MARKER_FILE))?;
        let _active_process_lease = registry.lock_profile(&profile)?;
        let adapter_probe_ran = AtomicBool::new(false);

        let error = registry
            .verify_or_bind_codex_identity(&profile, |_| {
                adapter_probe_ran.store(true, Ordering::SeqCst);
                Ok(test_identity_adapter())
            })
            .err()
            .ok_or("verification must not enter an active profile")?;
        assert_eq!(error.code(), "profile_busy");
        assert!(!adapter_probe_ran.load(Ordering::SeqCst));
        assert!(
            !profile_directory
                .join(crate::provider_identity::IDENTITY_MARKER_FILE)
                .exists()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn legacy_verification_is_explicit_idempotent_and_detects_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("legacy-identity-verification");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        write_test_codex_auth(&pending.home())?;
        let profile = pending.commit(test_identity_adapter())?;
        let profile_directory = registry.profile_directory(&profile)?;
        fs::remove_file(profile_directory.join(crate::provider_identity::IDENTITY_MARKER_FILE))?;

        let unverified = registry
            .revalidate_codex_identity(&profile, |_| Ok(test_identity_adapter()))
            .err()
            .ok_or("legacy profile must remain unverified")?;
        assert_eq!(unverified.code(), "provider_identity_unverified");

        let first =
            registry.verify_or_bind_codex_identity(&profile, |_| Ok(test_identity_adapter()))?;
        assert_eq!(first.profile(), &profile);
        drop(first);
        let repeated =
            registry.verify_or_bind_codex_identity(&profile, |_| Ok(test_identity_adapter()))?;
        drop(repeated);

        let home = registry.profile_home(&profile)?;
        fs::remove_file(home.join("auth.json"))?;
        let changed_scope = Uuid::new_v4().to_string();
        write_test_codex_auth_for_scope(&home, &changed_scope)?;
        let error = registry
            .revalidate_codex_identity(&profile, |_| Ok(test_identity_adapter()))
            .err()
            .ok_or("changed credentials must fail closed")?;
        assert_eq!(error.code(), "provider_identity_mismatch");
        assert!(!error.safe_message().contains(&changed_scope));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn legacy_duplicate_verification_mutates_neither_profile()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("legacy-duplicate-verification");
        let registry = Registry::at(root.clone());
        let duplicate_scope = Uuid::new_v4().to_string();

        let first = registry.begin_codex_registration("work")?;
        write_test_codex_auth_for_scope(&first.home(), &duplicate_scope)?;
        let first = first.commit(test_identity_adapter())?;

        let second = registry.begin_codex_registration("personal")?;
        write_test_codex_auth(&second.home())?;
        let second = second.commit(test_identity_adapter())?;
        let second_directory = registry.profile_directory(&second)?;
        fs::remove_file(second_directory.join(crate::provider_identity::IDENTITY_MARKER_FILE))?;
        let second_home = registry.profile_home(&second)?;
        fs::remove_file(second_home.join("auth.json"))?;
        write_test_codex_auth_for_scope(&second_home, &duplicate_scope)?;

        let error = registry
            .verify_or_bind_codex_identity(&second, |_| Ok(test_identity_adapter()))
            .err()
            .ok_or("legacy duplicate must fail")?;
        assert_eq!(error.code(), "duplicate_provider_identity");
        assert!(!error.safe_message().contains(&duplicate_scope));
        assert!(registry.profile_home(&first)?.join("auth.json").is_file());
        assert!(registry.profile_home(&second)?.join("auth.json").is_file());
        assert!(
            !second_directory
                .join(crate::provider_identity::IDENTITY_MARKER_FILE)
                .exists()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn verification_detects_preexisting_duplicate_bindings()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("preexisting-duplicate-bindings");
        let registry = Registry::at(root.clone());
        let duplicate_scope = Uuid::new_v4().to_string();

        let first = registry.begin_codex_registration("work")?;
        write_test_codex_auth_for_scope(&first.home(), &duplicate_scope)?;
        let first = first.commit(test_identity_adapter())?;
        let first_directory = registry.profile_directory(&first)?;

        let second = registry.begin_codex_registration("personal")?;
        write_test_codex_auth(&second.home())?;
        let second = second.commit(test_identity_adapter())?;
        let second_directory = registry.profile_directory(&second)?;
        let marker_name = crate::provider_identity::IDENTITY_MARKER_FILE;
        fs::remove_file(second_directory.join(marker_name))?;
        write_private_file(
            &second_directory.join(marker_name),
            &fs::read(first_directory.join(marker_name))?,
        )?;
        let second_home = registry.profile_home(&second)?;
        fs::remove_file(second_home.join("auth.json"))?;
        write_test_codex_auth_for_scope(&second_home, &duplicate_scope)?;

        let error = registry
            .verify_or_bind_codex_identity(&second, |_| Ok(test_identity_adapter()))
            .err()
            .ok_or("preexisting duplicate bindings must fail")?;
        assert_eq!(error.code(), "duplicate_provider_identity");
        assert!(!error.safe_message().contains(&duplicate_scope));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_legacy_verification_publishes_at_most_one_duplicate_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let root = temporary_root("concurrent-legacy-verification");
        let registry = Registry::at(root.clone());
        let duplicate_scope = Uuid::new_v4().to_string();
        let mut profiles = Vec::new();
        for alias in ["work", "personal"] {
            let pending = registry.begin_codex_registration(alias)?;
            write_test_codex_auth(&pending.home())?;
            let profile = pending.commit(test_identity_adapter())?;
            let directory = registry.profile_directory(&profile)?;
            fs::remove_file(directory.join(crate::provider_identity::IDENTITY_MARKER_FILE))?;
            let home = registry.profile_home(&profile)?;
            fs::remove_file(home.join("auth.json"))?;
            write_test_codex_auth_for_scope(&home, &duplicate_scope)?;
            profiles.push(profile);
        }

        let barrier = Arc::new(Barrier::new(3));
        let workers = profiles
            .into_iter()
            .map(|profile| {
                let worker_root = root.clone();
                let worker_barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    worker_barrier.wait();
                    Registry::at(worker_root)
                        .verify_or_bind_codex_identity(&profile, |_| Ok(test_identity_adapter()))
                        .map(|verified| verified.profile().reference())
                        .map_err(|error| error.code())
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "verification worker panicked"))
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(result, Err(code) if *code == "duplicate_provider_identity")
                })
                .count(),
            1
        );
        let marker_count = fs::read_dir(root.join("profiles/codex"))?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .join(crate::provider_identity::IDENTITY_MARKER_FILE)
                    .is_file()
            })
            .count();
        assert_eq!(marker_count, 1);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn lost_identity_key_disables_bound_profile_revalidation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("lost-identity-key");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        write_test_codex_auth(&pending.home())?;
        let profile = pending.commit(test_identity_adapter())?;
        fs::remove_file(root.join(crate::provider_identity::IDENTITY_KEY_FILE))?;

        let error = registry
            .revalidate_codex_identity(&profile, |_| Ok(test_identity_adapter()))
            .err()
            .ok_or("missing key must fail closed")?;
        assert_eq!(error.code(), "identity_key_unavailable");
        assert!(
            !root
                .join(crate::provider_identity::IDENTITY_KEY_FILE)
                .exists()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn orphaned_binding_prevents_silent_key_recreation() -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("orphaned-binding-key-loss");
        let registry = Registry::at(root.clone());
        let first = registry.begin_codex_registration("work")?;
        write_test_codex_auth(&first.home())?;
        first.commit(test_identity_adapter())?;

        fs::remove_file(root.join(REGISTRY_FILE))?;
        let empty_registry = serde_json::to_vec_pretty(&RegistryDocument::default())?;
        write_private_file(&root.join(REGISTRY_FILE), &empty_registry)?;
        fs::remove_file(root.join(crate::provider_identity::IDENTITY_KEY_FILE))?;

        let replacement = registry.begin_codex_registration("replacement")?;
        write_test_codex_auth(&replacement.home())?;
        let error = replacement
            .commit(test_identity_adapter())
            .err()
            .ok_or("orphaned binding must block key recreation")?;
        assert_eq!(error.code(), "identity_key_unavailable");
        assert!(
            !root
                .join(crate::provider_identity::IDENTITY_KEY_FILE)
                .exists()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn published_profiles_accept_the_previous_managed_config_during_upgrade()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("legacy-config-upgrade");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        write_test_codex_auth(&pending.home())?;
        let profile = pending.commit(test_identity_adapter())?;
        let config = root
            .join("profiles")
            .join("codex")
            .join(&profile.id)
            .join("home")
            .join("config.toml");
        fs::remove_file(&config)?;
        write_private_file(
            &config,
            b"# Managed by Calcifer.\ncli_auth_credentials_store = \"file\"\n",
        )?;

        assert!(registry.profile_home(&profile).is_ok());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registration_requires_a_private_auth_file() -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("missing-auth");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        let result = pending.commit(test_identity_adapter());
        assert!(matches!(result, Err(ProfileError::UnsafeState(_))));
        assert!(registry.list()?.is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registration_revalidates_complete_home_before_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("registration-home-revalidation");
        let registry = Registry::at(root.clone());

        let pending = registry.begin_codex_registration("work")?;
        write_test_codex_auth(&pending.home())?;
        fs::write(
            pending.home().join("config.toml"),
            b"cli_auth_credentials_store = \"file\"\n[agents.reviewer]\ndescription = \"synthetic\"\n",
        )?;
        let role_error = match pending.commit(test_identity_adapter()) {
            Err(error) => error,
            Ok(_) => panic!("registration published a role config"),
        };
        assert_eq!(role_error.code(), "unsafe_profile_state");
        assert!(!role_error.safe_message().contains("agents"));
        assert!(registry.list()?.is_empty());

        let pending = registry.begin_codex_registration("work")?;
        write_test_codex_auth(&pending.home())?;
        fs::create_dir(pending.home().join("agents"))?;
        let node_error = match pending.commit(test_identity_adapter()) {
            Err(error) => error,
            Ok(_) => panic!("registration published an auto-discovered agents node"),
        };
        assert_eq!(node_error.code(), "unsafe_profile_state");
        assert!(!node_error.safe_message().contains("agents"));
        assert!(registry.list()?.is_empty());

        let provider_root = root.join("profiles").join("codex");
        assert!(std::fs::read_dir(provider_root)?.next().is_none());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn published_profiles_revalidate_config_and_auth_before_use()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = temporary_root("profile-revalidation");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        write_test_codex_auth(&pending.home())?;
        let profile = pending.commit(test_identity_adapter())?;
        let home = root
            .join("profiles")
            .join("codex")
            .join(&profile.id)
            .join("home");
        let config = home.join("config.toml");
        let auth = home.join("auth.json");

        fs::remove_file(&config)?;
        symlink(&auth, &config)?;
        assert!(matches!(
            registry.profile_home(&profile),
            Err(ProfileError::UnsafeState(_))
        ));

        fs::remove_file(&config)?;
        write_private_file(
            &config,
            b"# Managed by Calcifer.\ncli_auth_credentials_store = \"file\"\n",
        )?;
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644))?;
        assert!(matches!(
            registry.profile_home(&profile),
            Err(ProfileError::UnsafeState(_))
        ));

        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
        fs::remove_file(&auth)?;
        assert!(matches!(
            registry.profile_home(&profile),
            Err(ProfileError::UnsafeState(_))
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn published_profiles_reject_every_auto_discovered_agents_node()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = temporary_root("profile-agents-revalidation");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        write_test_codex_auth(&pending.home())?;
        let profile = pending.commit(test_identity_adapter())?;
        let home = root
            .join("profiles")
            .join("codex")
            .join(&profile.id)
            .join("home");
        let agents = home.join("agents");
        let auth = home.join("auth.json");

        fs::create_dir(&agents)?;
        let directory_error = match registry.profile_home(&profile) {
            Err(error) => error,
            Ok(_) => panic!("an agents directory must fail closed"),
        };
        fs::remove_dir(&agents)?;

        write_private_file(&agents, b"synthetic test-only role")?;
        let file_error = match registry.profile_home(&profile) {
            Err(error) => error,
            Ok(_) => panic!("an agents file must fail closed"),
        };
        fs::remove_file(&agents)?;

        symlink(&auth, &agents)?;
        let symlink_error = match registry.profile_home(&profile) {
            Err(error) => error,
            Ok(_) => panic!("an agents symlink must fail closed"),
        };
        fs::remove_file(&agents)?;

        for error in [directory_error, file_error, symlink_error] {
            assert_eq!(error.code(), "unsafe_profile_state");
            let message = error.safe_message();
            assert!(!message.contains("agents"));
            assert!(!message.contains(&home.display().to_string()));
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registry_sync_failure_preserves_visible_profile_and_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("registry-sync-failure");
        let registry = Registry::at_with_registry_sync_failure(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        write_test_codex_auth(&pending.home())?;

        let result = pending.commit(test_identity_adapter());
        assert!(matches!(
            result,
            Err(ProfileError::RegistryCommitUncertain(_))
        ));
        let profiles = registry.list()?;
        assert_eq!(profiles.len(), 1);
        assert!(
            registry
                .profile_home(&profiles[0])?
                .join("auth.json")
                .is_file()
        );
        assert!(!root.join("profiles/codex").read_dir()?.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.starts_with(".staging-"))
        }));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rename_changes_only_alias_and_same_alias_is_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt;

        let root = temporary_root("rename-alias-only");
        let registry = Registry::at(root.clone());
        let original = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&original)?;
        let inode = fs::metadata(&profile_directory)?.ino();
        let marker = fs::read(profile_directory.join(OWNER_MARKER))?;
        let home_entries = fs::read_dir(profile_directory.join("home"))?
            .map(|entry| {
                let entry = entry?;
                Ok((entry.file_name(), fs::read(entry.path())?))
            })
            .collect::<io::Result<Vec<_>>>()?;

        let (renamed, changed) = registry.rename(Provider::Codex, "work", "client-a")?;
        assert!(changed);
        assert_eq!(renamed.id, original.id);
        assert_eq!(renamed.provider, original.provider);
        assert_eq!(renamed.created_at, original.created_at);
        assert_eq!(renamed.alias, "client-a");
        assert_eq!(fs::metadata(&profile_directory)?.ino(), inode);
        assert_eq!(fs::read(profile_directory.join(OWNER_MARKER))?, marker);
        assert_eq!(
            fs::read_dir(profile_directory.join("home"))?
                .map(|entry| {
                    let entry = entry?;
                    Ok((entry.file_name(), fs::read(entry.path())?))
                })
                .collect::<io::Result<Vec<_>>>()?,
            home_entries
        );
        assert!(matches!(
            registry.find(Provider::Codex, "work"),
            Err(ProfileError::NotFound(_))
        ));
        assert_eq!(registry.find(Provider::Codex, "client-a")?.id, original.id);

        let registry_before = fs::read(root.join(REGISTRY_FILE))?;
        let (unchanged, changed) = registry.rename(Provider::Codex, "client-a", "client-a")?;
        assert!(!changed);
        assert_eq!(unchanged, renamed);
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn profile_lease_revalidates_alias_after_a_completed_rename()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("profile-lease-alias-revalidation");
        let registry = Registry::at(root.clone());
        let stale = register_test_profile(&registry, "work")?;

        registry.rename(Provider::Codex, "work", "client-a")?;

        let error = registry
            .lock_profile_current(&stale, Some("work"))
            .err()
            .ok_or("an explicit stale alias must not acquire a status lease")?;
        assert_eq!(error.code(), "profile_not_found");

        let (current, _lease) = registry.lock_profile_current(&stale, None)?;
        assert_eq!(current.id, stale.id);
        assert_eq!(current.alias, "client-a");

        drop(_lease);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rename_does_not_inspect_provider_or_conversation_state()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = temporary_root("rename-does-not-read-provider-state");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let home = profile_directory.join("home");
        let private_sentinel = root.join("synthetic-private-sentinel");
        write_private_file(&private_sentinel, b"must-not-be-read")?;
        for name in ["auth.json", "config.toml"] {
            fs::remove_file(home.join(name))?;
            symlink(&private_sentinel, home.join(name))?;
        }
        let session = home.join("sessions.jsonl");
        symlink(&private_sentinel, &session)?;
        let identity = profile_directory.join(".calcifer-provider-identity");
        symlink(&private_sentinel, &identity)?;

        let (renamed, changed) = registry.rename(Provider::Codex, "work", "client-a")?;
        assert!(changed);
        assert_eq!(renamed.id, profile.id);
        for path in [
            home.join("auth.json"),
            home.join("config.toml"),
            session,
            identity,
        ] {
            assert!(fs::symlink_metadata(&path)?.file_type().is_symlink());
            assert_eq!(fs::read_link(path)?, private_sentinel);
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rename_rejects_invalid_duplicate_and_missing_aliases_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("rename-invalid-inputs");
        let registry = Registry::at(root.clone());
        register_test_profile(&registry, "work")?;
        register_test_profile(&registry, "personal")?;
        let before = fs::read(root.join(REGISTRY_FILE))?;

        let cases = [
            (
                registry.rename(Provider::Codex, "work", "../private-sentinel"),
                "invalid_profile_alias",
            ),
            (
                registry.rename(Provider::Codex, "work", "personal"),
                "profile_already_exists",
            ),
            (
                registry.rename(Provider::Codex, "missing", "client-a"),
                "profile_not_found",
            ),
        ];
        for (result, expected_code) in cases {
            let error = result.err().ok_or("rename should fail")?;
            assert_eq!(error.code(), expected_code);
            assert!(!error.safe_message().contains("private-sentinel"));
            assert_eq!(fs::read(root.join(REGISTRY_FILE))?, before);
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rename_rejects_corrupt_registry_and_unsafe_profile_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let corrupt_root = temporary_root("rename-corrupt-registry");
        let corrupt_registry = Registry::at(corrupt_root.clone());
        register_test_profile(&corrupt_registry, "work")?;
        let corrupt_bytes = b"{synthetic-private-sentinel";
        fs::write(corrupt_root.join(REGISTRY_FILE), corrupt_bytes)?;
        let error = corrupt_registry
            .rename(Provider::Codex, "work", "client-a")
            .err()
            .ok_or("corrupt registry must fail")?;
        assert_eq!(error.code(), "invalid_registry");
        assert!(!error.safe_message().contains("synthetic-private-sentinel"));
        assert_eq!(fs::read(corrupt_root.join(REGISTRY_FILE))?, corrupt_bytes);
        fs::remove_dir_all(corrupt_root)?;

        let oversized_root = temporary_root("rename-oversized-registry");
        let oversized_registry = Registry::at(oversized_root.clone());
        register_test_profile(&oversized_registry, "work")?;
        let oversized = vec![b' '; MAX_REGISTRY_BYTES + 1];
        fs::write(oversized_root.join(REGISTRY_FILE), &oversized)?;
        let error = oversized_registry
            .rename(Provider::Codex, "work", "client-a")
            .err()
            .ok_or("oversized registry must fail")?;
        assert_eq!(error.code(), "invalid_registry");
        assert_eq!(
            fs::metadata(oversized_root.join(REGISTRY_FILE))?.len(),
            oversized.len() as u64
        );
        fs::remove_dir_all(oversized_root)?;

        let unsafe_root = temporary_root("rename-unsafe-profile");
        let unsafe_registry = Registry::at(unsafe_root.clone());
        let profile = register_test_profile(&unsafe_registry, "work")?;
        let profile_directory = unsafe_registry.profile_directory(&profile)?;
        let before = fs::read(unsafe_root.join(REGISTRY_FILE))?;
        fs::write(
            profile_directory.join(OWNER_MARKER),
            b"synthetic-private-sentinel",
        )?;
        let error = unsafe_registry
            .rename(Provider::Codex, "work", "client-a")
            .err()
            .ok_or("unsafe profile must fail")?;
        assert_eq!(error.code(), "unsafe_profile_state");
        assert!(!error.safe_message().contains("synthetic-private-sentinel"));
        assert_eq!(fs::read(unsafe_root.join(REGISTRY_FILE))?, before);
        fs::remove_dir_all(unsafe_root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rename_respects_coordinator_guardian_and_status_leases()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("rename-active-leases");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let before = fs::read(root.join(REGISTRY_FILE))?;

        let coordinator = open_private_lock_file(&profile_directory.join(COORDINATOR_LOCK_FILE))?;
        FileExt::lock_exclusive(&coordinator)?;
        let error = registry
            .rename(Provider::Codex, "work", "coordinator-blocked")
            .err()
            .ok_or("coordinator lease must block rename")?;
        assert_eq!(error.code(), "profile_busy");
        FileExt::unlock(&coordinator)?;

        let provider = open_private_lock_file(&profile_directory.join(PROVIDER_LOCK_FILE))?;
        FileExt::lock_exclusive(&provider)?;
        let error = registry
            .rename(Provider::Codex, "work", "guardian-blocked")
            .err()
            .ok_or("guardian lease must block rename")?;
        assert_eq!(error.code(), "profile_busy");
        FileExt::unlock(&provider)?;

        let status_lease = registry.lock_profile(&profile)?;
        let error = registry
            .rename(Provider::Codex, "work", "status-blocked")
            .err()
            .ok_or("status lease must block rename")?;
        assert_eq!(error.code(), "profile_busy");
        drop(status_lease);

        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, before);
        assert_eq!(registry.find(Provider::Codex, "work")?, profile);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_renames_do_not_lose_updates_or_create_duplicates()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let root = temporary_root("concurrent-renames");
        let registry = Registry::at(root.clone());
        register_test_profile(&registry, "work")?;
        register_test_profile(&registry, "personal")?;

        let barrier = Arc::new(Barrier::new(3));
        let workers = ["client-a", "client-b"]
            .into_iter()
            .map(|new_alias| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    Registry::at(root)
                        .rename(Provider::Codex, "work", new_alias)
                        .map(|(profile, _)| profile.alias)
                        .map_err(|error| error.code())
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "rename worker panicked"))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(registry.list()?.len(), 2);

        let current_work_alias = results
            .iter()
            .find_map(|result| result.as_ref().ok())
            .ok_or("one rename must succeed")?
            .clone();
        let barrier = Arc::new(Barrier::new(3));
        let source_aliases = [current_work_alias, "personal".to_owned()];
        let workers = source_aliases
            .into_iter()
            .map(|old_alias| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    Registry::at(root)
                        .rename(Provider::Codex, &old_alias, "shared")
                        .map(|_| ())
                        .map_err(|error| error.code())
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "rename worker panicked"))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let profiles = registry.list()?;
        assert_eq!(profiles.len(), 2);
        assert_eq!(
            profiles
                .iter()
                .filter(|profile| profile.alias == "shared")
                .count(),
            1
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rename_faults_before_visibility_preserve_old_registry_and_sync_failure_is_uncertain()
    -> Result<(), Box<dyn std::error::Error>> {
        for fault in [
            RegistryWriteStep::TemporaryCreate,
            RegistryWriteStep::Write,
            RegistryWriteStep::FileSync,
            RegistryWriteStep::AtomicRename,
        ] {
            let root = temporary_root("rename-previsibility-fault");
            let registry = Registry::at(root.clone());
            register_test_profile(&registry, "work")?;
            let before = fs::read(root.join(REGISTRY_FILE))?;
            let faulting = Registry::at_with_registry_write_fault(root.clone(), fault);

            let error = faulting
                .rename(Provider::Codex, "work", "client-a")
                .err()
                .ok_or("fault injection must fail")?;
            assert_eq!(error.code(), "io_error");
            assert_eq!(fs::read(root.join(REGISTRY_FILE))?, before);
            assert!(registry.find(Provider::Codex, "work").is_ok());
            assert!(matches!(
                registry.find(Provider::Codex, "client-a"),
                Err(ProfileError::NotFound(_))
            ));
            assert!(!fs::read_dir(&root)?.any(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().into_string().ok())
                    .is_some_and(|name| name.starts_with(".profiles.json."))
            }));
            fs::remove_dir_all(root)?;
        }

        let root = temporary_root("rename-directory-sync-fault");
        let registry = Registry::at(root.clone());
        let original = register_test_profile(&registry, "work")?;
        let faulting =
            Registry::at_with_registry_write_fault(root.clone(), RegistryWriteStep::DirectorySync);
        let error = faulting
            .rename(Provider::Codex, "work", "client-a")
            .err()
            .ok_or("directory sync fault must be uncertain")?;
        assert_eq!(error.code(), "registry_commit_uncertain");
        assert!(error.safe_message().contains("auth list"));
        assert!(matches!(
            registry.find(Provider::Codex, "work"),
            Err(ProfileError::NotFound(_))
        ));
        assert_eq!(registry.find(Provider::Codex, "client-a")?.id, original.id);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_crash_boundaries_recover_to_one_complete_state()
    -> Result<(), Box<dyn std::error::Error>> {
        for fault in [
            RemovalFault::JournalTemporaryCreate,
            RemovalFault::JournalWrite,
            RemovalFault::JournalFileSync,
            RemovalFault::JournalAtomicRename,
            RemovalFault::JournalDirectorySync,
            RemovalFault::TombstoneRename,
            RemovalFault::ProviderRootSyncAfterRename,
            RemovalFault::RegistryTemporaryCreate,
            RemovalFault::RegistryWrite,
            RemovalFault::RegistryFileSync,
            RemovalFault::RegistryAtomicRename,
            RemovalFault::RegistryDirectorySync,
            RemovalFault::RecursiveCleanup,
            RemovalFault::ProviderRootSyncAfterCleanup,
            RemovalFault::JournalRemove,
            RemovalFault::JournalRemoveDirectorySync,
        ] {
            let root = temporary_root("removal-crash-boundary");
            let registry = Registry::at(root.clone());
            let profile = register_test_profile(&registry, "work")?;
            let identity_key = fs::read(root.join(crate::provider_identity::IDENTITY_KEY_FILE))?;
            let faulting = Registry::at_with_removal_fault(root.clone(), fault);

            let _ = faulting.remove(Provider::Codex, "work", None);
            Registry::at(root.clone()).recover_incomplete_removal()?;

            let profiles = Registry::at(root.clone()).list()?;
            let removal_was_visible = matches!(
                fault,
                RemovalFault::RegistryDirectorySync
                    | RemovalFault::RecursiveCleanup
                    | RemovalFault::ProviderRootSyncAfterCleanup
                    | RemovalFault::JournalRemove
                    | RemovalFault::JournalRemoveDirectorySync
            );
            if removal_was_visible {
                assert!(profiles.is_empty(), "{fault:?} must converge to removed");
            } else {
                assert_eq!(
                    profiles,
                    vec![profile.clone()],
                    "{fault:?} must converge to the complete old profile"
                );
            }
            assert_eq!(
                fs::read(root.join(crate::provider_identity::IDENTITY_KEY_FILE))?,
                identity_key
            );
            let provider_root = root.join("profiles/codex");
            assert!(!fs::read_dir(&provider_root)?.any(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().into_string().ok())
                    .is_some_and(|name| name.starts_with(".removing-"))
            }));
            assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
            if profiles.is_empty() {
                assert!(!provider_root.join(&profile.id).exists());
            } else {
                assert!(provider_root.join(&profile.id).is_dir());
            }
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_recovery_cannot_finalize_a_journal_during_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let root = temporary_root("remove-concurrent-finalization");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let (reached_tx, reached_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let worker_root = root.clone();
        let worker = thread::spawn(move || {
            Registry::at_with_removal_pause(worker_root, reached_tx, resume_rx)
                .remove(Provider::Codex, "work", None)
                .map_err(|error| error.code())
        });

        reached_rx.recv_timeout(Duration::from_secs(5))?;
        let competing_lock = open_private_lock_file(&root.join(REMOVAL_LOCK_FILE))?;
        let lock_error = FileExt::try_lock_exclusive(&competing_lock)
            .err()
            .ok_or("cleanup must retain the removal lock through journal finalization")?;
        assert_eq!(lock_error.kind(), io::ErrorKind::WouldBlock);
        drop(competing_lock);
        let competing_registry_lock = open_private_lock_file(&root.join(LOCK_FILE))?;
        let registry_lock_error = FileExt::try_lock_exclusive(&competing_registry_lock)
            .err()
            .ok_or("cleanup must retain the registry lock through journal finalization")?;
        assert_eq!(registry_lock_error.kind(), io::ErrorKind::WouldBlock);
        drop(competing_registry_lock);

        let (recovery_started_tx, recovery_started_rx) = mpsc::channel();
        let recovery_root = root.clone();
        let recovery = thread::spawn(move || {
            recovery_started_tx
                .send(())
                .map_err(|_| "recovery observer disconnected")?;
            Registry::at(recovery_root)
                .recover_incomplete_removal()
                .map_err(|error| error.code())
        });
        recovery_started_rx.recv_timeout(Duration::from_secs(5))?;
        resume_tx.send(())?;
        let removed = worker.join().map_err(|_| "removal worker panicked")?;
        let recovered = recovery.join().map_err(|_| "recovery worker panicked")?;

        assert_eq!(removed, Ok(profile.clone()));
        assert_eq!(recovered, Ok(()));
        assert!(registry.list()?.is_empty());
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
        assert!(!registry.profile_path(&profile)?.exists());
        assert!(registry.removal_tombstones()?.is_empty());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registry_mutators_recheck_removal_artifacts_after_a_stale_preflight()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        for operation in ["rename", "register"] {
            let root = temporary_root("remove-stale-mutator-preflight");
            let registry = Registry::at(root.clone());
            register_test_profile(&registry, "work")?;
            register_test_profile(&registry, "personal")?;
            let registry_before = fs::read(root.join(REGISTRY_FILE))?;
            let (reached_tx, reached_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let waiter_root = root.clone();
            let waiter = thread::spawn(move || -> Result<(), &'static str> {
                let waiting_registry =
                    Registry::at_with_registry_mutation_pause(waiter_root, reached_tx, resume_rx);
                match operation {
                    "rename" => waiting_registry
                        .rename(Provider::Codex, "personal", "client")
                        .map(|_| ())
                        .map_err(|error| error.code()),
                    "register" => {
                        let pending = waiting_registry
                            .begin_codex_registration("client")
                            .map_err(|error| error.code())?;
                        write_test_codex_auth(&pending.home()).map_err(|error| error.code())?;
                        pending
                            .commit(test_identity_adapter())
                            .map(|_| ())
                            .map_err(|error| error.code())
                    }
                    _ => Err("invalid test operation"),
                }
            });

            reached_rx.recv_timeout(Duration::from_secs(5))?;
            let faulting = Registry::at_with_removal_fault(
                root.clone(),
                RemovalFault::ProviderRootSyncAfterRename,
            );
            assert!(faulting.remove(Provider::Codex, "work", None).is_err());
            assert!(root.join(REMOVAL_JOURNAL_FILE).is_file());
            resume_tx.send(())?;
            let waiter_result = waiter.join().map_err(|_| "registry mutator panicked")?;

            assert_eq!(
                waiter_result,
                Err("removal_recovery_required"),
                "{operation} must reject artifacts that appeared after preflight"
            );
            assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);

            registry.recover_incomplete_removal()?;
            let profiles = registry.list()?;
            assert_eq!(profiles.len(), 2);
            assert!(profiles.iter().any(|profile| profile.alias == "work"));
            assert!(profiles.iter().any(|profile| profile.alias == "personal"));
            assert!(!profiles.iter().any(|profile| profile.alias == "client"));
            assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
            assert!(!fs::read_dir(root.join("profiles/codex"))?.any(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().into_string().ok())
                    .is_some_and(|name| name.starts_with(".staging-"))
            }));

            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_rejects_active_split_leases_without_preparing_a_transaction()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("remove-active-leases");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let registry_before = fs::read(root.join(REGISTRY_FILE))?;

        for lock_name in [COORDINATOR_LOCK_FILE, PROVIDER_LOCK_FILE] {
            let lock = open_private_lock_file(&profile_directory.join(lock_name))?;
            FileExt::lock_exclusive(&lock)?;
            let error = registry
                .remove(Provider::Codex, "work", None)
                .err()
                .ok_or("active lease must block removal")?;
            assert_eq!(error.code(), "profile_busy");
            assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);
            assert!(profile_directory.is_dir());
            assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
            FileExt::unlock(&lock)?;
        }

        let status_lease = registry.lock_profile(&profile)?;
        let error = registry
            .remove(Provider::Codex, "work", None)
            .err()
            .ok_or("combined status/verification lease must block removal")?;
        assert_eq!(error.code(), "profile_busy");
        drop(status_lease);
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);
        assert!(profile_directory.is_dir());
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_rejects_symlink_hard_link_mode_and_marker_attacks_before_journaling()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        for attack in ["symlink", "hard-link", "mode", "marker"] {
            let root = temporary_root("remove-owned-tree-attack");
            let registry = Registry::at(root.clone());
            let profile = register_test_profile(&registry, "work")?;
            let profile_directory = registry.profile_directory(&profile)?;
            let auth = profile_directory.join("home/auth.json");
            let outside = root
                .parent()
                .ok_or("temporary root must have a parent")?
                .join(format!("calcifer-removal-outside-{}", Uuid::new_v4()));
            write_private_file(&outside, b"synthetic-outside-private-sentinel")?;
            match attack {
                "symlink" => {
                    let session = profile_directory.join("home/sessions.jsonl");
                    symlink(&outside, session)?;
                }
                "hard-link" => {
                    fs::remove_file(&auth)?;
                    fs::hard_link(&outside, &auth)?;
                }
                "mode" => {
                    fs::set_permissions(&auth, fs::Permissions::from_mode(0o644))?;
                }
                "marker" => {
                    fs::write(profile_directory.join(OWNER_MARKER), b"wrong-local-id")?;
                }
                _ => return Err("unknown attack".into()),
            }
            let registry_before = fs::read(root.join(REGISTRY_FILE))?;

            let error = registry
                .remove(Provider::Codex, "work", None)
                .err()
                .ok_or("unsafe tree must block removal")?;
            assert_eq!(error.code(), "unsafe_profile_state", "{attack}");
            assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);
            assert!(profile_directory.exists());
            assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
            assert_eq!(
                fs::read(&outside)?,
                b"synthetic-outside-private-sentinel",
                "{attack} must not touch an outside inode"
            );

            fs::remove_dir_all(root)?;
            fs::remove_file(outside)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_recovery_rejects_root_replacement_and_orphan_tombstones()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, symlink};

        let root = temporary_root("remove-root-replacement");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let faulting = Registry::at_with_removal_fault(
            root.clone(),
            RemovalFault::ProviderRootSyncAfterRename,
        );
        assert!(faulting.remove(Provider::Codex, "work", None).is_err());
        let profiles_root = root.join("profiles");
        let provider_root = profiles_root.join("codex");
        let displaced = profiles_root.join("codex-displaced");
        fs::rename(&provider_root, &displaced)?;
        fs::DirBuilder::new().mode(0o700).create(&provider_root)?;
        let tombstone_name = format!(".removing-{}", profile.id);
        fs::rename(
            displaced.join(&tombstone_name),
            provider_root.join(&tombstone_name),
        )?;

        let error = registry
            .recover_incomplete_removal()
            .err()
            .ok_or("provider-root replacement must fail recovery")?;
        assert_eq!(error.code(), "removal_recovery_required");
        assert!(provider_root.join(&tombstone_name).is_dir());
        assert!(root.join(REMOVAL_JOURNAL_FILE).is_file());
        fs::remove_dir_all(root)?;

        let orphan_root = temporary_root("remove-orphan-tombstone");
        let orphan_registry = Registry::at(orphan_root.clone());
        let orphan_profile = register_test_profile(&orphan_registry, "work")?;
        let outside = orphan_root
            .parent()
            .ok_or("temporary root must have a parent")?
            .join(format!("calcifer-removal-outside-dir-{}", Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&outside)?;
        write_private_file(&outside.join("sentinel"), b"outside-must-survive")?;
        let orphan = orphan_root
            .join("profiles/codex")
            .join(format!(".removing-{}", orphan_profile.id));
        symlink(&outside, &orphan)?;
        let error = orphan_registry
            .recover_incomplete_removal()
            .err()
            .ok_or("journal-free tombstone must fail closed")?;
        assert_eq!(error.code(), "removal_recovery_required");
        assert_eq!(fs::read(outside.join("sentinel"))?, b"outside-must-survive");
        fs::remove_file(orphan)?;
        fs::remove_dir_all(orphan_root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_recovery_rejects_duplicate_tombstones_without_deleting_either()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::DirBuilderExt;

        let root = temporary_root("remove-duplicate-tombstones");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let provider_root = root.join("profiles/codex");
        let first = provider_root.join(format!(".removing-{}", Uuid::new_v4()));
        let second = provider_root.join(format!(".removing-{}", Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&first)?;
        fs::DirBuilder::new().mode(0o700).create(&second)?;
        let registry_before = fs::read(root.join(REGISTRY_FILE))?;

        let error = registry
            .recover_incomplete_removal()
            .err()
            .ok_or("duplicate tombstones must fail closed")?;

        assert_eq!(error.code(), "removal_recovery_required");
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);
        assert_eq!(
            registry.find_without_recovery(Provider::Codex, "work")?,
            profile
        );
        assert!(first.is_dir());
        assert!(second.is_dir());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn post_visibility_recovery_finishes_a_partially_unlinked_tombstone_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("remove-partial-cleanup");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let faulting =
            Registry::at_with_removal_fault(root.clone(), RemovalFault::RecursiveCleanup);
        assert!(faulting.remove(Provider::Codex, "work", None).is_err());
        let tombstone = root
            .join("profiles/codex")
            .join(format!(".removing-{}", profile.id));
        for file in [
            OWNER_MARKER,
            COORDINATOR_LOCK_FILE,
            PROVIDER_LOCK_FILE,
            crate::provider_identity::IDENTITY_MARKER_FILE,
        ] {
            fs::remove_file(tombstone.join(file))?;
        }
        fs::remove_file(tombstone.join("home/auth.json"))?;

        Registry::at(root.clone()).recover_incomplete_removal()?;

        assert!(!tombstone.exists());
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
        assert!(Registry::at(root.clone()).list()?.is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn pre_visibility_recovery_never_restores_a_partially_deleted_profile()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("remove-partial-previsibility");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let faulting = Registry::at_with_removal_fault(
            root.clone(),
            RemovalFault::ProviderRootSyncAfterRename,
        );
        assert!(faulting.remove(Provider::Codex, "work", None).is_err());
        let tombstone = root
            .join("profiles/codex")
            .join(format!(".removing-{}", profile.id));
        fs::remove_file(tombstone.join(OWNER_MARKER))?;

        let error = Registry::at(root.clone())
            .recover_incomplete_removal()
            .err()
            .ok_or("incomplete pre-visibility credentials must not be restored")?;
        assert_eq!(error.code(), "removal_recovery_required");
        assert!(tombstone.is_dir());
        assert!(root.join(REMOVAL_JOURNAL_FILE).is_file());
        assert_eq!(
            registry.list().err().map(|error| error.code()),
            Some("removal_recovery_required")
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn pre_visibility_recovery_rejects_a_tree_missing_credentials_even_with_its_owner_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("remove-partial-credentials-previsibility");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let faulting = Registry::at_with_removal_fault(
            root.clone(),
            RemovalFault::ProviderRootSyncAfterRename,
        );
        assert!(faulting.remove(Provider::Codex, "work", None).is_err());
        let tombstone = root
            .join("profiles/codex")
            .join(format!(".removing-{}", profile.id));
        fs::remove_file(tombstone.join("home/auth.json"))?;

        let error = Registry::at(root.clone())
            .recover_incomplete_removal()
            .err()
            .ok_or("a pre-visibility tree missing credentials must not be restored")?;

        assert_eq!(error.code(), "removal_recovery_required");
        assert!(tombstone.is_dir());
        assert!(tombstone.join(OWNER_MARKER).is_file());
        assert!(root.join(REMOVAL_JOURNAL_FILE).is_file());
        assert_eq!(
            registry.list().err().map(|error| error.code()),
            Some("removal_recovery_required")
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn confirmed_removal_never_follows_an_alias_to_a_replacement_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("remove-confirmed-id-race");
        let registry = Registry::at(root.clone());
        let confirmed = register_test_profile(&registry, "work")?;

        registry.rename(Provider::Codex, "work", "former-work")?;
        let replacement = register_test_profile(&registry, "work")?;
        let registry_before = fs::read(root.join(REGISTRY_FILE))?;

        let error = registry
            .remove(Provider::Codex, "work", Some(&confirmed.id))
            .err()
            .ok_or("alias reuse after confirmation must not remove its replacement")?;

        assert_eq!(error.code(), "profile_not_found");
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);
        assert_eq!(
            registry.find(Provider::Codex, "former-work")?.id,
            confirmed.id
        );
        assert_eq!(registry.find(Provider::Codex, "work")?.id, replacement.id);
        assert!(registry.profile_directory(&confirmed)?.is_dir());
        assert!(registry.profile_directory(&replacement)?.is_dir());
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removed_alias_reuse_gets_a_fresh_id_without_rebinding_lineage()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt;

        let root = temporary_root("remove-alias-reuse-lineage");
        let registry = Registry::at(root.clone());
        let removed = register_test_profile(&registry, "work")?;
        let conversation = root.join("conversations.json");
        write_private_file(
            &conversation,
            format!(
                "{{\"schema_version\":1,\"profile_id\":\"{}\",\"sentinel\":\"private-lineage\"}}",
                removed.id
            )
            .as_bytes(),
        )?;
        let lineage_inode = fs::metadata(&conversation)?.ino();
        let lineage = fs::read(&conversation)?;
        let identity_key = fs::read(root.join(crate::provider_identity::IDENTITY_KEY_FILE))?;

        assert_eq!(registry.remove(Provider::Codex, "work", None)?, removed);
        let replacement = register_test_profile(&registry, "work")?;

        assert_ne!(replacement.id, removed.id);
        assert_eq!(replacement.alias, removed.alias);
        assert_eq!(fs::metadata(&conversation)?.ino(), lineage_inode);
        assert_eq!(fs::read(&conversation)?, lineage);
        assert_eq!(
            fs::read(root.join(crate::provider_identity::IDENTITY_KEY_FILE))?,
            identity_key
        );
        assert!(matches!(
            registry.find_by_id(Provider::Codex, &removed.id),
            Err(ProfileError::NotFound(_))
        ));
        assert_eq!(registry.find(Provider::Codex, "work")?.id, replacement.id);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn malformed_removal_journal_is_bounded_redacted_and_non_destructive()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("remove-malformed-journal");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let private = "synthetic-private-journal@example.invalid";
        write_private_file(
            &root.join(REMOVAL_JOURNAL_FILE),
            format!("{{\"secret\":\"{private}\"}}").as_bytes(),
        )?;
        let registry_before = fs::read(root.join(REGISTRY_FILE))?;

        let error = registry
            .recover_incomplete_removal()
            .err()
            .ok_or("malformed journal must fail closed")?;
        assert_eq!(error.code(), "removal_recovery_required");
        assert!(!error.safe_message().contains(private));
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);
        assert!(profile_directory.is_dir());
        assert!(root.join(REMOVAL_JOURNAL_FILE).is_file());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn registration_rejects_symlinked_managed_parent() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, symlink};

        let root = temporary_root("symlinked-parent");
        let outside = temporary_root("symlinked-parent-outside");
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        fs::DirBuilder::new().mode(0o700).create(&outside)?;
        symlink(&outside, root.join("profiles"))?;
        let registry = Registry::at(root.clone());

        assert!(matches!(
            registry.begin_codex_registration("work"),
            Err(ProfileError::UnsafeState(_))
        ));

        fs::remove_file(root.join("profiles"))?;
        fs::remove_dir_all(root)?;
        fs::remove_dir(outside)?;
        Ok(())
    }
}
