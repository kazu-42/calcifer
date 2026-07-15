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
const REMOVAL_REGISTRY_BARRIER_SCHEMA_VERSION: u8 = 2;
const MAX_REMOVAL_JOURNAL_BYTES: usize = 16 * 1024;
const MAX_REMOVAL_REGISTRY_BARRIER_BYTES: usize = 2 * 1024 * 1024;
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
    profiles: Vec<Profile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RemovalRegistryBarrier {
    schema_version: u8,
    removal: RemovalJournal,
    expected_registry: RegistryDocument,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RegistryState {
    Stable(RegistryDocument),
    RemovalBarrier(Box<RemovalRegistryBarrier>),
}

#[derive(Deserialize)]
struct RegistrySchemaHeader {
    schema_version: u8,
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
    BarrierTemporaryCreate,
    BarrierWrite,
    BarrierFileSync,
    BarrierAtomicRename,
    BarrierDirectorySync,
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

#[derive(Clone, Eq, PartialEq)]
struct RemovalMountIdentity {
    token: Vec<u8>,
}

impl fmt::Debug for RemovalMountIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemovalMountIdentity(<redacted>)")
    }
}

#[derive(Debug)]
struct RemovalTraversalBudget {
    remaining_entries: usize,
    consumed_entries: usize,
    max_depth: usize,
}

impl RemovalTraversalBudget {
    const fn new(max_entries: usize, max_depth: usize) -> Self {
        Self {
            remaining_entries: max_entries,
            consumed_entries: 0,
            max_depth,
        }
    }

    fn consume_entry(&mut self) -> Result<(), ProfileError> {
        self.remaining_entries = self.remaining_entries.checked_sub(1).ok_or_else(|| {
            ProfileError::UnsafeState("managed profile tree is too large".to_owned())
        })?;
        self.consumed_entries = self.consumed_entries.checked_add(1).ok_or_else(|| {
            ProfileError::UnsafeState("managed profile tree is too large".to_owned())
        })?;
        Ok(())
    }

    fn child_depth(&self, parent_depth: usize) -> Result<usize, ProfileError> {
        let child_depth = parent_depth.checked_add(1).ok_or_else(|| {
            ProfileError::UnsafeState("managed profile tree is too deep".to_owned())
        })?;
        if child_depth > self.max_depth {
            return Err(ProfileError::UnsafeState(
                "managed profile tree is too deep".to_owned(),
            ));
        }
        Ok(child_depth)
    }
}

fn try_reserve_removal_slot<T>(values: &mut Vec<T>) -> Result<(), ProfileError> {
    values.try_reserve(1).map_err(|_| {
        ProfileError::UnsafeState("managed profile tree exceeds safe allocation limits".to_owned())
    })
}

#[cfg(unix)]
const fn removal_descendant_mode_is_safe(mode: u32) -> bool {
    // Codex legitimately creates 0755/0644/0444 state. The owner-only 0700
    // profile root prevents traversal by other users; descendants must only
    // reject group/other write access, which could let another user replace an
    // entry before descriptor-relative cleanup.
    mode & 0o022 == 0
}

#[cfg(unix)]
const fn removal_directory_mode_is_safe(mode: u32) -> bool {
    removal_descendant_mode_is_safe(mode) && mode & 0o700 == 0o700
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemovalEntryKind {
    Directory,
    RegularFile,
    NonFollowingLeaf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RemovalJournal {
    schema_version: u8,
    profile: Profile,
    expected_registry_digest: String,
    removed_registry_digest: String,
    data_root: FileSystemIdentity,
    profiles_root: FileSystemIdentity,
    provider_root: FileSystemIdentity,
    profile_tree: FileSystemIdentity,
    profile_tree_entry_count: u64,
    profile_tree_manifest_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RemovalRoots {
    data_root: FileSystemIdentity,
    profiles_root: FileSystemIdentity,
    provider_root: FileSystemIdentity,
    provider_mount: RemovalMountIdentity,
}

impl Default for RegistryDocument {
    fn default() -> Self {
        Self {
            schema_version: REGISTRY_SCHEMA_VERSION,
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
        let root = data_root()?;
        #[cfg(unix)]
        let root = canonicalize_managed_root(&root)?;
        Ok(Self {
            root,
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

        let expected_registry = current.clone();
        let expected_registry_digest = registry_digest(&current)?;
        current.profiles.remove(profile_index);
        let removed_registry_digest = registry_digest(&current)?;
        let journal = RemovalJournal {
            schema_version: REMOVAL_JOURNAL_SCHEMA_VERSION,
            profile: selected.clone(),
            expected_registry_digest,
            removed_registry_digest,
            data_root: roots.data_root,
            profiles_root: roots.profiles_root,
            provider_root: roots.provider_root,
            profile_tree: tree.root,
            profile_tree_entry_count: tree.entry_count,
            profile_tree_manifest_digest: tree.manifest_digest,
        };
        let barrier = RemovalRegistryBarrier {
            schema_version: REMOVAL_REGISTRY_BARRIER_SCHEMA_VERSION,
            removal: journal.clone(),
            expected_registry,
        };
        self.save_removal_barrier(&barrier)?;
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

        let preflight = (|| {
            Ok::<_, ProfileError>(
                self.read_removal_barrier()?.is_none()
                    && self.read_removal_journal()?.is_none()
                    && self.removal_tombstones()?.is_empty()
                    && self.removal_temporaries()?.is_empty(),
            )
        })();
        if preflight
            .as_ref()
            .is_ok_and(|artifacts_absent| *artifacts_absent)
        {
            return Ok(());
        }

        #[cfg(not(unix))]
        {
            let _artifacts_absent = preflight?;
            return Err(ProfileError::UnsupportedPlatform);
        }

        #[cfg(unix)]
        self.recover_incomplete_removal_unix()
    }

    #[cfg(unix)]
    fn recover_incomplete_removal_unix(&self) -> Result<(), ProfileError> {
        // Wait for a live remover to finish, then take one consistent artifact
        // snapshot while it cannot unlink the journal between verification and
        // open. Release this gate before taking a profile lease to preserve the
        // global profile-lease -> removal-lock -> registry-lock order.
        let quiescence_gate = self.lock_removal_exclusive()?;
        let first_barrier = self.read_removal_barrier()?;
        let first_journal = self.read_removal_journal()?;
        let tombstones = self.removal_tombstones()?;
        let temporaries = self.removal_temporaries()?;
        drop(quiescence_gate);
        let effective_journal =
            effective_removal_journal(first_barrier.as_ref(), first_journal.as_ref())?;
        if first_barrier.is_some() && first_journal.is_none() && !tombstones.is_empty() {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        if effective_journal.is_none() {
            if !tombstones.is_empty() {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
            if temporaries.is_empty() {
                return Ok(());
            }
            private_directory_identity(&self.root)?;
            let _removal_lock = self.lock_removal_exclusive()?;
            let _registry_lock = self.lock_exclusive()?;
            if self.read_removal_barrier()?.is_some() || self.read_removal_journal()?.is_some() {
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
        let journal = effective_journal.ok_or(ProfileError::RemovalRecoveryRequired)?;
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
        let current_barrier = self.read_removal_barrier()?;
        let current_journal = self.read_removal_journal()?;
        if current_barrier != first_barrier || current_journal != first_journal {
            if current_barrier.is_none()
                && current_journal.is_none()
                && self.removal_tombstones()?.is_empty()
                && self.removal_temporaries()?.is_empty()
            {
                return Ok(());
            }
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        let current_tombstones = self.removal_tombstones()?;
        let current_temporaries = self.removal_temporaries()?;
        self.validate_removal_artifact_set(&journal, &current_tombstones, &current_temporaries)?;
        let roots = self.validate_removal_roots(Some(&journal))?;
        let original_exists = path_exists(&original)?;
        let tombstone_exists = path_exists(&tombstone)?;
        if original_exists && tombstone_exists {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        let registry_lock = self.lock_exclusive()?;
        let registry_state = self.read_existing_registry_state()?;
        let (old_visible, removed_visible) = match &registry_state {
            RegistryState::RemovalBarrier(barrier)
                if first_barrier.as_ref() == Some(barrier.as_ref()) =>
            {
                (true, false)
            }
            RegistryState::Stable(document) if first_barrier.is_none() => {
                (false, journal.target_is_absent(document))
            }
            _ => (false, false),
        };
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
                false,
            )?;
            let RegistryState::RemovalBarrier(barrier) = registry_state else {
                return Err(ProfileError::RemovalRecoveryRequired);
            };
            self.save(&barrier.expected_registry)?;
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
                    true,
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
            || self.read_removal_barrier()?.is_some()
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
        // publication, so no remover can publish its transaction barrier before commit.
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
        create_durable_profile_lock_files(&staging)?;

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
        #[cfg(unix)]
        ensure_profile_lock_durability(&profile_dir, &coordinator, &provider)?;
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
        resolve_adapter: impl FnOnce(&Path, Option<&File>) -> Result<CodexIdentityAdapter, ProfileError>,
    ) -> Result<VerifiedProviderIdentityLease, ProfileError> {
        let lease = self.lock_profile(profile)?;
        let home = self.profile_home(profile)?;
        let adapter = resolve_adapter(&home, lease.provider_lock_for_probe()?)?;
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
    #[allow(dead_code)] // Reused by target reservation and pool selection.
    pub(crate) fn revalidate_codex_identity(
        &self,
        profile: &Profile,
        resolve_adapter: impl FnOnce(&Path, Option<&File>) -> Result<CodexIdentityAdapter, ProfileError>,
    ) -> Result<VerifiedProviderIdentityLease, ProfileError> {
        let lease = self.lock_profile(profile)?;
        let home = self.profile_home(profile)?;
        let adapter = resolve_adapter(&home, lease.provider_lock_for_probe()?)?;
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

    /// Reserves both target locks only after private identity revalidation.
    ///
    /// The returned guard is consumed by the Linux/macOS one-shot guardian
    /// transfer. It exposes identity equality only; account-derived material
    /// never enters the control frame or a public DTO.
    #[allow(dead_code)] // First consumed by supervised handoff in issue #33.
    pub(crate) fn reserve_verified_codex_target(
        &self,
        profile: &Profile,
        resolve_adapter: impl FnOnce(&Path, Option<&File>) -> Result<CodexIdentityAdapter, ProfileError>,
    ) -> Result<VerifiedTargetReservation, ProfileError> {
        let verified = self.revalidate_codex_identity(profile, resolve_adapter)?;
        // Rename takes the same A+B locks. Refetching by immutable ID while
        // those locks are still held gives the reservation a deterministic
        // current alias regardless of which operation won first.
        let current = self.find_by_id_without_recovery(profile.provider, &profile.id)?;
        Ok(VerifiedTargetReservation {
            lease: verified._lease,
            profile: current,
            identity: verified.identity,
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
    ) -> Result<CoordinatorProfileLease, ProfileError> {
        let profile_dir = self.profile_directory(profile)?;
        let coordinator = lock_profile_file(
            &profile_dir.join(COORDINATOR_LOCK_FILE),
            &profile.reference(),
        )?;
        Ok(CoordinatorProfileLease {
            lease: ProfileLease {
                coordinator: Some(coordinator),
                provider: None,
            },
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

    /// Receives the provider half of an already-held target reservation.
    ///
    /// The descriptor is accepted only when it still names the exact private
    /// `provider.lock` for this profile. It is marked close-on-exec before the
    /// caller can acknowledge receipt, so provider children and tools cannot
    /// inherit the lease.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(dead_code)] // First consumed by supervised handoff in issue #33.
    pub(crate) fn receive_profile_provider_lease<'control>(
        &self,
        profile: &Profile,
        control: &'control std::os::unix::net::UnixStream,
    ) -> Result<UnacknowledgedTargetGuardianLease<'control>, ProfileError> {
        use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};

        let profile_dir = self.profile_directory(profile)?;
        let provider_path = profile_dir.join(PROVIDER_LOCK_FILE);
        let provider = receive_provider_lock_descriptor(control)?;
        let flags = fcntl_getfd(&provider).map_err(io::Error::from)?;
        fcntl_setfd(&provider, flags | FdFlags::CLOEXEC).map_err(io::Error::from)?;
        if !fcntl_getfd(&provider)
            .map_err(io::Error::from)?
            .contains(FdFlags::CLOEXEC)
        {
            return Err(ProfileError::UnsafeState(
                "received provider lock is inheritable".to_owned(),
            ));
        }
        let provider = File::from(provider);
        private_lock_file_identity(&provider, &provider_path)?;
        verify_received_provider_lock_ownership(&provider, &provider_path)?;
        Ok(UnacknowledgedTargetGuardianLease {
            guardian: TargetGuardianLease {
                lease: ProfileLease {
                    coordinator: None,
                    provider: Some(provider),
                },
                profile: profile.clone(),
            },
            control,
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
        match self.read_registry_state()? {
            RegistryState::Stable(document) => Ok(document),
            RegistryState::RemovalBarrier(_) => Err(ProfileError::RemovalRecoveryRequired),
        }
    }

    fn read_registry_state(&self) -> Result<RegistryState, ProfileError> {
        let path = self.root.join(REGISTRY_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(RegistryState::Stable(RegistryDocument::default()));
            }
            Err(error) => return Err(ProfileError::Io(error)),
        }
        let file = open_verified_registry_file(&path, false)?;
        Self::decode_registry_state(file)
    }

    fn decode_registry_state(file: File) -> Result<RegistryState, ProfileError> {
        let mut bytes = Vec::new();
        file.take((MAX_REMOVAL_REGISTRY_BARRIER_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_REMOVAL_REGISTRY_BARRIER_BYTES {
            return Err(ProfileError::InvalidRegistry(
                "registry exceeds the supported size limit".to_owned(),
            ));
        }
        let header: RegistrySchemaHeader = serde_json::from_slice(&bytes)
            .map_err(|_| ProfileError::InvalidRegistry("registry is not valid JSON".to_owned()))?;
        match header.schema_version {
            REGISTRY_SCHEMA_VERSION => {
                if bytes.len() > MAX_REGISTRY_BYTES {
                    return Err(ProfileError::InvalidRegistry(
                        "registry exceeds the supported size limit".to_owned(),
                    ));
                }
                let document: RegistryDocument = serde_json::from_slice(&bytes).map_err(|_| {
                    ProfileError::InvalidRegistry("registry is not valid JSON".to_owned())
                })?;
                validate_document(&document)?;
                Ok(RegistryState::Stable(document))
            }
            REMOVAL_REGISTRY_BARRIER_SCHEMA_VERSION => {
                if bytes.len() > MAX_REMOVAL_REGISTRY_BARRIER_BYTES {
                    return Err(ProfileError::RemovalRecoveryRequired);
                }
                let barrier: RemovalRegistryBarrier = serde_json::from_slice(&bytes)
                    .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
                barrier.validate()?;
                Ok(RegistryState::RemovalBarrier(Box::new(barrier)))
            }
            schema_version => Err(ProfileError::InvalidRegistry(format!(
                "unsupported registry schema {schema_version}"
            ))),
        }
    }

    fn read_existing_registry_state(&self) -> Result<RegistryState, ProfileError> {
        let path = self.root.join(REGISTRY_FILE);
        let file = open_verified_registry_file(&path, true)
            .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
        Self::decode_registry_state(file).map_err(|_| ProfileError::RemovalRecoveryRequired)
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

    fn save_removal_barrier(&self, barrier: &RemovalRegistryBarrier) -> Result<(), ProfileError> {
        barrier.validate()?;
        let bytes = serde_json::to_vec_pretty(barrier)
            .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
        if bytes.len() > MAX_REMOVAL_REGISTRY_BARRIER_BYTES {
            return Err(ProfileError::UnsafeState(
                "removal barrier exceeds the supported size limit".to_owned(),
            ));
        }
        atomic_write_private(
            &self.root,
            REGISTRY_FILE,
            &bytes,
            |step| self.inject_removal_barrier_write_fault(step),
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
    /// TOCTOU before any registry or unpublished registration state changes.
    /// Recovery itself uses `lock_exclusive` because its barrier or sidecar must exist.
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
        let data_mount = removal_mount_identity_path(&self.root)?;
        let profiles_mount = removal_mount_identity_path(&profiles_root)?;
        let provider_mount = removal_mount_identity_path(&provider_root)?;
        ensure_same_removal_mount(&data_mount, &profiles_mount)?;
        ensure_same_removal_mount(&data_mount, &provider_mount)?;
        let roots = RemovalRoots {
            data_root: private_directory_identity(&self.root)?,
            profiles_root: private_directory_identity(&profiles_root)?,
            provider_root: private_directory_identity(&provider_root)?,
            provider_mount,
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
        let mut bytes = Vec::new();
        open_verified_registry_file(&path, true)
            .map_err(|_| ProfileError::RemovalRecoveryRequired)?
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

    fn read_removal_barrier(&self) -> Result<Option<RemovalRegistryBarrier>, ProfileError> {
        match self.read_registry_state()? {
            RegistryState::Stable(_) => Ok(None),
            RegistryState::RemovalBarrier(barrier) => Ok(Some(*barrier)),
        }
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
            let mut file = create_new_private_file(&temporary)?;
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
            &roots.provider_mount,
            usize::try_from(journal.profile_tree_entry_count)
                .map_err(|_| ProfileError::RemovalRecoveryRequired)?,
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
        self.remove_removal_journal(_removal_lock, registry_lock, journal, &temporaries, true)
    }

    fn remove_removal_journal(
        &self,
        _removal_lock: &RegistryLock,
        _registry_lock: &RegistryLock,
        journal: &RemovalJournal,
        temporaries: &[PathBuf],
        sidecar_required: bool,
    ) -> Result<(), ProfileError> {
        let current = self.read_removal_journal()?;
        match current.as_ref() {
            Some(current) if current == journal => {}
            None if !sidecar_required => {}
            _ => return Err(ProfileError::RemovalRecoveryRequired),
        }
        if !temporaries.is_empty() {
            if temporaries.len() != 1 {
                return Err(ProfileError::RemovalRecoveryRequired);
            }
            verify_private_single_link_regular_file(&temporaries[0])
                .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
            fs::remove_file(&temporaries[0]).map_err(ProfileError::RemovalCommitUncertain)?;
        }
        if current.is_some() {
            self.inject_removal_fault(RemovalFaultPoint::JournalRemove)
                .map_err(removal_commit_error)?;
            fs::remove_file(self.root.join(REMOVAL_JOURNAL_FILE))
                .map_err(ProfileError::RemovalCommitUncertain)?;
        }
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

    fn inject_removal_barrier_write_fault(
        &self,
        _step: RegistryWriteStep,
    ) -> Result<(), ProfileError> {
        #[cfg(test)]
        if self.removal_fault
            == Some(match _step {
                RegistryWriteStep::TemporaryCreate => RemovalFaultPoint::BarrierTemporaryCreate,
                RegistryWriteStep::Write => RemovalFaultPoint::BarrierWrite,
                RegistryWriteStep::FileSync => RemovalFaultPoint::BarrierFileSync,
                RegistryWriteStep::AtomicRename => RemovalFaultPoint::BarrierAtomicRename,
                RegistryWriteStep::DirectorySync => RemovalFaultPoint::BarrierDirectorySync,
            })
        {
            return Err(ProfileError::Io(io::Error::other(
                "injected removal barrier write failure",
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
        if !is_sha256_hex(&self.expected_registry_digest)
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
        Ok(registry_digest(document)? == self.expected_registry_digest
            && document
                .profiles
                .iter()
                .filter(|profile| *profile == &self.profile)
                .count()
                == 1)
    }

    fn matches_removed_registry(&self, document: &RegistryDocument) -> Result<bool, ProfileError> {
        Ok(registry_digest(document)? == self.removed_registry_digest
            && !document
                .profiles
                .iter()
                .any(|profile| profile.id == self.profile.id))
    }

    fn target_is_absent(&self, document: &RegistryDocument) -> bool {
        !document
            .profiles
            .iter()
            .any(|profile| profile.id == self.profile.id)
    }
}

impl RemovalRegistryBarrier {
    fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != REMOVAL_REGISTRY_BARRIER_SCHEMA_VERSION {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        self.removal.validate()?;
        validate_document(&self.expected_registry)
            .map_err(|_| ProfileError::RemovalRecoveryRequired)?;
        if !self
            .removal
            .matches_expected_registry(&self.expected_registry)?
        {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        let mut derived_removed = self.expected_registry.clone();
        let original_len = derived_removed.profiles.len();
        derived_removed
            .profiles
            .retain(|profile| profile.id != self.removal.profile.id);
        if derived_removed.profiles.len().checked_add(1) != Some(original_len)
            || !self.removal.matches_removed_registry(&derived_removed)?
        {
            return Err(ProfileError::RemovalRecoveryRequired);
        }
        Ok(())
    }
}

fn registry_digest(document: &RegistryDocument) -> Result<String, ProfileError> {
    let bytes = serde_json::to_vec(document)
        .map_err(|_| ProfileError::InvalidRegistry("registry serialization failed".to_owned()))?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn effective_removal_journal(
    barrier: Option<&RemovalRegistryBarrier>,
    sidecar: Option<&RemovalJournal>,
) -> Result<Option<RemovalJournal>, ProfileError> {
    match (barrier, sidecar) {
        (Some(barrier), Some(sidecar)) if &barrier.removal == sidecar => Ok(Some(sidecar.clone())),
        (Some(barrier), None) => Ok(Some(barrier.removal.clone())),
        (None, Some(sidecar)) => Ok(Some(sidecar.clone())),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(ProfileError::RemovalRecoveryRequired),
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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

fn ensure_same_removal_mount(
    expected: &RemovalMountIdentity,
    actual: &RemovalMountIdentity,
) -> Result<(), ProfileError> {
    if expected != actual {
        return Err(ProfileError::UnsafeState(
            "managed profile tree crosses a mount boundary".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn removal_boundary_error(error: rustix::io::Errno) -> ProfileError {
    let unsafe_boundary_errors = [
        rustix::io::Errno::XDEV,
        rustix::io::Errno::LOOP,
        rustix::io::Errno::AGAIN,
        rustix::io::Errno::NOSYS,
        rustix::io::Errno::INVAL,
        rustix::io::Errno::TOOBIG,
        rustix::io::Errno::NOENT,
        rustix::io::Errno::NOTDIR,
        rustix::io::Errno::PERM,
        rustix::io::Errno::ACCESS,
    ];
    if unsafe_boundary_errors.contains(&error) {
        ProfileError::UnsafeState("platform cannot prove the managed mount boundary".to_owned())
    } else {
        ProfileError::Io(io::Error::from(error))
    }
}

#[cfg(target_os = "linux")]
fn removal_mount_identity_path(path: &Path) -> Result<RemovalMountIdentity, ProfileError> {
    use rustix::fs::{AtFlags, CWD, StatxFlags, statx};

    let stat = statx(
        CWD,
        path,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .map_err(removal_boundary_error)?;
    removal_mount_identity_from_statx(&stat)
}

#[cfg(target_os = "linux")]
fn removal_mount_identity_fd<Fd: rustix::fd::AsFd>(
    fd: Fd,
) -> Result<RemovalMountIdentity, ProfileError> {
    use rustix::fs::{AtFlags, StatxFlags, statx};

    let stat = statx(
        fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .map_err(removal_boundary_error)?;
    removal_mount_identity_from_statx(&stat)
}

#[cfg(target_os = "linux")]
fn removal_mount_identity_from_statx(
    stat: &rustix::fs::Statx,
) -> Result<RemovalMountIdentity, ProfileError> {
    use rustix::fs::StatxFlags;

    if stat.stx_mask & StatxFlags::MNT_ID.bits() != StatxFlags::MNT_ID.bits()
        || stat.stx_mnt_id == 0
    {
        return Err(ProfileError::UnsafeState(
            "platform cannot prove the managed mount boundary".to_owned(),
        ));
    }
    Ok(RemovalMountIdentity {
        token: stat.stx_mnt_id.to_le_bytes().to_vec(),
    })
}

#[cfg(target_os = "macos")]
fn removal_mount_identity_path(path: &Path) -> Result<RemovalMountIdentity, ProfileError> {
    use rustix::fs::{Mode, OFlags, open};

    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(removal_boundary_error)?;
    removal_mount_identity_fd(fd)
}

#[cfg(target_os = "macos")]
fn removal_mount_identity_fd<Fd: rustix::fd::AsFd>(
    fd: Fd,
) -> Result<RemovalMountIdentity, ProfileError> {
    let stat = rustix::fs::fstatfs(fd).map_err(removal_boundary_error)?;
    let mut token = Vec::new();
    append_macos_mount_field(&mut token, &stat.f_mntonname, true)?;
    append_macos_mount_field(&mut token, &stat.f_mntfromname, false)?;
    append_macos_mount_field(&mut token, &stat.f_fstypename, false)?;
    Ok(RemovalMountIdentity { token })
}

#[cfg(target_os = "macos")]
fn append_macos_mount_field(
    token: &mut Vec<u8>,
    field: &[std::ffi::c_char],
    require_absolute: bool,
) -> Result<(), ProfileError> {
    let end = field.iter().position(|byte| *byte == 0).ok_or_else(|| {
        ProfileError::UnsafeState(
            "platform returned an ambiguous managed mount identity".to_owned(),
        )
    })?;
    let start = token.len();
    token.extend(field[..end].iter().map(|byte| byte.to_ne_bytes()[0]));
    if end == 0 || (require_absolute && token.get(start) != Some(&b'/')) {
        return Err(ProfileError::UnsafeState(
            "platform returned an ambiguous managed mount identity".to_owned(),
        ));
    }
    token.push(0);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn removal_mount_identity_path(_path: &Path) -> Result<RemovalMountIdentity, ProfileError> {
    Err(ProfileError::UnsupportedPlatform)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn removal_mount_identity_fd<Fd: rustix::fd::AsFd>(
    _fd: Fd,
) -> Result<RemovalMountIdentity, ProfileError> {
    Err(ProfileError::UnsupportedPlatform)
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
    validate_owned_removal_tree_inner_with_limits(
        data_root,
        roots,
        path,
        profile_id,
        expected,
        require_marker,
        MAX_REMOVAL_TREE_ENTRIES,
        MAX_REMOVAL_TREE_DEPTH,
    )
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn validate_owned_removal_tree_inner_with_limits(
    data_root: &Path,
    roots: &RemovalRoots,
    path: &Path,
    profile_id: &str,
    expected: Option<FileSystemIdentity>,
    require_marker: bool,
    max_entries: usize,
    max_depth: usize,
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
    ensure_same_removal_mount(&roots.provider_mount, &removal_mount_identity_path(path)?)?;

    let mut manifest = Sha256::new();
    manifest.update(b"calcifer-removal-tree-manifest-v1\0");
    let root_metadata = fs::symlink_metadata(path)?;
    update_removal_manifest(&mut manifest, Path::new(""), &root_metadata)?;

    let mut pending = Vec::new();
    try_reserve_removal_slot(&mut pending)?;
    pending.push((path.to_owned(), 0_usize));
    let mut budget = RemovalTraversalBudget::new(max_entries, max_depth);
    while let Some((directory, depth)) = pending.pop() {
        let directory_metadata = fs::symlink_metadata(&directory)?;
        if !directory_metadata.file_type().is_dir()
            || directory_metadata.file_type().is_symlink()
            || directory_metadata.uid() != rustix::process::getuid().as_raw()
            || !removal_directory_mode_is_safe(directory_metadata.mode())
            || directory_metadata.dev() != roots.provider_root.device
        {
            return Err(ProfileError::UnsafeState(
                "managed profile tree contains an unsafe directory".to_owned(),
            ));
        }
        verify_no_extended_macos_acl(&directory)?;
        verify_deletable_macos_flags_path(&directory)?;
        ensure_same_removal_mount(
            &roots.provider_mount,
            &removal_mount_identity_path(&directory)?,
        )?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            budget.consume_entry()?;
            try_reserve_removal_slot(&mut entries)?;
            entries.push(entry);
        }
        entries.sort_by(|left, right| {
            left.file_name()
                .as_bytes()
                .cmp(right.file_name().as_bytes())
        });
        let mut child_directories = Vec::new();
        for entry in entries {
            let entry_path = entry.path();
            let metadata = fs::symlink_metadata(&entry_path)?;
            let file_type = metadata.file_type();
            let non_following_leaf = !file_type.is_dir() && !file_type.is_file();
            let relative = entry_path.strip_prefix(path).map_err(|_| {
                ProfileError::UnsafeState(
                    "managed profile entry escaped its removal root".to_owned(),
                )
            })?;
            if metadata.uid() != rustix::process::getuid().as_raw()
                || metadata.dev() != roots.provider_root.device
                || (((file_type.is_dir() && !removal_directory_mode_is_safe(metadata.mode()))
                    || (file_type.is_file() && !removal_descendant_mode_is_safe(metadata.mode())))
                    || (!file_type.is_dir() && metadata.nlink() != 1))
            {
                return Err(ProfileError::UnsafeState(
                    "managed profile tree contains unsafe state".to_owned(),
                ));
            }
            verify_no_extended_macos_acl(&entry_path)?;
            verify_deletable_macos_flags_path(&entry_path)?;
            if !non_following_leaf {
                ensure_same_removal_mount(
                    &roots.provider_mount,
                    &removal_mount_identity_path(&entry_path)?,
                )?;
            }
            update_removal_manifest(&mut manifest, relative, &metadata)?;
            if file_type.is_dir() {
                let child_depth = budget.child_depth(depth)?;
                try_reserve_removal_slot(&mut child_directories)?;
                child_directories.push((entry_path, child_depth));
            }
        }
        for child in child_directories.into_iter().rev() {
            try_reserve_removal_slot(&mut pending)?;
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
        entry_count: u64::try_from(budget.consumed_entries).map_err(|_| {
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
    let file_type = metadata.file_type();
    manifest.update([if file_type.is_dir() {
        1
    } else if file_type.is_file() {
        2
    } else if file_type.is_symlink() {
        3
    } else {
        4
    }]);
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

#[cfg(target_os = "linux")]
fn open_removal_entry_at<Fd, P>(
    dirfd: Fd,
    path: P,
    directory: bool,
    expected_mount: &RemovalMountIdentity,
) -> Result<rustix::fd::OwnedFd, ProfileError>
where
    Fd: rustix::fd::AsFd,
    P: rustix::path::Arg,
{
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

    let type_flags = if directory {
        OFlags::RDONLY | OFlags::DIRECTORY
    } else {
        OFlags::PATH
    };
    let fd = openat2(
        dirfd,
        path,
        type_flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(removal_boundary_error)?;
    ensure_same_removal_mount(expected_mount, &removal_mount_identity_fd(&fd)?)?;
    Ok(fd)
}

#[cfg(target_os = "macos")]
fn open_removal_entry_at<Fd, P>(
    dirfd: Fd,
    path: P,
    directory: bool,
    expected_mount: &RemovalMountIdentity,
) -> Result<rustix::fd::OwnedFd, ProfileError>
where
    Fd: rustix::fd::AsFd,
    P: rustix::path::Arg,
{
    use rustix::fs::{Mode, OFlags, openat};

    let type_flags = if directory {
        OFlags::RDONLY | OFlags::DIRECTORY
    } else {
        OFlags::RDONLY | OFlags::NONBLOCK
    };
    let fd = openat(
        dirfd,
        path,
        type_flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(removal_boundary_error)?;
    ensure_same_removal_mount(expected_mount, &removal_mount_identity_fd(&fd)?)?;
    Ok(fd)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn open_removal_entry_at<Fd, P>(
    _dirfd: Fd,
    _path: P,
    _directory: bool,
    _expected_mount: &RemovalMountIdentity,
) -> Result<rustix::fd::OwnedFd, ProfileError>
where
    Fd: rustix::fd::AsFd,
    P: rustix::path::Arg,
{
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
    expected_mount: &RemovalMountIdentity,
    max_entries: usize,
) -> Result<(), ProfileError> {
    remove_owned_tombstone_at_with_limits(
        provider_root,
        tombstone,
        expected_provider,
        expected_tree,
        expected_mount,
        max_entries,
        MAX_REMOVAL_TREE_DEPTH,
    )
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn remove_owned_tombstone_at_with_limits(
    provider_root: &Path,
    tombstone: &Path,
    expected_provider: FileSystemIdentity,
    expected_tree: FileSystemIdentity,
    expected_mount: &RemovalMountIdentity,
    max_entries: usize,
    max_depth: usize,
) -> Result<(), ProfileError> {
    use rustix::fs::{AtFlags, Dir, Mode, OFlags, fstat, open, statat, unlinkat};

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
    ensure_same_removal_mount(expected_mount, &removal_mount_identity_fd(&provider_fd)?)?;
    let tree_fd = open_removal_entry_at(&provider_fd, tombstone_name, true, expected_mount)?;
    let tree_stat = fstat(&tree_fd)
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    if stat_identity(&tree_stat)? != expected_tree {
        return Err(ProfileError::UnsafeState(
            "managed profile tree was replaced".to_owned(),
        ));
    }
    validate_removal_stat(
        &tree_stat,
        RemovalEntryKind::Directory,
        expected_provider.device,
    )?;
    let mut budget = RemovalTraversalBudget::new(max_entries, max_depth);
    remove_owned_directory_entries(
        Dir::new(tree_fd).map_err(io::Error::from)?,
        expected_provider.device,
        expected_mount,
        &mut budget,
        0,
    )?;

    let final_stat = statat(&provider_fd, tombstone_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    validate_opened_removal_entry(
        &tree_stat,
        &final_stat,
        RemovalEntryKind::Directory,
        expected_provider.device,
    )?;
    if stat_identity(&final_stat)? != expected_tree {
        return Err(ProfileError::UnsafeState(
            "managed profile tree was replaced during cleanup".to_owned(),
        ));
    }
    let final_tree_fd = open_removal_entry_at(&provider_fd, tombstone_name, true, expected_mount)?;
    let final_opened_stat = fstat(&final_tree_fd)
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    validate_opened_removal_entry(
        &tree_stat,
        &final_opened_stat,
        RemovalEntryKind::Directory,
        expected_provider.device,
    )?;
    if stat_identity(&final_opened_stat)? != expected_tree {
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
    expected_mount: &RemovalMountIdentity,
    budget: &mut RemovalTraversalBudget,
    depth: usize,
) -> Result<(), ProfileError> {
    use rustix::fs::{AtFlags, fstat, statat, unlinkat};

    let directory_fd = rustix::io::fcntl_dupfd_cloexec(directory.fd().map_err(io::Error::from)?, 0)
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    let mut names = Vec::new();
    for entry in directory.by_ref() {
        let entry = entry.map_err(io::Error::from).map_err(ProfileError::Io)?;
        if entry.file_name().to_bytes() != b"." && entry.file_name().to_bytes() != b".." {
            budget.consume_entry()?;
            let stat = statat(&directory_fd, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io::Error::from)
                .map_err(ProfileError::Io)?;
            let entry_kind = removal_entry_kind(&stat);
            validate_removal_stat(&stat, entry_kind, expected_device)?;
            let child_depth = match entry_kind {
                RemovalEntryKind::Directory => Some(budget.child_depth(depth)?),
                RemovalEntryKind::RegularFile | RemovalEntryKind::NonFollowingLeaf => None,
            };
            try_reserve_removal_slot(&mut names)?;
            names.push((entry.file_name().to_owned(), entry_kind, child_depth));
        }
    }
    for (name, entry_kind, child_depth) in names {
        let stat = statat(&directory_fd, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)
            .map_err(ProfileError::Io)?;
        validate_removal_stat(&stat, entry_kind, expected_device)?;
        match entry_kind {
            RemovalEntryKind::Directory => {
                let child_depth = child_depth.ok_or_else(|| {
                    ProfileError::UnsafeState(
                        "managed profile tree changed during cleanup".to_owned(),
                    )
                })?;
                let child = open_removal_entry_at(&directory_fd, &name, true, expected_mount)?;
                let opened_stat = fstat(&child)
                    .map_err(io::Error::from)
                    .map_err(ProfileError::Io)?;
                validate_opened_removal_entry(
                    &stat,
                    &opened_stat,
                    RemovalEntryKind::Directory,
                    expected_device,
                )?;
                remove_owned_directory_entries(
                    rustix::fs::Dir::new(child).map_err(io::Error::from)?,
                    expected_device,
                    expected_mount,
                    budget,
                    child_depth,
                )?;
                let final_stat = statat(&directory_fd, &name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(io::Error::from)
                    .map_err(ProfileError::Io)?;
                validate_opened_removal_entry(
                    &stat,
                    &final_stat,
                    RemovalEntryKind::Directory,
                    expected_device,
                )?;
                let final_child =
                    open_removal_entry_at(&directory_fd, &name, true, expected_mount)?;
                let final_opened_stat = fstat(&final_child)
                    .map_err(io::Error::from)
                    .map_err(ProfileError::Io)?;
                validate_opened_removal_entry(
                    &stat,
                    &final_opened_stat,
                    RemovalEntryKind::Directory,
                    expected_device,
                )?;
                unlinkat(&directory_fd, &name, AtFlags::REMOVEDIR)
                    .map_err(io::Error::from)
                    .map_err(ProfileError::Io)?;
            }
            RemovalEntryKind::RegularFile => {
                let file = open_removal_entry_at(&directory_fd, &name, false, expected_mount)?;
                let opened_stat = fstat(&file)
                    .map_err(io::Error::from)
                    .map_err(ProfileError::Io)?;
                validate_opened_removal_entry(
                    &stat,
                    &opened_stat,
                    RemovalEntryKind::RegularFile,
                    expected_device,
                )?;
                unlinkat(&directory_fd, &name, AtFlags::empty())
                    .map_err(io::Error::from)
                    .map_err(ProfileError::Io)?;
            }
            RemovalEntryKind::NonFollowingLeaf => {
                // unlinkat without REMOVEDIR never follows a symlink and does
                // not open sockets, FIFOs, or device nodes. A last-moment type
                // replacement can therefore only unlink this in-tree name.
                unlinkat(&directory_fd, &name, AtFlags::empty())
                    .map_err(io::Error::from)
                    .map_err(ProfileError::Io)?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_opened_removal_entry(
    expected: &rustix::fs::Stat,
    opened: &rustix::fs::Stat,
    expected_kind: RemovalEntryKind,
    expected_device: u64,
) -> Result<(), ProfileError> {
    if stat_identity(opened)? != stat_identity(expected)? {
        return Err(ProfileError::UnsafeState(
            "managed profile entry was replaced during cleanup".to_owned(),
        ));
    }
    validate_removal_stat(opened, expected_kind, expected_device)
}

#[cfg(unix)]
fn stat_identity(stat: &rustix::fs::Stat) -> Result<FileSystemIdentity, ProfileError> {
    Ok(FileSystemIdentity {
        device: normalize_stat_device(stat.st_dev)?,
        inode: stat.st_ino,
    })
}

#[cfg(unix)]
fn normalize_stat_device<T>(device: T) -> Result<u64, ProfileError>
where
    u64: TryFrom<T>,
{
    u64::try_from(device)
        .map_err(|_| ProfileError::UnsafeState("managed filesystem identity is invalid".to_owned()))
}

#[cfg(unix)]
fn normalize_stat_mode<T>(mode: T) -> Result<u32, ProfileError>
where
    u32: TryFrom<T>,
{
    u32::try_from(mode)
        .map_err(|_| ProfileError::UnsafeState("managed filesystem mode is invalid".to_owned()))
}

#[cfg(unix)]
fn validate_removal_stat(
    stat: &rustix::fs::Stat,
    expected_kind: RemovalEntryKind,
    expected_device: u64,
) -> Result<(), ProfileError> {
    let actual_kind = removal_entry_kind(stat);
    let mode_is_safe = match actual_kind {
        RemovalEntryKind::Directory => {
            removal_directory_mode_is_safe(normalize_stat_mode(stat.st_mode)?)
        }
        RemovalEntryKind::RegularFile => {
            removal_descendant_mode_is_safe(normalize_stat_mode(stat.st_mode)?)
        }
        RemovalEntryKind::NonFollowingLeaf => true,
    };
    let link_count_is_safe = actual_kind == RemovalEntryKind::Directory || stat.st_nlink == 1;
    let actual_device = normalize_stat_device(stat.st_dev)?;
    if actual_kind != expected_kind
        || stat.st_uid != rustix::process::getuid().as_raw()
        || !mode_is_safe
        || !link_count_is_safe
        || actual_device != expected_device
    {
        return Err(ProfileError::UnsafeState(
            "managed profile tree changed during cleanup".to_owned(),
        ));
    }
    verify_deletable_macos_flags_stat(stat)
}

#[cfg(unix)]
fn removal_entry_kind(stat: &rustix::fs::Stat) -> RemovalEntryKind {
    let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    if file_type.is_dir() {
        RemovalEntryKind::Directory
    } else if file_type.is_file() {
        RemovalEntryKind::RegularFile
    } else {
        RemovalEntryKind::NonFollowingLeaf
    }
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

/// An A-only profile authority returned by the fixed-order coordinator lock.
///
/// Keeping this distinct from [`ProfileLease`] prevents fail-closed recovery
/// code from accidentally accepting a provider-only or combined lease.
pub(crate) struct CoordinatorProfileLease {
    lease: ProfileLease,
}

pub(crate) struct VerifiedProviderIdentityLease {
    _lease: ProfileLease,
    profile: Profile,
    identity: ProviderIdentity,
}

/// A freshly revalidated target profile with both lifetime locks held.
///
/// Provider identity material remains private to this guard. The handoff
/// selector may compare identities and transfer the provider lock, but cannot
/// serialize or expose the fingerprint or account-derived inputs.
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
pub(crate) struct VerifiedTargetReservation {
    lease: ProfileLease,
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

#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
impl VerifiedTargetReservation {
    pub(crate) const fn profile(&self) -> &Profile {
        &self.profile
    }

    pub(crate) fn same_provider_identity(&self, other: &Self) -> bool {
        self.identity.same_provider_identity(&other.identity)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn send_provider_lease<'control>(
        self,
        control: &'control std::os::unix::net::UnixStream,
    ) -> Result<AwaitingProviderLeaseAck<'control>, Box<ProviderLeaseTransferSendError>> {
        if self.lease.coordinator.is_none() {
            return Err(Box::new(ProviderLeaseTransferSendError {
                reservation: self,
                error: ProfileError::UnsafeState(
                    "provider lease transfer requires the coordinator lock".to_owned(),
                ),
            }));
        }
        let Some(provider) = self.lease.provider.as_ref() else {
            return Err(Box::new(ProviderLeaseTransferSendError {
                reservation: self,
                error: ProfileError::UnsafeState(
                    "provider lease transfer requires the provider lock".to_owned(),
                ),
            }));
        };
        match send_provider_lock_descriptor(control, provider) {
            Ok(()) => Ok(AwaitingProviderLeaseAck {
                reservation: self,
                control,
            }),
            Err(error) => Err(Box::new(ProviderLeaseTransferSendError {
                reservation: self,
                error,
            })),
        }
    }
}

impl CoordinatorProfileLease {
    /// Borrows the coordinator-side lock for one audited authority check.
    ///
    /// This does not expose ownership or permit callers to unlock the file.
    /// Long-running supervisor code must continue to acquire A before B and
    /// must retain this lease object for the complete coordinator lifetime.
    #[allow(dead_code)] // First consumed by the default-off supervisor in issue #50.
    pub(crate) fn lock_file(&self) -> Result<&File, ProfileError> {
        self.lease
            .coordinator
            .as_ref()
            .ok_or_else(|| ProfileError::UnsafeState("coordinator lock is not held".to_owned()))
    }
}

impl ProfileLease {
    /// Borrows the provider-side lock for one child-only inheritance action.
    ///
    /// The parent descriptor always remains close-on-exec. Provider adapters
    /// must pass this file to the audited Unix spawn boundary, which clears the
    /// flag only in the selected post-fork child.
    pub(crate) fn provider_lock_file(&self) -> Result<&File, ProfileError> {
        self.provider
            .as_ref()
            .ok_or_else(|| ProfileError::UnsafeState("provider lock is not held".to_owned()))
    }

    /// Returns the provider descriptor only where the audited child-side
    /// inheritance boundary is available.
    ///
    /// Non-Unix platforms keep the lease in the parent but preserve their
    /// existing ordinary-spawn behavior. The adapter's `Some` branch remains
    /// an invariant guard and must never be reached there.
    pub(crate) fn provider_lock_for_probe(&self) -> Result<Option<&File>, ProfileError> {
        let provider = self.provider_lock_file()?;
        #[cfg(unix)]
        {
            Ok(Some(provider))
        }
        #[cfg(not(unix))]
        {
            let _ = provider;
            Ok(None)
        }
    }
}

/// A complete target reservation whose provider descriptor was sent once.
///
/// This state has no resend operation. Dropping it before an ACK closes the
/// sender copies without `LOCK_UN`; a guardian that already received the
/// descriptor therefore continues to hold the provider lock.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
pub(crate) struct AwaitingProviderLeaseAck<'control> {
    reservation: VerifiedTargetReservation,
    control: &'control std::os::unix::net::UnixStream,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
impl<'control> AwaitingProviderLeaseAck<'control> {
    pub(crate) fn receive_ack(
        self,
    ) -> Result<AcknowledgedProviderLeaseTransfer, Box<ProviderLeaseAckError<'control>>> {
        match receive_provider_lease_ack(self.control) {
            Ok(()) => Ok(AcknowledgedProviderLeaseTransfer {
                reservation: self.reservation,
            }),
            Err(error) => Err(Box::new(ProviderLeaseAckError {
                awaiting: self,
                error,
            })),
        }
    }
}

/// A target reservation whose validated guardian ACK was read from the same
/// private control stream that carried B.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
pub(crate) struct AcknowledgedProviderLeaseTransfer {
    reservation: VerifiedTargetReservation,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
impl AcknowledgedProviderLeaseTransfer {
    pub(crate) fn commit(mut self) -> Result<TargetCoordinatorLease, ProfileError> {
        let provider = self.reservation.lease.provider.take().ok_or_else(|| {
            ProfileError::UnsafeState("transferred provider lock is not held".to_owned())
        })?;
        // Do not call `FileExt::unlock`: the receiving guardian owns another
        // descriptor for this same locked open-file description.
        drop(provider);
        Ok(TargetCoordinatorLease {
            lease: self.reservation.lease,
            profile: self.reservation.profile,
        })
    }
}

/// Preserves the awaiting state when the guardian ACK is missing or invalid.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
pub(crate) struct ProviderLeaseAckError<'control> {
    awaiting: AwaitingProviderLeaseAck<'control>,
    error: ProfileError,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
impl<'control> ProviderLeaseAckError<'control> {
    pub(crate) fn into_parts(self) -> (AwaitingProviderLeaseAck<'control>, ProfileError) {
        (self.awaiting, self.error)
    }

    fn into_error(self) -> ProfileError {
        self.error
    }
}

/// Preserves the complete reservation when the descriptor send itself fails.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
pub(crate) struct ProviderLeaseTransferSendError {
    reservation: VerifiedTargetReservation,
    error: ProfileError,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
impl ProviderLeaseTransferSendError {
    pub(crate) fn into_parts(self) -> (VerifiedTargetReservation, ProfileError) {
        (self.reservation, self.error)
    }

    fn into_error(self) -> ProfileError {
        self.error
    }
}

/// The coordinator half retained after the guardian acknowledges B.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
pub(crate) struct TargetCoordinatorLease {
    lease: ProfileLease,
    profile: Profile,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
impl TargetCoordinatorLease {
    pub(crate) const fn profile(&self) -> &Profile {
        &self.profile
    }
}

/// The provider half adopted by the authenticated target guardian.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
pub(crate) struct TargetGuardianLease {
    lease: ProfileLease,
    profile: Profile,
}

/// A validated B descriptor that cannot authorize child launch until it has
/// sent exactly one ACK on the stream that carried the descriptor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
pub(crate) struct UnacknowledgedTargetGuardianLease<'control> {
    guardian: TargetGuardianLease,
    control: &'control std::os::unix::net::UnixStream,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
impl<'control> UnacknowledgedTargetGuardianLease<'control> {
    pub(crate) fn send_ack(
        self,
    ) -> Result<TargetGuardianLease, Box<ProviderLeaseGuardianAckSendError<'control>>> {
        match send_provider_lease_ack(self.control) {
            Ok(()) => Ok(self.guardian),
            Err(error) => Err(Box::new(ProviderLeaseGuardianAckSendError {
                guardian: self,
                error,
            })),
        }
    }
}

/// Preserves provisional B ownership when the guardian cannot send its ACK.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
pub(crate) struct ProviderLeaseGuardianAckSendError<'control> {
    guardian: UnacknowledgedTargetGuardianLease<'control>,
    error: ProfileError,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
impl<'control> ProviderLeaseGuardianAckSendError<'control> {
    pub(crate) fn into_parts(self) -> (UnacknowledgedTargetGuardianLease<'control>, ProfileError) {
        (self.guardian, self.error)
    }

    fn into_error(self) -> ProfileError {
        self.error
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // First consumed by supervised handoff in issue #33.
impl TargetGuardianLease {
    pub(crate) const fn profile(&self) -> &Profile {
        &self.profile
    }
}

impl Drop for ProfileLease {
    fn drop(&mut self) {
        // `SCM_RIGHTS` and inherited descriptors share the same locked
        // open-file description on Unix. An explicit `LOCK_UN` from any owner
        // would therefore revoke every other owner's authority. Closing our
        // descriptors in reverse acquisition order releases an untransferred
        // lock normally, while a transferred lock remains held until its last
        // descriptor closes.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            drop(self.provider.take());
            drop(self.coordinator.take());
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            if let Some(provider) = &self.provider {
                let _ = FileExt::unlock(provider);
            }
            if let Some(coordinator) = &self.coordinator {
                let _ = FileExt::unlock(coordinator);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const PROVIDER_LEASE_TRANSFER_MARKER: u8 = 0xC1;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const PROVIDER_LEASE_ACK_MARKER: u8 = 0xA1;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn send_provider_lock_descriptor(
    control: &std::os::unix::net::UnixStream,
    provider: &File,
) -> Result<(), ProfileError> {
    use std::io::IoSlice;
    use std::mem::MaybeUninit;
    use std::os::fd::AsFd;

    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, sendmsg};

    let descriptors = [provider.as_fd()];
    let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut ancillary_space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(ProfileError::UnsafeState(
            "provider lease transfer descriptor did not fit".to_owned(),
        ));
    }
    let payload = [PROVIDER_LEASE_TRANSFER_MARKER];
    let slices = [IoSlice::new(&payload)];
    let flags = provider_lease_send_flags(control)?;
    loop {
        match sendmsg(control, &slices, &mut ancillary, flags) {
            Ok(1) => return Ok(()),
            Ok(_) => {
                return Err(ProfileError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "provider lease transfer was incomplete",
                )));
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(ProfileError::Io(io::Error::from(error))),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn provider_lease_send_flags(
    control: &std::os::unix::net::UnixStream,
) -> Result<rustix::net::SendFlags, ProfileError> {
    #[cfg(target_os = "linux")]
    {
        let _ = control;
        Ok(rustix::net::SendFlags::NOSIGNAL)
    }
    #[cfg(target_os = "macos")]
    {
        rustix::net::sockopt::set_socket_nosigpipe(control, true).map_err(io::Error::from)?;
        if !rustix::net::sockopt::socket_nosigpipe(control).map_err(io::Error::from)? {
            return Err(ProfileError::UnsafeState(
                "provider lease control socket allows SIGPIPE".to_owned(),
            ));
        }
        Ok(rustix::net::SendFlags::empty())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn send_provider_lease_ack(control: &std::os::unix::net::UnixStream) -> Result<(), ProfileError> {
    let flags = provider_lease_send_flags(control)?;
    loop {
        match rustix::net::send(control, &[PROVIDER_LEASE_ACK_MARKER], flags) {
            Ok(1) => return Ok(()),
            Ok(_) => {
                return Err(ProfileError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "provider lease ACK was incomplete",
                )));
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(ProfileError::Io(io::Error::from(error))),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn receive_provider_lease_ack(
    control: &std::os::unix::net::UnixStream,
) -> Result<(), ProfileError> {
    let mut payload = [0_u8; 1];
    loop {
        match rustix::net::recv(control, &mut payload[..], rustix::net::RecvFlags::empty()) {
            Ok((_, 1)) if payload == [PROVIDER_LEASE_ACK_MARKER] => return Ok(()),
            Ok((_, 0)) => {
                return Err(ProfileError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "provider guardian closed before ACK",
                )));
            }
            Ok(_) => {
                return Err(ProfileError::UnsafeState(
                    "provider guardian ACK is invalid".to_owned(),
                ));
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(ProfileError::Io(io::Error::from(error))),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)] // Called by the issue #33 guardian receive path.
fn receive_provider_lock_descriptor(
    control: &std::os::unix::net::UnixStream,
) -> Result<rustix::fd::OwnedFd, ProfileError> {
    use std::io::IoSliceMut;
    use std::mem::MaybeUninit;

    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};

    let mut payload = [0_u8; 1];
    let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut ancillary_space);
    let received = loop {
        let mut slices = [IoSliceMut::new(&mut payload)];
        #[cfg(target_os = "linux")]
        let flags = RecvFlags::CMSG_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = RecvFlags::empty();
        match recvmsg(control, &mut slices, &mut ancillary, flags) {
            Ok(received) => break received,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(ProfileError::Io(io::Error::from(error))),
        }
    };
    #[cfg(target_os = "linux")]
    let flags_are_invalid = received.flags != rustix::net::ReturnFlags::CMSG_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags_are_invalid = !received.flags.is_empty();
    if received.bytes != 1 || payload != [PROVIDER_LEASE_TRANSFER_MARKER] || flags_are_invalid {
        return Err(ProfileError::UnsafeState(
            "provider lease transfer frame is invalid".to_owned(),
        ));
    }

    let mut descriptors = Vec::new();
    let mut rights_messages = 0_usize;
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(received_descriptors) => {
                rights_messages += 1;
                descriptors.extend(received_descriptors);
            }
            _ => {
                return Err(ProfileError::UnsafeState(
                    "provider lease transfer contained unsupported metadata".to_owned(),
                ));
            }
        }
    }
    if rights_messages != 1 || descriptors.len() != 1 {
        return Err(ProfileError::UnsafeState(
            "provider lease transfer must contain exactly one descriptor".to_owned(),
        ));
    }
    descriptors.pop().ok_or_else(|| {
        ProfileError::UnsafeState("provider lease transfer descriptor is missing".to_owned())
    })
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

/// Resolves the existing portion of a managed Unix root exactly once.
///
/// User-selected roots may legitimately be reached through aliases such as
/// macOS `/var` or a symlinked home directory. Calcifer stores the physical
/// path and appends only components that do not exist yet. Operational storage
/// checks can therefore reject every symlink ancestor instead of performing
/// path-based ACL checks on a mutable symlink object.
#[cfg(unix)]
fn canonicalize_managed_root(path: &Path) -> Result<PathBuf, ProfileError> {
    let normalized = require_absolute_root(path.to_path_buf())?;
    let mut candidate = normalized.as_path();
    let mut missing = Vec::new();

    loop {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                    return Err(ProfileError::UnsafeState(
                        "managed data root has a non-directory ancestor".to_owned(),
                    ));
                }
                let mut canonical = fs::canonicalize(candidate).map_err(|_| {
                    ProfileError::UnsafeState(
                        "managed data root cannot be resolved safely".to_owned(),
                    )
                })?;
                if !fs::metadata(&canonical)?.is_dir() {
                    return Err(ProfileError::UnsafeState(
                        "managed data root has a non-directory ancestor".to_owned(),
                    ));
                }
                for component in missing.into_iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let component = candidate.file_name().ok_or_else(|| {
                    ProfileError::UnsafeState(
                        "managed data root has no resolvable ancestor".to_owned(),
                    )
                })?;
                missing.push(component.to_owned());
                candidate = candidate.parent().ok_or_else(|| {
                    ProfileError::UnsafeState(
                        "managed data root has no resolvable ancestor".to_owned(),
                    )
                })?;
            }
            Err(error) => return Err(ProfileError::Io(error)),
        }
    }
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
    if document.schema_version != REGISTRY_SCHEMA_VERSION {
        return Err(ProfileError::InvalidRegistry(format!(
            "unsupported registry schema {}",
            document.schema_version
        )));
    }
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

    verify_safe_creation_parent(path)?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    if let Err(error) = clear_inherited_macos_acl(path) {
        let _ = fs::remove_dir(path);
        return Err(error);
    }
    verify_private_directory(path)
}

#[cfg(not(unix))]
fn secure_create_dir(path: &Path) -> Result<(), ProfileError> {
    fs::create_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn secure_create_dir_all(path: &Path) -> Result<(), ProfileError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return verify_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(ProfileError::Io(error)),
    }

    let mut missing = Vec::new();
    let mut candidate = path;
    loop {
        match fs::symlink_metadata(candidate) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(candidate.to_owned());
                candidate = candidate.parent().ok_or_else(|| {
                    ProfileError::UnsafeState(
                        "managed directory has no existing ancestor".to_owned(),
                    )
                })?;
            }
            Err(error) => return Err(ProfileError::Io(error)),
        }
    }
    for directory in missing.into_iter().rev() {
        match secure_create_dir(&directory) {
            Ok(()) => {}
            Err(ProfileError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                verify_private_directory(&directory)?;
            }
            Err(error) => return Err(error),
        }
    }
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
pub(crate) fn managed_runtime_root() -> Result<PathBuf, ProfileError> {
    use std::os::unix::fs::MetadataExt;

    let runtime_root = canonicalize_managed_root(Path::new("/tmp"))?
        .join(format!("calcifer-{}", rustix::process::getuid().as_raw()));
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
fn private_directory_metadata_is_safe(metadata: &fs::Metadata, expected_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.file_type().is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == expected_uid
        && metadata.mode() & 0o077 == 0
}

#[cfg(target_os = "macos")]
struct MacosOpenedNode {
    metadata: fs::Metadata,
    stat: rustix::fs::Stat,
    acl: calcifer_macos_acl::Acl,
}

#[cfg(target_os = "macos")]
fn macos_acl_for_open_file(file: &File) -> io::Result<calcifer_macos_acl::Acl> {
    use std::os::fd::AsFd;

    calcifer_macos_acl::read_acl(file.as_fd())
}

#[cfg(target_os = "macos")]
fn inspect_opened_macos_node(
    file: &File,
    path: &Path,
    expected_directory: bool,
) -> Result<MacosOpenedNode, ProfileError> {
    use std::os::unix::fs::MetadataExt;

    let first_metadata = file.metadata()?;
    let expected_type = if expected_directory {
        first_metadata.file_type().is_dir()
    } else {
        first_metadata.file_type().is_file()
    };
    if !expected_type || first_metadata.file_type().is_symlink() {
        return Err(ProfileError::UnsafeState(
            "managed path has an unexpected filesystem type".to_owned(),
        ));
    }

    let acl = macos_acl_for_open_file(file).map_err(|_| {
        ProfileError::UnsafeState("managed path ACL could not be read safely".to_owned())
    })?;
    let stat = rustix::fs::fstat(file)
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    let metadata = file.metadata()?;
    let visible = fs::symlink_metadata(path)?;
    let opened_identity = FileSystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let visible_identity = FileSystemIdentity {
        device: visible.dev(),
        inode: visible.ino(),
    };
    if opened_identity != visible_identity
        || opened_identity != stat_identity(&stat)?
        || first_metadata.dev() != metadata.dev()
        || first_metadata.ino() != metadata.ino()
    {
        return Err(ProfileError::UnsafeState(
            "managed path changed while its permissions were inspected".to_owned(),
        ));
    }

    Ok(MacosOpenedNode {
        metadata,
        stat,
        acl,
    })
}

#[cfg(target_os = "macos")]
fn open_verified_macos_node(
    path: &Path,
    expected_directory: bool,
) -> Result<MacosOpenedNode, ProfileError> {
    use rustix::fs::{Mode, OFlags, open};

    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    if expected_directory {
        flags |= OFlags::DIRECTORY;
    }
    let descriptor = open(path, flags, Mode::empty()).map_err(|_| {
        ProfileError::UnsafeState(
            "managed path could not be opened without following links".to_owned(),
        )
    })?;
    let file = File::from(descriptor);
    inspect_opened_macos_node(&file, path, expected_directory)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn verify_private_directory(path: &Path) -> Result<(), ProfileError> {
    let metadata = fs::symlink_metadata(path)?;
    if !private_directory_metadata_is_safe(&metadata, rustix::process::getuid().as_raw()) {
        return Err(ProfileError::UnsafeState(
            "managed directory type, owner, or mode is unsafe".to_owned(),
        ));
    }
    verify_safe_creation_parent(path)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_private_directory(path: &Path) -> Result<(), ProfileError> {
    let node = open_verified_macos_node(path, true)?;
    if !private_directory_metadata_is_safe(&node.metadata, rustix::process::getuid().as_raw()) {
        return Err(ProfileError::UnsafeState(
            "managed directory type, owner, or mode is unsafe".to_owned(),
        ));
    }
    if !node.acl.is_empty() {
        return Err(ProfileError::UnsafeState(
            "managed path has unsupported extended permissions".to_owned(),
        ));
    }
    verify_deletable_macos_flags_stat(&node.stat)?;
    verify_safe_creation_parent(path)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_acl_options() -> Option<exacl::AclOption> {
    Some(exacl::AclOption::SYMLINK_ACL)
}

#[cfg(target_os = "macos")]
fn clear_inherited_macos_acl(path: &Path) -> Result<(), ProfileError> {
    use std::os::fd::AsFd;

    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|_| {
        ProfileError::UnsafeState(
            "managed directory could not be opened without following links".to_owned(),
        )
    })?;
    let file = File::from(descriptor);
    calcifer_macos_acl::clear_acl(file.as_fd()).map_err(|_| {
        ProfileError::UnsafeState("managed path has unsupported extended permissions".to_owned())
    })?;
    let node = inspect_opened_macos_node(&file, path, true)?;
    if node.acl.is_empty() {
        Ok(())
    } else {
        Err(ProfileError::UnsafeState(
            "managed path has unsupported extended permissions".to_owned(),
        ))
    }
}

#[cfg(not(target_os = "macos"))]
fn clear_inherited_macos_acl(_path: &Path) -> Result<(), ProfileError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_no_extended_macos_acl(path: &Path) -> Result<(), ProfileError> {
    match exacl::getfacl(path, macos_acl_options()) {
        Ok(entries) if entries.is_empty() => Ok(()),
        Ok(_) | Err(_) => Err(ProfileError::UnsafeState(
            "managed path has unsupported extended permissions".to_owned(),
        )),
    }
}

#[cfg(not(target_os = "macos"))]
fn verify_no_extended_macos_acl(_path: &Path) -> Result<(), ProfileError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_parent_acl_entry_is_safe(entry: &calcifer_macos_acl::Entry) -> bool {
    entry.tag == calcifer_macos_acl::TAG_DENY
        && entry.flags & !calcifer_macos_acl::FLAG_INHERITED == 0
        && entry.permissions & !calcifer_macos_acl::PERMISSION_DELETE == 0
}

#[cfg(all(unix, not(target_os = "macos")))]
fn verify_safe_creation_ancestor(directory: &Path, current_uid: u32) -> Result<(), ProfileError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(directory)?;
    let owner_is_trusted = metadata.uid() == 0 || metadata.uid() == current_uid;
    if !owner_is_trusted {
        return Err(ProfileError::UnsafeState(
            "managed path has a replaceable creation ancestor".to_owned(),
        ));
    }
    if metadata.file_type().is_symlink() {
        return Err(ProfileError::UnsafeState(
            "managed path has a symlink creation ancestor".to_owned(),
        ));
    }
    let writable_by_others = metadata.mode() & 0o022 != 0;
    let sticky = metadata.mode() & 0o1000 != 0;
    if !metadata.is_dir() || (writable_by_others && !sticky) {
        return Err(ProfileError::UnsafeState(
            "managed path has a replaceable creation ancestor".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_safe_creation_ancestor(directory: &Path, current_uid: u32) -> Result<(), ProfileError> {
    use std::os::unix::fs::MetadataExt;

    let node = open_verified_macos_node(directory, true)?;
    let owner_is_trusted = node.metadata.uid() == 0 || node.metadata.uid() == current_uid;
    let writable_by_others = node.metadata.mode() & 0o022 != 0;
    let sticky = node.metadata.mode() & 0o1000 != 0;
    if !owner_is_trusted || (writable_by_others && !sticky) {
        return Err(ProfileError::UnsafeState(
            "managed path has a replaceable creation ancestor".to_owned(),
        ));
    }
    verify_safe_macos_creation_parent_flags(&node.stat)?;
    if node.acl.flags != 0
        || node
            .acl
            .entries
            .iter()
            .any(|entry| !macos_parent_acl_entry_is_safe(entry))
    {
        return Err(ProfileError::UnsafeState(
            "managed path creation parent has unsafe extended permissions".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_safe_creation_parent(path: &Path) -> Result<(), ProfileError> {
    let parent = path.parent().ok_or_else(|| {
        ProfileError::UnsafeState("managed path has no creation parent".to_owned())
    })?;
    if !parent.is_absolute() {
        return Err(ProfileError::UnsafeState(
            "managed path creation parent is not absolute".to_owned(),
        ));
    }
    if fs::canonicalize(parent)? != parent {
        return Err(ProfileError::UnsafeState(
            "managed path has a non-canonical creation parent".to_owned(),
        ));
    }
    let current_uid = rustix::process::getuid().as_raw();
    for directory in parent.ancestors() {
        verify_safe_creation_ancestor(directory, current_uid)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_safe_creation_parent(_path: &Path) -> Result<(), ProfileError> {
    Ok(())
}

#[cfg(target_os = "macos")]
// Darwin's benign user flags: nodump, compressed, tracked, hidden; plus the
// benign superuser archive flag. Unknown future flags fail closed. In
// particular, this excludes namespace-affecting opaque, immutable, append,
// reserved no-unlink, datavault, restricted, and system no-unlink flags.
const MACOS_BENIGN_FILE_FLAGS: u32 =
    0x0000_0001 | 0x0000_0020 | 0x0000_0040 | 0x0000_8000 | 0x0001_0000;

#[cfg(target_os = "macos")]
fn verify_safe_macos_creation_parent_flags(stat: &rustix::fs::Stat) -> Result<(), ProfileError> {
    // Append and immutable directory flags can allow child creation while
    // blocking rollback or later unlink. DATAVAULT and RESTRICTED propagate to
    // new vnodes. Unknown future flags therefore fail closed. SF_NOUNLINK is
    // the one parent-only exception because standard macOS temp ancestry uses
    // it and it does not prevent removing children.
    const SF_NOUNLINK: u32 = 0x0010_0000;
    const SAFE_CREATION_PARENT_FLAGS: u32 = MACOS_BENIGN_FILE_FLAGS | SF_NOUNLINK;
    if stat.st_flags & !SAFE_CREATION_PARENT_FLAGS != 0 {
        return Err(ProfileError::UnsafeState(
            "managed path creation parent has restrictive flags".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_deletable_macos_flags_path(path: &Path) -> Result<(), ProfileError> {
    use rustix::fs::{AtFlags, CWD, statat};

    let stat = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)
        .map_err(ProfileError::Io)?;
    verify_deletable_macos_flags_stat(&stat)
}

#[cfg(not(target_os = "macos"))]
fn verify_deletable_macos_flags_path(_path: &Path) -> Result<(), ProfileError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_deletable_macos_flags_stat(stat: &rustix::fs::Stat) -> Result<(), ProfileError> {
    if stat.st_flags & !MACOS_BENIGN_FILE_FLAGS != 0 {
        return Err(ProfileError::UnsafeState(
            "managed path has flags that prevent safe removal".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn verify_deletable_macos_flags_stat(_stat: &rustix::fs::Stat) -> Result<(), ProfileError> {
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
    let mut file = create_new_private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    verify_private_regular_file_handle(path, &file)
}

fn create_new_private_file(path: &Path) -> Result<File, ProfileError> {
    verify_safe_creation_parent(path)?;
    let mut options = private_open_options();
    let file = options.write(true).create_new(true).open(path)?;
    let verification = prepare_new_private_file(path, &file);
    if let Err(error) = verification {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
fn prepare_new_private_file(path: &Path, file: &File) -> Result<(), ProfileError> {
    use std::os::fd::AsFd;

    calcifer_macos_acl::clear_acl(file.as_fd()).map_err(|_| {
        ProfileError::UnsafeState("managed path has unsupported extended permissions".to_owned())
    })?;
    verify_private_regular_file_handle(path, file)
}

#[cfg(not(target_os = "macos"))]
fn prepare_new_private_file(path: &Path, _file: &File) -> Result<(), ProfileError> {
    verify_private_regular_file(path)
}

#[cfg(unix)]
fn open_verified_registry_file(
    path: &Path,
    require_single_link: bool,
) -> Result<File, ProfileError> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{Mode, OFlags, open};

    if require_single_link {
        verify_private_single_link_regular_file(path)?;
    } else {
        verify_private_regular_file(path)?;
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
    .map_err(ProfileError::Io)?;
    let file = File::from(descriptor);

    if require_single_link {
        verify_private_single_link_regular_file(path)?;
    } else {
        verify_private_regular_file(path)?;
    }
    let opened = file.metadata()?;
    let visible = fs::symlink_metadata(path)?;
    if opened.dev() != visible.dev()
        || opened.ino() != visible.ino()
        || (require_single_link && (opened.nlink() != 1 || visible.nlink() != 1))
    {
        return Err(ProfileError::UnsafeState(
            "managed registry changed while it was opened".to_owned(),
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_verified_registry_file(
    path: &Path,
    require_single_link: bool,
) -> Result<File, ProfileError> {
    if require_single_link {
        verify_private_single_link_regular_file(path)?;
    } else {
        verify_private_regular_file(path)?;
    }
    File::open(path).map_err(ProfileError::Io)
}

#[cfg(unix)]
fn open_private_lock_file(path: &Path) -> Result<File, ProfileError> {
    open_verified_private_lock_file(path, true)
}

#[cfg(not(unix))]
fn open_private_lock_file(path: &Path) -> Result<File, ProfileError> {
    let mut options = private_open_options();
    let file = options.read(true).write(true).create(true).open(path)?;
    verify_private_regular_file(path)?;
    Ok(file)
}

#[cfg(unix)]
fn open_existing_private_lock_file(path: &Path) -> Result<File, ProfileError> {
    open_verified_private_lock_file(path, false)
}

#[cfg(unix)]
fn open_verified_private_lock_file(path: &Path, create: bool) -> Result<File, ProfileError> {
    use rustix::fs::{Mode, OFlags, open};

    if create {
        verify_safe_creation_parent(path)?;
    }
    match fs::symlink_metadata(path) {
        Ok(_) => verify_private_single_link_regular_file(path)?,
        Err(error) if create && error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(ProfileError::Io(error)),
    }

    let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if create {
        flags |= OFlags::CREATE;
    }
    let descriptor = open(path, flags, Mode::RUSR | Mode::WUSR).map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            ProfileError::UnsafeState("managed lock path is unsafe".to_owned())
        } else {
            ProfileError::Io(io::Error::from(error))
        }
    })?;
    let file = File::from(descriptor);
    private_lock_file_identity(&file, path)?;
    Ok(file)
}

fn create_durable_profile_lock_files(profile_directory: &Path) -> Result<(), ProfileError> {
    for name in [COORDINATOR_LOCK_FILE, PROVIDER_LOCK_FILE] {
        write_private_file(&profile_directory.join(name), b"")?;
        verify_private_single_link_regular_file(&profile_directory.join(name))?;
    }
    sync_directory(profile_directory)
}

#[cfg(unix)]
fn ensure_profile_lock_durability(
    profile_directory: &Path,
    coordinator: &File,
    provider: &File,
) -> Result<(), ProfileError> {
    ensure_profile_lock_durability_with_sync(
        profile_directory,
        coordinator,
        provider,
        |file| {
            file.sync_all()?;
            Ok(())
        },
        sync_directory,
    )
}

#[cfg(unix)]
fn ensure_profile_lock_durability_with_sync(
    profile_directory: &Path,
    coordinator: &File,
    provider: &File,
    mut sync_file: impl FnMut(&File) -> Result<(), ProfileError>,
    sync_parent: impl FnOnce(&Path) -> Result<(), ProfileError>,
) -> Result<(), ProfileError> {
    let coordinator_path = profile_directory.join(COORDINATOR_LOCK_FILE);
    let provider_path = profile_directory.join(PROVIDER_LOCK_FILE);
    sync_file(coordinator)?;
    sync_file(provider)?;
    let expected_directory = private_directory_identity(profile_directory)?;
    let expected_coordinator = private_lock_file_identity(coordinator, &coordinator_path)?;
    let expected_provider = private_lock_file_identity(provider, &provider_path)?;

    sync_parent(profile_directory)?;

    if private_directory_identity(profile_directory)? != expected_directory
        || private_lock_file_identity(coordinator, &coordinator_path)? != expected_coordinator
        || private_lock_file_identity(provider, &provider_path)? != expected_provider
    {
        return Err(ProfileError::UnsafeState(
            "managed profile lifetime locks changed during durability check".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn private_lock_file_identity(
    file: &File,
    path: &Path,
) -> Result<FileSystemIdentity, ProfileError> {
    use std::os::unix::fs::MetadataExt;

    verify_private_single_link_regular_file(path)?;
    let opened = file.metadata()?;
    let visible = fs::symlink_metadata(path)?;
    let opened_identity = FileSystemIdentity {
        device: opened.dev(),
        inode: opened.ino(),
    };
    let visible_identity = FileSystemIdentity {
        device: visible.dev(),
        inode: visible.ino(),
    };
    if opened_identity != visible_identity
        || !opened.file_type().is_file()
        || opened.uid() != rustix::process::getuid().as_raw()
        || opened.mode() & 0o077 != 0
        || opened.nlink() != 1
    {
        return Err(ProfileError::UnsafeState(
            "managed lock file was replaced".to_owned(),
        ));
    }
    Ok(opened_identity)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_received_provider_lock_ownership(
    provider: &File,
    path: &Path,
) -> Result<(), ProfileError> {
    let probe = open_existing_private_lock_file(path)?;
    match FileExt::try_lock_exclusive(&probe) {
        Ok(()) => {
            // No pre-existing B lock existed. Closing the probe releases the
            // lock it just acquired; the received descriptor is not accepted.
            drop(probe);
            return Err(ProfileError::UnsafeState(
                "received provider descriptor was not already locked".to_owned(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(ProfileError::Io(error)),
    }

    match FileExt::try_lock_exclusive(provider) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(ProfileError::UnsafeState(
            "received provider descriptor does not own the active lock".to_owned(),
        )),
        Err(error) => Err(ProfileError::Io(error)),
    }
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
    let file = open_existing_private_lock_file(path)?;
    FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            ProfileError::Busy(reference.to_owned())
        } else {
            ProfileError::Io(error)
        }
    })?;
    Ok(file)
}

#[cfg(all(unix, not(target_os = "macos")))]
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
    verify_safe_creation_parent(path)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_private_macos_regular_node(node: &MacosOpenedNode) -> Result<(), ProfileError> {
    use std::os::unix::fs::MetadataExt;

    if node.metadata.mode() & 0o077 != 0 {
        return Err(ProfileError::UnsafeState(
            "managed file is accessible by another OS user".to_owned(),
        ));
    }
    if !node.acl.is_empty() {
        return Err(ProfileError::UnsafeState(
            "managed path has unsupported extended permissions".to_owned(),
        ));
    }
    verify_deletable_macos_flags_stat(&node.stat)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_private_regular_file_handle(path: &Path, file: &File) -> Result<(), ProfileError> {
    let node = inspect_opened_macos_node(file, path, false)?;
    verify_private_macos_regular_node(&node)?;
    verify_safe_creation_parent(path)?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn verify_private_regular_file_handle(path: &Path, _file: &File) -> Result<(), ProfileError> {
    verify_private_regular_file(path)
}

#[cfg(target_os = "macos")]
fn verify_private_regular_file(path: &Path) -> Result<(), ProfileError> {
    let node = open_verified_macos_node(path, false)?;
    verify_private_macos_regular_node(&node)?;
    verify_safe_creation_parent(path)?;
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
        let mut file = create_new_private_file(&temporary)?;
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

    #[cfg(unix)]
    #[test]
    fn stat_mode_normalization_is_checked_for_signed_unix_modes()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(normalize_stat_mode(0o700_u16)?, 0o700);
        let error = normalize_stat_mode(-1_i32)
            .err()
            .ok_or("a negative signed Unix mode must fail closed")?;
        assert_eq!(error.code(), "unsafe_profile_state");
        Ok(())
    }

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
        let base = match fs::canonicalize(env::temp_dir()) {
            Ok(base) => base,
            Err(error) => panic!("temporary directory must have a physical path: {error}"),
        };
        base.join(format!(
            "calcifer-{test_name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ))
    }

    #[cfg(unix)]
    #[test]
    fn managed_root_canonicalization_resolves_existing_aliases_and_missing_suffixes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let sandbox = temporary_root("canonical-managed-root");
        secure_create_dir_all(&sandbox)?;
        let target = sandbox.join("physical-target");
        secure_create_dir(&target)?;
        let alias = sandbox.join("managed-root-alias");
        symlink(&target, &alias)?;

        assert_eq!(canonicalize_managed_root(&alias)?, target);
        assert_eq!(
            canonicalize_managed_root(&alias.join("future").join("nested"))?,
            target.join("future").join("nested")
        );

        let dangling = sandbox.join("dangling-managed-root");
        symlink(sandbox.join("missing-target"), &dangling)?;
        let error = canonicalize_managed_root(&dangling)
            .err()
            .ok_or("a dangling managed-root alias must fail closed")?;
        assert_eq!(error.code(), "unsafe_profile_state");

        fs::remove_file(dangling)?;
        fs::remove_file(alias)?;
        fs::remove_dir(target)?;
        fs::remove_dir(sandbox)?;
        Ok(())
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

    #[cfg(target_os = "macos")]
    fn macos_test_acl_options() -> Option<exacl::AclOption> {
        Some(exacl::AclOption::SYMLINK_ACL)
    }

    #[cfg(target_os = "macos")]
    fn clear_macos_test_acl(path: &Path) -> io::Result<()> {
        exacl::setfacl(&[path], &[], macos_test_acl_options())
    }

    #[cfg(target_os = "macos")]
    struct MacosAclCleanup {
        candidates: Vec<PathBuf>,
        armed: bool,
    }

    #[cfg(target_os = "macos")]
    impl MacosAclCleanup {
        fn new(candidates: Vec<PathBuf>) -> Self {
            Self {
                candidates,
                armed: true,
            }
        }

        fn clear(&mut self) -> io::Result<()> {
            let mut first_error = None;
            for path in &self.candidates {
                match fs::symlink_metadata(path) {
                    Ok(_) => {
                        if let Err(error) = clear_macos_test_acl(path) {
                            first_error.get_or_insert(error);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            self.armed = false;
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for MacosAclCleanup {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            for path in &self.candidates {
                if fs::symlink_metadata(path).is_ok() {
                    let _ = clear_macos_test_acl(path);
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    struct MacosFlagCleanup {
        candidates: Vec<PathBuf>,
        clear_flag: &'static str,
        armed: bool,
    }

    #[cfg(target_os = "macos")]
    impl MacosFlagCleanup {
        fn set(
            candidates: Vec<PathBuf>,
            target: &Path,
            set_flag: &'static str,
            clear_flag: &'static str,
        ) -> io::Result<Self> {
            use std::process::Command;

            let guard = Self {
                candidates,
                clear_flag,
                armed: true,
            };
            let status = Command::new("/usr/bin/chflags")
                .arg(set_flag)
                .arg(target)
                .status()?;
            if !status.success() {
                return Err(io::Error::other("could not set the macOS test file flag"));
            }
            Ok(guard)
        }

        fn clear(&mut self) -> io::Result<()> {
            use std::process::Command;

            let mut first_error = None;
            for path in &self.candidates {
                match fs::symlink_metadata(path) {
                    Ok(_) => match Command::new("/usr/bin/chflags")
                        .arg(self.clear_flag)
                        .arg(path)
                        .status()
                    {
                        Ok(status) if status.success() => {}
                        Ok(_) => {
                            first_error.get_or_insert_with(|| {
                                io::Error::other("could not clear the macOS test file flag")
                            });
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    },
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            self.armed = false;
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for MacosFlagCleanup {
        fn drop(&mut self) {
            use std::process::Command;

            if !self.armed {
                return;
            }
            for path in &self.candidates {
                if fs::symlink_metadata(path).is_ok() {
                    let _ = Command::new("/usr/bin/chflags")
                        .arg(self.clear_flag)
                        .arg(path)
                        .status();
                }
            }
        }
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn send_test_lease_frame(
        control: &std::os::unix::net::UnixStream,
        marker: u8,
        descriptors: &[std::os::fd::BorrowedFd<'_>],
    ) -> io::Result<()> {
        use std::io::IoSlice;
        use std::mem::MaybeUninit;

        use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

        if descriptors.is_empty() || descriptors.len() > 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "test lease frame needs one or two descriptors",
            ));
        }
        let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut ancillary_space);
        if !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
            return Err(io::Error::other(
                "test lease descriptors did not fit ancillary buffer",
            ));
        }
        let payload = [marker];
        let slices = [IoSlice::new(&payload)];
        loop {
            match sendmsg(control, &slices, &mut ancillary, SendFlags::empty()) {
                Ok(1) => return Ok(()),
                Ok(_) => return Err(io::Error::other("test lease frame was incomplete")),
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(io::Error::from(error)),
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct LeaseTransferTestChild {
        child: Option<std::process::Child>,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl LeaseTransferTestChild {
        fn spawn(
            role: &str,
            root: &Path,
            profile: &Profile,
            socket_path: Option<&Path>,
            sent_marker: Option<&Path>,
        ) -> io::Result<Self> {
            use std::process::Command;

            let mut command = Command::new(std::env::current_exe()?);
            command
                .args([
                    "--exact",
                    "profiles::tests::provider_lease_cross_process_helper",
                    "--nocapture",
                ])
                .env("CALCIFER_TEST_LEASE_CHILD_ROLE", role)
                .env("CALCIFER_TEST_LEASE_ROOT", root)
                .env("CALCIFER_TEST_LEASE_PROFILE_ID", &profile.id);
            if let Some(socket_path) = socket_path {
                command.env("CALCIFER_TEST_LEASE_SOCKET", socket_path);
            }
            if let Some(sent_marker) = sent_marker {
                command.env("CALCIFER_TEST_LEASE_SENT_MARKER", sent_marker);
            }
            Ok(Self {
                child: Some(command.spawn()?),
            })
        }

        fn child_mut(&mut self) -> io::Result<&mut std::process::Child> {
            self.child
                .as_mut()
                .ok_or_else(|| io::Error::other("lease test child was already reaped"))
        }

        fn kill_and_wait(mut self) -> io::Result<std::process::ExitStatus> {
            let mut child = self
                .child
                .take()
                .ok_or_else(|| io::Error::other("lease test child was already reaped"))?;
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            child.kill()?;
            child.wait()
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl Drop for LeaseTransferTestChild {
        fn drop(&mut self) {
            if let Some(child) = &mut self.child {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct LeaseTransferTestSocket(PathBuf);

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl Drop for LeaseTransferTestSocket {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn accept_lease_transfer_test_child(
        listener: &std::os::unix::net::UnixListener,
        child: &mut LeaseTransferTestChild,
    ) -> io::Result<std::os::unix::net::UnixStream> {
        use std::time::{Duration, Instant};

        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .ok_or_else(|| io::Error::other("lease test deadline overflow"))?;
        loop {
            match listener.accept() {
                Ok((control, _)) => {
                    control.set_nonblocking(false)?;
                    return Ok(control);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            if let Some(status) = child.child_mut()?.try_wait()? {
                return Err(io::Error::other(format!(
                    "lease test child exited before connect: {status}"
                )));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "lease test child did not connect",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn wait_for_lease_transfer_test_marker(
        path: &Path,
        child: &mut LeaseTransferTestChild,
    ) -> io::Result<()> {
        use std::time::{Duration, Instant};

        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .ok_or_else(|| io::Error::other("lease marker deadline overflow"))?;
        loop {
            if path.is_file() {
                return Ok(());
            }
            if let Some(status) = child.child_mut()?.try_wait()? {
                return Err(io::Error::other(format!(
                    "lease test child exited before marker: {status}"
                )));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "lease test child did not publish send marker",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    fn retry_profile_operation_after_exec_boundary<T>(
        mut operation: impl FnMut() -> Result<T, ProfileError>,
    ) -> Result<T, ProfileError> {
        use std::time::{Duration, Instant};

        // CLOEXEC is applied by exec, not fork. A different parallel test may
        // briefly snapshot this process's locked descriptors while its helper
        // child is between those operations. Retry only the post-final-close
        // availability assertion; live-owner exclusion remains immediate, and
        // exact descriptor scans separately reject any post-exec inheritance.
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| ProfileError::Io(io::Error::other("lease retry deadline overflow")))?;
        loop {
            match operation() {
                Err(ProfileError::Busy(_)) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => return result,
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn lock_profile_after_exec_boundary(
        registry: &Registry,
        profile: &Profile,
    ) -> Result<ProfileLease, ProfileError> {
        retry_profile_operation_after_exec_boundary(|| registry.lock_profile(profile))
    }

    #[cfg(unix)]
    fn reserve_target_after_exec_boundary(
        registry: &Registry,
        profile: &Profile,
    ) -> Result<VerifiedTargetReservation, ProfileError> {
        retry_profile_operation_after_exec_boundary(|| {
            registry.reserve_verified_codex_target(profile, |_, _| Ok(test_identity_adapter()))
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn run_lease_transfer_contender(
        root: &Path,
        profile: &Profile,
        expect_busy: bool,
    ) -> io::Result<()> {
        let role = if expect_busy {
            "contender-busy"
        } else {
            "contender-free"
        };
        let child = LeaseTransferTestChild::spawn(role, root, profile, None, None)?;
        let mut child = child;
        let status = child.child_mut()?.wait()?;
        child.child = None;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "lease contender assertion failed: {status}"
            )))
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn send_lease_transfer_test_marker(
        control: &std::os::unix::net::UnixStream,
        marker: u8,
    ) -> Result<(), ProfileError> {
        let flags = provider_lease_send_flags(control)?;
        loop {
            match rustix::net::send(control, &[marker], flags) {
                Ok(1) => return Ok(()),
                Ok(_) => {
                    return Err(ProfileError::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "lease test marker was incomplete",
                    )));
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(ProfileError::Io(io::Error::from(error))),
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn process_lease_descriptor_count(expected: &str) -> io::Result<usize> {
        use std::os::unix::fs::MetadataExt;

        #[cfg(target_os = "linux")]
        let descriptor_directory = Path::new("/proc/self/fd");
        #[cfg(target_os = "macos")]
        let descriptor_directory = Path::new("/dev/fd");

        // Collect first so opening a macOS `/dev/fd/N` entry cannot add a
        // transient descriptor to the directory iteration itself. Unlike
        // Linux procfs, macOS fdescfs reports the mount-node device from path
        // metadata; opening the entry and fstat'ing that file yields the
        // underlying descriptor's exact device and inode.
        let descriptor_paths = fs::read_dir(descriptor_directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        let mut count = 0_usize;
        for descriptor_path in descriptor_paths {
            #[cfg(target_os = "linux")]
            let metadata = fs::metadata(descriptor_path);
            #[cfg(target_os = "macos")]
            let metadata = OpenOptions::new()
                .read(true)
                .open(descriptor_path)
                .and_then(|descriptor| descriptor.metadata());
            match metadata {
                Ok(metadata) if format!("{}:{}", metadata.dev(), metadata.ino()) == expected => {
                    count += 1;
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                    ) => {}
                #[cfg(target_os = "macos")]
                Err(error)
                    if error.raw_os_error() == Some(rustix::io::Errno::NXIO.raw_os_error()) => {}
                Err(error)
                    if error.raw_os_error() == Some(rustix::io::Errno::BADF.raw_os_error()) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(count)
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
            .verify_or_bind_codex_identity(&profile, |_, _| {
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
            .revalidate_codex_identity(&profile, |_, _| Ok(test_identity_adapter()))
            .err()
            .ok_or("legacy profile must remain unverified")?;
        assert_eq!(unverified.code(), "provider_identity_unverified");

        let first =
            registry.verify_or_bind_codex_identity(&profile, |_, _| Ok(test_identity_adapter()))?;
        assert_eq!(first.profile(), &profile);
        drop(first);
        let repeated =
            registry.verify_or_bind_codex_identity(&profile, |_, _| Ok(test_identity_adapter()))?;
        drop(repeated);

        let home = registry.profile_home(&profile)?;
        fs::remove_file(home.join("auth.json"))?;
        let changed_scope = Uuid::new_v4().to_string();
        write_test_codex_auth_for_scope(&home, &changed_scope)?;
        let error = registry
            .revalidate_codex_identity(&profile, |_, _| Ok(test_identity_adapter()))
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
            .verify_or_bind_codex_identity(&second, |_, _| Ok(test_identity_adapter()))
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
            .verify_or_bind_codex_identity(&second, |_, _| Ok(test_identity_adapter()))
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
                        .verify_or_bind_codex_identity(&profile, |_, _| Ok(test_identity_adapter()))
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
            .revalidate_codex_identity(&profile, |_, _| Ok(test_identity_adapter()))
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn provider_lease_cross_process_helper() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let Some(role) = env::var_os("CALCIFER_TEST_LEASE_CHILD_ROLE") else {
            return Ok(());
        };
        let role = role
            .into_string()
            .map_err(|_| "lease child role must be UTF-8")?;
        let root = PathBuf::from(
            env::var_os("CALCIFER_TEST_LEASE_ROOT").ok_or("lease child root is missing")?,
        );
        let profile_id = env::var("CALCIFER_TEST_LEASE_PROFILE_ID")?;
        let registry = Registry::at(root);
        let profile = registry.find_by_id(Provider::Codex, &profile_id)?;

        match role.as_str() {
            "inherited-descriptor-holder" => {
                let expected = env::var("CALCIFER_TEST_LEASE_IDENTITY")?;
                let descriptor_count = process_lease_descriptor_count(&expected)?;
                if descriptor_count != 1 {
                    return Err(format!(
                        "selected child inherited {descriptor_count} provider lease descriptors for {expected}"
                    )
                    .into());
                }
                let marker = PathBuf::from(
                    env::var_os("CALCIFER_TEST_LEASE_SENT_MARKER")
                        .ok_or("inherited descriptor marker is missing")?,
                );
                write_private_file(&marker, b"ready")?;
                let mut release = [0_u8; 1];
                io::stdin().read_exact(&mut release)?;
                Ok(())
            }
            "unrelated-descriptor-child" => {
                let expected = env::var("CALCIFER_TEST_LEASE_IDENTITY")?;
                if process_lease_descriptor_count(&expected)? != 0 {
                    Err("unrelated child inherited the provider lease".into())
                } else {
                    Ok(())
                }
            }
            "coordinator" => {
                let reservation = registry
                    .reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
                let socket_path = PathBuf::from(
                    env::var_os("CALCIFER_TEST_LEASE_SOCKET")
                        .ok_or("lease child socket is missing")?,
                );
                let control = UnixStream::connect(socket_path)?;
                control.set_read_timeout(Some(Duration::from_secs(10)))?;
                let awaiting = reservation
                    .send_provider_lease(&control)
                    .map_err(|failure| (*failure).into_error())?;
                if let Some(sent_marker) = env::var_os("CALCIFER_TEST_LEASE_SENT_MARKER") {
                    write_private_file(&PathBuf::from(sent_marker), b"sent")?;
                }
                let acknowledged = awaiting
                    .receive_ack()
                    .map_err(|failure| (*failure).into_error())?;
                let _coordinator = acknowledged.commit()?;
                send_lease_transfer_test_marker(&control, b'C')?;
                let mut release = [0_u8; 1];
                (&control).read_exact(&mut release)?;
                Ok(())
            }
            "guardian" => {
                let socket_path = PathBuf::from(
                    env::var_os("CALCIFER_TEST_LEASE_SOCKET")
                        .ok_or("lease child socket is missing")?,
                );
                let control = UnixStream::connect(socket_path)?;
                control.set_read_timeout(Some(Duration::from_secs(10)))?;
                let _guardian = registry
                    .receive_profile_provider_lease(&profile, &control)?
                    .send_ack()
                    .map_err(|failure| (*failure).into_error())?;
                send_lease_transfer_test_marker(&control, b'G')?;
                let mut release = [0_u8; 1];
                (&control).read_exact(&mut release)?;
                Ok(())
            }
            "contender-busy" => match registry.lock_profile(&profile) {
                Err(ProfileError::Busy(_)) => Ok(()),
                Ok(lease) => {
                    drop(lease);
                    Err("contender unexpectedly acquired a busy target".into())
                }
                Err(error) => Err(error.into()),
            },
            "contender-free" => {
                drop(lock_profile_after_exec_boundary(&registry, &profile)?);
                Ok(())
            }
            _ => Err("unknown lease child role".into()),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn metadata_probe_inherits_provider_lease_only_in_the_selected_child()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::fd::AsFd;
        use std::os::unix::fs::MetadataExt;
        use std::process::{Command, Stdio};

        use rustix::io::{FdFlags, fcntl_getfd};

        let root = temporary_root("child-only-provider-inheritance");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let lease = registry.lock_profile(&profile)?;
        let provider = lease.provider_lock_file()?;
        let metadata = provider.metadata()?;
        let expected = format!("{}:{}", metadata.dev(), metadata.ino());
        let marker = root.join(format!(".inherited-ready-{}", Uuid::new_v4()));

        assert!(fcntl_getfd(provider)?.contains(FdFlags::CLOEXEC));

        let mut selected_command = Command::new(std::env::current_exe()?);
        selected_command
            .args([
                "--exact",
                "profiles::tests::provider_lease_cross_process_helper",
                "--nocapture",
            ])
            .env(
                "CALCIFER_TEST_LEASE_CHILD_ROLE",
                "inherited-descriptor-holder",
            )
            .env("CALCIFER_TEST_LEASE_ROOT", &root)
            .env("CALCIFER_TEST_LEASE_PROFILE_ID", &profile.id)
            .env("CALCIFER_TEST_LEASE_IDENTITY", &expected)
            .env("CALCIFER_TEST_LEASE_SENT_MARKER", &marker)
            .stdin(Stdio::piped());
        let selected_child =
            calcifer_unix_child_fd::spawn_with_inherited_fd(selected_command, provider.as_fd())?;
        let mut selected_child = LeaseTransferTestChild {
            child: Some(selected_child),
        };
        wait_for_lease_transfer_test_marker(&marker, &mut selected_child)?;

        // The post-fork child clears only its copy. The shared parent table
        // remains close-on-exec for every unrelated concurrent spawn.
        assert!(fcntl_getfd(provider)?.contains(FdFlags::CLOEXEC));
        let mut unrelated = Command::new(std::env::current_exe()?);
        let unrelated_status = unrelated
            .args([
                "--exact",
                "profiles::tests::provider_lease_cross_process_helper",
                "--nocapture",
            ])
            .env(
                "CALCIFER_TEST_LEASE_CHILD_ROLE",
                "unrelated-descriptor-child",
            )
            .env("CALCIFER_TEST_LEASE_ROOT", &root)
            .env("CALCIFER_TEST_LEASE_PROFILE_ID", &profile.id)
            .env("CALCIFER_TEST_LEASE_IDENTITY", &expected)
            .status()?;
        assert!(
            unrelated_status.success(),
            "an unrelated exec must not inherit the provider lease"
        );
        assert!(fcntl_getfd(provider)?.contains(FdFlags::CLOEXEC));

        // Once the parent closes A+B, the selected metadata child is the sole
        // B owner. Its descriptor, not its PID, keeps the target unavailable.
        drop(lease);
        run_lease_transfer_contender(&root, &profile, true)?;

        let child = selected_child.child_mut()?;
        child
            .stdin
            .take()
            .ok_or("selected child stdin is missing")?
            .write_all(b"R")?;
        let status = child.wait()?;
        selected_child.child = None;
        assert!(
            status.success(),
            "selected metadata child must exit cleanly"
        );
        run_lease_transfer_contender(&root, &profile, false)?;

        fs::remove_file(marker)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn metadata_probe_spawn_failure_preserves_parent_lease()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::fd::AsFd;
        use std::process::Command;

        use rustix::io::{FdFlags, fcntl_getfd};

        let root = temporary_root("child-only-provider-spawn-failure");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let lease = registry.lock_profile(&profile)?;
        let provider = lease.provider_lock_file()?;
        let command = Command::new(root.join("missing-provider-executable"));

        let error = calcifer_unix_child_fd::spawn_with_inherited_fd(command, provider.as_fd())
            .err()
            .ok_or("a missing provider executable must fail before launch")?;
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(fcntl_getfd(provider)?.contains(FdFlags::CLOEXEC));
        let busy = registry
            .lock_profile(&profile)
            .err()
            .ok_or("failed child spawn must leave parent A+B authoritative")?;
        assert_eq!(busy.code(), "profile_busy");

        drop(lease);
        drop(lock_profile_after_exec_boundary(&registry, &profile)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn target_identity_resolver_never_makes_parent_lease_inheritable()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt;
        use std::process::Command;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        use rustix::io::{FdFlags, fcntl_getfd};

        let root = temporary_root("target-resolver-child-inheritance-race");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let provider_path = registry
            .profile_directory(&profile)?
            .join(PROVIDER_LOCK_FILE);
        let metadata = fs::metadata(provider_path)?;
        let expected = format!("{}:{}", metadata.dev(), metadata.ino());
        let (reached_tx, reached_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let worker_root = root.clone();
        let worker_profile = profile.clone();

        let worker = thread::spawn(move || {
            let worker_registry = Registry::at(worker_root);
            let reservation = worker_registry.reserve_verified_codex_target(
                &worker_profile,
                |_, provider_lease| {
                    let provider_lease = provider_lease.ok_or_else(|| {
                        ProfileError::Io(io::Error::other(
                            "Unix target resolver did not receive its provider lease",
                        ))
                    })?;
                    let close_on_exec = fcntl_getfd(provider_lease)
                        .map(|flags| flags.contains(FdFlags::CLOEXEC))
                        .map_err(|error| ProfileError::Io(io::Error::from(error)))?;
                    reached_tx.send(close_on_exec).map_err(|_| {
                        ProfileError::Io(io::Error::other(
                            "target resolver race observer disconnected",
                        ))
                    })?;
                    release_rx.recv().map_err(|_| {
                        ProfileError::Io(io::Error::other(
                            "target resolver race release disconnected",
                        ))
                    })?;
                    Ok(test_identity_adapter())
                },
            )?;
            drop(reservation);
            Ok::<(), ProfileError>(())
        });

        let parent_close_on_exec = match reached_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(close_on_exec) => close_on_exec,
            Err(error) => {
                let _ = release_tx.send(());
                let _ = worker.join();
                return Err(error.into());
            }
        };
        let mut unrelated = Command::new(std::env::current_exe()?);
        let unrelated_status = unrelated
            .args([
                "--exact",
                "profiles::tests::provider_lease_cross_process_helper",
                "--nocapture",
            ])
            .env(
                "CALCIFER_TEST_LEASE_CHILD_ROLE",
                "unrelated-descriptor-child",
            )
            .env("CALCIFER_TEST_LEASE_ROOT", &root)
            .env("CALCIFER_TEST_LEASE_PROFILE_ID", &profile.id)
            .env("CALCIFER_TEST_LEASE_IDENTITY", &expected)
            .status();
        let release_result = release_tx.send(());
        let worker_result = worker
            .join()
            .map_err(|_| "target resolver worker panicked")?;
        release_result?;
        worker_result?;
        let unrelated_status = unrelated_status?;

        assert!(
            parent_close_on_exec,
            "the parent provider descriptor must remain close-on-exec during resolution"
        );
        assert!(
            unrelated_status.success(),
            "an unrelated concurrent exec must not inherit the target lease"
        );
        drop(lock_profile_after_exec_boundary(&registry, &profile)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn transferred_provider_lease_survives_real_owner_process_crashes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        use std::time::Duration;

        let root = temporary_root("cross-process-provider-transfer");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;

        // A coordinator child transfers B to this process, commits only after
        // the strict ACK, then is killed and reaped. Its surviving B owner is
        // the sole authority blocking an independent contender process.
        {
            let socket_path = registry.supervisor_socket_path(&profile, &Uuid::new_v4())?;
            let listener = UnixListener::bind(&socket_path)?;
            let socket_cleanup = LeaseTransferTestSocket(socket_path.clone());
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)?;
            let mut child = LeaseTransferTestChild::spawn(
                "coordinator",
                &root,
                &profile,
                Some(&socket_path),
                None,
            )?;
            let mut control = accept_lease_transfer_test_child(&listener, &mut child)?;
            control.set_read_timeout(Some(Duration::from_secs(10)))?;
            let guardian = registry
                .receive_profile_provider_lease(&profile, &control)?
                .send_ack()
                .map_err(|failure| (*failure).into_error())?;
            let mut committed = [0_u8; 1];
            control.read_exact(&mut committed)?;
            assert_eq!(committed, [b'C']);
            let status = child.kill_and_wait()?;
            assert!(!status.success(), "coordinator child must be killed");

            run_lease_transfer_contender(&root, &profile, true)?;
            drop(guardian);
            run_lease_transfer_contender(&root, &profile, false)?;
            drop(control);
            drop(listener);
            drop(socket_cleanup);
        }

        // If the coordinator dies after sendmsg but before the guardian reads
        // or ACKs B, the descriptor queued in the kernel still owns the exact
        // locked open-file description. There is no unlock window between the
        // dead sender and the eventual guardian receive.
        {
            let sent_marker = root.join(format!(".lease-sent-{}", Uuid::new_v4()));
            let socket_path = registry.supervisor_socket_path(&profile, &Uuid::new_v4())?;
            let listener = UnixListener::bind(&socket_path)?;
            let socket_cleanup = LeaseTransferTestSocket(socket_path.clone());
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)?;
            let mut child = LeaseTransferTestChild::spawn(
                "coordinator",
                &root,
                &profile,
                Some(&socket_path),
                Some(&sent_marker),
            )?;
            let control = accept_lease_transfer_test_child(&listener, &mut child)?;
            wait_for_lease_transfer_test_marker(&sent_marker, &mut child)?;
            let status = child.kill_and_wait()?;
            assert!(
                !status.success(),
                "pre-ACK coordinator child must be killed"
            );

            run_lease_transfer_contender(&root, &profile, true)?;
            let guardian = registry.receive_profile_provider_lease(&profile, &control)?;
            run_lease_transfer_contender(&root, &profile, true)?;
            drop(guardian);
            drop(control);
            run_lease_transfer_contender(&root, &profile, false)?;

            fs::remove_file(sent_marker)?;
            drop(listener);
            drop(socket_cleanup);
        }

        // A guardian child receives and ACKs B. After it is killed and reaped,
        // the parent coordinator's A remains sufficient to block an
        // independent contender until the exact A descriptor is closed.
        {
            let reservation = registry
                .reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
            let socket_path = registry.supervisor_socket_path(&profile, &Uuid::new_v4())?;
            let listener = UnixListener::bind(&socket_path)?;
            let socket_cleanup = LeaseTransferTestSocket(socket_path.clone());
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)?;
            let mut child = LeaseTransferTestChild::spawn(
                "guardian",
                &root,
                &profile,
                Some(&socket_path),
                None,
            )?;
            let mut control = accept_lease_transfer_test_child(&listener, &mut child)?;
            control.set_read_timeout(Some(Duration::from_secs(10)))?;
            let awaiting = reservation
                .send_provider_lease(&control)
                .map_err(|failure| (*failure).into_error())?;
            let acknowledged = awaiting
                .receive_ack()
                .map_err(|failure| (*failure).into_error())?;
            let coordinator = acknowledged.commit()?;
            let mut guardian_ready = [0_u8; 1];
            control.read_exact(&mut guardian_ready)?;
            assert_eq!(guardian_ready, [b'G']);
            let status = child.kill_and_wait()?;
            assert!(!status.success(), "guardian child must be killed");

            run_lease_transfer_contender(&root, &profile, true)?;
            drop(coordinator);
            run_lease_transfer_contender(&root, &profile, false)?;
            drop(control);
            drop(listener);
            drop(socket_cleanup);
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn transferred_provider_lease_survives_coordinator_release_without_a_reacquire_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::net::UnixStream;

        let root = temporary_root("transferred-provider-survives-coordinator");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let (sender, receiver) = UnixStream::pair()?;

        let sent = reservation
            .send_provider_lease(&sender)
            .map_err(|failure| (*failure).into_error())?;
        #[cfg(target_os = "macos")]
        assert!(rustix::net::sockopt::socket_nosigpipe(&sender)?);
        let guardian = registry
            .receive_profile_provider_lease(&profile, &receiver)?
            .send_ack()
            .map_err(|failure| (*failure).into_error())?;
        let acknowledged = sent
            .receive_ack()
            .map_err(|failure| (*failure).into_error())?;
        let coordinator = acknowledged.commit()?;

        drop(coordinator);
        let error = registry
            .lock_profile(&profile)
            .err()
            .ok_or("the guardian provider lease must block a second reservation")?;
        assert_eq!(error.code(), "profile_busy");

        drop(guardian);
        drop(lock_profile_after_exec_boundary(&registry, &profile)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn transferred_provider_lease_and_coordinator_each_block_a_second_reservation()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::net::UnixStream;

        let root = temporary_root("transferred-provider-split-ownership");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let (sender, receiver) = UnixStream::pair()?;

        let sent = reservation
            .send_provider_lease(&sender)
            .map_err(|failure| (*failure).into_error())?;
        let guardian = registry
            .receive_profile_provider_lease(&profile, &receiver)?
            .send_ack()
            .map_err(|failure| (*failure).into_error())?;
        let acknowledged = sent
            .receive_ack()
            .map_err(|failure| (*failure).into_error())?;
        let coordinator = acknowledged.commit()?;

        drop(guardian);
        let error = registry
            .lock_profile(&profile)
            .err()
            .ok_or("the coordinator lease must block a second reservation")?;
        assert_eq!(error.code(), "profile_busy");

        drop(coordinator);
        drop(lock_profile_after_exec_boundary(&registry, &profile)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn unacknowledged_provider_lease_transfer_keeps_the_parent_reservation()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::net::UnixStream;

        let root = temporary_root("unacknowledged-provider-transfer");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let (sender, receiver) = UnixStream::pair()?;

        let sent = reservation
            .send_provider_lease(&sender)
            .map_err(|failure| (*failure).into_error())?;
        let guardian = registry.receive_profile_provider_lease(&profile, &receiver)?;
        drop(guardian);

        let error = registry
            .lock_profile(&profile)
            .err()
            .ok_or("a failed ACK must leave the complete reservation with the parent")?;
        assert_eq!(error.code(), "profile_busy");

        drop(sent);
        drop(lock_profile_after_exec_boundary(&registry, &profile)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn guardian_lease_survives_sender_cleanup_when_the_ack_is_lost()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::net::UnixStream;

        let root = temporary_root("lost-ack-sender-cleanup");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let (sender, receiver) = UnixStream::pair()?;

        let sent = reservation
            .send_provider_lease(&sender)
            .map_err(|failure| (*failure).into_error())?;
        let guardian = registry.receive_profile_provider_lease(&profile, &receiver)?;
        drop(sent);

        let error = registry
            .lock_profile(&profile)
            .err()
            .ok_or("sender cleanup must not unlock the guardian's shared lock")?;
        assert_eq!(error.code(), "profile_busy");

        drop(guardian);
        drop(lock_profile_after_exec_boundary(&registry, &profile)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn invalid_guardian_ack_preserves_the_awaiting_target_reservation()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::net::UnixStream;

        let root = temporary_root("invalid-provider-lease-ack");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let (sender, receiver) = UnixStream::pair()?;
        let awaiting = reservation
            .send_provider_lease(&sender)
            .map_err(|failure| (*failure).into_error())?;
        let guardian = registry.receive_profile_provider_lease(&profile, &receiver)?;

        assert_eq!(
            rustix::net::send(
                &receiver,
                &[PROVIDER_LEASE_ACK_MARKER ^ 0xff],
                provider_lease_send_flags(&receiver)?,
            )?,
            1
        );
        let failure = awaiting
            .receive_ack()
            .err()
            .ok_or("an invalid ACK must not authorize sender commit")?;
        let (awaiting, error) = (*failure).into_parts();
        assert_eq!(error.code(), "unsafe_profile_state");
        let busy = registry
            .lock_profile(&profile)
            .err()
            .ok_or("invalid ACK must preserve the complete target reservation")?;
        assert_eq!(busy.code(), "profile_busy");

        drop(guardian);
        drop(awaiting);
        drop(lock_profile_after_exec_boundary(&registry, &profile)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn guardian_ack_send_failure_preserves_provisional_provider_ownership()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::net::UnixStream;

        let root = temporary_root("provider-lease-ack-send-failure");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let (sender, receiver) = UnixStream::pair()?;
        let awaiting = reservation
            .send_provider_lease(&sender)
            .map_err(|failure| (*failure).into_error())?;
        let guardian = registry.receive_profile_provider_lease(&profile, &receiver)?;
        drop(awaiting);
        drop(sender);

        let failure = guardian
            .send_ack()
            .err()
            .ok_or("ACK to a closed read side must fail")?;
        let (guardian, error) = (*failure).into_parts();
        assert_eq!(error.code(), "io_error");
        let busy = registry
            .lock_profile(&profile)
            .err()
            .ok_or("provisional guardian B must survive sender cleanup")?;
        assert_eq!(busy.code(), "profile_busy");

        drop(guardian);
        drop(lock_profile_after_exec_boundary(&registry, &profile)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn received_provider_lease_is_non_inheritable_and_bound_to_the_target()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::net::UnixStream;
        use std::process::Command;

        use rustix::io::{FdFlags, fcntl_getfd};

        let root = temporary_root("received-provider-cloexec");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let (sender, receiver) = UnixStream::pair()?;

        let sent = reservation
            .send_provider_lease(&sender)
            .map_err(|failure| (*failure).into_error())?;
        let guardian = registry.receive_profile_provider_lease(&profile, &receiver)?;
        let provider = guardian
            .guardian
            .lease
            .provider
            .as_ref()
            .ok_or("received guardian lease must own the provider descriptor")?;
        assert!(fcntl_getfd(provider)?.contains(FdFlags::CLOEXEC));
        assert_eq!(guardian.guardian.profile(), &profile);
        let metadata = provider.metadata()?;
        let inherited = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "profiles::tests::provider_lease_descriptor_is_closed_across_exec",
            ])
            .env(
                "CALCIFER_TEST_LEASE_IDENTITY",
                format!("{}:{}", metadata.dev(), metadata.ino()),
            )
            .status()?;
        assert!(
            inherited.success(),
            "an exec child must not inherit the guardian lease descriptor"
        );

        drop(sent);
        drop(guardian);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn provider_lease_descriptor_is_closed_across_exec() -> Result<(), Box<dyn std::error::Error>> {
        let Some(expected) = env::var_os("CALCIFER_TEST_LEASE_IDENTITY") else {
            return Ok(());
        };
        let expected = expected
            .into_string()
            .map_err(|_| "test lease identity must be UTF-8")?;
        assert_eq!(
            process_lease_descriptor_count(&expected)?,
            0,
            "a provider lease descriptor survived exec"
        );
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn provider_lease_receiver_rejects_a_different_lock_descriptor()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixStream;

        let root = temporary_root("provider-transfer-wrong-lock");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let coordinator = reservation
            .lease
            .coordinator
            .as_ref()
            .ok_or("verified reservation must own the coordinator lock")?;
        let (sender, receiver) = UnixStream::pair()?;

        send_test_lease_frame(
            &sender,
            PROVIDER_LEASE_TRANSFER_MARKER,
            &[coordinator.as_fd()],
        )?;
        let error = registry
            .receive_profile_provider_lease(&profile, &receiver)
            .err()
            .ok_or("the coordinator descriptor must not be accepted as provider authority")?;
        assert_eq!(error.code(), "unsafe_profile_state");

        drop(reservation);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn provider_lease_receiver_rejects_an_unlocked_reopen_of_the_same_file()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixStream;

        let root = temporary_root("provider-transfer-unlocked-reopen");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let reopened =
            open_existing_private_lock_file(&profile_directory.join(PROVIDER_LOCK_FILE))?;
        let (sender, receiver) = UnixStream::pair()?;

        send_test_lease_frame(&sender, PROVIDER_LEASE_TRANSFER_MARKER, &[reopened.as_fd()])?;
        let error = registry
            .receive_profile_provider_lease(&profile, &receiver)
            .err()
            .ok_or("an unlocked descriptor must not become guardian authority")?;
        assert_eq!(error.code(), "unsafe_profile_state");

        drop(reopened);
        drop(reservation);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn provider_lease_receiver_rejects_a_replaced_visible_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::net::UnixStream;

        let root = temporary_root("provider-transfer-replaced-lock");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let provider_path = profile_directory.join(PROVIDER_LOCK_FILE);
        let displaced_path = profile_directory.join("provider.lock.displaced");
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let (sender, receiver) = UnixStream::pair()?;
        let sent = reservation
            .send_provider_lease(&sender)
            .map_err(|failure| (*failure).into_error())?;

        fs::rename(&provider_path, &displaced_path)?;
        write_private_file(&provider_path, b"")?;
        let error = registry
            .receive_profile_provider_lease(&profile, &receiver)
            .err()
            .ok_or("a descriptor for the displaced lock must fail closed")?;
        assert_eq!(error.code(), "unsafe_profile_state");

        drop(sent);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn provider_lease_receiver_rejects_malformed_and_multiple_descriptor_frames()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixStream;

        for case in ["wrong-marker", "missing-descriptor", "multiple-descriptors"] {
            let root = temporary_root(case);
            let registry = Registry::at(root.clone());
            let profile = register_test_profile(&registry, "work")?;
            let reservation = registry
                .reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
            let provider = reservation
                .lease
                .provider
                .as_ref()
                .ok_or("verified reservation must own the provider lock")?;
            let coordinator = reservation
                .lease
                .coordinator
                .as_ref()
                .ok_or("verified reservation must own the coordinator lock")?;
            let (mut sender, receiver) = UnixStream::pair()?;

            match case {
                "wrong-marker" => send_test_lease_frame(
                    &sender,
                    PROVIDER_LEASE_TRANSFER_MARKER ^ 0xff,
                    &[provider.as_fd()],
                )?,
                "missing-descriptor" => {
                    sender.write_all(&[PROVIDER_LEASE_TRANSFER_MARKER])?;
                }
                "multiple-descriptors" => send_test_lease_frame(
                    &sender,
                    PROVIDER_LEASE_TRANSFER_MARKER,
                    &[provider.as_fd(), coordinator.as_fd()],
                )?,
                _ => return Err("unknown malformed transfer test case".into()),
            }
            let error = registry
                .receive_profile_provider_lease(&profile, &receiver)
                .err()
                .ok_or("a malformed transfer frame must fail closed")?;
            assert_eq!(error.code(), "unsafe_profile_state", "case: {case}");

            drop(reservation);
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn provider_lease_send_failure_returns_the_complete_target_reservation()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::net::UnixStream;

        let root = temporary_root("provider-transfer-send-failure");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let reservation =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let (sender, receiver) = UnixStream::pair()?;
        drop(receiver);

        let failure = reservation
            .send_provider_lease(&sender)
            .err()
            .ok_or("sending to a closed guardian socket must fail")?;
        let (reservation, error) = (*failure).into_parts();
        assert_eq!(error.code(), "io_error");
        let busy = registry
            .lock_profile(&profile)
            .err()
            .ok_or("send failure must preserve both target locks")?;
        assert_eq!(busy.code(), "profile_busy");

        drop(reservation);
        drop(lock_profile_after_exec_boundary(&registry, &profile)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn verified_target_reservation_has_a_single_nonblocking_winner()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::{AtomicBool, Ordering};

        let root = temporary_root("exclusive-verified-target-reservation");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let first =
            registry.reserve_verified_codex_target(&profile, |_, _| Ok(test_identity_adapter()))?;
        let losing_probe_ran = AtomicBool::new(false);

        let error = registry
            .reserve_verified_codex_target(&profile, |_, _| {
                losing_probe_ran.store(true, Ordering::SeqCst);
                Ok(test_identity_adapter())
            })
            .err()
            .ok_or("a second target reservation must lose without blocking")?;
        assert_eq!(error.code(), "profile_busy");
        assert!(!losing_probe_ran.load(Ordering::SeqCst));

        drop(first);
        drop(reserve_target_after_exec_boundary(&registry, &profile)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn verified_target_reservation_refetches_the_alias_after_rename_wins()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("target-reservation-after-rename");
        let registry = Registry::at(root.clone());
        let stale = register_test_profile(&registry, "work")?;
        let (renamed, _) = registry.rename(Provider::Codex, "work", "personal")?;

        let reservation = reserve_target_after_exec_boundary(&registry, &stale)?;
        assert_eq!(reservation.profile(), &renamed);

        drop(reservation);
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
            RemovalFault::BarrierTemporaryCreate,
            RemovalFault::BarrierWrite,
            RemovalFault::BarrierFileSync,
            RemovalFault::BarrierAtomicRename,
            RemovalFault::BarrierDirectorySync,
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
    fn transient_v2_barrier_blocks_alpha4_and_restores_exact_v1_without_a_sidecar()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("removal-v2-barrier");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let stable_before = fs::read(root.join(REGISTRY_FILE))?;
        let stable_document: RegistryDocument = serde_json::from_slice(&stable_before)?;
        assert_eq!(stable_document.schema_version, 1);

        let faulting =
            Registry::at_with_removal_fault(root.clone(), RemovalFault::JournalTemporaryCreate);
        assert!(faulting.remove(Provider::Codex, "work", None).is_err());
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
        assert!(registry.profile_path(&profile)?.is_dir());

        let barrier_bytes = fs::read(root.join(REGISTRY_FILE))?;
        assert!(
            serde_json::from_slice::<RegistryDocument>(&barrier_bytes).is_err(),
            "the published alpha.4 v1 reader must fail closed on the transient v2 barrier"
        );
        let RegistryState::RemovalBarrier(barrier) = registry.read_registry_state()? else {
            return Err("Calcifer must recognize its self-contained v2 barrier".into());
        };
        assert_eq!(barrier.expected_registry, stable_document);

        registry.recover_incomplete_removal()?;
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, stable_before);
        assert_eq!(registry.list()?, vec![profile]);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_barrier_validation_is_strict_bounded_and_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        for case in [
            "truncated",
            "unknown-field",
            "registry-mismatch",
            "embedded-schema",
            "oversized",
        ] {
            let root = temporary_root("removal-invalid-v2-barrier");
            let registry = Registry::at(root.clone());
            let profile = register_test_profile(&registry, "work")?;
            let profile_directory = registry.profile_path(&profile)?;
            let auth_path = profile_directory.join("home/auth.json");
            let auth_before = fs::read(&auth_path)?;
            let faulting =
                Registry::at_with_removal_fault(root.clone(), RemovalFault::JournalTemporaryCreate);
            assert!(faulting.remove(Provider::Codex, "work", None).is_err());

            let barrier_path = root.join(REGISTRY_FILE);
            let barrier_bytes = fs::read(&barrier_path)?;
            let private_sentinel = "private-barrier-sentinel@example.invalid";
            let invalid = match case {
                "truncated" => barrier_bytes[..barrier_bytes.len() - 1].to_vec(),
                "unknown-field" => {
                    let mut value: serde_json::Value = serde_json::from_slice(&barrier_bytes)?;
                    value["unexpected"] = serde_json::Value::String(private_sentinel.to_owned());
                    serde_json::to_vec_pretty(&value)?
                }
                "registry-mismatch" => {
                    let mut barrier: RemovalRegistryBarrier =
                        serde_json::from_slice(&barrier_bytes)?;
                    barrier.expected_registry.profiles[0].alias = private_sentinel.to_owned();
                    serde_json::to_vec_pretty(&barrier)?
                }
                "embedded-schema" => {
                    let mut barrier: RemovalRegistryBarrier =
                        serde_json::from_slice(&barrier_bytes)?;
                    barrier.expected_registry.schema_version =
                        REMOVAL_REGISTRY_BARRIER_SCHEMA_VERSION;
                    barrier.removal.expected_registry_digest =
                        registry_digest(&barrier.expected_registry)?;
                    let mut removed = barrier.expected_registry.clone();
                    removed
                        .profiles
                        .retain(|candidate| candidate.id != barrier.removal.profile.id);
                    barrier.removal.removed_registry_digest = registry_digest(&removed)?;
                    serde_json::to_vec_pretty(&barrier)?
                }
                "oversized" => {
                    let mut bytes = barrier_bytes;
                    bytes.resize(MAX_REMOVAL_REGISTRY_BARRIER_BYTES + 1, b' ');
                    bytes
                }
                _ => return Err("unknown barrier fixture".into()),
            };
            fs::write(&barrier_path, invalid)?;

            let error = registry
                .recover_incomplete_removal()
                .err()
                .ok_or("invalid barrier must fail recovery")?;
            assert!(
                matches!(
                    error.code(),
                    "invalid_registry" | "removal_recovery_required"
                ),
                "{case}: {}",
                error.code()
            );
            assert!(!error.safe_message().contains(private_sentinel), "{case}");
            assert!(!error.to_string().contains(private_sentinel), "{case}");
            assert!(profile_directory.is_dir(), "{case}");
            assert_eq!(fs::read(&auth_path)?, auth_before, "{case}");
            assert!(!root.join(REMOVAL_JOURNAL_FILE).exists(), "{case}");

            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_barrier_reader_has_a_separate_bounded_size_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("removal-large-v2-barrier");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let stable_before = fs::read(root.join(REGISTRY_FILE))?;
        let faulting =
            Registry::at_with_removal_fault(root.clone(), RemovalFault::JournalTemporaryCreate);
        assert!(faulting.remove(Provider::Codex, "work", None).is_err());

        let barrier_path = root.join(REGISTRY_FILE);
        let mut padded = fs::read(&barrier_path)?;
        padded.resize(MAX_REGISTRY_BYTES + 1, b' ');
        assert!(padded.len() < MAX_REMOVAL_REGISTRY_BARRIER_BYTES);
        fs::write(&barrier_path, padded)?;
        assert!(matches!(
            registry.read_registry_state()?,
            RegistryState::RemovalBarrier(_)
        ));

        registry.recover_incomplete_removal()?;
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, stable_before);
        assert_eq!(registry.list()?, vec![profile]);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_recovery_rejects_a_mismatched_sidecar_and_hard_linked_registry()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("removal-mismatched-sidecar");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_path(&profile)?;
        let auth_path = profile_directory.join("home/auth.json");
        let auth_before = fs::read(&auth_path)?;
        let faulting = Registry::at_with_removal_fault(root.clone(), RemovalFault::TombstoneRename);
        assert!(faulting.remove(Provider::Codex, "work", None).is_err());

        let sidecar_path = root.join(REMOVAL_JOURNAL_FILE);
        let mut sidecar: RemovalJournal = serde_json::from_slice(&fs::read(&sidecar_path)?)?;
        sidecar.expected_registry_digest = "0".repeat(64);
        fs::write(&sidecar_path, serde_json::to_vec_pretty(&sidecar)?)?;
        let error = registry
            .recover_incomplete_removal()
            .err()
            .ok_or("mismatched sidecar must fail recovery")?;
        assert_eq!(error.code(), "removal_recovery_required");
        assert!(profile_directory.is_dir());
        assert_eq!(fs::read(&auth_path)?, auth_before);
        fs::remove_dir_all(root)?;

        let root = temporary_root("removal-hard-linked-registry");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let faulting =
            Registry::at_with_removal_fault(root.clone(), RemovalFault::RecursiveCleanup);
        assert!(faulting.remove(Provider::Codex, "work", None).is_err());
        let tombstone = root
            .join("profiles/codex")
            .join(format!(".removing-{}", profile.id));
        let auth_path = tombstone.join("home/auth.json");
        let auth_before = fs::read(&auth_path)?;
        fs::hard_link(root.join(REGISTRY_FILE), root.join("registry-hard-link"))?;

        let error = registry
            .recover_incomplete_removal()
            .err()
            .ok_or("hard-linked registry must fail recovery")?;
        assert_eq!(error.code(), "removal_recovery_required");
        assert!(tombstone.is_dir());
        assert_eq!(fs::read(&auth_path)?, auth_before);
        assert!(root.join(REMOVAL_JOURNAL_FILE).is_file());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_recovery_never_treats_a_missing_registry_as_an_empty_registry()
    -> Result<(), Box<dyn std::error::Error>> {
        for fault in [
            RemovalFault::RegistryAtomicRename,
            RemovalFault::RecursiveCleanup,
        ] {
            let root = temporary_root("removal-missing-registry");
            let registry = Registry::at(root.clone());
            let profile = register_test_profile(&registry, "work")?;
            let faulting = Registry::at_with_removal_fault(root.clone(), fault);
            assert!(faulting.remove(Provider::Codex, "work", None).is_err());
            let tombstone = root
                .join("profiles/codex")
                .join(format!(".removing-{}", profile.id));
            let auth_before = fs::read(tombstone.join("home/auth.json"))?;
            assert!(root.join(REMOVAL_JOURNAL_FILE).is_file());

            fs::remove_file(root.join(REGISTRY_FILE))?;
            let error = registry
                .recover_incomplete_removal()
                .err()
                .ok_or("missing registry must fail recovery")?;

            assert_eq!(error.code(), "removal_recovery_required", "{fault:?}");
            assert!(tombstone.is_dir(), "{fault:?}");
            assert_eq!(
                fs::read(tombstone.join("home/auth.json"))?,
                auth_before,
                "{fault:?} must preserve credentials"
            );
            assert!(root.join(REMOVAL_JOURNAL_FILE).is_file(), "{fault:?}");
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn post_visibility_recovery_preserves_alpha4_unrelated_registry_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("removal-postvisibility-alpha4-mutation");
        let registry = Registry::at(root.clone());
        let removed = register_test_profile(&registry, "work")?;
        let retained = register_test_profile(&registry, "personal")?;
        let faulting =
            Registry::at_with_removal_fault(root.clone(), RemovalFault::RecursiveCleanup);
        assert!(faulting.remove(Provider::Codex, "work", None).is_err());

        let RegistryState::Stable(mut alpha4_document) = registry.read_registry_state()? else {
            return Err("post-visibility registry must be stable v1".into());
        };
        assert!(
            alpha4_document
                .profiles
                .iter()
                .all(|profile| profile.id != removed.id)
        );
        alpha4_document
            .profiles
            .iter_mut()
            .find(|profile| profile.id == retained.id)
            .ok_or("retained profile missing")?
            .alias = "client".to_owned();
        let alpha4_bytes = serde_json::to_vec_pretty(&alpha4_document)?;
        fs::write(root.join(REGISTRY_FILE), &alpha4_bytes)?;
        File::open(root.join(REGISTRY_FILE))?.sync_all()?;
        sync_directory(&root)?;

        registry.recover_incomplete_removal()?;

        let profiles = registry.list()?;
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id, retained.id);
        assert_eq!(profiles[0].alias, "client");
        assert!(!registry.profile_path(&removed)?.exists());
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
        fs::remove_dir_all(root)?;
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
            let RegistryState::RemovalBarrier(barrier) = registry.read_registry_state()? else {
                return Err("pre-visibility removal must retain its v2 registry barrier".into());
            };
            assert_eq!(
                serde_json::to_vec_pretty(&barrier.expected_registry)?,
                registry_before
            );

            registry.recover_incomplete_removal()?;
            assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);
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
    fn registration_stages_both_lifetime_locks_before_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("registration-durable-locks");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;

        for name in [COORDINATOR_LOCK_FILE, PROVIDER_LOCK_FILE] {
            verify_private_single_link_regular_file(&pending.staging.join(name))?;
        }

        pending.abort()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn legacy_lock_creation_is_durable_before_removal_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("legacy-durable-locks");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        for name in [COORDINATOR_LOCK_FILE, PROVIDER_LOCK_FILE] {
            fs::remove_file(profile_directory.join(name))?;
        }

        let lease = registry.lock_profile(&profile)?;
        for name in [COORDINATOR_LOCK_FILE, PROVIDER_LOCK_FILE] {
            verify_private_single_link_regular_file(&profile_directory.join(name))?;
        }
        let roots = registry.validate_removal_roots(None)?;
        validate_owned_removal_tree(&root, &roots, &profile_directory, &profile.id, None)?;
        drop(lease);

        assert_eq!(registry.remove(Provider::Codex, "work", None)?, profile);
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn lifetime_lock_directory_sync_failure_stops_before_removal_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("lock-sync-failure");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let coordinator = lock_profile_file(
            &profile_directory.join(COORDINATOR_LOCK_FILE),
            &profile.reference(),
        )?;
        let provider = lock_profile_file(
            &profile_directory.join(PROVIDER_LOCK_FILE),
            &profile.reference(),
        )?;
        let registry_before = fs::read(root.join(REGISTRY_FILE))?;

        let error = ensure_profile_lock_durability_with_sync(
            &profile_directory,
            &coordinator,
            &provider,
            |file| {
                file.sync_all()?;
                Ok(())
            },
            |_| {
                Err(ProfileError::Io(io::Error::other(
                    "injected directory sync failure",
                )))
            },
        )
        .err()
        .ok_or("lock directory sync failure must stop removal preparation")?;

        assert_eq!(error.code(), "io_error");
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);
        assert!(profile_directory.is_dir());
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
        assert!(registry.removal_tombstones()?.is_empty());

        drop(provider);
        drop(coordinator);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn lifetime_lock_file_syncs_precede_directory_sync_and_fail_before_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::cell::{Cell, RefCell};

        let root = temporary_root("lock-sync-order");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let coordinator = lock_profile_file(
            &profile_directory.join(COORDINATOR_LOCK_FILE),
            &profile.reference(),
        )?;
        let provider = lock_profile_file(
            &profile_directory.join(PROVIDER_LOCK_FILE),
            &profile.reference(),
        )?;

        let events = RefCell::new(Vec::new());
        ensure_profile_lock_durability_with_sync(
            &profile_directory,
            &coordinator,
            &provider,
            |_| {
                events.borrow_mut().push("file");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("directory");
                Ok(())
            },
        )?;
        assert_eq!(events.borrow().as_slice(), ["file", "file", "directory"]);

        for fail_on_call in [1_u8, 2] {
            let calls = Cell::new(0_u8);
            let directory_sync_called = Cell::new(false);
            let error = ensure_profile_lock_durability_with_sync(
                &profile_directory,
                &coordinator,
                &provider,
                |_| {
                    let next = calls.get().checked_add(1).ok_or_else(|| {
                        ProfileError::UnsafeState("test sync counter overflowed".to_owned())
                    })?;
                    calls.set(next);
                    if next == fail_on_call {
                        return Err(ProfileError::Io(io::Error::other(
                            "injected lock file sync failure",
                        )));
                    }
                    Ok(())
                },
                |_| {
                    directory_sync_called.set(true);
                    Ok(())
                },
            )
            .err()
            .ok_or("lock file sync failure must stop durability preparation")?;
            assert_eq!(error.code(), "io_error");
            assert!(!directory_sync_called.get());
            assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
            assert!(registry.removal_tombstones()?.is_empty());
        }

        drop(provider);
        drop(coordinator);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_rejects_hard_link_writable_mode_and_marker_attacks_before_journaling()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        for attack in [
            "hard-link",
            "file-mode",
            "directory-mode",
            "marker",
            "marker-symlink",
            "coordinator-lock-symlink",
            "provider-lock-symlink",
        ] {
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
                "hard-link" => {
                    fs::remove_file(&auth)?;
                    fs::hard_link(&outside, &auth)?;
                }
                "file-mode" => {
                    fs::set_permissions(&auth, fs::Permissions::from_mode(0o666))?;
                }
                "directory-mode" => {
                    fs::set_permissions(
                        profile_directory.join("home"),
                        fs::Permissions::from_mode(0o555),
                    )?;
                }
                "marker" => {
                    fs::write(profile_directory.join(OWNER_MARKER), b"wrong-local-id")?;
                }
                "marker-symlink" => {
                    fs::remove_file(profile_directory.join(OWNER_MARKER))?;
                    symlink(&outside, profile_directory.join(OWNER_MARKER))?;
                }
                "coordinator-lock-symlink" => {
                    fs::remove_file(profile_directory.join(COORDINATOR_LOCK_FILE))?;
                    symlink(&outside, profile_directory.join(COORDINATOR_LOCK_FILE))?;
                }
                "provider-lock-symlink" => {
                    fs::remove_file(profile_directory.join(PROVIDER_LOCK_FILE))?;
                    symlink(&outside, profile_directory.join(PROVIDER_LOCK_FILE))?;
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

            if attack == "directory-mode" {
                fs::set_permissions(
                    profile_directory.join("home"),
                    fs::Permissions::from_mode(0o700),
                )?;
            }
            fs::remove_dir_all(root)?;
            fs::remove_file(outside)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_never_creates_dangling_lifetime_lock_targets()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        for lock_name in [COORDINATOR_LOCK_FILE, PROVIDER_LOCK_FILE] {
            let root = temporary_root("remove-dangling-lock-target");
            let registry = Registry::at(root.clone());
            let profile = register_test_profile(&registry, "work")?;
            let profile_directory = registry.profile_directory(&profile)?;
            let lock_path = profile_directory.join(lock_name);
            fs::remove_file(&lock_path)?;
            let outside = root
                .parent()
                .ok_or("temporary root must have a parent")?
                .join(format!("calcifer-missing-lock-target-{}", Uuid::new_v4()));
            assert!(!outside.exists());
            symlink(&outside, &lock_path)?;
            let registry_before = fs::read(root.join(REGISTRY_FILE))?;

            let error = registry
                .remove(Provider::Codex, "work", None)
                .err()
                .ok_or("a symlinked lifetime lock must block removal")?;
            assert_eq!(error.code(), "unsafe_profile_state");
            assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);
            assert!(profile_directory.is_dir());
            assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
            assert!(
                !outside.exists(),
                "opening a lifetime lock must not create its symlink target"
            );

            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn every_managed_lock_rejects_an_external_hard_link_before_locking()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt;

        let root = temporary_root("hard-linked-locks");
        secure_create_dir_all(&root)?;
        let outside = root
            .parent()
            .ok_or("temporary root must have a parent")?
            .join(format!("calcifer-hard-linked-lock-{}", Uuid::new_v4()));
        write_private_file(&outside, b"unrelated-private-inode")?;

        for lock_name in [
            LOCK_FILE,
            REMOVAL_LOCK_FILE,
            COORDINATOR_LOCK_FILE,
            PROVIDER_LOCK_FILE,
        ] {
            let lock_path = root.join(lock_name);
            fs::hard_link(&outside, &lock_path)?;
            let error = open_private_lock_file(&lock_path)
                .err()
                .ok_or("a hard-linked managed lock must be rejected")?;
            assert_eq!(error.code(), "unsafe_profile_state", "{lock_name}");
            assert_eq!(
                fs::read(&outside)?,
                b"unrelated-private-inode",
                "{lock_name} must not modify an unrelated inode"
            );
            fs::remove_file(lock_path)?;
            assert_eq!(fs::metadata(&outside)?.nlink(), 1);
        }

        fs::remove_dir_all(root)?;
        fs::remove_file(outside)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_unlinks_provider_symlink_and_socket_leaves_without_following_them()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let root = fs::canonicalize("/tmp")?.join(format!(
            "c{}-{}",
            std::process::id(),
            &Uuid::new_v4().to_string()[..4]
        ));
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let provider_tmp = profile_directory.join("home/tmp");
        secure_create_dir(&provider_tmp)?;

        let outside = root
            .parent()
            .ok_or("temporary root must have a parent")?
            .join(format!("calcifer-removal-link-target-{}", Uuid::new_v4()));
        write_private_file(&outside, b"outside-target-must-survive")?;
        symlink(&outside, provider_tmp.join("provider-link"))?;
        let dangling_target = root.join("target-that-does-not-exist");
        let dangling_link = provider_tmp.join("dangling-provider-link");
        symlink(&dangling_target, &dangling_link)?;
        assert!(
            fs::symlink_metadata(&dangling_link)?
                .file_type()
                .is_symlink()
        );
        assert!(!dangling_target.exists());
        let socket_path = provider_tmp.join("provider.sock");
        let socket = UnixListener::bind(&socket_path)?;
        drop(socket);

        assert_eq!(registry.remove(Provider::Codex, "work", None)?, profile);
        assert!(!profile_directory.exists());
        assert_eq!(fs::read(&outside)?, b"outside-target-must-survive");
        assert!(!socket_path.exists());
        assert!(registry.list()?.is_empty());

        fs::remove_dir_all(root)?;
        fs::remove_file(outside)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn removal_rejects_extended_acl_on_non_following_leaves_before_visibility()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;
        use std::process::Command;

        use exacl::{AclEntry, Perm};

        let root = temporary_root("remove-special-leaf-acl");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let provider_tmp = profile_directory.join("home/tmp");
        secure_create_dir(&provider_tmp)?;
        let tombstone = registry.tombstone_path(&profile)?;

        let outside = root
            .parent()
            .ok_or("temporary root must have a parent")?
            .join(format!("calcifer-special-acl-target-{}", Uuid::new_v4()));
        write_private_file(&outside, b"outside-target-must-survive")?;
        let link = provider_tmp.join("provider-link");
        symlink(&outside, &link)?;
        let fifo = provider_tmp.join("provider-fifo");
        let fifo_status = Command::new("/usr/bin/mkfifo").arg(&fifo).status()?;
        if !fifo_status.success() {
            return Err("could not create the macOS FIFO test fixture".into());
        }

        let mut acl_cleanup = MacosAclCleanup::new(vec![
            link.clone(),
            fifo.clone(),
            tombstone.join("home/tmp/provider-link"),
            tombstone.join("home/tmp/provider-fifo"),
        ]);
        let uid = rustix::process::getuid().as_raw().to_string();
        let deny_delete = [AclEntry::deny_user(&uid, Perm::DELETE, None)];
        exacl::setfacl(&[&link], &deny_delete, macos_test_acl_options())?;
        exacl::setfacl(&[&fifo], &deny_delete, macos_test_acl_options())?;
        let fixtures_have_acl = !exacl::getfacl(&link, macos_test_acl_options())?.is_empty()
            && !exacl::getfacl(&fifo, macos_test_acl_options())?.is_empty();
        let registry_before = fs::read(root.join(REGISTRY_FILE))?;

        let error_code = registry
            .remove(Provider::Codex, "work", None)
            .err()
            .map(|error| error.code());
        let registry_unchanged = fs::read(root.join(REGISTRY_FILE))? == registry_before;
        let profile_preserved = profile_directory.is_dir();
        let journal_absent = !root.join(REMOVAL_JOURNAL_FILE).exists();
        let tombstones_absent = registry.removal_tombstones()?.is_empty();
        let outside_preserved = fs::read(&outside)? == b"outside-target-must-survive";

        acl_cleanup.clear()?;
        let cleanup_registry = Registry::at(root.clone());
        cleanup_registry.recover_incomplete_removal()?;
        if profile_directory.is_dir() {
            cleanup_registry.remove(Provider::Codex, "work", None)?;
        }
        fs::remove_dir_all(&root)?;
        fs::remove_file(&outside)?;

        assert!(
            fixtures_have_acl,
            "the special-leaf ACL fixture must be real"
        );
        assert_eq!(error_code, Some("unsafe_profile_state"));
        assert!(registry_unchanged, "the public registry must not change");
        assert!(
            profile_preserved,
            "the original profile must remain visible"
        );
        assert!(
            journal_absent,
            "preflight rejection must not create a journal"
        );
        assert!(
            tombstones_absent,
            "preflight rejection must not create a tombstone"
        );
        assert!(outside_preserved, "a symlink target must never be touched");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn pre_visibility_recovery_preserves_non_following_leaves_and_external_targets()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{FileTypeExt, symlink};
        use std::os::unix::net::UnixListener;

        let root = fs::canonicalize("/tmp")?.join(format!(
            "c{}-{}",
            std::process::id(),
            &Uuid::new_v4().to_string()[..4]
        ));
        let registry = Registry::at_with_removal_fault(
            root.clone(),
            RemovalFaultPoint::ProviderRootSyncAfterRename,
        );
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let provider_tmp = profile_directory.join("home/tmp");
        secure_create_dir(&provider_tmp)?;
        let outside = root
            .parent()
            .ok_or("short temporary root must have a parent")?
            .join(format!("cfr-target-{}", Uuid::new_v4()));
        write_private_file(&outside, b"external-target-must-survive-recovery")?;
        let link_path = provider_tmp.join("provider-link");
        symlink(&outside, &link_path)?;
        let socket_path = provider_tmp.join("provider.sock");
        let socket = UnixListener::bind(&socket_path)?;
        drop(socket);

        let error = registry
            .remove(Provider::Codex, "work", None)
            .err()
            .ok_or("injected pre-visibility failure must interrupt removal")?;
        assert_eq!(error.code(), "io_error");
        assert!(!profile_directory.exists());

        let recovered = Registry::at(root.clone());
        recovered.recover_incomplete_removal()?;
        assert_eq!(recovered.find(Provider::Codex, "work")?, profile);
        assert!(fs::symlink_metadata(&link_path)?.file_type().is_symlink());
        assert!(fs::symlink_metadata(&socket_path)?.file_type().is_socket());
        assert_eq!(
            fs::read(&outside)?,
            b"external-target-must-survive-recovery"
        );
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());

        fs::remove_dir_all(root)?;
        fs::remove_file(outside)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_accepts_provider_readable_legacy_modes_inside_the_private_profile_root()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let root = temporary_root("remove-provider-readable-modes");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let sessions = profile_directory.join("home/sessions");
        fs::DirBuilder::new().mode(0o755).create(&sessions)?;

        for (name, mode) in [
            ("rollout.jsonl", 0o644),
            ("cached-metadata.json", 0o444),
            ("provider-helper", 0o755),
        ] {
            let path = sessions.join(name);
            write_private_file(&path, b"provider-created-local-state")?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }

        assert_eq!(registry.remove(Provider::Codex, "work", None)?, profile);
        assert!(!profile_directory.exists());
        assert!(registry.list()?.is_empty());
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn opened_removal_entries_reject_post_validation_hard_links_and_mode_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        use rustix::fs::{AtFlags, CWD, Mode, OFlags, fstat, open, statat};

        let root = temporary_root("opened-removal-entry-revalidation");
        secure_create_dir_all(&root)?;
        let expected_device = private_directory_identity(&root)?.device;

        let hard_linked = root.join("hard-linked");
        write_private_file(&hard_linked, b"credential")?;
        let hard_link_expected = statat(CWD, &hard_linked, AtFlags::SYMLINK_NOFOLLOW)?;
        let second_name = root.join("outside-name");
        fs::hard_link(&hard_linked, &second_name)?;
        let hard_link_fd = open(
            &hard_linked,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let hard_link_opened = fstat(&hard_link_fd)?;
        assert_eq!(
            stat_identity(&hard_link_expected)?,
            stat_identity(&hard_link_opened)?,
            "the race must retain the inode while changing its link count"
        );
        assert_eq!(hard_link_opened.st_nlink, 2);
        let hard_link_error = validate_opened_removal_entry(
            &hard_link_expected,
            &hard_link_opened,
            RemovalEntryKind::RegularFile,
            expected_device,
        )
        .err()
        .ok_or("an opened hard-linked credential must fail closed")?;
        assert_eq!(hard_link_error.code(), "unsafe_profile_state");
        assert_eq!(fs::read(&hard_linked)?, b"credential");
        assert_eq!(fs::read(&second_name)?, b"credential");

        let mode_changed = root.join("mode-changed");
        write_private_file(&mode_changed, b"credential")?;
        let mode_expected = statat(CWD, &mode_changed, AtFlags::SYMLINK_NOFOLLOW)?;
        fs::set_permissions(&mode_changed, fs::Permissions::from_mode(0o666))?;
        let mode_fd = open(
            &mode_changed,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mode_opened = fstat(&mode_fd)?;
        assert_eq!(
            stat_identity(&mode_expected)?,
            stat_identity(&mode_opened)?,
            "the race must retain the inode while changing its mode"
        );
        assert_eq!(mode_opened.st_mode & 0o777, 0o666);
        let mode_error = validate_opened_removal_entry(
            &mode_expected,
            &mode_opened,
            RemovalEntryKind::RegularFile,
            expected_device,
        )
        .err()
        .ok_or("an opened group-writable credential must fail closed")?;
        assert_eq!(mode_error.code(), "unsafe_profile_state");
        assert_eq!(fs::read(&mode_changed)?, b"credential");

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn secure_creation_rejects_nonsticky_writable_parents_before_create()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let root = temporary_root("unsafe-creation-parent-mode");
        secure_create_dir_all(&root)?;
        let root_metadata = fs::symlink_metadata(&root)?;
        let current_uid = rustix::process::getuid().as_raw();
        assert!(private_directory_metadata_is_safe(
            &root_metadata,
            current_uid
        ));
        assert!(
            !private_directory_metadata_is_safe(&root_metadata, current_uid.wrapping_add(1)),
            "an existing directory owned by another UID must not become managed state"
        );

        let trusted_target = root.join("trusted-target");
        secure_create_dir(&trusted_target)?;
        let unsafe_link_container = root.join("unsafe-link-container");
        secure_create_dir(&unsafe_link_container)?;
        fs::set_permissions(&unsafe_link_container, fs::Permissions::from_mode(0o777))?;
        let link = unsafe_link_container.join("link");
        std::os::unix::fs::symlink(&trusted_target, &link)?;

        let lexical_directory = link.join("directory");
        let lexical_directory_error = secure_create_dir(&lexical_directory)
            .err()
            .ok_or("a canonical target must not hide an unsafe lexical ancestor")?;
        assert_eq!(lexical_directory_error.code(), "unsafe_profile_state");
        assert!(!trusted_target.join("directory").exists());

        let lexical_file = link.join("credential");
        let lexical_file_error = write_private_file(&lexical_file, b"credential")
            .err()
            .ok_or("private file creation must inspect the lexical ancestor chain")?;
        assert_eq!(lexical_file_error.code(), "unsafe_profile_state");
        assert!(!trusted_target.join("credential").exists());

        let nested_target = root.join("nested-target");
        secure_create_dir(&nested_target)?;
        let unsafe_nested_container = root.join("unsafe-nested-container");
        secure_create_dir(&unsafe_nested_container)?;
        fs::set_permissions(&unsafe_nested_container, fs::Permissions::from_mode(0o777))?;
        let nested_link = unsafe_nested_container.join("nested-link");
        std::os::unix::fs::symlink(&nested_target, &nested_link)?;
        let safe_link_container = root.join("safe-link-container");
        secure_create_dir(&safe_link_container)?;
        let outer_link = safe_link_container.join("outer-link");
        std::os::unix::fs::symlink(&nested_link, &outer_link)?;

        let nested_symlink_directory = outer_link.join("directory");
        let nested_symlink_error = secure_create_dir(&nested_symlink_directory)
            .err()
            .ok_or("canonicalization must not hide an unsafe nested symlink placement")?;
        assert_eq!(nested_symlink_error.code(), "unsafe_profile_state");
        assert!(!nested_target.join("directory").exists());

        let parent = root.join("parent");
        secure_create_dir(&parent)?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777))?;

        let blocked = parent.join("blocked");
        let error = secure_create_dir(&blocked)
            .err()
            .ok_or("a non-sticky writable parent must fail before creation")?;
        assert_eq!(error.code(), "unsafe_profile_state");
        assert!(!blocked.exists());

        let superficially_private = parent.join("private-child");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&superficially_private)?;
        let nested = superficially_private.join("nested");
        let ancestor_error = secure_create_dir(&nested)
            .err()
            .ok_or("a replaceable ancestor must fail even below a private immediate parent")?;
        assert_eq!(ancestor_error.code(), "unsafe_profile_state");
        assert!(!nested.exists());

        fs::set_permissions(&parent, fs::Permissions::from_mode(0o1777))?;
        let sticky_child = parent.join("sticky-child");
        secure_create_dir(&sticky_child)?;
        verify_private_directory(&sticky_child)?;

        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777))?;
        let existing_error = verify_private_directory(&sticky_child)
            .err()
            .ok_or("an existing managed path below an unsafe parent must fail closed")?;
        assert_eq!(existing_error.code(), "unsafe_profile_state");

        fs::set_permissions(&parent, fs::Permissions::from_mode(0o1777))?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn secure_creation_rejects_inheritable_macos_acls_before_creating_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::DirBuilderExt;

        use exacl::{AclEntry, Flag, Perm};

        let parent = temporary_root("inherited-macos-acl");
        secure_create_dir_all(&parent)?;
        let atomic_target = parent.join("atomic-state");
        write_private_file(&atomic_target, b"old-state")?;
        let raw_child = parent.join("raw-child");
        let mut acl_cleanup = MacosAclCleanup::new(vec![parent.clone(), raw_child.clone()]);
        let current_uid = rustix::process::getuid().as_raw();
        let other_uid = if current_uid == 89 { "1" } else { "89" };
        let unknown_flag = calcifer_macos_acl::Entry {
            tag: calcifer_macos_acl::TAG_DENY,
            flags: 1_u32 << 31,
            permissions: calcifer_macos_acl::PERMISSION_DELETE,
        };
        assert!(
            !macos_parent_acl_entry_is_safe(&unknown_flag),
            "unknown ACL flags must fail closed"
        );
        let unknown_permission = calcifer_macos_acl::Entry {
            tag: calcifer_macos_acl::TAG_DENY,
            flags: 0,
            permissions: calcifer_macos_acl::PERMISSION_DELETE | (1_u32 << 31),
        };
        assert!(
            !macos_parent_acl_entry_is_safe(&unknown_permission),
            "unknown ACL permissions must fail closed"
        );
        let inherited_delete = calcifer_macos_acl::Entry {
            tag: calcifer_macos_acl::TAG_DENY,
            flags: calcifer_macos_acl::FLAG_INHERITED,
            permissions: calcifer_macos_acl::PERMISSION_DELETE,
        };
        assert!(
            macos_parent_acl_entry_is_safe(&inherited_delete),
            "an inherited, non-propagating DELETE-only deny remains safe"
        );
        let inherited_acl = [AclEntry::allow_user(
            other_uid,
            Perm::READ | Perm::WRITE | Perm::EXECUTE,
            Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT,
        )];
        exacl::setfacl(&[&parent], &inherited_acl, macos_test_acl_options())?;
        assert!(!exacl::getfacl(&parent, macos_test_acl_options())?.is_empty());

        fs::DirBuilder::new().mode(0o700).create(&raw_child)?;
        assert!(
            !exacl::getfacl(&raw_child, macos_test_acl_options())?.is_empty(),
            "the fixture must prove that the parent ACL is inherited"
        );
        let existing_error = secure_create_dir_all(&raw_child)
            .err()
            .ok_or("an existing managed directory with an ACL must fail closed")?;
        assert_eq!(existing_error.code(), "unsafe_profile_state");
        assert!(
            !exacl::getfacl(&raw_child, macos_test_acl_options())?.is_empty(),
            "verification must not silently normalize existing ACL state"
        );
        clear_macos_test_acl(&raw_child)?;
        fs::remove_dir(&raw_child)?;

        let secure_child = parent.join("secure-child");
        let directory_error = secure_create_dir(&secure_child)
            .err()
            .ok_or("an inheritable parent ACL must stop directory creation")?;
        assert_eq!(directory_error.code(), "unsafe_profile_state");
        assert!(!secure_child.exists());

        let secure_file = parent.join("secure-file");
        let file_error = write_private_file(&secure_file, b"credential")
            .err()
            .ok_or("an inheritable parent ACL must stop private file creation")?;
        assert_eq!(file_error.code(), "unsafe_profile_state");
        assert!(
            !secure_file.exists(),
            "no empty credential inode may be exposed before ACL cleanup"
        );

        let deep_child = parent.join("deep/leaf");
        let recursive_error = secure_create_dir_all(&deep_child)
            .err()
            .ok_or("an inheritable ancestor ACL must stop recursive creation")?;
        assert_eq!(recursive_error.code(), "unsafe_profile_state");
        assert!(!parent.join("deep").exists());

        let mut atomic_steps = Vec::new();
        let atomic_error = atomic_write_private(
            &parent,
            "atomic-state",
            b"credential-state",
            |step| {
                atomic_steps.push(step);
                Ok(())
            },
            |_| Ok(()),
        )
        .err()
        .ok_or("an unsafe parent ACL must stop atomic state creation")?;
        assert_eq!(atomic_error.code(), "unsafe_profile_state");
        assert_eq!(atomic_steps, [RegistryWriteStep::TemporaryCreate]);
        assert_eq!(fs::read(&atomic_target)?, b"old-state");
        assert!(!fs::read_dir(&parent)?.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.starts_with(".atomic-state."))
        }));

        clear_macos_test_acl(&parent)?;
        let non_inheritable_allow = [AclEntry::allow_user(other_uid, Perm::READ, None)];
        exacl::setfacl(&[&parent], &non_inheritable_allow, macos_test_acl_options())?;
        let allowed_parent_child = parent.join("allow-parent-child");
        let allow_error = secure_create_dir(&allowed_parent_child)
            .err()
            .ok_or("any parent ALLOW entry must fail before creation")?;
        assert_eq!(allow_error.code(), "unsafe_profile_state");
        assert!(!allowed_parent_child.exists());

        clear_macos_test_acl(&parent)?;
        let deny_delete_child = [AclEntry::deny_group("everyone", Perm::DELETE_CHILD, None)];
        exacl::setfacl(&[&parent], &deny_delete_child, macos_test_acl_options())?;
        let denied_parent_child = parent.join("deny-delete-child");
        let deny_error = secure_create_dir(&denied_parent_child)
            .err()
            .ok_or("a parent deny-delete-child ACL must fail before creation")?;
        assert_eq!(deny_error.code(), "unsafe_profile_state");
        assert!(!denied_parent_child.exists());
        let denied_parent_file = parent.join("deny-delete-child-file");
        let deny_file_error = write_private_file(&denied_parent_file, b"credential")
            .err()
            .ok_or("deny-delete-child must stop a private file before creation")?;
        assert_eq!(deny_file_error.code(), "unsafe_profile_state");
        assert!(!denied_parent_file.exists());

        clear_macos_test_acl(&parent)?;
        let safe_deny = [AclEntry::deny_group("everyone", Perm::DELETE, None)];
        exacl::setfacl(&[&parent], &safe_deny, macos_test_acl_options())?;

        secure_create_dir(&secure_child)?;
        assert!(
            exacl::getfacl(&secure_child, macos_test_acl_options())?.is_empty(),
            "a non-inheritable deny ACL must not be copied to a new directory"
        );
        write_private_file(&secure_file, b"credential")?;
        assert!(
            exacl::getfacl(&secure_file, macos_test_acl_options())?.is_empty(),
            "a private file must be ACL-free before credential bytes are written"
        );
        secure_create_dir_all(&deep_child)?;
        assert!(exacl::getfacl(parent.join("deep"), macos_test_acl_options())?.is_empty());
        assert!(exacl::getfacl(&deep_child, macos_test_acl_options())?.is_empty());

        acl_cleanup.clear()?;
        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_acl_reads_stay_bound_to_an_open_inode_after_path_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::fd::AsFd;

        use exacl::{AclEntry, Perm};

        let root = temporary_root("opened-macos-acl");
        secure_create_dir_all(&root)?;
        let original = root.join("original");
        secure_create_dir(&original)?;
        let current_uid = rustix::process::getuid().as_raw();
        let other_uid = if current_uid == 89 { "1" } else { "89" };
        let allow_delete = [AclEntry::allow_user(other_uid, Perm::DELETE, None)];
        exacl::setfacl(&[&original], &allow_delete, macos_test_acl_options())?;
        let mut acl_cleanup = MacosAclCleanup::new(vec![original.clone()]);
        let opened = File::open(&original)?;

        let parked = root.join("parked");
        fs::rename(&original, &parked)?;
        acl_cleanup.candidates = vec![parked.clone()];
        secure_create_dir(&original)?;
        assert!(
            exacl::getfacl(&original, macos_test_acl_options())?.is_empty(),
            "the replacement pathname must be ACL-free"
        );
        let opened_acl = macos_acl_for_open_file(&opened)?;
        assert_eq!(opened_acl.entries.len(), 1);
        assert_eq!(opened_acl.entries[0].tag, calcifer_macos_acl::TAG_ALLOW);
        assert_eq!(
            opened_acl.entries[0].permissions,
            calcifer_macos_acl::PERMISSION_DELETE
        );
        calcifer_macos_acl::clear_acl(opened.as_fd())?;
        assert!(
            macos_acl_for_open_file(&opened)?.is_empty(),
            "descriptor-bound clearing must remove the parked inode's ACL"
        );
        assert!(
            exacl::getfacl(&parked, macos_test_acl_options())?.is_empty(),
            "descriptor-bound clearing must affect the parked inode, not its replacement"
        );

        acl_cleanup.clear()?;
        fs::remove_dir(original)?;
        fs::remove_dir(parked)?;
        fs::remove_dir(root)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn secure_creation_rejects_extended_acl_on_traversed_macos_symlink()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        use exacl::{AclEntry, Perm};

        let sticky_container = temporary_root("symlink-acl-sticky-container");
        secure_create_dir_all(&sticky_container)?;
        fs::set_permissions(&sticky_container, fs::Permissions::from_mode(0o1777))?;
        let target = temporary_root("symlink-acl-target");
        secure_create_dir_all(&target)?;
        let link = sticky_container.join("managed-link");
        symlink(&target, &link)?;
        let mut acl_cleanup = MacosAclCleanup::new(vec![link.clone()]);
        let current_uid = rustix::process::getuid().as_raw();
        let other_uid = if current_uid == 89 { "1" } else { "89" };
        let allow_delete = [AclEntry::allow_user(other_uid, Perm::DELETE, None)];
        exacl::setfacl(&[&link], &allow_delete, macos_test_acl_options())?;
        let fixture_has_acl = !exacl::getfacl(&link, macos_test_acl_options())?.is_empty();

        let managed_directory = link.join("managed-directory");
        let directory_result = secure_create_dir(&managed_directory);
        let directory_was_created = target.join("managed-directory").is_dir();
        let managed_file = link.join("managed-file");
        let file_result = write_private_file(&managed_file, b"credential");
        let file_was_created = target.join("managed-file").is_file();

        acl_cleanup.clear()?;
        if target.join("managed-file").is_file() {
            fs::remove_file(target.join("managed-file"))?;
        }
        if target.join("managed-directory").is_dir() {
            fs::remove_dir(target.join("managed-directory"))?;
        }
        fs::remove_file(&link)?;
        fs::set_permissions(&sticky_container, fs::Permissions::from_mode(0o700))?;
        fs::remove_dir(&sticky_container)?;
        fs::remove_dir(&target)?;

        assert!(fixture_has_acl, "the symlink ACL fixture must be real");
        let directory_error = directory_result
            .err()
            .ok_or("a replaceable ACL-bearing symlink must reject directory creation")?;
        assert_eq!(directory_error.code(), "unsafe_profile_state");
        assert!(
            !directory_was_created,
            "the symlink ACL must be rejected before mkdir"
        );
        let file_error = file_result
            .err()
            .ok_or("a replaceable ACL-bearing symlink must reject private file creation")?;
        assert_eq!(file_error.code(), "unsafe_profile_state");
        assert!(
            !file_was_created,
            "the symlink ACL must be rejected before credential inode creation"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn removal_rejects_extended_macos_acl_before_preparing_state()
    -> Result<(), Box<dyn std::error::Error>> {
        use exacl::{AclEntry, Perm};

        let root = temporary_root("remove-extended-macos-acl");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let tombstone = registry.tombstone_path(&profile)?;
        let auth = profile_directory.join("home/auth.json");
        let uid = rustix::process::getuid().as_raw().to_string();
        let deny_delete = [AclEntry::deny_user(&uid, Perm::DELETE, None)];
        exacl::setfacl(&[&auth], &deny_delete, macos_test_acl_options())?;
        assert!(!exacl::getfacl(&auth, macos_test_acl_options())?.is_empty());
        let registry_before = fs::read(root.join(REGISTRY_FILE))?;

        let result = registry.remove(Provider::Codex, "work", None);
        let error_code = result.err().map(|error| error.code());
        let registry_unchanged = fs::read(root.join(REGISTRY_FILE))? == registry_before;
        let profile_preserved = profile_directory.is_dir();
        let journal_absent = !root.join(REMOVAL_JOURNAL_FILE).exists();
        let tombstones_absent = registry.removal_tombstones()?.is_empty();

        for candidate in [auth, tombstone.join("home/auth.json")] {
            if candidate.exists() {
                clear_macos_test_acl(&candidate)?;
            }
        }
        let _ = Registry::at(root.clone()).recover_incomplete_removal();
        fs::remove_dir_all(&root)?;

        assert_eq!(error_code, Some("unsafe_profile_state"));
        assert!(registry_unchanged, "the public registry must not change");
        assert!(
            profile_preserved,
            "the original profile must remain visible"
        );
        assert!(
            journal_absent,
            "preflight rejection must not create a journal"
        );
        assert!(
            tombstones_absent,
            "preflight rejection must not create a tombstone"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn removal_rejects_immutable_macos_files_before_preparing_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("remove-immutable-macos-file");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let tombstone = registry.tombstone_path(&profile)?;
        let auth = profile_directory.join("home/auth.json");
        let mut immutable_cleanup = MacosFlagCleanup::set(
            vec![auth.clone(), tombstone.join("home/auth.json")],
            &auth,
            "uchg",
            "nouchg",
        )?;
        let registry_before = fs::read(root.join(REGISTRY_FILE))?;

        let result = registry.remove(Provider::Codex, "work", None);
        let error_code = result.err().map(|error| error.code());
        let registry_unchanged = fs::read(root.join(REGISTRY_FILE))? == registry_before;
        let profile_preserved = profile_directory.is_dir();
        let journal_absent = !root.join(REMOVAL_JOURNAL_FILE).exists();
        let tombstones_absent = registry.removal_tombstones()?.is_empty();

        immutable_cleanup.clear()?;
        let _ = Registry::at(root.clone()).recover_incomplete_removal();
        fs::remove_dir_all(&root)?;

        assert_eq!(error_code, Some("unsafe_profile_state"));
        assert!(registry_unchanged, "the public registry must not change");
        assert!(
            profile_preserved,
            "the original profile must remain visible"
        );
        assert!(
            journal_absent,
            "preflight rejection must not create a journal"
        );
        assert!(
            tombstones_absent,
            "preflight rejection must not create a tombstone"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_removal_rejects_blocking_and_unknown_file_flags()
    -> Result<(), Box<dyn std::error::Error>> {
        use rustix::fs::{AtFlags, CWD, statat};

        let root = temporary_root("macos-file-flags");
        secure_create_dir_all(&root)?;
        let file = root.join("state");
        write_private_file(&file, b"state")?;
        let stat = statat(CWD, &file, AtFlags::SYMLINK_NOFOLLOW)?;

        for flag in [
            0x0000_0002_u32,
            0x0000_0004,
            0x0000_0008,
            0x0000_0010,
            0x0000_0080,
            0x0000_0100,
            0x0002_0000,
            0x0004_0000,
            0x0008_0000,
            0x0010_0000,
        ] {
            let mut flagged = stat;
            flagged.st_flags = flag;
            let error = verify_deletable_macos_flags_stat(&flagged)
                .err()
                .ok_or("blocking and unknown macOS flags must fail closed")?;
            assert_eq!(error.code(), "unsafe_profile_state", "flag={flag:#x}");
        }
        for benign in [
            0x0000_0001_u32,
            0x0000_0020,
            0x0000_0040,
            0x0000_8000,
            0x0001_0000,
        ] {
            let mut flagged = stat;
            flagged.st_flags = benign;
            verify_deletable_macos_flags_stat(&flagged)?;
        }

        for inherited in [0x0000_0080_u32, 0x0008_0000] {
            let mut parent = stat;
            parent.st_flags = inherited;
            let error = verify_safe_macos_creation_parent_flags(&parent)
                .err()
                .ok_or("inherited restrictive parent flags must fail before creation")?;
            assert_eq!(error.code(), "unsafe_profile_state");
        }
        let mut standard_temp_parent = stat;
        standard_temp_parent.st_flags = 0x0010_0000;
        verify_safe_macos_creation_parent_flags(&standard_temp_parent)?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn secure_creation_rejects_append_only_macos_parent_before_creating_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("append-only-creation-parent");
        secure_create_dir_all(&root)?;
        let parent = root.join("parent");
        secure_create_dir(&parent)?;

        let raw_child = parent.join("raw-child");
        let mut raw_guard =
            MacosFlagCleanup::set(vec![parent.clone()], &parent, "uappnd", "nouappnd")?;
        fs::write(&raw_child, b"non-secret-fixture")?;
        let raw_unlink_was_blocked = fs::remove_file(&raw_child).is_err();
        raw_guard.clear()?;
        if fs::symlink_metadata(&raw_child).is_ok() {
            fs::remove_file(&raw_child)?;
        }

        let managed_directory = parent.join("managed-directory");
        let mut directory_guard =
            MacosFlagCleanup::set(vec![parent.clone()], &parent, "uappnd", "nouappnd")?;
        let directory_result = secure_create_dir(&managed_directory);
        let directory_was_created = managed_directory.is_dir();
        directory_guard.clear()?;
        if managed_directory.is_dir() {
            fs::remove_dir(&managed_directory)?;
        }

        let managed_file = parent.join("managed-file");
        let mut file_guard =
            MacosFlagCleanup::set(vec![parent.clone()], &parent, "uappnd", "nouappnd")?;
        let file_result = write_private_file(&managed_file, b"credential");
        let file_was_created = managed_file.is_file();
        file_guard.clear()?;
        if managed_file.is_file() {
            fs::remove_file(&managed_file)?;
        }

        fs::remove_dir_all(&root)?;

        assert!(
            raw_unlink_was_blocked,
            "the append-only parent fixture must allow create but block child unlink"
        );
        let directory_error = directory_result
            .err()
            .ok_or("an append-only parent must reject managed directory creation")?;
        assert_eq!(directory_error.code(), "unsafe_profile_state");
        assert!(
            !directory_was_created,
            "the unsafe parent must be rejected before mkdir"
        );
        let file_error = file_result
            .err()
            .ok_or("an append-only parent must reject private file creation")?;
        assert_eq!(file_error.code(), "unsafe_profile_state");
        assert!(
            !file_was_created,
            "the unsafe parent must be rejected before a credential inode exists"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn removal_rejects_owner_unreadable_regular_files_before_preparing_state()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_root("remove-owner-unreadable-file");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let auth = profile_directory.join("home/auth.json");
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o000))?;
        let registry_before = fs::read(root.join(REGISTRY_FILE))?;

        let error = registry
            .remove(Provider::Codex, "work", None)
            .err()
            .ok_or("owner-unreadable regular files must fail before visibility")?;
        assert_eq!(error.code(), "unsafe_profile_state");
        assert_eq!(fs::read(root.join(REGISTRY_FILE))?, registry_before);
        assert!(profile_directory.is_dir());
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());
        assert!(registry.removal_tombstones()?.is_empty());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_entry_budget_rejects_before_cleanup_and_preserves_every_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("remove-entry-budget");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let roots = registry.validate_removal_roots(None)?;
        let profile_directory = registry.profile_directory(&profile)?;
        let snapshot =
            validate_owned_removal_tree(&root, &roots, &profile_directory, &profile.id, None)?;
        let auth = profile_directory.join("home/auth.json");
        let auth_before = fs::read(&auth)?;

        let validation_error = validate_owned_removal_tree_inner_with_limits(
            &root,
            &roots,
            &profile_directory,
            &profile.id,
            Some(snapshot.root),
            true,
            1,
            MAX_REMOVAL_TREE_DEPTH,
        )
        .err()
        .ok_or("validation must enforce its streaming entry budget")?;
        assert_eq!(validation_error.code(), "unsafe_profile_state");
        assert_eq!(fs::read(&auth)?, auth_before);

        let provider_root = registry.provider_root(Provider::Codex)?;
        let tombstone = registry.tombstone_path(&profile)?;
        fs::rename(&profile_directory, &tombstone)?;
        let cleanup_error = remove_owned_tombstone_at_with_limits(
            &provider_root,
            &tombstone,
            roots.provider_root,
            snapshot.root,
            &roots.provider_mount,
            1,
            MAX_REMOVAL_TREE_DEPTH,
        )
        .err()
        .ok_or("cleanup must enforce its streaming entry budget")?;
        assert_eq!(cleanup_error.code(), "unsafe_profile_state");
        assert_eq!(fs::read(tombstone.join("home/auth.json"))?, auth_before);
        assert_eq!(
            validate_owned_removal_tree(
                &root,
                &roots,
                &tombstone,
                &profile.id,
                Some(snapshot.clone()),
            )?,
            snapshot
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_depth_budget_rejects_a_child_before_queuing_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("remove-depth-budget");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let nested = profile_directory.join("home/one/two");
        secure_create_dir_all(&nested)?;
        write_private_file(&nested.join("sentinel"), b"must-survive")?;
        let roots = registry.validate_removal_roots(None)?;
        let identity = private_directory_identity(&profile_directory)?;

        let error = validate_owned_removal_tree_inner_with_limits(
            &root,
            &roots,
            &profile_directory,
            &profile.id,
            Some(identity),
            true,
            MAX_REMOVAL_TREE_ENTRIES,
            1,
        )
        .err()
        .ok_or("validation must reject a directory beyond its depth budget")?;
        assert_eq!(error.code(), "unsafe_profile_state");
        assert_eq!(fs::read(nested.join("sentinel"))?, b"must-survive");
        assert!(!root.join(REMOVAL_JOURNAL_FILE).exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn removal_mount_identity_is_stable_within_one_mount() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::DirBuilderExt;

        let root = temporary_root("remove-mount-identity");
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let child = root.join("child");
        fs::DirBuilder::new().mode(0o700).create(&child)?;

        assert_eq!(
            removal_mount_identity_path(&root)?,
            removal_mount_identity_path(&child)?
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn removal_mount_identity_mismatch_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let expected = RemovalMountIdentity {
            token: b"provider-mount".to_vec(),
        };
        let nested_mount = RemovalMountIdentity {
            token: b"nested-bind-mount".to_vec(),
        };

        let error = ensure_same_removal_mount(&expected, &nested_mount)
            .err()
            .ok_or("a different mount identity must fail closed")?;
        assert_eq!(error.code(), "unsafe_profile_state");
        assert!(!error.safe_message().contains("provider-mount"));
        assert!(!error.safe_message().contains("nested-bind-mount"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_boundary_errors_distinguish_unprovable_paths_from_retryable_io() {
        for errno in [
            rustix::io::Errno::XDEV,
            rustix::io::Errno::LOOP,
            rustix::io::Errno::AGAIN,
            rustix::io::Errno::NOSYS,
            rustix::io::Errno::INVAL,
            rustix::io::Errno::TOOBIG,
            rustix::io::Errno::NOENT,
            rustix::io::Errno::NOTDIR,
        ] {
            assert_eq!(
                removal_boundary_error(errno).code(),
                "unsafe_profile_state",
                "{errno} must fail closed without a weaker fallback"
            );
        }
        for errno in [
            rustix::io::Errno::IO,
            rustix::io::Errno::NOMEM,
            rustix::io::Errno::MFILE,
        ] {
            let error = removal_boundary_error(errno);
            assert_eq!(error.code(), "io_error", "{errno}");
            assert_eq!(
                removal_commit_error(error).code(),
                "removal_commit_uncertain",
                "{errno} after registry visibility must remain retryable"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a private mount namespace plus CAP_SYS_ADMIN"]
    fn removal_rejects_same_device_bind_mount_during_validation_and_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        use std::process::Command;

        let root = temporary_root("remove-bind-mount");
        let registry = Registry::at(root.clone());
        let profile = register_test_profile(&registry, "work")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let bind_target = profile_directory.join("home/bind");
        fs::DirBuilder::new().mode(0o700).create(&bind_target)?;
        let source = root
            .parent()
            .ok_or("temporary root must have a parent")?
            .join(format!("calcifer-bind-source-{}", Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&source)?;
        write_private_file(&source.join("sentinel"), b"outside-must-survive")?;

        let mount_status = Command::new("mount")
            .args(["--bind"])
            .arg(&source)
            .arg(&bind_target)
            .status()?;
        if !mount_status.success() {
            return Err(
                "bind mount setup failed; run in a private privileged mount namespace".into(),
            );
        }
        assert_eq!(
            fs::metadata(&source)?.dev(),
            fs::metadata(&bind_target)?.dev(),
            "the fixture must prove that st_dev alone cannot detect this bind mount"
        );
        assert_ne!(
            removal_mount_identity_path(&source)?,
            removal_mount_identity_path(&bind_target)?,
            "same-device bind mounts must still have distinct mount identities"
        );

        let roots = registry.validate_removal_roots(None)?;
        let validation_error =
            validate_owned_removal_tree(&root, &roots, &profile_directory, &profile.id, None)
                .err()
                .ok_or("same-device bind mount must fail validation")?;
        assert_eq!(validation_error.code(), "unsafe_profile_state");
        assert!(
            validation_error
                .safe_message()
                .contains("crosses a mount boundary")
        );

        let tree_identity = private_directory_identity(&profile_directory)?;
        let tombstone = registry.tombstone_path(&profile)?;
        fs::rename(&profile_directory, &tombstone)?;
        let cleanup_error = remove_owned_tombstone_at(
            &registry.provider_root(Provider::Codex)?,
            &tombstone,
            roots.provider_root,
            tree_identity,
            &roots.provider_mount,
            MAX_REMOVAL_TREE_ENTRIES,
        )
        .err()
        .ok_or("same-device bind mount must fail descriptor cleanup")?;
        assert_eq!(cleanup_error.code(), "unsafe_profile_state");
        assert!(
            cleanup_error
                .safe_message()
                .contains("cannot prove the managed mount boundary")
        );
        assert_eq!(fs::read(source.join("sentinel"))?, b"outside-must-survive");

        let unmount_status = Command::new("umount")
            .arg(tombstone.join("home/bind"))
            .status()?;
        if !unmount_status.success() {
            return Err("bind mount cleanup failed".into());
        }
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(source)?;
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
