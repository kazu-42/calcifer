use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const REGISTRY_SCHEMA_VERSION: u8 = 1;
const REGISTRY_FILE: &str = "profiles.json";
const LOCK_FILE: &str = "registry.lock";
const OWNER_MARKER: &str = ".calcifer-profile";
const COORDINATOR_LOCK_FILE: &str = "profile.lock";
const PROVIDER_LOCK_FILE: &str = "provider.lock";
const MANAGED_CODEX_CONFIG: &[u8] = b"# Managed by Calcifer.\ncli_auth_credentials_store = \"file\"\nmcp_oauth_credentials_store = \"file\"\n";
const LEGACY_MANAGED_CODEX_CONFIG: &[u8] =
    b"# Managed by Calcifer.\ncli_auth_credentials_store = \"file\"\n";

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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    schema_version: u8,
    profiles: Vec<Profile>,
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
    fail_registry_directory_sync: bool,
}

impl Registry {
    pub(crate) fn discover() -> Result<Self, ProfileError> {
        Ok(Self {
            root: data_root()?,
            #[cfg(test)]
            fail_registry_directory_sync: false,
        })
    }

    #[cfg(all(test, unix))]
    pub(crate) fn at(root: PathBuf) -> Self {
        Self {
            root,
            fail_registry_directory_sync: false,
        }
    }

    #[cfg(all(test, unix))]
    fn at_with_registry_sync_failure(root: PathBuf) -> Self {
        Self {
            root,
            fail_registry_directory_sync: true,
        }
    }

    pub(crate) fn list(&self) -> Result<Vec<Profile>, ProfileError> {
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
        self.load()?
            .profiles
            .into_iter()
            .find(|profile| profile.provider == provider && profile.alias == alias)
            .ok_or_else(|| ProfileError::NotFound(format!("{}@{alias}", provider.as_str())))
    }

    pub(crate) fn begin_codex_registration(
        &self,
        alias: &str,
    ) -> Result<PendingProfile<'_>, ProfileError> {
        validate_alias(alias)?;
        ensure_registration_supported()?;
        self.ensure_root()?;

        let lock = self.lock_exclusive()?;
        let document = self.load()?;
        if document
            .profiles
            .iter()
            .any(|profile| profile.provider == Provider::Codex && profile.alias == alias)
        {
            return Err(ProfileError::AlreadyExists(format!("codex@{alias}")));
        }

        let id = Uuid::new_v4().to_string();
        let profiles_root = self.root.join("profiles");
        ensure_private_subdirectory(&profiles_root)?;
        let provider_root = profiles_root.join("codex");
        ensure_private_subdirectory(&provider_root)?;
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
        })
    }

    pub(crate) fn profile_home(&self, profile: &Profile) -> Result<PathBuf, ProfileError> {
        let directory = self.profile_directory(profile)?;
        let home = directory.join("home");
        verify_private_directory(&home)?;
        verify_managed_codex_config(&home.join("config.toml"))?;
        verify_codex_auth_file(&home.join("auth.json"))?;
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
        let bytes = fs::read(&path)?;
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
        atomic_write_private(&self.root, REGISTRY_FILE, &bytes, |root| {
            #[cfg(test)]
            if self.fail_registry_directory_sync {
                return Err(ProfileError::Io(io::Error::other(
                    "injected registry directory sync failure",
                )));
            }
            sync_directory(root)
        })
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
}

pub(crate) struct PendingProfile<'a> {
    registry: &'a Registry,
    _lock: RegistryLock,
    profile: Profile,
    staging: PathBuf,
    committed: bool,
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

    pub(crate) fn commit(mut self) -> Result<Profile, ProfileError> {
        verify_codex_auth_file(&self.home().join("auth.json"))?;
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
        if self.committed {
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
    InvalidAlias,
    InvalidRegistry(String),
    Io(io::Error),
    MissingDataRoot,
    NotFound(String),
    RegistrationRecoveryRequired,
    RegistryCommitUncertain(io::Error),
    UnsupportedPlatform,
    UnsafeState(String),
}

impl ProfileError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::AlreadyExists(_) => "profile_already_exists",
            Self::Busy(_) => "profile_busy",
            Self::InvalidAlias => "invalid_profile_alias",
            Self::InvalidRegistry(_) => "invalid_registry",
            Self::Io(_) => "io_error",
            Self::MissingDataRoot => "missing_data_root",
            Self::NotFound(_) => "profile_not_found",
            Self::RegistrationRecoveryRequired => "registration_recovery_required",
            Self::RegistryCommitUncertain(_) => "registry_commit_uncertain",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::UnsafeState(_) => "unsafe_profile_state",
        }
    }

    pub(crate) fn safe_message(&self) -> String {
        match self {
            Self::AlreadyExists(reference) => format!("Profile {reference} already exists."),
            Self::Busy(reference) => format!("Profile {reference} is already in use."),
            Self::InvalidAlias => "Profile aliases must be 1-64 ASCII letters, digits, '.', '_' or '-', and must start with a letter or digit.".to_owned(),
            Self::InvalidRegistry(reason) => format!("Calcifer's profile registry is invalid: {reason}."),
            Self::Io(_) => "Calcifer could not access its managed profile storage.".to_owned(),
            Self::MissingDataRoot => "Calcifer could not determine a user data directory. Set CALCIFER_HOME to an absolute path.".to_owned(),
            Self::NotFound(reference) => format!("Profile {reference} was not found."),
            Self::RegistrationRecoveryRequired => "Calcifer could not roll back a partially published profile. Do not retry registration until the managed state has been inspected.".to_owned(),
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

fn verify_managed_codex_config(path: &Path) -> Result<(), ProfileError> {
    verify_private_regular_file(path).map_err(|error| match error {
        ProfileError::Io(io_error) if io_error.kind() == io::ErrorKind::NotFound => {
            ProfileError::UnsafeState("managed Codex profile is missing its config.toml".to_owned())
        }
        other => other,
    })?;
    let contents = fs::read(path)?;
    if contents != MANAGED_CODEX_CONFIG && contents != LEGACY_MANAGED_CODEX_CONFIG {
        return Err(ProfileError::UnsafeState(
            "managed Codex config.toml was modified".to_owned(),
        ));
    }
    Ok(())
}

fn atomic_write_private(
    root: &Path,
    name: &str,
    bytes: &[u8],
    sync_parent: impl FnOnce(&Path) -> Result<(), ProfileError>,
) -> Result<(), ProfileError> {
    let temporary_name = format!(".{name}.{}.tmp", Uuid::new_v4());
    let temporary = root.join(temporary_name);
    let destination = root.join(name);
    write_private_file(&temporary, bytes)?;
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(ProfileError::Io(error));
    }
    sync_parent(root).map_err(|error| match error {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn temporary_root(test_name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "calcifer-{test_name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ))
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
    fn published_profiles_accept_the_previous_managed_config_during_upgrade()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("legacy-config-upgrade");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        write_private_file(
            &pending.home().join("auth.json"),
            br#"{"synthetic":"test-only"}"#,
        )?;
        let profile = pending.commit()?;
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
        let result = pending.commit();
        assert!(matches!(result, Err(ProfileError::UnsafeState(_))));
        assert!(registry.list()?.is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn published_profiles_revalidate_config_and_auth_before_use()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = temporary_root("profile-revalidation");
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        write_private_file(
            &pending.home().join("auth.json"),
            br#"{"synthetic":"test-only"}"#,
        )?;
        let profile = pending.commit()?;
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
    fn registry_sync_failure_preserves_visible_profile_and_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("registry-sync-failure");
        let registry = Registry::at_with_registry_sync_failure(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        write_private_file(
            &pending.home().join("auth.json"),
            br#"{"synthetic":"test-only"}"#,
        )?;

        let result = pending.commit();
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
