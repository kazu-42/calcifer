use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use fs2::FileExt;
use uuid::Uuid;

use super::{DefinitionError, DefinitionMutation, Definitions, MAX_SERIALIZED_BYTES};
use crate::profiles::{
    ProfileError, Registry, create_new_private_file, open_private_lock_file,
    open_verified_registry_file, secure_create_dir_all, sync_directory, verify_private_directory,
    verify_private_regular_file,
};
use crate::provider_identity::IdentityError;

const REGISTRY_FILE: &str = "routing.json";
const LOCK_FILE: &str = "routing.lock";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
enum WriteFault {
    BeforeFileSync,
    BeforeRename,
    AfterRename,
}

/// Durable user-level storage for inert routing definitions.
///
/// Production construction only accepts the already validated Calcifer data
/// root. A repository path or current working directory is never an input to
/// this authority boundary.
#[derive(Clone, Debug)]
pub(crate) struct Store {
    root: PathBuf,
    #[cfg(test)]
    fault: Option<WriteFault>,
}

impl Store {
    pub(crate) fn from_profiles(registry: &Registry) -> Self {
        Self {
            root: registry.managed_root().to_owned(),
            #[cfg(test)]
            fault: None,
        }
    }

    pub(crate) fn read(&self) -> Result<Definitions, RoutingError> {
        ensure_supported()?;
        match fs::symlink_metadata(&self.root) {
            Ok(_) => verify_private_directory(&self.root).map_err(storage_error)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Definitions::default());
            }
            Err(_) => return Err(RoutingError::StorageUnavailable),
        }

        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock).map_err(|_| RoutingError::StorageUnavailable)?;
        self.load()
    }

    #[cfg(test)]
    fn transact(
        &self,
        mutation: DefinitionMutation,
    ) -> Result<super::MutationOutcome, RoutingError> {
        self.transact_locked(None, mutation)
    }

    pub(crate) fn commit(
        &self,
        expected_revision: u64,
        mutation: DefinitionMutation,
    ) -> Result<super::MutationOutcome, RoutingError> {
        self.transact_locked(Some(expected_revision), mutation)
    }

    fn transact_locked(
        &self,
        expected_revision: Option<u64>,
        mutation: DefinitionMutation,
    ) -> Result<super::MutationOutcome, RoutingError> {
        ensure_supported()?;
        secure_create_dir_all(&self.root).map_err(storage_error)?;
        verify_private_directory(&self.root).map_err(storage_error)?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock).map_err(|_| RoutingError::StorageUnavailable)?;

        let mut definitions = self.load()?;
        let expected_revision = expected_revision.unwrap_or_else(|| definitions.revision());
        let outcome = definitions.apply(expected_revision, mutation)?;
        if outcome.changed() {
            self.save(&definitions)?;
        }
        Ok(outcome)
    }

    fn open_lock(&self) -> Result<fs::File, RoutingError> {
        let path = self.root.join(LOCK_FILE);
        let new_file = match fs::symlink_metadata(&path) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(_) => return Err(RoutingError::StorageUnavailable),
        };
        let file = open_private_lock_file(&path).map_err(storage_error)?;
        if new_file {
            file.sync_all()
                .map_err(|_| RoutingError::StorageUnavailable)?;
            sync_directory(&self.root).map_err(storage_error)?;
        }
        Ok(file)
    }

    fn load(&self) -> Result<Definitions, RoutingError> {
        let path = self.root.join(REGISTRY_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Definitions::default());
            }
            Err(_) => return Err(RoutingError::StorageUnavailable),
        }

        let mut bytes = Vec::new();
        open_verified_registry_file(&path, true)
            .map_err(storage_error)?
            .take((MAX_SERIALIZED_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| RoutingError::StorageUnavailable)?;
        Definitions::from_json(&bytes).map_err(RoutingError::Definition)
    }

    fn save(&self, definitions: &Definitions) -> Result<(), RoutingError> {
        let bytes = definitions.to_json()?;
        let temporary_name = format!(".{REGISTRY_FILE}.{}.tmp", Uuid::new_v4());
        let temporary = self.root.join(&temporary_name);
        let destination = self.root.join(REGISTRY_FILE);

        let publication = (|| {
            let mut file = create_new_private_file(&temporary).map_err(storage_error)?;
            file.write_all(&bytes)
                .map_err(|_| RoutingError::StorageUnavailable)?;

            #[cfg(test)]
            if self.fault == Some(WriteFault::BeforeFileSync) {
                return Err(RoutingError::StorageUnavailable);
            }

            file.sync_all()
                .map_err(|_| RoutingError::StorageUnavailable)?;
            verify_private_regular_file(&temporary).map_err(storage_error)?;
            drop(file);

            #[cfg(test)]
            if self.fault == Some(WriteFault::BeforeRename) {
                return Err(RoutingError::StorageUnavailable);
            }

            fs::rename(&temporary, &destination).map_err(|_| RoutingError::StorageUnavailable)?;
            Ok(())
        })();
        if let Err(error) = publication {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }

        #[cfg(test)]
        if self.fault == Some(WriteFault::AfterRename) {
            return Err(self.confirm_uncertain_commit(definitions.revision()));
        }

        if sync_directory(&self.root).is_err() {
            return Err(self.confirm_uncertain_commit(definitions.revision()));
        }
        Ok(())
    }

    fn confirm_uncertain_commit(&self, intended_revision: u64) -> RoutingError {
        let _intended_revision_is_visible = self
            .load()
            .is_ok_and(|definitions| definitions.revision() == intended_revision);
        RoutingError::CommitUncertain
    }

    #[cfg(test)]
    pub(super) fn at(root: PathBuf) -> Self {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RoutingError {
    Definition(DefinitionError),
    StorageInvalid,
    StorageUnavailable,
    CommitUncertain,
    UnsupportedPlatform,
    ProfileMissing,
    ProfileProviderMismatch,
    ProfileBusy,
    ProfileInvalid,
    ProfileUnavailable,
    IdentityUnverified,
    IdentityUnsupported,
    IdentityInvalid,
    IdentityMismatch,
    IdentityKeyUnavailable,
    IdentityCommitUncertain,
    DuplicateProviderIdentity,
}

impl RoutingError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Definition(error) => error.code(),
            Self::StorageInvalid => "routing_storage_invalid",
            Self::StorageUnavailable => "routing_storage_unavailable",
            Self::CommitUncertain => "routing_commit_uncertain",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::ProfileMissing => "routing_profile_missing",
            Self::ProfileProviderMismatch => "routing_profile_provider_mismatch",
            Self::ProfileBusy => "routing_profile_busy",
            Self::ProfileInvalid => "routing_profile_invalid",
            Self::ProfileUnavailable => "routing_profile_unavailable",
            Self::IdentityUnverified => "provider_identity_unverified",
            Self::IdentityUnsupported => "provider_identity_unsupported",
            Self::IdentityInvalid => "provider_identity_invalid",
            Self::IdentityMismatch => "provider_identity_mismatch",
            Self::IdentityKeyUnavailable => "identity_key_unavailable",
            Self::IdentityCommitUncertain => "identity_commit_uncertain",
            Self::DuplicateProviderIdentity => "routing_duplicate_provider_identity",
        }
    }

    pub(crate) const fn safe_message(self) -> &'static str {
        match self {
            Self::Definition(error) => error.safe_message(),
            Self::StorageInvalid => "Calcifer's routing storage is invalid or unsafe.",
            Self::StorageUnavailable => "Calcifer could not access its routing storage.",
            Self::CommitUncertain => {
                "The routing update became visible, but durability could not be confirmed. Inspect the routing registry before retrying."
            }
            Self::UnsupportedPlatform => {
                "Routing definitions are not supported on this platform because private storage has not been verified."
            }
            Self::ProfileMissing => "A routing member no longer resolves to a registered profile.",
            Self::ProfileProviderMismatch => {
                "A routing member belongs to a different provider than its trust domain."
            }
            Self::ProfileBusy => {
                "A routing member is currently in use and could not be identity-validated."
            }
            Self::ProfileInvalid => {
                "A routing member's managed profile state is invalid or unsafe."
            }
            Self::ProfileUnavailable => {
                "Calcifer could not access a routing member's managed profile."
            }
            Self::IdentityUnverified => {
                "A routing member has no verified provider identity. Run `calcifer auth verify codex@<alias>` first."
            }
            Self::IdentityUnsupported => {
                "A routing member uses an unsupported Codex version or authentication mode."
            }
            Self::IdentityInvalid => {
                "A routing member's private provider identity state is invalid."
            }
            Self::IdentityMismatch => {
                "A routing member's current authentication no longer matches its verified provider identity."
            }
            Self::IdentityKeyUnavailable => {
                "Calcifer's private provider identity key is unavailable or inconsistent."
            }
            Self::IdentityCommitUncertain => {
                "A private provider identity update reached an uncertain durability boundary."
            }
            Self::DuplicateProviderIdentity => {
                "Two routing members resolve to the same private provider identity."
            }
        }
    }
}

impl fmt::Display for RoutingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for RoutingError {}

impl From<DefinitionError> for RoutingError {
    fn from(error: DefinitionError) -> Self {
        Self::Definition(error)
    }
}

impl From<ProfileError> for RoutingError {
    fn from(error: ProfileError) -> Self {
        match error {
            ProfileError::NotFound(_) => Self::ProfileMissing,
            ProfileError::Busy(_) => Self::ProfileBusy,
            ProfileError::DuplicateProviderIdentity { .. } => Self::DuplicateProviderIdentity,
            ProfileError::Identity(error) => Self::from(error),
            ProfileError::UnsupportedPlatform => Self::UnsupportedPlatform,
            ProfileError::UnsafeState(_)
            | ProfileError::InvalidRegistry(_)
            | ProfileError::RegistrationRecoveryRequired
            | ProfileError::RemovalRecoveryRequired => Self::ProfileInvalid,
            _ => Self::ProfileUnavailable,
        }
    }
}

impl From<IdentityError> for RoutingError {
    fn from(error: IdentityError) -> Self {
        match error {
            IdentityError::Unverified => Self::IdentityUnverified,
            IdentityError::Unsupported => Self::IdentityUnsupported,
            IdentityError::Invalid => Self::IdentityInvalid,
            IdentityError::Mismatch => Self::IdentityMismatch,
            IdentityError::KeyUnavailable => Self::IdentityKeyUnavailable,
            IdentityError::CommitUncertain => Self::IdentityCommitUncertain,
            IdentityError::Io(_) => Self::ProfileUnavailable,
        }
    }
}

fn storage_error(error: ProfileError) -> RoutingError {
    match error {
        ProfileError::UnsupportedPlatform => RoutingError::UnsupportedPlatform,
        ProfileError::UnsafeState(_) | ProfileError::InvalidRegistry(_) => {
            RoutingError::StorageInvalid
        }
        _ => RoutingError::StorageUnavailable,
    }
}

#[cfg(unix)]
const fn ensure_supported() -> Result<(), RoutingError> {
    Ok(())
}

#[cfg(not(unix))]
const fn ensure_supported() -> Result<(), RoutingError> {
    Err(RoutingError::UnsupportedPlatform)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use uuid::Uuid;

    use super::*;
    use crate::profiles::Provider;
    use crate::routing::{DefinitionMutation, Definitions};

    const DOMAIN_A: &str = "01900000-0000-7000-8000-000000000101";
    const DOMAIN_B: &str = "01900000-0000-7000-8000-000000000102";
    const PROFILE_A: &str = "01900000-0000-7000-8000-000000000111";
    const PROFILE_B: &str = "01900000-0000-7000-8000-000000000112";

    fn private_root(name: &str) -> Result<PathBuf, io::Error> {
        let root = fs::canonicalize(std::env::temp_dir())?
            .join(format!("calcifer-routing-{name}-{}", Uuid::new_v4()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;

            fs::DirBuilder::new().mode(0o700).create(&root)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(&root)?;
        Ok(root)
    }

    fn create_domain(id: &str, alias: &str, profile_id: &str) -> DefinitionMutation {
        DefinitionMutation::CreateDomain {
            id: id.to_owned(),
            alias: alias.to_owned(),
            provider: Provider::Codex,
            profile_ids: vec![profile_id.to_owned()],
        }
    }

    #[test]
    fn private_store_round_trips_and_no_op_does_not_replace_the_document()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("round-trip")?;
        let store = Store::at(root.clone());

        let created = store.transact(create_domain(DOMAIN_A, "personal", PROFILE_A))?;
        assert!(created.changed());
        assert_eq!(created.revision(), 1);
        let before = fs::metadata(root.join(REGISTRY_FILE))?;

        let unchanged = store.transact(DefinitionMutation::RenameDomain {
            id: DOMAIN_A.to_owned(),
            alias: "personal".to_owned(),
        })?;
        let after = fs::metadata(root.join(REGISTRY_FILE))?;
        assert!(!unchanged.changed());
        assert_eq!(unchanged.revision(), 1);
        assert_eq!(store.read()?.revision(), 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            assert_eq!(
                before.ino(),
                after.ino(),
                "a no-op must not replace routing.json"
            );
            assert_eq!(after.mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(root.join(LOCK_FILE))?.mode() & 0o777, 0o600);
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn concurrent_transactions_serialize_without_losing_an_update()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("concurrent")?;
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for (id, alias, profile) in [
            (DOMAIN_A, "personal", PROFILE_A),
            (DOMAIN_B, "work", PROFILE_B),
        ] {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                Store::at(root).transact(create_domain(id, alias, profile))
            }));
        }
        barrier.wait();
        for worker in workers {
            worker
                .join()
                .map_err(|_| io::Error::other("routing worker panicked"))??;
        }

        let definitions = Store::at(root.clone()).read()?;
        assert_eq!(definitions.revision(), 2);
        assert_eq!(definitions.trust_domains.len(), 2);
        assert!(
            definitions
                .trust_domains
                .iter()
                .any(|domain| domain.id == DOMAIN_A)
        );
        assert!(
            definitions
                .trust_domains
                .iter()
                .any(|domain| domain.id == DOMAIN_B)
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn write_faults_expose_only_the_complete_old_or_new_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("faults")?;
        let store = Store::at(root.clone());
        store.transact(create_domain(DOMAIN_A, "personal", PROFILE_A))?;

        for fault in [WriteFault::BeforeFileSync, WriteFault::BeforeRename] {
            let failed = store
                .with_fault(fault)
                .transact(create_domain(DOMAIN_B, "work", PROFILE_B));
            assert!(failed.is_err());
            assert_eq!(store.read()?.revision(), 1);
        }

        let error = store
            .with_fault(WriteFault::AfterRename)
            .transact(create_domain(DOMAIN_B, "work", PROFILE_B))
            .err()
            .ok_or("post-rename fault must be commit-uncertain")?;
        assert_eq!(error.code(), "routing_commit_uncertain");
        let visible = store.read()?;
        assert_eq!(visible.revision(), 2);
        assert_eq!(visible.trust_domains.len(), 2);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_registry_and_lock_nodes_fail_closed_without_reflecting_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = private_root("unsafe-nodes")?;
        let store = Store::at(root.clone());
        store.transact(create_domain(DOMAIN_A, "personal", PROFILE_A))?;
        fs::set_permissions(root.join(REGISTRY_FILE), fs::Permissions::from_mode(0o644))?;

        let error = store.read().err().ok_or("public routing.json must fail")?;
        assert_eq!(error.code(), "routing_storage_invalid");
        assert!(!error.to_string().contains(&root.display().to_string()));

        fs::set_permissions(root.join(REGISTRY_FILE), fs::Permissions::from_mode(0o600))?;
        fs::remove_file(root.join(LOCK_FILE))?;
        let target = root.join("outside-lock");
        fs::write(&target, b"")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        symlink(&target, root.join(LOCK_FILE))?;

        let error = store.read().err().ok_or("symlink routing.lock must fail")?;
        assert_eq!(error.code(), "routing_storage_invalid");
        assert!(!error.to_string().contains(&root.display().to_string()));

        fs::remove_file(root.join(LOCK_FILE))?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_registry_is_an_empty_revision_zero_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("missing")?;
        let definitions = Store::at(root.clone()).read()?;
        assert_eq!(definitions, Definitions::default());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn _assert_path_is_not_part_of_the_store_authority(_path: &Path) {}
}

#[cfg(all(test, not(unix)))]
mod unsupported_tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn private_routing_storage_fails_closed_on_unverified_acl_platforms() {
        let error = Store::at(PathBuf::from("C:\\calcifer-routing-test"))
            .read()
            .err()
            .expect("unverified private storage must remain unavailable");
        assert_eq!(error.code(), "unsupported_platform");
    }
}
