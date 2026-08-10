use std::path::Path;
use std::time::Duration;

use crate::profiles::{Profile, Provider, Registry, VerifiedProviderIdentityLease};
use crate::provider_identity::IdentityError;
use crate::providers::codex::verify_codex_identity_adapter;

use super::storage::Store;
use super::{DefinitionError, DefinitionMutation, Definitions, MutationOutcome, RoutingError};

const IDENTITY_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) trait IdentityProof {
    fn same_provider_identity(&self, other: &Self) -> bool;
}

impl IdentityProof for VerifiedProviderIdentityLease {
    fn same_provider_identity(&self, other: &Self) -> bool {
        Self::same_provider_identity(self, other)
    }
}

pub(crate) trait MembershipSource {
    type Proof: IdentityProof;

    fn resolve(&self, profile_id: &str) -> Result<Profile, RoutingError>;
    fn verify(&self, profile: &Profile) -> Result<Self::Proof, RoutingError>;
}

pub(crate) struct LiveMembershipSource<'source> {
    registry: &'source Registry,
    executable: Option<&'source Path>,
    neutral_working_directory: Option<&'source Path>,
    profiles: Vec<Profile>,
}

impl<'source> LiveMembershipSource<'source> {
    pub(crate) fn new(
        registry: &'source Registry,
        executable: Option<&'source Path>,
        neutral_working_directory: Option<&'source Path>,
        profiles: Vec<Profile>,
    ) -> Self {
        Self {
            registry,
            executable,
            neutral_working_directory,
            profiles,
        }
    }

    pub(crate) fn resolve_alias(
        &self,
        provider: Provider,
        alias: &str,
    ) -> Result<Profile, RoutingError> {
        self.profiles
            .iter()
            .find(|profile| profile.provider == provider && profile.alias == alias)
            .cloned()
            .ok_or(RoutingError::ProfileMissing)
    }
}

impl MembershipSource for LiveMembershipSource<'_> {
    type Proof = VerifiedProviderIdentityLease;

    fn resolve(&self, profile_id: &str) -> Result<Profile, RoutingError> {
        self.profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .cloned()
            .ok_or(RoutingError::ProfileMissing)
    }

    fn verify(&self, profile: &Profile) -> Result<Self::Proof, RoutingError> {
        let (executable, neutral_working_directory) = self
            .executable
            .zip(self.neutral_working_directory)
            .ok_or(RoutingError::IdentityUnsupported)?;
        let verified = self
            .registry
            .revalidate_codex_identity(profile, |home, provider_lease| {
                verify_codex_identity_adapter(
                    executable,
                    home,
                    neutral_working_directory,
                    IDENTITY_PROBE_TIMEOUT,
                    provider_lease,
                )
                .map_err(|_| IdentityError::Unsupported.into())
            })
            .map_err(RoutingError::from)?;
        if verified.profile().alias != profile.alias {
            return Err(RoutingError::ProfileMissing);
        }
        Ok(verified)
    }
}

#[cfg(test)]
pub(crate) fn mutate<S: MembershipSource>(
    store: &Store,
    source: &S,
    mutation: DefinitionMutation,
) -> Result<MutationOutcome, RoutingError> {
    let snapshot = store.read()?;
    mutate_snapshot(store, source, &snapshot, mutation)
}

pub(crate) fn mutate_snapshot<S: MembershipSource>(
    store: &Store,
    source: &S,
    snapshot: &Definitions,
    mutation: DefinitionMutation,
) -> Result<MutationOutcome, RoutingError> {
    if let Some(validation) = membership_validation(snapshot, &mutation)? {
        let _proofs = validate_members(source, validation)?;
        return store.commit(snapshot.revision(), mutation);
    }
    store.commit(snapshot.revision(), mutation)
}

pub(crate) fn preflight(
    snapshot: &Definitions,
    mutation: &DefinitionMutation,
) -> Result<(), RoutingError> {
    let _ = membership_validation(snapshot, mutation)?;
    Ok(())
}

struct MembershipValidation {
    provider: Provider,
    profile_ids: Vec<String>,
}

fn membership_validation(
    definitions: &Definitions,
    mutation: &DefinitionMutation,
) -> Result<Option<MembershipValidation>, DefinitionError> {
    let target = match mutation {
        DefinitionMutation::CreateDomain { id, .. }
        | DefinitionMutation::ReplaceDomainMembers { id, .. } => Some((true, id.as_str())),
        DefinitionMutation::CreatePool { id, .. }
        | DefinitionMutation::ReplacePoolMembers { id, .. } => Some((false, id.as_str())),
        DefinitionMutation::SetPoolActivation { id, enabled: true } => Some((false, id.as_str())),
        DefinitionMutation::RenameDomain { .. }
        | DefinitionMutation::RemoveDomain { .. }
        | DefinitionMutation::RenamePool { .. }
        | DefinitionMutation::SetPoolActivation { enabled: false, .. }
        | DefinitionMutation::RemovePool { .. } => None,
    };
    let Some((is_domain, target_id)) = target else {
        return Ok(None);
    };

    let mut candidate = definitions.clone();
    candidate.apply(definitions.revision(), mutation.clone())?;
    if is_domain {
        let domain = candidate
            .trust_domains
            .iter()
            .find(|domain| domain.id == target_id)
            .ok_or(DefinitionError::NotFound)?;
        return Ok(Some(MembershipValidation {
            provider: domain.provider,
            profile_ids: domain.profile_ids.clone(),
        }));
    }

    let pool = candidate
        .pools
        .iter()
        .find(|pool| pool.id == target_id)
        .ok_or(DefinitionError::NotFound)?;
    let provider = candidate.domain_provider(&pool.trust_domain_id)?;
    Ok(Some(MembershipValidation {
        provider,
        profile_ids: pool.profile_ids.clone(),
    }))
}

fn validate_members<S: MembershipSource>(
    source: &S,
    mut validation: MembershipValidation,
) -> Result<Vec<S::Proof>, RoutingError> {
    validation.profile_ids.sort();
    let profiles = validation
        .profile_ids
        .iter()
        .map(|profile_id| source.resolve(profile_id))
        .collect::<Result<Vec<_>, _>>()?;
    if profiles
        .iter()
        .any(|profile| profile.provider != validation.provider)
    {
        return Err(RoutingError::ProfileProviderMismatch);
    }

    let mut proofs = Vec::with_capacity(profiles.len());
    for profile in &profiles {
        let proof = source.verify(profile)?;
        if proofs
            .iter()
            .any(|existing: &S::Proof| existing.same_provider_identity(&proof))
        {
            return Err(RoutingError::DuplicateProviderIdentity);
        }
        proofs.push(proof);
    }
    Ok(proofs)
}

#[cfg(all(test, unix))]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io;
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::*;
    use crate::profiles::{Profile, Provider};
    use crate::routing::storage::Store;
    use crate::routing::{DefinitionMutation, RoutingError};

    const DOMAIN_ID: &str = "01900000-0000-7000-8000-000000000201";
    const POOL_ID: &str = "01900000-0000-7000-8000-000000000202";
    const PROFILE_A: &str = "01900000-0000-7000-8000-000000000211";
    const PROFILE_B: &str = "01900000-0000-7000-8000-000000000212";

    #[derive(Clone, Copy)]
    struct FakeProof(u8);

    impl IdentityProof for FakeProof {
        fn same_provider_identity(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    struct FakeSource {
        profiles: BTreeMap<String, Profile>,
        resolve_errors: BTreeMap<String, RoutingError>,
        identities: BTreeMap<String, Result<u8, RoutingError>>,
        verified: RefCell<Vec<String>>,
    }

    impl FakeSource {
        fn healthy() -> Self {
            Self {
                profiles: [
                    test_profile(PROFILE_A, "work"),
                    test_profile(PROFILE_B, "personal"),
                ]
                .into_iter()
                .map(|profile| (profile.id.clone(), profile))
                .collect(),
                resolve_errors: BTreeMap::new(),
                identities: [(PROFILE_A.to_owned(), Ok(1)), (PROFILE_B.to_owned(), Ok(2))]
                    .into_iter()
                    .collect(),
                verified: RefCell::new(Vec::new()),
            }
        }
    }

    impl MembershipSource for FakeSource {
        type Proof = FakeProof;

        fn resolve(&self, profile_id: &str) -> Result<Profile, RoutingError> {
            if let Some(error) = self.resolve_errors.get(profile_id) {
                return Err(*error);
            }
            self.profiles
                .get(profile_id)
                .cloned()
                .ok_or(RoutingError::ProfileMissing)
        }

        fn verify(&self, profile: &Profile) -> Result<Self::Proof, RoutingError> {
            self.verified.borrow_mut().push(profile.id.clone());
            self.identities
                .get(&profile.id)
                .cloned()
                .unwrap_or(Err(RoutingError::ProfileMissing))
                .map(FakeProof)
        }
    }

    fn private_root(name: &str) -> Result<PathBuf, io::Error> {
        let root = fs::canonicalize(std::env::temp_dir())?.join(format!(
            "calcifer-routing-validation-{name}-{}",
            Uuid::new_v4()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;

            fs::DirBuilder::new().mode(0o700).create(&root)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(&root)?;
        Ok(root)
    }

    fn test_profile(id: &str, alias: &str) -> Profile {
        Profile {
            id: id.to_owned(),
            alias: alias.to_owned(),
            provider: Provider::Codex,
            created_at: 0,
        }
    }

    fn create_domain() -> DefinitionMutation {
        DefinitionMutation::CreateDomain {
            id: DOMAIN_ID.to_owned(),
            alias: "accounts".to_owned(),
            provider: Provider::Codex,
            profile_ids: vec![PROFILE_B.to_owned(), PROFILE_A.to_owned()],
        }
    }

    fn create_pool() -> DefinitionMutation {
        DefinitionMutation::CreatePool {
            id: POOL_ID.to_owned(),
            alias: "fallback".to_owned(),
            trust_domain_id: DOMAIN_ID.to_owned(),
            profile_ids: vec![PROFILE_B.to_owned(), PROFILE_A.to_owned()],
        }
    }

    #[test]
    fn membership_changes_validate_every_member_in_immutable_id_order_before_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("valid")?;
        let store = Store::at(root.clone());
        let source = FakeSource::healthy();

        let domain = mutate(&store, &source, create_domain())?;
        assert_eq!(domain.revision(), 1);
        assert_eq!(
            source.verified.take(),
            [PROFILE_A.to_owned(), PROFILE_B.to_owned()]
        );

        let pool = mutate(&store, &source, create_pool())?;
        assert_eq!(pool.revision(), 2);
        assert_eq!(
            source.verified.take(),
            [PROFILE_A.to_owned(), PROFILE_B.to_owned()]
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_unverified_or_drifted_member_aborts_the_whole_update()
    -> Result<(), Box<dyn std::error::Error>> {
        for (name, error) in [
            ("missing", RoutingError::ProfileMissing),
            ("unverified", RoutingError::IdentityUnverified),
            ("drift", RoutingError::IdentityMismatch),
        ] {
            let root = private_root(name)?;
            let store = Store::at(root.clone());
            let mut source = FakeSource::healthy();
            source.identities.insert(PROFILE_B.to_owned(), Err(error));

            let failure = mutate(&store, &source, create_domain())
                .err()
                .ok_or("invalid identity state must stop the update")?;
            assert_eq!(failure.code(), error.code());
            assert_eq!(store.read()?.revision(), 0);
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn duplicate_effective_identity_aborts_the_whole_update()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("duplicate")?;
        let store = Store::at(root.clone());
        let mut source = FakeSource::healthy();
        source.identities.insert(PROFILE_B.to_owned(), Ok(1));

        let error = mutate(&store, &source, create_domain())
            .err()
            .ok_or("duplicate provider identity must stop the update")?;
        assert_eq!(error.code(), "routing_duplicate_provider_identity");
        assert_eq!(store.read()?.revision(), 0);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn provider_mismatch_is_rejected_before_an_identity_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("provider")?;
        let store = Store::at(root.clone());
        let mut source = FakeSource::healthy();
        source
            .resolve_errors
            .insert(PROFILE_A.to_owned(), RoutingError::ProfileProviderMismatch);

        let error = mutate(&store, &source, create_domain())
            .err()
            .ok_or("provider mismatch must stop the update")?;
        assert_eq!(error.code(), "routing_profile_provider_mismatch");
        assert_eq!(store.read()?.revision(), 0);
        assert!(source.verified.borrow().is_empty());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn metadata_cleanup_does_not_require_a_live_identity_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("cleanup")?;
        let store = Store::at(root.clone());
        let mut source = FakeSource::healthy();
        mutate(&store, &source, create_domain())?;
        source.verified.borrow_mut().clear();
        source
            .identities
            .insert(PROFILE_A.to_owned(), Err(RoutingError::IdentityMismatch));

        let renamed = mutate(
            &store,
            &source,
            DefinitionMutation::RenameDomain {
                id: DOMAIN_ID.to_owned(),
                alias: "renamed".to_owned(),
            },
        )?;
        assert_eq!(renamed.revision(), 2);
        assert!(source.verified.borrow().is_empty());

        fs::remove_dir_all(root)?;
        Ok(())
    }
}
