use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::profiles::{Profile, Provider, validate_alias};

pub(crate) mod storage;
pub(crate) mod validation;

pub(crate) use storage::RoutingError;

const SCHEMA_VERSION: u8 = 1;
const MAX_SERIALIZED_BYTES: usize = 512 * 1024;
const MAX_TRUST_DOMAINS: usize = 128;
const MAX_POOLS: usize = 256;
const MAX_DOMAIN_PROFILE_IDS: usize = 64;
const MAX_POOL_PROFILE_IDS: usize = 32;
const MAX_MEMBERSHIP_EDGES: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Definitions {
    schema_version: u8,
    revision: u64,
    trust_domains: Vec<TrustDomainDefinition>,
    pools: Vec<PoolDefinition>,
}

/// Proof that two distinct profiles are members of one provider trust domain.
///
/// The proof contains no aliases, credentials, or provider-owned state. It is
/// intentionally minted from the validated routing snapshot immediately
/// before a durable handoff is prepared.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))] // Activated by cross-profile selection in issue #36.
pub(crate) struct HandoffAuthorization {
    trust_domain_id: String,
}

impl HandoffAuthorization {
    #[cfg_attr(not(test), allow(dead_code))] // Activated by cross-profile selection in issue #36.
    pub(crate) fn trust_domain_id(&self) -> &str {
        &self.trust_domain_id
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefinitionsDocument {
    schema_version: u8,
    revision: u64,
    trust_domains: Vec<TrustDomainDefinition>,
    pools: Vec<PoolDefinition>,
}

#[derive(Serialize)]
struct DefinitionsDocumentRef<'definitions> {
    schema_version: u8,
    revision: u64,
    trust_domains: &'definitions [TrustDomainDefinition],
    pools: &'definitions [PoolDefinition],
}

impl Default for Definitions {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            trust_domains: Vec::new(),
            pools: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustDomainDefinition {
    id: String,
    alias: String,
    provider: Provider,
    profile_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PoolDefinition {
    id: String,
    alias: String,
    trust_domain_id: String,
    activation: Activation,
    profile_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Inspection {
    revision: u64,
    trust_domains: Vec<TrustDomainInspection>,
    pools: Vec<PoolInspection>,
}

#[derive(Debug, Serialize)]
struct TrustDomainInspection {
    id: String,
    alias: String,
    provider: Provider,
    members: Vec<MemberInspection>,
}

#[derive(Debug, Serialize)]
struct PoolInspection {
    id: String,
    alias: String,
    trust_domain_id: String,
    activation: Activation,
    members: Vec<MemberInspection>,
}

#[derive(Debug, Serialize)]
struct MemberInspection {
    profile_id: String,
    profile: Option<String>,
}

impl Inspection {
    pub(crate) fn new(definitions: &Definitions, profiles: &[Profile]) -> Self {
        let member = |profile_id: &String| MemberInspection {
            profile_id: profile_id.clone(),
            profile: profiles
                .iter()
                .find(|profile| profile.id == *profile_id)
                .map(Profile::reference),
        };
        Self {
            revision: definitions.revision,
            trust_domains: definitions
                .trust_domains
                .iter()
                .map(|domain| TrustDomainInspection {
                    id: domain.id.clone(),
                    alias: domain.alias.clone(),
                    provider: domain.provider,
                    members: domain.profile_ids.iter().map(member).collect(),
                })
                .collect(),
            pools: definitions
                .pools
                .iter()
                .map(|pool| PoolInspection {
                    id: pool.id.clone(),
                    alias: pool.alias.clone(),
                    trust_domain_id: pool.trust_domain_id.clone(),
                    activation: pool.activation,
                    members: pool.profile_ids.iter().map(member).collect(),
                })
                .collect(),
        }
    }

    pub(crate) fn to_human(&self) -> String {
        let mut lines = vec![format!("Routing registry revision {}", self.revision)];
        if self.trust_domains.is_empty() {
            lines.push("Trust domains: none".to_owned());
        } else {
            lines.push("Trust domains:".to_owned());
            for domain in &self.trust_domains {
                lines.push(format!(
                    "- {}@{} ({})",
                    domain.provider.as_str(),
                    domain.alias,
                    domain.id
                ));
                lines.push(format!("  members: {}", human_members(&domain.members)));
            }
        }
        if self.pools.is_empty() {
            lines.push("Pools: none".to_owned());
        } else {
            lines.push("Pools:".to_owned());
            for pool in &self.pools {
                lines.push(format!(
                    "- {} ({}, trust domain {}, disabled)",
                    pool.alias, pool.id, pool.trust_domain_id
                ));
                lines.push(format!("  members: {}", human_members(&pool.members)));
            }
        }
        lines.push("Automatic routing is disabled; these definitions cannot launch or select a provider profile.".to_owned());
        lines.join("\n")
    }
}

fn human_members(members: &[MemberInspection]) -> String {
    if members.is_empty() {
        return "none".to_owned();
    }
    members
        .iter()
        .map(|member| {
            member.profile.as_ref().map_or_else(
                || format!("missing profile ({})", member.profile_id),
                |profile| format!("{profile} ({})", member.profile_id),
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Activation {
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DefinitionMutation {
    CreateDomain {
        id: String,
        alias: String,
        provider: Provider,
        profile_ids: Vec<String>,
    },
    RenameDomain {
        id: String,
        alias: String,
    },
    ReplaceDomainMembers {
        id: String,
        profile_ids: Vec<String>,
    },
    RemoveDomain {
        id: String,
    },
    CreatePool {
        id: String,
        alias: String,
        trust_domain_id: String,
        profile_ids: Vec<String>,
    },
    RenamePool {
        id: String,
        alias: String,
    },
    ReplacePoolMembers {
        id: String,
        profile_ids: Vec<String>,
    },
    RemovePool {
        id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MutationOutcome {
    changed: bool,
    revision: u64,
}

impl MutationOutcome {
    pub(crate) const fn changed(self) -> bool {
        self.changed
    }

    pub(crate) const fn revision(self) -> u64 {
        self.revision
    }
}

impl Definitions {
    pub(crate) fn from_json(bytes: &[u8]) -> Result<Self, DefinitionError> {
        if bytes.len() > MAX_SERIALIZED_BYTES {
            return Err(DefinitionError::LimitExceeded);
        }
        let document: DefinitionsDocument =
            serde_json::from_slice(bytes).map_err(|_| DefinitionError::InvalidSchema)?;
        let definitions = Self {
            schema_version: document.schema_version,
            revision: document.revision,
            trust_domains: document.trust_domains,
            pools: document.pools,
        };
        definitions.validate()?;
        Ok(definitions)
    }

    pub(crate) fn to_json(&self) -> Result<Vec<u8>, DefinitionError> {
        self.validate()?;
        let bytes = self.serialize_document()?;
        if bytes.len() > MAX_SERIALIZED_BYTES {
            return Err(DefinitionError::LimitExceeded);
        }
        Ok(bytes)
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn resolve_domain_id(
        &self,
        provider: Option<Provider>,
        value: &str,
    ) -> Result<String, DefinitionError> {
        if let Some(provider) = provider {
            validate_definition_alias(value)?;
            return self
                .trust_domains
                .iter()
                .find(|domain| domain.provider == provider && domain.alias == value)
                .map(|domain| domain.id.clone())
                .ok_or(DefinitionError::NotFound);
        }
        validate_uuid(value)?;
        self.trust_domains
            .iter()
            .find(|domain| domain.id == value)
            .map(|domain| domain.id.clone())
            .ok_or(DefinitionError::NotFound)
    }

    pub(crate) fn resolve_pool_id(
        &self,
        provider: Option<Provider>,
        value: &str,
    ) -> Result<String, DefinitionError> {
        if let Some(provider) = provider {
            validate_definition_alias(value)?;
            return self
                .pools
                .iter()
                .find(|pool| {
                    pool.alias == value
                        && self
                            .domain_provider(&pool.trust_domain_id)
                            .is_ok_and(|pool_provider| pool_provider == provider)
                })
                .map(|pool| pool.id.clone())
                .ok_or(DefinitionError::NotFound);
        }
        validate_uuid(value)?;
        self.pools
            .iter()
            .find(|pool| pool.id == value)
            .map(|pool| pool.id.clone())
            .ok_or(DefinitionError::NotFound)
    }

    pub(crate) fn domain_provider_for_id(
        &self,
        domain_id: &str,
    ) -> Result<Provider, DefinitionError> {
        self.domain_provider(domain_id)
    }

    #[cfg_attr(not(test), allow(dead_code))] // Activated by cross-profile selection in issue #36.
    pub(crate) fn authorize_handoff(
        &self,
        trust_domain_id: &str,
        source_profile_id: &str,
        target_profile_id: &str,
        provider: Provider,
    ) -> Result<HandoffAuthorization, DefinitionError> {
        validate_uuid(trust_domain_id)?;
        validate_uuid(source_profile_id)?;
        validate_uuid(target_profile_id)?;
        let domain = self
            .trust_domains
            .iter()
            .find(|domain| domain.id == trust_domain_id)
            .ok_or(DefinitionError::NotFound)?;
        if source_profile_id == target_profile_id
            || domain.provider != provider
            || domain
                .profile_ids
                .binary_search_by(|candidate| candidate.as_str().cmp(source_profile_id))
                .is_err()
            || domain
                .profile_ids
                .binary_search_by(|candidate| candidate.as_str().cmp(target_profile_id))
                .is_err()
        {
            return Err(DefinitionError::InvalidMembership);
        }
        Ok(HandoffAuthorization {
            trust_domain_id: domain.id.clone(),
        })
    }

    pub(crate) fn pool_provider_for_id(&self, pool_id: &str) -> Result<Provider, DefinitionError> {
        let pool = self
            .pools
            .iter()
            .find(|pool| pool.id == pool_id)
            .ok_or(DefinitionError::NotFound)?;
        self.domain_provider(&pool.trust_domain_id)
    }

    pub(crate) fn apply(
        &mut self,
        expected_revision: u64,
        mutation: DefinitionMutation,
    ) -> Result<MutationOutcome, DefinitionError> {
        if self.revision != expected_revision {
            return Err(DefinitionError::RevisionConflict);
        }

        let mut candidate = self.clone();
        let changed = candidate.apply_mutation(mutation)?;
        if !changed {
            candidate.validate()?;
            return Ok(MutationOutcome {
                changed: false,
                revision: self.revision,
            });
        }
        candidate.revision = candidate
            .revision
            .checked_add(1)
            .ok_or(DefinitionError::RevisionOverflow)?;
        candidate.validate()?;
        *self = candidate;
        Ok(MutationOutcome {
            changed: true,
            revision: self.revision,
        })
    }

    fn apply_mutation(&mut self, mutation: DefinitionMutation) -> Result<bool, DefinitionError> {
        match mutation {
            DefinitionMutation::CreateDomain {
                id,
                alias,
                provider,
                profile_ids,
            } => {
                validate_uuid(&id)?;
                validate_definition_alias(&alias)?;
                let profile_ids = canonical_member_set(profile_ids, MAX_DOMAIN_PROFILE_IDS)?;
                if self.trust_domains.iter().any(|domain| domain.id == id)
                    || self.pools.iter().any(|pool| pool.id == id)
                    || self
                        .trust_domains
                        .iter()
                        .any(|domain| domain.provider == provider && domain.alias == alias)
                {
                    return Err(DefinitionError::AlreadyExists);
                }
                self.trust_domains.push(TrustDomainDefinition {
                    id,
                    alias,
                    provider,
                    profile_ids,
                });
                self.trust_domains
                    .sort_by(|left, right| left.id.cmp(&right.id));
                Ok(true)
            }
            DefinitionMutation::RenameDomain { id, alias } => {
                validate_uuid(&id)?;
                validate_definition_alias(&alias)?;
                let index = self
                    .trust_domains
                    .iter()
                    .position(|domain| domain.id == id)
                    .ok_or(DefinitionError::NotFound)?;
                let provider = self.trust_domains[index].provider;
                if self.trust_domains[index].alias == alias {
                    return Ok(false);
                }
                if self
                    .trust_domains
                    .iter()
                    .enumerate()
                    .any(|(other_index, domain)| {
                        other_index != index && domain.provider == provider && domain.alias == alias
                    })
                {
                    return Err(DefinitionError::AlreadyExists);
                }
                self.trust_domains[index].alias = alias;
                Ok(true)
            }
            DefinitionMutation::ReplaceDomainMembers { id, profile_ids } => {
                validate_uuid(&id)?;
                let profile_ids = canonical_member_set(profile_ids, MAX_DOMAIN_PROFILE_IDS)?;
                let domain = self
                    .trust_domains
                    .iter_mut()
                    .find(|domain| domain.id == id)
                    .ok_or(DefinitionError::NotFound)?;
                if domain.profile_ids == profile_ids {
                    return Ok(false);
                }
                domain.profile_ids = profile_ids;
                Ok(true)
            }
            DefinitionMutation::RemoveDomain { id } => {
                validate_uuid(&id)?;
                let index = self
                    .trust_domains
                    .iter()
                    .position(|domain| domain.id == id)
                    .ok_or(DefinitionError::NotFound)?;
                if self.pools.iter().any(|pool| pool.trust_domain_id == id) {
                    return Err(DefinitionError::DomainInUse);
                }
                self.trust_domains.remove(index);
                Ok(true)
            }
            DefinitionMutation::CreatePool {
                id,
                alias,
                trust_domain_id,
                profile_ids,
            } => {
                validate_uuid(&id)?;
                validate_uuid(&trust_domain_id)?;
                validate_definition_alias(&alias)?;
                let profile_ids = ordered_pool_members(profile_ids)?;
                let provider = self.domain_provider(&trust_domain_id)?;
                if self.pools.iter().any(|pool| pool.id == id)
                    || self.trust_domains.iter().any(|domain| domain.id == id)
                    || self.pools.iter().any(|pool| {
                        pool.alias == alias
                            && self
                                .domain_provider(&pool.trust_domain_id)
                                .is_ok_and(|existing_provider| existing_provider == provider)
                    })
                {
                    return Err(DefinitionError::AlreadyExists);
                }
                self.pools.push(PoolDefinition {
                    id,
                    alias,
                    trust_domain_id,
                    activation: Activation::Disabled,
                    profile_ids,
                });
                self.pools.sort_by(|left, right| left.id.cmp(&right.id));
                Ok(true)
            }
            DefinitionMutation::RenamePool { id, alias } => {
                validate_uuid(&id)?;
                validate_definition_alias(&alias)?;
                let index = self
                    .pools
                    .iter()
                    .position(|pool| pool.id == id)
                    .ok_or(DefinitionError::NotFound)?;
                if self.pools[index].alias == alias {
                    return Ok(false);
                }
                let provider = self.domain_provider(&self.pools[index].trust_domain_id)?;
                if self.pools.iter().enumerate().any(|(other_index, pool)| {
                    other_index != index
                        && pool.alias == alias
                        && self
                            .domain_provider(&pool.trust_domain_id)
                            .is_ok_and(|existing_provider| existing_provider == provider)
                }) {
                    return Err(DefinitionError::AlreadyExists);
                }
                self.pools[index].alias = alias;
                Ok(true)
            }
            DefinitionMutation::ReplacePoolMembers { id, profile_ids } => {
                validate_uuid(&id)?;
                let profile_ids = ordered_pool_members(profile_ids)?;
                let pool = self
                    .pools
                    .iter_mut()
                    .find(|pool| pool.id == id)
                    .ok_or(DefinitionError::NotFound)?;
                if pool.profile_ids == profile_ids {
                    return Ok(false);
                }
                pool.profile_ids = profile_ids;
                Ok(true)
            }
            DefinitionMutation::RemovePool { id } => {
                validate_uuid(&id)?;
                let index = self
                    .pools
                    .iter()
                    .position(|pool| pool.id == id)
                    .ok_or(DefinitionError::NotFound)?;
                self.pools.remove(index);
                Ok(true)
            }
        }
    }

    fn domain_provider(&self, domain_id: &str) -> Result<Provider, DefinitionError> {
        self.trust_domains
            .iter()
            .find(|domain| domain.id == domain_id)
            .map(|domain| domain.provider)
            .ok_or(DefinitionError::NotFound)
    }

    fn validate(&self) -> Result<(), DefinitionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DefinitionError::InvalidSchema);
        }
        if self.trust_domains.len() > MAX_TRUST_DOMAINS || self.pools.len() > MAX_POOLS {
            return Err(DefinitionError::LimitExceeded);
        }
        if !strictly_sorted_by_id(&self.trust_domains, |domain| &domain.id)
            || !strictly_sorted_by_id(&self.pools, |pool| &pool.id)
        {
            return Err(DefinitionError::InvalidSchema);
        }

        let mut definition_ids = BTreeSet::new();
        let mut assigned_profiles = BTreeSet::new();
        let mut membership_edges = 0_usize;
        for (index, domain) in self.trust_domains.iter().enumerate() {
            validate_uuid(&domain.id)?;
            if !definition_ids.insert(domain.id.as_str()) {
                return Err(DefinitionError::AlreadyExists);
            }
            validate_definition_alias(&domain.alias)?;
            if domain.profile_ids.len() > MAX_DOMAIN_PROFILE_IDS {
                return Err(DefinitionError::LimitExceeded);
            }
            if !strictly_sorted_strings(&domain.profile_ids) {
                return Err(DefinitionError::InvalidMembership);
            }
            if self.trust_domains.iter().take(index).any(|previous| {
                previous.provider == domain.provider && previous.alias == domain.alias
            }) {
                return Err(DefinitionError::AlreadyExists);
            }
            for profile_id in &domain.profile_ids {
                validate_uuid(profile_id)?;
                if !assigned_profiles.insert(profile_id.as_str()) {
                    return Err(DefinitionError::ExclusiveMembership);
                }
            }
            membership_edges = membership_edges
                .checked_add(domain.profile_ids.len())
                .ok_or(DefinitionError::LimitExceeded)?;
        }

        for (index, pool) in self.pools.iter().enumerate() {
            validate_uuid(&pool.id)?;
            if !definition_ids.insert(pool.id.as_str()) {
                return Err(DefinitionError::AlreadyExists);
            }
            validate_definition_alias(&pool.alias)?;
            validate_uuid(&pool.trust_domain_id)?;
            if pool.activation != Activation::Disabled {
                return Err(DefinitionError::InvalidSchema);
            }
            if pool.profile_ids.len() > MAX_POOL_PROFILE_IDS {
                return Err(DefinitionError::LimitExceeded);
            }
            if pool.profile_ids.len() < 2 {
                return Err(DefinitionError::InvalidMembership);
            }
            let domain = self
                .trust_domains
                .iter()
                .find(|domain| domain.id == pool.trust_domain_id)
                .ok_or(DefinitionError::InvalidMembership)?;
            if self.pools.iter().take(index).any(|previous| {
                previous.alias == pool.alias
                    && self
                        .domain_provider(&previous.trust_domain_id)
                        .is_ok_and(|provider| provider == domain.provider)
            }) {
                return Err(DefinitionError::AlreadyExists);
            }
            let mut seen = BTreeSet::new();
            for profile_id in &pool.profile_ids {
                validate_uuid(profile_id)?;
                if !seen.insert(profile_id.as_str())
                    || domain.profile_ids.binary_search(profile_id).is_err()
                {
                    return Err(DefinitionError::InvalidMembership);
                }
            }
            membership_edges = membership_edges
                .checked_add(pool.profile_ids.len())
                .ok_or(DefinitionError::LimitExceeded)?;
        }
        if membership_edges > MAX_MEMBERSHIP_EDGES {
            return Err(DefinitionError::LimitExceeded);
        }

        let serialized = self.serialize_document()?;
        if serialized.len() > MAX_SERIALIZED_BYTES {
            return Err(DefinitionError::LimitExceeded);
        }
        Ok(())
    }

    fn serialize_document(&self) -> Result<Vec<u8>, DefinitionError> {
        serde_json::to_vec_pretty(&DefinitionsDocumentRef {
            schema_version: self.schema_version,
            revision: self.revision,
            trust_domains: &self.trust_domains,
            pools: &self.pools,
        })
        .map_err(|_| DefinitionError::SerializationFailed)
    }
}

fn validate_definition_alias(alias: &str) -> Result<(), DefinitionError> {
    validate_alias(alias).map_err(|_| DefinitionError::InvalidAlias)
}

fn validate_uuid(value: &str) -> Result<(), DefinitionError> {
    let parsed = Uuid::parse_str(value).map_err(|_| DefinitionError::InvalidId)?;
    if parsed.to_string() != value {
        return Err(DefinitionError::InvalidId);
    }
    Ok(())
}

fn canonical_member_set(
    mut profile_ids: Vec<String>,
    maximum: usize,
) -> Result<Vec<String>, DefinitionError> {
    if profile_ids.len() > maximum {
        return Err(DefinitionError::LimitExceeded);
    }
    for profile_id in &profile_ids {
        validate_uuid(profile_id)?;
    }
    profile_ids.sort();
    if !strictly_sorted_strings(&profile_ids) {
        return Err(DefinitionError::InvalidMembership);
    }
    Ok(profile_ids)
}

fn ordered_pool_members(profile_ids: Vec<String>) -> Result<Vec<String>, DefinitionError> {
    if profile_ids.len() > MAX_POOL_PROFILE_IDS {
        return Err(DefinitionError::LimitExceeded);
    }
    if profile_ids.len() < 2 {
        return Err(DefinitionError::InvalidMembership);
    }
    let mut seen = BTreeSet::new();
    for profile_id in &profile_ids {
        validate_uuid(profile_id)?;
        if !seen.insert(profile_id.as_str()) {
            return Err(DefinitionError::InvalidMembership);
        }
    }
    Ok(profile_ids)
}

fn strictly_sorted_strings(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by_id<T>(values: &[T], id: impl Fn(&T) -> &String) -> bool {
    values.windows(2).all(|pair| id(&pair[0]) < id(&pair[1]))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DefinitionError {
    InvalidSchema,
    InvalidId,
    InvalidAlias,
    InvalidMembership,
    ExclusiveMembership,
    AlreadyExists,
    NotFound,
    DomainInUse,
    LimitExceeded,
    RevisionConflict,
    RevisionOverflow,
    SerializationFailed,
}

impl DefinitionError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidSchema => "routing_definitions_invalid",
            Self::InvalidId => "routing_definition_id_invalid",
            Self::InvalidAlias => "routing_definition_alias_invalid",
            Self::InvalidMembership => "routing_definition_membership_invalid",
            Self::ExclusiveMembership => "routing_definition_membership_conflict",
            Self::AlreadyExists => "routing_definition_already_exists",
            Self::NotFound => "routing_definition_not_found",
            Self::DomainInUse => "routing_definition_domain_in_use",
            Self::LimitExceeded => "routing_definition_limit_exceeded",
            Self::RevisionConflict => "routing_definition_revision_conflict",
            Self::RevisionOverflow => "routing_definition_revision_overflow",
            Self::SerializationFailed => "routing_definitions_invalid",
        }
    }

    pub(crate) const fn safe_message(self) -> &'static str {
        match self {
            Self::InvalidSchema | Self::SerializationFailed => {
                "Calcifer's routing definitions are invalid."
            }
            Self::InvalidId => "A routing definition identifier is invalid.",
            Self::InvalidAlias => "A routing definition alias is invalid.",
            Self::InvalidMembership => "A routing definition membership is invalid.",
            Self::ExclusiveMembership => {
                "A profile cannot belong to more than one routing trust domain."
            }
            Self::AlreadyExists => "A routing definition already exists.",
            Self::NotFound => "A routing definition was not found.",
            Self::DomainInUse => "A routing trust domain is still referenced by a pool.",
            Self::LimitExceeded => "The routing definitions exceed a supported bound.",
            Self::RevisionConflict => "The routing definitions changed before this update.",
            Self::RevisionOverflow => "The routing definition revision cannot advance.",
        }
    }
}

impl fmt::Display for DefinitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for DefinitionError {}

#[cfg(test)]
mod tests {
    use std::io;

    use serde_json::{Value, json};

    use super::*;
    use crate::profiles::Provider;

    const DOMAIN_ID: &str = "01900000-0000-7000-8000-000000000001";
    const POOL_ID: &str = "01900000-0000-7000-8000-000000000002";
    const PROFILE_A: &str = "01900000-0000-7000-8000-000000000011";
    const PROFILE_B: &str = "01900000-0000-7000-8000-000000000012";
    const PROFILE_C: &str = "01900000-0000-7000-8000-000000000013";
    const PROFILE_D: &str = "01900000-0000-7000-8000-000000000014";
    const PROFILE_E: &str = "01900000-0000-7000-8000-000000000015";

    fn schema_document() -> Value {
        json!({
            "schema_version": 1,
            "revision": 7,
            "trust_domains": [{
                "id": DOMAIN_ID,
                "alias": "personal",
                "provider": "codex",
                "profile_ids": [PROFILE_A, PROFILE_B]
            }],
            "pools": [{
                "id": POOL_ID,
                "alias": "rotation",
                "trust_domain_id": DOMAIN_ID,
                "activation": "disabled",
                "profile_ids": [PROFILE_B, PROFILE_A]
            }]
        })
    }

    fn encoded(document: &Value) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(document)
    }

    fn generated_id(value: u128) -> String {
        Uuid::from_u128(value).to_string()
    }

    fn create_domain(
        definitions: &mut Definitions,
        expected_revision: u64,
        profile_ids: Vec<String>,
    ) -> Result<MutationOutcome, DefinitionError> {
        definitions.apply(
            expected_revision,
            DefinitionMutation::CreateDomain {
                id: DOMAIN_ID.to_owned(),
                alias: "personal".to_owned(),
                provider: Provider::Codex,
                profile_ids,
            },
        )
    }

    fn create_pool(
        definitions: &mut Definitions,
        expected_revision: u64,
        profile_ids: Vec<String>,
    ) -> Result<MutationOutcome, DefinitionError> {
        definitions.apply(
            expected_revision,
            DefinitionMutation::CreatePool {
                id: POOL_ID.to_owned(),
                alias: "rotation".to_owned(),
                trust_domain_id: DOMAIN_ID.to_owned(),
                profile_ids,
            },
        )
    }

    #[test]
    fn schema_v1_round_trips_only_disabled_pool_definitions()
    -> Result<(), Box<dyn std::error::Error>> {
        let definitions = Definitions::from_json(&encoded(&schema_document())?)?;
        let encoded: Value = serde_json::from_slice(&definitions.to_json()?)?;

        assert_eq!(definitions.revision(), 7);
        assert_eq!(definitions.trust_domains[0].provider, Provider::Codex);
        assert_eq!(definitions.pools[0].profile_ids, [PROFILE_B, PROFILE_A]);
        assert_eq!(encoded["pools"][0]["activation"], "disabled");
        assert!(encoded["pools"][0].get("provider").is_none());
        assert!(encoded["pools"][0].get("enabled").is_none());
        Ok(())
    }

    #[test]
    fn pure_mutations_compare_revision_and_do_not_bump_for_no_ops()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        let created = create_domain(
            &mut definitions,
            0,
            vec![PROFILE_B.to_owned(), PROFILE_A.to_owned()],
        )?;
        assert!(created.changed());
        assert_eq!(created.revision(), 1);
        assert_eq!(
            definitions.trust_domains[0].profile_ids,
            [PROFILE_A, PROFILE_B],
            "domain membership must be a canonical set"
        );

        let unchanged = definitions.apply(
            1,
            DefinitionMutation::RenameDomain {
                id: DOMAIN_ID.to_owned(),
                alias: "personal".to_owned(),
            },
        )?;
        assert!(!unchanged.changed());
        assert_eq!(unchanged.revision(), 1);
        assert_eq!(definitions.revision(), 1);

        let error = definitions
            .apply(
                0,
                DefinitionMutation::RemoveDomain {
                    id: DOMAIN_ID.to_owned(),
                },
            )
            .err()
            .ok_or("a stale expected revision must fail")?;
        assert_eq!(error.code(), "routing_definition_revision_conflict");
        assert_eq!(definitions.revision(), 1);
        Ok(())
    }

    #[test]
    fn handoff_authorization_requires_two_distinct_members_of_one_provider_domain()
    -> Result<(), Box<dyn std::error::Error>> {
        let definitions = Definitions::from_json(&encoded(&schema_document())?)?;

        let authorization =
            definitions.authorize_handoff(DOMAIN_ID, PROFILE_A, PROFILE_B, Provider::Codex)?;
        assert_eq!(authorization.trust_domain_id(), DOMAIN_ID);

        for (source, target) in [(PROFILE_A, PROFILE_A), (PROFILE_A, PROFILE_C)] {
            assert_eq!(
                definitions
                    .authorize_handoff(DOMAIN_ID, source, target, Provider::Codex)
                    .err(),
                Some(DefinitionError::InvalidMembership)
            );
        }
        assert_eq!(
            definitions
                .authorize_handoff(POOL_ID, PROFILE_A, PROFILE_B, Provider::Codex)
                .err(),
            Some(DefinitionError::NotFound)
        );
        Ok(())
    }

    #[test]
    fn trust_domains_are_first_class_and_may_have_an_empty_canonical_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        let created = create_domain(&mut definitions, 0, Vec::new())?;
        assert!(created.changed());
        assert_eq!(
            definitions.trust_domains[0].profile_ids,
            Vec::<String>::new()
        );

        let unchanged = definitions.apply(
            1,
            DefinitionMutation::ReplaceDomainMembers {
                id: DOMAIN_ID.to_owned(),
                profile_ids: Vec::new(),
            },
        )?;
        assert!(!unchanged.changed());
        assert_eq!(unchanged.revision(), 1);
        Definitions::from_json(&definitions.to_json()?)?;
        Ok(())
    }

    #[test]
    fn inclusive_member_bounds_accept_domain_and_pool_maxima()
    -> Result<(), Box<dyn std::error::Error>> {
        let domain_members: Vec<String> = (0..MAX_DOMAIN_PROFILE_IDS)
            .map(|index| generated_id(500_000 + index as u128))
            .collect();
        let pool_members = domain_members[..MAX_POOL_PROFILE_IDS].to_vec();
        let mut definitions = Definitions::default();

        create_domain(&mut definitions, 0, domain_members)?;
        create_pool(&mut definitions, 1, pool_members.clone())?;

        assert_eq!(
            definitions.trust_domains[0].profile_ids.len(),
            MAX_DOMAIN_PROFILE_IDS
        );
        assert_eq!(definitions.pools[0].profile_ids, pool_members);
        Definitions::from_json(&definitions.to_json()?)?;
        Ok(())
    }

    #[test]
    fn schema_rejects_every_alternative_to_required_disabled_activation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut documents = Vec::new();

        let mut missing = schema_document();
        missing["pools"][0]
            .as_object_mut()
            .ok_or("pool must be an object")?
            .remove("activation");
        documents.push(missing);

        let mut boolean = schema_document();
        boolean["pools"][0]["activation"] = json!(false);
        documents.push(boolean);

        let mut enabled = schema_document();
        enabled["pools"][0]["activation"] = json!("enabled");
        documents.push(enabled);

        let mut legacy_boolean = schema_document();
        legacy_boolean["pools"][0]
            .as_object_mut()
            .ok_or("pool must be an object")?
            .insert("enabled".to_owned(), json!(false));
        documents.push(legacy_boolean);

        let mut stored_provider = schema_document();
        stored_provider["pools"][0]
            .as_object_mut()
            .ok_or("pool must be an object")?
            .insert("provider".to_owned(), json!("codex"));
        documents.push(stored_provider);

        for document in documents {
            let error = Definitions::from_json(&encoded(&document)?)
                .err()
                .ok_or("unsupported activation shape must fail")?;
            assert_eq!(error.code(), "routing_definitions_invalid");
        }
        Ok(())
    }

    #[test]
    fn schema_rejects_unknown_fields_versions_and_noncanonical_sets()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut documents = Vec::new();

        let mut newer = schema_document();
        newer["schema_version"] = json!(2);
        documents.push(newer);

        let mut unknown = schema_document();
        unknown
            .as_object_mut()
            .ok_or("document must be an object")?
            .insert("future".to_owned(), json!(true));
        documents.push(unknown);

        let mut unknown_domain = schema_document();
        unknown_domain["trust_domains"][0]
            .as_object_mut()
            .ok_or("trust domain must be an object")?
            .insert("future".to_owned(), json!(true));
        documents.push(unknown_domain);

        let mut unordered = schema_document();
        unordered["trust_domains"][0]["profile_ids"] = json!([PROFILE_B, PROFILE_A]);
        documents.push(unordered);

        let mut duplicate = schema_document();
        duplicate["trust_domains"][0]["profile_ids"] = json!([PROFILE_A, PROFILE_A]);
        documents.push(duplicate);

        let mut unordered_domains = schema_document();
        unordered_domains["trust_domains"] = json!([
            {
                "id": "01900000-0000-7000-8000-000000000009",
                "alias": "work",
                "provider": "codex",
                "profile_ids": [PROFILE_C]
            },
            {
                "id": DOMAIN_ID,
                "alias": "personal",
                "provider": "codex",
                "profile_ids": [PROFILE_A, PROFILE_B]
            }
        ]);
        documents.push(unordered_domains);

        let mut unordered_pools = schema_document();
        unordered_pools["pools"] = json!([
            {
                "id": "01900000-0000-7000-8000-000000000009",
                "alias": "later",
                "trust_domain_id": DOMAIN_ID,
                "activation": "disabled",
                "profile_ids": [PROFILE_A, PROFILE_B]
            },
            {
                "id": POOL_ID,
                "alias": "rotation",
                "trust_domain_id": DOMAIN_ID,
                "activation": "disabled",
                "profile_ids": [PROFILE_B, PROFILE_A]
            }
        ]);
        documents.push(unordered_pools);

        for document in documents {
            assert!(Definitions::from_json(&encoded(&document)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn exclusive_domains_and_pool_subset_are_whole_definition_invariants()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut overlapping = schema_document();
        overlapping["trust_domains"] = json!([
            {
                "id": DOMAIN_ID,
                "alias": "personal",
                "provider": "codex",
                "profile_ids": [PROFILE_A, PROFILE_B]
            },
            {
                "id": "01900000-0000-7000-8000-000000000003",
                "alias": "work",
                "provider": "codex",
                "profile_ids": [PROFILE_B, PROFILE_C]
            }
        ]);
        let overlap_error = Definitions::from_json(&encoded(&overlapping)?)
            .err()
            .ok_or("overlapping domains must fail")?;
        assert_eq!(
            overlap_error.code(),
            "routing_definition_membership_conflict"
        );

        let mut outside = schema_document();
        outside["pools"][0]["profile_ids"] = json!([PROFILE_A, PROFILE_C]);
        let outside_error = Definitions::from_json(&encoded(&outside)?)
            .err()
            .ok_or("out-of-domain pool member must fail")?;
        assert_eq!(
            outside_error.code(),
            "routing_definition_membership_invalid"
        );

        for members in [json!([PROFILE_A]), json!([PROFILE_A, PROFILE_A])] {
            let mut invalid = schema_document();
            invalid["pools"][0]["profile_ids"] = members;
            assert!(Definitions::from_json(&encoded(&invalid)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn every_domain_and_pool_mutation_preserves_ids_and_pool_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        create_domain(
            &mut definitions,
            0,
            vec![
                PROFILE_C.to_owned(),
                PROFILE_A.to_owned(),
                PROFILE_B.to_owned(),
            ],
        )?;
        create_pool(
            &mut definitions,
            1,
            vec![PROFILE_B.to_owned(), PROFILE_A.to_owned()],
        )?;

        definitions.apply(
            2,
            DefinitionMutation::RenameDomain {
                id: DOMAIN_ID.to_owned(),
                alias: "private".to_owned(),
            },
        )?;
        let unchanged_domain = definitions.apply(
            3,
            DefinitionMutation::ReplaceDomainMembers {
                id: DOMAIN_ID.to_owned(),
                profile_ids: vec![
                    PROFILE_B.to_owned(),
                    PROFILE_C.to_owned(),
                    PROFILE_A.to_owned(),
                ],
            },
        )?;
        assert!(!unchanged_domain.changed());

        definitions.apply(
            3,
            DefinitionMutation::RenamePool {
                id: POOL_ID.to_owned(),
                alias: "fallback".to_owned(),
            },
        )?;
        let unchanged_pool = definitions.apply(
            4,
            DefinitionMutation::ReplacePoolMembers {
                id: POOL_ID.to_owned(),
                profile_ids: vec![PROFILE_B.to_owned(), PROFILE_A.to_owned()],
            },
        )?;
        assert!(!unchanged_pool.changed());
        definitions.apply(
            4,
            DefinitionMutation::ReplacePoolMembers {
                id: POOL_ID.to_owned(),
                profile_ids: vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
            },
        )?;

        assert_eq!(definitions.trust_domains[0].id, DOMAIN_ID);
        assert_eq!(definitions.pools[0].id, POOL_ID);
        assert_eq!(definitions.pools[0].trust_domain_id, DOMAIN_ID);
        assert_eq!(definitions.pools[0].profile_ids, [PROFILE_A, PROFILE_B]);
        assert_eq!(definitions.revision(), 5);
        Ok(())
    }

    #[test]
    fn domain_removal_requires_pool_removal_and_empty_state_keeps_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        create_domain(
            &mut definitions,
            0,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;
        create_pool(
            &mut definitions,
            1,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;

        let blocked = definitions
            .apply(
                2,
                DefinitionMutation::RemoveDomain {
                    id: DOMAIN_ID.to_owned(),
                },
            )
            .err()
            .ok_or("referenced domain removal must fail")?;
        assert_eq!(blocked.code(), "routing_definition_domain_in_use");
        assert_eq!(definitions.revision(), 2);

        definitions.apply(
            2,
            DefinitionMutation::RemovePool {
                id: POOL_ID.to_owned(),
            },
        )?;
        definitions.apply(
            3,
            DefinitionMutation::RemoveDomain {
                id: DOMAIN_ID.to_owned(),
            },
        )?;

        assert!(definitions.trust_domains.is_empty());
        assert!(definitions.pools.is_empty());
        assert_eq!(definitions.revision(), 4);
        let round_trip = Definitions::from_json(&definitions.to_json()?)?;
        assert_eq!(round_trip.revision(), 4);
        Ok(())
    }

    #[test]
    fn failed_mutations_leave_the_complete_previous_value_unchanged()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        create_domain(
            &mut definitions,
            0,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;
        create_pool(
            &mut definitions,
            1,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;

        let original = definitions.clone();
        let overlap_error = definitions
            .apply(
                2,
                DefinitionMutation::CreateDomain {
                    id: "01900000-0000-7000-8000-000000000003".to_owned(),
                    alias: "work".to_owned(),
                    provider: Provider::Codex,
                    profile_ids: vec![PROFILE_B.to_owned(), PROFILE_C.to_owned()],
                },
            )
            .err()
            .ok_or("overlap must fail")?;
        assert_eq!(
            overlap_error.code(),
            "routing_definition_membership_conflict"
        );
        assert_eq!(definitions, original);

        let subset_error = definitions
            .apply(
                2,
                DefinitionMutation::ReplaceDomainMembers {
                    id: DOMAIN_ID.to_owned(),
                    profile_ids: Vec::new(),
                },
            )
            .err()
            .ok_or("dependent pool subset violation must fail")?;
        assert_eq!(subset_error.code(), "routing_definition_membership_invalid");
        assert_eq!(definitions, original);
        Ok(())
    }

    #[test]
    fn no_op_mutations_cannot_publish_an_invalid_existing_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        create_domain(
            &mut definitions,
            0,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;
        definitions.trust_domains[0].profile_ids.reverse();
        let original = definitions.clone();

        let error = definitions
            .apply(
                1,
                DefinitionMutation::RenameDomain {
                    id: DOMAIN_ID.to_owned(),
                    alias: "personal".to_owned(),
                },
            )
            .err()
            .ok_or("invalid existing state must fail even for a semantic no-op")?;
        assert_eq!(error.code(), "routing_definition_membership_invalid");
        assert_eq!(definitions, original);
        Ok(())
    }

    #[test]
    fn ids_aliases_and_errors_are_canonical_and_redacted() -> Result<(), Box<dyn std::error::Error>>
    {
        let sentinel = "../private-provider-account@example.invalid";
        let mut definitions = Definitions::default();
        let alias_error = definitions
            .apply(
                0,
                DefinitionMutation::CreateDomain {
                    id: DOMAIN_ID.to_owned(),
                    alias: sentinel.to_owned(),
                    provider: Provider::Codex,
                    profile_ids: vec![PROFILE_A.to_owned()],
                },
            )
            .err()
            .ok_or("invalid alias must fail")?;
        assert_eq!(alias_error.code(), "routing_definition_alias_invalid");
        assert!(!alias_error.safe_message().contains(sentinel));
        assert!(!alias_error.to_string().contains(sentinel));

        let noncanonical_id = "01900000-0000-7000-8000-00000000000A";
        let id_error = definitions
            .apply(
                0,
                DefinitionMutation::RemovePool {
                    id: noncanonical_id.to_owned(),
                },
            )
            .err()
            .ok_or("noncanonical UUID must fail")?;
        assert_eq!(id_error.code(), "routing_definition_id_invalid");
        assert!(!id_error.safe_message().contains(noncanonical_id));
        assert!(!id_error.to_string().contains(noncanonical_id));
        Ok(())
    }

    #[test]
    fn count_edge_and_serialized_byte_bounds_fail_before_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut exact_bytes = Definitions::default().to_json()?;
        exact_bytes.resize(MAX_SERIALIZED_BYTES, b' ');
        Definitions::from_json(&exact_bytes)?;
        exact_bytes.push(b' ');
        let bytes_error = Definitions::from_json(&exact_bytes)
            .err()
            .ok_or("oversized input must fail")?;
        assert_eq!(bytes_error.code(), "routing_definition_limit_exceeded");

        let maximum_domains = Definitions {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            trust_domains: (0..MAX_TRUST_DOMAINS)
                .map(|index| TrustDomainDefinition {
                    id: generated_id(1_000 + index as u128),
                    alias: format!("domain-{index}"),
                    provider: Provider::Codex,
                    profile_ids: Vec::new(),
                })
                .collect(),
            pools: Vec::new(),
        };
        maximum_domains.validate()?;

        let too_many_domains = Definitions {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            trust_domains: (0..=MAX_TRUST_DOMAINS)
                .map(|index| TrustDomainDefinition {
                    id: generated_id(1_000 + index as u128),
                    alias: format!("domain-{index}"),
                    provider: Provider::Codex,
                    profile_ids: vec![generated_id(100_000 + index as u128)],
                })
                .collect(),
            pools: Vec::new(),
        };
        assert_eq!(
            too_many_domains
                .validate()
                .err()
                .ok_or("domain count bound must fail")?
                .code(),
            "routing_definition_limit_exceeded"
        );

        let maximum_pools = Definitions {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            trust_domains: vec![TrustDomainDefinition {
                id: DOMAIN_ID.to_owned(),
                alias: "personal".to_owned(),
                provider: Provider::Codex,
                profile_ids: vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
            }],
            pools: (0..MAX_POOLS)
                .map(|index| PoolDefinition {
                    id: generated_id(10_000 + index as u128),
                    alias: format!("pool-{index}"),
                    trust_domain_id: DOMAIN_ID.to_owned(),
                    activation: Activation::Disabled,
                    profile_ids: vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
                })
                .collect(),
        };
        maximum_pools.validate()?;

        let too_many_pools = Definitions {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            trust_domains: Vec::new(),
            pools: (0..=MAX_POOLS)
                .map(|index| PoolDefinition {
                    id: generated_id(10_000 + index as u128),
                    alias: format!("pool-{index}"),
                    trust_domain_id: DOMAIN_ID.to_owned(),
                    activation: Activation::Disabled,
                    profile_ids: vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
                })
                .collect(),
        };
        assert_eq!(
            too_many_pools
                .validate()
                .err()
                .ok_or("pool count bound must fail")?
                .code(),
            "routing_definition_limit_exceeded"
        );

        let mut next_profile = 1_000_000_u128;
        let edge_bound = Definitions {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            trust_domains: (0..65)
                .map(|domain_index| {
                    let profile_ids = (0..64)
                        .map(|_| {
                            let id = generated_id(next_profile);
                            next_profile += 1;
                            id
                        })
                        .collect();
                    TrustDomainDefinition {
                        id: generated_id(2_000_000 + domain_index),
                        alias: format!("domain-{domain_index}"),
                        provider: Provider::Codex,
                        profile_ids,
                    }
                })
                .collect(),
            pools: Vec::new(),
        };
        let maximum_edges = Definitions {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            trust_domains: edge_bound.trust_domains[..64].to_vec(),
            pools: Vec::new(),
        };
        maximum_edges.validate()?;
        assert_eq!(
            edge_bound
                .validate()
                .err()
                .ok_or("membership edge bound must fail")?
                .code(),
            "routing_definition_limit_exceeded"
        );
        Ok(())
    }

    #[test]
    fn per_definition_member_bounds_are_reported_as_limits_and_are_atomic()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        let too_many_domain_members = (0..=MAX_DOMAIN_PROFILE_IDS)
            .map(|index| generated_id(3_000_000 + index as u128))
            .collect();
        let domain_error = create_domain(&mut definitions, 0, too_many_domain_members)
            .err()
            .ok_or("domain member bound must fail")?;
        assert_eq!(domain_error.code(), "routing_definition_limit_exceeded");
        assert_eq!(definitions, Definitions::default());

        let members: Vec<String> = (0..=MAX_POOL_PROFILE_IDS)
            .map(|index| generated_id(4_000_000 + index as u128))
            .collect();
        create_domain(&mut definitions, 0, members.clone())?;
        let original = definitions.clone();
        let pool_error = create_pool(&mut definitions, 1, members)
            .err()
            .ok_or("pool member bound must fail")?;
        assert_eq!(pool_error.code(), "routing_definition_limit_exceeded");
        assert_eq!(definitions, original);
        Ok(())
    }

    #[test]
    fn revision_overflow_and_unknown_targets_are_non_mutating()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        create_domain(
            &mut definitions,
            0,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;
        definitions.revision = u64::MAX;
        let original = definitions.clone();
        let overflow = definitions
            .apply(
                u64::MAX,
                DefinitionMutation::RenameDomain {
                    id: DOMAIN_ID.to_owned(),
                    alias: "private".to_owned(),
                },
            )
            .err()
            .ok_or("revision overflow must fail")?;
        assert_eq!(overflow.code(), "routing_definition_revision_overflow");
        assert_eq!(definitions, original);

        definitions.revision = 1;
        let missing = definitions
            .apply(
                1,
                DefinitionMutation::RenamePool {
                    id: POOL_ID.to_owned(),
                    alias: "missing".to_owned(),
                },
            )
            .err()
            .ok_or("unknown target must fail")?;
        assert_eq!(missing.code(), "routing_definition_not_found");
        assert_eq!(definitions.revision(), 1);
        Ok(())
    }

    #[test]
    fn mutations_canonicalize_definition_order_but_not_pool_member_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        let later_domain = "01900000-0000-7000-8000-000000000009";
        definitions.apply(
            0,
            DefinitionMutation::CreateDomain {
                id: later_domain.to_owned(),
                alias: "work".to_owned(),
                provider: Provider::Codex,
                profile_ids: vec![PROFILE_C.to_owned()],
            },
        )?;
        definitions.apply(
            1,
            DefinitionMutation::CreateDomain {
                id: DOMAIN_ID.to_owned(),
                alias: "personal".to_owned(),
                provider: Provider::Codex,
                profile_ids: vec![PROFILE_B.to_owned(), PROFILE_A.to_owned()],
            },
        )?;
        let later_pool = "01900000-0000-7000-8000-000000000008";
        definitions.apply(
            2,
            DefinitionMutation::CreatePool {
                id: later_pool.to_owned(),
                alias: "later".to_owned(),
                trust_domain_id: DOMAIN_ID.to_owned(),
                profile_ids: vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
            },
        )?;
        create_pool(
            &mut definitions,
            3,
            vec![PROFILE_B.to_owned(), PROFILE_A.to_owned()],
        )?;

        assert_eq!(definitions.trust_domains[0].id, DOMAIN_ID);
        assert_eq!(definitions.trust_domains[1].id, later_domain);
        assert_eq!(definitions.pools[0].profile_ids, [PROFILE_B, PROFILE_A]);
        assert_eq!(definitions.pools[0].id, POOL_ID);
        assert_eq!(definitions.pools[1].id, later_pool);
        Definitions::from_json(&definitions.to_json()?)?;
        Ok(())
    }

    #[test]
    fn pool_ids_and_provider_derived_aliases_are_unique() -> Result<(), Box<dyn std::error::Error>>
    {
        let second_domain = "01900000-0000-7000-8000-000000000003";
        let second_pool = "01900000-0000-7000-8000-000000000004";
        let mut definitions = Definitions::default();
        create_domain(
            &mut definitions,
            0,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;
        create_pool(
            &mut definitions,
            1,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;
        definitions.apply(
            2,
            DefinitionMutation::CreateDomain {
                id: second_domain.to_owned(),
                alias: "work".to_owned(),
                provider: Provider::Codex,
                profile_ids: vec![PROFILE_D.to_owned(), PROFILE_E.to_owned()],
            },
        )?;
        let original = definitions.clone();

        for mutation in [
            DefinitionMutation::CreatePool {
                id: POOL_ID.to_owned(),
                alias: "other".to_owned(),
                trust_domain_id: second_domain.to_owned(),
                profile_ids: vec![PROFILE_D.to_owned(), PROFILE_E.to_owned()],
            },
            DefinitionMutation::CreatePool {
                id: second_pool.to_owned(),
                alias: "rotation".to_owned(),
                trust_domain_id: second_domain.to_owned(),
                profile_ids: vec![PROFILE_D.to_owned(), PROFILE_E.to_owned()],
            },
        ] {
            let error = definitions
                .apply(3, mutation)
                .err()
                .ok_or("duplicate pool identity must fail")?;
            assert_eq!(error.code(), "routing_definition_already_exists");
            assert_eq!(definitions, original);
        }
        Ok(())
    }

    #[test]
    fn duplicate_aliases_and_ids_are_rejected_without_reflecting_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        create_domain(&mut definitions, 0, vec![PROFILE_A.to_owned()])?;
        let original = definitions.clone();

        for mutation in [
            DefinitionMutation::CreateDomain {
                id: DOMAIN_ID.to_owned(),
                alias: "other".to_owned(),
                provider: Provider::Codex,
                profile_ids: vec![PROFILE_B.to_owned()],
            },
            DefinitionMutation::CreateDomain {
                id: "01900000-0000-7000-8000-000000000003".to_owned(),
                alias: "personal".to_owned(),
                provider: Provider::Codex,
                profile_ids: vec![PROFILE_B.to_owned()],
            },
        ] {
            let error = definitions
                .apply(1, mutation)
                .err()
                .ok_or("duplicate definition must fail")?;
            assert_eq!(error.code(), "routing_definition_already_exists");
            assert_eq!(definitions, original);
        }
        Ok(())
    }

    #[test]
    fn definition_ids_share_one_namespace_across_domains_and_pools()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        create_domain(
            &mut definitions,
            0,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;
        let domain_only = definitions.clone();

        let pool_collision = definitions
            .apply(
                1,
                DefinitionMutation::CreatePool {
                    id: DOMAIN_ID.to_owned(),
                    alias: "collision".to_owned(),
                    trust_domain_id: DOMAIN_ID.to_owned(),
                    profile_ids: vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
                },
            )
            .err()
            .ok_or("a pool cannot reuse a domain ID")?;
        assert_eq!(pool_collision.code(), "routing_definition_already_exists");
        assert_eq!(definitions, domain_only);

        create_pool(
            &mut definitions,
            1,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;
        let domain_and_pool = definitions.clone();
        let domain_collision = definitions
            .apply(
                2,
                DefinitionMutation::CreateDomain {
                    id: POOL_ID.to_owned(),
                    alias: "work".to_owned(),
                    provider: Provider::Codex,
                    profile_ids: vec![PROFILE_C.to_owned()],
                },
            )
            .err()
            .ok_or("a domain cannot reuse a pool ID")?;
        assert_eq!(domain_collision.code(), "routing_definition_already_exists");
        assert_eq!(definitions, domain_and_pool);

        let mut document = schema_document();
        document["pools"][0]["id"] = json!(DOMAIN_ID);
        let schema_collision = Definitions::from_json(&encoded(&document)?)
            .err()
            .ok_or("stored domain and pool IDs cannot collide")?;
        assert_eq!(schema_collision.code(), "routing_definition_already_exists");
        Ok(())
    }

    #[test]
    fn malformed_json_is_collapsed_to_a_fixed_safe_error() -> Result<(), io::Error> {
        let sensitive = b"{\"provider_account\":\"private@example.invalid\"";
        let error = Definitions::from_json(sensitive)
            .err()
            .ok_or_else(|| io::Error::other("malformed input must fail"))?;
        assert_eq!(error.code(), "routing_definitions_invalid");
        assert!(!error.safe_message().contains("private@example.invalid"));
        assert!(!error.to_string().contains("provider_account"));
        Ok(())
    }

    #[test]
    fn inspection_is_stable_redacted_and_marks_missing_profiles()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        create_domain(
            &mut definitions,
            0,
            vec![PROFILE_A.to_owned(), PROFILE_B.to_owned()],
        )?;
        create_pool(
            &mut definitions,
            1,
            vec![PROFILE_B.to_owned(), PROFILE_A.to_owned()],
        )?;
        let profiles = vec![crate::profiles::Profile {
            id: PROFILE_A.to_owned(),
            alias: "work".to_owned(),
            provider: Provider::Codex,
            created_at: 42,
        }];

        let inspection = Inspection::new(&definitions, &profiles);
        let json = serde_json::to_value(&inspection)?;
        assert_eq!(json["revision"], 2);
        assert_eq!(json["trust_domains"][0]["provider"], "codex");
        assert_eq!(
            json["trust_domains"][0]["members"][0],
            json!({"profile_id": PROFILE_A, "profile": "codex@work"})
        );
        assert_eq!(
            json["trust_domains"][0]["members"][1],
            json!({"profile_id": PROFILE_B, "profile": null})
        );
        assert_eq!(json["pools"][0]["activation"], "disabled");

        let rendered = serde_json::to_string(&inspection)?;
        for forbidden in [
            "fingerprint",
            "account_id",
            "workspace_id",
            "access_token",
            "reset_credit",
            "created_at",
        ] {
            assert!(!rendered.contains(forbidden));
        }
        let human = inspection.to_human();
        assert!(human.contains("codex@work"));
        assert!(human.contains("missing profile"));
        assert!(human.contains("Automatic routing is disabled"));
        Ok(())
    }
}
