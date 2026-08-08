use serde::Serialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::executable::resolve_codex;
use crate::profiles::{Profile, Provider, Registry};
use crate::routing::storage::Store;
use crate::routing::validation::{LiveMembershipSource, mutate_snapshot, preflight};
use crate::routing::{DefinitionMutation, Definitions, Inspection, MutationOutcome, RoutingError};

#[derive(Debug, Serialize)]
pub(crate) struct RoutingReport {
    schema_version: u8,
    command: &'static str,
    ok: bool,
    action: &'static str,
    routing: Inspection,
}

#[derive(Debug, Serialize)]
pub(crate) struct RoutingUpdateReport {
    schema_version: u8,
    command: &'static str,
    ok: bool,
    action: &'static str,
    changed: bool,
    revision: u64,
    definition_id: String,
}

impl RoutingReport {
    pub(crate) fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub(crate) fn to_human(&self) -> String {
        self.routing.to_human()
    }
}

impl RoutingUpdateReport {
    pub(crate) fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub(crate) fn to_human(&self) -> String {
        let result = if self.changed {
            "Updated"
        } else {
            "No change to"
        };
        let safety = match self.action {
            "pool_enable" => {
                "This pool may now enter guarded selection; explicit profile pins still bypass it."
            }
            "pool_disable" => {
                "This pool cannot enter guarded selection; its durable membership is unchanged."
            }
            _ => "Automatic routing remains unchanged.",
        };
        format!(
            "{result} routing definition {} at revision {}.\n{safety}",
            self.definition_id, self.revision
        )
    }
}

pub(crate) fn inspect() -> Result<RoutingReport, AppError> {
    let registry = Registry::discover()?;
    let store = Store::from_profiles(&registry);
    let definitions = store.read()?;
    let profiles = registry.list()?;
    Ok(RoutingReport {
        schema_version: 1,
        command: "routing",
        ok: true,
        action: "inspect",
        routing: Inspection::new(&definitions, &profiles),
    })
}

pub(crate) fn create_domain(
    provider: Provider,
    alias: String,
    members: Vec<(Provider, String)>,
) -> Result<RoutingUpdateReport, AppError> {
    let id = Uuid::new_v4().to_string();
    membership_update(
        "domain_create",
        id.clone(),
        move |_, _, profile_ids| {
            Ok(DefinitionMutation::CreateDomain {
                id,
                alias,
                provider,
                profile_ids,
            })
        },
        move |_| Ok(provider),
        members,
    )
}

pub(crate) fn rename_domain(
    provider: Option<Provider>,
    reference: &str,
    new_alias: String,
) -> Result<RoutingUpdateReport, AppError> {
    metadata_update("domain_rename", |definitions| {
        let id = definitions.resolve_domain_id(provider, reference)?;
        Ok((
            id.clone(),
            DefinitionMutation::RenameDomain {
                id,
                alias: new_alias,
            },
        ))
    })
}

pub(crate) fn replace_domain_members(
    provider: Option<Provider>,
    reference: &str,
    members: Vec<(Provider, String)>,
) -> Result<RoutingUpdateReport, AppError> {
    membership_update(
        "domain_set_profiles",
        String::new(),
        move |definitions, placeholder, profile_ids| {
            let id = definitions.resolve_domain_id(provider, reference)?;
            *placeholder = id.clone();
            Ok(DefinitionMutation::ReplaceDomainMembers { id, profile_ids })
        },
        move |definitions| {
            let id = definitions.resolve_domain_id(provider, reference)?;
            definitions.domain_provider_for_id(&id).map_err(Into::into)
        },
        members,
    )
}

pub(crate) fn remove_domain(
    provider: Option<Provider>,
    reference: &str,
) -> Result<RoutingUpdateReport, AppError> {
    metadata_update("domain_remove", |definitions| {
        let id = definitions.resolve_domain_id(provider, reference)?;
        Ok((id.clone(), DefinitionMutation::RemoveDomain { id }))
    })
}

pub(crate) fn create_pool(
    domain_provider: Option<Provider>,
    domain_reference: &str,
    alias: String,
    members: Vec<(Provider, String)>,
) -> Result<RoutingUpdateReport, AppError> {
    let id = Uuid::new_v4().to_string();
    membership_update(
        "pool_create",
        id.clone(),
        move |definitions, _, profile_ids| {
            let trust_domain_id =
                definitions.resolve_domain_id(domain_provider, domain_reference)?;
            Ok(DefinitionMutation::CreatePool {
                id,
                alias,
                trust_domain_id,
                profile_ids,
            })
        },
        move |definitions| {
            let id = definitions.resolve_domain_id(domain_provider, domain_reference)?;
            definitions.domain_provider_for_id(&id).map_err(Into::into)
        },
        members,
    )
}

pub(crate) fn rename_pool(
    provider: Option<Provider>,
    reference: &str,
    new_alias: String,
) -> Result<RoutingUpdateReport, AppError> {
    metadata_update("pool_rename", |definitions| {
        let id = definitions.resolve_pool_id(provider, reference)?;
        Ok((
            id.clone(),
            DefinitionMutation::RenamePool {
                id,
                alias: new_alias,
            },
        ))
    })
}

pub(crate) fn replace_pool_members(
    provider: Option<Provider>,
    reference: &str,
    members: Vec<(Provider, String)>,
) -> Result<RoutingUpdateReport, AppError> {
    membership_update(
        "pool_set_profiles",
        String::new(),
        move |definitions, placeholder, profile_ids| {
            let id = definitions.resolve_pool_id(provider, reference)?;
            *placeholder = id.clone();
            Ok(DefinitionMutation::ReplacePoolMembers { id, profile_ids })
        },
        move |definitions| {
            let id = definitions.resolve_pool_id(provider, reference)?;
            definitions.pool_provider_for_id(&id).map_err(Into::into)
        },
        members,
    )
}

pub(crate) fn remove_pool(
    provider: Option<Provider>,
    reference: &str,
) -> Result<RoutingUpdateReport, AppError> {
    metadata_update("pool_remove", |definitions| {
        let id = definitions.resolve_pool_id(provider, reference)?;
        Ok((id.clone(), DefinitionMutation::RemovePool { id }))
    })
}

pub(crate) fn set_pool_activation(
    provider: Option<Provider>,
    reference: &str,
    enabled: bool,
) -> Result<RoutingUpdateReport, AppError> {
    let registry = Registry::discover()?;
    let store = Store::from_profiles(&registry);
    let snapshot = store.read()?;
    let id = snapshot
        .resolve_pool_id(provider, reference)
        .map_err(RoutingError::from)?;
    let mutation = DefinitionMutation::SetPoolActivation {
        id: id.clone(),
        enabled,
    };
    let action = if enabled {
        "pool_enable"
    } else {
        "pool_disable"
    };

    if !enabled {
        let outcome = store.commit(snapshot.revision(), mutation)?;
        return Ok(update_report(action, id, outcome));
    }

    preflight(&snapshot, &mutation)?;
    let executable = resolve_codex()?;
    let neutral = registry.neutral_working_directory()?;
    let source = LiveMembershipSource::new(
        &registry,
        Some(executable.as_path()),
        Some(neutral.as_path()),
        registry.list()?,
    );
    let outcome = mutate_snapshot(&store, &source, &snapshot, mutation)?;
    Ok(update_report(action, id, outcome))
}

fn metadata_update(
    action: &'static str,
    mutation: impl FnOnce(&Definitions) -> Result<(String, DefinitionMutation), RoutingError>,
) -> Result<RoutingUpdateReport, AppError> {
    let registry = Registry::discover()?;
    let store = Store::from_profiles(&registry);
    let snapshot = store.read()?;
    let (id, mutation) = mutation(&snapshot)?;
    let outcome = store.commit(snapshot.revision(), mutation)?;
    Ok(update_report(action, id, outcome))
}

fn membership_update(
    action: &'static str,
    mut definition_id: String,
    mutation: impl FnOnce(
        &Definitions,
        &mut String,
        Vec<String>,
    ) -> Result<DefinitionMutation, RoutingError>,
    expected_provider: impl FnOnce(&Definitions) -> Result<Provider, RoutingError>,
    members: Vec<(Provider, String)>,
) -> Result<RoutingUpdateReport, AppError> {
    let registry = Registry::discover()?;
    let store = Store::from_profiles(&registry);
    let snapshot = store.read()?;
    let profiles = registry.list()?;
    let expected_provider = expected_provider(&snapshot)?;
    let profile_ids = resolve_members(&profiles, expected_provider, &members)?;
    let mutation = mutation(&snapshot, &mut definition_id, profile_ids)?;
    preflight(&snapshot, &mutation)?;

    let executable = if members.is_empty() {
        None
    } else {
        Some(resolve_codex()?)
    };
    let neutral = if members.is_empty() {
        None
    } else {
        Some(registry.neutral_working_directory()?)
    };
    let source = LiveMembershipSource::new(
        &registry,
        executable.as_deref(),
        neutral.as_deref(),
        profiles,
    );
    // Alias lookup is checked once more under each immutable profile lease by
    // LiveMembershipSource, so a concurrent rename cannot redirect this update.
    for (provider, alias) in &members {
        let _ = source.resolve_alias(*provider, alias)?;
    }
    let outcome = mutate_snapshot(&store, &source, &snapshot, mutation)?;
    Ok(update_report(action, definition_id, outcome))
}

fn resolve_members(
    profiles: &[Profile],
    expected_provider: Provider,
    members: &[(Provider, String)],
) -> Result<Vec<String>, RoutingError> {
    let mut ids = Vec::with_capacity(members.len());
    for (provider, alias) in members {
        if *provider != expected_provider {
            return Err(RoutingError::ProfileProviderMismatch);
        }
        let profile = profiles
            .iter()
            .find(|profile| profile.provider == *provider && profile.alias == *alias)
            .ok_or(RoutingError::ProfileMissing)?;
        ids.push(profile.id.clone());
    }
    Ok(ids)
}

fn update_report(
    action: &'static str,
    definition_id: String,
    outcome: MutationOutcome,
) -> RoutingUpdateReport {
    RoutingUpdateReport {
        schema_version: 1,
        command: "routing",
        ok: true,
        action,
        changed: outcome.changed(),
        revision: outcome.revision(),
        definition_id,
    }
}
