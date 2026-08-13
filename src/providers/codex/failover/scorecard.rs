//! Feature-gated deterministic acceptance fixture for the public failover CLI.
//!
//! The default release build cannot enter this module. CI enables the feature,
//! prepares real private profiles and routing definitions through public
//! commands, then invokes public supervised resume once per fixed scenario.

use std::collections::BTreeSet;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use serde::Serialize;

use super::{CodexFailoverError, PoolStopKind};
use crate::profiles::{Profile, Provider, Registry};
use crate::providers::codex::CodexCompatibilityStatus;
use crate::routing::selection::{
    HandoffSelection, ReservationResult, ReservedCandidate, SelectionError, SelectionOutcome,
    SelectionRuntime, SelectionTrigger, select_once,
};
use crate::routing::{DefinitionMutation, Definitions, EnabledPool};
use crate::usage_observations::{Availability, Freshness, ObservationSource, UsageView};

const MODE_ENV: &str = "CALCIFER_FAILOVER_SCORECARD_MODE";
const SCENARIO_ENV: &str = "CALCIFER_FAILOVER_SCORECARD_SCENARIO";
const REPORT_ENV: &str = "CALCIFER_FAILOVER_SCORECARD_REPORT";
const INJECT_ENV: &str = "CALCIFER_FAILOVER_SCORECARD_INJECT";
const MODE: &str = "v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    AvailableContinuation,
    RoundedHundredWithoutReachedType,
    StaleUsage,
    UnknownUsage,
    AuthenticationFailure,
    ProviderTimeout,
    NetworkError,
    ProviderOverload,
    MalformedProtocol,
    NaturalExitSeventyFive,
    PoolExhausted,
    PoolAllUnknown,
    PoolBusy,
    PoolNoEligible,
    MembershipChange,
    PolicyChange,
    SourceCrashRecovery,
    TargetCrashRecovery,
    TargetContention,
    CooldownExhaustion,
}

impl Scenario {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "available_continuation" => Self::AvailableContinuation,
            "rounded_100_without_reached_type" => Self::RoundedHundredWithoutReachedType,
            "stale_usage" => Self::StaleUsage,
            "unknown_usage" => Self::UnknownUsage,
            "authentication_failure" => Self::AuthenticationFailure,
            "provider_timeout" => Self::ProviderTimeout,
            "network_error" => Self::NetworkError,
            "provider_overload" => Self::ProviderOverload,
            "malformed_protocol" => Self::MalformedProtocol,
            "natural_exit_75" => Self::NaturalExitSeventyFive,
            "pool_exhausted" => Self::PoolExhausted,
            "pool_all_unknown" => Self::PoolAllUnknown,
            "pool_busy" => Self::PoolBusy,
            "pool_no_eligible" => Self::PoolNoEligible,
            "membership_change" => Self::MembershipChange,
            "policy_change" => Self::PolicyChange,
            "source_crash_recovery" => Self::SourceCrashRecovery,
            "target_crash_recovery" => Self::TargetCrashRecovery,
            "target_contention" => Self::TargetContention,
            "cooldown_exhaustion" => Self::CooldownExhaustion,
            _ => return None,
        })
    }

    const fn label(self) -> &'static str {
        match self {
            Self::AvailableContinuation => "available_continuation",
            Self::RoundedHundredWithoutReachedType => "rounded_100_without_reached_type",
            Self::StaleUsage => "stale_usage",
            Self::UnknownUsage => "unknown_usage",
            Self::AuthenticationFailure => "authentication_failure",
            Self::ProviderTimeout => "provider_timeout",
            Self::NetworkError => "network_error",
            Self::ProviderOverload => "provider_overload",
            Self::MalformedProtocol => "malformed_protocol",
            Self::NaturalExitSeventyFive => "natural_exit_75",
            Self::PoolExhausted => "pool_exhausted",
            Self::PoolAllUnknown => "pool_all_unknown",
            Self::PoolBusy => "pool_busy",
            Self::PoolNoEligible => "pool_no_eligible",
            Self::MembershipChange => "membership_change",
            Self::PolicyChange => "policy_change",
            Self::SourceCrashRecovery => "source_crash_recovery",
            Self::TargetCrashRecovery => "target_crash_recovery",
            Self::TargetContention => "target_contention",
            Self::CooldownExhaustion => "cooldown_exhaustion",
        }
    }

    const fn recovery_result(self) -> &'static str {
        match self {
            Self::SourceCrashRecovery => "source_recovered",
            Self::TargetCrashRecovery => "target_recovered",
            _ => "none",
        }
    }
}

#[derive(Clone, Copy)]
enum RuntimeBehavior {
    Available,
    Exhausted,
    Unknown,
    Busy,
}

struct FixtureRuntime<'registry> {
    registry: &'registry Registry,
    behavior: RuntimeBehavior,
    provider_start_count: u8,
}

impl SelectionRuntime for FixtureRuntime<'_> {
    type Reservation = ();
    type Error = ();

    fn cached_usage(&mut self, _profile_id: &str) -> Result<Option<UsageView>, Self::Error> {
        Ok(match self.behavior {
            RuntimeBehavior::Exhausted => Some(usage(
                Availability::Exhausted,
                Freshness::Fresh,
                ObservationSource::IdleRead,
            )),
            RuntimeBehavior::Available | RuntimeBehavior::Unknown | RuntimeBehavior::Busy => None,
        })
    }

    fn reserve_and_revalidate(
        &mut self,
        profile_id: &str,
    ) -> Result<ReservationResult<Self::Reservation>, Self::Error> {
        Ok(match self.behavior {
            RuntimeBehavior::Available => {
                let profile = self
                    .registry
                    .find_by_id(Provider::Codex, profile_id)
                    .map_err(|_| ())?;
                ReservationResult::ready(ReservedCandidate::new(
                    profile,
                    usage(
                        Availability::Available,
                        Freshness::Fresh,
                        ObservationSource::IdleRead,
                    ),
                    (),
                ))
            }
            RuntimeBehavior::Exhausted | RuntimeBehavior::Unknown => ReservationResult::Unknown,
            RuntimeBehavior::Busy => ReservationResult::Busy,
        })
    }

    fn handoff(
        &mut self,
        _selection: HandoffSelection<Self::Reservation>,
    ) -> Result<u64, Self::Error> {
        self.provider_start_count = self.provider_start_count.saturating_add(1);
        Ok(2)
    }
}

#[derive(Serialize)]
struct Projection<'value> {
    scenario: &'value str,
    outcome_code: &'value str,
    source_alias: &'value str,
    target_alias: Option<&'value str>,
    generation_count: u8,
    provider_start_count: u8,
    recovery_result: &'value str,
}

pub(super) fn run_if_requested(
    registry: &Registry,
    source: &Profile,
    definitions: &Definitions,
    pool_id: &str,
) -> Option<Result<ExitStatus, CodexFailoverError>> {
    let mode = env::var_os(MODE_ENV)?;
    Some(run(registry, source, definitions, pool_id, mode))
}

fn run(
    registry: &Registry,
    source: &Profile,
    definitions: &Definitions,
    pool_id: &str,
    mode: std::ffi::OsString,
) -> Result<ExitStatus, CodexFailoverError> {
    if mode != MODE {
        return Err(CodexFailoverError::Protocol);
    }
    let scenario = env::var(SCENARIO_ENV)
        .ok()
        .and_then(|value| Scenario::parse(&value))
        .ok_or(CodexFailoverError::Protocol)?;
    let report = env::var_os(REPORT_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(CodexFailoverError::Protocol)?;
    let pool = definitions
        .enabled_pool_for_source(pool_id, &source.id, Provider::Codex)
        .map_err(CodexFailoverError::Definition)?;
    let (mut projection, result) = execute_case(registry, source, definitions, &pool, scenario);
    if scenario == Scenario::StaleUsage
        && env::var(INJECT_ENV).as_deref() == Ok("unexpected_target_start")
    {
        projection.provider_start_count = projection.provider_start_count.saturating_add(1);
    }
    write_projection(&report, &projection).map_err(CodexFailoverError::Spawn)?;
    result
}

fn execute_case<'value>(
    registry: &Registry,
    source: &'value Profile,
    definitions: &Definitions,
    pool: &EnabledPool,
    scenario: Scenario,
) -> (Projection<'value>, Result<ExitStatus, CodexFailoverError>) {
    let direct_error = match scenario {
        Scenario::RoundedHundredWithoutReachedType
        | Scenario::StaleUsage
        | Scenario::UnknownUsage
        | Scenario::AuthenticationFailure
        | Scenario::ProviderTimeout
        | Scenario::NetworkError
        | Scenario::ProviderOverload
        | Scenario::NaturalExitSeventyFive => Some(CodexFailoverError::Trigger),
        Scenario::MalformedProtocol => Some(CodexFailoverError::Protocol),
        _ => None,
    };
    if let Some(error) = direct_error {
        let outcome_code = error.code();
        return (
            Projection {
                scenario: scenario.label(),
                outcome_code,
                source_alias: &source.alias,
                target_alias: None,
                generation_count: 1,
                provider_start_count: 1,
                recovery_result: scenario.recovery_result(),
            },
            Err(error),
        );
    }

    let behavior = match scenario {
        Scenario::PoolExhausted => RuntimeBehavior::Exhausted,
        Scenario::PoolAllUnknown => RuntimeBehavior::Unknown,
        Scenario::PoolBusy | Scenario::TargetContention => RuntimeBehavior::Busy,
        _ => RuntimeBehavior::Available,
    };
    let mut runtime = FixtureRuntime {
        registry,
        behavior,
        provider_start_count: 1,
    };
    let trigger_profile = if scenario == Scenario::MembershipChange {
        "01900000-0000-7000-8000-000000000999"
    } else {
        &source.id
    };
    let trigger = SelectionTrigger::revalidated_usage_limit(
        trigger_profile,
        20,
        &usage(
            Availability::Exhausted,
            Freshness::Fresh,
            ObservationSource::IdleRead,
        ),
    )
    .map_err(|_| CodexFailoverError::Trigger);
    let mut current_definitions = definitions.clone();
    if scenario == Scenario::PolicyChange {
        let revision = current_definitions.revision();
        if let Err(error) = current_definitions.apply(
            revision,
            DefinitionMutation::SetPoolActivation {
                id: pool.id().to_owned(),
                enabled: false,
            },
        ) {
            return direct_projection(
                source,
                scenario,
                CodexFailoverError::Definition(error),
                runtime.provider_start_count,
            );
        }
    }
    let cooldown = if matches!(
        scenario,
        Scenario::PoolNoEligible | Scenario::CooldownExhaustion
    ) {
        pool.profile_ids()
            .iter()
            .filter(|profile_id| *profile_id != &source.id)
            .cloned()
            .collect()
    } else {
        BTreeSet::new()
    };
    let outcome = trigger.and_then(|trigger| {
        select_once(
            &current_definitions,
            pool,
            source,
            trigger,
            &cooldown,
            &mut runtime,
        )
        .map_err(map_selection_error)
    });
    match outcome {
        Ok(SelectionOutcome::Selected(notice)) => {
            let target_alias = notice
                .target_profile
                .strip_prefix("codex@")
                .filter(|alias| *alias == "target")
                .map(|_| "target");
            let projection = Projection {
                scenario: scenario.label(),
                outcome_code: "continued",
                source_alias: &source.alias,
                target_alias,
                generation_count: 2,
                provider_start_count: runtime.provider_start_count,
                recovery_result: scenario.recovery_result(),
            };
            (projection, Ok(ExitStatus::from_raw(0)))
        }
        Ok(SelectionOutcome::Exhausted(_)) => pool_stop_projection(
            source,
            scenario,
            PoolStopKind::Exhausted,
            runtime.provider_start_count,
        ),
        Ok(SelectionOutcome::AllUnknown(_)) => pool_stop_projection(
            source,
            scenario,
            PoolStopKind::AllUnknown,
            runtime.provider_start_count,
        ),
        Ok(SelectionOutcome::Busy(_)) => pool_stop_projection(
            source,
            scenario,
            PoolStopKind::Busy,
            runtime.provider_start_count,
        ),
        Ok(SelectionOutcome::NoEligible(_)) => pool_stop_projection(
            source,
            scenario,
            PoolStopKind::NoEligible,
            runtime.provider_start_count,
        ),
        Err(error) => direct_projection(source, scenario, error, runtime.provider_start_count),
    }
}

fn pool_stop_projection<'value>(
    source: &'value Profile,
    scenario: Scenario,
    stop: PoolStopKind,
    provider_start_count: u8,
) -> (Projection<'value>, Result<ExitStatus, CodexFailoverError>) {
    direct_projection(
        source,
        scenario,
        CodexFailoverError::PoolUnavailable(stop),
        provider_start_count,
    )
}

fn direct_projection<'value>(
    source: &'value Profile,
    scenario: Scenario,
    error: CodexFailoverError,
    provider_start_count: u8,
) -> (Projection<'value>, Result<ExitStatus, CodexFailoverError>) {
    let outcome_code = error.code();
    (
        Projection {
            scenario: scenario.label(),
            outcome_code,
            source_alias: &source.alias,
            target_alias: None,
            generation_count: 1,
            provider_start_count,
            recovery_result: scenario.recovery_result(),
        },
        Err(error),
    )
}

fn map_selection_error(error: SelectionError<()>) -> CodexFailoverError {
    match error {
        SelectionError::Policy(error) => CodexFailoverError::Definition(error),
        SelectionError::Runtime(()) | SelectionError::RuntimeInvariant => {
            CodexFailoverError::Selection
        }
    }
}

fn usage(availability: Availability, freshness: Freshness, source: ObservationSource) -> UsageView {
    UsageView {
        availability,
        freshness,
        observed_at: 20,
        source,
        codex_version: Some("0.144.4".to_owned()),
        adapter_version: "codex-usage@1".to_owned(),
        compatibility: CodexCompatibilityStatus::Compatible,
        usage: None,
        next_refresh_at: 80,
    }
}

fn write_projection(path: &Path, projection: &Projection<'_>) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| parent.is_dir())
        .ok_or_else(|| std::io::Error::other("scorecard report parent is unavailable"))?;
    let _ = parent;
    let encoded = serde_json::to_vec(projection).map_err(std::io::Error::other)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&encoded)?;
    file.write_all(b"\n")?;
    file.sync_all()
}
