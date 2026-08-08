use std::collections::BTreeSet;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jiff::Timestamp;
use serde::Serialize;

use crate::error::AppError;
use crate::executable::resolve_codex;
use crate::profiles::{Profile, Provider, Registry};
use crate::providers::codex::{
    CODEX_STATUS_PROTOCOL, CodexCompatibilityStatus, CodexUsage, CodexUsageError,
    RateLimitSnapshot, RateLimitWindow, SUPPORTED_CODEX_STATUS_VERSIONS, read_account_usage,
};
use crate::usage_observations::{
    Availability, Freshness, ObservationError, ObservationSource, ObservationStore, UsageView,
};

const STATUS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize)]
pub(crate) struct StatusReport {
    schema_version: u8,
    command: &'static str,
    ok: bool,
    profiles: Vec<ProfileStatus>,
}

#[derive(Debug, Serialize)]
struct ProfileStatus {
    profile: String,
    provider: &'static str,
    availability: Availability,
    observed_at: i64,
    source: String,
    freshness: Freshness,
    codex_version: Option<String>,
    adapter_version: String,
    compatibility: CompatibilityReport,
    usage: Option<CodexUsage>,
    error: Option<StatusFailure>,
}

#[derive(Debug, Serialize)]
struct CompatibilityReport {
    status: CodexCompatibilityStatus,
    protocol: &'static str,
    supported_codex_versions: &'static [&'static str],
}

#[derive(Debug, Serialize)]
struct StatusFailure {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
struct InspectionFailure {
    status: StatusFailure,
    codex_version: Option<String>,
    compatibility: CodexCompatibilityStatus,
    provider_error: Option<CodexUsageError>,
}

impl InspectionFailure {
    fn local(status: StatusFailure) -> Self {
        Self {
            status,
            codex_version: None,
            compatibility: CodexCompatibilityStatus::Unverified,
            provider_error: None,
        }
    }
}

impl StatusReport {
    pub(crate) fn inspect(alias: Option<&str>) -> Result<Self, AppError> {
        let registry = Registry::discover()?;
        let profiles = match alias {
            Some(alias) => vec![registry.find(Provider::Codex, alias)?],
            None => registry
                .list()?
                .into_iter()
                .filter(|profile| profile.provider == Provider::Codex)
                .collect(),
        };
        if profiles.is_empty() {
            return Ok(Self {
                schema_version: 1,
                command: "status",
                ok: true,
                profiles: Vec::new(),
            });
        }
        let observations = ObservationStore::from_profiles(&registry);
        let executable = resolve_codex();
        let refresh_ids = match alias {
            Some(_) => profiles
                .iter()
                .map(|profile| profile.id.clone())
                .collect::<BTreeSet<_>>(),
            None => observations
                .due_idle_refresh(
                    &profiles
                        .iter()
                        .map(|profile| profile.id.clone())
                        .collect::<Vec<_>>(),
                    &BTreeSet::new(),
                    current_timestamp()?,
                )
                .map_err(cache_error)?
                .into_iter()
                .collect(),
        };
        let statuses = profiles
            .into_iter()
            .map(|profile| {
                if refresh_ids.contains(&profile.id) {
                    inspect_profile(
                        &registry,
                        &observations,
                        &profile,
                        alias,
                        executable.as_deref(),
                    )
                } else {
                    cached_profile_status(&observations, &profile, current_timestamp()?)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ok = statuses.iter().all(|profile| profile.error.is_none());
        Ok(Self {
            schema_version: 1,
            command: "status",
            ok,
            profiles: statuses,
        })
    }

    pub(crate) fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub(crate) fn to_human(&self) -> String {
        if self.profiles.is_empty() {
            return "No Codex profiles are registered. Run `calcifer auth add codex <alias>`."
                .to_owned();
        }

        self.profiles
            .iter()
            .map(ProfileStatus::to_human)
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    pub(crate) const fn exit_code(&self) -> u8 {
        if self.ok { 0 } else { 1 }
    }
}

impl ProfileStatus {
    fn to_human(&self) -> String {
        let mut lines = vec![format!("{} [{}]", self.profile, self.availability.label())];
        match (&self.usage, &self.error) {
            (Some(usage), _) => {
                for (name, snapshot) in display_snapshots(usage) {
                    lines.push(format!("  {name}"));
                    append_window(&mut lines, "primary", snapshot.primary.as_ref());
                    append_window(&mut lines, "secondary", snapshot.secondary.as_ref());
                    if let Some(credits) = &snapshot.credits {
                        let balance = credits
                            .balance
                            .as_deref()
                            .map_or_else(|| "unknown".to_owned(), safe_text);
                        lines.push(format!(
                            "    credits: has={} unlimited={} balance={balance}",
                            credits.has_credits, credits.unlimited
                        ));
                    }
                    if let Some(limit) = &snapshot.individual_limit {
                        lines.push(format!(
                            "    spend control: used {} of {} · {}% remaining · resets {}",
                            safe_text(&limit.used),
                            safe_text(&limit.limit),
                            limit.remaining_percent,
                            format_epoch(limit.resets_at)
                        ));
                    }
                }
                match &usage.reset_credits {
                    Some(reset) => {
                        lines.push(format!(
                            "  reset credits: {} available",
                            reset.available_count
                        ));
                        match &reset.details {
                            Some(details) if details.is_empty() => {
                                lines.push("    details: none returned".to_owned());
                            }
                            Some(details) => {
                                for detail in details {
                                    let expiry = detail
                                        .expires_at
                                        .map_or_else(|| "no expiry".to_owned(), format_epoch);
                                    lines.push(format!(
                                        "    {} · {} · expires {expiry}",
                                        safe_text(&detail.reset_type),
                                        safe_text(&detail.status)
                                    ));
                                }
                            }
                            None => lines.push("    details: unavailable".to_owned()),
                        }
                    }
                    None => lines.push("  reset credits: unavailable".to_owned()),
                }
            }
            (_, Some(error)) => lines.push(format!("  error: {} ({})", error.message, error.code)),
            _ => lines.push("  usage: unknown".to_owned()),
        }
        if self.usage.is_some() {
            if let Some(error) = &self.error {
                lines.push(format!(
                    "  refresh error: {} ({})",
                    error.message, error.code
                ));
            }
        }
        lines.push(format!(
            "  observed {} · {} · {}",
            format_epoch(self.observed_at),
            self.freshness.label(),
            self.source
        ));
        let codex_version = self.codex_version.as_deref().unwrap_or("unknown");
        lines.push(format!(
            "  compatibility {} · Codex {codex_version} · tested {} · adapter {}",
            self.compatibility.status.label(),
            self.compatibility.supported_codex_versions.join(", "),
            self.adapter_version
        ));
        lines.join("\n")
    }
}

fn inspect_profile(
    registry: &Registry,
    observations: &ObservationStore,
    profile: &Profile,
    expected_alias: Option<&str>,
    executable: Result<&std::path::Path, &crate::executable::ExecutableError>,
) -> Result<ProfileStatus, AppError> {
    let mut current_profile = profile.clone();
    let result = (|| {
        let (locked_profile, _lease) = registry
            .lock_profile_current(profile, expected_alias)
            .map_err(|error| {
                InspectionFailure::local(StatusFailure {
                    code: error.code(),
                    message: "Profile is busy, missing, or failed validation",
                })
            })?;
        current_profile = locked_profile;
        let executable = executable.map_err(|error| {
            InspectionFailure::local(StatusFailure {
                code: error.code(),
                message: error.safe_message(),
            })
        })?;
        let home = registry.profile_home(&current_profile).map_err(|_| {
            InspectionFailure::local(StatusFailure {
                code: "unsafe_profile_state",
                message: "Managed profile storage failed validation",
            })
        })?;
        let neutral_working_directory = registry.neutral_working_directory().map_err(|_| {
            InspectionFailure::local(StatusFailure {
                code: "unsafe_profile_state",
                message: "Managed neutral working directory failed validation",
            })
        })?;
        // The account app-server is a bounded, no-turn probe. Its child-side
        // provider lease survives exec while the parent's descriptor remains
        // close-on-exec, so concurrent parent spawns cannot inherit it.
        let provider_lease = _lease.provider_lock_for_probe().map_err(|_| {
            InspectionFailure::local(StatusFailure {
                code: "unsafe_profile_state",
                message: "Managed profile lease failed validation",
            })
        })?;
        read_account_usage(
            executable,
            &home,
            &neutral_working_directory,
            STATUS_TIMEOUT,
            provider_lease,
        )
        .map_err(|failure| InspectionFailure {
            status: status_failure(failure.kind()),
            codex_version: failure.codex_version().map(str::to_owned),
            compatibility: failure.compatibility(),
            provider_error: Some(failure.kind()),
        })
    })();

    let observed_at = current_timestamp()?;
    match result {
        Ok(observation) => {
            let view = observations
                .observe_usage(
                    &current_profile.id,
                    ObservationSource::IdleRead,
                    &observation.codex_version,
                    observation.usage,
                    observed_at,
                )
                .map_err(cache_error)?;
            Ok(status_from_view(current_profile.reference(), view, None))
        }
        Err(failure) => {
            let view = match failure.provider_error {
                Some(provider_error) => observations
                    .observe_failure(
                        &current_profile.id,
                        ObservationSource::IdleRead,
                        failure.codex_version.as_deref(),
                        failure.compatibility,
                        provider_error,
                        observed_at,
                    )
                    .map(Some)
                    .map_err(cache_error)?,
                None => observations
                    .view(&current_profile.id, observed_at)
                    .map_err(cache_error)?,
            };
            if let Some(view) = view {
                let usable_active_observation = view.source == ObservationSource::ActiveMonitor
                    && view.freshness == Freshness::Fresh;
                Ok(status_from_view(
                    current_profile.reference(),
                    view,
                    (!usable_active_observation).then_some(failure.status),
                ))
            } else {
                Ok(ProfileStatus {
                    profile: current_profile.reference(),
                    provider: "codex",
                    availability: Availability::Unknown,
                    observed_at,
                    source: ObservationSource::IdleRead.label().to_owned(),
                    freshness: Freshness::Unknown,
                    codex_version: failure.codex_version,
                    adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
                    compatibility: compatibility_report(failure.compatibility),
                    usage: None,
                    error: Some(failure.status),
                })
            }
        }
    }
}

fn status_from_view(
    profile: String,
    view: UsageView,
    error: Option<StatusFailure>,
) -> ProfileStatus {
    ProfileStatus {
        profile,
        provider: "codex",
        availability: view.availability,
        observed_at: view.observed_at,
        source: view.source.label().to_owned(),
        freshness: view.freshness,
        codex_version: view.codex_version,
        adapter_version: view.adapter_version,
        compatibility: compatibility_report(view.compatibility),
        usage: view.usage,
        error,
    }
}

fn cached_profile_status(
    observations: &ObservationStore,
    profile: &Profile,
    observed_at: i64,
) -> Result<ProfileStatus, AppError> {
    if let Some(view) = observations
        .view(&profile.id, observed_at)
        .map_err(cache_error)?
    {
        return Ok(status_from_view(profile.reference(), view, None));
    }
    Ok(ProfileStatus {
        profile: profile.reference(),
        provider: "codex",
        availability: Availability::Unknown,
        observed_at,
        source: "observation_cache".to_owned(),
        freshness: Freshness::Unknown,
        codex_version: None,
        adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
        compatibility: compatibility_report(CodexCompatibilityStatus::Unverified),
        usage: None,
        error: None,
    })
}

fn cache_error(error: ObservationError) -> AppError {
    AppError::Io(io::Error::other(error))
}

const fn compatibility_report(status: CodexCompatibilityStatus) -> CompatibilityReport {
    CompatibilityReport {
        status,
        protocol: CODEX_STATUS_PROTOCOL,
        supported_codex_versions: SUPPORTED_CODEX_STATUS_VERSIONS,
    }
}

fn display_snapshots(usage: &CodexUsage) -> Vec<(String, &RateLimitSnapshot)> {
    if usage.rate_limits_by_limit_id.is_empty() {
        return usage
            .rate_limits
            .as_ref()
            .map(|snapshot| {
                vec![(
                    safe_text(
                        &snapshot
                            .limit_name
                            .clone()
                            .or_else(|| snapshot.limit_id.clone())
                            .unwrap_or_else(|| "default limit".to_owned()),
                    ),
                    snapshot,
                )]
            })
            .unwrap_or_default();
    }
    usage
        .rate_limits_by_limit_id
        .iter()
        .map(|(id, snapshot)| {
            (
                snapshot.limit_name.clone().unwrap_or_else(|| id.clone()),
                snapshot,
            )
        })
        .map(|(name, snapshot)| (safe_text(&name), snapshot))
        .collect()
}

fn safe_text(value: &str) -> String {
    const MAX_CHARS: usize = 128;

    let mut characters = value.chars();
    let mut safe = String::new();
    for _ in 0..MAX_CHARS {
        let Some(character) = characters.next() else {
            return safe;
        };
        if character.is_control() {
            safe.push('\u{fffd}');
        } else {
            safe.push(character);
        }
    }
    if characters.next().is_some() {
        safe.push('…');
    }
    safe
}

fn append_window(lines: &mut Vec<String>, label: &str, window: Option<&RateLimitWindow>) {
    match window {
        Some(window) => {
            let reset = window
                .resets_at
                .map_or_else(|| "unknown".to_owned(), format_epoch);
            let duration = window.window_duration_mins.map_or_else(
                || "unknown window".to_owned(),
                |minutes| format!("{minutes}m window"),
            );
            lines.push(format!(
                "    {label}: {}% used · {}% remaining (display) · {duration} · resets {reset}",
                window.used_percent, window.remaining_percent
            ));
        }
        None => lines.push(format!("    {label}: unavailable")),
    }
}

fn status_failure(error: CodexUsageError) -> StatusFailure {
    match error {
        CodexUsageError::Unsupported => StatusFailure {
            code: "unsupported",
            message: "Installed Codex does not support structured rate-limit reads",
        },
        CodexUsageError::Protocol => StatusFailure {
            code: "protocol_error",
            message: "Codex returned an unsupported or malformed response",
        },
        CodexUsageError::Transport => StatusFailure {
            code: "protocol_error",
            message: "Codex status observation ended before completion",
        },
        CodexUsageError::Provider => StatusFailure {
            code: "protocol_error",
            message: "Codex returned an unrecognized provider error",
        },
        CodexUsageError::Authentication => StatusFailure {
            code: "authentication_required",
            message: "Profile requires Codex authentication",
        },
        CodexUsageError::Timeout => StatusFailure {
            code: "timeout",
            message: "Codex rate-limit read timed out",
        },
        CodexUsageError::Spawn => StatusFailure {
            code: "spawn_failed",
            message: "Codex app-server could not be started",
        },
    }
}

fn current_timestamp() -> Result<i64, AppError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| std::io::Error::other("system clock is before the Unix epoch"))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| AppError::Io(std::io::Error::other("system clock is out of range")))
}

fn format_epoch(seconds: i64) -> String {
    Timestamp::from_second(seconds).map_or_else(
        |_| format!("unix:{seconds}"),
        |timestamp| timestamp.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[cfg(unix)]
    #[test]
    fn explicit_status_rejects_a_stale_alias_before_provider_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let root = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
            "calcifer-status-stale-alias-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        let mut auth = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(pending.home().join("auth.json"))?;
        let account_scope = uuid::Uuid::new_v4().to_string();
        auth.write_all(
            serde_json::to_string(&serde_json::json!({
                "auth_mode": "chatgpt",
                "tokens": { "account_id": account_scope }
            }))?
            .as_bytes(),
        )?;
        auth.sync_all()?;
        let stale = pending.commit(crate::providers::codex::CodexIdentityAdapter::for_test())?;
        registry.rename(Provider::Codex, "work", "client-a")?;

        let observations = ObservationStore::from_profiles(&registry);
        let report = inspect_profile(
            &registry,
            &observations,
            &stale,
            Some("work"),
            Ok(std::path::Path::new("/synthetic/provider-must-not-run")),
        )?;

        assert_eq!(report.profile, "codex@work");
        assert_eq!(
            report.error.as_ref().map(|error| error.code),
            Some("profile_not_found")
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn busy_profile_uses_only_a_fresh_profile_owned_monitor_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let root = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
            "calcifer-status-active-cache-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
        let mut auth = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(pending.home().join("auth.json"))?;
        auth.write_all(
            serde_json::to_string(&serde_json::json!({
                "auth_mode": "chatgpt",
                "tokens": { "account_id": uuid::Uuid::new_v4().to_string() }
            }))?
            .as_bytes(),
        )?;
        auth.sync_all()?;
        let profile = pending.commit(crate::providers::codex::CodexIdentityAdapter::for_test())?;
        let observations = ObservationStore::from_profiles(&registry);
        let observed_at = current_timestamp()?;
        observations.observe_usage(
            &profile.id,
            ObservationSource::ActiveMonitor,
            crate::providers::codex::CodexIdentityAdapter::supported_version(),
            CodexUsage {
                rate_limits: Some(RateLimitSnapshot {
                    limit_id: Some("codex".to_owned()),
                    limit_name: None,
                    plan_type: None,
                    rate_limit_reached_type: None,
                    primary: Some(RateLimitWindow {
                        used_percent: 20,
                        remaining_percent: 80,
                        window_duration_mins: Some(300),
                        resets_at: Some(1_900_000_000),
                    }),
                    secondary: None,
                    credits: None,
                    individual_limit: None,
                }),
                rate_limits_by_limit_id: BTreeMap::new(),
                reset_credits: None,
            },
            observed_at,
        )?;
        let (_locked_profile, lease) = registry.lock_profile_current(&profile, Some("work"))?;

        let report = inspect_profile(
            &registry,
            &observations,
            &profile,
            Some("work"),
            Ok(std::path::Path::new("/synthetic/provider-must-not-run")),
        )?;

        assert_eq!(report.availability, Availability::Available);
        assert_eq!(report.freshness, Freshness::Fresh);
        assert_eq!(report.source, ObservationSource::ActiveMonitor.label());
        assert!(report.error.is_none());
        drop(lease);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn indeterminate_failures_preserve_the_schema_v1_protocol_error_code() {
        for (error, expected_message) in [
            (
                CodexUsageError::Protocol,
                "Codex returned an unsupported or malformed response",
            ),
            (
                CodexUsageError::Transport,
                "Codex status observation ended before completion",
            ),
            (
                CodexUsageError::Provider,
                "Codex returned an unrecognized provider error",
            ),
        ] {
            let failure = status_failure(error);
            assert_eq!(failure.code, "protocol_error");
            assert_eq!(failure.message, expected_message);
        }
    }
}
