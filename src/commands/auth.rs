use serde::Serialize;
use std::time::Duration;

use crate::error::AppError;
use crate::executable::resolve_codex;
use crate::profiles::{Profile, Provider, Registry};
use crate::provider_identity::IdentityError;
use crate::providers::codex::{managed_command, verify_codex_identity_adapter};

const IDENTITY_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize)]
pub(crate) struct AuthReport {
    schema_version: u8,
    command: &'static str,
    ok: bool,
    action: &'static str,
    profiles: Vec<Profile>,
}

impl AuthReport {
    pub(crate) fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub(crate) fn to_human(&self) -> String {
        match self.action {
            "add" => self.profiles.first().map_or_else(
                || "No profile was registered.".to_owned(),
                |profile| format!("Registered {}.", profile.reference()),
            ),
            "verify" => self.profiles.first().map_or_else(
                || "No profile identity was verified.".to_owned(),
                |profile| format!("Verified the private identity for {}.", profile.reference()),
            ),
            _ if self.profiles.is_empty() => "No profiles are registered.".to_owned(),
            _ => self
                .profiles
                .iter()
                .map(Profile::reference)
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

pub(crate) fn add_codex(alias: &str) -> Result<AuthReport, AppError> {
    let executable = resolve_codex()?;
    let registry = Registry::discover()?;
    let neutral_working_directory = registry.neutral_working_directory()?;
    let pending = registry.begin_codex_registration(alias)?;
    let home = pending.home();
    let status = managed_command(&executable, &home)
        .arg("login")
        .current_dir(&neutral_working_directory)
        .status();
    let status = match status {
        Ok(status) => status,
        Err(error) => {
            pending.abort()?;
            return Err(AppError::Io(error));
        }
    };
    if !status.success() {
        pending.abort()?;
        return Err(AppError::ProviderLoginFailed);
    }
    let adapter = verify_codex_identity_adapter(
        &executable,
        &home,
        &neutral_working_directory,
        IDENTITY_PROBE_TIMEOUT,
    )
    .map_err(|_| crate::profiles::ProfileError::from(IdentityError::Unsupported))?;
    let profile = pending.commit(adapter)?;
    Ok(AuthReport {
        schema_version: 1,
        command: "auth",
        ok: true,
        action: "add",
        profiles: vec![profile],
    })
}

pub(crate) fn verify_codex(alias: &str) -> Result<AuthReport, AppError> {
    let executable = resolve_codex()?;
    let registry = Registry::discover()?;
    let profile = registry.find(Provider::Codex, alias)?;
    let neutral_working_directory = registry.neutral_working_directory()?;
    let verified = registry.verify_or_bind_codex_identity(&profile, |home| {
        verify_codex_identity_adapter(
            &executable,
            home,
            &neutral_working_directory,
            IDENTITY_PROBE_TIMEOUT,
        )
        .map_err(|_| crate::profiles::ProfileError::from(IdentityError::Unsupported))
    })?;
    Ok(AuthReport {
        schema_version: 1,
        command: "auth",
        ok: true,
        action: "verify",
        profiles: vec![verified.profile().clone()],
    })
}

pub(crate) fn list() -> Result<AuthReport, AppError> {
    let registry = Registry::discover()?;
    Ok(AuthReport {
        schema_version: 1,
        command: "auth",
        ok: true,
        action: "list",
        profiles: registry
            .list()?
            .into_iter()
            .filter(|profile| profile.provider == Provider::Codex)
            .collect(),
    })
}
