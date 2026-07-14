use serde::Serialize;

use crate::error::AppError;
use crate::executable::resolve_codex;
use crate::profiles::{Profile, Provider, Registry};
use crate::providers::codex::managed_command;

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
    let profile = pending.commit()?;
    Ok(AuthReport {
        schema_version: 1,
        command: "auth",
        ok: true,
        action: "add",
        profiles: vec![profile],
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
