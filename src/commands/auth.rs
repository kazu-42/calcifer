use serde::Serialize;
use std::time::Duration;

use crate::error::AppError;
use crate::executable::{resolve_claude, resolve_codex};
use crate::profiles::{Profile, Provider, Registry};
use crate::provider_identity::IdentityError;
use crate::providers::claude::{
    managed_command as managed_claude_command, verify_profile as verify_claude_profile,
};
use crate::providers::codex::{managed_command, run_managed_login, verify_codex_identity_adapter};

const IDENTITY_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize)]
pub(crate) struct AuthReport {
    schema_version: u8,
    command: &'static str,
    ok: bool,
    action: &'static str,
    profiles: Vec<Profile>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RenameReport {
    schema_version: u8,
    command: &'static str,
    ok: bool,
    action: &'static str,
    changed: bool,
    from: String,
    to: String,
    profile: Profile,
}

#[derive(Debug, Serialize)]
pub(crate) struct RemoveReport {
    schema_version: u8,
    command: &'static str,
    ok: bool,
    action: &'static str,
    removed: bool,
    profile: Profile,
}

impl RenameReport {
    pub(crate) fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub(crate) fn to_human(&self) -> String {
        format!("Renamed {} to {}.", self.from, self.to)
    }
}

impl RemoveReport {
    pub(crate) fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub(crate) fn to_human(&self) -> String {
        format!(
            "Removed {}.\nThe Calcifer-managed credentials and sessions for this local profile are no longer registered.",
            self.profile.reference()
        )
    }
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
            "reauth" => self.profiles.first().map_or_else(
                || "No profile was re-authenticated.".to_owned(),
                |profile| {
                    let provider = match profile.provider {
                        Provider::Claude => "Claude",
                        Provider::Codex => "Codex",
                    };
                    format!(
                        "Re-authenticated {} through the official {provider} login flow.",
                        profile.reference(),
                    )
                },
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
        None,
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

pub(crate) fn add_claude(alias: &str) -> Result<AuthReport, AppError> {
    if !cfg!(target_os = "linux") {
        return Err(crate::profiles::ProfileError::UnsupportedPlatform.into());
    }
    let executable = resolve_claude()?;
    let registry = Registry::discover()?;
    let neutral_working_directory = registry.neutral_working_directory()?;
    let pending = registry.begin_claude_registration(alias)?;
    let home = pending.home();
    let status = managed_claude_command(&executable, &home)
        .args(["auth", "login"])
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
    verify_claude_profile(&executable, &home, &neutral_working_directory)
        .map_err(crate::profiles::ProfileError::from)?;
    let profile = pending.commit_claude()?;
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
    let verified = registry.verify_or_bind_codex_identity(&profile, |home, provider_lease| {
        verify_codex_identity_adapter(
            &executable,
            home,
            &neutral_working_directory,
            IDENTITY_PROBE_TIMEOUT,
            provider_lease,
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

pub(crate) fn verify_claude(alias: &str) -> Result<AuthReport, AppError> {
    if !cfg!(target_os = "linux") {
        return Err(crate::profiles::ProfileError::UnsupportedPlatform.into());
    }
    let executable = resolve_claude()?;
    let registry = Registry::discover()?;
    let profile = registry.find(Provider::Claude, alias)?;
    let lease = registry.lock_profile(&profile)?;
    let home = registry.profile_home(&profile)?;
    let neutral_working_directory = registry.neutral_working_directory()?;
    verify_claude_profile(&executable, &home, &neutral_working_directory)
        .map_err(crate::profiles::ProfileError::from)?;
    drop(lease);
    Ok(AuthReport {
        schema_version: 1,
        command: "auth",
        ok: true,
        action: "verify",
        profiles: vec![profile],
    })
}

pub(crate) fn reauth_codex(alias: &str) -> Result<AuthReport, AppError> {
    let executable = resolve_codex()?;
    let registry = Registry::discover()?;
    let neutral_working_directory = registry.neutral_working_directory()?;
    let pending = registry.begin_codex_reauthentication(alias, |home, provider_lease| {
        verify_codex_identity_adapter(
            &executable,
            home,
            &neutral_working_directory,
            IDENTITY_PROBE_TIMEOUT,
            provider_lease,
        )
        .map_err(|_| crate::profiles::ProfileError::from(IdentityError::Unsupported))
    })?;
    let staging_home = pending.home();
    let status = run_managed_login(
        &executable,
        &staging_home,
        &neutral_working_directory,
        pending.provider_lock_for_child()?,
    );
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
        &staging_home,
        &neutral_working_directory,
        IDENTITY_PROBE_TIMEOUT,
        pending.provider_lock_for_child()?,
    )
    .map_err(|_| crate::profiles::ProfileError::from(IdentityError::Unsupported))?;
    let profile = pending.commit(adapter)?;
    Ok(AuthReport {
        schema_version: 1,
        command: "auth",
        ok: true,
        action: "reauth",
        profiles: vec![profile],
    })
}

pub(crate) fn reauth_claude(alias: &str) -> Result<AuthReport, AppError> {
    if !cfg!(target_os = "linux") {
        return Err(crate::profiles::ProfileError::UnsupportedPlatform.into());
    }
    let executable = resolve_claude()?;
    let registry = Registry::discover()?;
    let neutral_working_directory = registry.neutral_working_directory()?;
    let pending = registry.begin_claude_reauthentication(alias)?;
    let staging_home = pending.home();
    let status = managed_claude_command(&executable, &staging_home)
        .args(["auth", "login"])
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
    verify_claude_profile(&executable, &staging_home, &neutral_working_directory)
        .map_err(crate::profiles::ProfileError::from)?;
    let profile = pending.commit_claude()?;
    Ok(AuthReport {
        schema_version: 1,
        command: "auth",
        ok: true,
        action: "reauth",
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
        profiles: registry.list()?,
    })
}

pub(crate) fn rename_codex(old_alias: &str, new_alias: &str) -> Result<RenameReport, AppError> {
    rename(Provider::Codex, old_alias, new_alias)
}

pub(crate) fn rename_claude(old_alias: &str, new_alias: &str) -> Result<RenameReport, AppError> {
    rename(Provider::Claude, old_alias, new_alias)
}

fn rename(provider: Provider, old_alias: &str, new_alias: &str) -> Result<RenameReport, AppError> {
    let registry = Registry::discover()?;
    let from = format!("{}@{old_alias}", provider.as_str());
    let (profile, changed) = registry.rename(provider, old_alias, new_alias)?;
    let to = profile.reference();
    Ok(RenameReport {
        schema_version: 1,
        command: "auth",
        ok: true,
        action: "rename",
        changed,
        from,
        to,
        profile,
    })
}

pub(crate) fn preview_remove_codex(registry: &Registry, alias: &str) -> Result<Profile, AppError> {
    Ok(registry.preview_remove(Provider::Codex, alias)?)
}

pub(crate) fn preview_remove_claude(registry: &Registry, alias: &str) -> Result<Profile, AppError> {
    Ok(registry.preview_remove(Provider::Claude, alias)?)
}

pub(crate) fn remove_codex(
    registry: &Registry,
    alias: &str,
    confirmed_profile_id: Option<&str>,
) -> Result<RemoveReport, AppError> {
    let profile = registry.remove(Provider::Codex, alias, confirmed_profile_id)?;
    Ok(RemoveReport {
        schema_version: 1,
        command: "auth",
        ok: true,
        action: "remove",
        removed: true,
        profile,
    })
}

pub(crate) fn remove_claude(
    registry: &Registry,
    alias: &str,
    confirmed_profile_id: Option<&str>,
) -> Result<RemoveReport, AppError> {
    let profile = registry.remove(Provider::Claude, alias, confirmed_profile_id)?;
    Ok(RemoveReport {
        schema_version: 1,
        command: "auth",
        ok: true,
        action: "remove",
        removed: true,
        profile,
    })
}
