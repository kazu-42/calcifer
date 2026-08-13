use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use super::*;

const REAUTH_JOURNAL_FILE: &str = ".calcifer-reauth.json";
const REAUTH_JOURNAL_SCHEMA_VERSION: u8 = 2;
const LEGACY_REAUTH_JOURNAL_SCHEMA_VERSION: u8 = 1;
const MAX_REAUTH_JOURNAL_BYTES: usize = 16 * 1024;
const MAX_REAUTH_AUTH_BYTES: usize = 1024 * 1024;
const MAX_REAUTH_TREE_ENTRIES: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
enum ReauthFaultPoint {
    StagingCreate,
    StagingDirectorySync,
    CredentialTemporaryCreate,
    CredentialTemporaryWrite,
    CredentialTemporarySync,
    CredentialTemporaryRename,
    CredentialTemporaryDirectorySync,
    JournalTemporaryCreate,
    JournalTemporaryWrite,
    JournalTemporarySync,
    JournalRename,
    JournalDirectorySync,
    OldCredentialRename,
    NewCredentialRename,
    HomeDirectorySync,
    BackupRemove,
    StagingCleanup,
    JournalRemove,
}

#[cfg(test)]
thread_local! {
    static REAUTH_FAULT: std::cell::Cell<Option<ReauthFaultPoint>> = const {
        std::cell::Cell::new(None)
    };
}

fn inject_reauth_fault(point: ReauthFaultPoint) -> Result<(), ProfileError> {
    #[cfg(test)]
    if REAUTH_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(ProfileError::Io(io::Error::other(
            "injected reauthentication fault",
        )));
    }
    #[cfg(not(test))]
    let _ = point;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReauthJournal {
    schema_version: u8,
    #[serde(default = "legacy_codex_provider")]
    provider: Provider,
    #[serde(default = "legacy_codex_credential_name")]
    credential_name: String,
    profile_id: String,
    transaction_id: String,
    staging_name: String,
    temporary_name: String,
    backup_name: String,
    old_auth_digest: String,
    new_auth_digest: String,
}

const fn legacy_codex_provider() -> Provider {
    Provider::Codex
}

fn legacy_codex_credential_name() -> String {
    "auth.json".to_owned()
}

const fn credential_name(provider: Provider) -> &'static str {
    match provider {
        Provider::Claude => ".credentials.json",
        Provider::Codex => "auth.json",
    }
}

fn credential_temporary_name(credential_name: &str, transaction_id: &str) -> String {
    let prefix = if credential_name.starts_with('.') {
        ""
    } else {
        "."
    };
    format!("{prefix}{credential_name}.reauth-new-{transaction_id}")
}

fn credential_backup_name(credential_name: &str, transaction_id: &str) -> String {
    let prefix = if credential_name.starts_with('.') {
        ""
    } else {
        "."
    };
    format!("{prefix}{credential_name}.reauth-old-{transaction_id}")
}

/// A staged official login guarded by both halves of the profile lifetime
/// lease. Provider identity material and credential bytes never leave this
/// move-only transaction.
pub(crate) struct PendingCodexReauth<'a> {
    registry: &'a Registry,
    profile: Profile,
    lease: ProfileLease,
    profile_directory: PathBuf,
    staging: PathBuf,
    transaction_id: String,
    expected_identity: Option<ProviderIdentity>,
    finished: bool,
    preserve: bool,
}

impl Registry {
    /// Recovers only transactions whose ownership can be derived from the
    /// current immutable registry. Unknown staging names or unsafe trees are
    /// retained for inspection instead of being guessed or recursively
    /// deleted.
    pub(crate) fn recover_incomplete_reauth(&self) -> Result<(), ProfileError> {
        if !path_exists(&self.root)? {
            return Ok(());
        }
        let document = self.load()?;
        let profiles_root = self.root.join("profiles");
        match fs::symlink_metadata(&profiles_root) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(ProfileError::Io(error)),
            Ok(_) => verify_private_directory(&profiles_root)?,
        }
        let mut affected_ids = Vec::new();
        for provider in [Provider::Claude, Provider::Codex] {
            let provider_root = profiles_root.join(provider.as_str());
            match fs::symlink_metadata(&provider_root) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(ProfileError::Io(error)),
                Ok(_) => verify_private_directory(&provider_root)?,
            }

            for profile in document
                .profiles
                .iter()
                .filter(|profile| profile.provider == provider)
            {
                let profile_directory = provider_root.join(&profile.id);
                match fs::symlink_metadata(profile_directory.join(REAUTH_JOURNAL_FILE)) {
                    Ok(_) => affected_ids.push(profile.id.clone()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(ProfileError::Io(error)),
                }
            }
            for entry in fs::read_dir(&provider_root)? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| ProfileError::ReauthRecoveryRequired)?;
                if !name.starts_with(".reauth-") {
                    continue;
                }
                let owner = document.profiles.iter().find(|profile| {
                    profile.provider == provider
                        && name.starts_with(&format!(".reauth-{}-", profile.id))
                });
                let Some(owner) = owner else {
                    return Err(ProfileError::ReauthRecoveryRequired);
                };
                if !affected_ids.contains(&owner.id) {
                    affected_ids.push(owner.id.clone());
                }
            }
        }
        affected_ids.sort();
        affected_ids.dedup();

        for id in affected_ids {
            let profile = document
                .profiles
                .iter()
                .find(|profile| profile.id == id)
                .ok_or(ProfileError::ReauthRecoveryRequired)?;
            let lease = self.lock_profile(profile)?;
            let current = self.find_by_id_without_recovery(profile.provider, &profile.id)?;
            if current != *profile {
                return Err(ProfileError::ReauthRecoveryRequired);
            }
            let profile_directory = self.profile_directory(&current)?;
            recover_reauth_under_lease(self, &current, &profile_directory)?;
            drop(lease);
        }
        Ok(())
    }

    pub(crate) fn begin_codex_reauthentication(
        &self,
        alias: &str,
        resolve_adapter: impl FnOnce(&Path, Option<&File>) -> Result<CodexIdentityAdapter, ProfileError>,
    ) -> Result<PendingCodexReauth<'_>, ProfileError> {
        self.recover_incomplete_removal()?;
        self.recover_incomplete_reauth()?;
        ensure_registration_supported()?;
        let selected = self.find_without_recovery(Provider::Codex, alias)?;
        let (profile, lease) = self.lock_profile_current(&selected, Some(alias))?;
        let profile_directory = self.profile_directory(&profile)?;

        recover_reauth_under_lease(self, &profile, &profile_directory)?;

        let home = self.profile_home(&profile)?;
        let _ = read_private_bounded(&home.join("auth.json"), MAX_REAUTH_AUTH_BYTES)?;
        let adapter = resolve_adapter(&home, lease.provider_lock_for_probe()?)?;
        let store = IdentityStore::new(&self.root);
        let key = store.load_key()?;
        let current = store.derive_codex_binding(&home, &key, adapter)?;
        store.revalidate_marker(&profile_directory, &key, &current)?;

        let provider_root = profile_directory.parent().ok_or_else(|| {
            ProfileError::UnsafeState("profile directory has no provider root".to_owned())
        })?;
        verify_private_directory(provider_root)?;
        let transaction_id = Uuid::new_v4().to_string();
        let staging_name = format!(".reauth-{}-{transaction_id}", profile.id);
        let staging = provider_root.join(&staging_name);
        inject_reauth_fault(ReauthFaultPoint::StagingCreate)?;
        secure_create_dir(&staging)?;
        let publication = (|| {
            write_private_file(&staging.join(OWNER_MARKER), profile.id.as_bytes())?;
            let staging_home = staging.join("home");
            secure_create_dir(&staging_home)?;
            write_private_file(&staging_home.join("config.toml"), MANAGED_CODEX_CONFIG)?;
            sync_directory(&staging_home)?;
            sync_directory(&staging)?;
            inject_reauth_fault(ReauthFaultPoint::StagingDirectorySync)?;
            sync_directory(provider_root)
        })();
        if let Err(error) = publication {
            let _ = safe_remove_reauth_staging(&staging, &profile.id, &transaction_id);
            return Err(error);
        }

        Ok(PendingCodexReauth {
            registry: self,
            profile,
            lease,
            profile_directory,
            staging,
            transaction_id,
            expected_identity: Some(current),
            finished: false,
            preserve: false,
        })
    }

    pub(crate) fn begin_claude_reauthentication(
        &self,
        alias: &str,
    ) -> Result<PendingCodexReauth<'_>, ProfileError> {
        if !cfg!(target_os = "linux") {
            return Err(ProfileError::UnsupportedPlatform);
        }
        self.recover_incomplete_removal()?;
        self.recover_incomplete_reauth()?;
        ensure_registration_supported()?;
        let selected = self.find_without_recovery(Provider::Claude, alias)?;
        let (profile, lease) = self.lock_profile_current(&selected, Some(alias))?;
        let profile_directory = self.profile_directory(&profile)?;
        recover_reauth_under_lease(self, &profile, &profile_directory)?;

        let home = self.profile_home(&profile)?;
        let _ = read_private_bounded(
            &home.join(credential_name(Provider::Claude)),
            MAX_REAUTH_AUTH_BYTES,
        )?;
        let provider_root = profile_directory.parent().ok_or_else(|| {
            ProfileError::UnsafeState("profile directory has no provider root".to_owned())
        })?;
        verify_private_directory(provider_root)?;
        let transaction_id = Uuid::new_v4().to_string();
        let staging_name = format!(".reauth-{}-{transaction_id}", profile.id);
        let staging = provider_root.join(&staging_name);
        inject_reauth_fault(ReauthFaultPoint::StagingCreate)?;
        secure_create_dir(&staging)?;
        let publication = (|| {
            write_private_file(&staging.join(OWNER_MARKER), profile.id.as_bytes())?;
            let staging_home = staging.join("home");
            secure_create_dir(&staging_home)?;
            sync_directory(&staging_home)?;
            sync_directory(&staging)?;
            inject_reauth_fault(ReauthFaultPoint::StagingDirectorySync)?;
            sync_directory(provider_root)
        })();
        if let Err(error) = publication {
            let _ = safe_remove_reauth_staging(&staging, &profile.id, &transaction_id);
            return Err(error);
        }

        Ok(PendingCodexReauth {
            registry: self,
            profile,
            lease,
            profile_directory,
            staging,
            transaction_id,
            expected_identity: None,
            finished: false,
            preserve: false,
        })
    }
}

impl PendingCodexReauth<'_> {
    pub(crate) fn home(&self) -> PathBuf {
        self.staging.join("home")
    }

    pub(crate) fn provider_lock_for_child(&self) -> Result<Option<&File>, ProfileError> {
        self.lease.provider_lock_for_probe()
    }

    pub(crate) fn abort(mut self) -> Result<(), ProfileError> {
        safe_remove_reauth_staging(&self.staging, &self.profile.id, &self.transaction_id)?;
        sync_directory(self.staging.parent().ok_or_else(|| {
            ProfileError::UnsafeState("reauth staging has no provider root".to_owned())
        })?)?;
        self.finished = true;
        Ok(())
    }

    pub(crate) fn commit(self, adapter: CodexIdentityAdapter) -> Result<Profile, ProfileError> {
        if self.profile.provider != Provider::Codex {
            return Err(ProfileError::ReauthRecoveryRequired);
        }
        let staging_home = self.home();
        verify_managed_codex_home(&staging_home)?;
        let store = IdentityStore::new(&self.registry.root);
        let key = store.load_key()?;
        let staged_identity = store.derive_codex_binding(&staging_home, &key, adapter)?;
        let Some(expected_identity) = self.expected_identity.as_ref() else {
            return Err(ProfileError::ReauthRecoveryRequired);
        };
        if !expected_identity.same_provider_identity(&staged_identity) {
            return Err(ProfileError::from(IdentityError::Mismatch));
        }

        self.commit_credential(credential_name(Provider::Codex))
    }

    pub(crate) fn commit_claude(self) -> Result<Profile, ProfileError> {
        if self.profile.provider != Provider::Claude || self.expected_identity.is_some() {
            return Err(ProfileError::ReauthRecoveryRequired);
        }
        crate::providers::claude::sync_linux_credentials(&self.home())?;
        self.commit_credential(credential_name(Provider::Claude))
    }

    fn commit_credential(mut self, credential_name: &'static str) -> Result<Profile, ProfileError> {
        let staging_home = self.home();
        let home = self.registry.profile_home(&self.profile)?;
        let current_auth = home.join(credential_name);
        let old_bytes = read_private_bounded(&current_auth, MAX_REAUTH_AUTH_BYTES)?;
        let staged_auth = staging_home.join(credential_name);
        let new_bytes = read_private_bounded(&staged_auth, MAX_REAUTH_AUTH_BYTES)?;
        let temporary_name = credential_temporary_name(credential_name, &self.transaction_id);
        let backup_name = credential_backup_name(credential_name, &self.transaction_id);
        let temporary = home.join(&temporary_name);
        let backup = home.join(&backup_name);
        let staging_temporary = self
            .staging
            .join(format!(".credential-candidate-{}", self.transaction_id));
        ensure_path_absent(&temporary)?;
        ensure_path_absent(&backup)?;
        ensure_path_absent(&staging_temporary)?;

        let journal = ReauthJournal {
            schema_version: REAUTH_JOURNAL_SCHEMA_VERSION,
            provider: self.profile.provider,
            credential_name: credential_name.to_owned(),
            profile_id: self.profile.id.clone(),
            transaction_id: self.transaction_id.clone(),
            staging_name: self
                .staging
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ProfileError::ReauthRecoveryRequired)?
                .to_owned(),
            temporary_name,
            backup_name,
            old_auth_digest: auth_digest(&old_bytes),
            new_auth_digest: auth_digest(&new_bytes),
        };

        publish_reauth_journal(&self.profile_directory, &self.staging, &journal)?;
        self.preserve = true;
        write_reauth_private_file(
            &staging_temporary,
            &new_bytes,
            ReauthFaultPoint::CredentialTemporaryCreate,
            ReauthFaultPoint::CredentialTemporaryWrite,
            ReauthFaultPoint::CredentialTemporarySync,
        )?;
        inject_reauth_fault(ReauthFaultPoint::CredentialTemporaryRename)
            .and_then(|()| fs::rename(&staging_temporary, &temporary).map_err(ProfileError::Io))
            .map_err(|_| ProfileError::ReauthRecoveryRequired)?;
        inject_reauth_fault(ReauthFaultPoint::CredentialTemporaryDirectorySync)
            .and_then(|()| sync_directory(&home))
            .map_err(|_| ProfileError::ReauthRecoveryRequired)?;
        if read_private_digest(&temporary)? != journal.new_auth_digest {
            return Err(ProfileError::ReauthRecoveryRequired);
        }

        if read_private_digest(&current_auth)? != journal.old_auth_digest {
            return Err(ProfileError::ReauthRecoveryRequired);
        }
        if inject_reauth_fault(ReauthFaultPoint::OldCredentialRename).is_err()
            || fs::rename(&current_auth, &backup).is_err()
        {
            return Err(ProfileError::ReauthRecoveryRequired);
        }
        if inject_reauth_fault(ReauthFaultPoint::NewCredentialRename).is_err()
            || fs::rename(&temporary, &current_auth).is_err()
        {
            return Err(ProfileError::ReauthRecoveryRequired);
        }
        if read_private_digest(&current_auth)? != journal.new_auth_digest {
            return Err(ProfileError::ReauthRecoveryRequired);
        }
        if inject_reauth_fault(ReauthFaultPoint::HomeDirectorySync).is_err()
            || sync_directory(&home).is_err()
        {
            return Err(ProfileError::ReauthCommitUncertain);
        }

        if finish_committed_reauth(&self.profile_directory, &home, &self.staging, &journal).is_err()
        {
            return Err(ProfileError::ReauthCommitUncertain);
        }
        self.finished = true;
        self.preserve = false;
        Ok(self.profile.clone())
    }
}

impl Drop for PendingCodexReauth<'_> {
    fn drop(&mut self) {
        if self.finished || self.preserve {
            return;
        }
        let _ = safe_remove_reauth_staging(&self.staging, &self.profile.id, &self.transaction_id);
    }
}

fn recover_reauth_under_lease(
    _registry: &Registry,
    profile: &Profile,
    profile_directory: &Path,
) -> Result<(), ProfileError> {
    let journal_path = profile_directory.join(REAUTH_JOURNAL_FILE);
    match fs::symlink_metadata(&journal_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            cleanup_orphan_reauth_staging(profile_directory, &profile.id)
        }
        Err(error) => Err(ProfileError::Io(error)),
        Ok(_) => {
            let journal = read_reauth_journal(&journal_path)?;
            if journal.profile_id != profile.id
                || journal.provider != profile.provider
                || journal.credential_name != credential_name(profile.provider)
            {
                return Err(ProfileError::ReauthRecoveryRequired);
            }
            let home = profile_directory.join("home");
            verify_private_directory(&home).map_err(|_| ProfileError::ReauthRecoveryRequired)?;
            if profile.provider == Provider::Codex {
                verify_managed_codex_config(&home.join("config.toml"))
                    .map_err(|_| ProfileError::ReauthRecoveryRequired)?;
            }
            let provider_root = profile_directory
                .parent()
                .ok_or(ProfileError::ReauthRecoveryRequired)?;
            let staging = provider_root.join(&journal.staging_name);
            validate_journal_paths(&journal, &staging, &home)?;
            recover_journaled_reauth(profile_directory, &home, &staging, &journal)
        }
    }
}

fn recover_journaled_reauth(
    profile_directory: &Path,
    home: &Path,
    staging: &Path,
    journal: &ReauthJournal,
) -> Result<(), ProfileError> {
    let current = home.join(&journal.credential_name);
    let temporary = home.join(&journal.temporary_name);
    let backup = home.join(&journal.backup_name);
    let current_digest = optional_private_digest(&current)?;
    let temporary_digest = optional_private_digest(&temporary)?;
    let backup_digest = optional_private_digest(&backup)?;

    if backup_digest
        .as_deref()
        .is_some_and(|digest| digest != journal.old_auth_digest)
        || temporary_digest
            .as_deref()
            .is_some_and(|digest| digest != journal.new_auth_digest)
    {
        return Err(ProfileError::ReauthRecoveryRequired);
    }

    match current_digest.as_deref() {
        Some(digest) if digest == journal.new_auth_digest => {
            finish_committed_reauth(profile_directory, home, staging, journal)
        }
        Some(digest)
            if digest == journal.old_auth_digest
                && backup_digest.is_none()
                && matches!(temporary_digest.as_deref(), Some(value) if value == journal.new_auth_digest) =>
        {
            rollback_unpublished_reauth(profile_directory, home, staging, journal)
        }
        Some(digest)
            if digest == journal.old_auth_digest
                && backup_digest.is_none()
                && temporary_digest.is_none() =>
        {
            rollback_unpublished_reauth(profile_directory, home, staging, journal)
        }
        None if matches!(backup_digest.as_deref(), Some(value) if value == journal.old_auth_digest)
            && matches!(temporary_digest.as_deref(), Some(value) if value == journal.new_auth_digest) =>
        {
            fs::rename(&temporary, &current).map_err(|_| ProfileError::ReauthRecoveryRequired)?;
            if read_private_digest(&current)? != journal.new_auth_digest {
                return Err(ProfileError::ReauthRecoveryRequired);
            }
            sync_directory(home).map_err(|_| ProfileError::ReauthCommitUncertain)?;
            finish_committed_reauth(profile_directory, home, staging, journal)
        }
        _ => Err(ProfileError::ReauthRecoveryRequired),
    }
}

fn finish_committed_reauth(
    profile_directory: &Path,
    home: &Path,
    staging: &Path,
    journal: &ReauthJournal,
) -> Result<(), ProfileError> {
    let current = home.join(&journal.credential_name);
    if read_private_digest(&current)? != journal.new_auth_digest {
        return Err(ProfileError::ReauthRecoveryRequired);
    }
    inject_reauth_fault(ReauthFaultPoint::BackupRemove)?;
    remove_exact_private_file(
        &home.join(&journal.backup_name),
        Some(&journal.old_auth_digest),
    )?;
    remove_exact_private_file(
        &home.join(&journal.temporary_name),
        Some(&journal.new_auth_digest),
    )?;
    sync_directory(home)?;
    inject_reauth_fault(ReauthFaultPoint::StagingCleanup)?;
    remove_reauth_staging_if_present(staging, &journal.profile_id, &journal.transaction_id)?;
    if let Some(provider_root) = staging.parent() {
        sync_directory(provider_root)?;
    }
    inject_reauth_fault(ReauthFaultPoint::JournalRemove)?;
    remove_exact_private_file(&profile_directory.join(REAUTH_JOURNAL_FILE), None)?;
    sync_directory(profile_directory)
}

fn rollback_unpublished_reauth(
    profile_directory: &Path,
    home: &Path,
    staging: &Path,
    journal: &ReauthJournal,
) -> Result<(), ProfileError> {
    if read_private_digest(&home.join(&journal.credential_name))? != journal.old_auth_digest {
        return Err(ProfileError::ReauthRecoveryRequired);
    }
    remove_exact_private_file(
        &home.join(&journal.temporary_name),
        Some(&journal.new_auth_digest),
    )?;
    remove_reauth_staging_if_present(staging, &journal.profile_id, &journal.transaction_id)?;
    if let Some(provider_root) = staging.parent() {
        sync_directory(provider_root)?;
    }
    remove_exact_private_file(&profile_directory.join(REAUTH_JOURNAL_FILE), None)?;
    sync_directory(profile_directory)
}

fn publish_reauth_journal(
    profile_directory: &Path,
    staging: &Path,
    journal: &ReauthJournal,
) -> Result<(), ProfileError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| ProfileError::ReauthRecoveryRequired)?;
    if bytes.len() > MAX_REAUTH_JOURNAL_BYTES {
        return Err(ProfileError::ReauthRecoveryRequired);
    }
    let temporary = staging.join(format!(
        ".{REAUTH_JOURNAL_FILE}.{}.tmp",
        journal.transaction_id
    ));
    let destination = profile_directory.join(REAUTH_JOURNAL_FILE);
    ensure_path_absent(&temporary)?;
    ensure_path_absent(&destination)?;
    write_reauth_private_file(
        &temporary,
        &bytes,
        ReauthFaultPoint::JournalTemporaryCreate,
        ReauthFaultPoint::JournalTemporaryWrite,
        ReauthFaultPoint::JournalTemporarySync,
    )?;
    if let Err(error) = inject_reauth_fault(ReauthFaultPoint::JournalRename)
        .and_then(|()| fs::rename(&temporary, &destination).map_err(ProfileError::Io))
    {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    inject_reauth_fault(ReauthFaultPoint::JournalDirectorySync)
        .and_then(|()| sync_directory(profile_directory))
        .and_then(|()| sync_directory(staging))
        .map_err(|_| ProfileError::ReauthRecoveryRequired)
}

fn read_reauth_journal(path: &Path) -> Result<ReauthJournal, ProfileError> {
    let bytes = read_private_bounded(path, MAX_REAUTH_JOURNAL_BYTES)
        .map_err(|_| ProfileError::ReauthRecoveryRequired)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ProfileError::ReauthRecoveryRequired)?;
    let explicit_provider_fields = value.as_object().is_some_and(|object| {
        object.contains_key("provider") && object.contains_key("credential_name")
    });
    let journal: ReauthJournal =
        serde_json::from_slice(&bytes).map_err(|_| ProfileError::ReauthRecoveryRequired)?;
    if !matches!(
        journal.schema_version,
        LEGACY_REAUTH_JOURNAL_SCHEMA_VERSION | REAUTH_JOURNAL_SCHEMA_VERSION
    ) || (journal.schema_version == REAUTH_JOURNAL_SCHEMA_VERSION && !explicit_provider_fields)
        || (journal.schema_version == LEGACY_REAUTH_JOURNAL_SCHEMA_VERSION
            && (journal.provider != Provider::Codex || journal.credential_name != "auth.json"))
        || journal.credential_name != credential_name(journal.provider)
        || validate_profile_id(&journal.profile_id).is_err()
        || Uuid::parse_str(&journal.transaction_id)
            .ok()
            .is_none_or(|id| id.to_string() != journal.transaction_id)
        || !is_sha256_hex(&journal.old_auth_digest)
        || !is_sha256_hex(&journal.new_auth_digest)
    {
        return Err(ProfileError::ReauthRecoveryRequired);
    }
    Ok(journal)
}

fn validate_journal_paths(
    journal: &ReauthJournal,
    staging: &Path,
    home: &Path,
) -> Result<(), ProfileError> {
    if journal.staging_name != format!(".reauth-{}-{}", journal.profile_id, journal.transaction_id)
        || journal.temporary_name
            != credential_temporary_name(&journal.credential_name, &journal.transaction_id)
        || journal.backup_name
            != credential_backup_name(&journal.credential_name, &journal.transaction_id)
        || staging.parent().is_none()
        || home.parent().is_none()
    {
        return Err(ProfileError::ReauthRecoveryRequired);
    }
    Ok(())
}

fn cleanup_orphan_reauth_staging(
    profile_directory: &Path,
    profile_id: &str,
) -> Result<(), ProfileError> {
    let provider_root = profile_directory
        .parent()
        .ok_or(ProfileError::ReauthRecoveryRequired)?;
    verify_private_directory(provider_root)?;
    let prefix = format!(".reauth-{profile_id}-");
    for entry in fs::read_dir(provider_root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ProfileError::ReauthRecoveryRequired)?;
        let Some(transaction_id) = name.strip_prefix(&prefix) else {
            continue;
        };
        if Uuid::parse_str(transaction_id)
            .ok()
            .is_none_or(|id| id.to_string() != transaction_id)
        {
            return Err(ProfileError::ReauthRecoveryRequired);
        }
        safe_remove_reauth_staging(&entry.path(), profile_id, transaction_id)?;
    }
    sync_directory(provider_root)
}

fn remove_reauth_staging_if_present(
    staging: &Path,
    profile_id: &str,
    transaction_id: &str,
) -> Result<(), ProfileError> {
    match fs::symlink_metadata(staging) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ProfileError::Io(error)),
        Ok(_) => safe_remove_reauth_staging(staging, profile_id, transaction_id),
    }
}

fn safe_remove_reauth_staging(
    staging: &Path,
    profile_id: &str,
    transaction_id: &str,
) -> Result<(), ProfileError> {
    let expected = format!(".reauth-{profile_id}-{transaction_id}");
    if staging.file_name().and_then(|name| name.to_str()) != Some(expected.as_str()) {
        return Err(ProfileError::ReauthRecoveryRequired);
    }
    let expected_tree = validate_reauth_tree(staging, profile_id)?;
    let provider_root = staging
        .parent()
        .ok_or(ProfileError::ReauthRecoveryRequired)?;
    remove_owned_reauth_staging_at(
        provider_root,
        staging,
        &expected,
        expected_tree,
        MAX_REAUTH_TREE_ENTRIES,
    )
    .map_err(|_| ProfileError::ReauthRecoveryRequired)
}

fn validate_reauth_tree(
    staging: &Path,
    profile_id: &str,
) -> Result<FileSystemIdentity, ProfileError> {
    let identity =
        private_directory_identity(staging).map_err(|_| ProfileError::ReauthRecoveryRequired)?;
    let marker = staging.join(OWNER_MARKER);
    verify_private_single_link_regular_file(&marker)
        .map_err(|_| ProfileError::ReauthRecoveryRequired)?;
    if fs::read_to_string(&marker).ok().as_deref() != Some(profile_id) {
        return Err(ProfileError::ReauthRecoveryRequired);
    }

    let mut pending = vec![staging.to_owned()];
    let mut entries = 0_usize;
    while let Some(directory) = pending.pop() {
        verify_private_directory(&directory).map_err(|_| ProfileError::ReauthRecoveryRequired)?;
        for entry in fs::read_dir(&directory)? {
            entries = entries
                .checked_add(1)
                .filter(|count| *count <= MAX_REAUTH_TREE_ENTRIES)
                .ok_or(ProfileError::ReauthRecoveryRequired)?;
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                pending.push(path);
            } else if metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
                verify_private_single_link_regular_file(&path)
                    .map_err(|_| ProfileError::ReauthRecoveryRequired)?;
            } else {
                return Err(ProfileError::ReauthRecoveryRequired);
            }
        }
    }
    if private_directory_identity(staging).map_err(|_| ProfileError::ReauthRecoveryRequired)?
        != identity
    {
        return Err(ProfileError::ReauthRecoveryRequired);
    }
    Ok(identity)
}

fn write_reauth_private_file(
    path: &Path,
    bytes: &[u8],
    create_fault: ReauthFaultPoint,
    write_fault: ReauthFaultPoint,
    sync_fault: ReauthFaultPoint,
) -> Result<(), ProfileError> {
    inject_reauth_fault(create_fault)?;
    let mut file = create_new_private_file(path)?;
    let publication = (|| {
        inject_reauth_fault(write_fault)?;
        file.write_all(bytes)?;
        inject_reauth_fault(sync_fault)?;
        file.sync_all()?;
        verify_private_single_link_regular_file(path)
    })();
    if publication.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    publication
}

fn read_private_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ProfileError> {
    verify_private_single_link_regular_file(path)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(ProfileError::UnsafeState(
            "managed credential exceeds the supported size limit".to_owned(),
        ));
    }
    Ok(bytes)
}

fn verify_private_single_link_regular_file(path: &Path) -> Result<(), ProfileError> {
    verify_private_regular_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if fs::symlink_metadata(path)?.nlink() != 1 {
            return Err(ProfileError::UnsafeState(
                "managed credential has multiple filesystem links".to_owned(),
            ));
        }
    }
    Ok(())
}

fn auth_digest(bytes: &[u8]) -> String {
    encode_lower_hex(&Sha256::digest(bytes))
}

fn read_private_digest(path: &Path) -> Result<String, ProfileError> {
    Ok(auth_digest(&read_private_bounded(
        path,
        MAX_REAUTH_AUTH_BYTES,
    )?))
}

fn optional_private_digest(path: &Path) -> Result<Option<String>, ProfileError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ProfileError::Io(error)),
        Ok(_) => read_private_digest(path).map(Some),
    }
}

fn remove_exact_private_file(
    path: &Path,
    expected_digest: Option<&str>,
) -> Result<(), ProfileError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ProfileError::Io(error)),
        Ok(_) => {
            verify_private_single_link_regular_file(path)
                .map_err(|_| ProfileError::ReauthRecoveryRequired)?;
            if let Some(expected_digest) = expected_digest {
                if read_private_digest(path)? != expected_digest {
                    return Err(ProfileError::ReauthRecoveryRequired);
                }
            }
            fs::remove_file(path).map_err(ProfileError::Io)
        }
    }
}

fn ensure_path_absent(path: &Path) -> Result<(), ProfileError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ProfileError::Io(error)),
        Ok(_) => Err(ProfileError::ReauthRecoveryRequired),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    struct ReauthFaultGuard;

    impl ReauthFaultGuard {
        fn set(point: ReauthFaultPoint) -> Self {
            REAUTH_FAULT.with(|fault| fault.set(Some(point)));
            Self
        }
    }

    impl Drop for ReauthFaultGuard {
        fn drop(&mut self) {
            REAUTH_FAULT.with(|fault| fault.set(None));
        }
    }

    fn sandbox(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "calcifer-reauth-{name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(fs::canonicalize(root)?)
    }

    fn auth_bytes(scope: &str, token: &str) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&serde_json::json!({
            "auth_mode": "chatgpt",
            "tokens": {
                "account_id": scope,
                "access_token": token,
            }
        }))
    }

    fn registered_profile(
        root: &Path,
        scope: &str,
    ) -> Result<(Registry, Profile), Box<dyn std::error::Error>> {
        let registry = Registry::at(root.to_owned());
        let pending = registry.begin_codex_registration("work")?;
        write_private_file(
            &pending.home().join("auth.json"),
            &auth_bytes(scope, "old")?,
        )?;
        let profile = pending.commit(CodexIdentityAdapter::for_test())?;
        Ok((registry, profile))
    }

    fn prepared_transaction<'a>(
        registry: &'a Registry,
        scope: &str,
    ) -> Result<(PendingCodexReauth<'a>, ReauthJournal), Box<dyn std::error::Error>> {
        let pending = registry
            .begin_codex_reauthentication("work", |_, _| Ok(CodexIdentityAdapter::for_test()))?;
        let staged = auth_bytes(scope, "new")?;
        write_private_file(&pending.home().join("auth.json"), &staged)?;
        let home = registry.profile_home(&pending.profile)?;
        let old = read_private_bounded(&home.join("auth.json"), MAX_REAUTH_AUTH_BYTES)?;
        let temporary_name = format!(".auth.json.reauth-new-{}", pending.transaction_id);
        let backup_name = format!(".auth.json.reauth-old-{}", pending.transaction_id);
        write_private_file(&home.join(&temporary_name), &staged)?;
        let journal = ReauthJournal {
            schema_version: REAUTH_JOURNAL_SCHEMA_VERSION,
            provider: Provider::Codex,
            credential_name: "auth.json".to_owned(),
            profile_id: pending.profile.id.clone(),
            transaction_id: pending.transaction_id.clone(),
            staging_name: pending
                .staging
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("staging name")?
                .to_owned(),
            temporary_name,
            backup_name,
            old_auth_digest: auth_digest(&old),
            new_auth_digest: auth_digest(&staged),
        };
        publish_reauth_journal(&pending.profile_directory, &pending.staging, &journal)?;
        Ok((pending, journal))
    }

    fn ready_pending<'a>(
        registry: &'a Registry,
        scope: &str,
    ) -> Result<PendingCodexReauth<'a>, Box<dyn std::error::Error>> {
        let pending = registry
            .begin_codex_reauthentication("work", |_, _| Ok(CodexIdentityAdapter::for_test()))?;
        write_private_file(
            &pending.home().join("auth.json"),
            &auth_bytes(scope, "new")?,
        )?;
        Ok(pending)
    }

    #[test]
    fn staging_creation_faults_leave_no_candidate_or_profile_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        for point in [
            ReauthFaultPoint::StagingCreate,
            ReauthFaultPoint::StagingDirectorySync,
        ] {
            let root = sandbox("staging-fault")?;
            let (registry, profile) = registered_profile(&root, "same-account")?;
            let home = registry.profile_home(&profile)?;
            let old = fs::read(home.join("auth.json"))?;
            let guard = ReauthFaultGuard::set(point);
            let error = registry
                .begin_codex_reauthentication("work", |_, _| Ok(CodexIdentityAdapter::for_test()))
                .err()
                .ok_or("staging fault must fail reauth preparation")?;
            drop(guard);
            assert!(matches!(error, ProfileError::Io(_)));
            assert_eq!(fs::read(home.join("auth.json"))?, old);
            let provider_root = registry
                .profile_directory(&profile)?
                .parent()
                .ok_or("provider root")?
                .to_owned();
            assert!(!fs::read_dir(provider_root)?.any(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().into_string().ok())
                    .is_some_and(|name| name.starts_with(".reauth-"))
            }));
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn every_commit_fault_converges_without_replacing_new_with_old()
    -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                ReauthFaultPoint::CredentialTemporaryCreate,
                "io_error",
                false,
            ),
            (
                ReauthFaultPoint::CredentialTemporaryWrite,
                "io_error",
                false,
            ),
            (ReauthFaultPoint::CredentialTemporarySync, "io_error", false),
            (
                ReauthFaultPoint::CredentialTemporaryRename,
                "reauth_recovery_required",
                false,
            ),
            (
                ReauthFaultPoint::CredentialTemporaryDirectorySync,
                "reauth_recovery_required",
                false,
            ),
            (ReauthFaultPoint::JournalTemporaryCreate, "io_error", false),
            (ReauthFaultPoint::JournalTemporaryWrite, "io_error", false),
            (ReauthFaultPoint::JournalTemporarySync, "io_error", false),
            (ReauthFaultPoint::JournalRename, "io_error", false),
            (
                ReauthFaultPoint::JournalDirectorySync,
                "reauth_recovery_required",
                false,
            ),
            (
                ReauthFaultPoint::OldCredentialRename,
                "reauth_recovery_required",
                false,
            ),
            (
                ReauthFaultPoint::NewCredentialRename,
                "reauth_recovery_required",
                true,
            ),
            (
                ReauthFaultPoint::HomeDirectorySync,
                "reauth_commit_uncertain",
                true,
            ),
            (
                ReauthFaultPoint::BackupRemove,
                "reauth_commit_uncertain",
                true,
            ),
            (
                ReauthFaultPoint::StagingCleanup,
                "reauth_commit_uncertain",
                true,
            ),
            (
                ReauthFaultPoint::JournalRemove,
                "reauth_commit_uncertain",
                true,
            ),
        ];

        for (point, expected_error_code, new_must_survive) in cases {
            let root = sandbox("commit-fault")?;
            let (registry, profile) = registered_profile(&root, "same-account")?;
            let home = registry.profile_home(&profile)?;
            let old = fs::read(home.join("auth.json"))?;
            let new = auth_bytes("same-account", "new")?;
            let pending = ready_pending(&registry, "same-account")?;
            let guard = ReauthFaultGuard::set(point);
            let error = pending
                .commit(CodexIdentityAdapter::for_test())
                .err()
                .ok_or("injected commit fault must fail the initiating command")?;
            drop(guard);
            assert_eq!(error.code(), expected_error_code);

            assert_eq!(registry.list()?, vec![profile.clone()]);
            assert_eq!(
                fs::read(home.join("auth.json"))?.as_slice(),
                if new_must_survive {
                    new.as_slice()
                } else {
                    old.as_slice()
                },
                "fault {point:?} must converge on the visibility side of the transaction"
            );
            let profile_directory = registry.profile_directory(&profile)?;
            assert!(!profile_directory.join(REAUTH_JOURNAL_FILE).exists());
            assert!(!fs::read_dir(&home)?.any(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().into_string().ok())
                    .is_some_and(|name| name.starts_with(".auth.json.reauth-"))
            }));
            let provider_root = profile_directory.parent().ok_or("provider root")?;
            assert!(!fs::read_dir(provider_root)?.any(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().into_string().ok())
                    .is_some_and(|name| name.starts_with(".reauth-"))
            }));
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn recovery_rolls_back_only_before_new_credential_visibility()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("rollback-before-visible")?;
        let (registry, profile) = registered_profile(&root, "same-account")?;
        let old = fs::read(registry.profile_home(&profile)?.join("auth.json"))?;
        let (mut interrupted, journal) = prepared_transaction(&registry, "same-account")?;
        interrupted.preserve = true;
        drop(interrupted);

        let fresh = registry
            .begin_codex_reauthentication("work", |_, _| Ok(CodexIdentityAdapter::for_test()))?;
        let home = registry.profile_home(&profile)?;
        assert_eq!(fs::read(home.join("auth.json"))?, old);
        assert!(!home.join(journal.temporary_name).exists());
        assert!(!home.join(journal.backup_name).exists());
        assert!(!fresh.profile_directory.join(REAUTH_JOURNAL_FILE).exists());
        fresh.abort()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn recovery_completes_a_new_credential_after_the_old_path_was_hidden()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("complete-after-old-hidden")?;
        let (registry, profile) = registered_profile(&root, "same-account")?;
        let (mut interrupted, journal) = prepared_transaction(&registry, "same-account")?;
        let home = registry.profile_home(&profile)?;
        fs::rename(home.join("auth.json"), home.join(&journal.backup_name))?;
        interrupted.preserve = true;
        drop(interrupted);

        let fresh = registry
            .begin_codex_reauthentication("work", |_, _| Ok(CodexIdentityAdapter::for_test()))?;
        assert_eq!(
            read_private_digest(&home.join("auth.json"))?,
            journal.new_auth_digest
        );
        assert!(!home.join(journal.temporary_name).exists());
        assert!(!home.join(journal.backup_name).exists());
        assert!(!fresh.profile_directory.join(REAUTH_JOURNAL_FILE).exists());
        fresh.abort()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn recovery_never_restores_the_old_backup_after_new_visibility()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("keep-new-visible")?;
        let (registry, profile) = registered_profile(&root, "same-account")?;
        let (mut interrupted, journal) = prepared_transaction(&registry, "same-account")?;
        let home = registry.profile_home(&profile)?;
        fs::rename(home.join("auth.json"), home.join(&journal.backup_name))?;
        fs::rename(home.join(&journal.temporary_name), home.join("auth.json"))?;
        interrupted.preserve = true;
        drop(interrupted);

        let listed = registry.list()?;
        assert_eq!(listed, vec![profile.clone()]);
        assert_eq!(
            read_private_digest(&home.join("auth.json"))?,
            journal.new_auth_digest
        );
        assert!(!home.join(journal.backup_name).exists());
        assert!(
            !registry
                .profile_directory(&profile)?
                .join(REAUTH_JOURNAL_FILE)
                .exists()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn active_profile_lease_rejects_reauth_before_staging() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = sandbox("busy")?;
        let (registry, profile) = registered_profile(&root, "same-account")?;
        let lease = registry.lock_profile(&profile)?;
        let error = registry
            .begin_codex_reauthentication("work", |_, _| Ok(CodexIdentityAdapter::for_test()))
            .err()
            .ok_or("active lease must reject reauth")?;
        assert_eq!(error.code(), "profile_busy");
        let profile_directory = registry.profile_directory(&profile)?;
        let provider_root = profile_directory
            .parent()
            .ok_or("profile directory must have a provider root")?
            .to_owned();
        assert!(!fs::read_dir(provider_root)?.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.starts_with(".reauth-"))
        }));
        drop(lease);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn hard_linked_current_credential_fails_before_adapter_or_staging()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("hard-linked-current")?;
        let (registry, profile) = registered_profile(&root, "same-account")?;
        let home = registry.profile_home(&profile)?;
        let linked = home.join("auth-linked-sentinel");
        fs::hard_link(home.join("auth.json"), &linked)?;
        let adapter_called = std::cell::Cell::new(false);

        let error = registry
            .begin_codex_reauthentication("work", |_, _| {
                adapter_called.set(true);
                Ok(CodexIdentityAdapter::for_test())
            })
            .err()
            .ok_or("hard-linked auth must be refused")?;
        assert_eq!(error.code(), "unsafe_profile_state");
        assert!(!adapter_called.get());
        let provider_root = registry
            .profile_directory(&profile)?
            .parent()
            .ok_or("provider root")?
            .to_owned();
        assert!(!fs::read_dir(provider_root)?.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.starts_with(".reauth-"))
        }));

        fs::remove_file(linked)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn unsafe_orphan_staging_is_refused_without_following_links()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("unsafe-orphan")?;
        let outside = sandbox("outside-sentinel")?;
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, b"must-survive")?;
        let (registry, profile) = registered_profile(&root, "same-account")?;
        let profile_directory = registry.profile_directory(&profile)?;
        let provider_root = profile_directory.parent().ok_or("provider root")?;
        let transaction_id = Uuid::new_v4().to_string();
        let staging = provider_root.join(format!(".reauth-{}-{transaction_id}", profile.id));
        secure_create_dir(&staging)?;
        write_private_file(&staging.join(OWNER_MARKER), profile.id.as_bytes())?;
        symlink(&outside, staging.join("unsafe-link"))?;

        let error = registry
            .begin_codex_reauthentication("work", |_, _| Ok(CodexIdentityAdapter::for_test()))
            .err()
            .ok_or("unsafe orphan must be refused")?;
        assert_eq!(error.code(), "reauth_recovery_required");
        assert_eq!(fs::read(&sentinel)?, b"must-survive");
        assert!(staging.exists());

        fs::remove_file(staging.join("unsafe-link"))?;
        fs::remove_file(staging.join(OWNER_MARKER))?;
        fs::remove_dir(staging)?;
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn claude_credential_recovery_converges_on_the_atomic_visibility_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        for (fault, expect_new) in [
            (ReauthFaultPoint::CredentialTemporaryDirectorySync, false),
            (ReauthFaultPoint::NewCredentialRename, true),
        ] {
            let root = sandbox("claude-credential-recovery")?;
            let registry = Registry::at(root.clone());
            let pending = registry.begin_claude_registration("work")?;
            write_private_file(
                &pending.home().join(".credentials.json"),
                b"old-claude-credential",
            )?;
            let profile = pending.commit_claude()?;
            let home = registry.profile_home(&profile)?;

            let pending = registry.begin_claude_reauthentication("work")?;
            write_private_file(
                &pending.home().join(".credentials.json"),
                b"new-claude-credential",
            )?;
            let guard = ReauthFaultGuard::set(fault);
            let error = pending
                .commit_claude()
                .err()
                .ok_or("injected Claude reauth fault must fail")?;
            drop(guard);
            assert_eq!(error.code(), "reauth_recovery_required");

            assert_eq!(registry.list()?, vec![profile]);
            assert_eq!(
                fs::read(home.join(".credentials.json"))?,
                if expect_new {
                    b"new-claude-credential".as_slice()
                } else {
                    b"old-claude-credential".as_slice()
                }
            );
            assert_eq!(fs::read_dir(&home)?.count(), 1);
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }
}
