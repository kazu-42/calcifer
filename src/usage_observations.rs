//! Bounded, disposable usage observations for profile selection and status.
//!
//! This cache contains only normalized provider quota metadata. It never
//! accepts credentials, provider account/workspace identifiers, reset-credit
//! identifiers, thread/turn identifiers, prompts, tool calls, or transcript
//! content. A cache entry is evidence, not authority: callers must still hold
//! the selected profile lease and perform the revalidation required by their
//! operation.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::profiles::{
    Registry, create_new_private_file, open_private_lock_file, open_verified_registry_file,
    secure_create_dir_all, sync_directory, verify_private_directory, verify_private_regular_file,
};
use crate::providers::codex::{
    CodexCompatibilityStatus, CodexUsage, CodexUsageError, RateLimitSnapshot,
};

const CACHE_SCHEMA_VERSION: u8 = 1;
const CACHE_FILE: &str = "usage-observations.json";
const CACHE_LOCK_FILE: &str = "usage-observations.lock";
const MAX_SERIALIZED_BYTES: usize = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 512;
const MAX_AUDIT_EVENTS: usize = 512;
const MAX_RATE_LIMIT_BUCKETS: usize = 64;
const MAX_RESET_CREDIT_DETAILS: usize = 64;
const MAX_TEXT_BYTES: usize = 256;
const MAX_DECIMAL_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 64;
const MAX_PROVIDER_TIMESTAMP_SECONDS: i64 = 253_402_300_799;

/// Default freshness and refresh limits. The selector may require a shorter
/// freshness window, but it may never extend a cache entry beyond this policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObservationPolicy {
    fresh_ttl_seconds: i64,
    retry_base_seconds: i64,
    retry_max_seconds: i64,
    max_idle_refresh: usize,
}

impl Default for ObservationPolicy {
    fn default() -> Self {
        Self {
            fresh_ttl_seconds: 60,
            retry_base_seconds: 5,
            retry_max_seconds: 300,
            max_idle_refresh: 4,
        }
    }
}

impl ObservationPolicy {
    #[cfg(test)]
    const fn for_test(
        fresh_ttl_seconds: i64,
        retry_base_seconds: i64,
        retry_max_seconds: i64,
        max_idle_refresh: usize,
    ) -> Self {
        Self {
            fresh_ttl_seconds,
            retry_base_seconds,
            retry_max_seconds,
            max_idle_refresh,
        }
    }

    fn validate(self) -> Result<(), ObservationError> {
        if self.fresh_ttl_seconds <= 0
            || self.retry_base_seconds <= 0
            || self.retry_max_seconds < self.retry_base_seconds
            || self.max_idle_refresh == 0
            || self.max_idle_refresh > MAX_ENTRIES
        {
            return Err(ObservationError::InvalidInput);
        }
        Ok(())
    }

    fn expiry(self, observed_at: i64) -> Result<i64, ObservationError> {
        observed_at
            .checked_add(self.fresh_ttl_seconds)
            .filter(|value| *value <= MAX_PROVIDER_TIMESTAMP_SECONDS)
            .ok_or(ObservationError::InvalidInput)
    }

    fn retry_at(self, observed_at: i64, consecutive_failures: u8) -> Result<i64, ObservationError> {
        let shift = u32::from(consecutive_failures.saturating_sub(1).min(30));
        let multiplier = 1_i64.checked_shl(shift).unwrap_or(i64::MAX);
        let delay = self
            .retry_base_seconds
            .saturating_mul(multiplier)
            .min(self.retry_max_seconds);
        observed_at
            .checked_add(delay)
            .filter(|value| *value <= MAX_PROVIDER_TIMESTAMP_SECONDS)
            .ok_or(ObservationError::InvalidInput)
    }
}

/// The conservative state exposed to status and the later selector.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Availability {
    Available,
    Exhausted,
    Stale,
    Unsupported,
    Unknown,
}

impl Availability {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Exhausted => "exhausted",
            Self::Stale => "stale",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Freshness {
    Fresh,
    Stale,
    RevalidationRequired,
    Unknown,
}

impl Freshness {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::RevalidationRequired => "revalidation_required",
            Self::Unknown => "unknown",
        }
    }
}

/// Fixed sources prevent provider-controlled or transcript text entering the
/// cache/audit document.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ObservationSource {
    ActiveMonitor,
    IdleRead,
    UsageLimitSignal,
}

impl ObservationSource {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ActiveMonitor => "codex_active_monitor",
            Self::IdleRead => "codex_app_server",
            Self::UsageLimitSignal => "codex_usage_limit_signal",
        }
    }

    const fn is_authoritative_usage(self) -> bool {
        matches!(self, Self::ActiveMonitor | Self::IdleRead)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredAvailability {
    Available,
    Exhausted,
    Unknown,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuditKind {
    UsageAccepted,
    FailureObserved,
    RevalidationRequired,
    OutOfOrderIgnored,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredFailure {
    Unsupported,
    Protocol,
    Authentication,
    Timeout,
    Transport,
    Provider,
    Spawn,
}

impl From<CodexUsageError> for StoredFailure {
    fn from(value: CodexUsageError) -> Self {
        match value {
            CodexUsageError::Unsupported => Self::Unsupported,
            CodexUsageError::Protocol => Self::Protocol,
            CodexUsageError::Authentication => Self::Authentication,
            CodexUsageError::Timeout => Self::Timeout,
            CodexUsageError::Transport => Self::Transport,
            CodexUsageError::Provider => Self::Provider,
            CodexUsageError::Spawn => Self::Spawn,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheEntry {
    profile_id: String,
    availability: StoredAvailability,
    observed_at: i64,
    latest_event_at: i64,
    expires_at: Option<i64>,
    source: ObservationSource,
    codex_version: Option<String>,
    adapter_version: String,
    compatibility: CodexCompatibilityStatus,
    usage: Option<CodexUsage>,
    revalidation_required_at: Option<i64>,
    consecutive_failures: u8,
    next_refresh_at: i64,
    last_failure: Option<StoredFailure>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditEvent {
    revision: u64,
    profile_id: String,
    observed_at: i64,
    source: ObservationSource,
    kind: AuditKind,
    availability: StoredAvailability,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheDocument {
    schema_version: u8,
    revision: u64,
    entries: Vec<CacheEntry>,
    audit: Vec<AuditEvent>,
}

impl Default for CacheDocument {
    fn default() -> Self {
        Self {
            schema_version: CACHE_SCHEMA_VERSION,
            revision: 0,
            entries: Vec::new(),
            audit: Vec::new(),
        }
    }
}

/// Redacted cache projection. The profile alias is resolved separately from
/// the live registry and never copied into durable observation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UsageView {
    pub(crate) availability: Availability,
    pub(crate) freshness: Freshness,
    pub(crate) observed_at: i64,
    pub(crate) source: ObservationSource,
    pub(crate) codex_version: Option<String>,
    pub(crate) adapter_version: String,
    pub(crate) compatibility: CodexCompatibilityStatus,
    pub(crate) usage: Option<CodexUsage>,
    pub(crate) next_refresh_at: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ObservationStore {
    root: PathBuf,
    policy: ObservationPolicy,
}

impl ObservationStore {
    pub(crate) fn from_profiles(registry: &Registry) -> Self {
        Self {
            root: registry.managed_root().to_owned(),
            policy: ObservationPolicy::default(),
        }
    }

    pub(crate) fn observe_usage(
        &self,
        profile_id: &str,
        source: ObservationSource,
        codex_version: &str,
        usage: CodexUsage,
        observed_at: i64,
    ) -> Result<UsageView, ObservationError> {
        if !source.is_authoritative_usage() {
            return Err(ObservationError::InvalidInput);
        }
        self.transact(|document| {
            document.observe_usage(
                profile_id,
                source,
                codex_version,
                usage,
                observed_at,
                self.policy,
            )?;
            document
                .view(profile_id, observed_at)
                .ok_or(ObservationError::InvalidDocument)
        })
    }

    pub(crate) fn observe_failure(
        &self,
        profile_id: &str,
        source: ObservationSource,
        codex_version: Option<&str>,
        compatibility: CodexCompatibilityStatus,
        failure: CodexUsageError,
        observed_at: i64,
    ) -> Result<UsageView, ObservationError> {
        if !source.is_authoritative_usage() {
            return Err(ObservationError::InvalidInput);
        }
        self.transact(|document| {
            document.observe_failure(
                profile_id,
                source,
                codex_version,
                compatibility,
                failure,
                observed_at,
                self.policy,
            )?;
            document
                .view(profile_id, observed_at)
                .ok_or(ObservationError::InvalidDocument)
        })
    }

    /// Records only that an exact supervised turn reported
    /// `usageLimitExceeded`. Thread/turn identifiers are deliberately not
    /// accepted by this API. The signal invalidates selection until a full
    /// authoritative usage snapshot at the same or a later timestamp arrives.
    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    #[allow(
        dead_code,
        reason = "the guarded selector in issue #36 consumes the revalidation gate"
    )]
    pub(crate) fn require_revalidation(
        &self,
        profile_id: &str,
        observed_at: i64,
    ) -> Result<UsageView, ObservationError> {
        self.transact(|document| {
            document.require_revalidation(profile_id, observed_at, self.policy)?;
            document
                .view(profile_id, observed_at)
                .ok_or(ObservationError::InvalidDocument)
        })
    }

    pub(crate) fn view(
        &self,
        profile_id: &str,
        now: i64,
    ) -> Result<Option<UsageView>, ObservationError> {
        validate_profile_id(profile_id)?;
        validate_timestamp(now)?;
        let document = self.read_document()?;
        Ok(document.view(profile_id, now))
    }

    /// Returns at most the policy limit of idle profile IDs, ordered by the
    /// earliest due time and then stable local ID. Active profiles are never
    /// selected for a second App Server read.
    pub(crate) fn due_idle_refresh(
        &self,
        registered_profile_ids: &[String],
        active_profile_ids: &BTreeSet<String>,
        now: i64,
    ) -> Result<Vec<String>, ObservationError> {
        validate_timestamp(now)?;
        if registered_profile_ids.len() > MAX_ENTRIES || active_profile_ids.len() > MAX_ENTRIES {
            return Err(ObservationError::LimitExceeded);
        }
        for profile_id in registered_profile_ids {
            validate_profile_id(profile_id)?;
        }
        for profile_id in active_profile_ids {
            validate_profile_id(profile_id)?;
        }
        let document = self.read_document()?;
        document.due_idle_refresh(registered_profile_ids, active_profile_ids, now, self.policy)
    }

    fn transact<T>(
        &self,
        mutation: impl FnOnce(&mut CacheDocument) -> Result<T, ObservationError>,
    ) -> Result<T, ObservationError> {
        ensure_supported()?;
        self.policy.validate()?;
        secure_create_dir_all(&self.root).map_err(storage_error)?;
        verify_private_directory(&self.root).map_err(storage_error)?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock).map_err(|_| ObservationError::StorageUnavailable)?;
        let mut document = self.load()?;
        let result = mutation(&mut document)?;
        document.validate()?;
        self.save(&document)?;
        Ok(result)
    }

    fn read_document(&self) -> Result<CacheDocument, ObservationError> {
        ensure_supported()?;
        self.policy.validate()?;
        match fs::symlink_metadata(&self.root) {
            Ok(_) => verify_private_directory(&self.root).map_err(storage_error)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(CacheDocument::default());
            }
            Err(_) => return Err(ObservationError::StorageUnavailable),
        }
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock).map_err(|_| ObservationError::StorageUnavailable)?;
        self.load()
    }

    fn open_lock(&self) -> Result<fs::File, ObservationError> {
        let path = self.root.join(CACHE_LOCK_FILE);
        let new_file = match fs::symlink_metadata(&path) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(_) => return Err(ObservationError::StorageUnavailable),
        };
        let file = open_private_lock_file(&path).map_err(storage_error)?;
        if new_file {
            file.sync_all()
                .map_err(|_| ObservationError::StorageUnavailable)?;
            sync_directory(&self.root).map_err(storage_error)?;
        }
        Ok(file)
    }

    fn load(&self) -> Result<CacheDocument, ObservationError> {
        let path = self.root.join(CACHE_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(CacheDocument::default());
            }
            Err(_) => return Err(ObservationError::StorageUnavailable),
        }
        let mut bytes = Vec::new();
        open_verified_registry_file(&path, true)
            .map_err(storage_error)?
            .take((MAX_SERIALIZED_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ObservationError::StorageUnavailable)?;
        if bytes.len() > MAX_SERIALIZED_BYTES {
            return Err(ObservationError::LimitExceeded);
        }
        let document: CacheDocument =
            serde_json::from_slice(&bytes).map_err(|_| ObservationError::InvalidDocument)?;
        document.validate()?;
        Ok(document)
    }

    fn save(&self, document: &CacheDocument) -> Result<(), ObservationError> {
        let bytes = serde_json::to_vec(document).map_err(|_| ObservationError::InvalidDocument)?;
        if bytes.len() > MAX_SERIALIZED_BYTES {
            return Err(ObservationError::LimitExceeded);
        }
        let temporary = self
            .root
            .join(format!(".{CACHE_FILE}.{}.tmp", Uuid::new_v4()));
        let destination = self.root.join(CACHE_FILE);
        let publication = (|| {
            let mut file = create_new_private_file(&temporary).map_err(storage_error)?;
            file.write_all(&bytes)
                .map_err(|_| ObservationError::StorageUnavailable)?;
            file.sync_all()
                .map_err(|_| ObservationError::StorageUnavailable)?;
            verify_private_regular_file(&temporary).map_err(storage_error)?;
            drop(file);
            fs::rename(&temporary, &destination)
                .map_err(|_| ObservationError::StorageUnavailable)?;
            sync_directory(&self.root).map_err(storage_error)
        })();
        if let Err(error) = publication {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        Ok(())
    }

    #[cfg(test)]
    fn at(root: PathBuf, policy: ObservationPolicy) -> Self {
        Self { root, policy }
    }
}

impl CacheDocument {
    fn observe_usage(
        &mut self,
        profile_id: &str,
        source: ObservationSource,
        codex_version: &str,
        usage: CodexUsage,
        observed_at: i64,
        policy: ObservationPolicy,
    ) -> Result<(), ObservationError> {
        validate_profile_id(profile_id)?;
        validate_timestamp(observed_at)?;
        validate_version(codex_version)?;
        validate_usage(&usage)?;
        policy.validate()?;
        if self.is_out_of_order(profile_id, observed_at) {
            return self.audit_ignored(profile_id, source, observed_at);
        }
        let availability = classify(&usage);
        let expires_at = policy.expiry(observed_at)?;
        let entry = CacheEntry {
            profile_id: profile_id.to_owned(),
            availability,
            observed_at,
            latest_event_at: observed_at,
            expires_at: Some(expires_at),
            source,
            codex_version: Some(codex_version.to_owned()),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            compatibility: CodexCompatibilityStatus::Compatible,
            usage: Some(usage),
            revalidation_required_at: None,
            consecutive_failures: 0,
            next_refresh_at: expires_at,
            last_failure: None,
        };
        self.replace_entry(entry)?;
        self.push_audit(
            profile_id,
            source,
            observed_at,
            AuditKind::UsageAccepted,
            availability,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "all evidence fields are explicit at the cache boundary"
    )]
    fn observe_failure(
        &mut self,
        profile_id: &str,
        source: ObservationSource,
        codex_version: Option<&str>,
        compatibility: CodexCompatibilityStatus,
        failure: CodexUsageError,
        observed_at: i64,
        policy: ObservationPolicy,
    ) -> Result<(), ObservationError> {
        validate_profile_id(profile_id)?;
        validate_timestamp(observed_at)?;
        if let Some(version) = codex_version {
            validate_version(version)?;
        }
        policy.validate()?;
        if self.is_out_of_order(profile_id, observed_at) {
            return self.audit_ignored(profile_id, source, observed_at);
        }
        let previous = self.entry(profile_id).cloned();
        let failures = previous
            .as_ref()
            .map_or(1, |entry| entry.consecutive_failures.saturating_add(1));
        let failure = StoredFailure::from(failure);
        let availability = if failure == StoredFailure::Unsupported {
            StoredAvailability::Unsupported
        } else {
            StoredAvailability::Unknown
        };
        let next_refresh_at = policy.retry_at(observed_at, failures)?;
        let entry = if failure != StoredFailure::Unsupported
            && previous.as_ref().is_some_and(|entry| entry.usage.is_some())
        {
            let mut previous = previous.ok_or(ObservationError::InvalidDocument)?;
            previous.latest_event_at = observed_at;
            previous.revalidation_required_at = None;
            previous.consecutive_failures = failures;
            previous.next_refresh_at = next_refresh_at;
            previous.last_failure = Some(failure);
            previous
        } else {
            CacheEntry {
                profile_id: profile_id.to_owned(),
                availability,
                observed_at,
                latest_event_at: observed_at,
                expires_at: None,
                source,
                codex_version: codex_version.map(str::to_owned),
                adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
                compatibility,
                usage: None,
                revalidation_required_at: None,
                consecutive_failures: failures,
                next_refresh_at,
                last_failure: Some(failure),
            }
        };
        let audit_availability = entry.availability;
        self.replace_entry(entry)?;
        self.push_audit(
            profile_id,
            source,
            observed_at,
            AuditKind::FailureObserved,
            audit_availability,
        )
    }

    fn require_revalidation(
        &mut self,
        profile_id: &str,
        observed_at: i64,
        policy: ObservationPolicy,
    ) -> Result<(), ObservationError> {
        validate_profile_id(profile_id)?;
        validate_timestamp(observed_at)?;
        policy.validate()?;
        if self.is_out_of_order(profile_id, observed_at) {
            return self.audit_ignored(
                profile_id,
                ObservationSource::UsageLimitSignal,
                observed_at,
            );
        }
        let previous = self.entry(profile_id).cloned();
        let entry = CacheEntry {
            profile_id: profile_id.to_owned(),
            availability: StoredAvailability::Unknown,
            observed_at,
            latest_event_at: observed_at,
            expires_at: None,
            source: ObservationSource::UsageLimitSignal,
            codex_version: previous
                .as_ref()
                .and_then(|entry| entry.codex_version.clone()),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            compatibility: previous
                .as_ref()
                .map_or(CodexCompatibilityStatus::Unverified, |entry| {
                    entry.compatibility
                }),
            usage: None,
            revalidation_required_at: Some(observed_at),
            consecutive_failures: 0,
            next_refresh_at: observed_at,
            last_failure: None,
        };
        self.replace_entry(entry)?;
        self.push_audit(
            profile_id,
            ObservationSource::UsageLimitSignal,
            observed_at,
            AuditKind::RevalidationRequired,
            StoredAvailability::Unknown,
        )
    }

    fn is_out_of_order(&self, profile_id: &str, observed_at: i64) -> bool {
        self.entry(profile_id)
            .is_some_and(|entry| observed_at < entry.latest_event_at)
    }

    fn audit_ignored(
        &mut self,
        profile_id: &str,
        source: ObservationSource,
        observed_at: i64,
    ) -> Result<(), ObservationError> {
        let availability = self
            .entry(profile_id)
            .map_or(StoredAvailability::Unknown, |entry| entry.availability);
        self.push_audit(
            profile_id,
            source,
            observed_at,
            AuditKind::OutOfOrderIgnored,
            availability,
        )
    }

    fn replace_entry(&mut self, entry: CacheEntry) -> Result<(), ObservationError> {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|existing| existing.profile_id == entry.profile_id)
        {
            *existing = entry;
        } else {
            if self.entries.len() >= MAX_ENTRIES {
                return Err(ObservationError::LimitExceeded);
            }
            self.entries.push(entry);
            self.entries
                .sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
        }
        Ok(())
    }

    fn push_audit(
        &mut self,
        profile_id: &str,
        source: ObservationSource,
        observed_at: i64,
        kind: AuditKind,
        availability: StoredAvailability,
    ) -> Result<(), ObservationError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ObservationError::LimitExceeded)?;
        self.audit.push(AuditEvent {
            revision: self.revision,
            profile_id: profile_id.to_owned(),
            observed_at,
            source,
            kind,
            availability,
        });
        if self.audit.len() > MAX_AUDIT_EVENTS {
            let drain = self.audit.len() - MAX_AUDIT_EVENTS;
            self.audit.drain(..drain);
        }
        Ok(())
    }

    fn entry(&self, profile_id: &str) -> Option<&CacheEntry> {
        self.entries
            .iter()
            .find(|entry| entry.profile_id == profile_id)
    }

    fn view(&self, profile_id: &str, now: i64) -> Option<UsageView> {
        let entry = self.entry(profile_id)?;
        let revalidation_required = entry
            .revalidation_required_at
            .is_some_and(|signal| signal >= entry.observed_at);
        let expired = entry.expires_at.is_some_and(|expiry| now >= expiry);
        let (availability, freshness) = if revalidation_required {
            (Availability::Unknown, Freshness::RevalidationRequired)
        } else if entry.availability == StoredAvailability::Unsupported {
            (Availability::Unsupported, Freshness::Unknown)
        } else if entry.last_failure.is_some() {
            if entry.usage.is_some() {
                (Availability::Stale, Freshness::Stale)
            } else {
                (Availability::Unknown, Freshness::Unknown)
            }
        } else if expired {
            (Availability::Stale, Freshness::Stale)
        } else {
            (
                match entry.availability {
                    StoredAvailability::Available => Availability::Available,
                    StoredAvailability::Exhausted => Availability::Exhausted,
                    StoredAvailability::Unknown => Availability::Unknown,
                    StoredAvailability::Unsupported => Availability::Unsupported,
                },
                Freshness::Fresh,
            )
        };
        Some(UsageView {
            availability,
            freshness,
            observed_at: entry.observed_at,
            source: entry.source,
            codex_version: entry.codex_version.clone(),
            adapter_version: entry.adapter_version.clone(),
            compatibility: entry.compatibility,
            usage: entry.usage.clone(),
            next_refresh_at: entry.next_refresh_at,
        })
    }

    fn due_idle_refresh(
        &self,
        registered_profile_ids: &[String],
        active_profile_ids: &BTreeSet<String>,
        now: i64,
        policy: ObservationPolicy,
    ) -> Result<Vec<String>, ObservationError> {
        policy.validate()?;
        let mut due = registered_profile_ids
            .iter()
            .filter(|profile_id| !active_profile_ids.contains(*profile_id))
            .filter_map(|profile_id| {
                let refresh_at = self.entry(profile_id).map_or(i64::MIN, |entry| {
                    if entry.revalidation_required_at.is_some() {
                        now
                    } else {
                        entry.next_refresh_at
                    }
                });
                (refresh_at <= now).then(|| (refresh_at, profile_id.clone()))
            })
            .collect::<Vec<_>>();
        due.sort();
        due.truncate(policy.max_idle_refresh);
        Ok(due.into_iter().map(|(_, profile_id)| profile_id).collect())
    }

    fn validate(&self) -> Result<(), ObservationError> {
        if self.schema_version != CACHE_SCHEMA_VERSION {
            return Err(ObservationError::InvalidDocument);
        }
        if self.entries.len() > MAX_ENTRIES || self.audit.len() > MAX_AUDIT_EVENTS {
            return Err(ObservationError::LimitExceeded);
        }
        let mut profile_ids = BTreeSet::new();
        for entry in &self.entries {
            validate_profile_id(&entry.profile_id)?;
            if !profile_ids.insert(&entry.profile_id) {
                return Err(ObservationError::InvalidDocument);
            }
            validate_timestamp(entry.observed_at)?;
            validate_timestamp(entry.latest_event_at)?;
            if entry.latest_event_at < entry.observed_at {
                return Err(ObservationError::InvalidDocument);
            }
            validate_timestamp(entry.next_refresh_at)?;
            if entry.next_refresh_at < entry.latest_event_at {
                return Err(ObservationError::InvalidDocument);
            }
            if let Some(expires_at) = entry.expires_at {
                validate_timestamp(expires_at)?;
                if expires_at < entry.observed_at {
                    return Err(ObservationError::InvalidDocument);
                }
            }
            if let Some(required_at) = entry.revalidation_required_at {
                validate_timestamp(required_at)?;
                if required_at > entry.latest_event_at
                    || entry.source != ObservationSource::UsageLimitSignal
                    || entry.last_failure.is_some()
                    || entry.next_refresh_at != required_at
                {
                    return Err(ObservationError::InvalidDocument);
                }
            }
            if let Some(version) = &entry.codex_version {
                validate_version(version)?;
            }
            validate_version(&entry.adapter_version)?;
            if let Some(usage) = &entry.usage {
                validate_usage(usage)?;
                if entry.expires_at.is_none()
                    || entry.codex_version.is_none()
                    || entry.compatibility != CodexCompatibilityStatus::Compatible
                {
                    return Err(ObservationError::InvalidDocument);
                }
            } else if matches!(
                entry.availability,
                StoredAvailability::Available | StoredAvailability::Exhausted
            ) {
                return Err(ObservationError::InvalidDocument);
            }
            if entry.availability == StoredAvailability::Unsupported
                && (entry.last_failure != Some(StoredFailure::Unsupported) || entry.usage.is_some())
            {
                return Err(ObservationError::InvalidDocument);
            }
            if entry.availability == StoredAvailability::Exhausted
                && entry
                    .usage
                    .as_ref()
                    .is_none_or(|usage| classify(usage) != StoredAvailability::Exhausted)
            {
                return Err(ObservationError::InvalidDocument);
            }
        }
        let mut previous_revision = None;
        for audit in &self.audit {
            validate_profile_id(&audit.profile_id)?;
            validate_timestamp(audit.observed_at)?;
            if audit.revision == 0
                || audit.revision > self.revision
                || previous_revision.is_some_and(|previous| audit.revision <= previous)
            {
                return Err(ObservationError::InvalidDocument);
            }
            previous_revision = Some(audit.revision);
        }
        Ok(())
    }
}

fn classify(usage: &CodexUsage) -> StoredAvailability {
    let snapshots = usage
        .rate_limits
        .iter()
        .chain(usage.rate_limits_by_limit_id.values());
    let mut saw_window = false;
    let mut saw_rounded_full_window = false;
    for snapshot in snapshots {
        if let Some(reached_type) = snapshot.rate_limit_reached_type.as_deref() {
            return if is_explicit_exhaustion(reached_type) {
                StoredAvailability::Exhausted
            } else {
                StoredAvailability::Unknown
            };
        }
        if snapshot
            .individual_limit
            .as_ref()
            .is_some_and(|limit| limit.remaining_percent == 0)
        {
            return StoredAvailability::Unknown;
        }
        for window in [snapshot.primary.as_ref(), snapshot.secondary.as_ref()]
            .into_iter()
            .flatten()
        {
            saw_window = true;
            saw_rounded_full_window |= window.used_percent >= 100;
        }
    }
    if saw_window && !saw_rounded_full_window {
        StoredAvailability::Available
    } else {
        StoredAvailability::Unknown
    }
}

fn is_explicit_exhaustion(value: &str) -> bool {
    matches!(
        value,
        "rate_limit_reached"
            | "workspace_owner_credits_depleted"
            | "workspace_member_credits_depleted"
            | "workspace_owner_usage_limit_reached"
            | "workspace_member_usage_limit_reached"
    )
}

fn validate_usage(usage: &CodexUsage) -> Result<(), ObservationError> {
    if usage.rate_limits_by_limit_id.len() > MAX_RATE_LIMIT_BUCKETS {
        return Err(ObservationError::LimitExceeded);
    }
    if let Some(snapshot) = &usage.rate_limits {
        validate_snapshot(snapshot)?;
    }
    for (key, snapshot) in &usage.rate_limits_by_limit_id {
        validate_text(key, MAX_TEXT_BYTES)?;
        validate_snapshot(snapshot)?;
    }
    if let Some(reset_credits) = &usage.reset_credits {
        if let Some(details) = &reset_credits.details {
            if details.len() > MAX_RESET_CREDIT_DETAILS {
                return Err(ObservationError::LimitExceeded);
            }
            for detail in details {
                validate_timestamp(detail.granted_at)?;
                if let Some(expires_at) = detail.expires_at {
                    validate_timestamp(expires_at)?;
                    if expires_at < detail.granted_at {
                        return Err(ObservationError::InvalidDocument);
                    }
                }
                validate_text(&detail.reset_type, MAX_TEXT_BYTES)?;
                validate_text(&detail.status, MAX_TEXT_BYTES)?;
            }
        }
    }
    Ok(())
}

fn validate_snapshot(snapshot: &RateLimitSnapshot) -> Result<(), ObservationError> {
    for value in [
        snapshot.limit_id.as_deref(),
        snapshot.limit_name.as_deref(),
        snapshot.plan_type.as_deref(),
        snapshot.rate_limit_reached_type.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_text(value, MAX_TEXT_BYTES)?;
    }
    for window in [snapshot.primary.as_ref(), snapshot.secondary.as_ref()]
        .into_iter()
        .flatten()
    {
        // Codex may report a value above 100 after rounding or provider-side
        // accounting. It is retained for display and classifies unknown; only
        // the derived remaining percentage is structurally bounded.
        if window.remaining_percent > 100 {
            return Err(ObservationError::InvalidDocument);
        }
        if let Some(resets_at) = window.resets_at {
            validate_timestamp(resets_at)?;
        }
    }
    if let Some(credits) = &snapshot.credits {
        if let Some(balance) = &credits.balance {
            validate_text(balance, MAX_DECIMAL_BYTES)?;
        }
    }
    if let Some(limit) = &snapshot.individual_limit {
        validate_text(&limit.limit, MAX_DECIMAL_BYTES)?;
        validate_text(&limit.used, MAX_DECIMAL_BYTES)?;
        if limit.remaining_percent > 100 {
            return Err(ObservationError::InvalidDocument);
        }
        validate_timestamp(limit.resets_at)?;
    }
    Ok(())
}

fn validate_profile_id(profile_id: &str) -> Result<(), ObservationError> {
    let parsed = Uuid::parse_str(profile_id).map_err(|_| ObservationError::InvalidInput)?;
    if parsed.hyphenated().to_string() != profile_id {
        return Err(ObservationError::InvalidInput);
    }
    Ok(())
}

fn validate_timestamp(value: i64) -> Result<(), ObservationError> {
    if !(0..=MAX_PROVIDER_TIMESTAMP_SECONDS).contains(&value) {
        return Err(ObservationError::InvalidInput);
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), ObservationError> {
    validate_text(value, MAX_VERSION_BYTES)
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), ObservationError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| character.is_control())
    {
        return Err(ObservationError::InvalidInput);
    }
    Ok(())
}

fn storage_error(_error: crate::profiles::ProfileError) -> ObservationError {
    ObservationError::StorageUnavailable
}

#[cfg(unix)]
fn ensure_supported() -> Result<(), ObservationError> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_supported() -> Result<(), ObservationError> {
    Err(ObservationError::UnsupportedPlatform)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservationError {
    InvalidInput,
    InvalidDocument,
    LimitExceeded,
    StorageUnavailable,
    #[cfg_attr(unix, allow(dead_code, reason = "constructed only by non-Unix builds"))]
    UnsupportedPlatform,
}

impl fmt::Display for ObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid usage observation input",
            Self::InvalidDocument => "invalid usage observation cache",
            Self::LimitExceeded => "usage observation cache limit exceeded",
            Self::StorageUnavailable => "usage observation cache unavailable",
            Self::UnsupportedPlatform => "usage observation cache unsupported on this platform",
        })
    }
}

impl std::error::Error for ObservationError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::providers::codex::{
        CreditsSnapshot, RateLimitWindow, ResetCreditDetail, ResetCredits,
        SpendControlLimitSnapshot,
    };

    fn profile_id(value: u128) -> String {
        Uuid::from_u128(value).hyphenated().to_string()
    }

    fn policy() -> ObservationPolicy {
        ObservationPolicy::for_test(10, 2, 8, 2)
    }

    fn snapshot(used_percent: u32, reached: Option<&str>) -> RateLimitSnapshot {
        RateLimitSnapshot {
            limit_id: Some("codex".to_owned()),
            limit_name: Some("Codex".to_owned()),
            plan_type: Some("team".to_owned()),
            rate_limit_reached_type: reached.map(str::to_owned),
            primary: Some(RateLimitWindow {
                used_percent,
                remaining_percent: 100_u32.saturating_sub(used_percent),
                window_duration_mins: Some(300),
                resets_at: Some(1_800_000_000),
            }),
            secondary: None,
            credits: Some(CreditsSnapshot {
                has_credits: true,
                unlimited: false,
                balance: Some("12.50".to_owned()),
            }),
            individual_limit: Some(SpendControlLimitSnapshot {
                limit: "100".to_owned(),
                used: "20".to_owned(),
                remaining_percent: 80,
                resets_at: 1_900_000_000,
            }),
        }
    }

    fn usage(used_percent: u32, reached: Option<&str>) -> CodexUsage {
        let snapshot = snapshot(used_percent, reached);
        CodexUsage {
            rate_limits: Some(snapshot.clone()),
            rate_limits_by_limit_id: BTreeMap::from([("codex".to_owned(), snapshot)]),
            reset_credits: Some(ResetCredits {
                available_count: 1,
                details: Some(vec![ResetCreditDetail {
                    granted_at: 1_700_000_000,
                    expires_at: Some(1_900_000_000),
                    reset_type: "weekly".to_owned(),
                    status: "available".to_owned(),
                }]),
            }),
        }
    }

    #[test]
    fn authoritative_classification_never_guesses_from_rounded_or_missing_data() {
        assert_eq!(classify(&usage(20, None)), StoredAvailability::Available);
        assert_eq!(classify(&usage(100, None)), StoredAvailability::Unknown);
        assert_eq!(classify(&usage(125, None)), StoredAvailability::Unknown);
        assert_eq!(
            classify(&usage(100, Some("rate_limit_reached"))),
            StoredAvailability::Exhausted
        );
        assert_eq!(
            classify(&usage(20, Some("future_state"))),
            StoredAvailability::Unknown
        );
        let empty = CodexUsage {
            rate_limits: None,
            rate_limits_by_limit_id: BTreeMap::new(),
            reset_credits: None,
        };
        assert_eq!(classify(&empty), StoredAvailability::Unknown);
    }

    #[test]
    fn fake_clock_drives_expiry_revalidation_and_out_of_order_merge() -> Result<(), ObservationError>
    {
        let profile = profile_id(1);
        let mut document = CacheDocument::default();
        document.observe_usage(
            &profile,
            ObservationSource::ActiveMonitor,
            "0.144.4",
            usage(20, None),
            100,
            policy(),
        )?;
        assert_eq!(
            document.view(&profile, 109).map(|view| view.availability),
            Some(Availability::Available)
        );
        assert_eq!(
            document.view(&profile, 110).map(|view| view.availability),
            Some(Availability::Stale)
        );

        document.require_revalidation(&profile, 111, policy())?;
        let signaled = document
            .view(&profile, 111)
            .ok_or(ObservationError::InvalidDocument)?;
        assert_eq!(signaled.availability, Availability::Unknown);
        assert_eq!(signaled.freshness, Freshness::RevalidationRequired);

        document.observe_usage(
            &profile,
            ObservationSource::IdleRead,
            "0.144.4",
            usage(100, Some("rate_limit_reached")),
            110,
            policy(),
        )?;
        assert_eq!(
            document.view(&profile, 111).map(|view| view.freshness),
            Some(Freshness::RevalidationRequired)
        );
        document.observe_usage(
            &profile,
            ObservationSource::ActiveMonitor,
            "0.144.4",
            usage(100, Some("rate_limit_reached")),
            111,
            policy(),
        )?;
        let revalidated = document
            .view(&profile, 111)
            .ok_or(ObservationError::InvalidDocument)?;
        assert_eq!(revalidated.availability, Availability::Exhausted);
        assert_eq!(revalidated.freshness, Freshness::Fresh);
        Ok(())
    }

    #[test]
    fn failures_back_off_with_a_bound_and_never_claim_exhaustion() -> Result<(), ObservationError> {
        let profile = profile_id(2);
        let mut document = CacheDocument::default();
        for (observed_at, expected_retry) in [(100, 102), (102, 106), (106, 114), (114, 122)] {
            document.observe_failure(
                &profile,
                ObservationSource::IdleRead,
                None,
                CodexCompatibilityStatus::Unverified,
                CodexUsageError::Timeout,
                observed_at,
                policy(),
            )?;
            let view = document
                .view(&profile, observed_at)
                .ok_or(ObservationError::InvalidDocument)?;
            assert_eq!(view.availability, Availability::Unknown);
            assert_eq!(view.next_refresh_at, expected_retry);
        }
        document.observe_failure(
            &profile,
            ObservationSource::IdleRead,
            Some("0.999.0"),
            CodexCompatibilityStatus::Incompatible,
            CodexUsageError::Unsupported,
            123,
            policy(),
        )?;
        assert_eq!(
            document.view(&profile, 123).map(|view| view.availability),
            Some(Availability::Unsupported)
        );
        Ok(())
    }

    #[test]
    fn refresh_failure_keeps_only_stale_safe_evidence_and_orders_later_events()
    -> Result<(), ObservationError> {
        let profile = profile_id(3);
        let mut document = CacheDocument::default();
        document.observe_usage(
            &profile,
            ObservationSource::ActiveMonitor,
            "0.144.4",
            usage(20, None),
            100,
            policy(),
        )?;
        document.observe_failure(
            &profile,
            ObservationSource::IdleRead,
            None,
            CodexCompatibilityStatus::Unverified,
            CodexUsageError::Timeout,
            105,
            policy(),
        )?;
        let stale = document
            .view(&profile, 105)
            .ok_or(ObservationError::InvalidDocument)?;
        assert_eq!(stale.availability, Availability::Stale);
        assert_eq!(stale.freshness, Freshness::Stale);
        assert_eq!(stale.observed_at, 100);
        assert_eq!(stale.codex_version.as_deref(), Some("0.144.4"));
        assert!(stale.usage.is_some());

        document.observe_usage(
            &profile,
            ObservationSource::IdleRead,
            "0.144.4",
            usage(100, Some("rate_limit_reached")),
            104,
            policy(),
        )?;
        assert_eq!(
            document.view(&profile, 105).map(|view| view.availability),
            Some(Availability::Stale)
        );
        Ok(())
    }

    #[test]
    fn idle_refresh_is_bounded_stable_and_excludes_active_profiles() -> Result<(), ObservationError>
    {
        let first = profile_id(10);
        let second = profile_id(11);
        let third = profile_id(12);
        let active = profile_id(13);
        let registered = vec![third.clone(), active.clone(), second.clone(), first.clone()];
        let active_profiles = BTreeSet::from([active]);
        let document = CacheDocument::default();
        assert_eq!(
            document.due_idle_refresh(&registered, &active_profiles, 100, policy())?,
            vec![first, second]
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn durable_cache_round_trip_preserves_safe_fields_and_no_sensitive_shapes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fs::canonicalize(std::env::temp_dir())?.join(format!(
            "calcifer-usage-cache-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        {
            use std::os::unix::fs::DirBuilderExt;

            fs::DirBuilder::new().mode(0o700).create(&root)?;
        }
        let store = ObservationStore::at(root.clone(), policy());
        let profile = profile_id(20);
        let accepted = store.observe_usage(
            &profile,
            ObservationSource::ActiveMonitor,
            "0.144.4",
            usage(20, None),
            100,
        )?;
        assert_eq!(accepted.availability, Availability::Available);
        let bytes = fs::read(root.join(CACHE_FILE))?;
        let serialized = String::from_utf8(bytes)?;
        for forbidden in [
            "access_token",
            "refresh_token",
            "account_id",
            "workspace_id",
            "thread_id",
            "turn_id",
            "transcript",
            "prompt",
        ] {
            assert!(!serialized.contains(forbidden), "leaked shape: {forbidden}");
        }
        let loaded = store
            .view(&profile, 105)?
            .ok_or(ObservationError::InvalidDocument)?;
        assert_eq!(loaded, accepted);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
