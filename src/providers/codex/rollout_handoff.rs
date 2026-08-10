//! Validated, profile-owned rollout authority for cross-profile handoff.
//!
//! This module deliberately has no constructor that accepts a path. A source
//! capability can be minted only from a current managed profile and the
//! provider adapter's already validated thread projection. The absolute path
//! stays sealed until the capability enters its one-shot import phase.

#![allow(dead_code)] // This sealed module is first consumed by issue #34.

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    CodexThreadRead, MAX_JSONL_LINE_BYTES, MAX_ROLLOUT_BYTES, read_bounded_line,
    validate_session_meta_value,
};
use crate::conversations::{
    GenerationRollout, HandoffTarget, RolloutFingerprint, RolloutLocator, RolloutRoot,
};
use crate::profiles::{Profile, Provider, Registry};

const ACTIVE_ROLLOUT_ROOT: &str = "sessions";
const MAX_LOCATOR_COMPONENTS: usize = 128;
const MAX_LOCATOR_BYTES: usize = 16 * 1024;
const MAX_FORK_CLOCK_SKEW_SECONDS: i64 = 5;

/// A redacted failure at the rollout capability boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexRolloutHandoffError {
    Profile,
    Thread,
    Archived,
    Missing,
    UnsafeSource,
    SourceChanged,
    ForkResponse,
    UnsafeTarget,
}

impl fmt::Display for CodexRolloutHandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Profile => "the Codex handoff profile is no longer current",
            Self::Thread => "the Codex handoff thread lineage is invalid",
            Self::Archived => "an archived Codex rollout cannot be handed off",
            Self::Missing => "the Codex handoff rollout is missing",
            Self::UnsafeSource => "the Codex source rollout is not safe to import",
            Self::SourceChanged => "the Codex source rollout changed during handoff",
            Self::ForkResponse => "Codex returned an invalid handoff fork response",
            Self::UnsafeTarget => "the Codex target rollout is not safe to adopt",
        })
    }
}

impl std::error::Error for CodexRolloutHandoffError {}

/// A sessions-root-relative locator safe for durable conversation metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexRolloutLocator {
    relative_path: PathBuf,
}

impl CodexRolloutLocator {
    pub(crate) const fn root(&self) -> &'static str {
        ACTIVE_ROLLOUT_ROOT
    }

    pub(crate) fn relative_path(&self) -> &Path {
        &self.relative_path
    }
}

/// A bounded identity and content fingerprint for one immutable rollout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexHandoffFingerprint {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) length: u64,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) links: u64,
    pub(crate) modified_seconds: i64,
    pub(crate) modified_nanoseconds: i64,
    pub(crate) changed_seconds: i64,
    pub(crate) changed_nanoseconds: i64,
    digest: [u8; 32],
}

impl CodexHandoffFingerprint {
    pub(crate) fn sha256(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in self.digest {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    fn same_file(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

struct DirectoryBinding {
    path: PathBuf,
    descriptor: File,
    identity: DirectoryIdentity,
    private_root: bool,
}

/// Linear authority to present one exact managed rollout to `thread/fork`.
#[must_use = "the validated rollout capability must be consumed or explicitly dropped"]
pub(crate) struct CodexRolloutHandoff {
    profile_id: String,
    thread_id: String,
    codex_version: String,
    canonical_cwd: PathBuf,
    locator: CodexRolloutLocator,
    fingerprint: CodexHandoffFingerprint,
    home: DirectoryBinding,
    sessions: DirectoryBinding,
    source: File,
    source_path: PathBuf,
}

impl CodexRolloutHandoff {
    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub(crate) fn thread_id(&self) -> &str {
        &self.thread_id
    }

    pub(crate) fn codex_version(&self) -> &str {
        &self.codex_version
    }

    pub(crate) fn canonical_cwd(&self) -> &Path {
        &self.canonical_cwd
    }

    pub(crate) fn locator(&self) -> &CodexRolloutLocator {
        &self.locator
    }

    pub(crate) fn fingerprint(&self) -> &CodexHandoffFingerprint {
        &self.fingerprint
    }

    /// Projects the sealed source into the bounded provider-free journal
    /// shape without exposing its absolute path.
    pub(crate) fn journal_rollout(&self) -> Result<GenerationRollout, CodexRolloutHandoffError> {
        project_journal_rollout(&self.locator, &self.fingerprint)
    }

    /// Revalidates immediately before exposing the sealed path to provider I/O.
    pub(crate) fn begin_import(mut self) -> Result<CodexRolloutImport, CodexRolloutHandoffError> {
        self.revalidate_source(CodexRolloutHandoffError::UnsafeSource)?;
        Ok(CodexRolloutImport { source: self })
    }

    fn revalidate_source(
        &mut self,
        mismatch: CodexRolloutHandoffError,
    ) -> Result<(), CodexRolloutHandoffError> {
        if fs::canonicalize(&self.canonical_cwd).map_err(|_| mismatch)? != self.canonical_cwd {
            return Err(mismatch);
        }
        self.home.revalidate(mismatch)?;
        self.sessions.revalidate(mismatch)?;

        let reopened_sessions = open_child_directory(
            &self.home.descriptor,
            OsStr::new(ACTIVE_ROLLOUT_ROOT),
            false,
            mismatch,
        )?;
        if directory_identity(&reopened_sessions, false, mismatch)? != self.sessions.identity {
            return Err(mismatch);
        }

        let mut visible = open_relative_rollout(
            &self.sessions.descriptor,
            self.locator.relative_path(),
            mismatch,
        )?;
        let retained = fingerprint_file(&mut self.source, mismatch)?;
        let visible_fingerprint = fingerprint_file(&mut visible, mismatch)?;
        if retained != self.fingerprint || visible_fingerprint != self.fingerprint {
            return Err(mismatch);
        }
        validate_visible_source_path(
            &self.home.path,
            &self.sessions.path,
            &self.source_path,
            &self.locator,
            &self.fingerprint,
            mismatch,
        )?;
        Ok(())
    }
}

/// The sole phase in which provider code may borrow the absolute source path.
#[must_use = "an in-flight rollout import must be finished and revalidated"]
pub(crate) struct CodexRolloutImport {
    source: CodexRolloutHandoff,
}

impl CodexRolloutImport {
    /// This accessor is crate-private but the type has no public constructor.
    /// Public CLI, configuration, and repository paths cannot reach it.
    pub(crate) fn source_path(&self) -> &Path {
        &self.source.source_path
    }

    /// Rehashes both the retained descriptor and the current managed path after
    /// the provider import has completed.
    pub(crate) fn finish(mut self) -> Result<VerifiedSourceRollout, CodexRolloutHandoffError> {
        self.source
            .revalidate_source(CodexRolloutHandoffError::SourceChanged)?;
        Ok(VerifiedSourceRollout {
            profile_id: self.source.profile_id,
            thread_id: self.source.thread_id,
            codex_version: self.source.codex_version,
            canonical_cwd: self.source.canonical_cwd,
            locator: self.source.locator,
            fingerprint: self.source.fingerprint,
        })
    }
}

/// Proof that the source remained byte- and identity-stable across import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedSourceRollout {
    profile_id: String,
    thread_id: String,
    codex_version: String,
    canonical_cwd: PathBuf,
    locator: CodexRolloutLocator,
    fingerprint: CodexHandoffFingerprint,
}

impl VerifiedSourceRollout {
    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub(crate) fn thread_id(&self) -> &str {
        &self.thread_id
    }

    pub(crate) fn canonical_cwd(&self) -> &Path {
        &self.canonical_cwd
    }

    pub(crate) fn locator(&self) -> &CodexRolloutLocator {
        &self.locator
    }

    pub(crate) fn fingerprint(&self) -> &CodexHandoffFingerprint {
        &self.fingerprint
    }

    pub(crate) fn journal_rollout(&self) -> Result<GenerationRollout, CodexRolloutHandoffError> {
        project_journal_rollout(&self.locator, &self.fingerprint)
    }
}

/// Strict handoff-only projection for a newly materialized target rollout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedForkRollout {
    profile_id: String,
    thread_id: String,
    canonical_cwd: PathBuf,
    locator: CodexRolloutLocator,
    fingerprint: CodexHandoffFingerprint,
}

impl ValidatedForkRollout {
    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub(crate) fn thread_id(&self) -> &str {
        &self.thread_id
    }

    pub(crate) fn canonical_cwd(&self) -> &Path {
        &self.canonical_cwd
    }

    pub(crate) fn locator(&self) -> &CodexRolloutLocator {
        &self.locator
    }

    pub(crate) fn fingerprint(&self) -> &CodexHandoffFingerprint {
        &self.fingerprint
    }

    /// Consumes a validated fork into the exact provider-free target that the
    /// journal may adopt. The source supplies the version invariant already
    /// checked in the provider response.
    pub(crate) fn into_handoff_target(
        self,
        source: &VerifiedSourceRollout,
    ) -> Result<HandoffTarget, CodexRolloutHandoffError> {
        if self.profile_id == source.profile_id
            || self.thread_id == source.thread_id
            || self.canonical_cwd != source.canonical_cwd
            || self.fingerprint.same_file(&source.fingerprint)
        {
            return Err(CodexRolloutHandoffError::UnsafeTarget);
        }
        Ok(HandoffTarget {
            thread_id: self.thread_id,
            canonical_cwd: self
                .canonical_cwd
                .to_str()
                .ok_or(CodexRolloutHandoffError::UnsafeTarget)?
                .to_owned(),
            codex_version: source.codex_version.clone(),
            rollout: project_journal_rollout(&self.locator, &self.fingerprint)?,
        })
    }
}

fn project_journal_rollout(
    locator: &CodexRolloutLocator,
    fingerprint: &CodexHandoffFingerprint,
) -> Result<GenerationRollout, CodexRolloutHandoffError> {
    let relative_path = locator
        .relative_path
        .to_str()
        .ok_or(CodexRolloutHandoffError::Thread)?
        .to_owned();
    Ok(GenerationRollout {
        locator: RolloutLocator {
            root: RolloutRoot::Sessions,
            relative_path,
        },
        fingerprint: RolloutFingerprint {
            device: fingerprint.device,
            inode: fingerprint.inode,
            length: fingerprint.length,
            mode: fingerprint.mode,
            owner: fingerprint.uid,
            link_count: fingerprint.links,
            modified_seconds: fingerprint.modified_seconds,
            modified_nanoseconds: fingerprint.modified_nanoseconds,
            changed_seconds: fingerprint.changed_seconds,
            changed_nanoseconds: fingerprint.changed_nanoseconds,
            sha256: fingerprint.sha256(),
        },
    })
}

/// Mints source authority from registered profile lineage, never from a path.
#[allow(dead_code)] // Consumed by the transactional handoff in issue #34.
pub(crate) fn mint_profile_rollout_handoff(
    registry: &Registry,
    profile: &Profile,
    thread: &CodexThreadRead,
) -> Result<CodexRolloutHandoff, CodexRolloutHandoffError> {
    if profile.provider != Provider::Codex {
        return Err(CodexRolloutHandoffError::Profile);
    }
    let current = registry
        .find_by_id(profile.provider, &profile.id)
        .map_err(|_| CodexRolloutHandoffError::Profile)?;
    if current != *profile {
        return Err(CodexRolloutHandoffError::Profile);
    }
    let home = registry
        .profile_home(&current)
        .map_err(|_| CodexRolloutHandoffError::Profile)?;
    mint_from_managed_lineage(&home, &current.id, thread)
}

fn mint_from_managed_lineage(
    managed_home: &Path,
    profile_id: &str,
    thread: &CodexThreadRead,
) -> Result<CodexRolloutHandoff, CodexRolloutHandoffError> {
    if thread.metadata.archived {
        return Err(CodexRolloutHandoffError::Archived);
    }
    if thread.codex_version != thread.metadata.cli_version {
        return Err(CodexRolloutHandoffError::Thread);
    }
    super::validate_canonical_uuid(&thread.metadata.thread_id)
        .map_err(|_| CodexRolloutHandoffError::Thread)?;
    let canonical_cwd = fs::canonicalize(&thread.metadata.canonical_cwd)
        .map_err(|_| CodexRolloutHandoffError::Thread)?;
    if canonical_cwd != thread.metadata.canonical_cwd {
        return Err(CodexRolloutHandoffError::Thread);
    }

    let canonical_home =
        fs::canonicalize(managed_home).map_err(|_| CodexRolloutHandoffError::Profile)?;
    if canonical_home != managed_home {
        return Err(CodexRolloutHandoffError::Profile);
    }
    let home = bind_absolute_directory(
        canonical_home.clone(),
        true,
        CodexRolloutHandoffError::Profile,
    )?;
    let sessions_path = canonical_home.join(ACTIVE_ROLLOUT_ROOT);
    let sessions_descriptor = open_child_directory(
        &home.descriptor,
        OsStr::new(ACTIVE_ROLLOUT_ROOT),
        false,
        CodexRolloutHandoffError::UnsafeSource,
    )?;
    let sessions = DirectoryBinding {
        identity: directory_identity(
            &sessions_descriptor,
            false,
            CodexRolloutHandoffError::UnsafeSource,
        )?,
        path: sessions_path.clone(),
        descriptor: sessions_descriptor,
        private_root: false,
    };

    let source_path = thread.metadata.rollout_path.clone();
    let canonical_source = fs::canonicalize(&source_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CodexRolloutHandoffError::Missing
        } else {
            CodexRolloutHandoffError::UnsafeSource
        }
    })?;
    if canonical_source != source_path {
        return Err(CodexRolloutHandoffError::UnsafeSource);
    }
    let relative = source_path
        .strip_prefix(&sessions_path)
        .map_err(|_| CodexRolloutHandoffError::UnsafeSource)?
        .to_path_buf();
    let locator = validate_locator(relative, CodexRolloutHandoffError::UnsafeSource)?;
    if locator.relative_path != thread.metadata.rollout_relative_path {
        return Err(CodexRolloutHandoffError::Thread);
    }
    let mut source = open_relative_rollout(
        &sessions.descriptor,
        locator.relative_path(),
        CodexRolloutHandoffError::UnsafeSource,
    )?;
    let fingerprint = fingerprint_file(&mut source, CodexRolloutHandoffError::UnsafeSource)?;
    if !same_legacy_fingerprint(&fingerprint, &thread.metadata.rollout_fingerprint) {
        return Err(CodexRolloutHandoffError::SourceChanged);
    }
    validate_source_session(
        &mut source,
        &thread.metadata,
        &canonical_cwd,
        CodexRolloutHandoffError::Thread,
    )?;
    validate_visible_source_path(
        &canonical_home,
        &sessions_path,
        &source_path,
        &locator,
        &fingerprint,
        CodexRolloutHandoffError::UnsafeSource,
    )?;

    Ok(CodexRolloutHandoff {
        profile_id: profile_id.to_owned(),
        thread_id: thread.metadata.thread_id.clone(),
        codex_version: thread.codex_version.clone(),
        canonical_cwd,
        locator,
        fingerprint,
        home,
        sessions,
        source,
        source_path,
    })
}

/// Validates a provider-returned fork without reusing or weakening the
/// same-profile root-thread projection.
#[allow(dead_code)] // Consumed by the transactional handoff in issue #34.
pub(crate) fn validate_handoff_fork_result(
    registry: &Registry,
    target_profile: &Profile,
    source: &VerifiedSourceRollout,
    result: &Value,
) -> Result<ValidatedForkRollout, CodexRolloutHandoffError> {
    if target_profile.provider != Provider::Codex || target_profile.id == source.profile_id {
        return Err(CodexRolloutHandoffError::Profile);
    }
    let current = registry
        .find_by_id(target_profile.provider, &target_profile.id)
        .map_err(|_| CodexRolloutHandoffError::Profile)?;
    if current != *target_profile {
        return Err(CodexRolloutHandoffError::Profile);
    }
    let home = registry
        .profile_home(&current)
        .map_err(|_| CodexRolloutHandoffError::Profile)?;

    let result = result
        .as_object()
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;
    let response_cwd = canonical_response_cwd(result.get("cwd"))?;
    if response_cwd != source.canonical_cwd {
        return Err(CodexRolloutHandoffError::ForkResponse);
    }
    let thread = result
        .get("thread")
        .and_then(Value::as_object)
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;
    let target_thread_id = thread
        .get("id")
        .and_then(Value::as_str)
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;
    super::validate_canonical_uuid(target_thread_id)
        .map_err(|_| CodexRolloutHandoffError::ForkResponse)?;
    if target_thread_id == source.thread_id
        || thread.get("forkedFromId").and_then(Value::as_str) != Some(source.thread_id.as_str())
        || thread.get("cliVersion").and_then(Value::as_str) != Some(source.codex_version.as_str())
        || canonical_response_cwd(thread.get("cwd"))? != source.canonical_cwd
    {
        return Err(CodexRolloutHandoffError::ForkResponse);
    }
    let target_path = thread
        .get("path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;
    let (locator, fingerprint) = validate_target_rollout(
        &home,
        &target_path,
        target_thread_id,
        &source.thread_id,
        &response_cwd,
        &source.codex_version,
    )?;
    if fingerprint.same_file(&source.fingerprint) {
        return Err(CodexRolloutHandoffError::UnsafeTarget);
    }
    Ok(ValidatedForkRollout {
        profile_id: current.id,
        thread_id: target_thread_id.to_owned(),
        canonical_cwd: response_cwd,
        locator,
        fingerprint,
    })
}

/// Validates one post-crash `thread/list` entry against the durable fork
/// window and the same source/target lineage rules as the direct response.
/// Baseline filtering happens before this call; any returned value is safe to
/// project as a matching reconciliation candidate.
pub(crate) fn validate_handoff_inventory_candidate(
    registry: &Registry,
    target_profile: &Profile,
    source: &VerifiedSourceRollout,
    candidate: &Value,
    fork_requested_at: i64,
    observed_at: i64,
) -> Result<ValidatedForkRollout, CodexRolloutHandoffError> {
    if fork_requested_at < 0 || observed_at < fork_requested_at {
        return Err(CodexRolloutHandoffError::ForkResponse);
    }
    let earliest = fork_requested_at
        .checked_sub(MAX_FORK_CLOCK_SKEW_SECONDS)
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;
    let latest = observed_at
        .checked_add(MAX_FORK_CLOCK_SKEW_SECONDS)
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;
    let candidate = candidate
        .as_object()
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;
    let target_thread_id = candidate
        .get("id")
        .and_then(Value::as_str)
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;
    super::validate_canonical_uuid(target_thread_id)
        .map_err(|_| CodexRolloutHandoffError::ForkResponse)?;
    let updated_at = candidate
        .get("updatedAt")
        .and_then(Value::as_i64)
        .filter(|timestamp| (*timestamp >= earliest) && (*timestamp <= latest))
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;
    let recency_at = match candidate.get("recencyAt") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_i64()
                .filter(|timestamp| (*timestamp >= earliest) && (*timestamp <= latest))
                .ok_or(CodexRolloutHandoffError::ForkResponse)?,
        ),
    };
    let _ = (updated_at, recency_at);
    if target_thread_id == source.thread_id
        || candidate.get("parentThreadId").and_then(Value::as_str)
            != Some(source.thread_id.as_str())
        || candidate.get("ephemeral").and_then(Value::as_bool) != Some(false)
        || candidate.get("cliVersion").and_then(Value::as_str)
            != Some(source.codex_version.as_str())
        || candidate.get("source").and_then(Value::as_str) != Some("cli")
    {
        return Err(CodexRolloutHandoffError::ForkResponse);
    }
    let response_cwd = canonical_response_cwd(candidate.get("cwd"))?;
    if response_cwd != source.canonical_cwd {
        return Err(CodexRolloutHandoffError::ForkResponse);
    }
    let target_path = candidate
        .get("path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;

    if target_profile.provider != Provider::Codex || target_profile.id == source.profile_id {
        return Err(CodexRolloutHandoffError::Profile);
    }
    let current = registry
        .find_by_id(target_profile.provider, &target_profile.id)
        .map_err(|_| CodexRolloutHandoffError::Profile)?;
    if current != *target_profile {
        return Err(CodexRolloutHandoffError::Profile);
    }
    let home = registry
        .profile_home(&current)
        .map_err(|_| CodexRolloutHandoffError::Profile)?;
    let (locator, fingerprint) = validate_target_rollout(
        &home,
        &target_path,
        target_thread_id,
        &source.thread_id,
        &response_cwd,
        &source.codex_version,
    )?;
    if fingerprint.same_file(&source.fingerprint) {
        return Err(CodexRolloutHandoffError::UnsafeTarget);
    }
    Ok(ValidatedForkRollout {
        profile_id: current.id,
        thread_id: target_thread_id.to_owned(),
        canonical_cwd: response_cwd,
        locator,
        fingerprint,
    })
}

fn validate_target_rollout(
    managed_home: &Path,
    path: &Path,
    target_thread_id: &str,
    source_thread_id: &str,
    expected_cwd: &Path,
    expected_version: &str,
) -> Result<(CodexRolloutLocator, CodexHandoffFingerprint), CodexRolloutHandoffError> {
    let canonical_home =
        fs::canonicalize(managed_home).map_err(|_| CodexRolloutHandoffError::UnsafeTarget)?;
    if canonical_home != managed_home {
        return Err(CodexRolloutHandoffError::UnsafeTarget);
    }
    let home = bind_absolute_directory(
        canonical_home.clone(),
        true,
        CodexRolloutHandoffError::UnsafeTarget,
    )?;
    let sessions_path = canonical_home.join(ACTIVE_ROLLOUT_ROOT);
    let sessions = open_child_directory(
        &home.descriptor,
        OsStr::new(ACTIVE_ROLLOUT_ROOT),
        false,
        CodexRolloutHandoffError::UnsafeTarget,
    )?;
    let canonical_path =
        fs::canonicalize(path).map_err(|_| CodexRolloutHandoffError::UnsafeTarget)?;
    if canonical_path != path {
        return Err(CodexRolloutHandoffError::UnsafeTarget);
    }
    let relative = path
        .strip_prefix(&sessions_path)
        .map_err(|_| CodexRolloutHandoffError::UnsafeTarget)?
        .to_path_buf();
    let locator = validate_locator(relative, CodexRolloutHandoffError::UnsafeTarget)?;
    let mut file = open_relative_rollout(
        &sessions,
        locator.relative_path(),
        CodexRolloutHandoffError::UnsafeTarget,
    )?;
    validate_target_session(
        &mut file,
        target_thread_id,
        source_thread_id,
        expected_cwd,
        expected_version,
    )?;
    let fingerprint = fingerprint_file(&mut file, CodexRolloutHandoffError::UnsafeTarget)?;
    let mut reopened = open_relative_rollout(
        &sessions,
        locator.relative_path(),
        CodexRolloutHandoffError::UnsafeTarget,
    )?;
    if fingerprint_file(&mut reopened, CodexRolloutHandoffError::UnsafeTarget)? != fingerprint {
        return Err(CodexRolloutHandoffError::UnsafeTarget);
    }
    Ok((locator, fingerprint))
}

fn validate_target_session(
    file: &mut File,
    target_thread_id: &str,
    source_thread_id: &str,
    expected_cwd: &Path,
    expected_version: &str,
) -> Result<(), CodexRolloutHandoffError> {
    let error = CodexRolloutHandoffError::UnsafeTarget;
    file.seek(SeekFrom::Start(0)).map_err(|_| error)?;
    let mut reader = BufReader::new(file);
    let first = read_bounded_line(&mut reader)
        .map_err(|_| error)?
        .ok_or(error)?;
    if first.len() > MAX_JSONL_LINE_BYTES {
        return Err(error);
    }
    let value = super::json::decode_unique_json(first.as_bytes()).map_err(|_| error)?;
    let object = value.as_object().ok_or(error)?;
    if object.get("type").and_then(Value::as_str) != Some("session_meta") {
        return Err(error);
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(error)?;
    let rollout_cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or(error)?;
    let canonical_cwd = fs::canonicalize(&rollout_cwd).map_err(|_| error)?;
    if payload.get("id").and_then(Value::as_str) != Some(target_thread_id)
        || payload.get("session_id").and_then(Value::as_str) != Some(target_thread_id)
        || payload.get("parent_thread_id").and_then(Value::as_str) != Some(source_thread_id)
        || payload.get("cli_version").and_then(Value::as_str) != Some(expected_version)
        || payload.get("source").and_then(Value::as_str) != Some("cli")
        || canonical_cwd != expected_cwd
        || canonical_cwd != rollout_cwd
    {
        return Err(error);
    }
    Ok(())
}

fn canonical_response_cwd(value: Option<&Value>) -> Result<PathBuf, CodexRolloutHandoffError> {
    let path = value
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(CodexRolloutHandoffError::ForkResponse)?;
    let canonical = fs::canonicalize(&path).map_err(|_| CodexRolloutHandoffError::ForkResponse)?;
    if canonical != path {
        return Err(CodexRolloutHandoffError::ForkResponse);
    }
    Ok(canonical)
}

fn bind_absolute_directory(
    path: PathBuf,
    private_root: bool,
    error: CodexRolloutHandoffError,
) -> Result<DirectoryBinding, CodexRolloutHandoffError> {
    let visible = fs::symlink_metadata(&path).map_err(|_| error)?;
    let descriptor = File::from(
        rustix::fs::open(
            &path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| error)?,
    );
    let identity = directory_identity(&descriptor, private_root, error)?;
    if visible.dev() != identity.device || visible.ino() != identity.inode {
        return Err(error);
    }
    Ok(DirectoryBinding {
        path,
        descriptor,
        identity,
        private_root,
    })
}

impl DirectoryBinding {
    fn revalidate(&self, error: CodexRolloutHandoffError) -> Result<(), CodexRolloutHandoffError> {
        let visible = fs::symlink_metadata(&self.path).map_err(|_| error)?;
        if visible.file_type().is_symlink()
            || visible.dev() != self.identity.device
            || visible.ino() != self.identity.inode
            || directory_identity(&self.descriptor, self.private_root, error)? != self.identity
        {
            return Err(error);
        }
        let reopened = File::from(
            rustix::fs::open(
                &self.path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| error)?,
        );
        if directory_identity(&reopened, self.private_root, error)? != self.identity {
            return Err(error);
        }
        Ok(())
    }
}

fn open_child_directory(
    parent: &File,
    name: &OsStr,
    private_root: bool,
    error: CodexRolloutHandoffError,
) -> Result<File, CodexRolloutHandoffError> {
    let directory = File::from(
        rustix::fs::openat(
            parent.as_fd(),
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| error)?,
    );
    directory_identity(&directory, private_root, error)?;
    Ok(directory)
}

fn directory_identity(
    directory: &File,
    private_root: bool,
    error: CodexRolloutHandoffError,
) -> Result<DirectoryIdentity, CodexRolloutHandoffError> {
    let metadata = directory.metadata().map_err(|_| error)?;
    let unsafe_mode = if private_root {
        metadata.mode() & 0o077 != 0
    } else {
        metadata.mode() & 0o022 != 0
    };
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || unsafe_mode
        || metadata.nlink() < 1
    {
        return Err(error);
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
    })
}

fn validate_locator(
    relative_path: PathBuf,
    error: CodexRolloutHandoffError,
) -> Result<CodexRolloutLocator, CodexRolloutHandoffError> {
    if relative_path.as_os_str().len() > MAX_LOCATOR_BYTES
        || relative_path.extension().and_then(OsStr::to_str) != Some("jsonl")
    {
        return Err(error);
    }
    let mut count = 0_usize;
    for component in relative_path.components() {
        match component {
            Component::Normal(name) if !name.is_empty() => {
                count = count.checked_add(1).ok_or(error)?;
                if count > MAX_LOCATOR_COMPONENTS {
                    return Err(error);
                }
            }
            _ => return Err(error),
        }
    }
    if count == 0 {
        return Err(error);
    }
    Ok(CodexRolloutLocator { relative_path })
}

fn open_relative_rollout(
    root: &File,
    relative: &Path,
    error: CodexRolloutHandoffError,
) -> Result<File, CodexRolloutHandoffError> {
    let components: Vec<_> = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) if !name.is_empty() => Ok(name.to_owned()),
            _ => Err(error),
        })
        .collect::<Result<_, _>>()?;
    let (file_name, directories) = components.split_last().ok_or(error)?;
    let mut current = root.try_clone().map_err(|_| error)?;
    for directory in directories {
        current = open_child_directory(&current, directory, false, error)?;
    }
    let file = File::from(
        rustix::fs::openat(
            current.as_fd(),
            file_name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| error)?,
    );
    validate_file_metadata(&file.metadata().map_err(|_| error)?, error)?;
    Ok(file)
}

fn validate_file_metadata(
    metadata: &fs::Metadata,
    error: CodexRolloutHandoffError,
) -> Result<(), CodexRolloutHandoffError> {
    validate_file_metadata_for_uid(metadata, rustix::process::geteuid().as_raw(), error)
}

fn validate_file_metadata_for_uid(
    metadata: &fs::Metadata,
    expected_uid: u32,
    error: CodexRolloutHandoffError,
) -> Result<(), CodexRolloutHandoffError> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_ROLLOUT_BYTES as u64
    {
        return Err(error);
    }
    Ok(())
}

fn fingerprint_file(
    file: &mut File,
    error: CodexRolloutHandoffError,
) -> Result<CodexHandoffFingerprint, CodexRolloutHandoffError> {
    let before = file.metadata().map_err(|_| error)?;
    validate_file_metadata(&before, error)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| error)?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| error)?;
        if count == 0 {
            break;
        }
        length = length.checked_add(count as u64).ok_or(error)?;
        if length > MAX_ROLLOUT_BYTES as u64 || length > before.len() {
            return Err(error);
        }
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(|_| error)?;
    validate_file_metadata(&after, error)?;
    let before_identity = file_metadata_identity(&before);
    let after_identity = file_metadata_identity(&after);
    if before_identity != after_identity || length != before.len() {
        return Err(error);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| error)?;
    Ok(CodexHandoffFingerprint {
        device: before.dev(),
        inode: before.ino(),
        length,
        mode: before.mode(),
        uid: before.uid(),
        gid: before.gid(),
        links: before.nlink(),
        modified_seconds: before.mtime(),
        modified_nanoseconds: before.mtime_nsec(),
        changed_seconds: before.ctime(),
        changed_nanoseconds: before.ctime_nsec(),
        digest: hasher.finalize().into(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileMetadataIdentity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn file_metadata_identity(metadata: &fs::Metadata) -> FileMetadataIdentity {
    FileMetadataIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn same_legacy_fingerprint(
    current: &CodexHandoffFingerprint,
    legacy: &super::CodexRolloutFingerprint,
) -> bool {
    current.device == legacy.device
        && current.inode == legacy.inode
        && current.length == legacy.length
        && current.modified_seconds == legacy.modified_seconds
        && current.modified_nanoseconds == legacy.modified_nanoseconds
        && current.changed_seconds == legacy.changed_seconds
        && current.changed_nanoseconds == legacy.changed_nanoseconds
}

fn validate_source_session(
    file: &mut File,
    metadata: &super::CodexThreadMetadata,
    expected_cwd: &Path,
    error: CodexRolloutHandoffError,
) -> Result<(), CodexRolloutHandoffError> {
    file.seek(SeekFrom::Start(0)).map_err(|_| error)?;
    let mut reader = BufReader::new(file);
    let first = read_bounded_line(&mut reader)
        .map_err(|_| error)?
        .ok_or(error)?;
    if first.len() > MAX_JSONL_LINE_BYTES {
        return Err(error);
    }
    let value = super::json::decode_unique_json(first.as_bytes()).map_err(|_| error)?;
    validate_session_meta_value(&value, metadata, expected_cwd).map_err(|_| error)?;
    let payload = value
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(error)?;
    if payload
        .get("session_id")
        .is_some_and(|value| value.as_str() != Some(metadata.thread_id.as_str()))
    {
        return Err(error);
    }
    Ok(())
}

fn validate_visible_source_path(
    home: &Path,
    sessions: &Path,
    source_path: &Path,
    locator: &CodexRolloutLocator,
    expected: &CodexHandoffFingerprint,
    error: CodexRolloutHandoffError,
) -> Result<(), CodexRolloutHandoffError> {
    if sessions != home.join(ACTIVE_ROLLOUT_ROOT)
        || source_path != sessions.join(locator.relative_path())
        || fs::canonicalize(source_path).map_err(|_| error)? != source_path
    {
        return Err(error);
    }
    let metadata = fs::symlink_metadata(source_path).map_err(|_| error)?;
    validate_file_metadata(&metadata, error)?;
    if metadata.dev() != expected.device || metadata.ino() != expected.inode {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{self, Write};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;

    use serde_json::json;

    use super::*;
    use crate::conversations::{
        BindingInput, ConversationLifecycle, ConversationRegistry, HandoffReason,
    };
    use crate::providers::codex::{
        CodexIdentityAdapter, CodexThreadLifecycle, WireThread, validate_thread_projection,
    };
    use crate::routing::{DefinitionMutation, Definitions};

    struct TestFixture {
        root: PathBuf,
        registry: Registry,
        source_profile: Profile,
        target_profile: Profile,
        workspace: PathBuf,
        source_rollout: PathBuf,
        source_read: CodexThreadRead,
    }

    impl TestFixture {
        fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let root = std::env::temp_dir().join(format!(
                "calcifer-rollout-handoff-{label}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::DirBuilder::new().mode(0o700).create(&root)?;
            let root = fs::canonicalize(root)?;
            let registry = Registry::at(root.join("registry"));
            let source_profile = register_profile(&registry, "source")?;
            let target_profile = register_profile(&registry, "target")?;
            let workspace = root.join("workspace");
            fs::DirBuilder::new().mode(0o700).create(&workspace)?;
            let source_home = registry.profile_home(&source_profile)?;
            let thread_id = uuid::Uuid::new_v4().to_string();
            let source_rollout =
                write_rollout(&source_home, &workspace, &thread_id, &thread_id, None)?;
            let source_read =
                read_projection(&source_home, &workspace, &thread_id, &source_rollout, false)?;
            Ok(Self {
                root,
                registry,
                source_profile,
                target_profile,
                workspace,
                source_rollout,
                source_read,
            })
        }

        fn source_home(&self) -> Result<PathBuf, crate::profiles::ProfileError> {
            self.registry.profile_home(&self.source_profile)
        }

        fn target_home(&self) -> Result<PathBuf, crate::profiles::ProfileError> {
            self.registry.profile_home(&self.target_profile)
        }

        fn mint(&self) -> Result<CodexRolloutHandoff, CodexRolloutHandoffError> {
            mint_profile_rollout_handoff(&self.registry, &self.source_profile, &self.source_read)
        }

        fn verified_source(&self) -> Result<VerifiedSourceRollout, CodexRolloutHandoffError> {
            self.mint()?.begin_import()?.finish()
        }
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn register_profile(
        registry: &Registry,
        alias: &str,
    ) -> Result<Profile, Box<dyn std::error::Error>> {
        let pending = registry.begin_codex_registration(alias)?;
        let auth = json!({
            "auth_mode": "chatgpt",
            "tokens": { "account_id": uuid::Uuid::new_v4().to_string() }
        });
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(pending.home().join("auth.json"))?;
        serde_json::to_writer(&mut file, &auth)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(pending.commit(CodexIdentityAdapter::for_test())?)
    }

    fn write_rollout(
        home: &Path,
        workspace: &Path,
        thread_id: &str,
        session_id: &str,
        parent_thread_id: Option<&str>,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let directory = home.join("sessions/2026/08/07");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)?;
        let path = directory.join(format!("rollout-{thread_id}.jsonl"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        for line in [
            json!({
                "timestamp": "2026-08-07T00:00:00Z",
                "type": "session_meta",
                "payload": {
                    "id": thread_id,
                    "session_id": session_id,
                    "cwd": workspace,
                    "cli_version": "0.144.4",
                    "source": "cli",
                    "parent_thread_id": parent_thread_id
                }
            }),
            json!({
                "timestamp": "2026-08-07T00:00:01Z",
                "type": "event_msg",
                "payload": { "type": "turn_aborted" }
            }),
        ] {
            serde_json::to_writer(&mut file, &line)?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
        Ok(path)
    }

    fn read_projection(
        home: &Path,
        workspace: &Path,
        thread_id: &str,
        rollout: &Path,
        archived: bool,
    ) -> Result<CodexThreadRead, Box<dyn std::error::Error>> {
        let wire: WireThread = serde_json::from_value(json!({
            "id": thread_id,
            "parentThreadId": null,
            "ephemeral": false,
            "updatedAt": 1_800_000_000,
            "recencyAt": 1_800_000_001,
            "cwd": workspace,
            "cliVersion": "0.144.4",
            "source": "cli",
            "path": rollout
        }))?;
        let metadata = validate_thread_projection(
            wire,
            &fs::canonicalize(workspace)?,
            home,
            "0.144.4",
            Some(archived),
        )
        .map_err(|error| io::Error::other(format!("projection failed: {error}")))?;
        Ok(CodexThreadRead {
            codex_version: "0.144.4".to_owned(),
            metadata,
            lifecycle: CodexThreadLifecycle::Interrupted,
        })
    }

    fn target_result(
        source: &VerifiedSourceRollout,
        target_thread_id: &str,
        target_rollout: &Path,
    ) -> Value {
        json!({
            "cwd": source.canonical_cwd(),
            "thread": {
                "id": target_thread_id,
                "forkedFromId": source.thread_id(),
                "cliVersion": "0.144.4",
                "cwd": source.canonical_cwd(),
                "path": target_rollout,
                "preview": "provider content is deliberately not projected",
                "turns": [{ "provider": "content is deliberately dropped" }]
            }
        })
    }

    fn inventory_candidate(
        source: &VerifiedSourceRollout,
        target_thread_id: &str,
        target_rollout: &Path,
        updated_at: i64,
    ) -> Value {
        json!({
            "id": target_thread_id,
            "parentThreadId": source.thread_id(),
            "ephemeral": false,
            "updatedAt": updated_at,
            "recencyAt": updated_at,
            "cwd": source.canonical_cwd(),
            "cliVersion": "0.144.4",
            "source": "cli",
            "path": target_rollout,
        })
    }

    fn write_target_rollout(
        fixture: &TestFixture,
        thread_id: &str,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        write_rollout(
            &fixture.target_home()?,
            &fixture.workspace,
            thread_id,
            thread_id,
            Some(fixture.source_read.metadata.thread_id.as_str()),
        )
    }

    #[test]
    fn capability_is_minted_only_from_current_profile_thread_lineage_and_is_linear()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new("valid-source")?;
        let capability = fixture.mint()?;

        assert_eq!(capability.profile_id(), fixture.source_profile.id);
        assert_eq!(
            capability.thread_id(),
            fixture.source_read.metadata.thread_id
        );
        assert_eq!(capability.canonical_cwd(), fixture.workspace);
        assert_eq!(capability.locator().root(), "sessions");
        assert!(!capability.locator().relative_path().is_absolute());
        assert_eq!(capability.fingerprint().sha256().len(), 64);
        let journal = capability.journal_rollout()?;
        assert_eq!(journal.locator.root, RolloutRoot::Sessions);
        assert!(!journal.locator.relative_path.starts_with('/'));
        assert_eq!(
            journal.fingerprint.sha256,
            capability.fingerprint().sha256()
        );

        let import = capability.begin_import()?;
        assert_eq!(import.source_path(), fixture.source_rollout);
        let verified = import.finish()?;
        assert_eq!(verified.profile_id(), fixture.source_profile.id);
        assert_eq!(verified.thread_id(), fixture.source_read.metadata.thread_id);
        assert_eq!(verified.canonical_cwd(), fixture.workspace);
        assert_eq!(verified.locator().root(), "sessions");
        assert_eq!(verified.fingerprint().sha256().len(), 64);
        assert_eq!(verified.journal_rollout()?, journal);
        Ok(())
    }

    #[test]
    fn concrete_handoff_preparation_binds_capability_policy_and_active_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new("transaction-preparation")?;
        let source = fixture.mint()?;
        let conversations = ConversationRegistry::from_profiles(&fixture.registry);
        let expected_source = conversations.adopt(BindingInput {
            profile_id: fixture.source_profile.id.clone(),
            thread_id: fixture.source_read.metadata.thread_id.clone(),
            canonical_cwd: fixture.workspace.to_string_lossy().into_owned(),
            codex_version: "0.144.4".to_owned(),
            lifecycle: ConversationLifecycle::Interrupted,
        })?;
        let trust_domain_id = uuid::Uuid::new_v4().to_string();
        let mut definitions = Definitions::default();
        definitions.apply(
            0,
            DefinitionMutation::CreateDomain {
                id: trust_domain_id.clone(),
                alias: "handoff-domain".to_owned(),
                provider: Provider::Codex,
                profile_ids: vec![
                    fixture.source_profile.id.clone(),
                    fixture.target_profile.id.clone(),
                ],
            },
        )?;

        let transition = crate::providers::codex::handoff_transaction::prepare_codex_handoff(
            &conversations,
            &definitions,
            expected_source.clone(),
            &fixture.target_profile,
            &trust_domain_id,
            HandoffReason::ConfirmedUsageExhaustion,
            &source,
        )?;
        assert_eq!(transition.conversation_id, expected_source.conversation_id);
        assert_eq!(transition.source_profile_id, fixture.source_profile.id);
        assert_eq!(transition.target_profile_id, fixture.target_profile.id);
        assert_eq!(transition.trust_domain_id, trust_domain_id);
        assert_eq!(transition.source_rollout, source.journal_rollout()?);
        assert_eq!(
            transition.phase,
            crate::conversations::HandoffPhase::Prepared
        );
        Ok(())
    }

    #[test]
    fn profile_thread_cwd_and_session_mismatches_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new("lineage-mismatch")?;
        assert_eq!(
            mint_profile_rollout_handoff(
                &fixture.registry,
                &fixture.target_profile,
                &fixture.source_read
            )
            .err(),
            Some(CodexRolloutHandoffError::UnsafeSource)
        );

        let mut wrong_thread = fixture.source_read.clone();
        wrong_thread.codex_version = "0.145.0".to_owned();
        assert_eq!(
            mint_profile_rollout_handoff(&fixture.registry, &fixture.source_profile, &wrong_thread)
                .err(),
            Some(CodexRolloutHandoffError::Thread)
        );

        let mut wrong_cwd = fixture.source_read.clone();
        wrong_cwd.metadata.canonical_cwd = fixture.root.join("not-the-workspace");
        assert_eq!(
            mint_profile_rollout_handoff(&fixture.registry, &fixture.source_profile, &wrong_cwd)
                .err(),
            Some(CodexRolloutHandoffError::Thread)
        );

        let bad_home = fixture.source_home()?;
        let bad_thread_id = uuid::Uuid::new_v4().to_string();
        let bad_rollout = write_rollout(
            &bad_home,
            &fixture.workspace,
            &bad_thread_id,
            &uuid::Uuid::new_v4().to_string(),
            None,
        )?;
        let bad_read = read_projection(
            &bad_home,
            &fixture.workspace,
            &bad_thread_id,
            &bad_rollout,
            false,
        )?;
        assert_eq!(
            mint_profile_rollout_handoff(&fixture.registry, &fixture.source_profile, &bad_read)
                .err(),
            Some(CodexRolloutHandoffError::Thread)
        );

        let mut archived = fixture.source_read.clone();
        archived.metadata.archived = true;
        assert_eq!(
            mint_profile_rollout_handoff(&fixture.registry, &fixture.source_profile, &archived)
                .err(),
            Some(CodexRolloutHandoffError::Archived)
        );
        Ok(())
    }

    #[test]
    fn traversal_symlink_and_ancestor_symlink_sources_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new("source-symlinks")?;
        let mut traversal = fixture.source_read.clone();
        traversal.metadata.rollout_path = fixture
            .source_home()?
            .join("sessions")
            .join("..")
            .join("config.toml");
        traversal.metadata.rollout_relative_path = PathBuf::from("../config.toml");
        assert_eq!(
            mint_profile_rollout_handoff(&fixture.registry, &fixture.source_profile, &traversal)
                .err(),
            Some(CodexRolloutHandoffError::UnsafeSource)
        );

        let moved = fixture.source_rollout.with_extension("moved");
        fs::rename(&fixture.source_rollout, &moved)?;
        symlink(&moved, &fixture.source_rollout)?;
        assert_eq!(
            fixture.mint().err(),
            Some(CodexRolloutHandoffError::UnsafeSource)
        );
        fs::remove_file(&fixture.source_rollout)?;
        fs::rename(&moved, &fixture.source_rollout)?;

        let day = fixture
            .source_rollout
            .parent()
            .ok_or("rollout has no parent")?;
        let moved_day = day.with_extension("moved");
        fs::rename(day, &moved_day)?;
        symlink(&moved_day, day)?;
        assert_eq!(
            fixture.mint().err(),
            Some(CodexRolloutHandoffError::UnsafeSource)
        );
        fs::remove_file(day)?;
        fs::rename(moved_day, day)?;
        Ok(())
    }

    #[test]
    fn hard_link_special_file_wrong_owner_writable_and_oversize_sources_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let hard_link_fixture = TestFixture::new("source-hard-link")?;
        fs::hard_link(
            &hard_link_fixture.source_rollout,
            hard_link_fixture.root.join("second-link"),
        )?;
        assert_eq!(
            hard_link_fixture.mint().err(),
            Some(CodexRolloutHandoffError::UnsafeSource)
        );

        let writable_fixture = TestFixture::new("source-writable")?;
        fs::set_permissions(
            &writable_fixture.source_rollout,
            fs::Permissions::from_mode(0o666),
        )?;
        assert_eq!(
            writable_fixture.mint().err(),
            Some(CodexRolloutHandoffError::UnsafeSource)
        );

        let oversize_fixture = TestFixture::new("source-oversize")?;
        OpenOptions::new()
            .write(true)
            .open(&oversize_fixture.source_rollout)?
            .set_len(MAX_ROLLOUT_BYTES as u64 + 1)?;
        assert_eq!(
            oversize_fixture.mint().err(),
            Some(CodexRolloutHandoffError::UnsafeSource)
        );

        let socket_path = std::env::temp_dir().join(format!("cfs-{}", uuid::Uuid::new_v4()));
        let socket = UnixListener::bind(&socket_path)?;
        assert_eq!(
            validate_file_metadata(
                &fs::metadata(&socket_path)?,
                CodexRolloutHandoffError::UnsafeSource
            ),
            Err(CodexRolloutHandoffError::UnsafeSource)
        );
        drop(socket);
        fs::remove_file(socket_path)?;

        let metadata = fs::metadata(&hard_link_fixture.source_rollout)?;
        let wrong_uid = rustix::process::geteuid().as_raw().wrapping_add(1);
        assert_eq!(
            validate_file_metadata_for_uid(
                &metadata,
                wrong_uid,
                CodexRolloutHandoffError::UnsafeSource
            ),
            Err(CodexRolloutHandoffError::UnsafeSource)
        );
        Ok(())
    }

    #[test]
    fn deleted_replaced_and_mutated_sources_fail_at_use_or_post_import()
    -> Result<(), Box<dyn std::error::Error>> {
        let deleted = TestFixture::new("source-deleted")?;
        let deleted_capability = deleted.mint()?;
        fs::remove_file(&deleted.source_rollout)?;
        assert_eq!(
            deleted_capability.begin_import().err(),
            Some(CodexRolloutHandoffError::UnsafeSource)
        );

        let replaced = TestFixture::new("source-replaced")?;
        let replaced_capability = replaced.mint()?;
        let displaced = replaced.source_rollout.with_extension("displaced");
        fs::rename(&replaced.source_rollout, &displaced)?;
        fs::copy(&displaced, &replaced.source_rollout)?;
        fs::set_permissions(&replaced.source_rollout, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            replaced_capability.begin_import().err(),
            Some(CodexRolloutHandoffError::UnsafeSource)
        );

        let mutated = TestFixture::new("source-mutated-after-import")?;
        let import = mutated.mint()?.begin_import()?;
        OpenOptions::new()
            .append(true)
            .open(&mutated.source_rollout)?
            .write_all(b"{\"type\":\"event_msg\"}\n")?;
        assert_eq!(
            import.finish().err(),
            Some(CodexRolloutHandoffError::SourceChanged)
        );
        Ok(())
    }

    #[test]
    fn fork_projection_requires_new_lineage_target_home_and_distinct_rollout()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new("valid-target")?;
        let source = fixture.verified_source()?;
        let target_thread_id = uuid::Uuid::new_v4().to_string();
        let target_rollout = write_target_rollout(&fixture, &target_thread_id)?;
        let result = target_result(&source, &target_thread_id, &target_rollout);

        let target = validate_handoff_fork_result(
            &fixture.registry,
            &fixture.target_profile,
            &source,
            &result,
        )?;
        assert_eq!(target.profile_id(), fixture.target_profile.id);
        assert_eq!(target.thread_id(), target_thread_id);
        assert_eq!(target.canonical_cwd(), fixture.workspace);
        assert_eq!(target.locator().root(), "sessions");
        assert!(!target.locator().relative_path().is_absolute());
        assert_eq!(target.fingerprint().sha256().len(), 64);
        assert_ne!(target.fingerprint().inode, source.fingerprint().inode);
        let adopted = target.into_handoff_target(&source)?;
        assert_eq!(adopted.thread_id, target_thread_id);
        assert_eq!(adopted.canonical_cwd, fixture.workspace.to_string_lossy());
        assert_eq!(adopted.codex_version, "0.144.4");
        assert_eq!(adopted.rollout.locator.root, RolloutRoot::Sessions);
        assert_ne!(adopted.rollout, source.journal_rollout()?);
        Ok(())
    }

    #[test]
    fn crash_inventory_candidate_requires_exact_lineage_and_durable_fork_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new("reconcile-target")?;
        let source = fixture.verified_source()?;
        let target_thread_id = uuid::Uuid::new_v4().to_string();
        let target_rollout = write_target_rollout(&fixture, &target_thread_id)?;
        let requested_at = 1_800_000_000;
        let observed_at = requested_at + 10;
        let candidate =
            inventory_candidate(&source, &target_thread_id, &target_rollout, requested_at);

        let validated = validate_handoff_inventory_candidate(
            &fixture.registry,
            &fixture.target_profile,
            &source,
            &candidate,
            requested_at,
            observed_at,
        )?;
        assert_eq!(validated.thread_id(), target_thread_id);
        let transaction_candidate =
            crate::providers::codex::handoff_transaction::ForkCandidate::from_validated_rollout(
                target_thread_id.clone(),
                validated,
                &source,
            );
        assert_eq!(
            transaction_candidate
                .matching_target_for_test()
                .map(|target| target.thread_id.as_str()),
            Some(target_thread_id.as_str())
        );

        let mut stale = candidate.clone();
        stale["updatedAt"] = json!(requested_at - MAX_FORK_CLOCK_SKEW_SECONDS - 1);
        assert_eq!(
            validate_handoff_inventory_candidate(
                &fixture.registry,
                &fixture.target_profile,
                &source,
                &stale,
                requested_at,
                observed_at,
            ),
            Err(CodexRolloutHandoffError::ForkResponse)
        );

        let mut wrong_parent = candidate;
        wrong_parent["parentThreadId"] = json!(uuid::Uuid::new_v4().to_string());
        assert_eq!(
            validate_handoff_inventory_candidate(
                &fixture.registry,
                &fixture.target_profile,
                &source,
                &wrong_parent,
                requested_at,
                observed_at,
            ),
            Err(CodexRolloutHandoffError::ForkResponse)
        );
        Ok(())
    }

    #[test]
    fn fork_projection_rejects_identity_cwd_parent_and_target_containment_mismatches()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new("target-mismatch")?;
        let source = fixture.verified_source()?;
        let target_thread_id = uuid::Uuid::new_v4().to_string();
        let target_rollout = write_target_rollout(&fixture, &target_thread_id)?;

        let mut same_id = target_result(&source, source.thread_id(), &target_rollout);
        same_id["thread"]["forkedFromId"] = json!(source.thread_id());
        assert_eq!(
            validate_handoff_fork_result(
                &fixture.registry,
                &fixture.target_profile,
                &source,
                &same_id
            ),
            Err(CodexRolloutHandoffError::ForkResponse)
        );

        let wrong_rollout_thread = uuid::Uuid::new_v4().to_string();
        let wrong_rollout_parent = uuid::Uuid::new_v4().to_string();
        let wrong_lineage_rollout = write_rollout(
            &fixture.target_home()?,
            &fixture.workspace,
            &wrong_rollout_thread,
            &wrong_rollout_thread,
            Some(&wrong_rollout_parent),
        )?;
        let wrong_lineage_result =
            target_result(&source, &wrong_rollout_thread, &wrong_lineage_rollout);
        assert_eq!(
            validate_handoff_fork_result(
                &fixture.registry,
                &fixture.target_profile,
                &source,
                &wrong_lineage_result,
            ),
            Err(CodexRolloutHandoffError::UnsafeTarget),
            "the provider response cannot substitute for target rollout lineage"
        );

        let mut wrong_parent = target_result(&source, &target_thread_id, &target_rollout);
        wrong_parent["thread"]["forkedFromId"] = json!(uuid::Uuid::new_v4().to_string());
        assert_eq!(
            validate_handoff_fork_result(
                &fixture.registry,
                &fixture.target_profile,
                &source,
                &wrong_parent
            ),
            Err(CodexRolloutHandoffError::ForkResponse)
        );

        let other_cwd = fixture.root.join("other-cwd");
        fs::DirBuilder::new().mode(0o700).create(&other_cwd)?;
        let mut wrong_cwd = target_result(&source, &target_thread_id, &target_rollout);
        wrong_cwd["cwd"] = json!(other_cwd);
        assert_eq!(
            validate_handoff_fork_result(
                &fixture.registry,
                &fixture.target_profile,
                &source,
                &wrong_cwd
            ),
            Err(CodexRolloutHandoffError::ForkResponse)
        );

        let outside = fixture.target_home()?.join("outside.jsonl");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&outside)?
            .write_all(b"{}\n")?;
        let outside_result = target_result(&source, &target_thread_id, &outside);
        assert_eq!(
            validate_handoff_fork_result(
                &fixture.registry,
                &fixture.target_profile,
                &source,
                &outside_result
            ),
            Err(CodexRolloutHandoffError::UnsafeTarget)
        );

        let archive_root = fixture.target_home()?.join("archived_sessions");
        fs::DirBuilder::new().mode(0o700).create(&archive_root)?;
        let archived = archive_root.join("archived.jsonl");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&archived)?
            .write_all(b"{}\n")?;
        let archived_result = target_result(&source, &target_thread_id, &archived);
        assert_eq!(
            validate_handoff_fork_result(
                &fixture.registry,
                &fixture.target_profile,
                &source,
                &archived_result
            ),
            Err(CodexRolloutHandoffError::UnsafeTarget)
        );
        Ok(())
    }

    #[test]
    fn fork_projection_rejects_unsafe_or_source_aliasing_target_nodes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new("unsafe-target")?;
        let source = fixture.verified_source()?;
        let target_thread_id = uuid::Uuid::new_v4().to_string();
        let target_rollout = write_target_rollout(&fixture, &target_thread_id)?;
        let second_link = fixture.target_home()?.join("target-second-link");
        fs::hard_link(&target_rollout, &second_link)?;
        let hard_link_result = target_result(&source, &target_thread_id, &target_rollout);
        assert_eq!(
            validate_handoff_fork_result(
                &fixture.registry,
                &fixture.target_profile,
                &source,
                &hard_link_result
            ),
            Err(CodexRolloutHandoffError::UnsafeTarget)
        );

        fs::remove_file(second_link)?;
        fs::set_permissions(&target_rollout, fs::Permissions::from_mode(0o666))?;
        let writable_result = target_result(&source, &target_thread_id, &target_rollout);
        assert_eq!(
            validate_handoff_fork_result(
                &fixture.registry,
                &fixture.target_profile,
                &source,
                &writable_result
            ),
            Err(CodexRolloutHandoffError::UnsafeTarget)
        );

        let aliasing = TestFixture::new("source-alias-target")?;
        let alias_source = aliasing.verified_source()?;
        let alias_thread_id = uuid::Uuid::new_v4().to_string();
        let alias_target_directory = aliasing.target_home()?.join("sessions/2026/08/07");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&alias_target_directory)?;
        let alias_target = alias_target_directory.join(format!("rollout-{alias_thread_id}.jsonl"));
        fs::rename(&aliasing.source_rollout, &alias_target)?;
        let alias_result = target_result(&alias_source, &alias_thread_id, &alias_target);
        assert_eq!(
            validate_handoff_fork_result(
                &aliasing.registry,
                &aliasing.target_profile,
                &alias_source,
                &alias_result
            ),
            Err(CodexRolloutHandoffError::UnsafeTarget),
            "a renamed source inode cannot be adopted as the target rollout"
        );
        Ok(())
    }

    #[test]
    fn handoff_projection_does_not_weaken_same_profile_root_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new("same-profile-unchanged")?;
        let source_parent = uuid::Uuid::new_v4().to_string();
        let fork_like_wire: WireThread = serde_json::from_value(json!({
            "id": fixture.source_read.metadata.thread_id,
            "parentThreadId": source_parent,
            "ephemeral": false,
            "updatedAt": 1_800_000_000,
            "recencyAt": null,
            "cwd": fixture.workspace,
            "cliVersion": "0.144.4",
            "source": "cli",
            "path": fixture.source_rollout
        }))?;
        assert!(
            validate_thread_projection(
                fork_like_wire,
                &fs::canonicalize(&fixture.workspace)?,
                &fixture.source_home()?,
                "0.144.4",
                Some(false)
            )
            .is_err(),
            "same-profile inventory/read must continue to reject non-root threads"
        );
        Ok(())
    }
}
