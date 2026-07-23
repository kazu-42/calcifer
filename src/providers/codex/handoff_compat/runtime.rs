use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::ops::Deref;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::super::remote::{
    ReadinessProbe, ReadinessProxy, ReadinessProxyError, ReadinessProxyShutdownFailure,
};
use super::super::{
    AppServerProcess, CodexThreadError, CodexUsageError, CodexVersionProbeFailure,
    CodexVersionProbeTimeoutOrigin, child_exit_observed_without_reaping, child_reap_confirmed,
    configure_own_process_group, force_terminate_process_tree, managed_command,
    probe_codex_version_command_with_origin, reap_exited_process_tree, validate_initialize_result,
};
use super::{
    CodexExecutableIdentity, CodexHandoffCapability, CodexHandoffCause, CodexHandoffError,
    CodexHandoffFailure, CompatibilityTimeoutOrigin, HandoffSchemaContract,
    validate_handoff_schema_pair,
};

const SUPPORTED_VERSION: &str = "0.144.4";
const SCHEMA_FILE: &str = "codex_app_server_protocol.v2.schemas.json";
const JSONRPC_ERROR_FILE: &str = "JSONRPCError.json";
const JSONRPC_ERROR_BODY_FILE: &str = "JSONRPCErrorError.json";
const MAX_SCHEMA_BYTES: u64 = 1024 * 1024;
const MAX_ROLLOUT_PROBE_BYTES: u64 = 1024 * 1024;
const MAX_SCRATCH_NODES: usize = 10_000;
const INITIALIZE_REQUEST_ID: u64 = 0;
const FORK_REQUEST_ID: u64 = 1;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
// Codex 0.144.4 can spend 30 seconds draining connection RPCs, followed by
// two sequential 10-second thread/background-task drains after stdio EOF.
// Keep ten seconds of scheduler headroom while retaining the probe's earlier
// absolute deadline as the authoritative outer bound.
const COMPLETED_REQUEST_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const SOURCE_TIMESTAMP: &str = "2026-07-15T00:00:00Z";
const SOURCE_FILENAME_TIMESTAMP: &str = "2026-07-15T00-00-00";
const MODEL_PROVIDER: &str = "calcifer_smoke";
const MODEL_NAME: &str = "calcifer-handoff-smoke";
const HISTORY_SENTINEL: &str = "calcifer handoff compatibility sentinel";
const MAX_TUI_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const PROBE_EXECUTABLE_FILE: &str = "codex";

#[cfg(test)]
thread_local! {
    static VERIFICATION_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PRE_VERSION_TIMEOUT_SEAM: std::cell::Cell<Option<CompatibilityTimeoutOrigin>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
struct PreVersionTimeoutSeamGuard {
    previous: Option<CompatibilityTimeoutOrigin>,
}

#[cfg(test)]
impl Drop for PreVersionTimeoutSeamGuard {
    fn drop(&mut self) {
        PRE_VERSION_TIMEOUT_SEAM.with(|seam| seam.set(self.previous));
    }
}

#[cfg(test)]
fn inject_pre_version_timeout(origin: CompatibilityTimeoutOrigin) -> PreVersionTimeoutSeamGuard {
    let previous = PRE_VERSION_TIMEOUT_SEAM.with(|seam| seam.replace(Some(origin)));
    assert!(
        previous.is_none(),
        "pre-version timeout seams must not be nested"
    );
    PreVersionTimeoutSeamGuard { previous }
}

fn check_pre_version_timeout_seam(
    origin: CompatibilityTimeoutOrigin,
) -> Result<(), CodexHandoffCause> {
    #[cfg(test)]
    if PRE_VERSION_TIMEOUT_SEAM.with(|seam| {
        if seam.get() == Some(origin) {
            seam.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(CodexHandoffCause::timeout(origin));
    }
    #[cfg(not(test))]
    let _ = origin;
    Ok(())
}

#[cfg(test)]
pub(super) fn verification_attempts_for_test() -> usize {
    VERIFICATION_ATTEMPTS.with(std::cell::Cell::get)
}

pub(super) fn verify(
    codex_executable: &Path,
    timeout: Duration,
) -> Result<CodexHandoffCapability, CodexHandoffFailure> {
    #[cfg(test)]
    VERIFICATION_ATTEMPTS.with(|attempts| {
        attempts.set(attempts.get().saturating_add(1));
    });
    check_pre_version_timeout_seam(CompatibilityTimeoutOrigin::DeadlineOverflow)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| CodexHandoffCause::timeout(CompatibilityTimeoutOrigin::DeadlineOverflow))?;
    let executable = capture_executable_at_boundary(
        codex_executable,
        deadline,
        CompatibilityTimeoutOrigin::SourceCapture,
    )?;
    let proof = verify_before_remote_until(&executable, deadline)?;
    let remote = match verify_remote_tui(&proof.probe_executable, &proof, deadline) {
        Ok(remote) => remote,
        Err(failure) => return Err(cleanup_failed_proof(proof, failure, deadline)),
    };
    let verification = (|| {
        ensure_no_credentials(proof.scratch.path())?;
        ensure_no_model_request(&proof.model_listener)?;
        proof.probe_binary_directory.revalidate()?;
        revalidate_executable_until(&proof.probe_executable, Some(deadline))?;
        revalidate_executable_until(&executable, Some(deadline))
    })();
    if let Err(error) = verification {
        return Err(cleanup_failed_proof(proof, error.into(), deadline));
    }
    let pinned_executable =
        match PinnedExecutableStage::from_verified(&proof.probe_executable, deadline) {
            Ok(stage) => stage,
            Err(failure) => {
                return Err(cleanup_failed_proof(proof, failure.into(), deadline));
            }
        };
    if let Err(error) = pinned_executable.revalidate(deadline) {
        let failure = CodexHandoffFailure::from(PinnedStageCreateFailure::with_complete(
            error,
            pinned_executable,
        ));
        return Err(cleanup_failed_proof(proof, failure, deadline));
    }
    cleanup_verified_proof(proof, pinned_executable, remote, deadline)
}

struct PreRemoteProof {
    scratch: ScratchRoot,
    probe_binary_directory: PrivateDirectory,
    probe_executable: CodexExecutableIdentity,
    schema: HandoffSchemaContract,
    fork: ForkProof,
    model_listener: TcpListener,
    source_home: PrivateDirectory,
    target_home: PrivateDirectory,
    workspace: PrivateDirectory,
    environment_home: PrivateDirectory,
    target_config: TargetConfigProof,
}

struct PreRemoteParts {
    probe_binary_directory: PrivateDirectory,
    probe_executable: CodexExecutableIdentity,
    schema: HandoffSchemaContract,
    fork: ForkProof,
    model_listener: TcpListener,
    source_home: PrivateDirectory,
    target_home: PrivateDirectory,
    workspace: PrivateDirectory,
    environment_home: PrivateDirectory,
    target_config: TargetConfigProof,
}

#[derive(Debug)]
struct ForkProof {
    source_rollout_relative: PathBuf,
    source_fingerprint: FileFingerprint,
    source_thread_id: String,
    target_thread_id: String,
    target_rollout_relative: PathBuf,
    target_fingerprint: FileFingerprint,
    target_home: PathBuf,
    workspace: PathBuf,
}

impl ForkProof {
    fn revalidate(
        &self,
        source_home: &PrivateDirectory,
        target_home: &PrivateDirectory,
    ) -> Result<(), CodexHandoffError> {
        if FileFingerprint::read_relative(
            source_home,
            &self.source_rollout_relative,
            MAX_ROLLOUT_PROBE_BYTES,
            FilePolicy::Private,
        )? != self.source_fingerprint
            || FileFingerprint::read_relative(
                target_home,
                &self.target_rollout_relative,
                MAX_ROLLOUT_PROBE_BYTES,
                FilePolicy::OwnedReadOnly,
            )? != self.target_fingerprint
        {
            return Err(CodexHandoffError::Protocol);
        }
        Ok(())
    }
}

struct RemoteTuiProof {
    _private: (),
}

#[cfg(test)]
fn verify_before_remote(
    codex_executable: &Path,
    timeout: Duration,
) -> Result<PreRemoteProof, CodexHandoffFailure> {
    check_pre_version_timeout_seam(CompatibilityTimeoutOrigin::DeadlineOverflow)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| CodexHandoffCause::timeout(CompatibilityTimeoutOrigin::DeadlineOverflow))?;
    let executable = capture_executable_at_boundary(
        codex_executable,
        deadline,
        CompatibilityTimeoutOrigin::SourceCapture,
    )?;
    verify_before_remote_until(&executable, deadline)
}

fn verify_before_remote_until(
    source_executable: &CodexExecutableIdentity,
    deadline: Instant,
) -> Result<PreRemoteProof, CodexHandoffFailure> {
    let scratch = ScratchRoot::create()?;
    match build_pre_remote_parts(source_executable, &scratch, deadline) {
        Ok(parts) => Ok(PreRemoteProof {
            scratch,
            probe_binary_directory: parts.probe_binary_directory,
            probe_executable: parts.probe_executable,
            schema: parts.schema,
            fork: parts.fork,
            model_listener: parts.model_listener,
            source_home: parts.source_home,
            target_home: parts.target_home,
            workspace: parts.workspace,
            environment_home: parts.environment_home,
            target_config: parts.target_config,
        }),
        Err(error) => match scratch.cleanup(deadline) {
            Ok(_) => Err(error.into()),
            Err(cleanup) => Err(CodexHandoffFailure::with_retained_cause(
                error,
                CodexHandoffRetention::ScratchCleanup(cleanup),
            )),
        },
    }
}

fn build_pre_remote_parts(
    source_executable: &CodexExecutableIdentity,
    scratch: &ScratchRoot,
    deadline: Instant,
) -> Result<PreRemoteParts, CodexHandoffCause> {
    let (probe_binary_directory, probe_executable) =
        stage_executable_with_origin(source_executable, scratch, deadline)?;
    let executable = &probe_executable;
    let source_home = scratch.create_directory("s")?;
    let target_home = scratch.create_directory("t")?;
    let workspace = scratch.create_directory("w")?;
    scratch.create_directory("w/.git")?;
    let environment_home = scratch.create_directory("h")?;
    scratch.create_directory("h/config")?;
    scratch.create_directory("h/data")?;
    scratch.create_directory("h/cache")?;
    scratch.create_directory("h/tmp")?;
    scratch.create_directory("h/run")?;

    let model_listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|_| CodexHandoffError::Transport)?;
    model_listener
        .set_nonblocking(true)
        .map_err(|_| CodexHandoffError::Transport)?;
    let target_config = write_target_config(
        &target_home,
        model_listener
            .local_addr()
            .map_err(|_| CodexHandoffError::Transport)?,
    )?;

    revalidate_probe_roots(
        scratch,
        &source_home,
        &target_home,
        &workspace,
        &environment_home,
    )?;

    revalidate_executable_metadata(executable)?;
    let version_command =
        isolated_command(&executable.canonical_path, &target_home, &environment_home);
    check_pre_version_timeout_seam(CompatibilityTimeoutOrigin::VersionChildExit)?;
    check_pre_version_timeout_seam(CompatibilityTimeoutOrigin::VersionStdoutDrain)?;
    let version =
        probe_codex_version_command_with_origin(version_command, &workspace, deadline, None)
            .map_err(map_version_probe_failure)?;
    target_config.revalidate(&target_home)?;
    revalidate_probe_roots(
        scratch,
        &source_home,
        &target_home,
        &workspace,
        &environment_home,
    )?;
    if version != SUPPORTED_VERSION {
        return Err(CodexHandoffError::Unsupported.into());
    }
    #[cfg(test)]
    eprintln!("handoff probe: version gate passed");

    let schema = generate_and_validate_schemas(
        executable,
        &target_home,
        &environment_home,
        &workspace,
        scratch,
        &target_config,
        deadline,
    )?;
    target_config.revalidate(&target_home)?;
    revalidate_probe_roots(
        scratch,
        &source_home,
        &target_home,
        &workspace,
        &environment_home,
    )?;
    #[cfg(test)]
    eprintln!("handoff probe: schema gate passed");
    let fork = fork_synthetic_rollout(
        executable,
        &source_home,
        &target_home,
        &environment_home,
        &workspace,
        deadline,
    )?;
    target_config.revalidate(&target_home)?;
    #[cfg(test)]
    eprintln!("handoff probe: fork gate passed");

    ensure_no_credentials(scratch.path())?;
    ensure_no_model_request(&model_listener)?;
    revalidate_probe_roots(
        scratch,
        &source_home,
        &target_home,
        &workspace,
        &environment_home,
    )?;

    Ok(PreRemoteParts {
        probe_binary_directory,
        probe_executable,
        schema,
        fork,
        model_listener,
        source_home,
        target_home,
        workspace,
        environment_home,
        target_config,
    })
}

fn verify_remote_tui(
    executable: &CodexExecutableIdentity,
    proof: &PreRemoteProof,
    deadline: Instant,
) -> Result<RemoteTuiProof, CodexHandoffFailure> {
    proof.scratch.revalidate()?;
    proof.source_home.revalidate()?;
    proof.target_home.revalidate()?;
    proof.workspace.revalidate()?;
    proof.environment_home.revalidate()?;
    proof.target_config.revalidate(&proof.target_home)?;
    proof
        .fork
        .revalidate(&proof.source_home, &proof.target_home)?;
    let app_server_socket = proof.scratch.path().join("a.sock");
    let proxy_socket = proof.scratch.path().join("p.sock");
    revalidate_executable_metadata(executable)?;
    let mut app_server_command = isolated_command(
        &executable.canonical_path,
        &proof.fork.target_home,
        &proof.environment_home,
    );
    app_server_command
        .args(["app-server", "--listen"])
        .arg(unix_address(&app_server_socket));
    let mut app_server = ChildGuard::spawn(app_server_command, &proof.fork.workspace)?;
    wait_for_unix_socket(&mut app_server, &app_server_socket, deadline)?;
    #[cfg(test)]
    eprintln!("handoff probe: remote app-server socket ready");

    let mut proxy = ReadinessProxy::spawn(
        &proxy_socket,
        &app_server_socket,
        ReadinessProbe::new(
            &proof.fork.target_thread_id,
            &proof.fork.source_thread_id,
            &proof.fork.workspace,
            MODEL_NAME,
            MODEL_PROVIDER,
        ),
        remaining(deadline)?,
    )
    .map_err(map_proxy_error)?;
    #[cfg(test)]
    eprintln!("handoff probe: readiness proxy ready");
    revalidate_executable_metadata(executable)?;
    proof.scratch.revalidate()?;
    proof.source_home.revalidate()?;
    proof.target_home.revalidate()?;
    proof.workspace.revalidate()?;
    proof.environment_home.revalidate()?;
    proof.target_config.revalidate(&proof.target_home)?;
    proof
        .fork
        .revalidate(&proof.source_home, &proof.target_home)?;
    let mut tui_command = isolated_command(
        &executable.canonical_path,
        &proof.fork.target_home,
        &proof.environment_home,
    );
    tui_command
        .args(["resume", "--no-alt-screen", "--remote"])
        .arg(unix_address(proxy.socket_path()))
        .arg(&proof.fork.target_thread_id);
    let mut tui = PtyChild::spawn(tui_command, &proof.fork.workspace)?;
    #[cfg(test)]
    eprintln!("handoff probe: remote TUI spawned");

    proxy.wait_until_ready().map_err(map_proxy_error)?;
    #[cfg(test)]
    eprintln!("handoff probe: remote TUI read/resume ready");
    let tui_running = tui.is_running()?;
    let app_server_running = app_server.is_running()?;
    #[cfg(test)]
    eprintln!(
        "handoff probe: post-ready liveness tui={tui_running} app-server={app_server_running}"
    );
    if !tui_running || !app_server_running {
        return Err(CodexHandoffError::Protocol.into());
    }
    proxy.ensure_connected().map_err(map_proxy_error)?;
    if let Err(failure) = proxy.shutdown(deadline) {
        let error = map_proxy_error(failure.error());
        return Err(CodexHandoffFailure::with_retained(
            error,
            CodexHandoffRetention::ProxyShutdown(Box::new(failure)),
        ));
    }
    #[cfg(test)]
    eprintln!("handoff probe: readiness proxy shut down while connected");
    let tui_output = tui.shutdown()?;
    #[cfg(test)]
    eprintln!(
        "handoff probe: TUI output bytes={} overflow={} failed={}",
        tui_output.bytes.len(),
        tui_output.overflowed,
        tui_output.failed
    );
    if tui_output.overflowed || tui_output.failed || tui_output.bytes.len() > MAX_TUI_OUTPUT_BYTES {
        return Err(CodexHandoffError::Protocol.into());
    }
    app_server.shutdown()?;
    #[cfg(test)]
    eprintln!("handoff probe: remote app-server shut down");
    ensure_no_model_request(&proof.model_listener)?;
    proof.scratch.revalidate()?;
    proof.source_home.revalidate()?;
    proof.target_home.revalidate()?;
    proof.workspace.revalidate()?;
    proof.environment_home.revalidate()?;
    proof.target_config.revalidate(&proof.target_home)?;
    proof
        .fork
        .revalidate(&proof.source_home, &proof.target_home)?;

    Ok(RemoteTuiProof { _private: () })
}

fn mint_capability(
    executable: PinnedExecutableStage,
    _schema: HandoffSchemaContract,
    _fork: ForkProof,
    _remote: RemoteTuiProof,
) -> CodexHandoffCapability {
    CodexHandoffCapability { executable }
}

fn cleanup_failed_proof(
    proof: PreRemoteProof,
    failure: CodexHandoffFailure,
    deadline: Instant,
) -> CodexHandoffFailure {
    let PreRemoteProof {
        scratch,
        probe_binary_directory,
        probe_executable,
        schema,
        fork,
        model_listener,
        source_home,
        target_home,
        workspace,
        environment_home,
        target_config,
    } = proof;
    drop((
        probe_binary_directory,
        probe_executable,
        schema,
        fork,
        model_listener,
        source_home,
        target_home,
        workspace,
        environment_home,
        target_config,
    ));
    match scratch.cleanup(deadline) {
        Ok(_) => failure,
        Err(cleanup) => retain_scratch_cleanup(failure, cleanup),
    }
}

fn cleanup_verified_proof(
    proof: PreRemoteProof,
    pinned_executable: PinnedExecutableStage,
    remote: RemoteTuiProof,
    deadline: Instant,
) -> Result<CodexHandoffCapability, CodexHandoffFailure> {
    let PreRemoteProof {
        scratch,
        probe_binary_directory,
        probe_executable,
        schema,
        fork,
        model_listener,
        source_home,
        target_home,
        workspace,
        environment_home,
        target_config,
    } = proof;
    drop((
        probe_binary_directory,
        probe_executable,
        model_listener,
        source_home,
        target_home,
        workspace,
        environment_home,
        target_config,
    ));
    match scratch.cleanup(deadline) {
        Ok(_) => Ok(mint_capability(pinned_executable, schema, fork, remote)),
        Err(cleanup) => {
            let cleanup_error = cleanup.error();
            let stage = PinnedStageCreateFailure::with_complete(
                PinnedStageError::Storage,
                pinned_executable,
            );
            let retained_stage = match CodexHandoffFailure::from(stage).retained {
                Some(retained) => retained,
                None => return Err(cleanup_error.into()),
            };
            Err(CodexHandoffFailure::with_retained(
                cleanup_error,
                CodexHandoffRetention::Combined {
                    prior: Box::new(retained_stage),
                    scratch: cleanup,
                },
            ))
        }
    }
}

fn retain_scratch_cleanup(
    mut failure: CodexHandoffFailure,
    cleanup: Box<ScratchRootCleanupFailure>,
) -> CodexHandoffFailure {
    failure.retained = Some(match failure.retained.take() {
        Some(prior) => CodexHandoffRetention::Combined {
            prior: Box::new(prior),
            scratch: cleanup,
        },
        None => CodexHandoffRetention::ScratchCleanup(cleanup),
    });
    failure
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinnedStageError {
    ExecutableChanged,
    Storage,
    Timeout,
}

impl fmt::Display for PinnedStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExecutableChanged => "the verified Codex executable changed",
            Self::Storage => "the private Codex executable stage is unsafe",
            Self::Timeout => "the verified Codex executable stage timed out",
        })
    }
}

impl std::error::Error for PinnedStageError {}

#[must_use = "stage creation failure can retain filesystem ownership"]
pub(crate) struct PinnedStageCreateFailure {
    error: PinnedStageError,
    ownership: Option<PinnedStageConstructionOwnership>,
}

enum PinnedStageConstructionOwnership {
    ScratchCreate(Box<ScratchRootCreateFailure>),
    Scratch(Box<ScratchRoot>),
    Complete(Box<PinnedExecutableStage>),
}

impl fmt::Debug for PinnedStageConstructionOwnership {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScratchCreate(failure) => {
                let _ = failure;
                formatter.write_str("PinnedStageConstructionOwnership::ScratchCreate(<redacted>)")
            }
            Self::Scratch(scratch) => {
                let _ = scratch;
                formatter.write_str("PinnedStageConstructionOwnership::Scratch(<redacted>)")
            }
            Self::Complete(stage) => {
                let _ = stage;
                formatter.write_str("PinnedStageConstructionOwnership::Complete(<redacted>)")
            }
        }
    }
}

pub(super) enum CodexHandoffRetention {
    ScratchCreate(Box<ScratchRootCreateFailure>),
    ScratchCleanup(Box<ScratchRootCleanupFailure>),
    StageCreate(Box<PinnedStageCreateFailure>),
    ProxyShutdown(Box<ReadinessProxyShutdownFailure>),
    Combined {
        prior: Box<CodexHandoffRetention>,
        scratch: Box<ScratchRootCleanupFailure>,
    },
}

pub(super) struct HandoffRetentionResolveFailure {
    pub(super) retained: CodexHandoffRetention,
    pub(super) error: CodexHandoffError,
}

/// Retries the exact cleanup phase retained by a failed compatibility probe.
///
/// Recursive `Combined` ownership is resolved in dependency order: a live
/// relay/probe or pinned stage first, then the scratch tree containing its
/// files. Every failed branch reconstructs an owned variant; no pathname-only
/// cleanup authority is invented.
pub(super) fn resolve_handoff_retention(
    retained: CodexHandoffRetention,
    deadline: Instant,
) -> Result<(), HandoffRetentionResolveFailure> {
    match retained {
        CodexHandoffRetention::ScratchCreate(mut failure) => {
            let Some(retained) = failure.retained.take() else {
                return Ok(());
            };
            match retained {
                ScratchRootRetention::Open(root) => resolve_scratch_root(*root, deadline),
                ScratchRootRetention::Partial(root) => {
                    let error = failure.error();
                    failure.retained = Some(ScratchRootRetention::Partial(root));
                    Err(HandoffRetentionResolveFailure {
                        retained: CodexHandoffRetention::ScratchCreate(failure),
                        error,
                    })
                }
            }
        }
        CodexHandoffRetention::ScratchCleanup(failure) => {
            resolve_scratch_cleanup(*failure, deadline)
        }
        CodexHandoffRetention::StageCreate(mut failure) => {
            let Some(ownership) = failure.ownership.take() else {
                return Ok(());
            };
            match ownership {
                PinnedStageConstructionOwnership::ScratchCreate(failure) => {
                    resolve_handoff_retention(
                        CodexHandoffRetention::ScratchCreate(failure),
                        deadline,
                    )
                }
                PinnedStageConstructionOwnership::Scratch(scratch) => {
                    resolve_scratch_root(*scratch, deadline)
                }
                PinnedStageConstructionOwnership::Complete(stage) => {
                    let original_error = failure.error;
                    match (*stage).cleanup(deadline) {
                        Ok(_) => Ok(()),
                        Err(cleanup) => {
                            let error = map_pinned_stage_error(cleanup.error());
                            Err(HandoffRetentionResolveFailure {
                                retained: CodexHandoffRetention::StageCreate(Box::new(
                                    PinnedStageCreateFailure::with_complete(
                                        original_error,
                                        (*cleanup).into_stage(),
                                    ),
                                )),
                                error,
                            })
                        }
                    }
                }
            }
        }
        CodexHandoffRetention::ProxyShutdown(failure) => {
            let Some(proxy) = failure.into_proxy() else {
                return Ok(());
            };
            match proxy.shutdown(deadline) {
                Ok(_) => Ok(()),
                Err(failure) => {
                    let error = map_proxy_error(failure.error());
                    Err(HandoffRetentionResolveFailure {
                        retained: CodexHandoffRetention::ProxyShutdown(Box::new(failure)),
                        error,
                    })
                }
            }
        }
        CodexHandoffRetention::Combined { prior, scratch } => {
            match resolve_handoff_retention(*prior, deadline) {
                Ok(()) => resolve_scratch_cleanup(*scratch, deadline),
                Err(failure) => Err(HandoffRetentionResolveFailure {
                    retained: CodexHandoffRetention::Combined {
                        prior: Box::new(failure.retained),
                        scratch,
                    },
                    error: failure.error,
                }),
            }
        }
    }
}

fn resolve_scratch_cleanup(
    failure: ScratchRootCleanupFailure,
    deadline: Instant,
) -> Result<(), HandoffRetentionResolveFailure> {
    let ScratchRootCleanupFailure { root, .. } = failure;
    resolve_scratch_root(root, deadline)
}

fn resolve_scratch_root(
    mut root: ScratchRoot,
    deadline: Instant,
) -> Result<(), HandoffRetentionResolveFailure> {
    // Construction failures intentionally mark an exact open root as
    // preserved so Drop can never mutate it. Reaching this function consumes
    // that retained owner through the explicit deadline-bearing cleanup API,
    // which is the only transition allowed to reactivate mutation.
    root.authorize_explicit_cleanup();
    match root.cleanup(deadline) {
        Ok(_) => Ok(()),
        Err(failure) => {
            let error = failure.error();
            Err(HandoffRetentionResolveFailure {
                retained: CodexHandoffRetention::ScratchCleanup(failure),
                error,
            })
        }
    }
}

impl PinnedStageCreateFailure {
    fn not_created(error: PinnedStageError) -> Self {
        Self {
            error,
            ownership: None,
        }
    }

    fn from_scratch_create(failure: ScratchRootCreateFailure) -> Self {
        Self {
            error: map_stage_error(failure.error()),
            ownership: Some(PinnedStageConstructionOwnership::ScratchCreate(Box::new(
                failure,
            ))),
        }
    }

    fn with_scratch(error: PinnedStageError, mut scratch: ScratchRoot) -> Self {
        scratch.preserve();
        Self {
            error,
            ownership: Some(PinnedStageConstructionOwnership::Scratch(Box::new(scratch))),
        }
    }

    fn with_complete(error: PinnedStageError, stage: PinnedExecutableStage) -> Self {
        Self {
            error,
            ownership: Some(PinnedStageConstructionOwnership::Complete(Box::new(stage))),
        }
    }

    pub(crate) const fn error(&self) -> PinnedStageError {
        self.error
    }

    #[cfg(test)]
    pub(crate) fn retained_path(&self) -> Option<&Path> {
        match self.ownership.as_ref()? {
            PinnedStageConstructionOwnership::ScratchCreate(failure) => failure.retained_path(),
            PinnedStageConstructionOwnership::Scratch(scratch) => Some(scratch.path()),
            PinnedStageConstructionOwnership::Complete(stage) => Some(stage.scratch.path()),
        }
    }
}

impl fmt::Display for PinnedStageCreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl fmt::Debug for PinnedStageCreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.ownership;
        formatter
            .debug_struct("PinnedStageCreateFailure")
            .field("error", &self.error)
            .field("retained", &self.ownership.is_some())
            .finish_non_exhaustive()
    }
}

impl std::error::Error for PinnedStageCreateFailure {}

impl From<PinnedStageCreateFailure> for CodexHandoffFailure {
    fn from(failure: PinnedStageCreateFailure) -> Self {
        let error = map_pinned_stage_error(failure.error());
        if failure.ownership.is_some() {
            Self::with_retained(error, CodexHandoffRetention::StageCreate(Box::new(failure)))
        } else {
            error.into()
        }
    }
}

impl From<ScratchRootCreateFailure> for CodexHandoffFailure {
    fn from(failure: ScratchRootCreateFailure) -> Self {
        let error = failure.error();
        if failure.retained.is_some() {
            Self::with_retained(
                error,
                CodexHandoffRetention::ScratchCreate(Box::new(failure)),
            )
        } else {
            error.into()
        }
    }
}

impl fmt::Debug for CodexHandoffRetention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScratchCreate(failure) => {
                let _ = failure;
                formatter.write_str("CodexHandoffRetention::ScratchCreate(<redacted>)")
            }
            Self::ScratchCleanup(failure) => {
                let _ = failure;
                formatter.write_str("CodexHandoffRetention::ScratchCleanup(<redacted>)")
            }
            Self::StageCreate(failure) => {
                let _ = failure;
                formatter.write_str("CodexHandoffRetention::StageCreate(<redacted>)")
            }
            Self::ProxyShutdown(failure) => {
                let _ = failure;
                formatter.write_str("CodexHandoffRetention::ProxyShutdown(<redacted>)")
            }
            Self::Combined { prior, scratch } => {
                let _ = (prior, scratch);
                formatter.write_str("CodexHandoffRetention::Combined(<redacted>)")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PinnedStageCleanupComplete {
    _private: (),
}

#[must_use = "cleanup failure retains the pinned stage and must be handled"]
pub(crate) struct PinnedStageCleanupFailure {
    stage: PinnedExecutableStage,
    error: PinnedStageError,
}

impl PinnedStageCleanupFailure {
    pub(crate) const fn error(&self) -> PinnedStageError {
        self.error
    }

    pub(crate) fn into_stage(self) -> PinnedExecutableStage {
        self.stage
    }
}

impl fmt::Debug for PinnedStageCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.stage;
        formatter
            .debug_struct("PinnedStageCleanupFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// One compatibility-proven executable retained below an owner-private root.
///
/// The installed pathname is never used after this value is minted. Both
/// provider command plans revalidate and use this exact private stage.
#[must_use = "a pinned executable stage must be explicitly cleaned or retained"]
pub(crate) struct PinnedExecutableStage {
    scratch: ScratchRoot,
    directory: PrivateDirectory,
    executable: CodexExecutableIdentity,
    cleanup_state: PinnedStageCleanupState,
    cleanup_first_error: Option<PinnedStageError>,
    cleanup_fault: Option<PinnedStageCleanupFault>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PinnedStageCleanupState {
    Active,
    ExecutableRemovedPendingDirectorySync,
    ExecutableRemovalDurable,
    DirectoryRemovedPendingRootSync,
    DirectoryRemovalDurable,
    RootRemovedPendingParentSync,
    Cleaned,
    Preserved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinnedStageCleanupFault {
    BeforeMutation,
    AfterExecutableRemove,
    AfterDirectorySync,
    AfterDirectoryRemove,
    AfterRootSync,
    AfterRootRemove,
}

impl PinnedExecutableStage {
    /// Appends every persistent descriptor that pins the private executable
    /// stage to one source-pinned child denyset.
    pub(crate) fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        forbidden.capture(self.scratch.parent_descriptor.as_fd())?;
        forbidden.capture(self.scratch.descriptor.as_fd())?;
        forbidden.capture(self.directory.descriptor.as_fd())
    }

    fn from_verified(
        source: &CodexExecutableIdentity,
        deadline: Instant,
    ) -> Result<Self, PinnedStageCreateFailure> {
        revalidate_executable_until(source, Some(deadline))
            .map_err(map_stage_error)
            .map_err(PinnedStageCreateFailure::not_created)?;
        let scratch =
            ScratchRoot::create().map_err(PinnedStageCreateFailure::from_scratch_create)?;
        Self::stage(source, scratch, deadline)
    }

    #[cfg(test)]
    fn from_verified_in(
        source: &CodexExecutableIdentity,
        parent: &Path,
        deadline: Instant,
    ) -> Result<Self, PinnedStageCreateFailure> {
        revalidate_executable_until(source, Some(deadline))
            .map_err(map_stage_error)
            .map_err(PinnedStageCreateFailure::not_created)?;
        let scratch = ScratchRoot::create_in(parent)
            .map_err(PinnedStageCreateFailure::from_scratch_create)?;
        Self::stage(source, scratch, deadline)
    }

    #[cfg(test)]
    fn from_verified_in_with_root_sync_failure(
        source: &CodexExecutableIdentity,
        parent: &Path,
        deadline: Instant,
    ) -> Result<Self, PinnedStageCreateFailure> {
        revalidate_executable_until(source, Some(deadline))
            .map_err(map_stage_error)
            .map_err(PinnedStageCreateFailure::not_created)?;
        let scratch = ScratchRoot::create_in_with_sync_failure(parent)
            .map_err(PinnedStageCreateFailure::from_scratch_create)?;
        Self::stage(source, scratch, deadline)
    }

    #[cfg(test)]
    fn from_verified_in_with_parent_sync_failure(
        source: &CodexExecutableIdentity,
        parent: &Path,
        deadline: Instant,
    ) -> Result<Self, PinnedStageCreateFailure> {
        revalidate_executable_until(source, Some(deadline))
            .map_err(map_stage_error)
            .map_err(PinnedStageCreateFailure::not_created)?;
        let scratch = ScratchRoot::create_in_with_parent_sync_failure(parent)
            .map_err(PinnedStageCreateFailure::from_scratch_create)?;
        Self::stage(source, scratch, deadline)
    }

    fn stage(
        source: &CodexExecutableIdentity,
        mut scratch: ScratchRoot,
        deadline: Instant,
    ) -> Result<Self, PinnedStageCreateFailure> {
        // A pinned stage never delegates to ScratchRoot's recursive probe
        // cleanup. From this point onward, partial or ambiguous construction
        // is retained; a complete stage uses only identity-conditioned cleanup.
        scratch.preserve();
        let (directory, executable) = match stage_executable(source, &scratch, deadline) {
            Ok(staged) => staged,
            Err(error) => {
                return Err(PinnedStageCreateFailure::with_scratch(
                    map_stage_error(error),
                    scratch,
                ));
            }
        };
        if directory.descriptor.sync_all().is_err() {
            return Err(PinnedStageCreateFailure::with_scratch(
                PinnedStageError::Storage,
                scratch,
            ));
        }
        if scratch.sync_all().is_err() {
            return Err(PinnedStageCreateFailure::with_scratch(
                PinnedStageError::Storage,
                scratch,
            ));
        }
        if let Err(error) = scratch.revalidate() {
            return Err(PinnedStageCreateFailure::with_scratch(
                map_stage_error(error),
                scratch,
            ));
        }
        Ok(Self {
            scratch,
            directory,
            executable,
            cleanup_state: PinnedStageCleanupState::Active,
            cleanup_first_error: None,
            cleanup_fault: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn executable_path_for_test(&self) -> &Path {
        &self.executable.canonical_path
    }

    #[cfg(test)]
    pub(crate) fn root_path(&self) -> &Path {
        self.directory.as_ref()
    }

    pub(crate) fn revalidate(&self, deadline: Instant) -> Result<(), PinnedStageError> {
        if self.cleanup_state != PinnedStageCleanupState::Active {
            return Err(PinnedStageError::Storage);
        }
        ensure_stage_deadline(deadline)?;
        self.scratch.revalidate().map_err(map_stage_error)?;
        self.directory.revalidate().map_err(map_stage_error)?;
        revalidate_executable_until(&self.executable, Some(deadline)).map_err(map_stage_error)
    }

    /// Rechecks the exact private stage without re-reading its full contents.
    ///
    /// A full digest validation must already have succeeded for the launch
    /// being prepared. This narrow check is intended for the final spawn
    /// boundary: it rejects pathname replacement and in-place metadata changes
    /// while keeping storage throughput out of a relative readiness budget.
    pub(crate) fn revalidate_metadata(&self) -> Result<(), PinnedStageError> {
        if self.cleanup_state != PinnedStageCleanupState::Active {
            return Err(PinnedStageError::Storage);
        }
        self.scratch.revalidate().map_err(map_stage_error)?;
        self.directory.revalidate().map_err(map_stage_error)?;
        revalidate_executable_metadata(&self.executable).map_err(map_stage_error)
    }

    pub(crate) fn app_server_command(
        &self,
        codex_home: &Path,
        working_directory: &Path,
        socket_address: &str,
        deadline: Instant,
    ) -> Result<Command, PinnedStageError> {
        self.revalidate(deadline)?;
        let mut command = managed_command(&self.executable.canonical_path, codex_home);
        command
            .env_remove("RUST_LOG")
            .env_remove("LOG_FORMAT")
            .args(["app-server", "--listen", socket_address])
            .current_dir(working_directory);
        Ok(command)
    }

    pub(crate) fn remote_tui_command(
        &self,
        codex_home: &Path,
        working_directory: &Path,
        socket_address: &str,
        thread_id: &str,
        deadline: Instant,
    ) -> Result<Command, PinnedStageError> {
        self.revalidate(deadline)?;
        let mut command = managed_command(&self.executable.canonical_path, codex_home);
        command
            .env_remove("RUST_LOG")
            .env_remove("LOG_FORMAT")
            .args([
                "resume",
                "--no-alt-screen",
                "--remote",
                socket_address,
                thread_id,
            ])
            .current_dir(working_directory);
        Ok(command)
    }

    pub(crate) fn cleanup(
        mut self,
        deadline: Instant,
    ) -> Result<PinnedStageCleanupComplete, Box<PinnedStageCleanupFailure>> {
        let result = self.cleanup_once(deadline);
        match result {
            Ok(()) => {
                self.cleanup_state = PinnedStageCleanupState::Cleaned;
                Ok(PinnedStageCleanupComplete { _private: () })
            }
            Err(error) => {
                self.scratch.preserve();
                let first_error = *self.cleanup_first_error.get_or_insert(error);
                Err(Box::new(PinnedStageCleanupFailure {
                    stage: self,
                    error: first_error,
                }))
            }
        }
    }

    fn cleanup_once(&mut self, deadline: Instant) -> Result<(), PinnedStageError> {
        loop {
            ensure_stage_deadline(deadline)?;
            match self.cleanup_state {
                PinnedStageCleanupState::Active => {
                    self.inject_cleanup_fault(PinnedStageCleanupFault::BeforeMutation)?;
                    self.revalidate(deadline)?;
                    let mut entries = fs::read_dir(self.directory.as_ref())
                        .map_err(|_| PinnedStageError::Storage)?;
                    let entry = entries
                        .next()
                        .transpose()
                        .map_err(|_| PinnedStageError::Storage)?
                        .ok_or(PinnedStageError::ExecutableChanged)?;
                    if entry.file_name() != OsStr::new(PROBE_EXECUTABLE_FILE) {
                        return Err(PinnedStageError::ExecutableChanged);
                    }
                    match entries.next() {
                        None => {}
                        Some(Ok(_)) => return Err(PinnedStageError::ExecutableChanged),
                        Some(Err(_)) => return Err(PinnedStageError::Storage),
                    }
                    ensure_stage_deadline(deadline)?;
                    fs::remove_file(&self.executable.canonical_path)
                        .map_err(|_| PinnedStageError::Storage)?;
                    if fs::symlink_metadata(&self.executable.canonical_path).is_ok() {
                        return Err(PinnedStageError::ExecutableChanged);
                    }
                    self.cleanup_state =
                        PinnedStageCleanupState::ExecutableRemovedPendingDirectorySync;
                    self.inject_cleanup_fault(PinnedStageCleanupFault::AfterExecutableRemove)?;
                }
                PinnedStageCleanupState::ExecutableRemovedPendingDirectorySync => {
                    self.directory
                        .descriptor
                        .sync_all()
                        .map_err(|_| PinnedStageError::Storage)?;
                    self.cleanup_state = PinnedStageCleanupState::ExecutableRemovalDurable;
                    self.inject_cleanup_fault(PinnedStageCleanupFault::AfterDirectorySync)?;
                }
                PinnedStageCleanupState::ExecutableRemovalDurable => {
                    self.directory.revalidate().map_err(map_stage_error)?;
                    self.scratch.revalidate().map_err(map_stage_error)?;
                    fs::remove_dir(self.directory.as_ref())
                        .map_err(|_| PinnedStageError::Storage)?;
                    if fs::symlink_metadata(self.directory.as_ref()).is_ok() {
                        return Err(PinnedStageError::Storage);
                    }
                    self.cleanup_state = PinnedStageCleanupState::DirectoryRemovedPendingRootSync;
                    self.inject_cleanup_fault(PinnedStageCleanupFault::AfterDirectoryRemove)?;
                }
                PinnedStageCleanupState::DirectoryRemovedPendingRootSync => {
                    self.scratch.sync_all().map_err(map_stage_error)?;
                    self.cleanup_state = PinnedStageCleanupState::DirectoryRemovalDurable;
                    self.inject_cleanup_fault(PinnedStageCleanupFault::AfterRootSync)?;
                }
                PinnedStageCleanupState::DirectoryRemovalDurable => {
                    self.scratch.revalidate().map_err(map_stage_error)?;
                    fs::remove_dir(self.scratch.path()).map_err(|_| PinnedStageError::Storage)?;
                    if fs::symlink_metadata(self.scratch.path()).is_ok() {
                        return Err(PinnedStageError::Storage);
                    }
                    self.cleanup_state = PinnedStageCleanupState::RootRemovedPendingParentSync;
                    self.inject_cleanup_fault(PinnedStageCleanupFault::AfterRootRemove)?;
                }
                PinnedStageCleanupState::RootRemovedPendingParentSync => {
                    self.scratch.sync_parent().map_err(map_stage_error)?;
                    return Ok(());
                }
                PinnedStageCleanupState::Cleaned => return Ok(()),
                PinnedStageCleanupState::Preserved => return Err(PinnedStageError::Storage),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_cleanup_for_test(&mut self) {
        self.cleanup_fault = Some(PinnedStageCleanupFault::BeforeMutation);
    }

    #[cfg(test)]
    pub(crate) fn fail_cleanup_at_for_test(&mut self, fault: PinnedStageCleanupFault) {
        self.cleanup_fault = Some(fault);
    }

    fn inject_cleanup_fault(
        &mut self,
        expected: PinnedStageCleanupFault,
    ) -> Result<(), PinnedStageError> {
        if self.cleanup_fault == Some(expected) {
            self.cleanup_fault = None;
            Err(PinnedStageError::Storage)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for PinnedExecutableStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.executable, self.cleanup_state);
        formatter.write_str("PinnedExecutableStage(<redacted>)")
    }
}

impl Drop for PinnedExecutableStage {
    fn drop(&mut self) {
        if !matches!(
            self.cleanup_state,
            PinnedStageCleanupState::Cleaned | PinnedStageCleanupState::Preserved
        ) {
            // Drop must never perform an unbounded executable hash or hide a
            // cleanup failure. Explicit cleanup owns a caller-supplied
            // deadline; implicit drop retains the identity-bound evidence and
            // never attempts a remaining partial-cleanup phase.
            self.cleanup_state = PinnedStageCleanupState::Preserved;
            self.scratch.preserve();
        }
    }
}

fn ensure_stage_deadline(deadline: Instant) -> Result<(), PinnedStageError> {
    if Instant::now() >= deadline {
        Err(PinnedStageError::Timeout)
    } else {
        Ok(())
    }
}

fn map_pinned_stage_error(error: PinnedStageError) -> CodexHandoffError {
    match error {
        PinnedStageError::ExecutableChanged => CodexHandoffError::Unsupported,
        PinnedStageError::Storage => CodexHandoffError::Transport,
        PinnedStageError::Timeout => CodexHandoffError::Timeout,
    }
}

fn map_stage_error(error: CodexHandoffError) -> PinnedStageError {
    match error {
        CodexHandoffError::Timeout => PinnedStageError::Timeout,
        CodexHandoffError::Unsupported | CodexHandoffError::Spawn => {
            PinnedStageError::ExecutableChanged
        }
        CodexHandoffError::Protocol | CodexHandoffError::Transport => PinnedStageError::Storage,
    }
}

#[cfg(test)]
pub(super) fn capture_test_compatibility(
    executable: &Path,
) -> Result<CodexExecutableIdentity, PinnedStageError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or(PinnedStageError::Timeout)?;
    capture_test_compatibility_until(executable, deadline).map_err(map_stage_error)
}

#[cfg(test)]
pub(super) fn capture_test_compatibility_until(
    executable: &Path,
    deadline: Instant,
) -> Result<CodexExecutableIdentity, CodexHandoffError> {
    capture_executable(executable, deadline)
}

#[cfg(test)]
pub(super) fn pin_test_compatibility(
    executable: CodexExecutableIdentity,
    parent: &Path,
) -> Result<PinnedExecutableStage, PinnedStageCreateFailure> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or_else(|| PinnedStageCreateFailure::not_created(PinnedStageError::Timeout))?;
    pin_test_compatibility_until(executable, parent, deadline)
}

#[cfg(test)]
pub(super) fn pin_test_compatibility_until(
    executable: CodexExecutableIdentity,
    parent: &Path,
    deadline: Instant,
) -> Result<PinnedExecutableStage, PinnedStageCreateFailure> {
    PinnedExecutableStage::from_verified_in(&executable, parent, deadline)
}

#[cfg(test)]
pub(super) fn pin_test_compatibility_with_root_sync_failure(
    executable: CodexExecutableIdentity,
    parent: &Path,
) -> Result<PinnedExecutableStage, PinnedStageCreateFailure> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or_else(|| PinnedStageCreateFailure::not_created(PinnedStageError::Timeout))?;
    PinnedExecutableStage::from_verified_in_with_root_sync_failure(&executable, parent, deadline)
}

#[cfg(test)]
pub(super) fn pin_test_compatibility_with_parent_sync_failure(
    executable: CodexExecutableIdentity,
    parent: &Path,
) -> Result<PinnedExecutableStage, PinnedStageCreateFailure> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or_else(|| PinnedStageCreateFailure::not_created(PinnedStageError::Timeout))?;
    PinnedExecutableStage::from_verified_in_with_parent_sync_failure(&executable, parent, deadline)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ExecutableMetadata {
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

fn stage_executable(
    source: &CodexExecutableIdentity,
    scratch: &ScratchRoot,
    deadline: Instant,
) -> Result<(PrivateDirectory, CodexExecutableIdentity), CodexHandoffError> {
    stage_executable_with_origin(source, scratch, deadline).map_err(CodexHandoffCause::release)
}

fn stage_executable_with_origin(
    source: &CodexExecutableIdentity,
    scratch: &ScratchRoot,
    deadline: Instant,
) -> Result<(PrivateDirectory, CodexExecutableIdentity), CodexHandoffCause> {
    check_pre_version_timeout_seam(CompatibilityTimeoutOrigin::ProbeStageCopyDurability)?;
    ensure_compatibility_deadline(
        deadline,
        CompatibilityTimeoutOrigin::ProbeStageCopyDurability,
    )?;
    scratch.revalidate()?;
    let directory = scratch.create_directory("b")?;
    let (mut input, before) = open_executable(&source.canonical_path)?;
    ensure_compatibility_deadline(
        deadline,
        CompatibilityTimeoutOrigin::ProbeStageCopyDurability,
    )?;
    if before != metadata_from_identity(source) {
        return Err(CodexHandoffError::Unsupported.into());
    }
    let output_descriptor = rustix::fs::openat(
        &directory.descriptor,
        PROBE_EXECUTABLE_FILE,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o500),
    )
    .map_err(|_| CodexHandoffError::Transport)?;
    let mut output = File::from(output_descriptor);
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        ensure_compatibility_deadline(
            deadline,
            CompatibilityTimeoutOrigin::ProbeStageCopyDurability,
        )?;
        let count = input
            .read(&mut buffer)
            .map_err(|_| CodexHandoffError::Transport)?;
        ensure_compatibility_deadline(
            deadline,
            CompatibilityTimeoutOrigin::ProbeStageCopyDurability,
        )?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(CodexHandoffError::Unsupported)?;
        if total > MAX_EXECUTABLE_BYTES || total > source.length {
            return Err(CodexHandoffError::Unsupported.into());
        }
        output
            .write_all(&buffer[..count])
            .map_err(|_| CodexHandoffError::Transport)?;
        ensure_compatibility_deadline(
            deadline,
            CompatibilityTimeoutOrigin::ProbeStageCopyDurability,
        )?;
        hasher.update(&buffer[..count]);
    }
    output
        .sync_all()
        .map_err(|_| CodexHandoffError::Transport)?;
    ensure_compatibility_deadline(
        deadline,
        CompatibilityTimeoutOrigin::ProbeStageCopyDurability,
    )?;
    let staged_metadata = executable_metadata(
        &output
            .metadata()
            .map_err(|_| CodexHandoffError::Transport)?,
    )?;
    let source_after =
        executable_metadata(&input.metadata().map_err(|_| CodexHandoffError::Transport)?)?;
    let source_visible = visible_executable_metadata(&source.canonical_path)?;
    let digest: [u8; 32] = hasher.finalize().into();
    if total != source.length
        || staged_metadata.length != source.length
        || staged_metadata.mode & 0o777 != 0o500
        || staged_metadata.uid != rustix::process::geteuid().as_raw()
        || staged_metadata.links != 1
        || source_after != before
        || source_visible != before
        || digest != source.digest
    {
        return Err(CodexHandoffError::Unsupported.into());
    }
    drop(output);
    directory.revalidate()?;
    scratch.revalidate()?;
    ensure_compatibility_deadline(
        deadline,
        CompatibilityTimeoutOrigin::ProbeStageCopyDurability,
    )?;

    check_pre_version_timeout_seam(CompatibilityTimeoutOrigin::ProbeStageRecapture)?;
    let staged = capture_executable_at_boundary(
        &directory.join(PROBE_EXECUTABLE_FILE),
        deadline,
        CompatibilityTimeoutOrigin::ProbeStageRecapture,
    )?;
    if staged.digest != source.digest || staged.length != source.length {
        return Err(CodexHandoffError::Unsupported.into());
    }
    Ok((directory, staged))
}

fn capture_executable_at_boundary(
    executable: &Path,
    deadline: Instant,
    origin: CompatibilityTimeoutOrigin,
) -> Result<CodexExecutableIdentity, CodexHandoffCause> {
    check_pre_version_timeout_seam(origin)?;
    ensure_compatibility_deadline(deadline, origin)?;
    let identity = capture_executable(executable, deadline)
        .map_err(|error| CodexHandoffCause::at_timeout_boundary(error, origin))?;
    ensure_compatibility_deadline(deadline, origin)?;
    Ok(identity)
}

fn ensure_compatibility_deadline(
    deadline: Instant,
    origin: CompatibilityTimeoutOrigin,
) -> Result<(), CodexHandoffCause> {
    if Instant::now() >= deadline {
        Err(CodexHandoffCause::timeout(origin))
    } else {
        Ok(())
    }
}

fn capture_executable(
    executable: &Path,
    deadline: Instant,
) -> Result<CodexExecutableIdentity, CodexHandoffError> {
    if !executable.is_absolute() {
        return Err(CodexHandoffError::Spawn);
    }
    let canonical_path = fs::canonicalize(executable).map_err(|_| CodexHandoffError::Spawn)?;
    let (mut file, before) = open_executable(&canonical_path)?;
    let digest = hash_executable(&mut file, Some(deadline))?;
    let after = executable_metadata(&file.metadata().map_err(|_| CodexHandoffError::Transport)?)?;
    let visible = visible_executable_metadata(&canonical_path)?;
    if before != after || before != visible {
        return Err(CodexHandoffError::Unsupported);
    }
    Ok(identity_from_metadata(canonical_path, before, digest))
}

fn revalidate_executable_metadata(
    expected: &CodexExecutableIdentity,
) -> Result<(), CodexHandoffError> {
    let (_file, actual) = open_executable(&expected.canonical_path)?;
    if actual == metadata_from_identity(expected) {
        Ok(())
    } else {
        Err(CodexHandoffError::Unsupported)
    }
}

fn revalidate_executable_until(
    expected: &CodexExecutableIdentity,
    deadline: Option<Instant>,
) -> Result<(), CodexHandoffError> {
    let (mut file, before) = open_executable(&expected.canonical_path)?;
    if before != metadata_from_identity(expected) {
        return Err(CodexHandoffError::Unsupported);
    }
    let digest = hash_executable(&mut file, deadline)?;
    let after = executable_metadata(&file.metadata().map_err(|_| CodexHandoffError::Transport)?)?;
    let visible = visible_executable_metadata(&expected.canonical_path)?;
    if before != after || before != visible || digest != expected.digest {
        return Err(CodexHandoffError::Unsupported);
    }
    Ok(())
}

fn open_executable(path: &Path) -> Result<(File, ExecutableMetadata), CodexHandoffError> {
    use rustix::fs::{Mode, OFlags, open};

    if fs::canonicalize(path).map_err(|_| CodexHandoffError::Spawn)? != path {
        return Err(CodexHandoffError::Unsupported);
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CodexHandoffError::Spawn)?;
    let file = File::from(descriptor);
    let opened = executable_metadata(&file.metadata().map_err(|_| CodexHandoffError::Transport)?)?;
    if opened != visible_executable_metadata(path)? {
        return Err(CodexHandoffError::Unsupported);
    }
    Ok((file, opened))
}

fn visible_executable_metadata(path: &Path) -> Result<ExecutableMetadata, CodexHandoffError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CodexHandoffError::Spawn)?;
    executable_metadata(&metadata)
}

fn executable_metadata(metadata: &fs::Metadata) -> Result<ExecutableMetadata, CodexHandoffError> {
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_EXECUTABLE_BYTES
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o6022 != 0
        || metadata.nlink() == 0
    {
        return Err(CodexHandoffError::Unsupported);
    }
    Ok(ExecutableMetadata {
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
    })
}

fn metadata_from_identity(identity: &CodexExecutableIdentity) -> ExecutableMetadata {
    ExecutableMetadata {
        device: identity.device,
        inode: identity.inode,
        length: identity.length,
        mode: identity.mode,
        uid: identity.uid,
        gid: identity.gid,
        links: identity.links,
        modified_seconds: identity.modified_seconds,
        modified_nanoseconds: identity.modified_nanoseconds,
        changed_seconds: identity.changed_seconds,
        changed_nanoseconds: identity.changed_nanoseconds,
    }
}

fn identity_from_metadata(
    canonical_path: PathBuf,
    metadata: ExecutableMetadata,
    digest: [u8; 32],
) -> CodexExecutableIdentity {
    CodexExecutableIdentity {
        canonical_path,
        device: metadata.device,
        inode: metadata.inode,
        length: metadata.length,
        mode: metadata.mode,
        uid: metadata.uid,
        gid: metadata.gid,
        links: metadata.links,
        modified_seconds: metadata.modified_seconds,
        modified_nanoseconds: metadata.modified_nanoseconds,
        changed_seconds: metadata.changed_seconds,
        changed_nanoseconds: metadata.changed_nanoseconds,
        digest,
    }
}

fn hash_executable(
    file: &mut File,
    deadline: Option<Instant>,
) -> Result<[u8; 32], CodexHandoffError> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(CodexHandoffError::Timeout);
        }
        let length = file
            .read(&mut buffer)
            .map_err(|_| CodexHandoffError::Transport)?;
        if length == 0 {
            break;
        }
        total = total
            .checked_add(length as u64)
            .ok_or(CodexHandoffError::Unsupported)?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(CodexHandoffError::Unsupported);
        }
        hasher.update(&buffer[..length]);
    }
    if total == 0 {
        return Err(CodexHandoffError::Unsupported);
    }
    Ok(hasher.finalize().into())
}

fn unix_address(socket_path: &Path) -> String {
    format!("unix://{}", socket_path.display())
}

fn revalidate_probe_roots(
    scratch: &ScratchRoot,
    source_home: &PrivateDirectory,
    target_home: &PrivateDirectory,
    workspace: &PrivateDirectory,
    environment_home: &PrivateDirectory,
) -> Result<(), CodexHandoffError> {
    scratch.revalidate()?;
    source_home.revalidate()?;
    target_home.revalidate()?;
    workspace.revalidate()?;
    environment_home.revalidate()
}

fn ensure_no_model_request(listener: &TcpListener) -> Result<(), CodexHandoffError> {
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Ok((stream, _)) => {
            let _ = stream;
            Err(CodexHandoffError::Protocol)
        }
        Err(_) => Err(CodexHandoffError::Protocol),
    }
}

fn generate_and_validate_schemas(
    executable: &CodexExecutableIdentity,
    codex_home: &PrivateDirectory,
    environment_home: &PrivateDirectory,
    working_directory: &PrivateDirectory,
    scratch: &ScratchRoot,
    target_config: &TargetConfigProof,
    deadline: Instant,
) -> Result<HandoffSchemaContract, CodexHandoffError> {
    let default_output = create_private_directory(&scratch.path().join("sd"))?;
    let experimental_output = create_private_directory(&scratch.path().join("se"))?;
    for (output, experimental) in [(&default_output, false), (&experimental_output, true)] {
        revalidate_executable_metadata(executable)?;
        let mut command = isolated_command(
            &executable.canonical_path,
            codex_home.as_ref(),
            environment_home.as_ref(),
        );
        command.args(["app-server", "generate-json-schema"]);
        if experimental {
            command.arg("--experimental");
        }
        command.arg("--out").arg(output.as_os_str());
        run_to_success(command, working_directory.as_ref(), deadline)?;
        scratch.revalidate()?;
        codex_home.revalidate()?;
        environment_home.revalidate()?;
        working_directory.revalidate()?;
        target_config.revalidate(codex_home)?;
        revalidate_executable_metadata(executable)?;
        output.revalidate()?;
    }

    default_output.revalidate()?;
    experimental_output.revalidate()?;
    let default_schema = default_output.read_relative_json(SCHEMA_FILE)?;
    let default_error = default_output.read_relative_json(JSONRPC_ERROR_FILE)?;
    let default_error_body = default_output.read_relative_json(JSONRPC_ERROR_BODY_FILE)?;
    let experimental_schema = experimental_output.read_relative_json(SCHEMA_FILE)?;
    let experimental_error = experimental_output.read_relative_json(JSONRPC_ERROR_FILE)?;
    let experimental_error_body =
        experimental_output.read_relative_json(JSONRPC_ERROR_BODY_FILE)?;
    validate_handoff_schema_pair(
        &default_schema,
        &experimental_schema,
        &default_error,
        &default_error_body,
        &experimental_error,
        &experimental_error_body,
    )
    .map_err(|_| CodexHandoffError::Protocol)
}

fn fork_synthetic_rollout(
    executable: &CodexExecutableIdentity,
    source_home: &PrivateDirectory,
    target_home: &PrivateDirectory,
    environment_home: &PrivateDirectory,
    workspace: &PrivateDirectory,
    deadline: Instant,
) -> Result<ForkProof, CodexHandoffError> {
    let source_thread_id = Uuid::new_v4().to_string();
    let source_rollout = write_source_rollout(source_home, workspace.as_ref(), &source_thread_id)?;
    let source_rollout_relative = source_rollout
        .strip_prefix(source_home.as_ref())
        .map(Path::to_path_buf)
        .map_err(|_| CodexHandoffError::Protocol)?;
    let source_before = FileFingerprint::read_relative(
        source_home,
        &source_rollout_relative,
        MAX_ROLLOUT_PROBE_BYTES,
        FilePolicy::Private,
    )?;

    revalidate_executable_metadata(executable)?;
    let mut command = isolated_command(
        &executable.canonical_path,
        target_home.as_ref(),
        environment_home.as_ref(),
    );
    command.args(["app-server", "--stdio"]);
    let mut process = AppServerProcess::spawn_command(command, workspace.as_ref(), None)
        .map_err(map_usage_error)?;
    #[cfg(test)]
    eprintln!("handoff probe: fork app-server spawned");
    process
        .send(&json!({
            "id": INITIALIZE_REQUEST_ID,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "calcifer",
                    "title": "Calcifer compatibility probe",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": {
                    "experimentalApi": true
                }
            }
        }))
        .map_err(map_usage_error)?;
    #[cfg(test)]
    eprintln!("handoff probe: initialize request sent");
    let initialize = process
        .receive_result(INITIALIZE_REQUEST_ID, deadline)
        .map_err(map_usage_error)?;
    #[cfg(test)]
    eprintln!("handoff probe: initialize response received");
    let version = validate_initialize_result(initialize, target_home.as_ref())
        .map_err(|error| map_usage_error(error.kind))?;
    if version != SUPPORTED_VERSION {
        return Err(CodexHandoffError::Unsupported);
    }

    process
        .send(&json!({
            "id": FORK_REQUEST_ID,
            "method": "thread/fork",
            "params": {
                "threadId": "",
                "path": source_rollout,
                "cwd": workspace.as_ref(),
                "model": MODEL_NAME,
                "modelProvider": MODEL_PROVIDER,
                "approvalPolicy": "never",
                "sandbox": "read-only",
                "ephemeral": false
            }
        }))
        .map_err(map_usage_error)?;
    #[cfg(test)]
    eprintln!("handoff probe: fork request sent");
    let result = process
        .receive_result(FORK_REQUEST_ID, deadline)
        .map_err(map_usage_error)?;
    #[cfg(test)]
    eprintln!("handoff probe: fork response received");
    let fork = validate_fork_result(
        &result,
        &source_thread_id,
        source_rollout_relative,
        source_before,
        target_home,
        workspace,
    )?;
    #[cfg(test)]
    eprintln!("handoff probe: fork response validation passed");
    let shutdown_deadline = Instant::now()
        .checked_add(COMPLETED_REQUEST_SHUTDOWN_TIMEOUT)
        .ok_or(CodexHandoffError::Timeout)?
        .min(deadline);
    process
        .shutdown_after_completed_request_until(shutdown_deadline)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::TimedOut {
                CodexHandoffError::Timeout
            } else {
                CodexHandoffError::Transport
            }
        })?;
    #[cfg(test)]
    eprintln!("handoff probe: fork app-server shut down");
    source_home.revalidate()?;
    target_home.revalidate()?;
    environment_home.revalidate()?;
    workspace.revalidate()?;
    revalidate_executable_metadata(executable)?;
    fork.revalidate(source_home, target_home)?;
    #[cfg(test)]
    eprintln!("handoff probe: source and target fingerprints remained stable");
    Ok(fork)
}

fn validate_fork_result(
    result: &Value,
    source_thread_id: &str,
    source_rollout_relative: PathBuf,
    source_fingerprint: FileFingerprint,
    target_home: &PrivateDirectory,
    workspace: &PrivateDirectory,
) -> Result<ForkProof, CodexHandoffError> {
    let result_object = result.as_object().ok_or(CodexHandoffError::Protocol)?;
    let canonical_workspace = workspace.as_ref();
    let response_cwd = result_object
        .get("cwd")
        .and_then(Value::as_str)
        .ok_or(CodexHandoffError::Protocol)?;
    let sandbox = result_object
        .get("sandbox")
        .and_then(Value::as_object)
        .ok_or(CodexHandoffError::Protocol)?;
    if result_object.get("model").and_then(Value::as_str) != Some(MODEL_NAME)
        || result_object.get("modelProvider").and_then(Value::as_str) != Some(MODEL_PROVIDER)
        || result_object.get("approvalPolicy").and_then(Value::as_str) != Some("never")
        || result_object
            .get("approvalsReviewer")
            .and_then(Value::as_str)
            != Some("user")
        || sandbox.len() != 2
        || sandbox.get("type").and_then(Value::as_str) != Some("readOnly")
        || sandbox.get("networkAccess").and_then(Value::as_bool) != Some(false)
        || fs::canonicalize(response_cwd).map_err(|_| CodexHandoffError::Protocol)?
            != canonical_workspace
    {
        return Err(CodexHandoffError::Protocol);
    }
    let thread = result
        .get("thread")
        .and_then(Value::as_object)
        .ok_or(CodexHandoffError::Protocol)?;
    let target_thread_id = thread
        .get("id")
        .and_then(Value::as_str)
        .ok_or(CodexHandoffError::Protocol)?;
    let source_thread_uuid =
        Uuid::parse_str(source_thread_id).map_err(|_| CodexHandoffError::Protocol)?;
    let target_thread_uuid =
        Uuid::parse_str(target_thread_id).map_err(|_| CodexHandoffError::Protocol)?;
    if target_thread_uuid.to_string() != target_thread_id
        || target_thread_uuid == source_thread_uuid
        || thread.get("forkedFromId").and_then(Value::as_str) != Some(source_thread_id)
        || thread.get("cliVersion").and_then(Value::as_str) != Some(SUPPORTED_VERSION)
        || thread.get("modelProvider").and_then(Value::as_str) != Some(MODEL_PROVIDER)
        || thread.get("preview").and_then(Value::as_str) != Some(HISTORY_SENTINEL)
        || thread
            .get("turns")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        return Err(CodexHandoffError::Protocol);
    }

    let thread_cwd = thread
        .get("cwd")
        .and_then(Value::as_str)
        .ok_or(CodexHandoffError::Protocol)?;
    if fs::canonicalize(thread_cwd).map_err(|_| CodexHandoffError::Protocol)? != canonical_workspace
    {
        return Err(CodexHandoffError::Protocol);
    }

    let target_rollout = thread
        .get("path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or(CodexHandoffError::Protocol)?;
    if !target_rollout.is_absolute() {
        return Err(CodexHandoffError::Protocol);
    }
    let target_rollout_relative = target_rollout
        .strip_prefix(target_home.as_ref())
        .map(Path::to_path_buf)
        .map_err(|_| CodexHandoffError::Protocol)?;
    let components = safe_relative_components(&target_rollout_relative)?;
    if components.first().copied() != Some(OsStr::new("sessions")) || components.len() < 2 {
        return Err(CodexHandoffError::Protocol);
    }
    let (target_bytes, target_metadata) = target_home.read_relative_file(
        &target_rollout_relative,
        MAX_ROLLOUT_PROBE_BYTES,
        FilePolicy::OwnedReadOnly,
    )?;
    if fs::canonicalize(&target_rollout).map_err(|_| CodexHandoffError::Protocol)? != target_rollout
        || !target_bytes
            .windows(HISTORY_SENTINEL.len())
            .any(|window| window == HISTORY_SENTINEL.as_bytes())
    {
        return Err(CodexHandoffError::Protocol);
    }
    let target_fingerprint =
        FileFingerprint::from_bytes_and_metadata(target_bytes, target_metadata)?;

    Ok(ForkProof {
        source_rollout_relative,
        source_fingerprint,
        source_thread_id: source_thread_id.to_owned(),
        target_thread_id: target_thread_id.to_owned(),
        target_rollout_relative,
        target_fingerprint,
        target_home: target_home.as_ref().to_path_buf(),
        workspace: canonical_workspace.to_path_buf(),
    })
}

fn write_source_rollout(
    source_home: &PrivateDirectory,
    workspace: &Path,
    source_thread_id: &str,
) -> Result<PathBuf, CodexHandoffError> {
    let directory = Path::new("sessions/2026/07/15");
    source_home.create_relative_directories(directory)?;
    let relative = directory.join(format!(
        "rollout-{SOURCE_FILENAME_TIMESTAMP}-{source_thread_id}.jsonl"
    ));
    let mut contents = Vec::new();
    for line in [
        json!({
            "timestamp": SOURCE_TIMESTAMP,
            "type": "session_meta",
            "payload": {
                "id": source_thread_id,
                "session_id": source_thread_id,
                "timestamp": SOURCE_TIMESTAMP,
                "cwd": workspace,
                "originator": "codex",
                "cli_version": SUPPORTED_VERSION,
                "source": "cli",
                "model_provider": MODEL_PROVIDER,
                "parent_thread_id": null
            }
        }),
        json!({
            "timestamp": SOURCE_TIMESTAMP,
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{ "type": "input_text", "text": HISTORY_SENTINEL }]
            }
        }),
        json!({
            "timestamp": SOURCE_TIMESTAMP,
            "type": "event_msg",
            "payload": {
                "type": "user_message",
                "message": HISTORY_SENTINEL,
                "kind": "plain"
            }
        }),
    ] {
        serde_json::to_writer(&mut contents, &line).map_err(|_| CodexHandoffError::Transport)?;
        contents
            .write_all(b"\n")
            .map_err(|_| CodexHandoffError::Transport)?;
    }
    source_home.write_relative_new(&relative, &contents)?;
    Ok(source_home.join(relative))
}

fn write_target_config(
    target_home: &PrivateDirectory,
    model_address: std::net::SocketAddr,
) -> Result<TargetConfigProof, CodexHandoffError> {
    let catalog_relative = PathBuf::from("model-catalog.json");
    let catalog_path = target_home.join(&catalog_relative);
    let catalog = json!({
        "models": [{
            "slug": MODEL_NAME,
            "display_name": "Calcifer compatibility probe",
            "description": null,
            "default_reasoning_level": "medium",
            "supported_reasoning_levels": [{
                "effort": "medium",
                "description": "Compatibility probe"
            }],
            "shell_type": "shell_command",
            "visibility": "list",
            "supported_in_api": true,
            "priority": 0,
            "availability_nux": null,
            "upgrade": null,
            "base_instructions": "Calcifer compatibility probe",
            "model_messages": null,
            "supports_reasoning_summaries": false,
            "default_reasoning_summary": "none",
            "support_verbosity": false,
            "default_verbosity": null,
            "apply_patch_tool_type": "freeform",
            "truncation_policy": { "mode": "tokens", "limit": 10_000 },
            "supports_parallel_tool_calls": false,
            "context_window": 200_000,
            "experimental_supported_tools": []
        }]
    });
    let catalog_bytes = serde_json::to_vec(&catalog).map_err(|_| CodexHandoffError::Protocol)?;
    target_home.write_relative_new(&catalog_relative, &catalog_bytes)?;
    let contents = format!(
        r#"model = "{MODEL_NAME}"
model_provider = "{MODEL_PROVIDER}"
model_catalog_json = "{}"
personality = "pragmatic"
approval_policy = "never"
sandbox_mode = "read-only"
cli_auth_credentials_store = "file"
mcp_oauth_credentials_store = "file"
check_for_update_on_startup = false

[analytics]
enabled = false

[otel]
exporter = "none"
trace_exporter = "none"
metrics_exporter = "none"

[tui]
show_tooltips = false

[features]
shell_snapshot = false
apps = false
plugins = false
remote_plugin = false

[model_providers.{MODEL_PROVIDER}]
name = "Calcifer compatibility probe"
base_url = "http://{model_address}/v1"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
supports_websockets = false
requires_openai_auth = false
"#,
        catalog_path.display()
    );
    let config_relative = PathBuf::from("config.toml");
    target_home.write_relative_new(&config_relative, contents.as_bytes())?;
    Ok(TargetConfigProof {
        catalog_fingerprint: FileFingerprint::read_relative(
            target_home,
            &catalog_relative,
            MAX_SCHEMA_BYTES,
            FilePolicy::Private,
        )?,
        config_fingerprint: FileFingerprint::read_relative(
            target_home,
            &config_relative,
            MAX_SCHEMA_BYTES,
            FilePolicy::Private,
        )?,
        catalog_relative,
        config_relative,
    })
}

struct TargetConfigProof {
    catalog_relative: PathBuf,
    catalog_fingerprint: FileFingerprint,
    config_relative: PathBuf,
    config_fingerprint: FileFingerprint,
}

impl TargetConfigProof {
    fn revalidate(&self, target_home: &PrivateDirectory) -> Result<(), CodexHandoffError> {
        if FileFingerprint::read_relative(
            target_home,
            &self.catalog_relative,
            MAX_SCHEMA_BYTES,
            FilePolicy::Private,
        )? != self.catalog_fingerprint
            || FileFingerprint::read_relative(
                target_home,
                &self.config_relative,
                MAX_SCHEMA_BYTES,
                FilePolicy::Private,
            )? != self.config_fingerprint
        {
            return Err(CodexHandoffError::Protocol);
        }
        Ok(())
    }
}

fn isolated_command(
    codex_executable: &Path,
    codex_home: &Path,
    environment_home: &Path,
) -> Command {
    let mut command = Command::new(codex_executable);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("SHELL", "/bin/sh")
        .env("TERM", "xterm-256color")
        .env("CODEX_HOME", codex_home)
        .env("HOME", environment_home)
        .env("XDG_CONFIG_HOME", environment_home.join("config"))
        .env("XDG_DATA_HOME", environment_home.join("data"))
        .env("XDG_CACHE_HOME", environment_home.join("cache"))
        .env("XDG_RUNTIME_DIR", environment_home.join("run"))
        .env("TMPDIR", environment_home.join("tmp"))
        .env("TMP", environment_home.join("tmp"))
        .env("TEMP", environment_home.join("tmp"));
    command
}

fn run_to_success(
    mut command: Command,
    working_directory: &Path,
    deadline: Instant,
) -> Result<(), CodexHandoffError> {
    configure_own_process_group(&mut command);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(working_directory)
        .spawn()
        .map_err(|_| CodexHandoffError::Spawn)?;
    wait_for_success(&mut child, deadline)
}

fn wait_for_success(child: &mut Child, deadline: Instant) -> Result<(), CodexHandoffError> {
    loop {
        match child_exit_observed_without_reaping(child) {
            Ok(true) => {
                let status =
                    reap_exited_process_tree(child).map_err(|_| CodexHandoffError::Transport)?;
                return if status.success() {
                    Ok(())
                } else {
                    Err(CodexHandoffError::Transport)
                };
            }
            Err(_) => {
                force_terminate_process_tree(child).map_err(|_| CodexHandoffError::Transport)?;
                return Err(CodexHandoffError::Transport);
            }
            Ok(false) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(false) => {
                force_terminate_process_tree(child).map_err(|_| CodexHandoffError::Transport)?;
                return Err(CodexHandoffError::Timeout);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum FilePolicy {
    Private,
    OwnedReadOnly,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileNodeMetadata {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn file_node_metadata(
    metadata: &fs::Metadata,
    policy: FilePolicy,
) -> Result<FileNodeMetadata, CodexHandoffError> {
    let unsafe_mode = match policy {
        FilePolicy::Private => metadata.mode() & 0o077 != 0,
        FilePolicy::OwnedReadOnly => metadata.mode() & 0o022 != 0,
    };
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || unsafe_mode
    {
        return Err(CodexHandoffError::Protocol);
    }
    Ok(FileNodeMetadata {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn ensure_no_credentials(root: &Path) -> Result<(), CodexHandoffError> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|_| CodexHandoffError::Transport)? {
            let entry = entry.map_err(|_| CodexHandoffError::Transport)?;
            visited = visited.saturating_add(1);
            if visited > MAX_SCRATCH_NODES {
                return Err(CodexHandoffError::Protocol);
            }
            let file_type = entry
                .file_type()
                .map_err(|_| CodexHandoffError::Transport)?;
            if entry.file_name() == "auth.json" || entry.file_name() == ".credentials.json" {
                return Err(CodexHandoffError::Protocol);
            }
            if file_type.is_symlink() {
                continue;
            } else if file_type.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, CodexHandoffError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or(CodexHandoffError::Timeout)
}

fn map_usage_error(error: CodexUsageError) -> CodexHandoffError {
    match error {
        CodexUsageError::Unsupported | CodexUsageError::Authentication => {
            CodexHandoffError::Unsupported
        }
        CodexUsageError::Protocol | CodexUsageError::Provider => CodexHandoffError::Protocol,
        CodexUsageError::Timeout => CodexHandoffError::Timeout,
        CodexUsageError::Transport => CodexHandoffError::Transport,
        CodexUsageError::Spawn => CodexHandoffError::Spawn,
    }
}

fn map_version_probe_failure(error: CodexVersionProbeFailure) -> CodexHandoffCause {
    let cleanup_error = error.cleanup_error().map(map_thread_error);
    match error.timeout_origin() {
        Some(CodexVersionProbeTimeoutOrigin::ChildExit) => CodexHandoffCause::timeout_with_cleanup(
            CompatibilityTimeoutOrigin::VersionChildExit,
            cleanup_error,
        ),
        Some(CodexVersionProbeTimeoutOrigin::StdoutDrain) => {
            CodexHandoffCause::timeout_with_cleanup(
                CompatibilityTimeoutOrigin::VersionStdoutDrain,
                cleanup_error,
            )
        }
        None => map_thread_error(error.error()).into(),
    }
}

fn map_thread_error(error: CodexThreadError) -> CodexHandoffError {
    match error {
        CodexThreadError::UnsupportedVersion | CodexThreadError::Authentication => {
            CodexHandoffError::Unsupported
        }
        CodexThreadError::Timeout => CodexHandoffError::Timeout,
        CodexThreadError::Transport => CodexHandoffError::Transport,
        CodexThreadError::Spawn => CodexHandoffError::Spawn,
        CodexThreadError::Protocol
        | CodexThreadError::CwdMismatch
        | CodexThreadError::Provider
        | CodexThreadError::Missing
        | CodexThreadError::Archived
        | CodexThreadError::SessionSchema => CodexHandoffError::Protocol,
    }
}

fn create_private_directory(path: &Path) -> Result<PrivateDirectory, CodexHandoffError> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| CodexHandoffError::Transport)?;
    PrivateDirectory::capture(path)
}

fn verify_private_directory(path: &Path) -> Result<(), CodexHandoffError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CodexHandoffError::Transport)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(CodexHandoffError::Protocol);
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

struct PrivateDirectory {
    path: PathBuf,
    identity: DirectoryIdentity,
    descriptor: File,
}

impl PrivateDirectory {
    fn capture(path: &Path) -> Result<Self, CodexHandoffError> {
        verify_private_directory(path)?;
        let canonical_path = fs::canonicalize(path).map_err(|_| CodexHandoffError::Transport)?;
        let metadata =
            fs::symlink_metadata(&canonical_path).map_err(|_| CodexHandoffError::Transport)?;
        verify_private_directory(&canonical_path)?;
        let descriptor = rustix::fs::open(
            &canonical_path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| CodexHandoffError::Transport)?;
        let identity = DirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        };
        if directory_identity(
            &descriptor
                .metadata()
                .map_err(|_| CodexHandoffError::Transport)?,
            true,
        )? != identity
        {
            return Err(CodexHandoffError::Protocol);
        }
        Ok(Self {
            path: canonical_path,
            identity,
            descriptor,
        })
    }

    fn revalidate(&self) -> Result<(), CodexHandoffError> {
        if fs::canonicalize(&self.path).map_err(|_| CodexHandoffError::Protocol)? != self.path {
            return Err(CodexHandoffError::Protocol);
        }
        let visible = fs::symlink_metadata(&self.path).map_err(|_| CodexHandoffError::Protocol)?;
        let opened = self
            .descriptor
            .metadata()
            .map_err(|_| CodexHandoffError::Transport)?;
        if directory_identity(&visible, true)? != self.identity
            || directory_identity(&opened, true)? != self.identity
        {
            return Err(CodexHandoffError::Protocol);
        }
        Ok(())
    }

    fn read_relative_file(
        &self,
        relative: &Path,
        limit: u64,
        policy: FilePolicy,
    ) -> Result<(Vec<u8>, FileNodeMetadata), CodexHandoffError> {
        self.revalidate()?;
        let components = safe_relative_components(relative)?;
        let (file_name, parents) = components.split_last().ok_or(CodexHandoffError::Protocol)?;
        let mut directory = self
            .descriptor
            .try_clone()
            .map_err(|_| CodexHandoffError::Transport)?;
        for component in parents {
            let descriptor = rustix::fs::openat(
                &directory,
                *component,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| CodexHandoffError::Protocol)?;
            let next = File::from(descriptor);
            directory_identity(
                &next.metadata().map_err(|_| CodexHandoffError::Transport)?,
                false,
            )?;
            directory = next;
        }
        let descriptor = rustix::fs::openat(
            &directory,
            *file_name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| CodexHandoffError::Protocol)?;
        let mut file = File::from(descriptor);
        let before = file_node_metadata(
            &file.metadata().map_err(|_| CodexHandoffError::Transport)?,
            policy,
        )?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| CodexHandoffError::Transport)?;
        if bytes.len() as u64 > limit {
            return Err(CodexHandoffError::Protocol);
        }
        let after = file_node_metadata(
            &file.metadata().map_err(|_| CodexHandoffError::Transport)?,
            policy,
        )?;
        self.revalidate()?;
        if before != after {
            return Err(CodexHandoffError::Protocol);
        }
        Ok((bytes, before))
    }

    fn read_relative_json(&self, relative: &str) -> Result<Value, CodexHandoffError> {
        let (bytes, _) = self.read_relative_file(
            Path::new(relative),
            MAX_SCHEMA_BYTES,
            FilePolicy::OwnedReadOnly,
        )?;
        serde_json::from_slice(&bytes).map_err(|_| CodexHandoffError::Protocol)
    }

    fn create_relative_directories(&self, relative: &Path) -> Result<(), CodexHandoffError> {
        self.revalidate()?;
        let components = safe_relative_components(relative)?;
        let mut directory = self
            .descriptor
            .try_clone()
            .map_err(|_| CodexHandoffError::Transport)?;
        for component in components {
            match rustix::fs::mkdirat(
                &directory,
                component,
                rustix::fs::Mode::from_raw_mode(0o700),
            ) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(_) => return Err(CodexHandoffError::Transport),
            }
            let descriptor = rustix::fs::openat(
                &directory,
                component,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| CodexHandoffError::Protocol)?;
            let next = File::from(descriptor);
            directory_identity(
                &next.metadata().map_err(|_| CodexHandoffError::Transport)?,
                false,
            )?;
            directory = next;
        }
        self.revalidate()
    }

    fn write_relative_new(
        &self,
        relative: &Path,
        contents: &[u8],
    ) -> Result<(), CodexHandoffError> {
        self.revalidate()?;
        let components = safe_relative_components(relative)?;
        let (file_name, parents) = components.split_last().ok_or(CodexHandoffError::Protocol)?;
        let mut directory = self
            .descriptor
            .try_clone()
            .map_err(|_| CodexHandoffError::Transport)?;
        for component in parents {
            let descriptor = rustix::fs::openat(
                &directory,
                *component,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| CodexHandoffError::Protocol)?;
            let next = File::from(descriptor);
            directory_identity(
                &next.metadata().map_err(|_| CodexHandoffError::Transport)?,
                false,
            )?;
            directory = next;
        }
        let descriptor = rustix::fs::openat(
            &directory,
            *file_name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(|_| CodexHandoffError::Transport)?;
        let mut file = File::from(descriptor);
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|_| CodexHandoffError::Transport)?;
        file_node_metadata(
            &file.metadata().map_err(|_| CodexHandoffError::Transport)?,
            FilePolicy::Private,
        )?;
        self.revalidate()
    }
}

fn safe_relative_components(relative: &Path) -> Result<Vec<&OsStr>, CodexHandoffError> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(CodexHandoffError::Protocol);
    }
    relative
        .components()
        .map(|component| match component {
            Component::Normal(name) if !name.is_empty() => Ok(name),
            _ => Err(CodexHandoffError::Protocol),
        })
        .collect()
}

fn directory_identity(
    metadata: &fs::Metadata,
    private_root: bool,
) -> Result<DirectoryIdentity, CodexHandoffError> {
    let unsafe_mode = if private_root {
        metadata.mode() & 0o077 != 0
    } else {
        metadata.mode() & 0o022 != 0
    };
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || unsafe_mode
    {
        return Err(CodexHandoffError::Protocol);
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
    })
}

impl Deref for PrivateDirectory {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<Path> for PrivateDirectory {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileFingerprint {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    digest: [u8; 32],
}

impl FileFingerprint {
    fn read_relative(
        root: &PrivateDirectory,
        relative: &Path,
        limit: u64,
        policy: FilePolicy,
    ) -> Result<Self, CodexHandoffError> {
        let (bytes, metadata) = root.read_relative_file(relative, limit, policy)?;
        Self::from_bytes_and_metadata(bytes, metadata)
    }

    fn from_bytes_and_metadata(
        bytes: Vec<u8>,
        metadata: FileNodeMetadata,
    ) -> Result<Self, CodexHandoffError> {
        let digest: [u8; 32] = Sha256::digest(bytes)
            .as_slice()
            .try_into()
            .map_err(|_| CodexHandoffError::Protocol)?;
        Ok(Self {
            device: metadata.device,
            inode: metadata.inode,
            length: metadata.length,
            mode: metadata.mode,
            uid: metadata.uid,
            links: metadata.links,
            modified_seconds: metadata.modified_seconds,
            modified_nanoseconds: metadata.modified_nanoseconds,
            changed_seconds: metadata.changed_seconds,
            changed_nanoseconds: metadata.changed_nanoseconds,
            digest,
        })
    }
}

struct ScratchRoot {
    path: PathBuf,
    identity: ScratchIdentity,
    descriptor: File,
    parent_path: PathBuf,
    parent_identity: ScratchParentIdentity,
    parent_descriptor: File,
    cleanup_state: ScratchRootCleanupState,
    cleanup_first_error: Option<CodexHandoffError>,
    #[cfg(test)]
    fail_next_sync: std::cell::Cell<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScratchRootCleanupState {
    Active,
    RootRemovedPendingParentSync,
    Cleaned,
    Preserved,
}

#[derive(Clone, Copy)]
struct ScratchIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

#[derive(Clone, Copy)]
struct ScratchParentIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScratchRootCleanupComplete {
    _private: (),
}

#[must_use = "scratch cleanup failure retains the exact root owner"]
pub(super) struct ScratchRootCleanupFailure {
    root: ScratchRoot,
    error: CodexHandoffError,
}

impl ScratchRootCleanupFailure {
    const fn error(&self) -> CodexHandoffError {
        self.error
    }

    #[cfg(test)]
    fn into_root(self) -> ScratchRoot {
        self.root
    }
}

impl fmt::Debug for ScratchRootCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.root;
        formatter
            .debug_struct("ScratchRootCleanupFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[must_use = "scratch creation can retain a created path requiring ownership"]
pub(super) struct ScratchRootCreateFailure {
    error: CodexHandoffError,
    retained: Option<ScratchRootRetention>,
}

enum ScratchRootRetention {
    Open(Box<ScratchRoot>),
    Partial(Box<PartialScratchRoot>),
}

impl fmt::Debug for ScratchRootRetention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(root) => {
                let _ = root;
                formatter.write_str("ScratchRootRetention::Open(<redacted>)")
            }
            Self::Partial(root) => {
                let _ = root;
                formatter.write_str("ScratchRootRetention::Partial(<redacted>)")
            }
        }
    }
}

struct PartialScratchRoot {
    path: PathBuf,
    parent_path: PathBuf,
    parent_identity: ScratchParentIdentity,
    parent_descriptor: File,
}

impl ScratchRootCreateFailure {
    const fn not_created(error: CodexHandoffError) -> Self {
        Self {
            error,
            retained: None,
        }
    }

    fn with_root(error: CodexHandoffError, mut root: ScratchRoot) -> Self {
        root.preserve();
        Self {
            error,
            retained: Some(ScratchRootRetention::Open(Box::new(root))),
        }
    }

    fn with_partial(
        error: CodexHandoffError,
        path: PathBuf,
        parent_path: PathBuf,
        parent_identity: ScratchParentIdentity,
        parent_descriptor: File,
    ) -> Self {
        Self {
            error,
            retained: Some(ScratchRootRetention::Partial(Box::new(
                PartialScratchRoot {
                    path,
                    parent_path,
                    parent_identity,
                    parent_descriptor,
                },
            ))),
        }
    }

    const fn error(&self) -> CodexHandoffError {
        self.error
    }

    #[cfg(test)]
    fn retained_path(&self) -> Option<&Path> {
        match self.retained.as_ref()? {
            ScratchRootRetention::Open(root) => Some(root.path()),
            ScratchRootRetention::Partial(root) => Some(&root.path),
        }
    }
}

impl From<CodexHandoffError> for ScratchRootCreateFailure {
    fn from(error: CodexHandoffError) -> Self {
        Self::not_created(error)
    }
}

impl fmt::Display for ScratchRootCreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl fmt::Debug for ScratchRootCreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ScratchRootRetention::Partial(root)) = &self.retained {
            let _ = (
                &root.path,
                &root.parent_path,
                root.parent_identity,
                &root.parent_descriptor,
            );
        }
        formatter
            .debug_struct("ScratchRootCreateFailure")
            .field("error", &self.error)
            .field("created", &self.retained.is_some())
            .finish_non_exhaustive()
    }
}

impl std::error::Error for ScratchRootCreateFailure {}

impl ScratchRoot {
    fn create() -> Result<Self, ScratchRootCreateFailure> {
        Self::create_below(Path::new("/tmp"), false, false)
    }

    #[cfg(test)]
    fn create_in(parent: &Path) -> Result<Self, ScratchRootCreateFailure> {
        Self::create_below(parent, true, false)
    }

    #[cfg(test)]
    fn create_in_with_sync_failure(parent: &Path) -> Result<Self, ScratchRootCreateFailure> {
        let root = Self::create_below(parent, true, false)?;
        root.fail_next_sync.set(true);
        Ok(root)
    }

    #[cfg(test)]
    fn create_in_with_parent_sync_failure(parent: &Path) -> Result<Self, ScratchRootCreateFailure> {
        Self::create_below(parent, true, true)
    }

    fn create_below(
        parent: &Path,
        require_private_parent: bool,
        fail_parent_sync_for_test: bool,
    ) -> Result<Self, ScratchRootCreateFailure> {
        let canonical_parent =
            fs::canonicalize(parent).map_err(|_| CodexHandoffError::Transport)?;
        if require_private_parent {
            verify_private_directory(parent)?;
            if canonical_parent != parent {
                return Err(CodexHandoffError::Protocol.into());
            }
        }
        let parent_visible =
            fs::symlink_metadata(&canonical_parent).map_err(|_| CodexHandoffError::Transport)?;
        if !parent_visible.file_type().is_dir() {
            return Err(CodexHandoffError::Protocol.into());
        }
        let parent_descriptor = rustix::fs::open(
            &canonical_parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| CodexHandoffError::Transport)?;
        let parent_opened = parent_descriptor
            .metadata()
            .map_err(|_| CodexHandoffError::Transport)?;
        if !parent_opened.file_type().is_dir()
            || parent_opened.dev() != parent_visible.dev()
            || parent_opened.ino() != parent_visible.ino()
        {
            return Err(CodexHandoffError::Protocol.into());
        }
        let parent_identity = ScratchParentIdentity {
            device: parent_visible.dev(),
            inode: parent_visible.ino(),
        };
        for _ in 0..4 {
            let path =
                canonical_parent.join(format!("cfh-{}-{}", std::process::id(), Uuid::new_v4()));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    if let Err(error) = verify_private_directory(&path) {
                        return Err(ScratchRootCreateFailure::with_partial(
                            error,
                            path,
                            canonical_parent,
                            parent_identity,
                            parent_descriptor,
                        ));
                    }
                    let path = match fs::canonicalize(&path) {
                        Ok(path) => path,
                        Err(_) => {
                            return Err(ScratchRootCreateFailure::with_partial(
                                CodexHandoffError::Transport,
                                path,
                                canonical_parent,
                                parent_identity,
                                parent_descriptor,
                            ));
                        }
                    };
                    if let Err(error) = verify_private_directory(&path) {
                        return Err(ScratchRootCreateFailure::with_partial(
                            error,
                            path,
                            canonical_parent,
                            parent_identity,
                            parent_descriptor,
                        ));
                    }
                    let metadata = match fs::symlink_metadata(&path) {
                        Ok(metadata) => metadata,
                        Err(_) => {
                            return Err(ScratchRootCreateFailure::with_partial(
                                CodexHandoffError::Transport,
                                path,
                                canonical_parent,
                                parent_identity,
                                parent_descriptor,
                            ));
                        }
                    };
                    let descriptor = match rustix::fs::open(
                        &path,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    ) {
                        Ok(descriptor) => File::from(descriptor),
                        Err(_) => {
                            return Err(ScratchRootCreateFailure::with_partial(
                                CodexHandoffError::Transport,
                                path,
                                canonical_parent,
                                parent_identity,
                                parent_descriptor,
                            ));
                        }
                    };
                    let root = Self {
                        path,
                        identity: ScratchIdentity {
                            device: metadata.dev(),
                            inode: metadata.ino(),
                            uid: metadata.uid(),
                        },
                        descriptor,
                        parent_path: canonical_parent,
                        parent_identity,
                        parent_descriptor,
                        cleanup_state: ScratchRootCleanupState::Active,
                        cleanup_first_error: None,
                        #[cfg(test)]
                        fail_next_sync: std::cell::Cell::new(false),
                    };
                    // Persist the new scratch-root directory entry before any
                    // staged child is published. A failed parent fsync leaves
                    // its exact open identity in the returned failure.
                    if fail_parent_sync_for_test || root.parent_descriptor.sync_all().is_err() {
                        return Err(ScratchRootCreateFailure::with_root(
                            CodexHandoffError::Transport,
                            root,
                        ));
                    }
                    return Ok(root);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(CodexHandoffError::Transport.into()),
            }
        }
        Err(CodexHandoffError::Transport.into())
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn create_directory(&self, relative: &str) -> Result<PrivateDirectory, CodexHandoffError> {
        let path = self.path.join(relative);
        create_private_directory(&path)
    }

    fn revalidate(&self) -> Result<(), CodexHandoffError> {
        if fs::canonicalize(&self.path).map_err(|_| CodexHandoffError::Protocol)? != self.path {
            return Err(CodexHandoffError::Protocol);
        }
        let metadata = fs::symlink_metadata(&self.path).map_err(|_| CodexHandoffError::Protocol)?;
        let opened = self
            .descriptor
            .metadata()
            .map_err(|_| CodexHandoffError::Transport)?;
        if !metadata.file_type().is_dir()
            || metadata.dev() != self.identity.device
            || metadata.ino() != self.identity.inode
            || metadata.uid() != self.identity.uid
            || metadata.mode() & 0o077 != 0
            || !opened.file_type().is_dir()
            || opened.dev() != self.identity.device
            || opened.ino() != self.identity.inode
            || opened.uid() != self.identity.uid
            || opened.mode() & 0o077 != 0
        {
            return Err(CodexHandoffError::Protocol);
        }
        Ok(())
    }

    fn sync_all(&self) -> Result<(), CodexHandoffError> {
        #[cfg(test)]
        if self.fail_next_sync.replace(false) {
            return Err(CodexHandoffError::Transport);
        }
        self.descriptor
            .sync_all()
            .map_err(|_| CodexHandoffError::Transport)
    }

    fn sync_parent(&self) -> Result<(), CodexHandoffError> {
        if fs::canonicalize(&self.parent_path).map_err(|_| CodexHandoffError::Protocol)?
            != self.parent_path
        {
            return Err(CodexHandoffError::Protocol);
        }
        let visible =
            fs::symlink_metadata(&self.parent_path).map_err(|_| CodexHandoffError::Protocol)?;
        let opened = self
            .parent_descriptor
            .metadata()
            .map_err(|_| CodexHandoffError::Transport)?;
        if !visible.file_type().is_dir()
            || !opened.file_type().is_dir()
            || visible.dev() != self.parent_identity.device
            || visible.ino() != self.parent_identity.inode
            || opened.dev() != self.parent_identity.device
            || opened.ino() != self.parent_identity.inode
        {
            return Err(CodexHandoffError::Protocol);
        }
        self.parent_descriptor
            .sync_all()
            .map_err(|_| CodexHandoffError::Transport)
    }

    fn preserve(&mut self) {
        if self.cleanup_state != ScratchRootCleanupState::Cleaned {
            self.cleanup_state = ScratchRootCleanupState::Preserved;
        }
    }

    fn authorize_explicit_cleanup(&mut self) {
        if self.cleanup_state == ScratchRootCleanupState::Preserved {
            self.cleanup_state = ScratchRootCleanupState::Active;
        }
    }

    fn cleanup(
        mut self,
        deadline: Instant,
    ) -> Result<ScratchRootCleanupComplete, Box<ScratchRootCleanupFailure>> {
        let result = self.cleanup_once(deadline);
        match result {
            Ok(()) => {
                self.cleanup_state = ScratchRootCleanupState::Cleaned;
                Ok(ScratchRootCleanupComplete { _private: () })
            }
            Err(error) => {
                let first_error = *self.cleanup_first_error.get_or_insert(error);
                Err(Box::new(ScratchRootCleanupFailure {
                    root: self,
                    error: first_error,
                }))
            }
        }
    }

    fn cleanup_once(&mut self, deadline: Instant) -> Result<(), CodexHandoffError> {
        loop {
            ensure_before_deadline(deadline)?;
            match self.cleanup_state {
                ScratchRootCleanupState::Active => {
                    self.revalidate()?;
                    let descriptor = rustix::io::fcntl_dupfd_cloexec(&self.descriptor, 0)
                        .map_err(|_| CodexHandoffError::Transport)?;
                    let mut budget = MAX_SCRATCH_NODES;
                    remove_scratch_entries(
                        rustix::fs::Dir::new(descriptor)
                            .map_err(|_| CodexHandoffError::Transport)?,
                        self.identity.device,
                        self.identity.uid,
                        &mut budget,
                        0,
                        deadline,
                    )?;
                    self.descriptor
                        .sync_all()
                        .map_err(|_| CodexHandoffError::Transport)?;
                    self.revalidate()?;
                    revalidate_scratch_parent(self)?;
                    let name = self.path.file_name().ok_or(CodexHandoffError::Protocol)?;
                    let visible = rustix::fs::statat(
                        &self.parent_descriptor,
                        name,
                        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                    )
                    .map_err(|_| CodexHandoffError::Protocol)?;
                    if visible.st_dev as u64 != self.identity.device
                        || visible.st_ino != self.identity.inode
                        || visible.st_uid != self.identity.uid
                        || !rustix::fs::FileType::from_raw_mode(visible.st_mode).is_dir()
                    {
                        return Err(CodexHandoffError::Protocol);
                    }
                    let opened = rustix::fs::openat(
                        &self.parent_descriptor,
                        name,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|_| CodexHandoffError::Protocol)?;
                    let opened =
                        rustix::fs::fstat(&opened).map_err(|_| CodexHandoffError::Transport)?;
                    if opened.st_dev as u64 != self.identity.device
                        || opened.st_ino != self.identity.inode
                        || opened.st_uid != self.identity.uid
                    {
                        return Err(CodexHandoffError::Protocol);
                    }
                    rustix::fs::unlinkat(
                        &self.parent_descriptor,
                        name,
                        rustix::fs::AtFlags::REMOVEDIR,
                    )
                    .map_err(|_| CodexHandoffError::Transport)?;
                    self.cleanup_state = ScratchRootCleanupState::RootRemovedPendingParentSync;
                }
                ScratchRootCleanupState::RootRemovedPendingParentSync => {
                    self.sync_parent()?;
                    return Ok(());
                }
                ScratchRootCleanupState::Cleaned => return Ok(()),
                ScratchRootCleanupState::Preserved => return Err(CodexHandoffError::Protocol),
            }
        }
    }
}

impl Drop for ScratchRoot {
    fn drop(&mut self) {
        if !matches!(
            self.cleanup_state,
            ScratchRootCleanupState::Cleaned | ScratchRootCleanupState::Preserved
        ) {
            // Drop is deliberately mutation-free. Explicit cleanup is bounded
            // by a caller-owned deadline and returns the exact root authority
            // when a retry is required.
            self.cleanup_state = ScratchRootCleanupState::Preserved;
        }
    }
}

fn revalidate_scratch_parent(root: &ScratchRoot) -> Result<(), CodexHandoffError> {
    if fs::canonicalize(&root.parent_path).map_err(|_| CodexHandoffError::Protocol)?
        != root.parent_path
    {
        return Err(CodexHandoffError::Protocol);
    }
    let visible =
        fs::symlink_metadata(&root.parent_path).map_err(|_| CodexHandoffError::Protocol)?;
    let opened = root
        .parent_descriptor
        .metadata()
        .map_err(|_| CodexHandoffError::Transport)?;
    if !visible.file_type().is_dir()
        || !opened.file_type().is_dir()
        || visible.dev() != root.parent_identity.device
        || visible.ino() != root.parent_identity.inode
        || opened.dev() != root.parent_identity.device
        || opened.ino() != root.parent_identity.inode
    {
        return Err(CodexHandoffError::Protocol);
    }
    Ok(())
}

fn remove_scratch_entries(
    directory: rustix::fs::Dir,
    expected_device: u64,
    expected_uid: u32,
    budget: &mut usize,
    depth: usize,
    deadline: Instant,
) -> Result<(), CodexHandoffError> {
    const MAX_DEPTH: usize = 128;
    ensure_before_deadline(deadline)?;
    if depth > MAX_DEPTH {
        return Err(CodexHandoffError::Protocol);
    }
    // dup(2) shares a directory stream offset. Reopen `.` first so a failed
    // or diagnostic traversal cannot advance the retained owner's descriptor
    // and make a later retry incorrectly observe an empty directory.
    let reopened = rustix::fs::openat(
        directory.fd().map_err(|_| CodexHandoffError::Transport)?,
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| CodexHandoffError::Transport)?;
    drop(directory);
    let mut directory = rustix::fs::Dir::new(reopened).map_err(|_| CodexHandoffError::Transport)?;
    let descriptor = rustix::io::fcntl_dupfd_cloexec(
        directory.fd().map_err(|_| CodexHandoffError::Transport)?,
        0,
    )
    .map_err(|_| CodexHandoffError::Transport)?;
    let mut entries: Vec<(CString, rustix::fs::Stat)> = Vec::new();
    for entry in directory.by_ref() {
        ensure_before_deadline(deadline)?;
        let entry = entry.map_err(|_| CodexHandoffError::Transport)?;
        if entry.file_name().to_bytes() == b"." || entry.file_name().to_bytes() == b".." {
            continue;
        }
        *budget = budget.checked_sub(1).ok_or(CodexHandoffError::Protocol)?;
        let stat = rustix::fs::statat(
            &descriptor,
            entry.file_name(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| CodexHandoffError::Transport)?;
        validate_scratch_entry(&stat, expected_device, expected_uid)?;
        entries
            .try_reserve(1)
            .map_err(|_| CodexHandoffError::Transport)?;
        entries.push((entry.file_name().to_owned(), stat));
    }
    for (name, expected) in entries {
        ensure_before_deadline(deadline)?;
        let current = rustix::fs::statat(&descriptor, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| CodexHandoffError::Transport)?;
        validate_scratch_entry(&current, expected_device, expected_uid)?;
        if current.st_dev != expected.st_dev
            || current.st_ino != expected.st_ino
            || current.st_mode != expected.st_mode
            || current.st_uid != expected.st_uid
        {
            return Err(CodexHandoffError::Protocol);
        }
        let kind = rustix::fs::FileType::from_raw_mode(current.st_mode);
        if kind.is_dir() {
            let child = rustix::fs::openat(
                &descriptor,
                &name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| CodexHandoffError::Protocol)?;
            let opened = rustix::fs::fstat(&child).map_err(|_| CodexHandoffError::Transport)?;
            if opened.st_dev != current.st_dev
                || opened.st_ino != current.st_ino
                || opened.st_uid != current.st_uid
            {
                return Err(CodexHandoffError::Protocol);
            }
            remove_scratch_entries(
                rustix::fs::Dir::new(child).map_err(|_| CodexHandoffError::Transport)?,
                expected_device,
                expected_uid,
                budget,
                depth + 1,
                deadline,
            )?;
            let final_stat =
                rustix::fs::statat(&descriptor, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| CodexHandoffError::Transport)?;
            if final_stat.st_dev != current.st_dev
                || final_stat.st_ino != current.st_ino
                || !rustix::fs::FileType::from_raw_mode(final_stat.st_mode).is_dir()
            {
                return Err(CodexHandoffError::Protocol);
            }
            rustix::fs::unlinkat(&descriptor, &name, rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|_| CodexHandoffError::Transport)?;
        } else {
            // unlinkat without REMOVEDIR never follows a symlink and cannot
            // escape this already-open owner-private directory.
            rustix::fs::unlinkat(&descriptor, &name, rustix::fs::AtFlags::empty())
                .map_err(|_| CodexHandoffError::Transport)?;
        }
    }
    rustix::fs::fsync(&descriptor).map_err(|_| CodexHandoffError::Transport)
}

fn validate_scratch_entry(
    stat: &rustix::fs::Stat,
    expected_device: u64,
    expected_uid: u32,
) -> Result<(), CodexHandoffError> {
    let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    let safe_links = !kind.is_file() || stat.st_nlink == 1;
    #[cfg(target_os = "linux")]
    let device = stat.st_dev;
    #[cfg(target_os = "macos")]
    let device = stat.st_dev as u64;
    if device != expected_device
        || stat.st_uid != expected_uid
        || !safe_links
        || (kind.is_dir() && stat.st_mode & 0o022 != 0)
    {
        return Err(CodexHandoffError::Protocol);
    }
    Ok(())
}

fn ensure_before_deadline(deadline: Instant) -> Result<(), CodexHandoffError> {
    if Instant::now() >= deadline {
        Err(CodexHandoffError::Timeout)
    } else {
        Ok(())
    }
}

struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl ChildGuard {
    fn spawn(mut command: Command, working_directory: &Path) -> Result<Self, CodexHandoffError> {
        configure_own_process_group(&mut command);
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir(working_directory)
            .spawn()
            .map_err(|_| CodexHandoffError::Spawn)?;
        Ok(Self {
            child,
            reaped: false,
        })
    }

    fn is_running(&mut self) -> Result<bool, CodexHandoffError> {
        if self.reaped {
            return Ok(false);
        }
        child_exit_observed_without_reaping(&mut self.child)
            .map(|exited| !exited)
            .map_err(|_| CodexHandoffError::Transport)
    }

    fn shutdown(&mut self) -> Result<(), CodexHandoffError> {
        if !self.reaped {
            let termination = force_terminate_process_tree(&mut self.child);
            self.reaped = child_reap_confirmed(&mut self.child);
            termination.map_err(|_| CodexHandoffError::Transport)?;
            if !self.reaped {
                return Err(CodexHandoffError::Transport);
            }
        }
        Ok(())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = force_terminate_process_tree(&mut self.child);
            self.reaped = child_reap_confirmed(&mut self.child);
        }
    }
}

fn wait_for_unix_socket(
    child: &mut ChildGuard,
    socket_path: &Path,
    deadline: Instant,
) -> Result<(), CodexHandoffError> {
    loop {
        match fs::symlink_metadata(socket_path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && metadata.uid() == rustix::process::geteuid().as_raw() =>
            {
                // The official app-server owns this inode but may create it
                // with the platform's normal umask. Access is contained by
                // the identity-bound mode-0700 scratch parent, not by the
                // implementation-defined mode on the socket itself.
                return if child.is_running()? {
                    Ok(())
                } else {
                    Err(CodexHandoffError::Transport)
                };
            }
            Ok(_) => return Err(CodexHandoffError::Protocol),
            Err(error) if error.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                if !child.is_running()? {
                    return Err(CodexHandoffError::Transport);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(CodexHandoffError::Timeout);
            }
            Err(_) => return Err(CodexHandoffError::Transport),
        }
    }
}

fn map_proxy_error(error: ReadinessProxyError) -> CodexHandoffError {
    #[cfg(test)]
    eprintln!("handoff readiness proxy failed: {error:?}");
    match error {
        ReadinessProxyError::Timeout => CodexHandoffError::Timeout,
        ReadinessProxyError::InvalidArgument
        | ReadinessProxyError::HandshakeTooLarge
        | ReadinessProxyError::InvalidHandshake
        | ReadinessProxyError::FrameTooLarge
        | ReadinessProxyError::InvalidFrame
        | ReadinessProxyError::InvalidMessage
        | ReadinessProxyError::UnexpectedSequence
        | ReadinessProxyError::TargetMismatch => CodexHandoffError::Protocol,
        ReadinessProxyError::Bind
        | ReadinessProxyError::Accept
        | ReadinessProxyError::Connect
        | ReadinessProxyError::Transport(_)
        | ReadinessProxyError::Worker
        | ReadinessProxyError::Cleanup => CodexHandoffError::Transport,
    }
}

struct PtyChild {
    child: Child,
    reaped: bool,
    master: Option<File>,
    drainer: Option<thread::JoinHandle<PtyDrain>>,
}

struct PtyDrain {
    bytes: Vec<u8>,
    overflowed: bool,
    failed: bool,
}

impl PtyChild {
    fn spawn(mut command: Command, working_directory: &Path) -> Result<Self, CodexHandoffError> {
        let master =
            rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)
                .map_err(|error| pty_spawn_error("openpt", error))?;
        rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC)
            .map_err(|error| pty_spawn_error("fcntl_setfd", error))?;
        rustix::pty::grantpt(&master).map_err(|error| pty_spawn_error("grantpt", error))?;
        rustix::pty::unlockpt(&master).map_err(|error| pty_spawn_error("unlockpt", error))?;
        let slave = open_pty_slave(&master)?;
        rustix::termios::tcsetwinsize(
            &slave,
            rustix::termios::Winsize {
                ws_row: 40,
                ws_col: 120,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .map_err(|error| pty_spawn_error("tcsetwinsize", error))?;
        let slave_stdout = slave
            .try_clone()
            .map_err(|error| pty_spawn_error("clone stdout", error))?;
        let slave_stderr = slave
            .try_clone()
            .map_err(|error| pty_spawn_error("clone stderr", error))?;
        let master = File::from(master);
        let mut reader = master
            .try_clone()
            .map_err(|error| pty_spawn_error("clone master", error))?;
        let drainer = thread::Builder::new()
            .name("calcifer-handoff-tui-pty".to_owned())
            .spawn(move || drain_pty(&mut reader))
            .map_err(|error| pty_spawn_error("spawn drainer", error))?;
        configure_own_process_group(&mut command);
        let child = command
            .stdin(Stdio::from(slave))
            .stdout(Stdio::from(slave_stdout))
            .stderr(Stdio::from(slave_stderr))
            .current_dir(working_directory)
            .env("TERM", "xterm-256color")
            .spawn()
            .map_err(|error| pty_spawn_error("spawn child", error))?;
        Ok(Self {
            child,
            reaped: false,
            master: Some(master),
            drainer: Some(drainer),
        })
    }

    fn is_running(&mut self) -> Result<bool, CodexHandoffError> {
        child_exit_observed_without_reaping(&mut self.child)
            .map(|exited| !exited)
            .map_err(|_| CodexHandoffError::Transport)
    }

    #[cfg(test)]
    fn wait_until_exit(mut self, deadline: Instant) -> Result<PtyDrain, CodexHandoffError> {
        loop {
            match child_exit_observed_without_reaping(&mut self.child) {
                Ok(true) => {
                    let status = reap_exited_process_tree(&mut self.child)
                        .map_err(|_| CodexHandoffError::Transport)?;
                    self.reaped = true;
                    return if status.success() {
                        self.collect_after_reap()
                    } else {
                        Err(CodexHandoffError::Transport)
                    };
                }
                Err(_) => return Err(CodexHandoffError::Transport),
                Ok(false) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                Ok(false) => return Err(CodexHandoffError::Timeout),
            }
        }
    }

    fn shutdown(mut self) -> Result<PtyDrain, CodexHandoffError> {
        self.finish()
    }

    fn finish(&mut self) -> Result<PtyDrain, CodexHandoffError> {
        let settlement = if self.reaped {
            Ok(())
        } else {
            let settlement = match child_exit_observed_without_reaping(&mut self.child) {
                // Protocol and liveness were proven before the readiness
                // proxy was intentionally closed. A natural TUI exit after
                // that close is a cleanup disposition, not a new protocol
                // result, regardless of its provider-defined exit code.
                Ok(true) => reap_exited_process_tree(&mut self.child)
                    .map(|_| ())
                    .map_err(|_| CodexHandoffError::Transport),
                Ok(false) => force_terminate_process_tree(&mut self.child)
                    .map(|_| ())
                    .map_err(|_error| {
                        #[cfg(test)]
                        eprintln!(
                            "handoff probe: TUI process-tree termination failed kind={:?} os={:?}",
                            _error.kind(),
                            _error.raw_os_error()
                        );
                        CodexHandoffError::Transport
                    }),
                Err(_) => {
                    // Contain and reap if possible, but an ambiguous liveness
                    // observation can never become compatibility success.
                    let _ = force_terminate_process_tree(&mut self.child);
                    Err(CodexHandoffError::Transport)
                }
            };
            self.reaped = child_reap_confirmed(&mut self.child);
            if !self.reaped {
                return Err(CodexHandoffError::Transport);
            }
            settlement
        };
        let output = self.collect_after_reap();
        match (settlement, output) {
            (Ok(()), Ok(output)) => Ok(output),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    fn collect_after_reap(&mut self) -> Result<PtyDrain, CodexHandoffError> {
        drop(self.master.take());
        self.drainer
            .take()
            .ok_or(CodexHandoffError::Transport)?
            .join()
            .map_err(|_| CodexHandoffError::Transport)
    }
}

fn open_pty_slave(master: &impl AsFd) -> Result<File, CodexHandoffError> {
    let slave_name = rustix::pty::ptsname(master, Vec::new())
        .map_err(|error| pty_spawn_error("ptsname", error))?;
    rustix::fs::open(
        slave_name.as_c_str(),
        // A supervisor started as a session leader may not let this parent
        // acquire the probe PTY as its controlling terminal. Otherwise the
        // separately grouped TUI becomes a background job and can stop on its
        // first terminal read before opening the readiness WebSocket.
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| pty_spawn_error("open slave", error))
}

impl Drop for PtyChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = force_terminate_process_tree(&mut self.child);
            self.reaped = child_reap_confirmed(&mut self.child);
        }
        drop(self.master.take());
        if let Some(drainer) = self.drainer.take() {
            let _ = drainer.join();
        }
    }
}

fn pty_spawn_error(stage: &str, error: impl std::fmt::Debug) -> CodexHandoffError {
    #[cfg(test)]
    eprintln!("handoff PTY {stage} failed: {error:?}");
    #[cfg(not(test))]
    let _ = (stage, error);
    CodexHandoffError::Spawn
}

fn drain_pty(reader: &mut File) -> PtyDrain {
    let mut bytes = Vec::new();
    let mut overflowed = false;
    let mut failed = false;
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(length) => {
                let remaining = MAX_TUI_OUTPUT_BYTES.saturating_sub(bytes.len());
                let retained = remaining.min(length);
                bytes.extend_from_slice(&buffer[..retained]);
                overflowed |= retained != length;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) => {
                break;
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    PtyDrain {
        bytes,
        overflowed,
        failed,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::{OsStr, OsString};
    use std::fs::OpenOptions;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use super::*;

    const PTY_SESSION_LEADER_HELPER_ENV: &str = "CALCIFER_TEST_PTY_SESSION_LEADER_HELPER";
    const PTY_SESSION_LEADER_HELPER_TEST: &str = concat!(
        "providers::codex::handoff_compat::runtime::tests::",
        "pty_slave_open_session_leader_helper"
    );

    fn cleanup_test_scratch(scratch: ScratchRoot) -> Result<(), CodexHandoffError> {
        scratch
            .cleanup(Instant::now() + Duration::from_secs(2))
            .map(|_| ())
            .map_err(|failure| failure.error())
    }

    fn cleanup_test_proof(proof: PreRemoteProof) -> Result<(), CodexHandoffError> {
        let PreRemoteProof {
            scratch,
            probe_binary_directory,
            probe_executable,
            schema,
            fork,
            model_listener,
            source_home,
            target_home,
            workspace,
            environment_home,
            target_config,
        } = proof;
        drop((
            probe_binary_directory,
            probe_executable,
            schema,
            fork,
            model_listener,
            source_home,
            target_home,
            workspace,
            environment_home,
            target_config,
        ));
        cleanup_test_scratch(scratch)
    }

    #[test]
    fn pre_version_timeout_boundaries_preserve_only_closed_origins()
    -> Result<(), Box<dyn std::error::Error>> {
        for origin in CompatibilityTimeoutOrigin::ALL {
            let cause = match ensure_compatibility_deadline(Instant::now(), origin) {
                Err(cause) => cause,
                Ok(()) => return Err("an expired compatibility boundary did not time out".into()),
            };
            let failure = CodexHandoffFailure::from(cause);
            assert_eq!(failure.error(), CodexHandoffError::Timeout);
            assert_eq!(failure.timeout_origin(), Some(origin));
        }

        for (probe, expected) in [
            (
                CodexVersionProbeTimeoutOrigin::ChildExit,
                CompatibilityTimeoutOrigin::VersionChildExit,
            ),
            (
                CodexVersionProbeTimeoutOrigin::StdoutDrain,
                CompatibilityTimeoutOrigin::VersionStdoutDrain,
            ),
        ] {
            let cause = map_version_probe_failure(CodexVersionProbeFailure::timeout(probe));
            let failure = CodexHandoffFailure::from(cause);
            assert_eq!(failure.error(), CodexHandoffError::Timeout);
            assert_eq!(failure.timeout_origin(), Some(expected));
        }

        let non_timeout = CodexHandoffFailure::from(CodexHandoffCause::at_timeout_boundary(
            CodexHandoffError::Transport,
            CompatibilityTimeoutOrigin::SourceCapture,
        ));
        assert_eq!(non_timeout.error(), CodexHandoffError::Transport);
        assert_eq!(non_timeout.timeout_origin(), None);

        let later_timeout = CodexHandoffFailure::from(CodexHandoffError::Timeout);
        assert_eq!(later_timeout.error(), CodexHandoffError::Timeout);
        assert_eq!(later_timeout.timeout_origin(), None);
        Ok(())
    }

    #[test]
    fn every_pre_version_timeout_seam_stops_before_any_provider_child_and_cleans()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = ScratchRoot::create()?;
        let executable = fixture.path().join("codex-timeout-fixture");
        let child_started = fixture.path().join("provider-child-started");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\nprintf started > '{}'\n",
                child_started.display()
            ),
        )?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;

        for origin in CompatibilityTimeoutOrigin::ALL {
            let seam = inject_pre_version_timeout(origin);
            let started = Instant::now();
            let result = verify_before_remote(&executable, Duration::from_secs(2));
            drop(seam);
            let failure = match result {
                Err(failure) => failure,
                Ok(proof) => {
                    cleanup_test_proof(proof)?;
                    return Err(format!("the {origin:?} timeout seam unexpectedly passed").into());
                }
            };

            assert_eq!(failure.error(), CodexHandoffError::Timeout);
            assert_eq!(failure.timeout_origin(), Some(origin));
            assert_eq!(failure.cleanup_error(), None);
            assert!(
                !failure.has_retained_ownership(),
                "the {origin:?} timeout retained scratch or stage cleanup authority"
            );
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "the {origin:?} timeout seam exceeded its fixed test bound"
            );
            assert!(
                !child_started.exists(),
                "the {origin:?} pre-version timeout started a provider child"
            );
        }

        cleanup_test_scratch(fixture)?;
        Ok(())
    }

    #[test]
    fn compatibility_target_config_disables_out_of_scope_dynamic_features()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let target_home = scratch.create_directory("target")?;
        let backend = "127.0.0.1:12345".parse()?;
        let proof = write_target_config(&target_home, backend)?;
        let contents = fs::read_to_string(target_home.join("config.toml"))?;
        drop((proof, target_home));
        cleanup_test_scratch(scratch)?;

        let config: toml::Value = toml::from_str(&contents)?;
        assert_eq!(
            config
                .get("check_for_update_on_startup")
                .and_then(toml::Value::as_bool),
            Some(false),
            "the compatibility probe allowed an out-of-scope update request"
        );
        assert_eq!(
            config.get("personality").and_then(toml::Value::as_str),
            Some("pragmatic"),
            "the compatibility probe allowed resume to mutate personality"
        );
        assert_eq!(
            config
                .get("analytics")
                .and_then(toml::Value::as_table)
                .and_then(|analytics| analytics.get("enabled"))
                .and_then(toml::Value::as_bool),
            Some(false),
            "the compatibility probe allowed default analytics egress"
        );
        let otel = config
            .get("otel")
            .and_then(toml::Value::as_table)
            .ok_or("the compatibility probe omitted its OTEL table")?;
        for exporter in ["exporter", "trace_exporter", "metrics_exporter"] {
            assert_eq!(
                otel.get(exporter).and_then(toml::Value::as_str),
                Some("none"),
                "the compatibility probe did not disable {exporter}"
            );
        }
        assert_eq!(
            config
                .get("tui")
                .and_then(toml::Value::as_table)
                .and_then(|tui| tui.get("show_tooltips"))
                .and_then(toml::Value::as_bool),
            Some(false),
            "the compatibility probe allowed remote tooltip content to affect output"
        );
        let features = config
            .get("features")
            .and_then(toml::Value::as_table)
            .ok_or("the compatibility probe omitted its feature table")?;
        for feature in ["shell_snapshot", "apps", "plugins", "remote_plugin"] {
            assert_eq!(
                features.get(feature).and_then(toml::Value::as_bool),
                Some(false),
                "the compatibility probe did not disable {feature}"
            );
        }
        Ok(())
    }

    fn valid_fork_result(
        source_thread_id: &str,
        target_thread_id: &str,
        target_rollout: &Path,
        workspace: &Path,
    ) -> Value {
        json!({
            "model": MODEL_NAME,
            "modelProvider": MODEL_PROVIDER,
            "cwd": workspace,
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "sandbox": { "type": "readOnly", "networkAccess": false },
            "thread": {
                "id": target_thread_id,
                "forkedFromId": source_thread_id,
                "cliVersion": SUPPORTED_VERSION,
                "modelProvider": MODEL_PROVIDER,
                "preview": HISTORY_SENTINEL,
                "cwd": workspace,
                "path": target_rollout,
                "turns": [{ "id": "synthetic-turn" }]
            }
        })
    }

    #[test]
    #[ignore = "requires the pinned official Codex 0.144.4 package"]
    fn packaged_codex_passes_schema_and_credential_free_fork_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        let executable = std::env::var_os("CALCIFER_CODEX_COMPAT_BINARY")
            .map(PathBuf::from)
            .ok_or("CALCIFER_CODEX_COMPAT_BINARY must name the pinned Codex binary")?;

        let proof = verify_before_remote(&executable, Duration::from_secs(120))?;
        assert!(Uuid::parse_str(&proof.fork.target_thread_id).is_ok());
        assert!(
            proof
                .fork
                .target_home
                .join(&proof.fork.target_rollout_relative)
                .starts_with(&proof.fork.target_home)
        );
        assert_eq!(
            proof
                .fork
                .workspace
                .file_name()
                .and_then(|name| name.to_str()),
            Some("w")
        );
        cleanup_test_proof(proof)?;
        Ok(())
    }

    #[test]
    fn scratch_root_uses_the_canonical_fixed_parent() -> Result<(), Box<dyn std::error::Error>> {
        let expected_parent = fs::canonicalize("/tmp")?;
        let scratch = ScratchRoot::create()?;

        assert_eq!(scratch.path().parent(), Some(expected_parent.as_path()));
        scratch.revalidate()?;
        cleanup_test_scratch(scratch)?;
        Ok(())
    }

    #[test]
    fn scratch_cleanup_is_identity_bound() -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let path = scratch.path().to_path_buf();
        let moved = path.with_extension("moved");
        fs::rename(&path, &moved)?;
        fs::DirBuilder::new().mode(0o700).create(&path)?;

        drop(scratch);

        assert!(path.is_dir(), "replacement directory must not be deleted");
        assert!(moved.is_dir(), "moved owned directory must not be followed");
        fs::remove_dir(&path)?;
        fs::remove_dir_all(&moved)?;
        Ok(())
    }

    #[test]
    fn scratch_cleanup_is_explicit_recursive_and_retryable()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let root = scratch.path().to_path_buf();
        let nested = scratch.create_directory("nested")?;
        nested.create_relative_directories(Path::new("one/two"))?;
        nested.write_relative_new(Path::new("one/two/probe.json"), b"{}")?;
        symlink("one/two/probe.json", nested.join("probe-link"))?;

        let failure = match scratch.cleanup(Instant::now()) {
            Ok(_) => return Err("expired cleanup released the exact scratch owner".into()),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), CodexHandoffError::Timeout);
        assert!(root.exists());

        let scratch = (*failure).into_root();
        cleanup_test_scratch(scratch)?;
        assert!(!root.exists());
        Ok(())
    }

    #[test]
    fn handoff_failure_retains_and_retries_exact_cleanup_ownership()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let root = scratch.path().to_path_buf();
        fs::write(root.join("retained"), b"compatibility-evidence")?;
        let cleanup = match scratch.cleanup(Instant::now()) {
            Ok(_) => return Err("expired cleanup released the scratch owner".into()),
            Err(cleanup) => cleanup,
        };
        let failure = Box::new(CodexHandoffFailure::with_retained(
            CodexHandoffError::Protocol,
            CodexHandoffRetention::ScratchCleanup(cleanup),
        ));
        fn assert_static<T: 'static>(_: &T) {}
        assert_static(&failure);

        let failure = match failure.resolve(Instant::now()) {
            Ok(_) => return Err("an expired retained cleanup unexpectedly resolved".into()),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), CodexHandoffError::Protocol);
        assert_eq!(failure.cleanup_error(), Some(CodexHandoffError::Timeout));
        assert!(failure.has_retained_ownership());
        assert_eq!(fs::read(root.join("retained"))?, b"compatibility-evidence");

        let resolution = failure
            .resolve(Instant::now() + Duration::from_secs(2))
            .map_err(|failure| format!("retained cleanup did not resolve: {failure:?}"))?;
        assert_eq!(resolution.error(), CodexHandoffError::Protocol);
        assert_eq!(resolution.cleanup_error(), Some(CodexHandoffError::Timeout));
        assert_eq!(resolution.release(), CodexHandoffError::Protocol);
        assert!(!root.exists());
        Ok(())
    }

    #[test]
    fn handoff_timeout_origin_survives_failed_and_successful_cleanup_retries()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let root = scratch.path().to_path_buf();
        fs::write(root.join("retained"), b"timeout-evidence")?;
        let cleanup = match scratch.cleanup(Instant::now()) {
            Ok(_) => return Err("expired cleanup released the timeout owner".into()),
            Err(cleanup) => cleanup,
        };
        let origin = CompatibilityTimeoutOrigin::ProbeStageCopyDurability;
        let failure = Box::new(CodexHandoffFailure::with_retained_cause(
            CodexHandoffCause::timeout(origin),
            CodexHandoffRetention::ScratchCleanup(cleanup),
        ));

        let failure = match failure.resolve(Instant::now()) {
            Ok(_) => return Err("an expired retained timeout cleanup unexpectedly resolved".into()),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), CodexHandoffError::Timeout);
        assert_eq!(failure.timeout_origin(), Some(origin));
        assert_eq!(failure.cleanup_error(), Some(CodexHandoffError::Timeout));
        assert!(failure.has_retained_ownership());
        assert_eq!(fs::read(root.join("retained"))?, b"timeout-evidence");

        let resolution = failure
            .resolve(Instant::now() + Duration::from_secs(2))
            .map_err(|failure| format!("retained timeout cleanup did not resolve: {failure:?}"))?;
        assert_eq!(resolution.error(), CodexHandoffError::Timeout);
        assert_eq!(resolution.timeout_origin(), Some(origin));
        assert_eq!(resolution.cleanup_error(), Some(CodexHandoffError::Timeout));
        assert_eq!(resolution.release(), CodexHandoffError::Timeout);
        assert!(!root.exists());
        Ok(())
    }

    #[test]
    fn handoff_failure_explicitly_cleans_preserved_construction_owners()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = ScratchRoot::create()?;

        let create = match ScratchRoot::create_in_with_parent_sync_failure(parent.path()) {
            Ok(root) => {
                cleanup_test_scratch(root)?;
                return Err(
                    "injected parent sync failure unexpectedly created a clean root".into(),
                );
            }
            Err(failure) => failure,
        };
        let create_path = create
            .retained_path()
            .ok_or("scratch create failure lost its exact root")?
            .to_path_buf();
        let create = Box::new(CodexHandoffFailure::from(create));
        assert!(create.has_retained_ownership());
        let create = match create.resolve(Instant::now()) {
            Ok(_) => return Err("expired construction cleanup unexpectedly resolved".into()),
            Err(create) => create,
        };
        assert_eq!(create.error(), CodexHandoffError::Transport);
        assert_eq!(create.cleanup_error(), Some(CodexHandoffError::Timeout));
        assert!(create_path.exists());
        let resolution = create
            .resolve(Instant::now() + Duration::from_secs(2))
            .map_err(|failure| format!("preserved create root did not resolve: {failure:?}"))?;
        assert_eq!(resolution.error(), CodexHandoffError::Transport);
        assert_eq!(resolution.cleanup_error(), Some(CodexHandoffError::Timeout));
        assert!(!create_path.exists());

        let scratch = ScratchRoot::create_in(parent.path())?;
        let stage_path = scratch.path().to_path_buf();
        fs::write(stage_path.join("partial-stage"), b"owned-evidence")?;
        let stage = PinnedStageCreateFailure::with_scratch(PinnedStageError::Storage, scratch);
        let stage = Box::new(CodexHandoffFailure::from(stage));
        assert!(stage.has_retained_ownership());
        let resolution = stage
            .resolve(Instant::now() + Duration::from_secs(2))
            .map_err(|failure| format!("preserved stage root did not resolve: {failure:?}"))?;
        assert_eq!(resolution.error(), CodexHandoffError::Transport);
        assert!(!stage_path.exists());
        cleanup_test_scratch(parent)?;
        Ok(())
    }

    #[test]
    fn scratch_cleanup_budget_failure_does_not_mutate_the_tree()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        fs::write(scratch.path().join("retained"), b"safe")?;
        let descriptor = rustix::io::fcntl_dupfd_cloexec(&scratch.descriptor, 0)?;
        let mut budget = 0;

        assert_eq!(
            remove_scratch_entries(
                rustix::fs::Dir::new(descriptor)?,
                scratch.identity.device,
                scratch.identity.uid,
                &mut budget,
                0,
                Instant::now() + Duration::from_secs(1),
            ),
            Err(CodexHandoffError::Protocol)
        );
        assert_eq!(fs::read(scratch.path().join("retained"))?, b"safe");
        cleanup_test_scratch(scratch)?;
        Ok(())
    }

    #[test]
    fn app_server_socket_may_inherit_the_childs_normal_umask()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let socket_path = scratch.path().join("app-server.sock");
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o755))?;
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30"]);
        let mut child = ChildGuard::spawn(command, scratch.path())?;

        let result = wait_for_unix_socket(
            &mut child,
            &socket_path,
            Instant::now() + Duration::from_secs(1),
        );
        child.shutdown()?;

        assert_eq!(result, Ok(()));
        drop(listener);
        cleanup_test_scratch(scratch)?;
        Ok(())
    }

    #[test]
    fn private_directory_reads_reject_symlinks_without_mutating_the_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let output = scratch.create_directory("output")?;
        let victim = scratch.create_directory("victim")?;
        victim.write_relative_new(Path::new("schema.json"), br#"{"safe":true}"#)?;
        let victim_path = victim.join("schema.json");
        let before = fs::symlink_metadata(&victim_path)?;
        symlink(&victim_path, output.join("schema.json"))?;

        assert_eq!(
            output.read_relative_json("schema.json"),
            Err(CodexHandoffError::Protocol)
        );
        assert_eq!(fs::read(&victim_path)?, br#"{"safe":true}"#);
        let after = fs::symlink_metadata(&victim_path)?;
        assert_eq!(before.mode(), after.mode());
        assert_eq!(before.ino(), after.ino());
        cleanup_test_scratch(scratch)?;
        Ok(())
    }

    #[test]
    fn private_directory_descriptor_detects_a_replaced_visible_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let directory = scratch.create_directory("owned")?;
        let moved = scratch.path().join("owned-moved");
        fs::rename(directory.as_ref(), &moved)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory.as_ref())?;

        assert_eq!(directory.revalidate(), Err(CodexHandoffError::Protocol));
        assert!(moved.is_dir());
        assert!(directory.is_dir());
        cleanup_test_scratch(scratch)?;
        Ok(())
    }

    #[test]
    fn executable_identity_rejects_replacement_and_unsafe_modes()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let executable = scratch.path().join("codex-test");
        fs::write(&executable, b"#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        let identity = capture_executable(&executable, Instant::now() + Duration::from_secs(2))?;
        let original = scratch.path().join("codex-test-original");
        fs::rename(&executable, &original)?;
        fs::write(&executable, b"#!/bin/sh\nexit 1\n")?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;

        assert!(matches!(
            revalidate_executable_until(&identity, Some(Instant::now() + Duration::from_secs(2))),
            Err(CodexHandoffError::Unsupported)
        ));
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o722))?;
        assert!(matches!(
            capture_executable(&executable, Instant::now() + Duration::from_secs(2)),
            Err(CodexHandoffError::Unsupported)
        ));
        cleanup_test_scratch(scratch)?;
        Ok(())
    }

    #[test]
    fn staged_probe_keeps_verified_bytes_when_the_install_path_is_replaced()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let executable = scratch.path().join("installed-codex");
        fs::write(&executable, b"#!/bin/sh\nprintf 'verified\\n'\n")?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let installed = capture_executable(&executable, deadline)?;
        let (_directory, staged) = stage_executable(&installed, &scratch, deadline)?;

        fs::rename(&executable, scratch.path().join("installed-codex-old"))?;
        fs::write(&executable, b"#!/bin/sh\nprintf 'replacement\\n'\n")?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;

        let output = Command::new(&staged.canonical_path).output()?;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"verified\n");
        assert_eq!(
            revalidate_executable_until(&installed, Some(deadline)),
            Err(CodexHandoffError::Unsupported)
        );
        revalidate_executable_until(&staged, Some(deadline))?;
        cleanup_test_scratch(scratch)?;
        Ok(())
    }

    #[test]
    fn fork_response_requires_effective_safety_settings_and_anchored_rollout()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let source_home = scratch.create_directory("source")?;
        let target_home = scratch.create_directory("target")?;
        let workspace = scratch.create_directory("workspace")?;
        source_home.write_relative_new(Path::new("source.jsonl"), b"source")?;
        let source_relative = PathBuf::from("source.jsonl");
        let source_fingerprint = FileFingerprint::read_relative(
            &source_home,
            &source_relative,
            MAX_ROLLOUT_PROBE_BYTES,
            FilePolicy::Private,
        )?;
        let target_relative = PathBuf::from("sessions/2026/07/15/rollout.jsonl");
        target_home.create_relative_directories(Path::new("sessions/2026/07/15"))?;
        target_home.write_relative_new(&target_relative, HISTORY_SENTINEL.as_bytes())?;
        let target_rollout = target_home.join(&target_relative);
        let source_thread_id = "019f64a7-c5d1-7ed1-aca8-156bc32b650c";
        let target_thread_id = "019f64a7-c5d1-7ed1-aca8-156bc32b650d";
        let valid = valid_fork_result(
            source_thread_id,
            target_thread_id,
            &target_rollout,
            &workspace,
        );

        assert!(
            validate_fork_result(
                &valid,
                source_thread_id,
                source_relative.clone(),
                source_fingerprint.clone(),
                &target_home,
                &workspace,
            )
            .is_ok()
        );

        for (pointer, replacement) in [
            ("/model", json!("other")),
            ("/modelProvider", json!("other")),
            ("/cwd", json!("/tmp")),
            ("/approvalPolicy", json!("on-request")),
            ("/approvalsReviewer", json!("auto_review")),
            ("/sandbox/type", json!("workspaceWrite")),
            ("/sandbox/networkAccess", json!(true)),
            ("/thread/cwd", json!("/tmp")),
        ] {
            let mut mutated = valid.clone();
            *mutated
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("fixture pointer must exist: {pointer}")) = replacement;
            assert!(
                matches!(
                    validate_fork_result(
                        &mutated,
                        source_thread_id,
                        source_relative.clone(),
                        source_fingerprint.clone(),
                        &target_home,
                        &workspace,
                    ),
                    Err(CodexHandoffError::Protocol)
                ),
                "mutation at {pointer} must fail closed"
            );
        }
        for invalid_thread_id in [
            source_thread_id.to_owned(),
            target_thread_id.to_uppercase(),
            source_thread_id.to_uppercase(),
        ] {
            let mut mutated = valid.clone();
            mutated["thread"]["id"] = json!(invalid_thread_id);
            assert!(matches!(
                validate_fork_result(
                    &mutated,
                    source_thread_id,
                    source_relative.clone(),
                    source_fingerprint.clone(),
                    &target_home,
                    &workspace,
                ),
                Err(CodexHandoffError::Protocol)
            ));
        }
        cleanup_test_scratch(scratch)?;
        Ok(())
    }

    #[test]
    fn fork_response_rejects_a_sessions_symlink_escape() -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let source_home = scratch.create_directory("source")?;
        let target_home = scratch.create_directory("target")?;
        let workspace = scratch.create_directory("workspace")?;
        let external = scratch.create_directory("external")?;
        source_home.write_relative_new(Path::new("source.jsonl"), b"source")?;
        external.write_relative_new(Path::new("rollout.jsonl"), HISTORY_SENTINEL.as_bytes())?;
        symlink(external.as_ref(), target_home.join("sessions"))?;
        let source_relative = PathBuf::from("source.jsonl");
        let source_fingerprint = FileFingerprint::read_relative(
            &source_home,
            &source_relative,
            MAX_ROLLOUT_PROBE_BYTES,
            FilePolicy::Private,
        )?;
        let escaped_rollout = target_home.join("sessions/rollout.jsonl");
        let source_thread_id = "019f64a7-c5d1-7ed1-aca8-156bc32b650c";
        let result = valid_fork_result(
            source_thread_id,
            "019f64a7-c5d1-7ed1-aca8-156bc32b650d",
            &escaped_rollout,
            &workspace,
        );

        assert!(matches!(
            validate_fork_result(
                &result,
                source_thread_id,
                source_relative,
                source_fingerprint,
                &target_home,
                &workspace,
            ),
            Err(CodexHandoffError::Protocol)
        ));
        assert_eq!(
            fs::read(external.join("rollout.jsonl"))?,
            HISTORY_SENTINEL.as_bytes()
        );
        cleanup_test_scratch(scratch)?;
        Ok(())
    }

    #[test]
    fn isolated_probe_command_removes_calcifer_and_provider_routing() {
        let command = isolated_command(
            Path::new("/synthetic/codex"),
            Path::new("/synthetic/codex-home"),
            Path::new("/synthetic/environment-home"),
        );
        let environment = command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(OsStr::to_owned)))
            .collect::<BTreeMap<OsString, Option<OsString>>>();

        let expected_names = [
            "CODEX_HOME",
            "HOME",
            "LANG",
            "LC_ALL",
            "PATH",
            "SHELL",
            "TEMP",
            "TERM",
            "TMP",
            "TMPDIR",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_RUNTIME_DIR",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<BTreeSet<_>>();
        assert_eq!(
            environment.keys().cloned().collect::<BTreeSet<_>>(),
            expected_names
        );
        assert!(environment.values().all(Option::is_some));

        for name in [
            "CALCIFER_HOME",
            "OPENAI_API_KEY",
            "CODEX_ACCESS_TOKEN",
            "CODEX_AUTHAPI_BASE_URL",
            "CODEX_REMOTE_AUTH_TOKEN",
            "CODEX_THREAD_ID",
            "CODEX_SANDBOX",
            "PWD",
            "OLDPWD",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_CONFIG",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_COUNT",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ] {
            assert!(
                !environment.contains_key(OsStr::new(name)),
                "{name} must not be present in the credential-free compatibility probe"
            );
        }
        assert_eq!(
            environment
                .get(OsStr::new("CODEX_HOME"))
                .and_then(Option::as_deref),
            Some(OsStr::new("/synthetic/codex-home"))
        );
        assert_eq!(
            environment
                .get(OsStr::new("HOME"))
                .and_then(Option::as_deref),
            Some(OsStr::new("/synthetic/environment-home"))
        );
        assert_eq!(
            environment
                .get(OsStr::new("XDG_CONFIG_HOME"))
                .and_then(Option::as_deref),
            Some(OsStr::new("/synthetic/environment-home/config"))
        );
        assert_eq!(
            environment
                .get(OsStr::new("XDG_DATA_HOME"))
                .and_then(Option::as_deref),
            Some(OsStr::new("/synthetic/environment-home/data"))
        );
        assert_eq!(
            environment
                .get(OsStr::new("XDG_CACHE_HOME"))
                .and_then(Option::as_deref),
            Some(OsStr::new("/synthetic/environment-home/cache"))
        );
        assert_eq!(
            environment
                .get(OsStr::new("XDG_RUNTIME_DIR"))
                .and_then(Option::as_deref),
            Some(OsStr::new("/synthetic/environment-home/run"))
        );
        for name in ["TMPDIR", "TMP", "TEMP"] {
            assert_eq!(
                environment.get(OsStr::new(name)).and_then(Option::as_deref),
                Some(OsStr::new("/synthetic/environment-home/tmp")),
                "{name} must remain inside the synthetic environment home"
            );
        }
    }

    #[test]
    fn pty_child_has_a_terminal_and_bounded_output() -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "test -t 0 && test -t 1 && printf calcifer-pty-ok"]);

        let child = PtyChild::spawn(command, Path::new("/tmp"))?;
        let output = child.wait_until_exit(
            Instant::now()
                .checked_add(Duration::from_secs(2))
                .ok_or("deadline overflow")?,
        )?;

        assert!(!output.overflowed);
        assert!(!output.failed);
        assert!(
            output
                .bytes
                .windows(b"calcifer-pty-ok".len())
                .any(|window| window == b"calcifer-pty-ok")
        );
        Ok(())
    }

    #[test]
    fn pty_shutdown_reaps_and_collects_a_natural_exit_after_proxy_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        const NATURAL_EXIT_MARKER: &[u8] = b"calcifer-natural-exit";

        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf calcifer-natural-exit; exit 7"]);
        let mut child = PtyChild::spawn(command, Path::new("/tmp"))?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or("deadline overflow")?;
        while !child_exit_observed_without_reaping(&mut child.child)? {
            if Instant::now() >= deadline {
                return Err("PTY child did not reach its natural exit".into());
            }
            thread::sleep(POLL_INTERVAL);
        }

        let output = child.shutdown()?;
        assert!(!output.overflowed);
        assert!(!output.failed);
        assert!(
            output
                .bytes
                .windows(NATURAL_EXIT_MARKER.len())
                .any(|window| window == NATURAL_EXIT_MARKER)
        );
        Ok(())
    }

    #[test]
    fn pty_slave_open_session_leader_helper() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(PTY_SESSION_LEADER_HELPER_ENV).is_none() {
            return Ok(());
        }
        let process = rustix::process::getpid();
        let session = rustix::process::setsid()?;
        if session != process
            || rustix::process::getpgrp() != process
            || rustix::process::getsid(Some(process))? != process
        {
            return Err("PTY helper did not become its own session leader".into());
        }
        if OpenOptions::new().read(true).open("/dev/tty").is_ok() {
            return Err("PTY helper unexpectedly began with a controlling terminal".into());
        }

        let master =
            rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)?;
        rustix::pty::grantpt(&master)?;
        rustix::pty::unlockpt(&master)?;
        let _slave = open_pty_slave(&master)?;

        if OpenOptions::new().read(true).open("/dev/tty").is_ok() {
            return Err("opening the PTY slave claimed a controlling terminal".into());
        }
        Ok(())
    }

    #[test]
    fn pty_slave_open_never_claims_a_controlling_terminal() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", PTY_SESSION_LEADER_HELPER_TEST, "--nocapture"])
            .env(PTY_SESSION_LEADER_HELPER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn()?;
        wait_for_success(
            &mut child,
            Instant::now()
                .checked_add(Duration::from_secs(2))
                .ok_or("deadline overflow")?,
        )?;
        Ok(())
    }

    #[test]
    fn pty_exit_kills_a_descendant_that_inherits_the_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        const DESCENDANT_READY: &[u8] = b"calcifer-descendant-ready";
        const DESCENDANT_SURVIVED: &[u8] = b"calcifer-descendant-survived";

        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "(trap '' HUP TERM; sleep 30; printf calcifer-descendant-survived) & \
             printf calcifer-descendant-ready; exit 0",
        ]);

        // This deadline bounds observation of the direct leader only. After
        // that exit, `wait_until_exit` kills the exact process group and joins
        // the PTY drainer. A total wall-clock assertion would therefore test
        // scheduler latency outside the deadline contract. The descendant's
        // terminal marker below instead proves whether it survived that kill
        // long enough to close the inherited descriptor naturally.
        let child = PtyChild::spawn(command, Path::new("/tmp"))?;
        let output = child.wait_until_exit(
            Instant::now()
                .checked_add(Duration::from_secs(2))
                .ok_or("deadline overflow")?,
        )?;

        assert!(!output.overflowed);
        assert!(!output.failed);
        assert!(
            output
                .bytes
                .windows(DESCENDANT_READY.len())
                .any(|window| window == DESCENDANT_READY)
        );
        assert!(
            !output
                .bytes
                .windows(DESCENDANT_SURVIVED.len())
                .any(|window| window == DESCENDANT_SURVIVED),
            "the exited leader's process-group kill must terminate the inherited PTY holder"
        );
        Ok(())
    }
}
