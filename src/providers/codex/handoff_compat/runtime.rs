use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::super::remote::{ReadinessProbe, ReadinessProxy, ReadinessProxyError};
use super::super::{
    AppServerProcess, CodexThreadError, CodexUsageError, child_exit_observed_without_reaping,
    child_reap_confirmed, configure_own_process_group, force_terminate_process_tree,
    probe_codex_version_command, reap_exited_process_tree, validate_initialize_result,
};
use super::{
    CodexExecutableIdentity, CodexHandoffCapability, CodexHandoffError, HandoffSchemaContract,
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
const SOURCE_TIMESTAMP: &str = "2026-07-15T00:00:00Z";
const SOURCE_FILENAME_TIMESTAMP: &str = "2026-07-15T00-00-00";
const MODEL_PROVIDER: &str = "calcifer_smoke";
const MODEL_NAME: &str = "calcifer-handoff-smoke";
const HISTORY_SENTINEL: &str = "calcifer handoff compatibility sentinel";
const MAX_TUI_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const PROBE_EXECUTABLE_FILE: &str = "codex";

pub(super) fn verify(
    codex_executable: &Path,
    timeout: Duration,
) -> Result<CodexHandoffCapability, CodexHandoffError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(CodexHandoffError::Timeout)?;
    let executable = capture_executable(codex_executable, deadline)?;
    let proof = verify_before_remote_until(&executable, deadline)?;
    let remote = verify_remote_tui(&proof.probe_executable, &proof, deadline)?;
    ensure_no_credentials(proof.scratch.path())?;
    ensure_no_model_request(&proof.model_listener)?;
    proof.probe_binary_directory.revalidate()?;
    revalidate_executable_until(&proof.probe_executable, Some(deadline))?;
    revalidate_executable_until(&executable, Some(deadline))?;
    Ok(mint_capability(
        executable,
        proof.schema,
        proof.fork,
        remote,
    ))
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
) -> Result<PreRemoteProof, CodexHandoffError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(CodexHandoffError::Timeout)?;
    let executable = capture_executable(codex_executable, deadline)?;
    verify_before_remote_until(&executable, deadline)
}

fn verify_before_remote_until(
    source_executable: &CodexExecutableIdentity,
    deadline: Instant,
) -> Result<PreRemoteProof, CodexHandoffError> {
    let scratch = ScratchRoot::create()?;
    let (probe_binary_directory, probe_executable) =
        stage_executable(source_executable, &scratch, deadline)?;
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
        &scratch,
        &source_home,
        &target_home,
        &workspace,
        &environment_home,
    )?;

    revalidate_executable_metadata(executable)?;
    let version_command =
        isolated_command(&executable.canonical_path, &target_home, &environment_home);
    let version = probe_codex_version_command(version_command, &workspace, deadline, None)
        .map_err(map_thread_error)?;
    target_config.revalidate(&target_home)?;
    revalidate_probe_roots(
        &scratch,
        &source_home,
        &target_home,
        &workspace,
        &environment_home,
    )?;
    if version != SUPPORTED_VERSION {
        return Err(CodexHandoffError::Unsupported);
    }
    #[cfg(test)]
    eprintln!("handoff probe: version gate passed");

    let schema = generate_and_validate_schemas(
        executable,
        &target_home,
        &environment_home,
        &workspace,
        &scratch,
        &target_config,
        deadline,
    )?;
    target_config.revalidate(&target_home)?;
    revalidate_probe_roots(
        &scratch,
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
        &scratch,
        &source_home,
        &target_home,
        &workspace,
        &environment_home,
    )?;

    Ok(PreRemoteProof {
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
    })
}

fn verify_remote_tui(
    executable: &CodexExecutableIdentity,
    proof: &PreRemoteProof,
    deadline: Instant,
) -> Result<RemoteTuiProof, CodexHandoffError> {
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
        return Err(CodexHandoffError::Protocol);
    }
    proxy.ensure_connected().map_err(map_proxy_error)?;
    proxy.shutdown().map_err(map_proxy_error)?;
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
        return Err(CodexHandoffError::Protocol);
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
    executable: CodexExecutableIdentity,
    _schema: HandoffSchemaContract,
    _fork: ForkProof,
    _remote: RemoteTuiProof,
) -> CodexHandoffCapability {
    CodexHandoffCapability { executable }
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
    scratch.revalidate()?;
    let directory = scratch.create_directory("b")?;
    let (mut input, before) = open_executable(&source.canonical_path)?;
    if before != metadata_from_identity(source) {
        return Err(CodexHandoffError::Unsupported);
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
        if Instant::now() >= deadline {
            return Err(CodexHandoffError::Timeout);
        }
        let count = input
            .read(&mut buffer)
            .map_err(|_| CodexHandoffError::Transport)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(CodexHandoffError::Unsupported)?;
        if total > MAX_EXECUTABLE_BYTES || total > source.length {
            return Err(CodexHandoffError::Unsupported);
        }
        output
            .write_all(&buffer[..count])
            .map_err(|_| CodexHandoffError::Transport)?;
        hasher.update(&buffer[..count]);
    }
    output
        .sync_all()
        .map_err(|_| CodexHandoffError::Transport)?;
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
        || source_after != before
        || source_visible != before
        || digest != source.digest
    {
        return Err(CodexHandoffError::Unsupported);
    }
    drop(output);
    directory.revalidate()?;
    scratch.revalidate()?;

    let staged = capture_executable(&directory.join(PROBE_EXECUTABLE_FILE), deadline)?;
    if staged.digest != source.digest || staged.length != source.length {
        return Err(CodexHandoffError::Unsupported);
    }
    Ok((directory, staged))
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
    let initialize = process
        .receive_result(INITIALIZE_REQUEST_ID, deadline)
        .map_err(map_usage_error)?;
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
    let result = process
        .receive_result(FORK_REQUEST_ID, deadline)
        .map_err(map_usage_error)?;
    process
        .shutdown()
        .map_err(|_| CodexHandoffError::Transport)?;
    source_home.revalidate()?;
    target_home.revalidate()?;
    environment_home.revalidate()?;
    workspace.revalidate()?;
    revalidate_executable_metadata(executable)?;
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
approval_policy = "never"
sandbox_mode = "read-only"
cli_auth_credentials_store = "file"
mcp_oauth_credentials_store = "file"

[features]
shell_snapshot = false

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
}

#[derive(Clone, Copy)]
struct ScratchIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

impl ScratchRoot {
    fn create() -> Result<Self, CodexHandoffError> {
        for _ in 0..4 {
            let path =
                Path::new("/tmp").join(format!("cfh-{}-{}", std::process::id(), Uuid::new_v4()));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    verify_private_directory(&path)?;
                    let path = fs::canonicalize(path).map_err(|_| CodexHandoffError::Transport)?;
                    verify_private_directory(&path)?;
                    let metadata =
                        fs::symlink_metadata(&path).map_err(|_| CodexHandoffError::Transport)?;
                    return Ok(Self {
                        path,
                        identity: ScratchIdentity {
                            device: metadata.dev(),
                            inode: metadata.ino(),
                            uid: metadata.uid(),
                        },
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(CodexHandoffError::Transport),
            }
        }
        Err(CodexHandoffError::Transport)
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
        if !metadata.file_type().is_dir()
            || metadata.dev() != self.identity.device
            || metadata.ino() != self.identity.inode
            || metadata.uid() != self.identity.uid
            || metadata.mode() & 0o077 != 0
        {
            return Err(CodexHandoffError::Protocol);
        }
        Ok(())
    }
}

impl Drop for ScratchRoot {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_dir()
            && metadata.dev() == self.identity.device
            && metadata.ino() == self.identity.inode
            && metadata.uid() == self.identity.uid
        {
            let _ = fs::remove_dir_all(&self.path);
        }
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
        | ReadinessProxyError::Transport
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
        let slave_name = rustix::pty::ptsname(&master, Vec::new())
            .map_err(|error| pty_spawn_error("ptsname", error))?;
        let slave_path = Path::new(OsStr::from_bytes(slave_name.to_bytes()));
        let slave = OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave_path)
            .map_err(|error| pty_spawn_error("open slave", error))?;
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
        if !self.reaped {
            let termination = force_terminate_process_tree(&mut self.child);
            self.reaped = child_reap_confirmed(&mut self.child);
            termination.map_err(|_| CodexHandoffError::Transport)?;
            if !self.reaped {
                return Err(CodexHandoffError::Transport);
            }
        }
        self.collect_after_reap()
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
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use super::*;

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
    fn app_server_socket_may_inherit_the_childs_normal_umask()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchRoot::create()?;
        let socket_path = scratch.path().join("app-server.sock");
        let _listener = UnixListener::bind(&socket_path)?;
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
    fn pty_exit_kills_a_descendant_that_inherits_the_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "(trap '' HUP TERM; sleep 30) & printf calcifer-descendant-ready; exit 0",
        ]);
        let started = Instant::now();

        let child = PtyChild::spawn(command, Path::new("/tmp"))?;
        let output = child.wait_until_exit(
            Instant::now()
                .checked_add(Duration::from_secs(2))
                .ok_or("deadline overflow")?,
        )?;

        assert!(
            output
                .bytes
                .windows(b"calcifer-descendant-ready".len())
                .any(|window| window == b"calcifer-descendant-ready")
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the inherited PTY descriptor must not stall cleanup"
        );
        Ok(())
    }
}
