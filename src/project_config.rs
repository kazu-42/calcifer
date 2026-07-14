use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const MAX_PROJECT_CONFIG_BYTES: usize = 1024 * 1024;

const MANAGED_PROJECT_CONFIG_KEYS: &[&str] = &[
    "apps_mcp_product_sku",
    "chatgpt_base_url",
    "cli_auth_credentials_store",
    "debug",
    "experimental_realtime_webrtc_call_base_url",
    "experimental_realtime_ws_base_url",
    "experimental_thread_config_endpoint",
    "experimental_thread_store",
    "features",
    "forced_chatgpt_workspace_id",
    "forced_login_method",
    "log_dir",
    "marketplaces",
    "mcp_oauth_credentials_store",
    "mcp_servers",
    "model_catalog_json",
    "model_provider",
    "model_providers",
    "openai_base_url",
    "oss_provider",
    "plugins",
    "profile",
    "profiles",
    "project_root_markers",
    "sqlite_home",
];

// This allowlist is deliberately narrower than Codex's full 0.144.4 schema.
// Unknown future keys fail closed until their effect on managed routing and
// state has been reviewed.
const CODEX_0_144_4_SAFE_PROJECT_CONFIG_KEYS: &[&str] = &[
    "approval_policy",
    "compact_prompt",
    "developer_instructions",
    "disable_paste_burst",
    "file_opener",
    "hide_agent_reasoning",
    "hooks",
    "include_apps_instructions",
    "include_collaboration_mode_instructions",
    "include_environment_context",
    "include_permissions_instructions",
    "instructions",
    "model",
    "model_auto_compact_token_limit",
    "model_auto_compact_token_limit_scope",
    "model_context_window",
    "model_reasoning_effort",
    "model_reasoning_summary",
    "model_supports_reasoning_summaries",
    "model_verbosity",
    "notice",
    "permissions",
    "personality",
    "plan_mode_reasoning_effort",
    "project_doc_fallback_filenames",
    "project_doc_max_bytes",
    "review_model",
    "sandbox_mode",
    "sandbox_workspace_write",
    "show_raw_agent_reasoning",
    "skills",
    "suppress_unstable_features_warning",
    "tool_output_token_limit",
    "tool_suggest",
    "tools",
    "tui",
    "web_search",
    "windows",
];

pub(crate) struct LaunchContext {
    working_directory: PathBuf,
}

impl LaunchContext {
    pub(crate) fn working_directory(&self) -> &Path {
        &self.working_directory
    }
}

#[derive(Debug)]
pub(crate) enum ProjectConfigError {
    Unsafe,
    Io(io::Error),
}

impl ProjectConfigError {
    pub(crate) const fn code(&self) -> &'static str {
        "unsafe_project_configuration"
    }

    pub(crate) fn safe_message(&self) -> &'static str {
        if let Self::Io(error) = self {
            let _ = error.kind();
        }
        "Calcifer refused repository-local Codex configuration because it can alter managed account, provider, or state isolation."
    }
}

impl fmt::Display for ProjectConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for ProjectConfigError {}

impl From<io::Error> for ProjectConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) fn verify_current_repository_config() -> Result<LaunchContext, ProjectConfigError> {
    let current_directory = std::env::current_dir()?;
    verify_repository_config(&current_directory)
}

fn verify_repository_config(start: &Path) -> Result<LaunchContext, ProjectConfigError> {
    let working_directory = fs::canonicalize(start)?;
    if !fs::metadata(&working_directory)?.is_dir() {
        return Err(ProjectConfigError::Unsafe);
    }

    let repository_root = repository_root(&working_directory)?;
    let mut directories = Vec::new();
    for directory in working_directory.ancestors() {
        directories.push(directory.to_path_buf());
        if directory == repository_root {
            break;
        }
    }
    if directories
        .last()
        .is_none_or(|directory| directory != &repository_root)
    {
        return Err(ProjectConfigError::Unsafe);
    }
    directories.reverse();

    for directory in directories {
        verify_config_layer(&directory)?;
    }
    Ok(LaunchContext { working_directory })
}

fn repository_root(working_directory: &Path) -> Result<PathBuf, ProjectConfigError> {
    for directory in working_directory.ancestors() {
        let marker = directory.join(".git");
        match fs::symlink_metadata(marker) {
            Ok(metadata)
                if !is_link_like(&metadata) && (metadata.is_dir() || metadata.is_file()) =>
            {
                return Ok(directory.to_path_buf());
            }
            Ok(_) => return Err(ProjectConfigError::Unsafe),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(working_directory.to_path_buf())
}

fn verify_config_layer(directory: &Path) -> Result<(), ProjectConfigError> {
    let codex_directory = directory.join(".codex");
    match fs::symlink_metadata(&codex_directory) {
        Ok(metadata) if metadata.is_dir() && !is_link_like(&metadata) => {}
        Ok(_) => return Err(ProjectConfigError::Unsafe),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }

    match fs::symlink_metadata(codex_directory.join("agents")) {
        Ok(_) => return Err(ProjectConfigError::Unsafe),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let config = codex_directory.join("config.toml");
    let path_metadata = match fs::symlink_metadata(&config) {
        Ok(metadata) if metadata.is_file() && !is_link_like(&metadata) => metadata,
        Ok(_) => return Err(ProjectConfigError::Unsafe),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };

    verify_config_file(&config, &path_metadata)
}

fn verify_config_file(path: &Path, path_metadata: &Metadata) -> Result<(), ProjectConfigError> {
    let mut file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() || !same_file(path_metadata, &opened_metadata) {
        return Err(ProjectConfigError::Unsafe);
    }

    let read_limit = u64::try_from(MAX_PROJECT_CONFIG_BYTES)
        .map_err(|_| ProjectConfigError::Unsafe)?
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.by_ref().take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PROJECT_CONFIG_BYTES {
        return Err(ProjectConfigError::Unsafe);
    }
    let final_path_metadata = fs::symlink_metadata(path)?;
    if !final_path_metadata.is_file()
        || is_link_like(&final_path_metadata)
        || !same_file(&opened_metadata, &final_path_metadata)
    {
        return Err(ProjectConfigError::Unsafe);
    }

    let text = std::str::from_utf8(&bytes).map_err(|_| ProjectConfigError::Unsafe)?;
    let table = text
        .parse::<toml::Table>()
        .map_err(|_| ProjectConfigError::Unsafe)?;
    if table.keys().any(|key| {
        MANAGED_PROJECT_CONFIG_KEYS.contains(&key.as_str())
            || !CODEX_0_144_4_SAFE_PROJECT_CONFIG_KEYS.contains(&key.as_str())
    }) {
        return Err(ProjectConfigError::Unsafe);
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    before.dev() == after.dev() && before.ino() == after.ino()
}

#[cfg(not(unix))]
fn same_file(_before: &Metadata, _after: &Metadata) -> bool {
    true
}

#[cfg(windows)]
fn is_link_like(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link_like(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::*;

    fn sandbox(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "calcifer-project-config-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root)?;
        Ok(root)
    }

    fn write_config(directory: &Path, contents: &[u8]) -> io::Result<()> {
        let codex_directory = directory.join(".codex");
        fs::create_dir_all(&codex_directory)?;
        fs::write(codex_directory.join("config.toml"), contents)
    }

    #[test]
    fn accepts_benign_layers_from_repository_root_to_working_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("benign")?;
        let nested = root.join("src").join("nested");
        fs::create_dir(root.join(".git"))?;
        fs::create_dir_all(&nested)?;
        write_config(&root, b"model = \"gpt-5.4\"\n")?;
        write_config(&nested, b"instructions = \"Use repository rules\"\n")?;

        assert!(verify_repository_config(&nested).is_ok());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_every_managed_project_configuration_key() -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("managed-keys")?;
        fs::create_dir(root.join(".git"))?;

        for key in MANAGED_PROJECT_CONFIG_KEYS {
            write_config(&root, format!("{key} = true\n").as_bytes())?;
            assert!(
                verify_repository_config(&root).is_err(),
                "managed project key {key} must be rejected"
            );
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn pinned_safe_keys_are_sorted_unique_and_disjoint_from_managed_keys() {
        assert!(
            CODEX_0_144_4_SAFE_PROJECT_CONFIG_KEYS
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(
            MANAGED_PROJECT_CONFIG_KEYS
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        for key in MANAGED_PROJECT_CONFIG_KEYS {
            assert!(!CODEX_0_144_4_SAFE_PROJECT_CONFIG_KEYS.contains(key));
        }
    }

    #[test]
    fn rejects_invalid_and_oversized_project_configuration()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("invalid")?;
        fs::create_dir(root.join(".git"))?;

        write_config(&root, b"not valid = [toml")?;
        assert!(verify_repository_config(&root).is_err());

        write_config(&root, &vec![b' '; MAX_PROJECT_CONFIG_BYTES])?;
        assert!(verify_repository_config(&root).is_ok());

        write_config(&root, &vec![b' '; MAX_PROJECT_CONFIG_BYTES + 1])?;
        assert!(verify_repository_config(&root).is_err());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_unknown_future_keys_without_disclosing_contents_or_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("unknown-key")?;
        fs::create_dir(root.join(".git"))?;
        let sensitive = "synthetic-token-value";
        write_config(
            &root,
            format!("future_routing_key = \"{sensitive}\"\n").as_bytes(),
        )?;

        let error = match verify_repository_config(&root) {
            Ok(_) => return Err(io::Error::other("unknown key was accepted").into()),
            Err(error) => error,
        };
        let rendered = error.to_string();
        assert!(!rendered.contains("future_routing_key"));
        assert!(!rendered.contains(sensitive));
        assert!(!rendered.contains(&root.display().to_string()));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn a_non_repository_scans_only_the_working_directory() -> Result<(), Box<dyn std::error::Error>>
    {
        let outer = sandbox("ordinary-directory")?;
        let working_directory = outer.join("nested");
        fs::create_dir(&working_directory)?;
        write_config(&outer, b"debug = {}\n")?;
        write_config(&working_directory, b"model = \"gpt-5.4\"\n")?;

        assert!(verify_repository_config(&working_directory).is_ok());

        write_config(&working_directory, b"debug = {}\n")?;
        assert!(verify_repository_config(&working_directory).is_err());

        fs::remove_dir_all(outer)?;
        Ok(())
    }

    #[test]
    fn accepts_a_regular_file_git_worktree_marker() -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("git-file")?;
        let nested = root.join("nested");
        fs::create_dir(&nested)?;
        fs::write(root.join(".git"), "gitdir: /synthetic/git-dir\n")?;
        write_config(&root, b"model = \"gpt-5.4\"\n")?;

        assert!(verify_repository_config(&nested).is_ok());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_non_directory_and_non_regular_configuration_nodes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("node-types")?;
        fs::create_dir(root.join(".git"))?;
        fs::write(root.join(".codex"), "not a directory")?;
        assert!(verify_repository_config(&root).is_err());

        fs::remove_file(root.join(".codex"))?;
        fs::create_dir(root.join(".codex"))?;
        fs::create_dir(root.join(".codex").join("config.toml"))?;
        assert!(verify_repository_config(&root).is_err());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_auto_discovered_project_agents_nodes_with_or_without_config()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = sandbox("agents-node")?;
        fs::create_dir(root.join(".git"))?;
        fs::create_dir(root.join(".codex"))?;
        let agents = root.join(".codex").join("agents");

        fs::create_dir(&agents)?;
        let directory_error = match verify_repository_config(&root) {
            Err(error) => error,
            Ok(_) => return Err(io::Error::other("project agents directory was accepted").into()),
        };
        fs::remove_dir(&agents)?;

        write_config(&root, b"model = \"gpt-5.4\"\n")?;
        fs::write(&agents, "synthetic role")?;
        let file_error = match verify_repository_config(&root) {
            Err(error) => error,
            Ok(_) => return Err(io::Error::other("project agents file was accepted").into()),
        };

        for error in [directory_error, file_error] {
            assert_eq!(error.code(), "unsafe_project_configuration");
            let message = error.safe_message();
            assert!(!message.contains("agents"));
            assert!(!message.contains(&root.display().to_string()));
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_dangling_and_special_project_agents_nodes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let unique = uuid::Uuid::new_v4().to_string();
        let root = std::env::temp_dir().join(format!("ca-{}", &unique[..8]));
        fs::create_dir(&root)?;
        fs::create_dir(root.join(".git"))?;
        fs::create_dir(root.join(".codex"))?;
        let agents = root.join(".codex").join("agents");
        let target = root.join("synthetic-role.toml");
        fs::write(&target, "model = \"gpt-5.4\"\n")?;

        symlink(&target, &agents)?;
        assert!(verify_repository_config(&root).is_err());
        fs::remove_file(&agents)?;

        symlink(root.join("missing-role.toml"), &agents)?;
        assert!(verify_repository_config(&root).is_err());
        fs::remove_file(&agents)?;

        let listener = UnixListener::bind(&agents)?;
        assert!(verify_repository_config(&root).is_err());
        drop(listener);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn fails_closed_when_project_agents_metadata_cannot_be_read()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        if rustix::process::geteuid().is_root() {
            return Ok(());
        }

        let root = sandbox("agents-metadata-error")?;
        fs::create_dir(root.join(".git"))?;
        let codex_directory = root.join(".codex");
        fs::create_dir(&codex_directory)?;
        fs::set_permissions(&codex_directory, fs::Permissions::from_mode(0o600))?;

        let result = verify_repository_config(&root);
        fs::set_permissions(&codex_directory, fs::Permissions::from_mode(0o700))?;
        assert!(matches!(
            result,
            Err(ProjectConfigError::Io(ref error))
                if error.kind() == io::ErrorKind::PermissionDenied
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stops_at_the_nearest_repository_boundary_and_scans_its_ancestors()
    -> Result<(), Box<dyn std::error::Error>> {
        let outer = sandbox("nested-repository")?;
        let inner = outer.join("inner");
        let nested = inner.join("src");
        fs::create_dir(outer.join(".git"))?;
        fs::create_dir_all(inner.join(".git"))?;
        fs::create_dir_all(&nested)?;
        write_config(
            &outer,
            b"experimental_thread_config_endpoint = \"synthetic\"\n",
        )?;
        write_config(&inner, b"model = \"gpt-5.4\"\n")?;

        assert!(verify_repository_config(&nested).is_ok());

        write_config(&inner, b"debug = {}\n")?;
        assert!(verify_repository_config(&nested).is_err());

        fs::remove_dir_all(outer)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_project_configuration_state() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = sandbox("symlink")?;
        let external = sandbox("symlink-target")?;
        fs::create_dir(root.join(".git"))?;
        write_config(&external, b"model = \"gpt-5.4\"\n")?;
        symlink(external.join(".codex"), root.join(".codex"))?;

        assert!(verify_repository_config(&root).is_err());

        fs::remove_dir_all(root)?;
        fs::remove_dir_all(external)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_config_files_and_repository_markers()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = sandbox("symlink-file")?;
        let external = sandbox("symlink-file-target")?;
        fs::create_dir(root.join(".git"))?;
        fs::create_dir(root.join(".codex"))?;
        let external_config = external.join("config.toml");
        fs::write(&external_config, "model = \"gpt-5.4\"\n")?;
        symlink(&external_config, root.join(".codex").join("config.toml"))?;
        assert!(verify_repository_config(&root).is_err());

        fs::remove_file(root.join(".codex").join("config.toml"))?;
        fs::write(
            root.join(".codex").join("config.toml"),
            "model = \"gpt-5.4\"\n",
        )?;
        fs::remove_dir_all(root.join(".git"))?;
        symlink(external.join("missing-git-dir"), root.join(".git"))?;
        assert!(verify_repository_config(&root).is_err());

        fs::remove_dir_all(root)?;
        fs::remove_dir_all(external)?;
        Ok(())
    }
}
