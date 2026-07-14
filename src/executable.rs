use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) enum ExecutableError {
    NotFound,
    Unsafe,
    Io(io::Error),
}

impl ExecutableError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "codex_not_found",
            Self::Unsafe => "unsafe_codex_executable",
            Self::Io(_) => "executable_io_error",
        }
    }

    pub(crate) fn safe_message(&self) -> &'static str {
        match self {
            Self::NotFound => "An executable named 'codex' was not found on PATH.",
            Self::Unsafe => {
                "Calcifer refused the Codex executable because its path or permissions are unsafe."
            }
            Self::Io(error) => {
                let _ = error.kind();
                "Calcifer could not inspect the Codex executable."
            }
        }
    }
}

impl fmt::Display for ExecutableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for ExecutableError {}

impl From<io::Error> for ExecutableError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) fn resolve_codex() -> Result<PathBuf, ExecutableError> {
    let discovered = which::which("codex").map_err(|_| ExecutableError::NotFound)?;
    let executable = fs::canonicalize(discovered)?;
    let metadata = fs::symlink_metadata(&executable)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ExecutableError::Unsafe);
    }
    verify_executable_permissions(&executable, &metadata)?;

    if let Ok(current_directory) = std::env::current_dir() {
        if repository_root(&current_directory).is_some_and(|root| is_within(&executable, &root)) {
            return Err(ExecutableError::Unsafe);
        }
    }

    Ok(executable)
}

fn is_within(path: &Path, directory: &Path) -> bool {
    fs::canonicalize(directory)
        .is_ok_and(|canonical_directory| path.starts_with(canonical_directory))
}

fn repository_root(start: &Path) -> Option<PathBuf> {
    let canonical = fs::canonicalize(start).ok()?;
    canonical
        .ancestors()
        .find(|ancestor| ancestor.join(".git").exists())
        .map(Path::to_path_buf)
}

#[cfg(unix)]
fn verify_executable_permissions(
    executable: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ExecutableError> {
    use std::os::unix::fs::MetadataExt;

    let current_uid = rustix::process::getuid().as_raw();
    let mode = metadata.mode();
    let executable_owner = metadata.uid();
    if mode & 0o111 == 0
        || mode & 0o022 != 0
        || (executable_owner != 0 && executable_owner != current_uid)
    {
        return Err(ExecutableError::Unsafe);
    }

    for directory in executable.parent().into_iter().flat_map(Path::ancestors) {
        let metadata = fs::metadata(directory)?;
        let mode = metadata.mode();
        let owner = metadata.uid();
        let owner_is_trusted = owner == 0 || owner == current_uid;
        let writable_by_others = mode & 0o022 != 0;
        let sticky_directory = mode & 0o1000 != 0;
        if !metadata.is_dir() || !owner_is_trusted || (writable_by_others && !sticky_directory) {
            return Err(ExecutableError::Unsafe);
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_executable_permissions(
    _executable: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), ExecutableError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn repository_detection_does_not_treat_every_working_directory_as_a_repo()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sandbox = std::env::temp_dir().join(format!(
            "calcifer-executable-test-{}-{nonce}",
            std::process::id()
        ));
        let repo = sandbox.join("repo");
        let nested = repo.join("src").join("nested");
        let ordinary = sandbox.join("ordinary").join("nested");
        fs::create_dir_all(repo.join(".git"))?;
        fs::create_dir_all(&nested)?;
        fs::create_dir_all(&ordinary)?;

        assert_eq!(repository_root(&nested), Some(fs::canonicalize(&repo)?));
        assert_eq!(repository_root(&ordinary), None);

        fs::remove_dir_all(sandbox)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_executable_below_non_sticky_world_writable_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sandbox = std::env::temp_dir().join(format!(
            "calcifer-executable-permissions-{}-{nonce}",
            std::process::id()
        ));
        let unsafe_parent = sandbox.join("replaceable");
        let executable = unsafe_parent.join("codex");
        fs::create_dir_all(&unsafe_parent)?;
        fs::write(&executable, b"synthetic executable")?;
        fs::set_permissions(&sandbox, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;

        let result = verify_executable_permissions(&executable, &fs::metadata(&executable)?);
        assert!(matches!(result, Err(ExecutableError::Unsafe)));

        fs::remove_dir_all(sandbox)?;
        Ok(())
    }
}
