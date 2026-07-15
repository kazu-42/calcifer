//! Owner-private runtime state for the staged Codex supervisor.
//!
//! Cleanup is explicit and identity-conditioned. Dropping an unclean runtime
//! deliberately leaves it in place: a path replacement must never turn a
//! best-effort destructor into authority to delete an unverified node.

use std::fmt;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use uuid::Uuid;

const RUNTIME_CREATE_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl NodeIdentity {
    fn private_directory(metadata: &fs::Metadata) -> Result<Self, RuntimeError> {
        let mode = metadata.permissions().mode() & 0o777;
        if !metadata.file_type().is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || mode != 0o700
        {
            return Err(RuntimeError::UnsafeIdentity);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode,
        })
    }

    fn matches_private_directory(self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_dir()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.uid() == self.uid
            && metadata.permissions().mode() & 0o777 == self.mode
    }
}

/// A fresh nonce directory whose exact filesystem identity is retained.
#[must_use = "a supervisor runtime must be explicitly cleaned or deliberately preserved"]
pub(super) struct PrivateRuntime {
    path: PathBuf,
    identity: NodeIdentity,
}

impl PrivateRuntime {
    /// Creates a new empty mode-0700 directory below an already-private parent.
    pub(super) fn create(parent: &Path) -> Result<Self, RuntimeError> {
        let canonical_parent = fs::canonicalize(parent).map_err(|_| RuntimeError::UnsafeParent)?;
        if canonical_parent != parent {
            return Err(RuntimeError::UnsafeParent);
        }
        let parent_identity = private_parent_identity(parent)?;

        for _ in 0..RUNTIME_CREATE_ATTEMPTS {
            let path = parent.join(format!(".calcifer-supervisor-{}", Uuid::new_v4()));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    let metadata =
                        fs::symlink_metadata(&path).map_err(|_| RuntimeError::UnsafeIdentity)?;
                    let identity = NodeIdentity::private_directory(&metadata)?;
                    let current_parent =
                        fs::symlink_metadata(parent).map_err(|_| RuntimeError::UnsafeParent)?;
                    if !parent_identity.matches_private_directory(&current_parent) {
                        return Err(RuntimeError::UnsafeParent);
                    }
                    return Ok(Self { path, identity });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(RuntimeError::Create),
            }
        }
        Err(RuntimeError::Create)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Removes only the still-empty directory with the exact recorded identity.
    pub(super) fn cleanup(self) -> Result<CleanRuntime, RuntimeCleanupFailure> {
        match self.verify_empty_and_remove() {
            Ok(()) => Ok(CleanRuntime { _private: () }),
            Err(error) => Err(RuntimeCleanupFailure {
                runtime: self,
                error,
            }),
        }
    }

    fn verify_empty_and_remove(&self) -> Result<(), RuntimeError> {
        self.verify_identity()?;
        let mut entries = fs::read_dir(&self.path).map_err(|_| RuntimeError::Cleanup)?;
        if entries
            .next()
            .transpose()
            .map_err(|_| RuntimeError::Cleanup)?
            .is_some()
        {
            return Err(RuntimeError::NotEmpty);
        }
        // Recheck after enumeration so a mode or identity change observed
        // before unlink cannot be silently accepted.
        self.verify_identity()?;
        fs::remove_dir(&self.path).map_err(|_| RuntimeError::Cleanup)
    }

    fn verify_identity(&self) -> Result<(), RuntimeError> {
        let metadata =
            fs::symlink_metadata(&self.path).map_err(|_| RuntimeError::IdentityMismatch)?;
        if self.identity.matches_private_directory(&metadata) {
            Ok(())
        } else {
            Err(RuntimeError::IdentityMismatch)
        }
    }
}

fn private_parent_identity(parent: &Path) -> Result<NodeIdentity, RuntimeError> {
    let metadata = fs::symlink_metadata(parent).map_err(|_| RuntimeError::UnsafeParent)?;
    NodeIdentity::private_directory(&metadata).map_err(|_| RuntimeError::UnsafeParent)
}

/// Capability minted only after exact runtime cleanup succeeds.
pub(super) struct CleanRuntime {
    _private: (),
}

/// Preserves the unclean runtime and a redacted failure classification.
pub(super) struct RuntimeCleanupFailure {
    runtime: PrivateRuntime,
    error: RuntimeError,
}

impl RuntimeCleanupFailure {
    pub(super) const fn error(&self) -> RuntimeError {
        self.error
    }

    pub(super) fn into_runtime(self) -> PrivateRuntime {
        self.runtime
    }
}

impl fmt::Debug for RuntimeCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeCleanupFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeError {
    UnsafeParent,
    Create,
    UnsafeIdentity,
    IdentityMismatch,
    NotEmpty,
    Cleanup,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeParent => "supervisor runtime parent is unsafe",
            Self::Create => "supervisor runtime creation failed",
            Self::UnsafeIdentity => "supervisor runtime identity is unsafe",
            Self::IdentityMismatch => "supervisor runtime identity changed",
            Self::NotEmpty => "supervisor runtime contains an unknown entry",
            Self::Cleanup => "supervisor runtime cleanup failed",
        })
    }
}

impl std::error::Error for RuntimeError {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Result<Self, Box<dyn Error>> {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let raw = std::env::temp_dir().join(format!(
                "calcifer-supervisor-runtime-test-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&raw)?;
            Ok(Self {
                path: fs::canonicalize(raw)?,
            })
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn creates_an_owner_private_nonce_runtime_and_removes_only_that_identity()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        let metadata = fs::symlink_metadata(&path)?;

        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("runtime name must be UTF-8")?;
        let nonce = name
            .strip_prefix(".calcifer-supervisor-")
            .ok_or("runtime name prefix is missing")?;
        assert_eq!(Uuid::parse_str(nonce)?.to_string(), nonce);

        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn cleanup_preserves_a_replacement_directory() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        let original = parent.path.join("preserved-original");
        fs::rename(&path, &original)?;
        fs::DirBuilder::new().mode(0o700).create(&path)?;

        let failure = runtime.cleanup().err().ok_or("cleanup must fail")?;
        assert_eq!(failure.error(), RuntimeError::IdentityMismatch);
        assert!(path.is_dir());
        assert!(original.is_dir());
        let _runtime = failure.into_runtime();
        Ok(())
    }

    #[test]
    fn cleanup_preserves_a_runtime_whose_mode_changed() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;

        let failure = runtime.cleanup().err().ok_or("cleanup must fail")?;
        assert_eq!(failure.error(), RuntimeError::IdentityMismatch);
        assert!(path.is_dir());
        Ok(())
    }

    #[test]
    fn cleanup_preserves_unknown_entries() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        fs::write(path.join("unexpected"), b"synthetic")?;

        let failure = runtime.cleanup().err().ok_or("cleanup must fail")?;
        assert_eq!(failure.error(), RuntimeError::NotEmpty);
        assert_eq!(fs::read(path.join("unexpected"))?, b"synthetic");
        Ok(())
    }

    #[test]
    fn creation_rejects_non_private_and_symlinked_parents() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        fs::set_permissions(&parent.path, fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            PrivateRuntime::create(&parent.path),
            Err(RuntimeError::UnsafeParent)
        ));
        fs::set_permissions(&parent.path, fs::Permissions::from_mode(0o700))?;

        let link = parent.path.with_extension("link");
        std::os::unix::fs::symlink(&parent.path, &link)?;
        assert!(matches!(
            PrivateRuntime::create(&link),
            Err(RuntimeError::UnsafeParent)
        ));
        fs::remove_file(link)?;
        Ok(())
    }

    #[test]
    fn cleanup_errors_never_render_the_runtime_path() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        fs::write(path.join("do-not-render"), b"synthetic")?;

        let failure = runtime.cleanup().err().ok_or("cleanup must fail")?;
        let rendered = format!("{failure:?}");
        assert!(!rendered.contains(path.to_string_lossy().as_ref()));
        assert!(!rendered.contains("do-not-render"));
        Ok(())
    }
}
