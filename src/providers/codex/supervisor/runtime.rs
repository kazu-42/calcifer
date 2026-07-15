//! Owner-private runtime state for the staged Codex supervisor.
//!
//! Cleanup is explicit, descriptor-relative, and identity-conditioned.
//! Dropping an unclean runtime deliberately leaves it in place: a path
//! replacement must never become authority to report an unverified deletion as
//! a clean runtime transition.

use std::fmt;
use std::fs;
#[cfg(feature = "internal-supervisor-fixture")]
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{
    AtFlags, Dir, FileType, Mode, OFlags, RawMode, RenameFlags, Stat, fstat, mkdirat, open, openat,
    renameat_with, statat, unlinkat,
};
use uuid::Uuid;

const RUNTIME_CREATE_ATTEMPTS: usize = 8;
const RUNTIME_QUARANTINE_ATTEMPTS: usize = 8;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

#[cfg(target_os = "linux")]
fn stat_permission_mode(mode: RawMode) -> u32 {
    mode & 0o7777
}

#[cfg(target_os = "macos")]
fn stat_permission_mode(mode: RawMode) -> u32 {
    u32::from(mode & 0o7777)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl NodeIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
        }
    }

    fn private_directory_metadata(metadata: &fs::Metadata) -> Result<Self, RuntimeError> {
        let identity = Self::from_metadata(metadata);
        if metadata.file_type().is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && identity.mode == PRIVATE_DIRECTORY_MODE
        {
            Ok(identity)
        } else {
            Err(RuntimeError::UnsafeIdentity)
        }
    }

    fn from_stat(stat: &Stat) -> Self {
        #[cfg(target_os = "macos")]
        let device = u64::from(stat.st_dev as u32);
        #[cfg(target_os = "linux")]
        let device = stat.st_dev;

        Self {
            device,
            inode: stat.st_ino,
            uid: stat.st_uid,
            mode: stat_permission_mode(stat.st_mode),
        }
    }

    fn private_directory_stat(stat: &Stat) -> Result<Self, RuntimeError> {
        let identity = Self::from_stat(stat);
        if FileType::from_raw_mode(stat.st_mode).is_dir()
            && stat.st_uid == rustix::process::geteuid().as_raw()
            && identity.mode == PRIVATE_DIRECTORY_MODE
        {
            Ok(identity)
        } else {
            Err(RuntimeError::UnsafeIdentity)
        }
    }

    fn matches_private_metadata(self, metadata: &fs::Metadata) -> bool {
        Self::private_directory_metadata(metadata) == Ok(self)
    }

    fn matches_private_stat(self, stat: &Stat) -> bool {
        Self::private_directory_stat(stat) == Ok(self)
    }
}

/// A parent directory whose open inode, visible path, owner, mode, and ACL are
/// bound together. All mutation authority below it uses `descriptor`, never
/// the rendered path.
struct StableParent {
    path: PathBuf,
    descriptor: OwnedFd,
    identity: NodeIdentity,
}

impl StableParent {
    fn open_private(parent: &Path) -> Result<Self, RuntimeError> {
        let canonical_parent = fs::canonicalize(parent).map_err(|_| RuntimeError::UnsafeParent)?;
        if canonical_parent != parent {
            return Err(RuntimeError::UnsafeParent);
        }

        let visible_before =
            fs::symlink_metadata(parent).map_err(|_| RuntimeError::UnsafeParent)?;
        let visible_identity = NodeIdentity::private_directory_metadata(&visible_before)
            .map_err(|_| RuntimeError::UnsafeParent)?;
        let descriptor = open(parent, directory_open_flags(), Mode::empty())
            .map_err(|_| RuntimeError::UnsafeParent)?;
        let opened_stat = fstat(&descriptor).map_err(|_| RuntimeError::UnsafeParent)?;
        let opened_identity = NodeIdentity::private_directory_stat(&opened_stat)
            .map_err(|_| RuntimeError::UnsafeParent)?;
        if opened_identity != visible_identity || !open_inode_acl_is_empty(&descriptor) {
            return Err(RuntimeError::UnsafeParent);
        }

        let stable = Self {
            path: parent.to_path_buf(),
            descriptor,
            identity: opened_identity,
        };
        stable.verify()?;
        Ok(stable)
    }

    fn verify(&self) -> Result<(), RuntimeError> {
        let opened = fstat(&self.descriptor).map_err(|_| RuntimeError::UnsafeParent)?;
        if !self.identity.matches_private_stat(&opened)
            || !open_inode_acl_is_empty(&self.descriptor)
        {
            return Err(RuntimeError::UnsafeParent);
        }
        let visible = fs::symlink_metadata(&self.path).map_err(|_| RuntimeError::UnsafeParent)?;
        if self.identity.matches_private_metadata(&visible) {
            Ok(())
        } else {
            Err(RuntimeError::UnsafeParent)
        }
    }
}

fn directory_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
}

#[cfg(target_os = "macos")]
fn open_inode_acl_is_empty(descriptor: impl AsFd) -> bool {
    calcifer_macos_acl::read_acl(descriptor.as_fd()).is_ok_and(|acl| acl.is_empty())
}

#[cfg(not(target_os = "macos"))]
fn open_inode_acl_is_empty(_descriptor: impl AsFd) -> bool {
    true
}

#[cfg(target_os = "macos")]
fn clear_created_inode_acl(descriptor: impl AsFd) -> bool {
    calcifer_macos_acl::clear_acl(descriptor.as_fd()).is_ok() && open_inode_acl_is_empty(descriptor)
}

#[cfg(not(target_os = "macos"))]
fn clear_created_inode_acl(_descriptor: impl AsFd) -> bool {
    true
}

#[cfg(target_os = "linux")]
fn open_inode_was_unlinked(
    _descriptor: impl AsFd,
    unlinked: &Stat,
    _linked_count: u64,
    _expected_path: &Path,
) -> bool {
    unlinked.st_nlink == 0
}

#[cfg(target_os = "macos")]
fn open_inode_was_unlinked(
    descriptor: impl AsFd,
    unlinked: &Stat,
    linked_count: u64,
    expected_path: &Path,
) -> bool {
    // APFS keeps the open directory vnode's link count unchanged after rmdir.
    // F_GETPATH continues to report its last path, but follows a rename. The
    // expected quarantine path therefore distinguishes our removed vnode from
    // an original that was moved aside while a replacement was unlinked. The
    // path comparison is the primary Darwin proof; the non-increasing link
    // count additionally rejects a late child/link addition to the directory
    // that was verified empty immediately before this race window.
    unlinked.st_nlink as u64 <= linked_count
        && rustix::fs::getpath(descriptor)
            .is_ok_and(|path| path.to_bytes() == expected_path.as_os_str().as_bytes())
}

/// A fresh nonce directory whose exact open filesystem identity is retained.
#[must_use = "a supervisor runtime must be explicitly cleaned or deliberately preserved"]
pub(super) struct PrivateRuntime {
    path: PathBuf,
    name: Option<String>,
    parent: StableParent,
    directory: OwnedFd,
    identity: NodeIdentity,
}

impl PrivateRuntime {
    /// Creates a new empty mode-0700 directory below an already-private parent.
    pub(super) fn create(parent: &Path) -> Result<Self, RuntimeCreateFailure> {
        Self::create_inner(parent, |_| Ok(()))
    }

    fn create_inner<F>(parent: &Path, mut post_mkdir: F) -> Result<Self, RuntimeCreateFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        let stable_parent =
            StableParent::open_private(parent).map_err(RuntimeCreateFailure::not_created)?;

        for _ in 0..RUNTIME_CREATE_ATTEMPTS {
            let name = format!(".calcifer-supervisor-{}", Uuid::new_v4());
            match mkdirat(
                &stable_parent.descriptor,
                name.as_str(),
                Mode::from_raw_mode(0o700),
            ) {
                Ok(()) => {
                    let path = stable_parent.path.join(&name);
                    let created = CreatedRuntimePath {
                        path,
                        name: Some(name),
                        parent: stable_parent,
                        directory: None,
                        identity: None,
                    };
                    return Self::finish_created_runtime(created, &mut post_mkdir);
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(_) => {
                    return Err(RuntimeCreateFailure::not_created(RuntimeError::Create));
                }
            }
        }
        Err(RuntimeCreateFailure::not_created(RuntimeError::Create))
    }

    fn finish_created_runtime<F>(
        mut created: CreatedRuntimePath,
        post_mkdir: &mut F,
    ) -> Result<Self, RuntimeCreateFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        let Some(name) = created.name.as_deref() else {
            return Err(RuntimeCreateFailure::with_created(
                RuntimeError::UnsafeIdentity,
                created,
            ));
        };
        let directory = match openat(
            &created.parent.descriptor,
            name,
            directory_open_flags(),
            Mode::empty(),
        ) {
            Ok(directory) => directory,
            Err(_) => {
                return Err(RuntimeCreateFailure::with_created(
                    RuntimeError::UnsafeIdentity,
                    created,
                ));
            }
        };
        let opened_stat = match fstat(&directory) {
            Ok(stat) => stat,
            Err(_) => {
                created.directory = Some(directory);
                return Err(RuntimeCreateFailure::with_created(
                    RuntimeError::UnsafeIdentity,
                    created,
                ));
            }
        };
        let opened_identity = NodeIdentity::from_stat(&opened_stat);
        created.identity = Some(opened_identity);
        created.directory = Some(directory);
        if NodeIdentity::private_directory_stat(&opened_stat) != Ok(opened_identity) {
            return Err(RuntimeCreateFailure::with_created(
                RuntimeError::UnsafeIdentity,
                created,
            ));
        }
        let Some(directory) = created.directory.as_ref() else {
            return Err(RuntimeCreateFailure::with_created(
                RuntimeError::UnsafeIdentity,
                created,
            ));
        };
        if !clear_created_inode_acl(directory) {
            return Err(RuntimeCreateFailure::with_created(
                RuntimeError::UnsafeIdentity,
                created,
            ));
        }
        if post_mkdir(&created.path).is_err() {
            return Err(RuntimeCreateFailure::with_created(
                RuntimeError::UnsafeIdentity,
                created,
            ));
        }

        let descriptor_stat = match fstat(directory) {
            Ok(stat) => stat,
            Err(_) => {
                return Err(RuntimeCreateFailure::with_created(
                    RuntimeError::UnsafeIdentity,
                    created,
                ));
            }
        };
        let entry_stat = match statat(&created.parent.descriptor, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(_) => {
                return Err(RuntimeCreateFailure::with_created(
                    RuntimeError::UnsafeIdentity,
                    created,
                ));
            }
        };
        if !opened_identity.matches_private_stat(&descriptor_stat)
            || !opened_identity.matches_private_stat(&entry_stat)
            || !open_inode_acl_is_empty(directory)
        {
            return Err(RuntimeCreateFailure::with_created(
                RuntimeError::UnsafeIdentity,
                created,
            ));
        }
        if created.parent.verify().is_err() {
            return Err(RuntimeCreateFailure::with_created(
                RuntimeError::UnsafeParent,
                created,
            ));
        }

        let Some(directory) = created.directory.take() else {
            return Err(RuntimeCreateFailure::with_created(
                RuntimeError::UnsafeIdentity,
                created,
            ));
        };
        Ok(Self {
            path: created.path,
            name: created.name,
            parent: created.parent,
            directory,
            identity: opened_identity,
        })
    }

    #[cfg(test)]
    fn create_with_post_mkdir<F>(parent: &Path, post_mkdir: F) -> Result<Self, RuntimeCreateFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        Self::create_inner(parent, post_mkdir)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Removes only the still-empty directory with the exact recorded identity.
    pub(super) fn cleanup(self) -> Result<CleanRuntime, RuntimeCleanupFailure> {
        self.cleanup_inner(|_| Ok(()))
    }

    #[cfg(test)]
    fn cleanup_with_before_unlink<F>(
        self,
        before_unlink: F,
    ) -> Result<CleanRuntime, RuntimeCleanupFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        self.cleanup_inner(before_unlink)
    }

    fn cleanup_inner<F>(
        mut self,
        mut before_unlink: F,
    ) -> Result<CleanRuntime, RuntimeCleanupFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        let result = (|| {
            self.verify_runtime_entry()?;
            self.verify_empty()?;
            self.move_to_quarantine()?;
            self.verify_runtime_entry()?;
            self.verify_empty()?;
            self.verify_runtime_entry()?;
            let linked = fstat(&self.directory).map_err(|_| RuntimeError::IdentityMismatch)?;
            let linked_count = linked.st_nlink as u64;
            if linked_count == 0 || !self.identity.matches_private_stat(&linked) {
                return Err(RuntimeError::IdentityMismatch);
            }

            // The test hook is deliberately after the final path/descriptor
            // comparison. The open-inode postcondition below must still catch
            // a replacement in this last unavoidable unlinkat race window.
            before_unlink(&self.path).map_err(|_| RuntimeError::Cleanup)?;
            let Some(name) = self.name.clone() else {
                return Err(RuntimeError::IdentityMismatch);
            };
            unlinkat(&self.parent.descriptor, name.as_str(), AtFlags::REMOVEDIR)
                .map_err(|_| RuntimeError::Cleanup)?;
            self.name = None;

            // `unlinkat` is path-relative, so a final replacement could make
            // it remove a different empty directory. Only the retained open
            // inode postcondition proves that our runtime was the directory
            // actually removed. Linux reports zero links; Darwin keeps the
            // vnode count unchanged, so its descriptor path must remain the
            // now-absent quarantine path (a rename updates F_GETPATH). Recheck
            // mode and ACL as well before minting the clean capability.
            let unlinked = fstat(&self.directory).map_err(|_| RuntimeError::IdentityMismatch)?;
            let name_is_absent = matches!(
                statat(
                    &self.parent.descriptor,
                    name.as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                ),
                Err(rustix::io::Errno::NOENT)
            );
            if !name_is_absent
                || !open_inode_was_unlinked(&self.directory, &unlinked, linked_count, &self.path)
                || !self.identity.matches_private_stat(&unlinked)
                || !open_inode_acl_is_empty(&self.directory)
            {
                return Err(RuntimeError::IdentityMismatch);
            }
            Ok(())
        })();

        match result {
            Ok(()) => Ok(CleanRuntime { _private: () }),
            Err(error) => Err(RuntimeCleanupFailure {
                runtime: Box::new(self),
                error,
            }),
        }
    }

    fn verify_runtime_entry(&self) -> Result<(), RuntimeError> {
        self.parent.verify()?;
        let opened = fstat(&self.directory).map_err(|_| RuntimeError::IdentityMismatch)?;
        if !self.identity.matches_private_stat(&opened) || !open_inode_acl_is_empty(&self.directory)
        {
            return Err(RuntimeError::IdentityMismatch);
        }
        let Some(name) = self.name.as_deref() else {
            return Err(RuntimeError::IdentityMismatch);
        };
        let visible = statat(&self.parent.descriptor, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| RuntimeError::IdentityMismatch)?;
        if self.identity.matches_private_stat(&visible) {
            Ok(())
        } else {
            Err(RuntimeError::IdentityMismatch)
        }
    }

    fn verify_empty(&self) -> Result<(), RuntimeError> {
        let directory = Dir::read_from(&self.directory).map_err(|_| RuntimeError::Cleanup)?;
        for entry in directory {
            let entry = entry.map_err(|_| RuntimeError::Cleanup)?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                return Err(RuntimeError::NotEmpty);
            }
        }
        Ok(())
    }

    fn move_to_quarantine(&mut self) -> Result<(), RuntimeError> {
        let Some(current_name) = self.name.clone() else {
            return Err(RuntimeError::IdentityMismatch);
        };
        for _ in 0..RUNTIME_QUARANTINE_ATTEMPTS {
            let quarantine_name = format!(".calcifer-cleanup-{}", Uuid::new_v4());
            match renameat_with(
                &self.parent.descriptor,
                current_name.as_str(),
                &self.parent.descriptor,
                quarantine_name.as_str(),
                RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {
                    self.path = self.parent.path.join(&quarantine_name);
                    self.name = Some(quarantine_name);
                    return Ok(());
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(rustix::io::Errno::NOENT) => return Err(RuntimeError::IdentityMismatch),
                Err(_) => return Err(RuntimeError::Cleanup),
            }
        }
        Err(RuntimeError::Cleanup)
    }
}

/// A path created by this process whose final private-runtime validation did
/// not complete. The stable parent and optional open directory identity retain
/// exactly as much cleanup authority as creation reached; path text alone never
/// authorizes removal.
#[must_use = "a created runtime path must be exactly cleaned or deliberately retained"]
pub(super) struct CreatedRuntimePath {
    path: PathBuf,
    name: Option<String>,
    parent: StableParent,
    directory: Option<OwnedFd>,
    identity: Option<NodeIdentity>,
}

impl CreatedRuntimePath {
    fn into_runtime(mut self: Box<Self>) -> Result<PrivateRuntime, Box<Self>> {
        let Some(name) = self.name.take() else {
            return Err(self);
        };
        let Some(directory) = self.directory.take() else {
            self.name = Some(name);
            return Err(self);
        };
        let Some(identity) = self.identity else {
            self.name = Some(name);
            self.directory = Some(directory);
            return Err(self);
        };
        Ok(PrivateRuntime {
            path: self.path,
            name: Some(name),
            parent: self.parent,
            directory,
            identity,
        })
    }

    fn from_runtime(runtime: PrivateRuntime) -> Self {
        Self {
            path: runtime.path,
            name: runtime.name,
            parent: runtime.parent,
            directory: Some(runtime.directory),
            identity: Some(runtime.identity),
        }
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }
}

/// A runtime creation failure split by whether `mkdirat` took effect.
///
/// `created == None` proves that no runtime cleanup authority exists. When it
/// is `Some`, the caller must either consume `cleanup_created` successfully or
/// retain the returned failure together with its surrounding lease authority.
#[must_use = "runtime creation can leave a created path requiring ownership"]
pub(super) struct RuntimeCreateFailure {
    error: RuntimeError,
    cleanup_error: Option<RuntimeError>,
    created: Option<Box<CreatedRuntimePath>>,
}

impl RuntimeCreateFailure {
    const fn not_created(error: RuntimeError) -> Self {
        Self {
            error,
            cleanup_error: None,
            created: None,
        }
    }

    fn with_created(error: RuntimeError, created: CreatedRuntimePath) -> Self {
        Self {
            error,
            cleanup_error: None,
            created: Some(Box::new(created)),
        }
    }

    pub(super) const fn error(&self) -> RuntimeError {
        self.error
    }

    pub(super) const fn has_created_path(&self) -> bool {
        self.created.is_some()
    }

    pub(super) const fn cleanup_error(&self) -> Option<RuntimeError> {
        self.cleanup_error
    }

    /// Removes a created runtime only when a stable parent, open directory, and
    /// exact private identity were captured. Any uncertainty is returned with
    /// ownership intact.
    pub(super) fn cleanup_created(mut self) -> Result<CleanRuntime, Self> {
        let Some(created) = self.created.take() else {
            return Err(self);
        };
        let runtime = match created.into_runtime() {
            Ok(runtime) => runtime,
            Err(created) => {
                self.created = Some(created);
                return Err(self);
            }
        };
        match runtime.cleanup() {
            Ok(clean) => Ok(clean),
            Err(cleanup) => {
                self.cleanup_error = Some(cleanup.error());
                self.created = Some(Box::new(CreatedRuntimePath::from_runtime(
                    cleanup.into_runtime(),
                )));
                Err(self)
            }
        }
    }

    #[cfg(test)]
    fn into_created_runtime(self) -> Option<Box<CreatedRuntimePath>> {
        self.created
    }
}

impl fmt::Debug for RuntimeCreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeCreateFailure")
            .field("error", &self.error)
            .field("cleanup_error", &self.cleanup_error)
            .field("created", &self.created.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RuntimeCreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for RuntimeCreateFailure {}

/// Capability minted only after exact open-inode runtime cleanup succeeds.
pub(super) struct CleanRuntime {
    _private: (),
}

/// Preserves the unclean runtime and a redacted failure classification.
pub(super) struct RuntimeCleanupFailure {
    runtime: Box<PrivateRuntime>,
    error: RuntimeError,
}

impl RuntimeCleanupFailure {
    pub(super) const fn error(&self) -> RuntimeError {
        self.error
    }

    pub(super) fn into_runtime(self) -> PrivateRuntime {
        *self.runtime
    }

    /// Resolves only the fixed synthetic unknown entry used by the real-exec
    /// cleanup-retention test. No path or entry name is caller-controlled, and
    /// the retained directory descriptor remains the sole mutation authority.
    #[cfg(feature = "internal-supervisor-fixture")]
    pub(super) fn resolve_fixture_synthetic_unknown_entry(self) -> Result<CleanRuntime, Self> {
        let Self { runtime, error } = self;
        if remove_fixture_synthetic_unknown_entry(runtime.as_ref()).is_err() {
            return Err(Self { runtime, error });
        }
        (*runtime).cleanup()
    }
}

#[cfg(feature = "internal-supervisor-fixture")]
fn remove_fixture_synthetic_unknown_entry(runtime: &PrivateRuntime) -> Result<(), RuntimeError> {
    const ENTRY: &str = "unexpected";
    const PAYLOAD: &[u8] = b"synthetic";

    runtime.verify_runtime_entry()?;
    let descriptor = openat(
        &runtime.directory,
        ENTRY,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RuntimeError::IdentityMismatch)?;
    let stat = fstat(&descriptor).map_err(|_| RuntimeError::IdentityMismatch)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat_permission_mode(stat.st_mode) != 0o600
        || stat.st_nlink != 1
        || stat.st_size != i64::try_from(PAYLOAD.len()).map_err(|_| RuntimeError::Cleanup)?
    {
        return Err(RuntimeError::UnsafeIdentity);
    }
    let mut file = fs::File::from(descriptor);
    let mut payload = [0_u8; PAYLOAD.len()];
    file.read_exact(&mut payload)
        .map_err(|_| RuntimeError::Cleanup)?;
    let mut trailing = [0_u8; 1];
    if payload != PAYLOAD
        || file
            .read(&mut trailing)
            .map_err(|_| RuntimeError::Cleanup)?
            != 0
    {
        return Err(RuntimeError::UnsafeIdentity);
    }
    unlinkat(&runtime.directory, ENTRY, AtFlags::empty()).map_err(|_| RuntimeError::Cleanup)?;
    if !matches!(
        statat(&runtime.directory, ENTRY, AtFlags::SYMLINK_NOFOLLOW,),
        Err(rustix::io::Errno::NOENT)
    ) {
        return Err(RuntimeError::IdentityMismatch);
    }
    runtime.verify_runtime_entry()
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
    use std::os::unix::fs::DirBuilderExt;
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
    fn stat_permission_projection_is_platform_stable() {
        assert_eq!(stat_permission_mode(0o100600), 0o600);
        assert_eq!(stat_permission_mode(0o107777), 0o7777);
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
    fn cleanup_never_mints_clean_proof_when_quarantine_is_replaced_at_unlink()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let parked_original = parent.path.join("parked-final-race-original");
        let mut raced_path = None;

        let failure = runtime
            .cleanup_with_before_unlink(|quarantine| {
                raced_path = Some(quarantine.to_path_buf());
                fs::rename(quarantine, &parked_original)?;
                fs::DirBuilder::new().mode(0o700).create(quarantine)
            })
            .err()
            .ok_or("a replaced quarantine must never produce CleanRuntime")?;

        assert_eq!(failure.error(), RuntimeError::IdentityMismatch);
        assert!(parked_original.is_dir());
        let raced_path = raced_path.ok_or("cleanup hook did not observe quarantine")?;
        assert!(
            raced_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".calcifer-cleanup-"))
        );
        let _runtime = failure.into_runtime();
        Ok(())
    }

    #[test]
    fn creation_rejects_non_private_and_symlinked_parents() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        fs::set_permissions(&parent.path, fs::Permissions::from_mode(0o755))?;
        let failure = PrivateRuntime::create(&parent.path)
            .err()
            .ok_or("non-private parent must fail")?;
        assert_eq!(failure.error(), RuntimeError::UnsafeParent);
        assert!(!failure.has_created_path());
        fs::set_permissions(&parent.path, fs::Permissions::from_mode(0o700))?;

        let link = parent.path.with_extension("link");
        std::os::unix::fs::symlink(&parent.path, &link)?;
        let failure = PrivateRuntime::create(&link)
            .err()
            .ok_or("symlinked parent must fail")?;
        assert_eq!(failure.error(), RuntimeError::UnsafeParent);
        assert!(!failure.has_created_path());
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

    #[test]
    fn post_mkdir_validation_failure_returns_created_runtime_ownership()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let failure = PrivateRuntime::create_with_post_mkdir(&parent.path, |path| {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        })
        .err()
        .ok_or("post-mkdir validation must fail")?;

        assert_eq!(failure.error(), RuntimeError::UnsafeIdentity);
        assert!(failure.has_created_path());
        let path = {
            let created = failure
                .into_created_runtime()
                .ok_or("created runtime ownership must be returned")?;
            assert!(created.path().is_dir());
            assert_eq!(
                fs::symlink_metadata(created.path())?.permissions().mode() & 0o777,
                0o755
            );
            created.path().to_path_buf()
        };

        assert!(path.is_dir());
        Ok(())
    }

    #[test]
    fn verified_created_runtime_failure_can_be_exactly_cleaned() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        let failure = RuntimeCreateFailure::with_created(
            RuntimeError::UnsafeParent,
            CreatedRuntimePath::from_runtime(runtime),
        );

        let _clean = failure
            .cleanup_created()
            .map_err(|failure| failure.error())?;
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn failed_created_runtime_cleanup_returns_ownership() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        let original = parent.path.join("original-created-runtime");
        fs::rename(&path, &original)?;
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        let failure = RuntimeCreateFailure::with_created(
            RuntimeError::UnsafeParent,
            CreatedRuntimePath::from_runtime(runtime),
        );

        let failure = failure
            .cleanup_created()
            .err()
            .ok_or("identity mismatch cleanup must retain ownership")?;
        assert!(failure.has_created_path());
        assert_eq!(
            failure.cleanup_error(),
            Some(RuntimeError::IdentityMismatch)
        );
        assert!(path.is_dir());
        assert!(original.is_dir());
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn creation_rejects_a_parent_with_extended_acl_without_creating_a_runtime()
    -> Result<(), Box<dyn Error>> {
        use exacl::{AclEntry, Flag, Perm};

        let parent = TestDirectory::new()?;
        let current_uid = rustix::process::geteuid().as_raw();
        let other_uid = if current_uid == 89 { "1" } else { "89" };
        let acl = [AclEntry::allow_user(
            other_uid,
            Perm::READ | Perm::WRITE | Perm::EXECUTE,
            Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT,
        )];
        exacl::setfacl(&[&parent.path], &acl, Some(exacl::AclOption::SYMLINK_ACL))?;

        let failure = PrivateRuntime::create(&parent.path)
            .err()
            .ok_or("an extended parent ACL must fail closed")?;
        assert_eq!(failure.error(), RuntimeError::UnsafeParent);
        assert!(!failure.has_created_path());

        exacl::setfacl(&[&parent.path], &[], Some(exacl::AclOption::SYMLINK_ACL))?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cleanup_rechecks_the_runtime_acl_through_its_open_inode() -> Result<(), Box<dyn Error>> {
        use exacl::{AclEntry, Perm};

        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let current_uid = rustix::process::geteuid().as_raw();
        let other_uid = if current_uid == 89 { "1" } else { "89" };
        let acl = [AclEntry::allow_user(other_uid, Perm::READ, None)];
        exacl::setfacl(&[runtime.path()], &acl, Some(exacl::AclOption::SYMLINK_ACL))?;

        let failure = runtime
            .cleanup()
            .err()
            .ok_or("runtime ACL must fail closed")?;
        assert_eq!(failure.error(), RuntimeError::IdentityMismatch);
        let runtime = failure.into_runtime();
        calcifer_macos_acl::clear_acl(runtime.directory.as_fd())?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }
}
