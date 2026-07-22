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
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rustix::fs::{
    AtFlags, Dir, FileType, Mode, OFlags, RawMode, RenameFlags, Stat, fstat, mkdirat, open, openat,
    renameat_with, statat, unlinkat,
};
use uuid::Uuid;

use super::process::{ChildAuthority, PinnedAppGracefulDrain};

const RUNTIME_CREATE_ATTEMPTS: usize = 8;
const RUNTIME_QUARANTINE_ATTEMPTS: usize = 8;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const APP_SOCKET_NAME: &str = "app.sock";
const TUI_RELAY_SOCKET_NAME: &str = "tui.sock";
const APP_SOCKET_QUARANTINE_PREFIX: &str = ".calcifer-app-socket-quarantine-";
const APP_SOCKET_MODE: u32 = 0o600;
const MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES: usize = 103;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl SocketIdentity {
    fn private_socket_stat(stat: &Stat) -> Result<Self, AppSocketError> {
        #[cfg(target_os = "macos")]
        let device = u64::from(stat.st_dev as u32);
        #[cfg(target_os = "linux")]
        let device = stat.st_dev;

        let identity = Self {
            device,
            inode: stat.st_ino,
            uid: stat.st_uid,
            mode: stat_permission_mode(stat.st_mode),
        };
        if FileType::from_raw_mode(stat.st_mode).is_socket()
            && identity.uid == rustix::process::geteuid().as_raw()
            && identity.mode == APP_SOCKET_MODE
            && stat.st_nlink == 1
        {
            Ok(identity)
        } else {
            Err(AppSocketError::UnsafeNode)
        }
    }

    fn matches_socket_stat(self, stat: &Stat) -> bool {
        FileType::from_raw_mode(stat.st_mode).is_socket()
            && stat.st_uid == rustix::process::geteuid().as_raw()
            && stat_permission_mode(stat.st_mode) == APP_SOCKET_MODE
            && Self::private_socket_stat_with_any_link_count(stat) == Some(self)
    }

    fn private_socket_stat_with_any_link_count(stat: &Stat) -> Option<Self> {
        if !FileType::from_raw_mode(stat.st_mode).is_socket() {
            return None;
        }
        #[cfg(target_os = "macos")]
        let device = u64::from(stat.st_dev as u32);
        #[cfg(target_os = "linux")]
        let device = stat.st_dev;
        Some(Self {
            device,
            inode: stat.st_ino,
            uid: stat.st_uid,
            mode: stat_permission_mode(stat.st_mode),
        })
    }
}

/// Identity of the exact App socket vnode while its creator is still applying
/// the final private mode. The mode itself is deliberately excluded: only a
/// same-UID Unix socket with one link and no special permission bits may enter
/// this state, and every later observation must retain this exact vnode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InitializingSocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

impl InitializingSocketIdentity {
    fn private_socket_candidate_stat(stat: &Stat) -> Result<Self, AppSocketError> {
        #[cfg(target_os = "macos")]
        let device = u64::from(stat.st_dev as u32);
        #[cfg(target_os = "linux")]
        let device = stat.st_dev;

        let mode = stat_permission_mode(stat.st_mode);
        if !FileType::from_raw_mode(stat.st_mode).is_socket()
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_nlink != 1
            || mode & 0o7000 != 0
        {
            return Err(AppSocketError::UnsafeNode);
        }
        Ok(Self {
            device,
            inode: stat.st_ino,
            uid: stat.st_uid,
        })
    }

    fn matches_candidate_stat(self, stat: &Stat) -> bool {
        stat.st_nlink == 1 && self.matches_socket_stat(stat)
    }

    fn matches_unlinked_stat(self, stat: &Stat) -> bool {
        stat.st_nlink == 0 && self.matches_socket_stat(stat)
    }

    fn matches_socket_stat(self, stat: &Stat) -> bool {
        #[cfg(target_os = "macos")]
        let device = u64::from(stat.st_dev as u32);
        #[cfg(target_os = "linux")]
        let device = stat.st_dev;

        FileType::from_raw_mode(stat.st_mode).is_socket()
            && stat.st_uid == rustix::process::geteuid().as_raw()
            && stat_permission_mode(stat.st_mode) & 0o7000 == 0
            && device == self.device
            && stat.st_ino == self.inode
            && stat.st_uid == self.uid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppSocketCleanupIdentity {
    Ready(SocketIdentity),
    Initializing(InitializingSocketIdentity),
}

impl AppSocketCleanupIdentity {
    fn matches_named_stat(self, stat: &Stat) -> bool {
        match self {
            Self::Ready(identity) => SocketIdentity::private_socket_stat(stat) == Ok(identity),
            Self::Initializing(identity) => identity.matches_candidate_stat(stat),
        }
    }

    fn matches_unlinked_stat(self, stat: &Stat) -> bool {
        match self {
            Self::Ready(identity) => identity.matches_socket_stat(stat) && stat.st_nlink == 0,
            Self::Initializing(identity) => identity.matches_unlinked_stat(stat),
        }
    }

    const fn is_ready(self) -> bool {
        matches!(self, Self::Ready(_))
    }
}

struct InitializingAppSocket {
    identity: InitializingSocketIdentity,
    descriptor: Option<OwnedFd>,
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

fn sync_runtime_parent(descriptor: &OwnedFd) -> Result<(), RuntimeError> {
    rustix::fs::fsync(descriptor).map_err(|_| RuntimeError::Cleanup)
}

fn sync_app_socket_runtime(descriptor: &OwnedFd) -> Result<(), AppSocketError> {
    rustix::fs::fsync(descriptor).map_err(|_| AppSocketError::Cleanup)
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
    /// Appends the stable parent and runtime-directory authorities to a
    /// source-pinned child denyset. Raw descriptor identities never leave the
    /// typed set.
    fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        forbidden.capture(self.parent.descriptor.as_fd())?;
        forbidden.capture(self.directory.as_fd())
    }

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
    pub(super) fn create_with_post_mkdir<F>(
        parent: &Path,
        post_mkdir: F,
    ) -> Result<Self, RuntimeCreateFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        Self::create_inner(parent, post_mkdir)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Reserves the one fixed App Server socket node below this runtime.
    ///
    /// The reservation is a linear state transition: callers receive no API
    /// that accepts a filename, and the runtime can no longer be cleaned while
    /// the child may create `app.sock`.
    #[cfg(test)]
    pub(super) fn reserve_app_socket(
        self,
    ) -> Result<AppSocketReservation, AppSocketReserveFailure> {
        let socket_path = self.path.join(APP_SOCKET_NAME);
        let result = (|| {
            validate_app_socket_path(&socket_path)?;
            match self.checked_app_socket_state()? {
                AppSocketEntryState::Absent => Ok(()),
                AppSocketEntryState::Present => Err(AppSocketError::Collision),
            }
        })();

        match result {
            Ok(()) => Ok(AppSocketReservation {
                runtime: Box::new(self),
                socket_path,
                initializing: None,
                app_child_authority: None,
            }),
            Err(error) => Err(AppSocketReserveFailure {
                runtime: Box::new(self),
                error,
            }),
        }
    }

    /// Reserves the fixed App Server and exact-resume relay routes as one
    /// owner-private layout.
    ///
    /// The App reservation remains the sole runtime owner. The relay route is
    /// a sealed, non-owning capability whose downstream is always `tui.sock`
    /// and whose upstream is the same layout's exact `app.sock`. Consumers
    /// receive no parent-directory or arbitrary-filename constructor.
    pub(super) fn reserve_supervised_layout(
        self,
    ) -> Result<SupervisedRuntimeLayout, AppSocketReserveFailure> {
        let app_socket_path = self.path.join(APP_SOCKET_NAME);
        let relay_socket_path = self.path.join(TUI_RELAY_SOCKET_NAME);
        let result = (|| {
            validate_app_socket_path(&app_socket_path)?;
            validate_app_socket_path(&relay_socket_path)?;
            match self.checked_app_socket_state()? {
                AppSocketEntryState::Absent => {}
                AppSocketEntryState::Present => return Err(AppSocketError::Collision),
            }
            let relay_address = relay_socket_path
                .to_str()
                .ok_or(AppSocketError::UnsafeRuntime)?
                .to_owned();
            Ok(relay_address)
        })();

        match result {
            Ok(relay_address) => Ok(SupervisedRuntimeLayout {
                app: AppSocketReservation {
                    runtime: Box::new(self),
                    socket_path: app_socket_path.clone(),
                    initializing: None,
                    app_child_authority: None,
                },
                relay: ExactRelayRoute {
                    relay_socket_path,
                    relay_address,
                    upstream_socket_path: app_socket_path,
                },
            }),
            Err(error) => Err(AppSocketReserveFailure {
                runtime: Box::new(self),
                error,
            }),
        }
    }

    /// Removes only the still-empty directory with the exact recorded identity.
    pub(super) fn cleanup(self) -> Result<CleanRuntime, RuntimeCleanupFailure> {
        self.cleanup_inner(|_| Ok(()), sync_runtime_parent)
    }

    /// Clears the bounded, owner-private registry tree used by supervisor
    /// process fixtures, then applies the normal exact-inode runtime cleanup.
    /// Every opened node must remain on the root's exact mount; entries are
    /// quarantined and retain an open-inode unlink proof, while links, foreign
    /// owners, special nodes, mount crossings, and identity changes fail closed.
    #[cfg(test)]
    pub(super) fn cleanup_fixture_tree(self) -> Result<CleanRuntime, RuntimeCleanupFailure> {
        self.cleanup_fixture_tree_inner(|_| Ok(()))
    }

    #[cfg(test)]
    pub(super) fn cleanup_fixture_tree_with_before_cleanup<F>(
        self,
        mut before_cleanup: F,
    ) -> Result<CleanRuntime, RuntimeCleanupFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        if let Err(error) = remove_fixture_runtime_entries(&self) {
            return Err(RuntimeCleanupFailure {
                runtime: Box::new(self),
                error,
            });
        }
        if before_cleanup(self.path()).is_err() {
            return Err(RuntimeCleanupFailure {
                runtime: Box::new(self),
                error: RuntimeError::Cleanup,
            });
        }
        self.cleanup()
    }

    #[cfg(test)]
    fn cleanup_fixture_tree_inner<F>(
        self,
        before_unlink: F,
    ) -> Result<CleanRuntime, RuntimeCleanupFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        if let Err(error) = remove_fixture_runtime_entries(&self) {
            return Err(RuntimeCleanupFailure {
                runtime: Box::new(self),
                error,
            });
        }
        self.cleanup_inner(before_unlink, sync_runtime_parent)
    }

    #[cfg(test)]
    fn cleanup_fixture_tree_with_before_entry_unlink<F>(
        self,
        mut before_unlink: F,
    ) -> Result<CleanRuntime, RuntimeCleanupFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        if let Err(error) =
            remove_fixture_runtime_entries_with_before_unlink(&self, &mut before_unlink)
        {
            return Err(RuntimeCleanupFailure {
                runtime: Box::new(self),
                error,
            });
        }
        self.cleanup()
    }

    #[cfg(test)]
    fn cleanup_with_before_unlink<F>(
        self,
        before_unlink: F,
    ) -> Result<CleanRuntime, RuntimeCleanupFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        self.cleanup_inner(before_unlink, sync_runtime_parent)
    }

    #[cfg(test)]
    fn cleanup_with_parent_sync_failure(
        self,
        fail_on_sync: usize,
    ) -> Result<CleanRuntime, RuntimeCleanupFailure> {
        let mut sync_count = 0_usize;
        self.cleanup_inner(
            |_| Ok(()),
            move |_| {
                sync_count += 1;
                if sync_count == fail_on_sync {
                    Err(RuntimeError::Cleanup)
                } else {
                    Ok(())
                }
            },
        )
    }

    fn cleanup_inner<F, S>(
        mut self,
        mut before_unlink: F,
        mut sync_parent: S,
    ) -> Result<CleanRuntime, RuntimeCleanupFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
        S: FnMut(&OwnedFd) -> Result<(), RuntimeError>,
    {
        let result = (|| {
            if self.name.is_none() {
                self.verify_removed_runtime()?;
                sync_parent(&self.parent.descriptor)?;
                self.parent.verify()?;
                return self.verify_removed_runtime();
            }
            self.verify_runtime_entry()?;
            self.verify_empty()?;
            self.move_to_quarantine(&mut sync_parent)?;
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
            sync_parent(&self.parent.descriptor)?;
            self.parent.verify()?;
            self.verify_removed_runtime()?;
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

    fn verify_removed_runtime(&self) -> Result<(), RuntimeError> {
        if self.name.is_some() {
            return Err(RuntimeError::IdentityMismatch);
        }
        self.parent.verify()?;
        let opened = fstat(&self.directory).map_err(|_| RuntimeError::IdentityMismatch)?;
        if !self.identity.matches_private_stat(&opened) || !open_inode_acl_is_empty(&self.directory)
        {
            return Err(RuntimeError::IdentityMismatch);
        }
        let removed_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(RuntimeError::IdentityMismatch)?;
        if !matches!(
            statat(
                &self.parent.descriptor,
                removed_name,
                AtFlags::SYMLINK_NOFOLLOW,
            ),
            Err(rustix::io::Errno::NOENT)
        ) || !open_inode_was_unlinked(
            &self.directory,
            &opened,
            opened.st_nlink as u64,
            &self.path,
        ) {
            return Err(RuntimeError::IdentityMismatch);
        }
        self.parent.verify()
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

    fn checked_app_socket_state(&self) -> Result<AppSocketEntryState, AppSocketError> {
        strict_app_socket_entry_state(self.observe_app_socket_entry()?)
    }

    /// Accepts only the monotonic absence-to-presence transition that the
    /// exact bound App child is authorized to perform during its first bind.
    /// Every later reservation, revalidation, and cleanup observation keeps
    /// using the strict stable-state check above.
    fn checked_app_socket_state_for_initial_bind(
        &self,
    ) -> Result<AppSocketEntryState, AppSocketError> {
        initial_bind_app_socket_entry_state(self.observe_app_socket_entry()?)
    }

    fn observe_app_socket_entry(&self) -> Result<AppSocketEntryObservation, AppSocketError> {
        self.verify_runtime_entry()
            .map_err(AppSocketError::from_runtime)?;
        let before = self.app_socket_entry_state()?;
        let visible = match statat(&self.directory, APP_SOCKET_NAME, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => AppSocketEntryState::Present,
            Err(rustix::io::Errno::NOENT) => AppSocketEntryState::Absent,
            Err(_) => return Err(AppSocketError::IdentityMismatch),
        };
        self.verify_runtime_entry()
            .map_err(AppSocketError::from_runtime)?;
        let after = self.app_socket_entry_state()?;
        classify_app_socket_entry_observation(before, visible, after)
    }

    fn app_socket_entry_state(&self) -> Result<AppSocketEntryState, AppSocketError> {
        let directory =
            Dir::read_from(&self.directory).map_err(|_| AppSocketError::IdentityMismatch)?;
        let mut app_socket_present = false;
        for entry in directory {
            let entry = entry.map_err(|_| AppSocketError::IdentityMismatch)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if name == APP_SOCKET_NAME.as_bytes() && !app_socket_present {
                app_socket_present = true;
            } else {
                return Err(AppSocketError::UnknownEntry);
            }
        }
        Ok(if app_socket_present {
            AppSocketEntryState::Present
        } else {
            AppSocketEntryState::Absent
        })
    }

    fn verify_only_generated_entry(&self, expected: &str) -> Result<(), AppSocketError> {
        self.verify_runtime_entry()
            .map_err(AppSocketError::from_runtime)?;
        let directory =
            Dir::read_from(&self.directory).map_err(|_| AppSocketError::IdentityMismatch)?;
        let mut expected_present = false;
        for entry in directory {
            let entry = entry.map_err(|_| AppSocketError::IdentityMismatch)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if name == expected.as_bytes() && !expected_present {
                expected_present = true;
            } else {
                return Err(AppSocketError::UnknownEntry);
            }
        }
        self.verify_runtime_entry()
            .map_err(AppSocketError::from_runtime)?;
        if expected_present {
            Ok(())
        } else {
            Err(AppSocketError::IdentityMismatch)
        }
    }

    fn move_to_quarantine<S>(&mut self, sync_parent: &mut S) -> Result<(), RuntimeError>
    where
        S: FnMut(&OwnedFd) -> Result<(), RuntimeError>,
    {
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
                    sync_parent(&self.parent.descriptor)?;
                    self.parent.verify()?;
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

#[cfg(test)]
const FIXTURE_TREE_MAX_ENTRIES: usize = 4096;
#[cfg(test)]
const FIXTURE_TREE_MAX_DEPTH: usize = 32;
#[cfg(test)]
const FIXTURE_ENTRY_QUARANTINE_ATTEMPTS: usize = 8;
#[cfg(test)]
const FIXTURE_ENTRY_QUARANTINE_PREFIX: &str = ".calcifer-fixture-cleanup-";

#[cfg(test)]
#[derive(Clone, Eq, PartialEq)]
struct FixtureMountIdentity {
    token: Vec<u8>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum FixtureTreeEntryKind {
    Directory,
    RegularFile,
}

#[cfg(test)]
fn remove_fixture_runtime_entries(runtime: &PrivateRuntime) -> Result<(), RuntimeError> {
    remove_fixture_runtime_entries_with_before_unlink(runtime, &mut |_| Ok(()))
}

#[cfg(test)]
fn remove_fixture_runtime_entries_with_before_unlink<F>(
    runtime: &PrivateRuntime,
    before_unlink: &mut F,
) -> Result<(), RuntimeError>
where
    F: FnMut(&Path) -> std::io::Result<()>,
{
    runtime.verify_runtime_entry()?;
    let root = fstat(&runtime.directory).map_err(|_| RuntimeError::IdentityMismatch)?;
    let expected_device = NodeIdentity::from_stat(&root).device;
    let expected_mount = fixture_mount_identity_fd(&runtime.directory)?;
    let directory = rustix::io::fcntl_dupfd_cloexec(&runtime.directory, 0)
        .map_err(|_| RuntimeError::Cleanup)?;
    let mut remaining = FIXTURE_TREE_MAX_ENTRIES;
    remove_fixture_directory_entries(
        Dir::new(directory).map_err(|_| RuntimeError::Cleanup)?,
        runtime.path(),
        expected_device,
        &expected_mount,
        &mut remaining,
        0,
        before_unlink,
    )?;
    runtime.verify_runtime_entry()?;
    runtime.verify_empty()
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn remove_fixture_directory_entries<F>(
    mut directory: Dir,
    directory_path: &Path,
    expected_device: u64,
    expected_mount: &FixtureMountIdentity,
    remaining: &mut usize,
    depth: usize,
    before_unlink: &mut F,
) -> Result<(), RuntimeError>
where
    F: FnMut(&Path) -> std::io::Result<()>,
{
    if depth > FIXTURE_TREE_MAX_DEPTH {
        return Err(RuntimeError::Cleanup);
    }
    let directory_fd =
        rustix::io::fcntl_dupfd_cloexec(directory.fd().map_err(|_| RuntimeError::Cleanup)?, 0)
            .map_err(|_| RuntimeError::Cleanup)?;
    ensure_fixture_mount(expected_mount, &fixture_mount_identity_fd(&directory_fd)?)?;
    let mut entries = Vec::new();
    for entry in directory.by_ref() {
        let entry = entry.map_err(|_| RuntimeError::Cleanup)?;
        if entry.file_name().to_bytes() == b"." || entry.file_name().to_bytes() == b".." {
            continue;
        }
        *remaining = remaining.checked_sub(1).ok_or(RuntimeError::Cleanup)?;
        let stat = statat(&directory_fd, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| RuntimeError::Cleanup)?;
        let kind = validate_fixture_tree_entry(&stat, expected_device)?;
        entries.try_reserve(1).map_err(|_| RuntimeError::Cleanup)?;
        entries.push((entry.file_name().to_owned(), stat, kind));
    }

    for (name, observed, kind) in entries {
        let current = statat(&directory_fd, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| RuntimeError::IdentityMismatch)?;
        validate_same_fixture_tree_entry(&observed, &current, kind, expected_device)?;
        let entry_fd = open_fixture_entry_at(&directory_fd, &name, kind, expected_mount)?;
        let opened = fstat(&entry_fd).map_err(|_| RuntimeError::IdentityMismatch)?;
        validate_same_fixture_tree_entry(&observed, &opened, kind, expected_device)?;

        let quarantine_name = move_fixture_entry_to_quarantine(&directory_fd, &name)?;
        rustix::fs::fsync(&directory_fd).map_err(|_| RuntimeError::Cleanup)?;
        let quarantined = statat(
            &directory_fd,
            quarantine_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| RuntimeError::IdentityMismatch)?;
        validate_same_fixture_tree_entry(&observed, &quarantined, kind, expected_device)?;
        let quarantine_path = directory_path.join(&quarantine_name);

        if matches!(kind, FixtureTreeEntryKind::Directory) {
            let traversal =
                rustix::io::fcntl_dupfd_cloexec(&entry_fd, 0).map_err(|_| RuntimeError::Cleanup)?;
            remove_fixture_directory_entries(
                Dir::new(traversal).map_err(|_| RuntimeError::Cleanup)?,
                &quarantine_path,
                expected_device,
                expected_mount,
                remaining,
                depth.checked_add(1).ok_or(RuntimeError::Cleanup)?,
                before_unlink,
            )?;
        }

        let final_opened = fstat(&entry_fd).map_err(|_| RuntimeError::IdentityMismatch)?;
        validate_same_fixture_tree_entry(&observed, &final_opened, kind, expected_device)?;
        let final_named = statat(
            &directory_fd,
            quarantine_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| RuntimeError::IdentityMismatch)?;
        validate_same_fixture_tree_entry(&observed, &final_named, kind, expected_device)?;
        let linked_count = final_opened.st_nlink as u64;
        if linked_count == 0 {
            return Err(RuntimeError::IdentityMismatch);
        }
        before_unlink(&quarantine_path).map_err(|_| RuntimeError::Cleanup)?;
        let unlink_flags = if matches!(kind, FixtureTreeEntryKind::Directory) {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        unlinkat(&directory_fd, quarantine_name.as_str(), unlink_flags)
            .map_err(|_| RuntimeError::Cleanup)?;

        let unlinked = fstat(&entry_fd).map_err(|_| RuntimeError::IdentityMismatch)?;
        let quarantine_is_absent = matches!(
            statat(
                &directory_fd,
                quarantine_name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            ),
            Err(rustix::io::Errno::NOENT)
        );
        let regular_file_was_unlinked =
            !matches!(kind, FixtureTreeEntryKind::RegularFile) || unlinked.st_nlink == 0;
        if !quarantine_is_absent
            || !regular_file_was_unlinked
            || !fixture_tree_entry_identity_matches_after_unlink(&observed, &unlinked, kind)
            || !open_inode_was_unlinked(&entry_fd, &unlinked, linked_count, &quarantine_path)
        {
            return Err(RuntimeError::IdentityMismatch);
        }
        rustix::fs::fsync(&directory_fd).map_err(|_| RuntimeError::Cleanup)?;
    }
    Ok(())
}

#[cfg(test)]
fn move_fixture_entry_to_quarantine(
    directory: &OwnedFd,
    visible_name: &std::ffi::CStr,
) -> Result<String, RuntimeError> {
    for _ in 0..FIXTURE_ENTRY_QUARANTINE_ATTEMPTS {
        let quarantine_name = format!("{FIXTURE_ENTRY_QUARANTINE_PREFIX}{}", Uuid::new_v4());
        match renameat_with(
            directory,
            visible_name,
            directory,
            quarantine_name.as_str(),
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => return Ok(quarantine_name),
            Err(rustix::io::Errno::EXIST) => {}
            Err(rustix::io::Errno::NOENT) => return Err(RuntimeError::IdentityMismatch),
            Err(_) => return Err(RuntimeError::Cleanup),
        }
    }
    Err(RuntimeError::Cleanup)
}

#[cfg(test)]
fn validate_fixture_tree_entry(
    stat: &Stat,
    expected_device: u64,
) -> Result<FixtureTreeEntryKind, RuntimeError> {
    let identity = NodeIdentity::from_stat(stat);
    if identity.device != expected_device || stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(RuntimeError::UnsafeIdentity);
    }
    let file_type = FileType::from_raw_mode(stat.st_mode);
    if file_type.is_dir() {
        Ok(FixtureTreeEntryKind::Directory)
    } else if file_type.is_file() && stat.st_nlink == 1 {
        Ok(FixtureTreeEntryKind::RegularFile)
    } else {
        Err(RuntimeError::UnsafeIdentity)
    }
}

#[cfg(test)]
fn validate_same_fixture_tree_entry(
    expected: &Stat,
    observed: &Stat,
    expected_kind: FixtureTreeEntryKind,
    expected_device: u64,
) -> Result<(), RuntimeError> {
    let kind = validate_fixture_tree_entry(observed, expected_device)?;
    let kind_matches = matches!(
        (expected_kind, kind),
        (
            FixtureTreeEntryKind::Directory,
            FixtureTreeEntryKind::Directory
        ) | (
            FixtureTreeEntryKind::RegularFile,
            FixtureTreeEntryKind::RegularFile
        )
    );
    let link_count_matches = matches!(expected_kind, FixtureTreeEntryKind::Directory)
        || expected.st_nlink == observed.st_nlink;
    if kind_matches
        && link_count_matches
        && NodeIdentity::from_stat(expected) == NodeIdentity::from_stat(observed)
    {
        Ok(())
    } else {
        Err(RuntimeError::IdentityMismatch)
    }
}

#[cfg(test)]
fn fixture_tree_entry_identity_matches_after_unlink(
    expected: &Stat,
    observed: &Stat,
    expected_kind: FixtureTreeEntryKind,
) -> bool {
    let observed_kind = FileType::from_raw_mode(observed.st_mode);
    let kind_matches = match expected_kind {
        FixtureTreeEntryKind::Directory => observed_kind.is_dir(),
        FixtureTreeEntryKind::RegularFile => observed_kind.is_file(),
    };
    kind_matches && NodeIdentity::from_stat(expected) == NodeIdentity::from_stat(observed)
}

#[cfg(all(test, target_os = "linux"))]
fn open_fixture_entry_at(
    directory: &OwnedFd,
    name: &std::ffi::CStr,
    kind: FixtureTreeEntryKind,
    expected_mount: &FixtureMountIdentity,
) -> Result<OwnedFd, RuntimeError> {
    use rustix::fs::{ResolveFlags, openat2};

    let type_flags = if matches!(kind, FixtureTreeEntryKind::Directory) {
        OFlags::RDONLY | OFlags::DIRECTORY
    } else {
        OFlags::PATH
    };
    let descriptor = openat2(
        directory,
        name,
        type_flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(fixture_boundary_error)?;
    ensure_fixture_mount(expected_mount, &fixture_mount_identity_fd(&descriptor)?)?;
    Ok(descriptor)
}

#[cfg(all(test, target_os = "macos"))]
fn open_fixture_entry_at(
    directory: &OwnedFd,
    name: &std::ffi::CStr,
    kind: FixtureTreeEntryKind,
    expected_mount: &FixtureMountIdentity,
) -> Result<OwnedFd, RuntimeError> {
    let type_flags = if matches!(kind, FixtureTreeEntryKind::Directory) {
        OFlags::RDONLY | OFlags::DIRECTORY
    } else {
        OFlags::RDONLY | OFlags::NONBLOCK
    };
    let descriptor = openat(
        directory,
        name,
        type_flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(fixture_boundary_error)?;
    ensure_fixture_mount(expected_mount, &fixture_mount_identity_fd(&descriptor)?)?;
    Ok(descriptor)
}

#[cfg(test)]
fn ensure_fixture_mount(
    expected: &FixtureMountIdentity,
    observed: &FixtureMountIdentity,
) -> Result<(), RuntimeError> {
    if expected == observed {
        Ok(())
    } else {
        Err(RuntimeError::UnsafeIdentity)
    }
}

#[cfg(test)]
fn fixture_boundary_error(error: rustix::io::Errno) -> RuntimeError {
    if matches!(
        error,
        rustix::io::Errno::XDEV
            | rustix::io::Errno::LOOP
            | rustix::io::Errno::NOSYS
            | rustix::io::Errno::INVAL
            | rustix::io::Errno::PERM
            | rustix::io::Errno::ACCESS
    ) {
        RuntimeError::UnsafeIdentity
    } else {
        RuntimeError::IdentityMismatch
    }
}

#[cfg(all(test, target_os = "linux"))]
fn fixture_mount_identity_fd(descriptor: &OwnedFd) -> Result<FixtureMountIdentity, RuntimeError> {
    use rustix::fs::{AtFlags, StatxFlags, statx};

    let stat = statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .map_err(fixture_boundary_error)?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() != StatxFlags::MNT_ID.bits()
        || stat.stx_mnt_id == 0
    {
        return Err(RuntimeError::UnsafeIdentity);
    }
    Ok(FixtureMountIdentity {
        token: stat.stx_mnt_id.to_le_bytes().to_vec(),
    })
}

#[cfg(all(test, target_os = "macos"))]
fn fixture_mount_identity_fd(descriptor: &OwnedFd) -> Result<FixtureMountIdentity, RuntimeError> {
    let stat = rustix::fs::fstatfs(descriptor).map_err(fixture_boundary_error)?;
    let mut token = Vec::new();
    append_fixture_mount_field(&mut token, &stat.f_mntonname, true)?;
    append_fixture_mount_field(&mut token, &stat.f_mntfromname, false)?;
    append_fixture_mount_field(&mut token, &stat.f_fstypename, false)?;
    Ok(FixtureMountIdentity { token })
}

#[cfg(all(test, target_os = "macos"))]
fn append_fixture_mount_field(
    token: &mut Vec<u8>,
    field: &[std::ffi::c_char],
    require_absolute: bool,
) -> Result<(), RuntimeError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(RuntimeError::UnsafeIdentity)?;
    let start = token.len();
    token.extend(field[..end].iter().map(|byte| byte.to_ne_bytes()[0]));
    if end == 0 || (require_absolute && token.get(start) != Some(&b'/')) {
        return Err(RuntimeError::UnsafeIdentity);
    }
    token.push(0);
    Ok(())
}

/// One fixed runtime layout for an App Server plus exact-resume relay.
#[must_use = "a supervised runtime layout must be split into its linear owners"]
pub(super) struct SupervisedRuntimeLayout {
    app: AppSocketReservation,
    relay: ExactRelayRoute,
}

impl SupervisedRuntimeLayout {
    pub(super) fn into_parts(self) -> (AppSocketReservation, ExactRelayRoute) {
        (self.app, self.relay)
    }
}

impl fmt::Debug for SupervisedRuntimeLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.app, &self.relay);
        formatter.write_str("SupervisedRuntimeLayout(<redacted>)")
    }
}

/// Sealed exact route from fixed `tui.sock` to the same layout's `app.sock`.
///
/// This capability owns no runtime. The session aggregate must therefore stop
/// and join the relay before cleaning the App reservation/runtime owner.
#[must_use = "an exact relay route must be bound to one pinned provider session"]
pub(super) struct ExactRelayRoute {
    relay_socket_path: PathBuf,
    relay_address: String,
    upstream_socket_path: PathBuf,
}

impl ExactRelayRoute {
    pub(super) fn relay_address(&self) -> &str {
        &self.relay_address
    }

    #[cfg(all(
        test,
        feature = "internal-supervisor-fixture",
        any(target_os = "linux", target_os = "macos")
    ))]
    pub(super) fn spawn_exact(
        &self,
        probe: crate::providers::codex::remote::ExactResumeProbe<'_>,
        timeout: std::time::Duration,
    ) -> Result<
        crate::providers::codex::remote::ReadinessProxy,
        Box<crate::providers::codex::remote::ReadinessProxyStartFailure>,
    > {
        crate::providers::codex::remote::ReadinessProxy::spawn_exact_owned(
            &self.relay_socket_path,
            &self.upstream_socket_path,
            probe,
            timeout,
        )
    }

    #[cfg(feature = "internal-supervisor-fixture")]
    pub(super) fn spawn_exact_until(
        &self,
        probe: crate::providers::codex::remote::ExactResumeProbe<'_>,
        deadline: std::time::Instant,
    ) -> Result<
        crate::providers::codex::remote::ReadinessProxy,
        Box<crate::providers::codex::remote::ReadinessProxyStartFailure>,
    > {
        crate::providers::codex::remote::ReadinessProxy::spawn_exact_owned_until(
            &self.relay_socket_path,
            &self.upstream_socket_path,
            probe,
            deadline,
        )
    }

    #[cfg(test)]
    fn paths_for_test(&self) -> (&Path, &Path) {
        (&self.relay_socket_path, &self.upstream_socket_path)
    }
}

impl fmt::Debug for ExactRelayRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.relay_socket_path,
            &self.relay_address,
            &self.upstream_socket_path,
        );
        formatter.write_str("ExactRelayRoute(<redacted>)")
    }
}

fn validate_app_socket_path(path: &Path) -> Result<(), AppSocketError> {
    if path.as_os_str().as_bytes().len() > MAX_PORTABLE_UNIX_SOCKET_PATH_BYTES {
        return Err(AppSocketError::PathTooLong);
    }
    if !path.is_absolute()
        || path
            .to_str()
            .is_none_or(|path| path.chars().any(char::is_control))
    {
        return Err(AppSocketError::UnsafeRuntime);
    }
    Ok(())
}

/// Test-only fail-fast validation for a package harness runtime parent.
///
/// This intentionally reuses the production parent identity/ACL validation
/// and the production portable socket-path bound. It does not mint a runtime
/// owner or weaken either invariant.
#[cfg(test)]
pub(super) fn validate_packaged_runtime_parent(parent: &Path) -> Result<(), AppSocketError> {
    let _stable_parent =
        StableParent::open_private(parent).map_err(AppSocketError::from_runtime)?;
    let runtime_name = format!(".calcifer-supervisor-{}", Uuid::nil());
    for socket_name in [APP_SOCKET_NAME, TUI_RELAY_SOCKET_NAME] {
        validate_app_socket_path(&parent.join(&runtime_name).join(socket_name))?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppSocketEntryState {
    Absent,
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppSocketEntryObservation {
    Stable(AppSocketEntryState),
    Appeared,
}

fn strict_app_socket_entry_state(
    observation: AppSocketEntryObservation,
) -> Result<AppSocketEntryState, AppSocketError> {
    match observation {
        AppSocketEntryObservation::Stable(state) => Ok(state),
        AppSocketEntryObservation::Appeared => Err(AppSocketError::IdentityMismatch),
    }
}

fn initial_bind_app_socket_entry_state(
    observation: AppSocketEntryObservation,
) -> Result<AppSocketEntryState, AppSocketError> {
    match observation {
        AppSocketEntryObservation::Stable(state) => Ok(state),
        AppSocketEntryObservation::Appeared => Ok(AppSocketEntryState::Present),
    }
}

fn classify_app_socket_entry_observation(
    before: AppSocketEntryState,
    visible: AppSocketEntryState,
    after: AppSocketEntryState,
) -> Result<AppSocketEntryObservation, AppSocketError> {
    use AppSocketEntryObservation::{Appeared, Stable};
    use AppSocketEntryState::{Absent, Present};

    match (before, visible, after) {
        (Absent, Absent, Absent) => Ok(Stable(Absent)),
        (Present, Present, Present) => Ok(Stable(Present)),
        (Absent, Absent, Present) | (Absent, Present, Present) => Ok(Appeared),
        (Absent, Present, Absent)
        | (Present, Absent, Absent)
        | (Present, Absent, Present)
        | (Present, Present, Absent) => Err(AppSocketError::IdentityMismatch),
    }
}

/// Linear authority for the one fixed App Server socket pathname.
///
/// The reservation contains the runtime itself, so cleanup cannot race a
/// child that has been authorized to bind the socket.
#[must_use = "an App Server socket reservation must be adopted, released, or retained"]
pub(super) struct AppSocketReservation {
    runtime: Box<PrivateRuntime>,
    socket_path: PathBuf,
    initializing: Option<InitializingAppSocket>,
    app_child_authority: Option<ChildAuthority>,
}

impl AppSocketReservation {
    pub(super) fn path(&self) -> &Path {
        &self.socket_path
    }

    pub(super) fn bind_app_child(
        &mut self,
        authority: ChildAuthority,
    ) -> Result<(), AppSocketError> {
        match self.app_child_authority {
            None => {
                self.app_child_authority = Some(authority);
                Ok(())
            }
            Some(existing) if existing == authority => Ok(()),
            Some(_) => Err(AppSocketError::IdentityMismatch),
        }
    }

    pub(super) const fn is_unbound_from_app_child(&self) -> bool {
        self.app_child_authority.is_none()
    }

    /// Requires the exact managed App child bound at launch/adoption to be the
    /// child represented by this move-only graceful-reap proof. This check is
    /// mandatory before releasing even an apparently empty reservation: an
    /// unrelated live child may still be about to bind its socket.
    pub(super) fn require_matching_reaped_child(
        self,
        reaped_child: &PinnedAppGracefulDrain,
    ) -> Result<Self, AppSocketReservationFailure> {
        if self.app_child_authority == Some(reaped_child.child_authority()) {
            Ok(self)
        } else {
            Err(AppSocketReservationFailure {
                reservation: Box::new(self),
                error: AppSocketError::IdentityMismatch,
            })
        }
    }

    /// Appends every persistent runtime descriptor retained by this
    /// reservation to one source-pinned child denyset.
    pub(super) fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        self.runtime.append_forbidden_descriptors(forbidden)?;
        if let Some(descriptor) = self
            .initializing
            .as_ref()
            .and_then(|initializing| initializing.descriptor.as_ref())
        {
            forbidden.capture(descriptor.as_fd())?;
        }
        Ok(())
    }

    /// Adopts the socket only after comparing the visible node around every
    /// runtime identity/ACL check and retaining the vnode where the OS permits.
    ///
    /// Linux uses `O_PATH`, which can retain a Unix-domain socket vnode without
    /// opening its stream. Darwin rejects every safe `open(2)` probe for a Unix
    /// socket with `EOPNOTSUPP`; on Darwin the owner is therefore a conservative
    /// path observation below the retained private runtime descriptor. That
    /// observation may prove absence, but never authorizes rename or unlink.
    pub(super) fn adopt(mut self) -> Result<OwnedAppSocket, AppSocketReservationFailure> {
        let captured = self.capture_identity();
        match captured {
            Ok((descriptor, identity)) => Ok(OwnedAppSocket {
                runtime: Some(self.runtime),
                descriptor,
                identity: AppSocketCleanupIdentity::Ready(identity),
                location: AppSocketLocation::Visible,
                visible_path: self.socket_path,
            }),
            Err(error) => Err(AppSocketReservationFailure {
                reservation: Box::new(self),
                error,
            }),
        }
    }

    /// Claims the exact socket vnode for namespace cleanup after the caller
    /// has proved that the exact direct App child completed its pinned
    /// graceful-drain contract.
    ///
    /// This deliberately returns a cleanup-only capability. A pre-`chmod`
    /// socket never becomes connectable, and a replacement or disappearance
    /// returns the original reservation without mutating the namespace.
    pub(super) fn claim_socket_for_cleanup_after_child_exit(
        self,
        reaped_child: &PinnedAppGracefulDrain,
    ) -> Result<AppSocketCleanupAuthority, AppSocketReservationFailure> {
        self.require_matching_reaped_child(reaped_child)?
            .claim_socket_for_cleanup()
    }

    #[cfg(test)]
    fn claim_socket_for_cleanup_for_test(
        self,
    ) -> Result<AppSocketCleanupAuthority, AppSocketReservationFailure> {
        self.claim_socket_for_cleanup()
    }

    fn claim_socket_for_cleanup(
        mut self,
    ) -> Result<AppSocketCleanupAuthority, AppSocketReservationFailure> {
        let captured = self.capture_cleanup_identity();
        match captured {
            Ok((descriptor, identity)) => Ok(AppSocketCleanupAuthority {
                socket: Box::new(OwnedAppSocket {
                    runtime: Some(self.runtime),
                    descriptor,
                    identity: AppSocketCleanupIdentity::Initializing(identity),
                    location: AppSocketLocation::Visible,
                    visible_path: self.socket_path,
                }),
            }),
            Err(error) => Err(AppSocketReservationFailure {
                reservation: Box::new(self),
                error,
            }),
        }
    }

    /// Releases the reservation only when the fixed node is still absent and
    /// the runtime identity, ACL, and directory contents remain unchanged.
    pub(super) fn release_if_absent(self) -> Result<PrivateRuntime, AppSocketReservationFailure> {
        let result = match self.runtime.checked_app_socket_state() {
            Ok(AppSocketEntryState::Absent) => Ok(()),
            Ok(AppSocketEntryState::Present) => Err(AppSocketError::SocketStillPresent),
            Err(error) => Err(error),
        };
        match result {
            Ok(()) => Ok(*self.runtime),
            Err(error) => Err(AppSocketReservationFailure {
                reservation: Box::new(self),
                error,
            }),
        }
    }

    fn capture_identity(&mut self) -> Result<(Option<OwnedFd>, SocketIdentity), AppSocketError> {
        let entry_state = if self.initializing.is_none() && self.app_child_authority.is_some() {
            self.runtime.checked_app_socket_state_for_initial_bind()?
        } else {
            self.runtime.checked_app_socket_state()?
        };
        match entry_state {
            AppSocketEntryState::Absent if self.initializing.is_some() => {
                return Err(AppSocketError::IdentityMismatch);
            }
            AppSocketEntryState::Absent => return Err(AppSocketError::SocketNotReady),
            AppSocketEntryState::Present => {}
        }

        let before = statat(
            &self.runtime.directory,
            APP_SOCKET_NAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| AppSocketError::IdentityMismatch)?;
        let candidate = InitializingSocketIdentity::private_socket_candidate_stat(&before)?;
        if self
            .initializing
            .as_ref()
            .is_some_and(|initializing| initializing.identity != candidate)
        {
            return Err(AppSocketError::IdentityMismatch);
        }

        if stat_permission_mode(before.st_mode) != APP_SOCKET_MODE {
            if self.initializing.is_none() {
                let descriptor =
                    capture_initializing_app_socket_descriptor(&self.runtime.directory, candidate)?;
                let after = statat(
                    &self.runtime.directory,
                    APP_SOCKET_NAME,
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(|_| AppSocketError::IdentityMismatch)?;
                if !candidate.matches_candidate_stat(&after)
                    || self.runtime.checked_app_socket_state()? != AppSocketEntryState::Present
                {
                    return Err(AppSocketError::IdentityMismatch);
                }
                if let Some(descriptor) = descriptor.as_ref() {
                    let opened = fstat(descriptor).map_err(|_| AppSocketError::IdentityMismatch)?;
                    if !candidate.matches_candidate_stat(&opened) {
                        return Err(AppSocketError::IdentityMismatch);
                    }
                }
                self.initializing = Some(InitializingAppSocket {
                    identity: candidate,
                    descriptor,
                });
            } else {
                let after = statat(
                    &self.runtime.directory,
                    APP_SOCKET_NAME,
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(|_| AppSocketError::IdentityMismatch)?;
                let initializing = self
                    .initializing
                    .as_ref()
                    .ok_or(AppSocketError::IdentityMismatch)?;
                if !initializing.identity.matches_candidate_stat(&after)
                    || self.runtime.checked_app_socket_state()? != AppSocketEntryState::Present
                {
                    return Err(AppSocketError::IdentityMismatch);
                }
                if let Some(descriptor) = initializing.descriptor.as_ref() {
                    let opened = fstat(descriptor).map_err(|_| AppSocketError::IdentityMismatch)?;
                    if !initializing.identity.matches_candidate_stat(&opened) {
                        return Err(AppSocketError::IdentityMismatch);
                    }
                }
            }
            return Err(AppSocketError::SocketNotReady);
        }

        let identity = SocketIdentity::private_socket_stat(&before)?;
        let descriptor = if self.initializing.is_none() {
            capture_app_socket_descriptor(&self.runtime.directory, identity)?
        } else {
            None
        };

        let after = statat(
            &self.runtime.directory,
            APP_SOCKET_NAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| AppSocketError::IdentityMismatch)?;
        if SocketIdentity::private_socket_stat(&after) != Ok(identity)
            || self.runtime.checked_app_socket_state()? != AppSocketEntryState::Present
        {
            return Err(AppSocketError::IdentityMismatch);
        }
        let retained_descriptor = self
            .initializing
            .as_ref()
            .and_then(|initializing| initializing.descriptor.as_ref())
            .or(descriptor.as_ref());
        if let Some(descriptor) = retained_descriptor {
            let opened_after = fstat(descriptor).map_err(|_| AppSocketError::IdentityMismatch)?;
            if SocketIdentity::private_socket_stat(&opened_after) != Ok(identity) {
                return Err(AppSocketError::IdentityMismatch);
            }
        }
        let descriptor = match self.initializing.take() {
            Some(initializing) => initializing.descriptor,
            None => descriptor,
        };
        Ok((descriptor, identity))
    }

    fn capture_cleanup_identity(
        &mut self,
    ) -> Result<(Option<OwnedFd>, InitializingSocketIdentity), AppSocketError> {
        match self.runtime.checked_app_socket_state()? {
            AppSocketEntryState::Absent if self.initializing.is_some() => {
                return Err(AppSocketError::IdentityMismatch);
            }
            AppSocketEntryState::Absent => return Err(AppSocketError::SocketNotReady),
            AppSocketEntryState::Present => {}
        }

        let before = statat(
            &self.runtime.directory,
            APP_SOCKET_NAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| AppSocketError::IdentityMismatch)?;
        let candidate = InitializingSocketIdentity::private_socket_candidate_stat(&before)?;
        if self
            .initializing
            .as_ref()
            .is_some_and(|initializing| initializing.identity != candidate)
        {
            return Err(AppSocketError::IdentityMismatch);
        }

        if self.initializing.is_none() {
            let descriptor =
                capture_initializing_app_socket_descriptor(&self.runtime.directory, candidate)?;
            self.initializing = Some(InitializingAppSocket {
                identity: candidate,
                descriptor,
            });
        }

        let after = statat(
            &self.runtime.directory,
            APP_SOCKET_NAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| AppSocketError::IdentityMismatch)?;
        let initializing = self
            .initializing
            .as_ref()
            .ok_or(AppSocketError::IdentityMismatch)?;
        if !initializing.identity.matches_candidate_stat(&after)
            || self.runtime.checked_app_socket_state()? != AppSocketEntryState::Present
        {
            return Err(AppSocketError::IdentityMismatch);
        }
        if let Some(descriptor) = initializing.descriptor.as_ref() {
            let opened = fstat(descriptor).map_err(|_| AppSocketError::IdentityMismatch)?;
            if !initializing.identity.matches_candidate_stat(&opened) {
                return Err(AppSocketError::IdentityMismatch);
            }
        }

        let initializing = self
            .initializing
            .take()
            .ok_or(AppSocketError::IdentityMismatch)?;
        Ok((initializing.descriptor, initializing.identity))
    }
}

impl fmt::Debug for AppSocketReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.runtime,
            &self.socket_path,
            &self.initializing,
            self.app_child_authority,
        );
        formatter.write_str("AppSocketReservation(<redacted>)")
    }
}

#[cfg(target_os = "linux")]
fn capture_app_socket_descriptor(
    directory: impl AsFd,
    identity: SocketIdentity,
) -> Result<Option<OwnedFd>, AppSocketError> {
    let descriptor = openat(
        directory,
        APP_SOCKET_NAME,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            AppSocketError::IdentityMismatch
        } else {
            AppSocketError::IdentityLeaseUnavailable
        }
    })?;
    let opened = fstat(&descriptor).map_err(|_| AppSocketError::IdentityMismatch)?;
    if SocketIdentity::private_socket_stat(&opened) == Ok(identity) {
        Ok(Some(descriptor))
    } else {
        Err(AppSocketError::IdentityMismatch)
    }
}

#[cfg(target_os = "linux")]
fn capture_initializing_app_socket_descriptor(
    directory: impl AsFd,
    identity: InitializingSocketIdentity,
) -> Result<Option<OwnedFd>, AppSocketError> {
    let descriptor = openat(
        directory,
        APP_SOCKET_NAME,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            AppSocketError::IdentityMismatch
        } else {
            AppSocketError::IdentityLeaseUnavailable
        }
    })?;
    let opened = fstat(&descriptor).map_err(|_| AppSocketError::IdentityMismatch)?;
    if identity.matches_candidate_stat(&opened) {
        Ok(Some(descriptor))
    } else {
        Err(AppSocketError::IdentityMismatch)
    }
}

#[cfg(target_os = "macos")]
fn capture_initializing_app_socket_descriptor(
    _directory: impl AsFd,
    _identity: InitializingSocketIdentity,
) -> Result<Option<OwnedFd>, AppSocketError> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn capture_app_socket_descriptor(
    _directory: impl AsFd,
    _identity: SocketIdentity,
) -> Result<Option<OwnedFd>, AppSocketError> {
    // Darwin 25 returns EOPNOTSUPP for O_RDONLY | O_NONBLOCK | O_NOFOLLOW on a
    // Unix socket. Do not pretend a descriptor exists; namespace cleanup stays
    // non-destructive and descriptor-relative to the private runtime instead.
    Ok(None)
}

#[derive(Clone)]
enum AppSocketLocation {
    Visible,
    QuarantineCandidate(String),
    Quarantined { name: String, durable: bool },
    Removed(String),
}

/// A connectable private App socket. Linux retains its exact vnode through an
/// `O_PATH` descriptor; Darwin uses repeated identity checks beneath the
/// retained private runtime because it cannot safely open a Unix socket vnode.
#[must_use = "an owned App Server socket must be exactly released or deliberately retained"]
pub(super) struct OwnedAppSocket {
    runtime: Option<Box<PrivateRuntime>>,
    descriptor: Option<OwnedFd>,
    identity: AppSocketCleanupIdentity,
    location: AppSocketLocation,
    visible_path: PathBuf,
}

impl OwnedAppSocket {
    pub(super) fn visible_path(&self) -> &Path {
        &self.visible_path
    }

    /// Appends the runtime namespace and, where the platform can safely retain
    /// it, the exact socket vnode to one source-pinned child denyset.
    pub(super) fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        let runtime = self.runtime.as_deref().ok_or(
            calcifer_unix_child_fd::CrossProcessDescriptorIdentityError::ObservationFailed,
        )?;
        runtime.append_forbidden_descriptors(forbidden)?;
        if let Some(descriptor) = self.descriptor.as_ref() {
            forbidden.capture(descriptor.as_fd())?;
        }
        Ok(())
    }

    /// Connects only through the exact identity-validated socket owned by
    /// this value. Callers never receive a raw pathname with which they could
    /// substitute another session's App Server.
    pub(super) fn connect(&self, deadline: Instant) -> Result<UnixStream, AppSocketError> {
        ensure_before_deadline(deadline)?;
        if !self.identity.is_ready() {
            return Err(AppSocketError::IdentityMismatch);
        }
        self.revalidate()?;
        if !matches!(self.location, AppSocketLocation::Visible) {
            return Err(AppSocketError::IdentityMismatch);
        }
        let stream =
            UnixStream::connect(&self.visible_path).map_err(|_| AppSocketError::SocketNotReady)?;
        ensure_before_deadline(deadline)?;
        self.revalidate()?;
        Ok(stream)
    }

    pub(super) fn revalidate(&self) -> Result<(), AppSocketError> {
        let runtime = self
            .runtime
            .as_deref()
            .ok_or(AppSocketError::IdentityMismatch)?;
        match &self.location {
            AppSocketLocation::Visible => {
                if runtime.checked_app_socket_state()? != AppSocketEntryState::Present {
                    return Err(AppSocketError::IdentityMismatch);
                }
                self.verify_named_identity(APP_SOCKET_NAME)
            }
            AppSocketLocation::Quarantined { name, .. } => {
                runtime.verify_only_generated_entry(name)?;
                self.verify_named_identity(name)
            }
            AppSocketLocation::QuarantineCandidate(_) | AppSocketLocation::Removed(_) => {
                Err(AppSocketError::IdentityMismatch)
            }
        }
    }

    /// Releases an already-unlinked socket. A lingering exact socket is moved
    /// to an unguessable same-directory quarantine, durably synced, revalidated,
    /// and then removed. A collision or replacement is never unlinked.
    ///
    /// The deadline is checked before and after each multi-step transition.
    /// Filesystem syscalls are not cancellable; an overrun therefore returns
    /// retained ownership instead of a clean capability.
    pub(super) fn cleanup(
        self,
        deadline: Instant,
    ) -> Result<PrivateRuntime, AppSocketCleanupFailure> {
        self.cleanup_inner(deadline, |_| Ok(()), sync_app_socket_runtime)
    }

    #[cfg(test)]
    fn cleanup_with_before_final_revalidation<F>(
        self,
        deadline: Instant,
        before_final_revalidation: F,
    ) -> Result<PrivateRuntime, AppSocketCleanupFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        self.cleanup_inner(deadline, before_final_revalidation, sync_app_socket_runtime)
    }

    #[cfg(test)]
    fn cleanup_with_runtime_sync_failure(
        self,
        deadline: Instant,
        fail_on_sync: usize,
    ) -> Result<PrivateRuntime, AppSocketCleanupFailure> {
        let mut sync_count = 0_usize;
        self.cleanup_inner(
            deadline,
            |_| Ok(()),
            move |_| {
                sync_count += 1;
                if sync_count == fail_on_sync {
                    Err(AppSocketError::Cleanup)
                } else {
                    Ok(())
                }
            },
        )
    }

    fn cleanup_inner<F, S>(
        mut self,
        deadline: Instant,
        mut before_final_revalidation: F,
        mut sync_runtime: S,
    ) -> Result<PrivateRuntime, AppSocketCleanupFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
        S: FnMut(&OwnedFd) -> Result<(), AppSocketError>,
    {
        match self.try_release(deadline, &mut before_final_revalidation, &mut sync_runtime) {
            Ok(()) => {
                self.descriptor = None;
                let runtime = self
                    .runtime
                    .take()
                    .ok_or(AppSocketError::IdentityMismatch)
                    .map_err(|error| AppSocketCleanupFailure {
                        socket: AppSocketCleanupAuthority {
                            socket: Box::new(self),
                        },
                        error,
                    })?;
                Ok(*runtime)
            }
            Err(error) => Err(AppSocketCleanupFailure {
                socket: AppSocketCleanupAuthority {
                    socket: Box::new(self),
                },
                error,
            }),
        }
    }

    fn try_release<F, S>(
        &mut self,
        deadline: Instant,
        before_final_revalidation: &mut F,
        sync_runtime: &mut S,
    ) -> Result<(), AppSocketError>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
        S: FnMut(&OwnedFd) -> Result<(), AppSocketError>,
    {
        ensure_before_deadline(deadline)?;
        match self.location.clone() {
            AppSocketLocation::Visible => {
                let runtime = self
                    .runtime
                    .as_deref()
                    .ok_or(AppSocketError::IdentityMismatch)?;
                match runtime.checked_app_socket_state()? {
                    AppSocketEntryState::Absent => {
                        self.verify_unlinked_identity(deadline, sync_runtime)
                    }
                    AppSocketEntryState::Present => {
                        self.revalidate()?;
                        self.move_visible_to_quarantine(
                            deadline,
                            before_final_revalidation,
                            sync_runtime,
                        )
                    }
                }
            }
            AppSocketLocation::QuarantineCandidate(name) => {
                self.make_quarantine_durable(&name, deadline, sync_runtime)?;
                self.remove_quarantined(&name, deadline, before_final_revalidation, sync_runtime)
            }
            AppSocketLocation::Quarantined { name, durable } => {
                if !durable {
                    self.make_quarantine_durable(&name, deadline, sync_runtime)?;
                }
                self.remove_quarantined(&name, deadline, before_final_revalidation, sync_runtime)
            }
            AppSocketLocation::Removed(_name) => {
                self.verify_unlinked_identity(deadline, sync_runtime)
            }
        }
    }

    fn move_visible_to_quarantine<F, S>(
        &mut self,
        deadline: Instant,
        before_final_revalidation: &mut F,
        sync_runtime: &mut S,
    ) -> Result<(), AppSocketError>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
        S: FnMut(&OwnedFd) -> Result<(), AppSocketError>,
    {
        for _ in 0..RUNTIME_QUARANTINE_ATTEMPTS {
            ensure_before_deadline(deadline)?;
            let quarantine_name = format!("{APP_SOCKET_QUARANTINE_PREFIX}{}", Uuid::new_v4());
            let rename = {
                let runtime = self
                    .runtime
                    .as_deref()
                    .ok_or(AppSocketError::IdentityMismatch)?;
                runtime
                    .verify_runtime_entry()
                    .map_err(AppSocketError::from_runtime)?;
                renameat_with(
                    &runtime.directory,
                    APP_SOCKET_NAME,
                    &runtime.directory,
                    quarantine_name.as_str(),
                    RenameFlags::NOREPLACE,
                )
            };
            match rename {
                Ok(()) => {
                    // A rename is namespace-preserving. Until the moved node is
                    // compared with the retained identity, the candidate name
                    // carries no unlink authority.
                    self.location = AppSocketLocation::QuarantineCandidate(quarantine_name.clone());
                    self.make_quarantine_durable(&quarantine_name, deadline, sync_runtime)?;
                    return self.remove_quarantined(
                        &quarantine_name,
                        deadline,
                        before_final_revalidation,
                        sync_runtime,
                    );
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(rustix::io::Errno::NOENT) => {
                    return self.verify_unlinked_identity(deadline, sync_runtime);
                }
                Err(_) => return Err(AppSocketError::Cleanup),
            }
        }
        Err(AppSocketError::Cleanup)
    }

    fn make_quarantine_durable<S>(
        &mut self,
        name: &str,
        deadline: Instant,
        sync_runtime: &mut S,
    ) -> Result<(), AppSocketError>
    where
        S: FnMut(&OwnedFd) -> Result<(), AppSocketError>,
    {
        if self.verify_quarantine_candidate(name).is_err() {
            self.location = AppSocketLocation::QuarantineCandidate(name.to_owned());
            return Err(AppSocketError::IdentityMismatch);
        }
        self.location = AppSocketLocation::Quarantined {
            name: name.to_owned(),
            durable: false,
        };
        ensure_before_deadline(deadline)?;
        let runtime = self
            .runtime
            .as_deref()
            .ok_or(AppSocketError::IdentityMismatch)?;
        sync_runtime(&runtime.directory)?;
        if self.verify_quarantine_candidate(name).is_err() {
            self.location = AppSocketLocation::QuarantineCandidate(name.to_owned());
            return Err(AppSocketError::IdentityMismatch);
        }
        self.location = AppSocketLocation::Quarantined {
            name: name.to_owned(),
            durable: true,
        };
        ensure_before_deadline(deadline)
    }

    fn remove_quarantined<F, S>(
        &mut self,
        name: &str,
        deadline: Instant,
        before_final_revalidation: &mut F,
        sync_runtime: &mut S,
    ) -> Result<(), AppSocketError>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
        S: FnMut(&OwnedFd) -> Result<(), AppSocketError>,
    {
        self.revalidate()?;
        let quarantine_path = self
            .runtime
            .as_deref()
            .ok_or(AppSocketError::IdentityMismatch)?
            .path
            .join(name);
        before_final_revalidation(&quarantine_path).map_err(|_| AppSocketError::Cleanup)?;
        ensure_before_deadline(deadline)?;
        if self.revalidate().is_err() {
            self.location = AppSocketLocation::QuarantineCandidate(name.to_owned());
            return Err(AppSocketError::IdentityMismatch);
        }

        let unlink_result = {
            let runtime = self
                .runtime
                .as_deref()
                .ok_or(AppSocketError::IdentityMismatch)?;
            unlinkat(&runtime.directory, name, AtFlags::empty())
        };
        match unlink_result {
            Ok(()) => {
                self.location = AppSocketLocation::Removed(name.to_owned());
                self.verify_unlinked_identity(deadline, sync_runtime)
            }
            Err(_) => {
                if self.verify_quarantine_candidate(name).is_err() {
                    self.location = AppSocketLocation::QuarantineCandidate(name.to_owned());
                    Err(AppSocketError::IdentityMismatch)
                } else {
                    Err(AppSocketError::Cleanup)
                }
            }
        }
    }

    fn verify_quarantine_candidate(&self, name: &str) -> Result<(), AppSocketError> {
        let runtime = self
            .runtime
            .as_deref()
            .ok_or(AppSocketError::IdentityMismatch)?;
        runtime.verify_only_generated_entry(name)?;
        self.verify_named_identity(name)
    }

    fn verify_named_identity(&self, name: &str) -> Result<(), AppSocketError> {
        let runtime = self
            .runtime
            .as_deref()
            .ok_or(AppSocketError::IdentityMismatch)?;
        runtime
            .verify_runtime_entry()
            .map_err(AppSocketError::from_runtime)?;
        if let Some(descriptor) = self.descriptor.as_ref() {
            let opened = fstat(descriptor).map_err(|_| AppSocketError::IdentityMismatch)?;
            if !self.identity.matches_named_stat(&opened) {
                return Err(AppSocketError::IdentityMismatch);
            }
        }
        let visible = statat(&runtime.directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| AppSocketError::IdentityMismatch)?;
        if !self.identity.matches_named_stat(&visible) {
            return Err(AppSocketError::IdentityMismatch);
        }
        runtime
            .verify_runtime_entry()
            .map_err(AppSocketError::from_runtime)?;
        let visible_after = statat(&runtime.directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| AppSocketError::IdentityMismatch)?;
        if !self.identity.matches_named_stat(&visible_after) {
            return Err(AppSocketError::IdentityMismatch);
        }
        if let Some(descriptor) = self.descriptor.as_ref() {
            let opened_after = fstat(descriptor).map_err(|_| AppSocketError::IdentityMismatch)?;
            if !self.identity.matches_named_stat(&opened_after) {
                return Err(AppSocketError::IdentityMismatch);
            }
        }
        Ok(())
    }

    fn verify_unlinked_identity<S>(
        &self,
        deadline: Instant,
        sync_runtime: &mut S,
    ) -> Result<(), AppSocketError>
    where
        S: FnMut(&OwnedFd) -> Result<(), AppSocketError>,
    {
        let runtime = self
            .runtime
            .as_deref()
            .ok_or(AppSocketError::IdentityMismatch)?;
        runtime
            .verify_runtime_entry()
            .map_err(AppSocketError::from_runtime)?;
        runtime
            .verify_empty()
            .map_err(AppSocketError::from_runtime)?;
        if let Some(descriptor) = self.descriptor.as_ref() {
            let unlinked = fstat(descriptor).map_err(|_| AppSocketError::IdentityMismatch)?;
            if !self.identity.matches_unlinked_stat(&unlinked) {
                return Err(AppSocketError::IdentityMismatch);
            }
        }
        ensure_before_deadline(deadline)?;
        sync_runtime(&runtime.directory)?;
        runtime
            .verify_runtime_entry()
            .map_err(AppSocketError::from_runtime)?;
        runtime
            .verify_empty()
            .map_err(AppSocketError::from_runtime)?;
        ensure_before_deadline(deadline)
    }

    #[cfg(test)]
    fn runtime_path_for_test(&self) -> &Path {
        self.runtime
            .as_deref()
            .map_or(Path::new(""), PrivateRuntime::path)
    }

    #[cfg(test)]
    fn visible_path_for_test(&self) -> &Path {
        &self.visible_path
    }

    #[cfg(test)]
    fn quarantine_path_for_test(&self) -> Option<PathBuf> {
        let name = match &self.location {
            AppSocketLocation::QuarantineCandidate(name)
            | AppSocketLocation::Quarantined { name, .. }
            | AppSocketLocation::Removed(name) => name,
            AppSocketLocation::Visible => return None,
        };
        self.runtime
            .as_deref()
            .map(|runtime| runtime.path.join(name))
    }
}

impl Drop for OwnedAppSocket {
    fn drop(&mut self) {
        // Dropping authority is not authorization to mutate the namespace.
        // Explicit deadline-bearing cleanup is the only cleanup transition.
    }
}

impl fmt::Debug for OwnedAppSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.runtime,
            &self.descriptor,
            self.identity,
            &self.location,
            &self.visible_path,
        );
        formatter.write_str("OwnedAppSocket(<redacted>)")
    }
}

/// Cleanup-only ownership for either a fully ready socket or the exact vnode
/// observed during bind-before-chmod initialization. This type intentionally
/// exposes no monitor connection transition.
#[must_use = "App socket cleanup authority must be released or deliberately retained"]
pub(super) struct AppSocketCleanupAuthority {
    socket: Box<OwnedAppSocket>,
}

impl AppSocketCleanupAuthority {
    pub(super) fn cleanup(
        self,
        deadline: Instant,
    ) -> Result<PrivateRuntime, AppSocketCleanupFailure> {
        (*self.socket).cleanup_inner(deadline, |_| Ok(()), sync_app_socket_runtime)
    }

    #[cfg(test)]
    fn cleanup_with_before_final_revalidation<F>(
        self,
        deadline: Instant,
        before_final_revalidation: F,
    ) -> Result<PrivateRuntime, AppSocketCleanupFailure>
    where
        F: FnMut(&Path) -> std::io::Result<()>,
    {
        (*self.socket).cleanup_inner(deadline, before_final_revalidation, sync_app_socket_runtime)
    }

    #[cfg(test)]
    fn cleanup_with_runtime_sync_failure(
        self,
        deadline: Instant,
        fail_on_sync: usize,
    ) -> Result<PrivateRuntime, AppSocketCleanupFailure> {
        let mut sync_count = 0_usize;
        (*self.socket).cleanup_inner(
            deadline,
            |_| Ok(()),
            move |_| {
                sync_count += 1;
                if sync_count == fail_on_sync {
                    Err(AppSocketError::Cleanup)
                } else {
                    Ok(())
                }
            },
        )
    }

    #[cfg(test)]
    fn runtime_path_for_test(&self) -> &Path {
        self.socket.runtime_path_for_test()
    }

    #[cfg(test)]
    fn quarantine_path_for_test(&self) -> Option<PathBuf> {
        self.socket.quarantine_path_for_test()
    }
}

impl fmt::Debug for AppSocketCleanupAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.socket;
        formatter.write_str("AppSocketCleanupAuthority(<redacted>)")
    }
}

/// Reservation failure before a runtime has transferred into socket state.
#[must_use = "a failed reservation returns the private runtime ownership"]
pub(super) struct AppSocketReserveFailure {
    runtime: Box<PrivateRuntime>,
    error: AppSocketError,
}

impl AppSocketReserveFailure {
    #[cfg(test)]
    pub(super) const fn error(&self) -> AppSocketError {
        self.error
    }

    pub(super) fn into_runtime(self) -> PrivateRuntime {
        *self.runtime
    }
}

impl fmt::Debug for AppSocketReserveFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppSocketReserveFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AppSocketReserveFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for AppSocketReserveFailure {}

/// Adoption/release failure that returns the exact reservation ownership.
#[must_use = "a failed socket transition returns its reservation ownership"]
pub(super) struct AppSocketReservationFailure {
    reservation: Box<AppSocketReservation>,
    error: AppSocketError,
}

impl AppSocketReservationFailure {
    pub(super) const fn error(&self) -> AppSocketError {
        self.error
    }

    pub(super) fn into_reservation(self) -> AppSocketReservation {
        *self.reservation
    }
}

impl fmt::Debug for AppSocketReservationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppSocketReservationFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AppSocketReservationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for AppSocketReservationFailure {}

/// Cleanup failure that retains descriptor-backed ownership on Linux and the
/// conservative private-runtime identity observation on Darwin.
#[must_use = "failed socket cleanup returns ownership and must be retried or retained"]
pub(super) struct AppSocketCleanupFailure {
    socket: AppSocketCleanupAuthority,
    error: AppSocketError,
}

impl AppSocketCleanupFailure {
    pub(super) const fn error(&self) -> AppSocketError {
        self.error
    }

    pub(super) fn into_socket(self) -> AppSocketCleanupAuthority {
        self.socket
    }
}

impl fmt::Debug for AppSocketCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppSocketCleanupFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AppSocketCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for AppSocketCleanupFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AppSocketError {
    UnsafeRuntime,
    PathTooLong,
    Collision,
    UnknownEntry,
    SocketNotReady,
    UnsafeNode,
    #[cfg(target_os = "linux")]
    IdentityLeaseUnavailable,
    IdentityMismatch,
    SocketStillPresent,
    AdoptionTimeout,
    Timeout,
    Cleanup,
}

impl AppSocketError {
    const fn from_runtime(error: RuntimeError) -> Self {
        match error {
            RuntimeError::NotEmpty => Self::UnknownEntry,
            RuntimeError::Cleanup => Self::Cleanup,
            RuntimeError::UnsafeParent
            | RuntimeError::Create
            | RuntimeError::UnsafeIdentity
            | RuntimeError::IdentityMismatch => Self::IdentityMismatch,
        }
    }
}

impl fmt::Display for AppSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeRuntime => "App Server socket runtime is unsafe",
            Self::PathTooLong => "App Server socket address exceeds the portable limit",
            Self::Collision => "App Server socket reservation collided",
            Self::UnknownEntry => "App Server socket runtime contains an unknown entry",
            Self::SocketNotReady => "App Server socket is not ready",
            Self::UnsafeNode => "App Server socket node is unsafe",
            #[cfg(target_os = "linux")]
            Self::IdentityLeaseUnavailable => "App Server socket identity cannot be retained",
            Self::IdentityMismatch => "App Server socket identity changed",
            Self::SocketStillPresent => "App Server socket remains present",
            Self::AdoptionTimeout => "App Server socket adoption deadline elapsed",
            Self::Timeout => "App Server socket cleanup deadline elapsed",
            Self::Cleanup => "App Server socket cleanup failed",
        })
    }
}

impl std::error::Error for AppSocketError {}

fn ensure_before_deadline(deadline: Instant) -> Result<(), AppSocketError> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(AppSocketError::Timeout)
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
    use std::time::Duration;

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

        fn new_short() -> Result<Self, Box<dyn Error>> {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            // Keep this namespace disjoint from provider.rs's independently
            // allocated short parents; both modules run in the same parallel
            // libtest process and therefore share /tmp and the process id.
            let raw = PathBuf::from("/tmp").join(format!(
                "cf-r-{}-{}",
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

    fn socket_cleanup_deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn app_socket_entry_observation_accepts_only_stable_or_monotonic_creation() {
        use AppSocketEntryObservation::{Appeared, Stable};
        use AppSocketEntryState::{Absent, Present};

        for (states, expected) in [
            ((Absent, Absent, Absent), Ok(Stable(Absent))),
            ((Present, Present, Present), Ok(Stable(Present))),
            ((Absent, Absent, Present), Ok(Appeared)),
            ((Absent, Present, Present), Ok(Appeared)),
            (
                (Absent, Present, Absent),
                Err(AppSocketError::IdentityMismatch),
            ),
            (
                (Present, Absent, Absent),
                Err(AppSocketError::IdentityMismatch),
            ),
            (
                (Present, Absent, Present),
                Err(AppSocketError::IdentityMismatch),
            ),
            (
                (Present, Present, Absent),
                Err(AppSocketError::IdentityMismatch),
            ),
        ] {
            assert_eq!(
                classify_app_socket_entry_observation(states.0, states.1, states.2),
                expected
            );
        }
    }

    #[test]
    fn app_socket_appearance_is_allowed_only_at_the_exact_initial_bind_boundary() {
        assert_eq!(
            strict_app_socket_entry_state(AppSocketEntryObservation::Appeared),
            Err(AppSocketError::IdentityMismatch)
        );
        assert_eq!(
            initial_bind_app_socket_entry_state(AppSocketEntryObservation::Appeared),
            Ok(AppSocketEntryState::Present)
        );
        for state in [AppSocketEntryState::Absent, AppSocketEntryState::Present] {
            let observation = AppSocketEntryObservation::Stable(state);
            assert_eq!(strict_app_socket_entry_state(observation), Ok(state));
            assert_eq!(initial_bind_app_socket_entry_state(observation), Ok(state));
        }
    }

    #[test]
    fn stat_permission_projection_is_platform_stable() {
        assert_eq!(stat_permission_mode(0o100600), 0o600);
        assert_eq!(stat_permission_mode(0o107777), 0o7777);
    }

    #[test]
    fn portable_app_socket_path_limit_accepts_103_bytes_and_rejects_104() {
        let exact = PathBuf::from(format!("/{}", "a".repeat(102)));
        let over = PathBuf::from(format!("/{}", "a".repeat(103)));

        assert_eq!(exact.as_os_str().as_bytes().len(), 103);
        assert_eq!(validate_app_socket_path(&exact), Ok(()));
        assert_eq!(over.as_os_str().as_bytes().len(), 104);
        assert_eq!(
            validate_app_socket_path(&over),
            Err(AppSocketError::PathTooLong)
        );
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
    fn fixture_cleanup_removes_a_bounded_same_mount_registry_tree() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        let profile_home = path.join("profiles/codex/profile/home");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&profile_home)?;
        fs::write(profile_home.join("auth.json"), b"auth")?;
        fs::write(profile_home.join("config.toml"), b"config")?;
        fs::write(path.join("matrix-app-group.identity"), b"app")?;
        fs::write(path.join("matrix-tui-group.identity"), b"tui")?;
        fs::write(
            path.join(format!(".calcifer-private-publish-{}.tmp", Uuid::new_v4())),
            b"temporary",
        )?;

        let _clean = runtime
            .cleanup_fixture_tree()
            .map_err(|failure| failure.error())?;
        assert!(!path.try_exists()?);
        Ok(())
    }

    #[test]
    fn fixture_cleanup_mount_identity_is_exact_and_mismatch_fails_closed()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        let nested = path.join("same-mount-directory");
        fs::DirBuilder::new().mode(0o700).create(&nested)?;
        let nested_fd = open(
            &nested,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let root_mount = fixture_mount_identity_fd(&runtime.directory)?;
        assert_eq!(
            ensure_fixture_mount(&root_mount, &fixture_mount_identity_fd(&nested_fd)?),
            Ok(())
        );
        let different_mount = FixtureMountIdentity {
            token: b"synthetic-different-mount".to_vec(),
        };
        assert_eq!(
            ensure_fixture_mount(&root_mount, &different_mount),
            Err(RuntimeError::UnsafeIdentity)
        );

        let _clean = runtime
            .cleanup_fixture_tree()
            .map_err(|failure| failure.error())?;
        assert!(!path.try_exists()?);
        Ok(())
    }

    #[test]
    fn fixture_cleanup_rejects_a_link_without_touching_its_target() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        let target = parent.path.join("outside-target");
        fs::write(&target, b"must-survive")?;
        let link = path.join("unexpected-link");
        std::os::unix::fs::symlink(&target, &link)?;

        let failure = runtime
            .cleanup_fixture_tree()
            .err()
            .ok_or("a fixture symlink must be rejected")?;
        assert_eq!(failure.error(), RuntimeError::UnsafeIdentity);
        assert_eq!(fs::read(&target)?, b"must-survive");
        let runtime = failure.into_runtime();
        fs::remove_file(&link)?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        assert!(!path.try_exists()?);
        Ok(())
    }

    #[test]
    fn fixture_cleanup_quarantine_preserves_a_late_visible_replacement()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        let visible = path.join("matrix-app-group.identity");
        fs::write(&visible, b"original")?;
        let mut observed_quarantine = None;

        let failure = runtime
            .cleanup_fixture_tree_with_before_entry_unlink(|quarantine| {
                observed_quarantine = Some(quarantine.to_path_buf());
                fs::write(&visible, b"replacement")
            })
            .err()
            .ok_or("a late visible replacement must retain the runtime")?;
        assert_eq!(fs::read(&visible)?, b"replacement");
        let quarantine = observed_quarantine.ok_or("fixture quarantine was not observed")?;
        assert!(
            quarantine
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(FIXTURE_ENTRY_QUARANTINE_PREFIX))
        );

        let runtime = failure.into_runtime();
        fs::remove_file(&visible)?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        assert!(!path.try_exists()?);
        Ok(())
    }

    #[test]
    fn fixture_cleanup_never_mints_clean_proof_after_final_entry_replacement()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let path = runtime.path().to_path_buf();
        fs::write(path.join("matrix-app-group.identity"), b"original")?;
        let parked = path.join("parked-original");

        let failure = runtime
            .cleanup_fixture_tree_with_before_entry_unlink(|quarantine| {
                fs::rename(quarantine, &parked)?;
                fs::write(quarantine, b"replacement")
            })
            .err()
            .ok_or("a replaced fixture quarantine must not mint CleanRuntime")?;
        assert_eq!(failure.error(), RuntimeError::IdentityMismatch);
        assert_eq!(fs::read(&parked)?, b"original");
        let runtime = failure.into_runtime();
        fs::remove_file(&parked)?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        assert!(!path.try_exists()?);
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
    fn runtime_cleanup_retains_ownership_when_parent_sync_after_rename_fails()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;

        let failure = runtime
            .cleanup_with_parent_sync_failure(1)
            .err()
            .ok_or("the quarantine rename sync failure must retain ownership")?;
        assert_eq!(failure.error(), RuntimeError::Cleanup);
        let runtime = failure.into_runtime();
        assert!(runtime.path().exists());
        assert!(
            runtime
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".calcifer-cleanup-"))
        );

        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn runtime_cleanup_retains_removed_identity_when_parent_sync_after_remove_fails()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let runtime = PrivateRuntime::create(&parent.path)?;

        let failure = runtime
            .cleanup_with_parent_sync_failure(2)
            .err()
            .ok_or("the remove sync failure must retain open-inode evidence")?;
        assert_eq!(failure.error(), RuntimeError::Cleanup);
        let runtime = failure.into_runtime();
        assert!(!runtime.path().exists());
        assert!(runtime.name.is_none());

        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
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

    #[test]
    fn app_socket_reservation_has_one_fixed_portable_name() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let runtime_path = runtime.path().to_path_buf();

        let reservation = runtime.reserve_app_socket()?;
        assert_eq!(
            reservation
                .path()
                .file_name()
                .and_then(|name| name.to_str()),
            Some("app.sock")
        );
        assert_eq!(reservation.path(), runtime_path.join("app.sock"));
        assert!(reservation.path().as_os_str().as_bytes().len() <= 103);

        let runtime = reservation.release_if_absent()?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn supervised_layout_seals_fixed_app_and_exact_relay_routes() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let runtime_path = runtime.path().to_path_buf();

        let layout = runtime.reserve_supervised_layout()?;
        assert_eq!(format!("{layout:?}"), "SupervisedRuntimeLayout(<redacted>)");
        let (app, relay) = layout.into_parts();
        let (downstream, upstream) = relay.paths_for_test();
        assert_eq!(app.path(), runtime_path.join("app.sock"));
        assert_eq!(upstream, app.path());
        assert_eq!(downstream, runtime_path.join("tui.sock"));
        assert_ne!(downstream, upstream);
        assert!(downstream.as_os_str().as_bytes().len() <= 103);
        assert_eq!(format!("{relay:?}"), "ExactRelayRoute(<redacted>)");

        let runtime = app.release_if_absent()?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn app_socket_reservation_rejects_an_overlong_path_and_returns_runtime()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new()?;
        let long_parent = parent.path.join("x".repeat(110));
        fs::DirBuilder::new().mode(0o700).create(&long_parent)?;
        let long_parent = fs::canonicalize(long_parent)?;
        let runtime = PrivateRuntime::create(&long_parent)?;
        let runtime_path = runtime.path().to_path_buf();

        let failure = runtime
            .reserve_app_socket()
            .err()
            .ok_or("an overlong socket address must fail")?;
        assert_eq!(failure.error(), AppSocketError::PathTooLong);
        let runtime = failure.into_runtime();
        assert_eq!(runtime.path(), runtime_path);
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn app_socket_reservation_rejects_a_collision_without_rendering_data()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let runtime_path = runtime.path().to_path_buf();
        let socket_path = runtime_path.join("app.sock");
        fs::write(&socket_path, b"secret-payload")?;

        let failure = runtime
            .reserve_app_socket()
            .err()
            .ok_or("a pre-existing node must fail reservation")?;
        assert_eq!(failure.error(), AppSocketError::Collision);
        let rendered = format!("{failure:?} {failure}");
        assert!(!rendered.contains(runtime_path.to_string_lossy().as_ref()));
        assert!(!rendered.contains("app.sock"));
        assert!(!rendered.contains("secret-payload"));

        let runtime = failure.into_runtime();
        fs::remove_file(socket_path)?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn reservation_release_fails_closed_for_an_unknown_entry_and_returns_ownership()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let reservation = runtime.reserve_app_socket()?;
        let runtime_path = reservation.runtime.path().to_path_buf();
        fs::write(runtime_path.join("sensitive-node-name"), b"secret-payload")?;

        let failure = reservation
            .release_if_absent()
            .err()
            .ok_or("an unknown entry must prevent release")?;
        assert_eq!(failure.error(), AppSocketError::UnknownEntry);
        let rendered = format!("{failure:?} {failure}");
        assert!(!rendered.contains(runtime_path.to_string_lossy().as_ref()));
        assert!(!rendered.contains("sensitive-node-name"));
        assert!(!rendered.contains("secret-payload"));

        let reservation = failure.into_reservation();
        fs::remove_file(runtime_path.join("sensitive-node-name"))?;
        let runtime = reservation.release_if_absent()?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn app_socket_transition_rechecks_the_runtime_identity() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let reservation = runtime.reserve_app_socket()?;
        let runtime_path = reservation.runtime.path().to_path_buf();
        fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o755))?;

        let failure = reservation
            .release_if_absent()
            .err()
            .ok_or("a changed runtime mode must fail closed")?;
        assert_eq!(failure.error(), AppSocketError::IdentityMismatch);

        fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o700))?;
        let runtime = failure.into_reservation().release_if_absent()?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn app_socket_adoption_rejects_a_file_symlink_and_unknown_entry() -> Result<(), Box<dyn Error>>
    {
        use std::os::unix::net::UnixListener;

        for bad_node in ["file", "symlink", "unknown-entry"] {
            let parent = TestDirectory::new_short()?;
            let runtime = PrivateRuntime::create(&parent.path)?;
            let reservation = runtime.reserve_app_socket()?;
            let runtime_path = reservation.runtime.path().to_path_buf();
            let socket_path = reservation.path().to_path_buf();
            let mut listener = None;

            match bad_node {
                "file" => fs::write(&socket_path, b"not-a-socket")?,
                "symlink" => std::os::unix::fs::symlink("target", &socket_path)?,
                "unknown-entry" => {
                    listener = Some(UnixListener::bind(&socket_path)?);
                    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
                    fs::write(runtime_path.join("unknown"), b"secret-payload")?;
                }
                _ => return Err("unknown test case".into()),
            }

            let failure = reservation
                .adopt()
                .err()
                .ok_or("unsafe socket adoption must fail")?;
            let expected = if bad_node == "unknown-entry" {
                AppSocketError::UnknownEntry
            } else {
                AppSocketError::UnsafeNode
            };
            assert_eq!(failure.error(), expected);
            assert!(fs::symlink_metadata(&socket_path).is_ok());

            let reservation = failure.into_reservation();
            drop(listener);
            fs::remove_file(&socket_path)?;
            if bad_node == "unknown-entry" {
                fs::remove_file(runtime_path.join("unknown"))?;
            }
            let runtime = reservation.release_if_absent()?;
            let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        }
        Ok(())
    }

    #[test]
    fn app_socket_initialization_never_accepts_a_replacement_vnode() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::net::UnixListener;

        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let reservation = runtime.reserve_app_socket()?;
        let socket_path = reservation.path().to_path_buf();
        let first = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o755))?;
        let first_identity = fs::symlink_metadata(&socket_path)?;

        let failure = reservation
            .adopt()
            .err()
            .ok_or("a bind-before-chmod socket must remain pending")?;
        assert_eq!(failure.error(), AppSocketError::SocketNotReady);
        let reservation = failure.into_reservation();

        // Keep the original listener open while replacing its unlinked name,
        // making inode reuse impossible and exercising the exact-vnode guard.
        fs::remove_file(&socket_path)?;
        let second = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let second_identity = fs::symlink_metadata(&socket_path)?;
        assert_ne!(
            (first_identity.dev(), first_identity.ino()),
            (second_identity.dev(), second_identity.ino())
        );

        let failure = reservation
            .adopt()
            .err()
            .ok_or("a replacement ready socket must not satisfy initialization")?;
        assert_eq!(failure.error(), AppSocketError::IdentityMismatch);

        let reservation = failure.into_reservation();
        drop(second);
        fs::remove_file(&socket_path)?;
        drop(first);
        let runtime = reservation.release_if_absent()?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn initializing_app_socket_retains_a_non_inheritable_exact_identity()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::net::UnixListener;

        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let reservation = runtime.reserve_app_socket()?;
        let socket_path = reservation.path().to_path_buf();
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o755))?;

        let failure = reservation
            .adopt()
            .err()
            .ok_or("a bind-before-chmod socket must remain pending")?;
        assert_eq!(failure.error(), AppSocketError::SocketNotReady);
        let reservation = failure.into_reservation();

        #[cfg(target_os = "linux")]
        {
            let initializing = reservation
                .initializing
                .as_ref()
                .ok_or("initialization must retain exact cleanup identity")?;
            let descriptor = initializing
                .descriptor
                .as_ref()
                .ok_or("Linux initialization must retain an O_PATH descriptor")?;
            assert!(rustix::fs::fcntl_getfl(descriptor)?.contains(OFlags::PATH));
            assert!(rustix::io::fcntl_getfd(descriptor)?.contains(rustix::io::FdFlags::CLOEXEC));
            assert!(
                initializing
                    .identity
                    .matches_candidate_stat(&fstat(descriptor)?)
            );
        }

        drop(listener);
        fs::remove_file(&socket_path)?;
        let runtime = reservation.release_if_absent()?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    fn initializing_cleanup_authority(
        parent: &TestDirectory,
    ) -> Result<
        (
            std::os::unix::net::UnixListener,
            PathBuf,
            AppSocketCleanupAuthority,
        ),
        Box<dyn Error>,
    > {
        use std::os::unix::net::UnixListener;

        let runtime = PrivateRuntime::create(&parent.path)?;
        let reservation = runtime.reserve_app_socket()?;
        let socket_path = reservation.path().to_path_buf();
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o755))?;
        let failure = reservation
            .adopt()
            .err()
            .ok_or("a bind-before-chmod socket must remain pending")?;
        assert_eq!(failure.error(), AppSocketError::SocketNotReady);
        let cleanup = failure
            .into_reservation()
            .claim_socket_for_cleanup_for_test()?;
        Ok((listener, socket_path, cleanup))
    }

    #[test]
    fn initializing_cleanup_deadline_and_fsync_failure_retain_retryable_authority()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let (listener, socket_path, cleanup) = initializing_cleanup_authority(&parent)?;
        let runtime_path = cleanup.runtime_path_for_test().to_path_buf();
        drop(listener);

        let failure = cleanup
            .cleanup(Instant::now())
            .err()
            .ok_or("expired initialization cleanup must retain authority")?;
        assert_eq!(failure.error(), AppSocketError::Timeout);
        assert!(socket_path.exists());
        assert!(runtime_path.exists());

        let failure = failure
            .into_socket()
            .cleanup_with_runtime_sync_failure(socket_cleanup_deadline(), 1)
            .err()
            .ok_or("initialization quarantine fsync failure must retain authority")?;
        assert_eq!(failure.error(), AppSocketError::Cleanup);
        let cleanup = failure.into_socket();
        let quarantine = cleanup
            .quarantine_path_for_test()
            .ok_or("initialization quarantine identity must remain retained")?;
        assert!(quarantine.exists());
        assert!(!socket_path.exists());

        let runtime = cleanup.cleanup(socket_cleanup_deadline())?;
        assert!(!quarantine.exists());
        assert_eq!(runtime.path(), runtime_path);
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn initializing_cleanup_never_unlinks_a_last_moment_replacement() -> Result<(), Box<dyn Error>>
    {
        use std::os::unix::fs::MetadataExt;

        let parent = TestDirectory::new_short()?;
        let (listener, socket_path, cleanup) = initializing_cleanup_authority(&parent)?;
        let runtime_path = cleanup.runtime_path_for_test().to_path_buf();
        let parked_original = parent.path.join("parked-initializing-original");
        let mut replacement_inode = None;
        drop(listener);

        let failure = cleanup
            .cleanup_with_before_final_revalidation(socket_cleanup_deadline(), |quarantine| {
                fs::rename(quarantine, &parked_original)?;
                fs::write(quarantine, b"replacement-must-survive")?;
                fs::set_permissions(quarantine, fs::Permissions::from_mode(0o600))?;
                replacement_inode = Some(fs::symlink_metadata(quarantine)?.ino());
                Ok(())
            })
            .err()
            .ok_or("a replacement must prevent initialization cleanup")?;

        assert_eq!(failure.error(), AppSocketError::IdentityMismatch);
        assert!(parked_original.exists());
        let cleanup = failure.into_socket();
        let quarantine = cleanup
            .quarantine_path_for_test()
            .ok_or("raced initialization quarantine must remain owned")?;
        assert_eq!(
            fs::symlink_metadata(&quarantine)?.ino(),
            replacement_inode.ok_or("replacement was not created")?
        );
        assert_eq!(fs::read(&quarantine)?, b"replacement-must-survive");
        assert!(!socket_path.exists());
        assert!(runtime_path.exists());

        drop(cleanup);
        assert!(parked_original.exists());
        assert!(quarantine.exists());
        Ok(())
    }

    #[test]
    fn another_app_childs_reap_proof_cannot_authorize_initializing_cleanup()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::net::UnixListener;

        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let mut reservation = runtime.reserve_app_socket()?;
        let socket_path = reservation.path().to_path_buf();
        let owning_child = ChildAuthority::for_test(41);
        let other_child = ChildAuthority::for_test(42);
        reservation.bind_app_child(owning_child)?;
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o755))?;
        let failure = reservation
            .adopt()
            .err()
            .ok_or("a bind-before-chmod socket must remain pending")?;
        assert_eq!(failure.error(), AppSocketError::SocketNotReady);
        let reservation = failure.into_reservation();

        let unrelated_drain = PinnedAppGracefulDrain::for_child_authority_test(other_child);
        let failure = reservation
            .claim_socket_for_cleanup_after_child_exit(&unrelated_drain)
            .err()
            .ok_or("another App child's reap proof authorized cleanup")?;
        assert_eq!(failure.error(), AppSocketError::IdentityMismatch);
        assert!(socket_path.exists());

        let owning_drain = PinnedAppGracefulDrain::for_child_authority_test(owning_child);
        drop(listener);
        let cleanup = failure
            .into_reservation()
            .claim_socket_for_cleanup_after_child_exit(&owning_drain)?;
        let runtime = cleanup.cleanup(socket_cleanup_deadline())?;
        assert!(!socket_path.exists());
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_adopts_by_private_runtime_observation_without_fabricating_a_vnode_descriptor()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::net::UnixListener;

        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let reservation = runtime.reserve_app_socket()?;
        let socket_path = reservation.path().to_path_buf();
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

        let socket = reservation.adopt()?;
        assert!(socket.descriptor.is_none());
        socket.revalidate()?;
        assert!(socket_path.exists());

        drop(listener);
        fs::remove_file(&socket_path)?;
        let runtime = socket.cleanup(socket_cleanup_deadline())?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    fn bind_adopted_socket(
        runtime: PrivateRuntime,
    ) -> Result<(std::os::unix::net::UnixListener, OwnedAppSocket), Box<dyn Error>> {
        use std::os::unix::net::UnixListener;

        let reservation = runtime.reserve_app_socket()?;
        let listener = UnixListener::bind(reservation.path())?;
        fs::set_permissions(reservation.path(), fs::Permissions::from_mode(0o600))?;
        let socket = reservation.adopt()?;
        Ok((listener, socket))
    }

    #[test]
    fn owned_socket_drop_preserves_the_visible_node_and_runtime() -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let (listener, socket) = bind_adopted_socket(runtime)?;
        let runtime_path = socket.runtime_path_for_test().to_path_buf();
        let socket_path = socket.visible_path_for_test().to_path_buf();

        drop(socket);
        assert!(runtime_path.exists());
        assert!(socket_path.exists());
        drop(listener);
        Ok(())
    }

    #[test]
    fn expired_socket_cleanup_deadline_returns_ownership_without_mutation()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let (listener, socket) = bind_adopted_socket(runtime)?;
        let runtime_path = socket.runtime_path_for_test().to_path_buf();
        let socket_path = socket.visible_path_for_test().to_path_buf();

        let failure = socket
            .cleanup(Instant::now())
            .err()
            .ok_or("an elapsed deadline must return socket ownership")?;
        assert_eq!(failure.error(), AppSocketError::Timeout);
        assert!(runtime_path.exists());
        assert!(socket_path.exists());

        let socket = failure.into_socket();
        drop(listener);
        fs::remove_file(socket_path)?;
        let runtime = socket.cleanup(socket_cleanup_deadline())?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn socket_absence_sync_failure_returns_identity_ownership_for_retry()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let (listener, socket) = bind_adopted_socket(runtime)?;
        let runtime_path = socket.runtime_path_for_test().to_path_buf();
        let socket_path = socket.visible_path_for_test().to_path_buf();
        drop(listener);
        fs::remove_file(socket_path)?;

        let failure = socket
            .cleanup_with_runtime_sync_failure(socket_cleanup_deadline(), 1)
            .err()
            .ok_or("an absence fsync failure must return socket ownership")?;
        assert_eq!(failure.error(), AppSocketError::Cleanup);
        assert!(runtime_path.exists());

        let runtime = failure.into_socket().cleanup(socket_cleanup_deadline())?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn socket_quarantine_sync_failure_returns_exact_ownership_for_retry()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let (listener, socket) = bind_adopted_socket(runtime)?;
        let runtime_path = socket.runtime_path_for_test().to_path_buf();
        drop(listener);

        let failure = socket
            .cleanup_with_runtime_sync_failure(socket_cleanup_deadline(), 1)
            .err()
            .ok_or("the quarantine fsync failure must return exact ownership")?;
        assert_eq!(failure.error(), AppSocketError::Cleanup);
        let socket = failure.into_socket();
        let quarantine = socket
            .quarantine_path_for_test()
            .ok_or("the quarantine identity must be retained")?;
        assert!(quarantine.exists());
        assert!(!runtime_path.join(APP_SOCKET_NAME).exists());

        let runtime = socket.cleanup(socket_cleanup_deadline())?;
        assert!(!quarantine.exists());
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn socket_remove_sync_failure_returns_removed_identity_evidence_for_retry()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let (listener, socket) = bind_adopted_socket(runtime)?;
        let runtime_path = socket.runtime_path_for_test().to_path_buf();
        drop(listener);

        let failure = socket
            .cleanup_with_runtime_sync_failure(socket_cleanup_deadline(), 2)
            .err()
            .ok_or("the socket unlink fsync failure must retain evidence")?;
        assert_eq!(failure.error(), AppSocketError::Cleanup);
        let socket = failure.into_socket();
        let removed_path = socket
            .quarantine_path_for_test()
            .ok_or("the removed quarantine name must remain recorded")?;
        assert!(!removed_path.exists());
        assert!(!runtime_path.join(APP_SOCKET_NAME).exists());

        let runtime = socket.cleanup(socket_cleanup_deadline())?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_adoption_retains_an_o_path_identity_and_revalidates_it() -> Result<(), Box<dyn Error>>
    {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let (listener, socket) = bind_adopted_socket(runtime)?;

        assert!(
            rustix::fs::fcntl_getfl(
                socket
                    .descriptor
                    .as_ref()
                    .ok_or("the Linux lease must retain a descriptor")?
            )?
            .contains(OFlags::PATH)
        );
        socket.revalidate()?;

        let runtime_path = socket.runtime_path_for_test().to_path_buf();
        let socket_path = socket.visible_path_for_test().to_path_buf();
        drop(listener);
        fs::remove_file(&socket_path)?;
        let runtime = socket.cleanup(socket_cleanup_deadline())?;
        assert_eq!(runtime.path(), runtime_path);
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_adoption_rejects_a_socket_with_an_extra_hard_link() -> Result<(), Box<dyn Error>> {
        use std::os::unix::net::UnixListener;

        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let reservation = runtime.reserve_app_socket()?;
        let socket_path = reservation.path().to_path_buf();
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let extra_link = parent.path.join("extra-socket-link");
        fs::hard_link(&socket_path, &extra_link)?;

        let failure = reservation
            .adopt()
            .err()
            .ok_or("a socket with st_nlink != 1 must fail closed")?;
        assert_eq!(failure.error(), AppSocketError::UnsafeNode);
        assert_eq!(fs::symlink_metadata(&socket_path)?.nlink(), 2);

        let reservation = failure.into_reservation();
        drop(listener);
        fs::remove_file(extra_link)?;
        fs::remove_file(socket_path)?;
        let runtime = reservation.release_if_absent()?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn revalidation_rejects_replacement_without_mutating_either_socket()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::net::UnixListener;

        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let (original_listener, socket) = bind_adopted_socket(runtime)?;
        let socket_path = socket.visible_path_for_test().to_path_buf();
        let parked_original = parent.path.join("parked-original");
        fs::rename(&socket_path, &parked_original)?;
        let replacement_listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

        assert_eq!(socket.revalidate(), Err(AppSocketError::IdentityMismatch));
        assert!(socket_path.exists());
        assert!(parked_original.exists());

        drop(original_listener);
        drop(replacement_listener);
        drop(socket);
        assert!(socket_path.exists());
        assert!(parked_original.exists());
        Ok(())
    }

    #[test]
    fn cleanup_removes_a_lingering_exact_socket_via_durable_quarantine()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let (listener, socket) = bind_adopted_socket(runtime)?;
        let runtime_path = socket.runtime_path_for_test().to_path_buf();
        let visible_path = socket.visible_path_for_test().to_path_buf();

        drop(listener);
        let runtime = socket.cleanup(socket_cleanup_deadline())?;
        assert!(!visible_path.exists());
        assert_eq!(runtime.path(), runtime_path);
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn last_race_replacement_is_never_renamed_unlinked_or_reported_clean()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let (original_listener, socket) = bind_adopted_socket(runtime)?;
        let runtime_path = socket.runtime_path_for_test().to_path_buf();
        let parked_original = parent.path.join("parked-final-race-original");
        let mut replacement_inode = None;

        let failure = socket
            .cleanup_with_before_final_revalidation(socket_cleanup_deadline(), |visible| {
                fs::rename(visible, &parked_original)?;
                fs::write(visible, b"replacement-must-survive")?;
                fs::set_permissions(visible, fs::Permissions::from_mode(0o600))?;
                replacement_inode = Some(fs::symlink_metadata(visible)?.ino());
                Ok(())
            })
            .err()
            .ok_or("a final replacement race must not report clean")?;

        assert_eq!(failure.error(), AppSocketError::IdentityMismatch);
        assert!(parked_original.exists());
        let replacement_inode = replacement_inode.ok_or("replacement was not created")?;
        let quarantine_path = failure
            .socket
            .quarantine_path_for_test()
            .ok_or("the raced quarantine path must remain owned")?;
        assert_eq!(
            fs::symlink_metadata(&quarantine_path)?.ino(),
            replacement_inode
        );
        assert_eq!(fs::read(&quarantine_path)?, b"replacement-must-survive");
        assert!(!runtime_path.join(APP_SOCKET_NAME).exists());

        drop(original_listener);
        drop(failure);
        assert!(parked_original.exists());
        Ok(())
    }

    #[test]
    fn cleanup_failure_drop_preserves_runtime_without_an_implicit_retry()
    -> Result<(), Box<dyn Error>> {
        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let (listener, socket) = bind_adopted_socket(runtime)?;
        let runtime_path = socket.runtime_path_for_test().to_path_buf();
        drop(listener);
        let failure = socket
            .cleanup_with_runtime_sync_failure(socket_cleanup_deadline(), 1)
            .err()
            .ok_or("a quarantine sync failure must return ownership")?;
        assert_eq!(failure.error(), AppSocketError::Cleanup);
        let quarantine_path = failure
            .socket
            .quarantine_path_for_test()
            .ok_or("the exact quarantine must remain owned")?;
        assert!(quarantine_path.exists());
        assert!(!runtime_path.join(APP_SOCKET_NAME).exists());
        let rendered = format!("{failure:?} {failure}");
        assert!(!rendered.contains(runtime_path.to_string_lossy().as_ref()));
        assert!(!rendered.contains("app.sock"));

        drop(failure);
        assert!(runtime_path.exists());
        assert!(quarantine_path.exists());
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

    #[cfg(target_os = "macos")]
    #[test]
    fn app_socket_transition_rechecks_the_runtime_acl_through_its_open_inode()
    -> Result<(), Box<dyn Error>> {
        use exacl::{AclEntry, Perm};

        let parent = TestDirectory::new_short()?;
        let runtime = PrivateRuntime::create(&parent.path)?;
        let reservation = runtime.reserve_app_socket()?;
        let current_uid = rustix::process::geteuid().as_raw();
        let other_uid = if current_uid == 89 { "1" } else { "89" };
        let acl = [AclEntry::allow_user(other_uid, Perm::READ, None)];
        exacl::setfacl(
            &[reservation.runtime.path()],
            &acl,
            Some(exacl::AclOption::SYMLINK_ACL),
        )?;

        let failure = reservation
            .release_if_absent()
            .err()
            .ok_or("a changed runtime ACL must fail closed")?;
        assert_eq!(failure.error(), AppSocketError::IdentityMismatch);
        let reservation = failure.into_reservation();
        calcifer_macos_acl::clear_acl(reservation.runtime.directory.as_fd())?;
        let runtime = reservation.release_if_absent()?;
        let _clean = runtime.cleanup().map_err(|failure| failure.error())?;
        Ok(())
    }
}
