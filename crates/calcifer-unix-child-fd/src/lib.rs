//! Audited Unix process and descriptor primitives for Calcifer.
//!
//! The main crate forbids unsafe Rust. This crate confines the required unsafe
//! OS boundaries: signal-mask guards, child-only `pre_exec` descriptor
//! inheritance, exact child/process-group lifecycle operations, and bounded
//! Linux/macOS process-group descriptor inspection. Safe wrappers preserve
//! descriptor ownership, validate native return sizes and process identity,
//! cap every externally sized scan, and fail closed on mutation, permission
//! loss, unsupported descriptor identity, or deadline exhaustion. The parent
//! process never clears `FD_CLOEXEC` on a shared descriptor.

#![cfg(unix)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::fs;
use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod process_group_scan;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use process_group_scan::{
    CrossProcessDescriptorIdentityError, CrossProcessDescriptorSet,
    ProcessGroupDescriptorIsolationProof, ProcessGroupDescriptorScanError,
    verify_process_group_forbidden_descriptors_absent_before,
};

const MAX_DESCRIPTOR_SCAN_ENTRIES: usize = 4_096;
#[cfg(target_os = "macos")]
const MAX_PROCESS_GROUP_SCAN_ENTRIES: usize = 4_096;
const CHILD_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const CHILD_CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Fixed, private environment key carrying the dynamically selected child fd.
///
/// The value is installed only on a command passed to
/// [`spawn_with_inherited_readiness_fd`]. It is never exported into the parent
/// process environment.
pub const READINESS_FD_ENV: &str = "CALCIFER_SUPERVISOR_READINESS_FD";

static READINESS_FD_TAKEN: AtomicBool = AtomicBool::new(false);

thread_local! {
    static SIGTTOU_BLOCK_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SIGCONT_BLOCK_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Terminates the complete Unix process without running Rust/C destructors or
/// producing a signal-driven core dump.
///
/// This is the safe, audited `_exit(2)` boundary for a fail-closed process that
/// must not unwind or run cleanup code. Callers are responsible for writing and
/// flushing any required diagnostic first. A zero status is technically
/// accepted by the kernel, so callers that report failure must pass a fixed
/// nonzero value.
pub fn exit_process_without_destructors(status: u8) -> ! {
    // SAFETY: `_exit` accepts every integer status, does not dereference
    // pointers, and never returns. Restricting the public input to `u8` avoids
    // target-specific truncation while keeping the unsafe libc call confined
    // to this audited crate.
    unsafe { libc::_exit(i32::from(status)) }
}

/// A calling-thread-only `SIGTTOU` mask guard.
///
/// The previous complete signal mask is private and is restored on drop. The
/// guard is deliberately neither `Send` nor `Sync`, so restoration cannot move
/// to a different thread. Nested guards must be dropped in reverse acquisition
/// order; violating that linear order or encountering an impossible restore
/// failure aborts instead of silently leaving a guardian with the wrong mask.
#[must_use = "dropping the guard restores the calling thread's prior signal mask"]
pub struct SigttouBlockGuard {
    previous_mask: libc::sigset_t,
    depth: usize,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl fmt::Debug for SigttouBlockGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigttouBlockGuard(<active>)")
    }
}

impl Drop for SigttouBlockGuard {
    fn drop(&mut self) {
        let in_order = SIGTTOU_BLOCK_DEPTH.with(|depth| depth.get() == self.depth);
        if !in_order {
            std::process::abort();
        }

        // SAFETY: `previous_mask` was fully initialized by the successful
        // pthread_sigmask call that created this same-thread guard. The null
        // output pointer requests no additional write.
        let result = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut())
        };
        if result != 0 {
            std::process::abort();
        }
        SIGTTOU_BLOCK_DEPTH.with(|depth| depth.set(self.depth - 1));
    }
}

/// Blocks `SIGTTOU` only in the calling thread until the returned guard drops.
///
/// This is intended for a background guardian's bounded terminal restoration:
/// POSIX terminal ioctls may otherwise stop the guardian before it can publish
/// recovery evidence. The complete prior mask is restored exactly, including
/// when the guarded scope exits through `?` or unwinding.
///
/// Keep the guard in one short lexical scope. It must not be forgotten, and
/// that scope must not create a thread, fork, or exec: those operations can
/// inherit the temporarily blocked mask without this process-local guard.
///
/// ```compile_fail
/// let guard = calcifer_unix_child_fd::block_sigttou_for_current_thread().unwrap();
/// std::thread::spawn(move || drop(guard));
/// ```
pub fn block_sigttou_for_current_thread() -> io::Result<SigttouBlockGuard> {
    let mut blocked = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: `blocked` points to writable storage for one sigset, which
    // sigemptyset fully initializes on success.
    if unsafe { libc::sigemptyset(blocked.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sigemptyset initialized the set and SIGTTOU is a valid signal on
    // the Unix targets supported by this crate.
    if unsafe { libc::sigaddset(blocked.as_mut_ptr(), libc::SIGTTOU) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the two successful calls above initialized the complete set.
    let blocked = unsafe { blocked.assume_init() };

    let mut previous_mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: `blocked` is initialized and immutable, while `previous_mask`
    // points to writable output storage. pthread_sigmask affects only this
    // calling thread and returns an errno value directly.
    let result =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, previous_mask.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    // SAFETY: successful pthread_sigmask initialized the complete prior mask.
    let previous_mask = unsafe { previous_mask.assume_init() };
    let depth = SIGTTOU_BLOCK_DEPTH.with(|depth| {
        let next = depth
            .get()
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        depth.set(next);
        next
    });
    Ok(SigttouBlockGuard {
        previous_mask,
        depth,
        _not_send_or_sync: PhantomData,
    })
}

/// Calling-thread-only `SIGCONT` mask guard for an atomic self-stop boundary.
///
/// This is deliberately separate from [`SigttouBlockGuard`]: job-control
/// continuation has different ordering semantics, and nesting the two guards
/// must restore each complete prior mask in strict LIFO order.
#[must_use = "dropping the guard restores the calling thread's prior signal mask"]
pub struct SigcontBlockGuard {
    previous_mask: libc::sigset_t,
    depth: usize,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl fmt::Debug for SigcontBlockGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigcontBlockGuard(<active>)")
    }
}

impl Drop for SigcontBlockGuard {
    fn drop(&mut self) {
        let in_order = SIGCONT_BLOCK_DEPTH.with(|depth| depth.get() == self.depth);
        if !in_order {
            std::process::abort();
        }
        // SAFETY: the successful pthread_sigmask call below initialized the
        // complete prior mask, and this !Send guard drops on that same thread.
        let result = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut())
        };
        if result != 0 {
            std::process::abort();
        }
        SIGCONT_BLOCK_DEPTH.with(|depth| depth.set(self.depth - 1));
    }
}

/// Blocks `SIGCONT` only on the calling coordinator thread.
///
/// The guarded scope must not create a thread, fork, or exec. A process-level
/// `SIGCONT` still resumes a stopped process while blocked; after resumption,
/// dropping this guard restores the exact prior mask and lets the installed
/// handler mint the fresh continuation latch.
pub fn block_sigcont_for_current_thread() -> io::Result<SigcontBlockGuard> {
    let mut blocked = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: writable storage is fully initialized by sigemptyset on success.
    if unsafe { libc::sigemptyset(blocked.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SIGCONT is valid on every Unix target supported by this crate.
    if unsafe { libc::sigaddset(blocked.as_mut_ptr(), libc::SIGCONT) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both initialization calls succeeded.
    let blocked = unsafe { blocked.assume_init() };
    let mut previous_mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: inputs are initialized and pthread_sigmask writes one full mask.
    let result =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, previous_mask.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    // SAFETY: successful pthread_sigmask initialized the output mask.
    let previous_mask = unsafe { previous_mask.assume_init() };
    let depth = SIGCONT_BLOCK_DEPTH.with(|depth| {
        let next = depth
            .get()
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        depth.set(next);
        next
    });
    Ok(SigcontBlockGuard {
        previous_mask,
        depth,
        _not_send_or_sync: PhantomData,
    })
}

/// A child-fd spawn failure that distinguishes pre-spawn failure from a
/// started child whose direct wait authority must still be consumed.
///
/// Debug and display output deliberately omit the command and raw I/O error.
/// If a started child is not extracted, dropping this value performs the same
/// bounded, fail-closed kill-and-`try_wait` fallback as the legacy inheritance
/// API.
#[must_use = "a started child may still require exact cleanup"]
pub struct InheritedFdSpawnError {
    cause: Option<io::Error>,
    child: Option<StartedChild>,
}

impl InheritedFdSpawnError {
    fn not_started(cause: io::Error) -> Self {
        Self {
            cause: Some(cause),
            child: None,
        }
    }

    fn started(cause: io::Error, child: Child) -> Self {
        Self {
            cause: Some(cause),
            child: Some(StartedChild { child: Some(child) }),
        }
    }

    /// Returns whether the failed operation created a direct child.
    pub fn child_started(&self) -> bool {
        self.child.is_some()
    }

    /// Transfers the direct child handle to a bounded cleanup authority.
    pub fn into_started_child(mut self) -> Option<StartedChild> {
        self.child.take()
    }
}

impl fmt::Debug for InheritedFdSpawnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InheritedFdSpawnError")
            .field("child_started", &self.child_started())
            .finish()
    }
}

impl fmt::Display for InheritedFdSpawnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.child_started() {
            formatter.write_str("inherited descriptor spawn failed after child start")
        } else {
            formatter.write_str("inherited descriptor spawn failed before child start")
        }
    }
}

impl std::error::Error for InheritedFdSpawnError {}

/// Exact direct-child authority returned only for a post-spawn failure.
///
/// A caller may transfer the underlying [`Child`] into a stronger supervisor
/// contract with [`Self::into_child`]. If this value is instead dropped, it
/// performs bounded kill-and-`try_wait` cleanup. Failure to reap within that
/// bound aborts, because returning while silently discarding direct wait
/// authority could leave an untracked live child.
#[must_use = "started child authority must be transferred or exactly reaped"]
pub struct StartedChild {
    child: Option<Child>,
}

impl StartedChild {
    /// Transfers the direct child handle into the caller's bounded supervisor.
    pub fn into_child(mut self) -> Child {
        match self.child.take() {
            Some(child) => child,
            None => std::process::abort(),
        }
    }
}

impl fmt::Debug for StartedChild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StartedChild(<direct-wait-authority>)")
    }
}

impl Drop for StartedChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if !terminate_spawned_child(child) {
                std::process::abort();
            }
        }
    }
}

/// Removes a consumed or stale readiness advertisement from a later exec.
///
/// Every command spawned after [`take_inherited_readiness_fd`] must pass
/// through this helper. Descriptor sealing prevents resource inheritance;
/// scrubbing the key also prevents a later executable from interpreting a
/// recycled fd number as a new readiness capability.
pub fn scrub_readiness_fd_env(command: &mut Command) {
    command.env_remove(READINESS_FD_ENV);
}

/// Path-free device/inode identity returned by `fstat(2)`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DescriptorIdentity {
    /// Device containing the descriptor's underlying object.
    pub device: u64,
    /// Inode of the descriptor's underlying object.
    pub inode: u64,
}

impl fmt::Debug for DescriptorIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (self.device, self.inode);
        formatter.write_str("DescriptorIdentity(<redacted>)")
    }
}

/// Reads one open descriptor's path-free filesystem identity.
pub fn descriptor_identity(descriptor: BorrowedFd<'_>) -> io::Result<DescriptorIdentity> {
    descriptor_identity_raw(descriptor.as_raw_fd())
}

/// Counts open descriptors with an exact path-free identity.
///
/// This bounded scanner exists for real-exec inheritance assertions. It never
/// takes ownership of, duplicates, closes, or renders any inspected descriptor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn count_open_descriptors_with_identity(expected: DescriptorIdentity) -> io::Result<usize> {
    if expected.inode == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor identity inode is zero",
        ));
    }
    #[cfg(target_os = "linux")]
    let descriptor_directory = "/proc/self/fd";
    #[cfg(target_os = "macos")]
    let descriptor_directory = "/dev/fd";

    let mut descriptors = Vec::new();
    for entry in fs::read_dir(descriptor_directory)? {
        if descriptors.len() == MAX_DESCRIPTOR_SCAN_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "descriptor scan exceeded its entry limit",
            ));
        }
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Ok(raw_descriptor) = name.parse::<RawFd>() {
            descriptors.push(raw_descriptor);
        }
    }

    let mut matches = 0_usize;
    for raw_descriptor in descriptors {
        match descriptor_identity_raw(raw_descriptor) {
            Ok(identity) if identity == expected => matches += 1,
            Ok(_) => {}
            Err(error)
                if matches!(error.raw_os_error(), Some(libc::EBADF) | Some(libc::ENOENT)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(matches)
}

/// Returns whether a macOS process group contains any non-zombie member.
///
/// This bounded observation exists only for explicitly synthetic fixtures
/// after `killpg(2)` reports `EPERM`; it is never production containment
/// proof. Darwin can retain a wait-visible zombie group leader that cannot
/// receive a signal; that leader no longer holds fixture resources, but its
/// exit alone says nothing about same-group descendants. `proc_listpgrppids`
/// enumerates the whole group and each member is checked with
/// `PROC_PIDTBSDINFO`. Capacity saturation or an unreadable member fails
/// closed instead of being interpreted as absence.
#[cfg(target_os = "macos")]
pub fn macos_process_group_has_live_members(process_group: i32) -> io::Result<bool> {
    if process_group <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process group must be positive",
        ));
    }
    let mut members = [0_i32; MAX_PROCESS_GROUP_SCAN_ENTRIES];
    let buffer_bytes = std::mem::size_of_val(&members);
    let buffer_size = libc::c_int::try_from(buffer_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process scan was too large"))?;
    // SAFETY: `members` is a writable fixed-size PID array for the entire
    // declared byte range. `proc_listpgrppids` does not retain the pointer.
    let count =
        unsafe { libc::proc_listpgrppids(process_group, members.as_mut_ptr().cast(), buffer_size) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let count = usize::try_from(count)
        .map_err(|_| io::Error::other("process-group scan count was invalid"))?;
    if count >= members.len() {
        return Err(io::Error::other(
            "process-group scan reached its fixed bound",
        ));
    }

    for pid in members.into_iter().take(count) {
        if pid <= 0 {
            continue;
        }
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let info_size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
            .map_err(|_| io::Error::other("process info size was invalid"))?;
        // SAFETY: `info` is writable storage for exactly one proc_bsdinfo and
        // `proc_pidinfo` does not retain the pointer. The value is read only
        // after the function reports a complete structure.
        let read = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                info_size,
            )
        };
        if read == 0 {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT)) {
                continue;
            }
            return Err(error);
        }
        if read != info_size {
            return Err(io::Error::other("process info read was incomplete"));
        }
        // SAFETY: the exact-size successful read initialized the structure.
        let info = unsafe { info.assume_init() };
        if info.pbi_pgid == process_group as u32 && info.pbi_status != libc::SZOMB {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Proves that an unreaped process-group leader anchors a zombie-only group.
///
/// This is stricter than [`macos_process_group_has_live_members`]. It is
/// suitable for a production containment decision only after the caller has
/// independently observed the exact direct child in a terminal wait state
/// without reaping it. The unreaped leader pins the numeric PID/PGID against
/// reuse while two complete snapshots prove that the exact leader is the
/// group's only member and is a zombie. Production deliberately rejects
/// additional zombie members: PID-list equality alone cannot exclude a
/// descendant reap/reuse ABA without another birth-identity anchor. A missing,
/// vanished, or unreadable member, capacity saturation, or membership drift
/// fails closed.
#[cfg(target_os = "macos")]
pub fn macos_process_group_is_anchored_zombie_only(
    process_group: i32,
    leader_pid: i32,
) -> io::Result<bool> {
    if process_group <= 0 || leader_pid != process_group {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the unreaped group leader must anchor its own positive process group",
        ));
    }

    let first = macos_zombie_group_snapshot(process_group, leader_pid)?;
    if !first.all_zombie || !first.leader_seen || first.members.as_slice() != [leader_pid] {
        return Ok(false);
    }
    let second = macos_zombie_group_snapshot(process_group, leader_pid)?;
    Ok(second.all_zombie
        && second.leader_seen
        && second.members.as_slice() == [leader_pid]
        && first.members == second.members)
}

#[cfg(target_os = "macos")]
struct MacosZombieGroupSnapshot {
    members: Vec<i32>,
    leader_seen: bool,
    all_zombie: bool,
}

#[cfg(target_os = "macos")]
fn macos_zombie_group_snapshot(
    process_group: i32,
    leader_pid: i32,
) -> io::Result<MacosZombieGroupSnapshot> {
    let mut listed = [0_i32; MAX_PROCESS_GROUP_SCAN_ENTRIES];
    let buffer_size = libc::c_int::try_from(std::mem::size_of_val(&listed))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process scan was too large"))?;
    // SAFETY: `listed` is writable for the complete byte range and the call
    // does not retain the pointer.
    let count =
        unsafe { libc::proc_listpgrppids(process_group, listed.as_mut_ptr().cast(), buffer_size) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let count = usize::try_from(count)
        .map_err(|_| io::Error::other("process-group scan count was invalid"))?;
    if count == 0 || count >= listed.len() {
        return Err(io::Error::other(
            "anchored process-group scan was empty or reached its fixed bound",
        ));
    }

    let mut members = Vec::with_capacity(count);
    let mut leader_seen = false;
    let mut all_zombie = true;
    for pid in listed.into_iter().take(count) {
        if pid <= 0 {
            return Err(io::Error::other(
                "anchored process-group scan returned an invalid member",
            ));
        }
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let info_size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
            .map_err(|_| io::Error::other("process info size was invalid"))?;
        // SAFETY: `info` is exact writable storage for one proc_bsdinfo and
        // is read only after a complete successful call.
        let read = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                1,
                info.as_mut_ptr().cast(),
                info_size,
            )
        };
        if read != info_size {
            return Err(if read == 0 {
                io::Error::last_os_error()
            } else {
                io::Error::other("process info read was incomplete")
            });
        }
        // SAFETY: the exact-size successful read initialized the structure.
        let info = unsafe { info.assume_init() };
        if info.pbi_pgid != process_group as u32 {
            return Err(io::Error::other(
                "process-group member identity changed during inspection",
            ));
        }
        leader_seen |= pid == leader_pid && info.pbi_status == libc::SZOMB;
        all_zombie &= info.pbi_status == libc::SZOMB;
        members.push(pid);
    }
    members.sort_unstable();
    if members.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(io::Error::other(
            "process-group scan returned a duplicate member",
        ));
    }
    Ok(MacosZombieGroupSnapshot {
        members,
        leader_seen,
        all_zombie,
    })
}

/// Atomically replaces inherited stdin with a close-on-exec `/dev/null` while
/// preserving exactly one already-created duplicate of `expected`.
///
/// This is an exec-entry operation for Calcifer's still-single-threaded
/// guardian. The caller must first create one close-on-exec duplicate and end
/// every `BorrowedFd` lifetime for fd 0. The identity is revalidated before
/// replacement, so a raced standard stream is never silently accepted.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn replace_inherited_stdin_with_dev_null(expected: DescriptorIdentity) -> io::Result<()> {
    replace_inherited_standard_stream_with_dev_null(libc::STDIN_FILENO, libc::O_RDONLY, expected)
}

/// Atomically replaces inherited stdout with a close-on-exec `/dev/null`
/// while preserving exactly one already-created duplicate of `expected`.
///
/// See [`replace_inherited_stdin_with_dev_null`] for the single-threaded
/// exec-entry and identity-pinning contract.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn replace_inherited_stdout_with_dev_null(expected: DescriptorIdentity) -> io::Result<()> {
    replace_inherited_standard_stream_with_dev_null(libc::STDOUT_FILENO, libc::O_WRONLY, expected)
}

/// Atomically replaces inherited stderr with a close-on-exec `/dev/null`
/// while preserving exactly one already-created duplicate of `expected`.
///
/// See [`replace_inherited_stdin_with_dev_null`] for the single-threaded
/// exec-entry and identity-pinning contract.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn replace_inherited_stderr_with_dev_null(expected: DescriptorIdentity) -> io::Result<()> {
    replace_inherited_standard_stream_with_dev_null(libc::STDERR_FILENO, libc::O_WRONLY, expected)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn replace_inherited_standard_stream_with_dev_null(
    standard_stream: RawFd,
    access_mode: libc::c_int,
    expected: DescriptorIdentity,
) -> io::Result<()> {
    if expected.inode == 0
        || !matches!(
            standard_stream,
            libc::STDIN_FILENO | libc::STDOUT_FILENO | libc::STDERR_FILENO
        )
        || !matches!(access_mode, libc::O_RDONLY | libc::O_WRONLY)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid inherited standard-stream replacement request",
        ));
    }
    if descriptor_identity_raw(standard_stream)? != expected
        || count_open_descriptors_with_identity(expected)? != 2
    {
        return Err(io::Error::other(
            "inherited standard-stream identity was not exclusive",
        ));
    }

    let dev_null = open_dev_null(access_mode)?;
    if !descriptor_is_character_device(dev_null.as_raw_fd())? {
        return Err(io::Error::other(
            "dev-null descriptor was not a character device",
        ));
    }
    let dev_null_identity = descriptor_identity(dev_null.as_fd())?;
    if dev_null_identity == expected {
        return Err(io::Error::other(
            "dev-null identity overlapped inherited standard stream",
        ));
    }

    duplicate_to_standard_stream(dev_null.as_raw_fd(), standard_stream)?;
    let flags = descriptor_flags(standard_stream)?;
    set_close_on_exec(standard_stream, flags)?;
    if descriptor_flags(standard_stream)? & libc::FD_CLOEXEC == 0
        || descriptor_status_flags(standard_stream)? & libc::O_ACCMODE != access_mode
        || descriptor_identity_raw(standard_stream)? != dev_null_identity
        || descriptor_identity_raw(standard_stream)? == expected
        || count_open_descriptors_with_identity(expected)? != 1
    {
        return Err(io::Error::other(
            "inherited standard stream could not be safely replaced",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_dev_null(access_mode: libc::c_int) -> io::Result<OwnedFd> {
    let flags = access_mode | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    loop {
        // SAFETY: the byte string is a fixed NUL-terminated path and `flags`
        // contains no variadic create mode. Successful ownership is moved into
        // exactly one `OwnedFd` below.
        let raw_descriptor = unsafe { libc::open(c"/dev/null".as_ptr(), flags) };
        if raw_descriptor >= 0 {
            // SAFETY: `open` returned one fresh owned descriptor.
            return Ok(unsafe { OwnedFd::from_raw_fd(raw_descriptor) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn duplicate_to_standard_stream(source: RawFd, target: RawFd) -> io::Result<()> {
    loop {
        // SAFETY: both integers name live descriptors at this single-threaded
        // exec-entry boundary. `dup2` atomically replaces `target`, so no
        // reusable closed standard-stream hole is exposed.
        let duplicated = unsafe { libc::dup2(source, target) };
        if duplicated == target {
            return Ok(());
        }
        if duplicated >= 0 {
            return Err(io::Error::other(
                "standard-stream duplication returned an unexpected descriptor",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn descriptor_status_flags(raw_descriptor: RawFd) -> io::Result<libc::c_int> {
    // SAFETY: `F_GETFL` reads status flags without taking ownership.
    let flags = unsafe { libc::fcntl(raw_descriptor, libc::F_GETFL) };
    if flags == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn descriptor_is_character_device(raw_descriptor: RawFd) -> io::Result<bool> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `status` is writable storage for one complete `stat` value.
    if unsafe { libc::fstat(raw_descriptor, status.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstat` initialized the complete value.
    let status = unsafe { status.assume_init() };
    Ok(status.st_mode & libc::S_IFMT == libc::S_IFCHR)
}

fn descriptor_identity_raw(raw_descriptor: RawFd) -> io::Result<DescriptorIdentity> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `status` points to writable storage for one `libc::stat` and
    // `fstat` does not take ownership of or close the integer descriptor. An
    // invalid/raced descriptor is reported as an ordinary errno.
    let result = unsafe { libc::fstat(raw_descriptor, status.as_mut_ptr()) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstat` initialized the complete output structure.
    let status = unsafe { status.assume_init() };
    #[cfg(target_os = "macos")]
    // Darwin exposes `dev_t` through a signed 32-bit C type. Its high bit is
    // part of an opaque kernel identity, not a semantic negative value. Keep
    // the exact bit pattern so two `fstat(2)` results remain comparable.
    let device = u64::from(status.st_dev as u32);
    #[cfg(target_os = "linux")]
    let device = status.st_dev;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let device = status.st_dev as u64;
    Ok(DescriptorIdentity {
        device,
        inode: status.st_ino,
    })
}

/// Spawns one command whose child-side copy of `descriptor` survives `exec`.
///
/// The descriptor must already be close-on-exec in the parent. The command is
/// consumed so the installed `pre_exec` closure cannot outlive the borrowed
/// descriptor or be reused after its file number has been recycled.
///
/// Only async-signal-safe `fcntl(2)` calls run between `fork` and `exec`. The
/// parent descriptor is never mutated. A parent-side readback is performed
/// after spawn; if that invariant cannot be confirmed, the child is killed and
/// reaped before an error is returned.
pub fn spawn_with_inherited_fd(command: Command, descriptor: BorrowedFd<'_>) -> io::Result<Child> {
    #[cfg(test)]
    let result = spawn_with_inherited_fd_inner(command, descriptor, false, None);
    #[cfg(not(test))]
    let result = spawn_with_inherited_fd_inner(command, descriptor, false);
    result.map_err(collapse_spawn_error)
}

/// Spawns one reviewed child with a one-shot readiness fd advertised through
/// [`READINESS_FD_ENV`].
///
/// The parent descriptor must already be close-on-exec. A fresh, dynamically
/// numbered duplicate is made inheritable only inside this child's audited
/// post-fork callback; unrelated concurrent execs cannot inherit it. The exec'd
/// program must call [`take_inherited_readiness_fd`] before starting threads or
/// spawning another process.
pub fn spawn_with_inherited_readiness_fd(
    command: Command,
    descriptor: BorrowedFd<'_>,
) -> Result<Child, InheritedFdSpawnError> {
    #[cfg(test)]
    {
        spawn_with_inherited_fd_inner(command, descriptor, true, None)
    }
    #[cfg(not(test))]
    {
        spawn_with_inherited_fd_inner(command, descriptor, true)
    }
}

/// Takes the one readiness fd installed by
/// [`spawn_with_inherited_readiness_fd`] and immediately restores
/// `FD_CLOEXEC`.
///
/// This is a safe, one-shot exec-entry API: it accepts only a non-stdio fd from
/// the fixed private environment key, requires that the child-only inheritance
/// flag is still clear, atomically rejects a second take, and restores and
/// verifies close-on-exec.
///
/// The returned owner is a fresh close-on-exec duplicate. The environment is
/// process input and cannot prove that its raw fd is not already owned by a
/// safe Rust wrapper, so this function never adopts or closes that number. The
/// sealed bootstrap fd remains open until the next exec or process exit. This
/// costs one bounded descriptor but keeps the safe API sound even if the
/// environment entry is stale or spoofed. The raw environment value is never
/// included in an error.
///
/// Callers must pass every later [`Command`] through
/// [`scrub_readiness_fd_env`]. If peer-observed EOF is part of the one-shot
/// protocol, use a full-duplex socket and shut down its write half after the
/// final write: dropping only the returned duplicate cannot close the sealed
/// bootstrap fd.
pub fn take_inherited_readiness_fd() -> io::Result<OwnedFd> {
    let raw_descriptor = parse_inherited_readiness_fd()?;
    if READINESS_FD_TAKEN
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the inherited readiness descriptor was already taken",
        ));
    }

    take_inherited_readiness_fd_inner(raw_descriptor)
}

fn parse_inherited_readiness_fd() -> io::Result<RawFd> {
    let value = std::env::var_os(READINESS_FD_ENV).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the inherited readiness descriptor was not advertised",
        )
    })?;
    let value = value.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the inherited readiness descriptor was not valid UTF-8",
        )
    })?;
    let raw_descriptor = value.parse::<RawFd>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the inherited readiness descriptor was invalid",
        )
    })?;
    if raw_descriptor < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the inherited readiness descriptor overlapped standard I/O",
        ));
    }
    Ok(raw_descriptor)
}

fn take_inherited_readiness_fd_inner(raw_descriptor: RawFd) -> io::Result<OwnedFd> {
    let flags = descriptor_flags(raw_descriptor)?;
    if flags & libc::FD_CLOEXEC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the inherited readiness descriptor was already close-on-exec",
        ));
    }
    set_close_on_exec(raw_descriptor, flags)?;
    if descriptor_flags(raw_descriptor)? & libc::FD_CLOEXEC == 0 {
        return Err(io::Error::other(
            "the inherited readiness descriptor could not be resealed",
        ));
    }
    let inherited_identity = descriptor_identity_raw(raw_descriptor)?;
    let owned_descriptor = duplicate_for_child(raw_descriptor)?;
    if descriptor_identity_raw(raw_descriptor)? != inherited_identity
        || descriptor_identity(owned_descriptor.as_fd())? != inherited_identity
    {
        return Err(io::Error::other(
            "the inherited readiness descriptor changed while it was resealed",
        ));
    }
    Ok(owned_descriptor)
}

fn spawn_with_inherited_fd_inner(
    mut command: Command,
    descriptor: BorrowedFd<'_>,
    advertise_readiness_fd: bool,
    #[cfg(test)] pre_exec_barrier: Option<PreExecBarrier>,
) -> Result<Child, InheritedFdSpawnError> {
    let source_descriptor = descriptor.as_raw_fd();
    let parent_flags =
        descriptor_flags(source_descriptor).map_err(InheritedFdSpawnError::not_started)?;
    if parent_flags & libc::FD_CLOEXEC == 0 {
        return Err(InheritedFdSpawnError::not_started(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inherited descriptor is not close-on-exec in the parent",
        )));
    }

    // Duplicate atomically with close-on-exec and keep the child-facing number
    // outside the standard streams. Rust configures stdio before `pre_exec`, so
    // passing source fd 0, 1, or 2 directly could otherwise be overwritten.
    let child_descriptor =
        duplicate_for_child(source_descriptor).map_err(InheritedFdSpawnError::not_started)?;
    let child_raw_descriptor = child_descriptor.as_raw_fd();
    scrub_readiness_fd_env(&mut command);
    if advertise_readiness_fd {
        command.env(READINESS_FD_ENV, child_raw_descriptor.to_string());
    }

    // SAFETY: `child_raw_descriptor` remains valid through the one immediate
    // spawn because `child_descriptor` is held below. The command is consumed
    // and spawned exactly once, so the closure cannot be retained or reused
    // after that descriptor closes. Inside the post-fork child the closure
    // calls only async-signal-safe `fcntl(2)` operations and returns errno.
    unsafe {
        command.pre_exec(move || {
            clear_close_on_exec_in_child(child_raw_descriptor)?;
            #[cfg(test)]
            if let Some(barrier) = pre_exec_barrier {
                barrier.synchronize()?;
            }
            Ok(())
        });
    }

    let child = command
        .spawn()
        .map_err(InheritedFdSpawnError::not_started)?;
    let parent_source_flags = descriptor_flags(source_descriptor);
    let parent_child_flags = descriptor_flags(child_raw_descriptor);
    drop(child_descriptor);
    match (parent_source_flags, parent_child_flags) {
        (Ok(source_flags), Ok(child_flags))
            if source_flags & libc::FD_CLOEXEC != 0 && child_flags & libc::FD_CLOEXEC != 0 =>
        {
            Ok(child)
        }
        (Ok(_), Ok(_)) => Err(InheritedFdSpawnError::started(
            io::Error::other("child spawn changed the parent descriptor inheritance flag"),
            child,
        )),
        (Err(error), _) | (_, Err(error)) => Err(InheritedFdSpawnError::started(error, child)),
    }
}

fn collapse_spawn_error(mut error: InheritedFdSpawnError) -> io::Error {
    // The legacy API cannot return post-spawn authority. Dropping the typed
    // owner performs bounded cleanup and aborts fail-closed if exact reap could
    // not be confirmed.
    drop(error.child.take());
    match error.cause.take() {
        Some(cause) => cause,
        None => io::Error::other("inherited descriptor spawn failed"),
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct PreExecBarrier {
    ready: RawFd,
    release: RawFd,
}

#[cfg(test)]
impl PreExecBarrier {
    fn synchronize(self) -> io::Result<()> {
        let ready = [1_u8];
        retry_one_byte_io(|| {
            // SAFETY: `ready` is a live one-byte input buffer, and this runs
            // before exec while the captured socket descriptor is still open.
            unsafe { libc::write(self.ready, ready.as_ptr().cast(), ready.len()) }
        })?;

        let mut release = [0_u8; 1];
        retry_one_byte_io(|| {
            // SAFETY: `release` is a live one-byte output buffer, and this
            // runs before exec while the captured socket descriptor is open.
            unsafe { libc::read(self.release, release.as_mut_ptr().cast(), release.len()) }
        })
    }
}

#[cfg(test)]
fn retry_one_byte_io(mut operation: impl FnMut() -> isize) -> io::Result<()> {
    loop {
        match operation() {
            1 => return Ok(()),
            0 => return Err(io::Error::from_raw_os_error(libc::EPIPE)),
            -1 => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            _ => return Err(io::Error::from_raw_os_error(libc::EIO)),
        }
    }
}

fn duplicate_for_child(source_descriptor: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `F_DUPFD_CLOEXEC` atomically creates a new descriptor referring
    // to the same open-file description. The lower bound of 3 keeps it outside
    // stdio setup. A nonnegative result is newly owned by this function.
    let duplicated = unsafe { libc::fcntl(source_descriptor, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated == -1 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: A successful `F_DUPFD_CLOEXEC` returns one fresh owned fd.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
    }
}

fn descriptor_flags(raw_descriptor: RawFd) -> io::Result<libc::c_int> {
    // SAFETY: `F_GETFD` reads flags from the borrowed, live descriptor and
    // does not dereference a pointer.
    let flags = unsafe { libc::fcntl(raw_descriptor, libc::F_GETFD) };
    if flags == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

fn clear_close_on_exec_in_child(raw_descriptor: RawFd) -> io::Result<()> {
    // SAFETY: Both calls operate on the child-side copy of the descriptor.
    // `fcntl` with `F_GETFD`/`F_SETFD` is async-signal-safe and uses no pointer.
    let flags = unsafe { libc::fcntl(raw_descriptor, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe { libc::fcntl(raw_descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_close_on_exec(raw_descriptor: RawFd, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: `F_SETFD` changes only descriptor flags on the live descriptor
    // and uses no pointer. The caller read `flags` from this exact fd.
    let result = unsafe { libc::fcntl(raw_descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn terminate_spawned_child(child: &mut Child) -> bool {
    let _ = child.kill();
    let Some(deadline) = Instant::now().checked_add(CHILD_CLEANUP_TIMEOUT) else {
        return false;
    };
    poll_child_until_reaped(deadline, || child.try_wait())
}

fn poll_child_until_reaped(
    deadline: Instant,
    mut try_wait: impl FnMut() -> io::Result<Option<std::process::ExitStatus>>,
) -> bool {
    loop {
        match try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        thread::sleep(
            deadline
                .saturating_duration_since(now)
                .min(CHILD_CLEANUP_POLL_INTERVAL),
        );
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const TAKE_READINESS_HELPER_ENV: &str = "CALCIFER_TEST_TAKE_READINESS_FD";
    const RESEALED_GRANDCHILD_HELPER_ENV: &str = "CALCIFER_TEST_RESEALED_READINESS_FD";
    const RESEALED_IDENTITY_ENV: &str = "CALCIFER_TEST_RESEALED_READINESS_IDENTITY";
    const INVALID_READINESS_HELPER_ENV: &str = "CALCIFER_TEST_INVALID_READINESS_FD";
    const SIGTTOU_LIFO_ABORT_HELPER_ENV: &str = "CALCIFER_TEST_SIGTTOU_LIFO_ABORT";

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_process_group_scan_observes_the_live_calling_process()
    -> Result<(), Box<dyn std::error::Error>> {
        // SAFETY: getpgrp has no arguments and returns process-local metadata.
        let process_group = unsafe { libc::getpgrp() };
        assert!(macos_process_group_has_live_members(process_group)?);
        assert!(macos_process_group_has_live_members(0).is_err());
        Ok(())
    }

    #[test]
    fn child_reap_poll_returns_at_its_deadline_without_a_blocking_wait() {
        let mut attempts = 0_usize;
        let started_at = Instant::now();

        let reaped = poll_child_until_reaped(Instant::now(), || {
            attempts += 1;
            Ok(None)
        });

        assert!(!reaped);
        assert_eq!(attempts, 1);
        assert!(started_at.elapsed() < Duration::from_millis(100));
    }

    fn set_signal_blocked_for_test(signal: libc::c_int, blocked: bool) -> io::Result<()> {
        let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: `signals` points to writable storage for one sigset, which
        // `sigemptyset` initializes on success.
        if unsafe { libc::sigemptyset(signals.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `sigemptyset` initialized the set and callers pass one valid
        // platform signal constant.
        if unsafe { libc::sigaddset(signals.as_mut_ptr(), signal) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both successful calls above initialized the full set.
        let signals = unsafe { signals.assume_init() };
        let how = if blocked {
            libc::SIG_BLOCK
        } else {
            libc::SIG_UNBLOCK
        };
        // SAFETY: `signals` is initialized, the output pointer is null, and
        // pthread_sigmask changes only the calling test thread.
        let result = unsafe { libc::pthread_sigmask(how, &signals, std::ptr::null_mut()) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(result))
        }
    }

    fn signal_is_blocked_for_test(signal: libc::c_int) -> io::Result<bool> {
        let mut current = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: a null input set queries without changing the calling
        // thread's mask, and `current` is valid writable output storage.
        let result = unsafe {
            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), current.as_mut_ptr())
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        // SAFETY: successful pthread_sigmask initialized the complete set.
        let current = unsafe { current.assume_init() };
        // SAFETY: `current` is initialized and callers pass one valid platform
        // signal constant.
        match unsafe { libc::sigismember(&current, signal) } {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn set_sigttou_blocked_for_test(blocked: bool) -> io::Result<()> {
        set_signal_blocked_for_test(libc::SIGTTOU, blocked)
    }

    fn sigttou_is_blocked_for_test() -> io::Result<bool> {
        signal_is_blocked_for_test(libc::SIGTTOU)
    }

    #[test]
    fn sigttou_block_is_scoped_and_restores_the_previous_mask()
    -> Result<(), Box<dyn std::error::Error>> {
        thread::spawn(|| -> io::Result<()> {
            set_sigttou_blocked_for_test(false)?;
            set_signal_blocked_for_test(libc::SIGUSR1, true)?;
            assert!(!sigttou_is_blocked_for_test()?);
            assert!(signal_is_blocked_for_test(libc::SIGUSR1)?);
            {
                let guard = block_sigttou_for_current_thread()?;
                assert!(sigttou_is_blocked_for_test()?);
                assert_eq!(format!("{guard:?}"), "SigttouBlockGuard(<active>)");
                set_signal_blocked_for_test(libc::SIGUSR1, false)?;
                assert!(!signal_is_blocked_for_test(libc::SIGUSR1)?);
            }
            assert!(!sigttou_is_blocked_for_test()?);
            assert!(signal_is_blocked_for_test(libc::SIGUSR1)?);
            Ok(())
        })
        .join()
        .map_err(|_| io::Error::other("SIGTTOU scope test thread panicked"))??;
        Ok(())
    }

    #[test]
    fn sigttou_block_nesting_restores_each_exact_prior_state()
    -> Result<(), Box<dyn std::error::Error>> {
        thread::spawn(|| -> io::Result<()> {
            set_sigttou_blocked_for_test(false)?;
            let outer = block_sigttou_for_current_thread()?;
            assert!(sigttou_is_blocked_for_test()?);
            {
                let _inner = block_sigttou_for_current_thread()?;
                assert!(sigttou_is_blocked_for_test()?);
            }
            assert!(sigttou_is_blocked_for_test()?);
            drop(outer);
            assert!(!sigttou_is_blocked_for_test()?);

            set_sigttou_blocked_for_test(true)?;
            {
                let _already_blocked = block_sigttou_for_current_thread()?;
            }
            assert!(sigttou_is_blocked_for_test()?);
            Ok(())
        })
        .join()
        .map_err(|_| io::Error::other("nested SIGTTOU test thread panicked"))??;
        Ok(())
    }

    #[test]
    fn sigttou_block_restores_during_error_and_unwind_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        thread::spawn(|| -> io::Result<()> {
            set_sigttou_blocked_for_test(false)?;
            let failed_scope = (|| -> io::Result<()> {
                let _guard = block_sigttou_for_current_thread()?;
                assert!(sigttou_is_blocked_for_test()?);
                Err(io::Error::other("injected scoped failure"))
            })();
            assert!(failed_scope.is_err());
            assert!(!sigttou_is_blocked_for_test()?);

            let unwound = std::panic::catch_unwind(|| {
                let _guard = match block_sigttou_for_current_thread() {
                    Ok(guard) => guard,
                    Err(error) => panic!("SIGTTOU guard setup failed: {error}"),
                };
                panic!("injected scoped unwind");
            });
            assert!(unwound.is_err());
            assert!(!sigttou_is_blocked_for_test()?);
            Ok(())
        })
        .join()
        .map_err(|_| io::Error::other("SIGTTOU failure test thread panicked"))??;
        Ok(())
    }

    #[test]
    fn sigttou_block_changes_only_the_calling_thread_mask() -> Result<(), Box<dyn std::error::Error>>
    {
        thread::spawn(|| -> io::Result<()> {
            set_sigttou_blocked_for_test(false)?;
            let entered = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            let worker_entered = Arc::clone(&entered);
            let worker_release = Arc::clone(&release);
            let worker = thread::spawn(move || -> io::Result<()> {
                assert!(!sigttou_is_blocked_for_test()?);
                let _guard = block_sigttou_for_current_thread()?;
                assert!(sigttou_is_blocked_for_test()?);
                worker_entered.wait();
                worker_release.wait();
                Ok(())
            });

            entered.wait();
            assert!(!sigttou_is_blocked_for_test()?);
            release.wait();
            worker
                .join()
                .map_err(|_| io::Error::other("SIGTTOU worker thread panicked"))??;
            assert!(!sigttou_is_blocked_for_test()?);
            Ok(())
        })
        .join()
        .map_err(|_| io::Error::other("SIGTTOU locality test thread panicked"))??;
        Ok(())
    }

    #[test]
    fn sigttou_lifo_abort_child_helper() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(SIGTTOU_LIFO_ABORT_HELPER_ENV).is_none() {
            return Ok(());
        }
        let outer = block_sigttou_for_current_thread()?;
        let inner = block_sigttou_for_current_thread()?;
        drop(outer);
        drop(inner);
        Err("out-of-order SIGTTOU guard drop did not abort".into())
    }

    #[test]
    fn sigttou_block_aborts_on_out_of_order_drop() -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "tests::sigttou_lifo_abort_child_helper",
                "--nocapture",
            ])
            .env(SIGTTOU_LIFO_ABORT_HELPER_ENV, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        assert_eq!(status.signal(), Some(libc::SIGABRT));
        Ok(())
    }

    #[test]
    fn invalid_readiness_fd_child_helper() -> Result<(), Box<dyn std::error::Error>> {
        let Some(case) = std::env::var_os(INVALID_READINESS_HELPER_ENV) else {
            return Ok(());
        };
        let case = case.into_string().map_err(|_| "invalid test case")?;
        let error = take_inherited_readiness_fd()
            .err()
            .ok_or("invalid readiness descriptor must fail")?;
        match case.as_str() {
            "missing" => assert_eq!(error.kind(), io::ErrorKind::NotFound),
            "malformed" | "stdio" => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
            _ => return Err("unknown invalid readiness descriptor test case".into()),
        }
        assert!(!format!("{error:?}").contains("credential-sentinel"));
        assert!(!error.to_string().contains("credential-sentinel"));
        Ok(())
    }

    #[test]
    fn readiness_fd_environment_input_is_strict_and_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        for (case, value) in [
            ("missing", None),
            ("malformed", Some("credential-sentinel")),
            ("stdio", Some("1")),
        ] {
            let mut command = Command::new(std::env::current_exe()?);
            command
                .args([
                    "--exact",
                    "tests::invalid_readiness_fd_child_helper",
                    "--nocapture",
                ])
                .env(INVALID_READINESS_HELPER_ENV, case)
                .env_remove(READINESS_FD_ENV);
            if let Some(value) = value {
                command.env(READINESS_FD_ENV, value);
            }
            if !command.status()?.success() {
                return Err(io::Error::other("invalid readiness fd case failed").into());
            }
        }
        Ok(())
    }

    #[test]
    fn inherited_readiness_fd_child_helper() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(TAKE_READINESS_HELPER_ENV).is_none() {
            return Ok(());
        }

        let expected_raw: RawFd = std::env::var(READINESS_FD_ENV)?.parse()?;
        let inherited = take_inherited_readiness_fd()?;
        assert_ne!(inherited.as_raw_fd(), expected_raw);
        assert!(descriptor_flags(expected_raw)? & libc::FD_CLOEXEC != 0);
        assert!(descriptor_flags(inherited.as_raw_fd())? & libc::FD_CLOEXEC != 0);
        assert!(matches!(
            take_inherited_readiness_fd(),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        let identity = descriptor_identity(inherited.as_fd())?;

        let mut grandchild = Command::new(std::env::current_exe()?);
        scrub_readiness_fd_env(&mut grandchild);
        let grandchild_status = grandchild
            .args([
                "--exact",
                "tests::resealed_readiness_fd_is_absent_after_another_exec",
                "--nocapture",
            ])
            .env_remove(TAKE_READINESS_HELPER_ENV)
            .env(RESEALED_GRANDCHILD_HELPER_ENV, "1")
            .env(
                RESEALED_IDENTITY_ENV,
                format!("{}:{}", identity.device, identity.inode),
            )
            .status()?;
        if !grandchild_status.success() {
            return Err(io::Error::other("resealed descriptor leaked across exec").into());
        }

        let mut inherited = UnixStream::from(inherited);
        inherited.write_all(b"R")?;
        inherited.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    #[test]
    fn readiness_take_duplicates_instead_of_adopting_an_existing_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut existing_owner, mut peer) = UnixStream::pair()?;
        let existing_raw = existing_owner.as_raw_fd();
        clear_close_on_exec_in_child(existing_raw)?;

        let inherited = take_inherited_readiness_fd_inner(existing_raw)?;
        assert_ne!(inherited.as_raw_fd(), existing_raw);
        assert_eq!(
            descriptor_identity(inherited.as_fd())?,
            descriptor_identity(existing_owner.as_fd())?
        );
        assert!(descriptor_flags(existing_raw)? & libc::FD_CLOEXEC != 0);
        assert!(descriptor_flags(inherited.as_raw_fd())? & libc::FD_CLOEXEC != 0);

        drop(inherited);
        existing_owner.write_all(b"S")?;
        let mut marker = [0_u8; 1];
        peer.read_exact(&mut marker)?;
        assert_eq!(marker, [b'S']);
        Ok(())
    }

    #[test]
    fn resealed_readiness_fd_is_absent_after_another_exec() -> Result<(), Box<dyn std::error::Error>>
    {
        if std::env::var_os(RESEALED_GRANDCHILD_HELPER_ENV).is_none() {
            return Ok(());
        }
        assert!(std::env::var_os(READINESS_FD_ENV).is_none());
        let identity = std::env::var(RESEALED_IDENTITY_ENV)?;
        let (device, inode) = identity
            .split_once(':')
            .ok_or("resealed descriptor identity was malformed")?;
        let identity = DescriptorIdentity {
            device: device.parse()?,
            inode: inode.parse()?,
        };
        assert_eq!(count_open_descriptors_with_identity(identity)?, 0);
        Ok(())
    }

    #[test]
    fn readiness_fd_is_advertised_dynamically_and_resealed_after_exec()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut observer, inherited) = UnixStream::pair()?;
        observer.set_read_timeout(Some(Duration::from_secs(10)))?;
        assert!(descriptor_flags(inherited.as_raw_fd())? & libc::FD_CLOEXEC != 0);

        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "tests::inherited_readiness_fd_child_helper",
                "--nocapture",
            ])
            .env(TAKE_READINESS_HELPER_ENV, "1");
        let mut child = spawn_with_inherited_readiness_fd(command, inherited.as_fd())?;
        drop(inherited);

        let mut marker = [0_u8; 1];
        observer.read_exact(&mut marker)?;
        assert_eq!(marker, [b'R']);
        let mut trailing = [0_u8; 1];
        assert_eq!(observer.read(&mut trailing)?, 0);
        assert!(child.wait()?.success());
        Ok(())
    }

    #[test]
    fn bounded_identity_scan_counts_regular_files_and_unix_sockets()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "calcifer-fd-identity-test-{}-{nonce}",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        let file_clone = file.try_clone()?;
        let file_identity = descriptor_identity(file.as_fd())?;
        assert_ne!(file_identity.inode, 0);
        assert_eq!(count_open_descriptors_with_identity(file_identity)?, 2);

        let (socket, peer) = UnixStream::pair()?;
        let socket_identity = descriptor_identity(socket.as_fd())?;
        assert_ne!(socket_identity.inode, 0);
        assert_eq!(count_open_descriptors_with_identity(socket_identity)?, 1);

        drop(peer);
        drop(socket);
        drop(file_clone);
        drop(file);
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn descriptor_scan_rejects_a_zero_inode() {
        assert!(matches!(
            count_open_descriptors_with_identity(DescriptorIdentity {
                device: 0,
                inode: 0,
            }),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn descriptor_identity_debug_is_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let (socket, _peer) = UnixStream::pair()?;
        let identity = descriptor_identity(socket.as_fd())?;
        let rendered = format!("{identity:?}");

        assert_eq!(rendered, "DescriptorIdentity(<redacted>)");
        assert!(!rendered.contains(&identity.device.to_string()));
        assert!(!rendered.contains(&identity.inode.to_string()));
        Ok(())
    }

    #[test]
    fn source_descriptor_stays_close_on_exec_during_the_child_callback()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            std::env::temp_dir().join(format!("calcifer-child-fd-{}-{nonce}", std::process::id()));
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        let source_metadata = source.metadata()?;
        let expected_identity = format!("{}:{}", source_metadata.dev(), source_metadata.ino());
        assert!(descriptor_flags(source.as_raw_fd())? & libc::FD_CLOEXEC != 0);

        let (mut ready_parent, ready_child) = UnixStream::pair()?;
        let (mut release_parent, release_child) = UnixStream::pair()?;
        ready_parent.set_read_timeout(Some(Duration::from_secs(10)))?;
        release_parent.set_write_timeout(Some(Duration::from_secs(10)))?;
        let source_ref = &source;
        let test_result = thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
            let worker = scope.spawn(move || {
                let command = Command::new("/usr/bin/true");
                spawn_with_inherited_fd_inner(
                    command,
                    source_ref.as_fd(),
                    true,
                    Some(PreExecBarrier {
                        ready: ready_child.as_raw_fd(),
                        release: release_child.as_raw_fd(),
                    }),
                )
            });

            // Record all observations without returning early: the pre-exec
            // child must always be released and the spawn worker joined before
            // any assertion or error is propagated.
            let observations = (|| -> Result<(), Box<dyn std::error::Error>> {
                let mut ready = [0_u8; 1];
                ready_parent.read_exact(&mut ready)?;
                if ready != [1] {
                    return Err(io::Error::other("pre-exec barrier marker was invalid").into());
                }
                if descriptor_flags(source_ref.as_raw_fd())? & libc::FD_CLOEXEC == 0 {
                    return Err(io::Error::other(
                        "source descriptor became inheritable during pre-exec",
                    )
                    .into());
                }

                // The selected child is paused after changing only its
                // duplicate. An unrelated concurrent spawn therefore still
                // sees no matching descriptor in the parent table.
                let mut unrelated = Command::new(std::env::current_exe()?);
                let unrelated_status = unrelated
                    .args([
                        "--exact",
                        "tests::unrelated_exec_has_no_inherited_test_descriptor",
                        "--nocapture",
                    ])
                    .env("CALCIFER_TEST_CHILD_FD_IDENTITY", &expected_identity)
                    .status()?;
                if !unrelated_status.success() {
                    return Err(io::Error::other(
                        "unrelated exec inherited the child-only descriptor",
                    )
                    .into());
                }
                if descriptor_flags(source_ref.as_raw_fd())? & libc::FD_CLOEXEC == 0 {
                    return Err(io::Error::other(
                        "source descriptor became inheritable after concurrent exec",
                    )
                    .into());
                }
                Ok(())
            })();

            let release_result = release_parent.write_all(&[1]);
            drop(release_parent);
            let worker_result = worker.join();
            let child_result = match worker_result {
                Ok(Ok(mut child)) => child.wait(),
                Ok(Err(error)) => Err(collapse_spawn_error(error)),
                Err(_) => Err(io::Error::other("spawn worker panicked")),
            };

            observations?;
            release_result?;
            if !child_result?.success() {
                return Err(io::Error::other("selected child exited unsuccessfully").into());
            }
            Ok(())
        });

        drop(source);
        let cleanup_result = fs::remove_file(path);
        test_result?;
        cleanup_result?;
        Ok(())
    }

    #[test]
    fn readiness_spawn_returns_started_child_authority_after_parent_readback_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let (source, _peer) = UnixStream::pair()?;
        let source_ref = &source;
        assert!(descriptor_flags(source.as_raw_fd())? & libc::FD_CLOEXEC != 0);

        let (mut ready_parent, ready_child) = UnixStream::pair()?;
        let (mut release_parent, release_child) = UnixStream::pair()?;
        ready_parent.set_read_timeout(Some(Duration::from_secs(10)))?;
        release_parent.set_write_timeout(Some(Duration::from_secs(10)))?;

        thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
            let worker = scope.spawn(move || {
                let mut command = Command::new("/bin/sleep");
                command.arg("5");
                spawn_with_inherited_fd_inner(
                    command,
                    source_ref.as_fd(),
                    true,
                    Some(PreExecBarrier {
                        ready: ready_child.as_raw_fd(),
                        release: release_child.as_raw_fd(),
                    }),
                )
            });

            let mutation = (|| -> io::Result<()> {
                let mut ready = [0_u8; 1];
                ready_parent.read_exact(&mut ready)?;
                if ready != [1] {
                    return Err(io::Error::other("pre-exec barrier marker was invalid"));
                }
                clear_close_on_exec_in_child(source_ref.as_raw_fd())
            })();
            let release = release_parent.write_all(&[1]);
            drop(release_parent);
            let worker_result = worker.join();

            let current_flags = descriptor_flags(source_ref.as_raw_fd())?;
            set_close_on_exec(source_ref.as_raw_fd(), current_flags)?;
            mutation?;
            release?;

            let failure = match worker_result {
                Ok(Err(failure)) => failure,
                Ok(Ok(mut child)) => {
                    terminate_spawned_child(&mut child);
                    return Err("parent readback mutation did not fail the spawn".into());
                }
                Err(_) => return Err("spawn worker panicked".into()),
            };
            assert!(failure.child_started());
            assert_eq!(
                format!("{failure:?}"),
                "InheritedFdSpawnError { child_started: true }"
            );

            let started_child = failure
                .into_started_child()
                .ok_or("started child authority was missing")?;
            let mut child = started_child.into_child();
            assert!(terminate_spawned_child(&mut child));
            Ok(())
        })
    }

    #[test]
    fn unrelated_exec_has_no_inherited_test_descriptor() -> Result<(), Box<dyn std::error::Error>> {
        let Some(expected) = std::env::var_os("CALCIFER_TEST_CHILD_FD_IDENTITY") else {
            return Ok(());
        };
        let expected = expected
            .into_string()
            .map_err(|_| "test descriptor identity must be UTF-8")?;
        #[cfg(target_os = "linux")]
        let descriptor_directory = std::path::Path::new("/proc/self/fd");
        #[cfg(target_os = "macos")]
        let descriptor_directory = std::path::Path::new("/dev/fd");

        let descriptor_paths = fs::read_dir(descriptor_directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        for descriptor_path in descriptor_paths {
            #[cfg(target_os = "linux")]
            let metadata = fs::metadata(descriptor_path);
            #[cfg(target_os = "macos")]
            let metadata = OpenOptions::new()
                .read(true)
                .open(descriptor_path)
                .and_then(|descriptor| descriptor.metadata());
            match metadata {
                Ok(metadata) => assert_ne!(
                    format!("{}:{}", metadata.dev(), metadata.ino()),
                    expected,
                    "an unrelated exec inherited the child-only descriptor"
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EBADF | libc::EACCES | libc::EPERM | libc::ENXIO)
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
