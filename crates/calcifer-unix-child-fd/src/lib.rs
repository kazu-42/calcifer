//! Minimal child-only Unix descriptor inheritance for Calcifer.
//!
//! The main crate forbids unsafe Rust. This crate contains the one audited
//! `pre_exec` boundary needed to preserve an already-open lease descriptor in
//! one selected child without ever clearing `FD_CLOEXEC` in the multithreaded
//! parent process.

#![cfg(unix)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

const MAX_DESCRIPTOR_SCAN_ENTRIES: usize = 4_096;

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
    {
        spawn_with_inherited_fd_inner(command, descriptor, None)
    }
    #[cfg(not(test))]
    {
        spawn_with_inherited_fd_inner(command, descriptor)
    }
}

fn spawn_with_inherited_fd_inner(
    mut command: Command,
    descriptor: BorrowedFd<'_>,
    #[cfg(test)] pre_exec_barrier: Option<PreExecBarrier>,
) -> io::Result<Child> {
    let source_descriptor = descriptor.as_raw_fd();
    let parent_flags = descriptor_flags(source_descriptor)?;
    if parent_flags & libc::FD_CLOEXEC == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inherited descriptor is not close-on-exec in the parent",
        ));
    }

    // Duplicate atomically with close-on-exec and keep the child-facing number
    // outside the standard streams. Rust configures stdio before `pre_exec`, so
    // passing source fd 0, 1, or 2 directly could otherwise be overwritten.
    let child_descriptor = duplicate_for_child(source_descriptor)?;
    let child_raw_descriptor = child_descriptor.as_raw_fd();

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

    let mut child = command.spawn()?;
    let parent_source_flags = descriptor_flags(source_descriptor);
    let parent_child_flags = descriptor_flags(child_raw_descriptor);
    drop(child_descriptor);
    match (parent_source_flags, parent_child_flags) {
        (Ok(source_flags), Ok(child_flags))
            if source_flags & libc::FD_CLOEXEC != 0 && child_flags & libc::FD_CLOEXEC != 0 =>
        {
            Ok(child)
        }
        (Ok(_), Ok(_)) => {
            terminate_spawned_child(&mut child);
            Err(io::Error::other(
                "child spawn changed the parent descriptor inheritance flag",
            ))
        }
        (Err(error), _) | (_, Err(error)) => {
            terminate_spawned_child(&mut child);
            Err(error)
        }
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

fn terminate_spawned_child(child: &mut Child) {
    let _ = child.kill();
    loop {
        match child.wait() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Ok(_) | Err(_) => return,
        }
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
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
                Ok(Err(error)) => Err(error),
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
