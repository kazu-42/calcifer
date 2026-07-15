//! Minimal safe wrapper for descriptor-bound macOS extended ACL access.
//!
//! Calcifer keeps this FFI boundary in a separate crate so the main binary can
//! continue to forbid unsafe Rust. The wrapper intentionally exposes only the
//! raw policy bits Calcifer needs; it does not resolve ACL principals.

#![cfg(target_os = "macos")]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;

/// An ACL entry that preserves every native tag, flag, and permission bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Native entry tag (`TAG_ALLOW`, `TAG_DENY`, or an unknown value).
    pub tag: u32,
    /// Native entry flags, excluding the low tag bits.
    pub flags: u32,
    /// Native permission mask, including unknown future bits.
    pub permissions: u32,
}

/// An extended ACL copied from one open vnode.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Acl {
    /// Native ACL-level flags, including private or unknown future bits.
    pub flags: u32,
    /// Ordered native ACL entries.
    pub entries: Vec<Entry>,
}

impl Acl {
    /// Returns true only when neither ACL-level flags nor entries are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flags == 0 && self.entries.is_empty()
    }
}

/// Native macOS extended ACL tag for an ALLOW entry.
pub const TAG_ALLOW: u32 = 1;
/// Native macOS extended ACL tag for a DENY entry.
pub const TAG_DENY: u32 = 2;
/// Native entry flag indicating that the entry was inherited.
pub const FLAG_INHERITED: u32 = 1 << 4;
/// Native permission for deleting the node carrying an entry.
pub const PERMISSION_DELETE: u32 = 1 << 4;

const ACL_TYPE_EXTENDED: c_int = 0x100;
const ACL_MAX_ENTRIES: usize = 128;
const KAUTH_FILESEC_MAGIC: u32 = 0x012c_c16d;
const KAUTH_ACE_KIND_MASK: u32 = 0xf;

// Native `kauth_filesec` is 44 bytes before its variable-length ACE array:
// magic (4), owner GUID (16), group GUID (16), count (4), ACL flags (4).
const HEADER_WORDS: usize = 11;
// Native `kauth_ace` is six u32 words: GUID (4), flags/tag (1), rights (1).
const ENTRY_WORDS: usize = 6;
const ENTRY_COUNT_WORD: usize = 9;
const ACL_FLAGS_WORD: usize = 10;
const ENTRY_FLAGS_WORD: usize = 4;
const ENTRY_PERMISSIONS_WORD: usize = 5;

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
    fn acl_init(count: c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: c_int, acl: *mut c_void, acl_type: c_int) -> c_int;
    fn acl_size(acl: *mut c_void) -> isize;
    fn acl_copy_ext_native(buffer: *mut c_void, acl: *mut c_void, size: isize) -> isize;
    fn acl_free(object: *mut c_void) -> c_int;
}

struct AclHandle {
    pointer: Option<NonNull<c_void>>,
}

impl AclHandle {
    fn from_pointer(pointer: *mut c_void) -> Option<Self> {
        NonNull::new(pointer).map(|pointer| Self {
            pointer: Some(pointer),
        })
    }

    fn pointer(&self) -> *mut c_void {
        self.pointer.map_or(std::ptr::null_mut(), NonNull::as_ptr)
    }

    fn free(mut self) -> io::Result<()> {
        let Some(pointer) = self.pointer.take() else {
            return Ok(());
        };
        // SAFETY: `pointer` came from an ACL allocation function and ownership
        // is consumed exactly once by taking it out of `self.pointer`.
        let result = unsafe { acl_free(pointer.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for AclHandle {
    fn drop(&mut self) {
        let Some(pointer) = self.pointer.take() else {
            return;
        };
        // SAFETY: `pointer` came from an ACL allocation function and this Drop
        // runs only while ownership is still present in `self.pointer`.
        let _ = unsafe { acl_free(pointer.as_ptr()) };
    }
}

/// Reads the extended ACL attached to the vnode referenced by `descriptor`.
///
/// A missing ACL is returned as an empty value. Any other native error, an
/// unsupported entry count, or a malformed external representation fails.
pub fn read_acl(descriptor: BorrowedFd<'_>) -> io::Result<Acl> {
    // SAFETY: `BorrowedFd` guarantees that the descriptor remains valid for
    // this call, and `ACL_TYPE_EXTENDED` is the documented macOS ACL type.
    let pointer = unsafe { acl_get_fd_np(descriptor.as_raw_fd(), ACL_TYPE_EXTENDED) };
    let Some(handle) = AclHandle::from_pointer(pointer) else {
        let error = io::Error::last_os_error();
        // Apple Libc reports ENOENT when the already-valid vnode has no ACL.
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(Acl::default())
        } else {
            Err(error)
        };
    };

    let result = copy_acl(&handle);
    let free_result = handle.free();
    match result {
        Ok(acl) => {
            free_result?;
            Ok(acl)
        }
        Err(error) => Err(error),
    }
}

/// Removes every extended ACL entry and ACL-level flag from an open vnode.
pub fn clear_acl(descriptor: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: zero is a valid documented capacity and the returned allocation
    // is immediately wrapped in unique RAII ownership.
    let pointer = unsafe { acl_init(0) };
    let Some(handle) = AclHandle::from_pointer(pointer) else {
        return Err(io::Error::last_os_error());
    };

    // SAFETY: both the borrowed descriptor and ACL allocation remain valid for
    // the duration of this synchronous call.
    let result =
        unsafe { acl_set_fd_np(descriptor.as_raw_fd(), handle.pointer(), ACL_TYPE_EXTENDED) };
    let operation_error = (result != 0).then(io::Error::last_os_error);
    let free_result = handle.free();
    if let Some(error) = operation_error {
        return Err(error);
    }
    free_result
}

fn copy_acl(handle: &AclHandle) -> io::Result<Acl> {
    // SAFETY: the handle owns a valid ACL pointer for this call.
    let native_size = unsafe { acl_size(handle.pointer()) };
    let byte_count =
        usize::try_from(native_size).map_err(|_| invalid_acl("native ACL size is invalid"))?;
    let maximum_bytes = (HEADER_WORDS + ACL_MAX_ENTRIES * ENTRY_WORDS)
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or_else(|| invalid_acl("native ACL size overflowed"))?;
    if byte_count < HEADER_WORDS * std::mem::size_of::<u32>()
        || byte_count > maximum_bytes
        || byte_count % std::mem::size_of::<u32>() != 0
    {
        return Err(invalid_acl("native ACL size is out of bounds"));
    }

    // A u32 buffer provides the alignment required by `kauth_filesec` while
    // preserving the exact native byte count returned by Libc.
    let mut words = vec![0_u32; byte_count / std::mem::size_of::<u32>()];
    // SAFETY: `words` is writable for exactly `byte_count` bytes, correctly
    // aligned, and `handle` remains alive throughout the copy.
    let copied = unsafe {
        acl_copy_ext_native(
            words.as_mut_ptr().cast::<c_void>(),
            handle.pointer(),
            native_size,
        )
    };
    if copied != native_size {
        return Err(if copied < 0 {
            io::Error::last_os_error()
        } else {
            invalid_acl("native ACL copy returned a partial value")
        });
    }
    parse_native_words(&words)
}

fn parse_native_words(words: &[u32]) -> io::Result<Acl> {
    if words.len() < HEADER_WORDS || words[0] != KAUTH_FILESEC_MAGIC {
        return Err(invalid_acl("native ACL header is invalid"));
    }
    let entry_count = usize::try_from(words[ENTRY_COUNT_WORD])
        .map_err(|_| invalid_acl("native ACL entry count is invalid"))?;
    if entry_count > ACL_MAX_ENTRIES {
        return Err(invalid_acl("native ACL has too many entries"));
    }
    let expected_words = HEADER_WORDS
        .checked_add(
            entry_count
                .checked_mul(ENTRY_WORDS)
                .ok_or_else(|| invalid_acl("native ACL entry count overflowed"))?,
        )
        .ok_or_else(|| invalid_acl("native ACL size overflowed"))?;
    if words.len() != expected_words {
        return Err(invalid_acl(
            "native ACL size does not match its entry count",
        ));
    }

    let mut entries = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let base = HEADER_WORDS + index * ENTRY_WORDS;
        let combined_flags = words[base + ENTRY_FLAGS_WORD];
        entries.push(Entry {
            tag: combined_flags & KAUTH_ACE_KIND_MASK,
            flags: combined_flags & !KAUTH_ACE_KIND_MASK,
            permissions: words[base + ENTRY_PERMISSIONS_WORD],
        });
    }
    Ok(Acl {
        flags: words[ACL_FLAGS_WORD],
        entries,
    })
}

fn invalid_acl(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_preserves_unknown_policy_bits() -> io::Result<()> {
        let mut words = vec![0_u32; HEADER_WORDS + ENTRY_WORDS];
        words[0] = KAUTH_FILESEC_MAGIC;
        words[ENTRY_COUNT_WORD] = 1;
        words[ACL_FLAGS_WORD] = 1 << 31;
        words[HEADER_WORDS + ENTRY_FLAGS_WORD] = TAG_DENY | FLAG_INHERITED | (1 << 30);
        words[HEADER_WORDS + ENTRY_PERMISSIONS_WORD] = PERMISSION_DELETE | (1 << 31);

        let acl = parse_native_words(&words)?;
        assert_eq!(acl.flags, 1 << 31);
        assert_eq!(
            acl.entries,
            [Entry {
                tag: TAG_DENY,
                flags: FLAG_INHERITED | (1 << 30),
                permissions: PERMISSION_DELETE | (1 << 31),
            }]
        );
        Ok(())
    }

    #[test]
    fn parser_rejects_inconsistent_entry_count() {
        let mut words = vec![0_u32; HEADER_WORDS];
        words[0] = KAUTH_FILESEC_MAGIC;
        words[ENTRY_COUNT_WORD] = 1;
        let error = parse_native_words(&words).err();
        assert!(error.is_some_and(|error| error.kind() == io::ErrorKind::InvalidData));
    }
}
