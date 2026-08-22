//! Minimal safe wrapper for handle-bound Windows DACL create/validate.
//!
//! Calcifer keeps this FFI boundary in a separate crate so the main binary can
//! continue to forbid unsafe Rust. The contract is current-user-only, protected
//! (no inherited ACEs), and fail-closed on unknown policy bits.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use std::ptr::{self, NonNull};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, FALSE, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, AclSizeInformation, CopySid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED, TOKEN_QUERY, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const INHERITED_ACE: u8 = 0x10;
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

#[repr(C)]
struct AclSizeInfo {
    acl_bytes_in_use: u32,
    acl_bytes_free: u32,
    ace_count: u32,
    acl_revision: u32,
}

#[repr(C)]
struct AceHeader {
    ace_type: u8,
    ace_flags: u8,
    ace_size: u16,
}

#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[repr(C)]
struct TokenUserLayout {
    user: SidAndAttributes,
}

struct LocalPtr {
    pointer: Option<NonNull<c_void>>,
}

impl LocalPtr {
    fn from_raw(pointer: *mut c_void) -> Option<Self> {
        NonNull::new(pointer).map(|pointer| Self {
            pointer: Some(pointer),
        })
    }

    fn as_ptr(&self) -> *mut c_void {
        self.pointer.map_or(ptr::null_mut(), NonNull::as_ptr)
    }
}

impl Drop for LocalPtr {
    fn drop(&mut self) {
        if let Some(pointer) = self.pointer.take() {
            unsafe {
                let _ = LocalFree(pointer.as_ptr() as _);
            }
        }
    }
}

struct HandleGuard {
    handle: HANDLE,
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

struct SidBuffer {
    bytes: Vec<u8>,
}

impl SidBuffer {
    fn as_ptr(&self) -> *mut c_void {
        self.bytes.as_ptr().cast::<c_void>().cast_mut()
    }
}

/// Apply a protected current-user-only DACL to an already-opened node.
pub fn apply_current_user_only(handle: BorrowedHandle<'_>) -> io::Result<()> {
    let sddl = current_user_only_sddl()?;
    let mut descriptor: *mut c_void = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(&sddl).as_ptr(),
            u32::from(SDDL_REVISION_1),
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == FALSE {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalPtr::from_raw(descriptor).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "windows current-user ACL descriptor was empty",
        )
    })?;
    let mut owner: *mut c_void = ptr::null_mut();
    let mut owner_defaulted = FALSE;
    let got_owner = unsafe {
        GetSecurityDescriptorOwner(descriptor.as_ptr(), &mut owner, &mut owner_defaulted)
    };
    if got_owner == FALSE || owner.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "windows current-user ACL owner was missing",
        ));
    }
    let mut dacl_present = FALSE;
    let mut dacl_defaulted = FALSE;
    let mut dacl: *mut ACL = ptr::null_mut();
    let got_dacl = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_ptr(),
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if got_dacl == FALSE || dacl_present == FALSE || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "windows current-user DACL was missing",
        ));
    }
    let status = unsafe {
        SetSecurityInfo(
            handle.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    verify_current_user_only(handle)
}

/// Revalidate that an open node is still current-user-only and protected.
pub fn verify_current_user_only(handle: BorrowedHandle<'_>) -> io::Result<()> {
    let expected = current_user_sid()?;
    let mut owner: *mut c_void = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut security: *mut c_void = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut security,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let security = LocalPtr::from_raw(security).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "windows security descriptor was empty",
        )
    })?;
    if owner.is_null() || unsafe { EqualSid(owner, expected.as_ptr()) } == FALSE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path is not owned by the current user",
        ));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let control_ok =
        unsafe { GetSecurityDescriptorControl(security.as_ptr(), &mut control, &mut revision) };
    if control_ok == FALSE || control & SE_DACL_PROTECTED == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path DACL is not protected from inheritance",
        ));
    }
    if dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path DACL is missing",
        ));
    }
    verify_single_current_user_allow_ace(dacl, expected.as_ptr())
}

fn verify_single_current_user_allow_ace(
    dacl: *mut ACL,
    expected_sid: *mut c_void,
) -> io::Result<()> {
    let mut size_info = AclSizeInfo {
        acl_bytes_in_use: 0,
        acl_bytes_free: 0,
        ace_count: 0,
        acl_revision: 0,
    };
    let info_size = u32::try_from(size_of::<AclSizeInfo>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "windows ACL size information overflowed",
        )
    })?;
    let got_size = unsafe {
        GetAclInformation(
            dacl,
            ptr::from_mut(&mut size_info).cast(),
            info_size,
            AclSizeInformation,
        )
    };
    if got_size == FALSE || size_info.ace_count != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path DACL is not a single current-user allow entry",
        ));
    }
    let mut ace: *mut c_void = ptr::null_mut();
    let got_ace = unsafe { GetAce(dacl, 0, &mut ace) };
    if got_ace == FALSE || ace.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path DACL entry was unreadable",
        ));
    }
    let header = unsafe { ace.cast::<AceHeader>().as_ref() }.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path DACL entry header was unreadable",
        )
    })?;
    if header.ace_type != ACCESS_ALLOWED_ACE_TYPE || header.ace_flags != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path DACL admits inherited or unknown policy bits",
        ));
    }
    let mask = unsafe { ace.cast::<u32>().add(1).read_unaligned() };
    // SDDL `FA` may be stored as GENERIC_ALL or as mapped FILE_ALL_ACCESS.
    const GENERIC_ALL: u32 = 0x1000_0000;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    let has_owner_control = mask == GENERIC_ALL
        || mask == FILE_ALL_ACCESS
        || mask & (DELETE | WRITE_DAC | READ_CONTROL) == (DELETE | WRITE_DAC | READ_CONTROL);
    if !has_owner_control {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path DACL grant is not current-user FILE_ALL_ACCESS",
        ));
    }
    let sid = unsafe { ace.cast::<u8>().add(8).cast::<c_void>() };
    if unsafe { EqualSid(sid, expected_sid) } == FALSE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path DACL principal is not the current user",
        ));
    }
    let _ = INHERITED_ACE;
    Ok(())
}

fn current_user_only_sddl() -> io::Result<String> {
    let sid = current_user_sid_string()?;
    Ok(format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})"))
}

fn current_user_sid_string() -> io::Result<String> {
    let sid = current_user_sid()?;
    let mut string_sid: windows_sys::core::PWSTR = ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(sid.as_ptr(), &mut string_sid) };
    if converted == FALSE {
        return Err(io::Error::last_os_error());
    }
    let _guard = LocalPtr::from_raw(string_sid.cast());
    let mut len = 0_usize;
    loop {
        let unit = unsafe { *string_sid.add(len) };
        if unit == 0 {
            break;
        }
        len = len.saturating_add(1);
        if len > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "windows SID string was unbounded",
            ));
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(string_sid, len) };
    String::from_utf16(slice).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "windows SID string was not UTF-16",
        )
    })
}

fn current_user_sid() -> io::Result<SidBuffer> {
    let mut token: HANDLE = ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == FALSE {
        return Err(io::Error::last_os_error());
    }
    let _token = HandleGuard { handle: token };
    let mut required = 0_u32;
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut required);
    }
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0_u8; required as usize];
    let got = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    if got == FALSE {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { buffer.as_ptr().cast::<TokenUserLayout>().as_ref() }.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "windows token user was unreadable",
        )
    })?;
    if user.user.sid.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "windows token user SID was empty",
        ));
    }
    let sid_length = unsafe { GetLengthSid(user.user.sid) };
    if sid_length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sid_bytes = vec![0_u8; sid_length as usize];
    let copied = unsafe { CopySid(sid_length, sid_bytes.as_mut_ptr().cast(), user.user.sid) };
    if copied == FALSE {
        return Err(io::Error::last_os_error());
    }
    Ok(SidBuffer { bytes: sid_bytes })
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::windows::io::AsHandle;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "calcifer-windows-acl-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn apply_and_verify_round_trip_on_a_new_file() -> io::Result<()> {
        let path = temp_path("round-trip");
        fs::write(&path, b"calcifer-windows-acl")?;
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        apply_current_user_only(file.as_handle())?;
        verify_current_user_only(file.as_handle())?;
        fs::remove_file(&path)?;
        Ok(())
    }

    #[test]
    fn verify_rejects_an_unprotected_inherited_dacl() -> io::Result<()> {
        let path = temp_path("inherited");
        fs::write(&path, b"calcifer-windows-acl")?;
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        let error = verify_current_user_only(file.as_handle()).expect_err(
            "a default NTFS DACL must not already be a protected current-user-only ACL",
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        fs::remove_file(&path)?;
        Ok(())
    }
}
