//! Minimal safe wrapper for handle-bound Windows DACL create/validate.
//!
//! Calcifer keeps this FFI boundary in a separate crate so the main binary can
//! continue to forbid unsafe Rust. The contract is current-user-only, protected
//! (no inherited ACEs), and fail-closed on unknown policy bits.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{
    AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle, RawHandle,
};
use std::ptr::{self, NonNull};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::NtCreateFile;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, FALSE, HANDLE, LocalFree, UNICODE_STRING,
};
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
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FULL_DIR_INFO, FileDispositionInfo, FileDispositionInfoEx,
    FileFullDirectoryInfo, FileFullDirectoryRestartInfo, FlushFileBuffers,
    GetFileInformationByHandle, GetFileInformationByHandleEx, SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const INHERITED_ACE: u8 = 0x10;
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const OBJ_DONT_REPARSE: u32 = 0x0000_1000;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000D_u32 as i32;
const STATUS_REPARSE_POINT_ENCOUNTERED: i32 = 0xC000_0280_u32 as i32;
const ERROR_NO_MORE_FILES: i32 = 18;
const ERROR_MORE_DATA: i32 = 234;
const FILE_DISPOSITION_FLAG_DELETE: u32 = 0x0000_0001;
const FILE_DISPOSITION_FLAG_POSIX_SEMANTICS: u32 = 0x0000_0002;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

/// Volume serial, file index, attributes, and link count for an open node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenedIdentity {
    pub volume_serial: u64,
    pub file_index: u64,
    pub attributes: u32,
    pub link_count: u32,
    pub file_size: u64,
}

impl OpenedIdentity {
    pub const fn is_directory(self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    pub const fn is_reparse_point(self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
}

#[repr(C)]
struct AclSizeInfo {
    ace_count: u32,
    acl_bytes_in_use: u32,
    acl_bytes_free: u32,
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

/// Returns `(volume serial, file index)` for an open node.
pub fn volume_file_identity(handle: BorrowedHandle<'_>) -> io::Result<(u64, u64)> {
    let identity = inspect(handle)?;
    Ok((identity.volume_serial, identity.file_index))
}

/// Reads handle-bound identity without following a reparse point that is already open.
pub fn inspect(handle: BorrowedHandle<'_>) -> io::Result<OpenedIdentity> {
    let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    let ok = unsafe { GetFileInformationByHandle(handle.as_raw_handle() as HANDLE, &mut info) };
    if ok == FALSE {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok(OpenedIdentity {
        volume_serial: u64::from(info.dwVolumeSerialNumber),
        file_index: index,
        attributes: info.dwFileAttributes,
        link_count: info.nNumberOfLinks,
        file_size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
    })
}

/// Flushes metadata for an open directory or file handle.
pub fn flush(handle: BorrowedHandle<'_>) -> io::Result<()> {
    let ok = unsafe { FlushFileBuffers(handle.as_raw_handle() as HANDLE) };
    if ok == FALSE {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Opens `name` relative to an already-opened parent without following reparse points.
pub fn open_nofollow_child(
    parent: BorrowedHandle<'_>,
    name: &OsStr,
    directory: bool,
) -> io::Result<File> {
    validate_relative_child_name(name)?;
    let wide: Vec<u16> = name.encode_wide().collect();
    let byte_len = u16::try_from(wide.len().saturating_mul(2)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "windows relative name is too long",
        )
    })?;
    let mut object_name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: wide.as_ptr().cast_mut(),
    };
    let mut handle = ptr::null_mut();
    let mut io_status = IO_STATUS_BLOCK::default();
    let create_options = if directory {
        FILE_DIRECTORY_FILE
            | FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_OPEN_FOR_BACKUP_INTENT
            | FILE_OPEN_REPARSE_POINT
    } else {
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT
    };
    let access = GENERIC_READ | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let mut status = nt_create_relative(
        parent,
        &mut object_name,
        OBJ_DONT_REPARSE,
        access,
        share,
        create_options,
        &mut handle,
        &mut io_status,
    );
    if status == STATUS_INVALID_PARAMETER {
        handle = ptr::null_mut();
        io_status = IO_STATUS_BLOCK::default();
        status = nt_create_relative(
            parent,
            &mut object_name,
            0,
            access,
            share,
            create_options,
            &mut handle,
            &mut io_status,
        );
    }
    if status == STATUS_REPARSE_POINT_ENCOUNTERED {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path is a reparse point",
        ));
    }
    if status < 0 {
        return Err(ntstatus_error(status));
    }
    let file = owned_file(handle)?;
    let identity = inspect(file.as_handle())?;
    if identity.is_reparse_point() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path is a reparse point",
        ));
    }
    if directory != identity.is_directory() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed path type changed during relative open",
        ));
    }
    Ok(file)
}

/// One child observed through an already-opened directory handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: OsString,
    pub attributes: u32,
}

impl DirectoryEntry {
    pub const fn is_directory(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    pub const fn is_reparse_point(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
}

/// Lists children through an already-opened directory handle.
pub fn read_directory_entries(parent: BorrowedHandle<'_>) -> io::Result<Vec<DirectoryEntry>> {
    let mut entries = Vec::new();
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut class = FileFullDirectoryRestartInfo;
    loop {
        let ok = unsafe {
            GetFileInformationByHandleEx(
                parent.as_raw_handle() as HANDLE,
                class,
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "windows directory listing overflowed",
                    )
                })?,
            )
        };
        if ok == FALSE {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(ERROR_NO_MORE_FILES) => break,
                Some(ERROR_MORE_DATA) if buffer.len() < 256 * 1024 => {
                    buffer.resize(buffer.len().saturating_mul(2), 0);
                    class = FileFullDirectoryRestartInfo;
                    entries.clear();
                    continue;
                }
                _ => return Err(error),
            }
        }
        append_directory_entries(&buffer, &mut entries)?;
        class = FileFullDirectoryInfo;
    }
    Ok(entries)
}

/// Marks an opened node for deletion without following a reparse target.
pub fn mark_for_delete(handle: BorrowedHandle<'_>) -> io::Result<()> {
    #[repr(C)]
    struct DispositionEx {
        flags: u32,
    }
    let mut posix = DispositionEx {
        flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    let posix_ok = unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle() as HANDLE,
            FileDispositionInfoEx,
            ptr::from_mut(&mut posix).cast(),
            size_of::<DispositionEx>() as u32,
        )
    };
    if posix_ok != FALSE {
        return Ok(());
    }
    #[repr(C)]
    struct Disposition {
        delete_file: u8,
    }
    let mut basic = Disposition { delete_file: 1 };
    let ok = unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            ptr::from_mut(&mut basic).cast(),
            size_of::<Disposition>() as u32,
        )
    };
    if ok == FALSE {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn nt_create_relative(
    parent: BorrowedHandle<'_>,
    object_name: &mut UNICODE_STRING,
    attributes: u32,
    access: u32,
    share: u32,
    create_options: u32,
    handle: &mut HANDLE,
    io_status: &mut IO_STATUS_BLOCK,
) -> i32 {
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: object_name,
        Attributes: attributes,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    unsafe {
        NtCreateFile(
            handle,
            access,
            &object_attributes,
            io_status,
            ptr::null(),
            0,
            share,
            FILE_OPEN,
            create_options,
            ptr::null(),
            0,
        )
    }
}

fn owned_file(handle: HANDLE) -> io::Result<File> {
    if handle.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "windows relative open returned an empty handle",
        ));
    }
    Ok(File::from(unsafe {
        OwnedHandle::from_raw_handle(handle as RawHandle)
    }))
}

fn ntstatus_error(status: i32) -> io::Error {
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

fn validate_relative_child_name(name: &OsStr) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "windows relative name is reserved",
        ));
    }
    if name
        .encode_wide()
        .any(|unit| unit == 0 || unit == u16::from(b'\\') || unit == u16::from(b'/'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "windows relative name is not a single component",
        ));
    }
    Ok(())
}

fn append_directory_entries(buffer: &[u8], entries: &mut Vec<DirectoryEntry>) -> io::Result<()> {
    let mut offset = 0_usize;
    loop {
        let next_entry_offset = read_u32_at(buffer, offset)?;
        let attributes = read_u32_at(
            buffer,
            offset
                .checked_add(std::mem::offset_of!(FILE_FULL_DIR_INFO, FileAttributes))
                .ok_or_else(directory_listing_overflow)?,
        )?;
        let name_len_offset = offset
            .checked_add(std::mem::offset_of!(FILE_FULL_DIR_INFO, FileNameLength))
            .ok_or_else(directory_listing_overflow)?;
        let name_bytes = usize::try_from(read_u32_at(buffer, name_len_offset)?)
            .map_err(|_| directory_listing_overflow())?;
        if name_bytes % 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "windows directory listing name was not UTF-16",
            ));
        }
        let name_start = offset
            .checked_add(std::mem::offset_of!(FILE_FULL_DIR_INFO, FileName))
            .ok_or_else(directory_listing_overflow)?;
        let name_end = name_start
            .checked_add(name_bytes)
            .ok_or_else(directory_listing_overflow)?;
        if name_start % 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "windows directory listing name was unaligned",
            ));
        }
        let name_slice = buffer.get(name_start..name_end).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "windows directory listing name was truncated",
            )
        })?;
        let units = unsafe {
            std::slice::from_raw_parts(name_slice.as_ptr().cast::<u16>(), name_bytes / 2)
        };
        let name = OsString::from_wide(units);
        if name != "." && name != ".." {
            entries.push(DirectoryEntry { name, attributes });
        }
        if next_entry_offset == 0 {
            return Ok(());
        }
        let next = offset
            .checked_add(
                usize::try_from(next_entry_offset).map_err(|_| directory_listing_overflow())?,
            )
            .ok_or_else(directory_listing_overflow)?;
        if next <= offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "windows directory listing was not advancing",
            ));
        }
        offset = next;
    }
}

fn directory_listing_overflow() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "windows directory listing overflowed",
    )
}

fn read_u32_at(buffer: &[u8], offset: usize) -> io::Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(directory_listing_overflow)?;
    let bytes: [u8; 4] = buffer
        .get(offset..end)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "windows directory listing was truncated",
            )
        })?
        .try_into()
        .map_err(|_| directory_listing_overflow())?;
    Ok(u32::from_le_bytes(bytes))
}

fn verify_single_current_user_allow_ace(
    dacl: *mut ACL,
    expected_sid: *mut c_void,
) -> io::Result<()> {
    let mut size_info = AclSizeInfo {
        ace_count: 0,
        acl_bytes_in_use: 0,
        acl_bytes_free: 0,
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
    use std::ffi::OsStr;
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

    fn open_with_acl_rights(path: &std::path::Path) -> io::Result<std::fs::File> {
        use std::os::windows::fs::OpenOptionsExt;

        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const WRITE_DAC: u32 = 0x0004_0000;
        const WRITE_OWNER: u32 = 0x0008_0000;
        OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
            .open(path)
    }

    #[test]
    fn apply_and_verify_round_trip_on_a_new_file() -> io::Result<()> {
        let path = temp_path("round-trip");
        fs::write(&path, b"calcifer-windows-acl")?;
        let file = open_with_acl_rights(&path)?;
        apply_current_user_only(file.as_handle())?;
        verify_current_user_only(file.as_handle())?;
        fs::remove_file(&path)?;
        Ok(())
    }

    #[test]
    fn verify_rejects_an_unprotected_inherited_dacl() -> io::Result<()> {
        let path = temp_path("inherited");
        fs::write(&path, b"calcifer-windows-acl")?;
        let file = open_with_acl_rights(&path)?;
        let error = verify_current_user_only(file.as_handle()).expect_err(
            "a default NTFS DACL must not already be a protected current-user-only ACL",
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        fs::remove_file(&path)?;
        Ok(())
    }

    fn apply_sddl(handle: BorrowedHandle<'_>, sddl: &str) -> io::Result<()> {
        let mut descriptor: *mut c_void = ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                u32::from(SDDL_REVISION_1),
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if converted == FALSE {
            return Err(io::Error::last_os_error());
        }
        let descriptor = LocalPtr::from_raw(descriptor).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "test SDDL descriptor was empty")
        })?;
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
        if got_dacl == FALSE || dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "test SDDL DACL was missing",
            ));
        }
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    fn open_directory_with_acl_rights(path: &std::path::Path) -> io::Result<std::fs::File> {
        use std::os::windows::fs::OpenOptionsExt;

        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const WRITE_DAC: u32 = 0x0004_0000;
        const WRITE_OWNER: u32 = 0x0008_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
            .open(path)
    }

    #[test]
    fn apply_strips_inherited_everyone_from_a_child_file() -> io::Result<()> {
        let parent = temp_path("everyone-parent");
        fs::create_dir(&parent)?;
        let parent_dir = open_directory_with_acl_rights(&parent)?;
        apply_sddl(parent_dir.as_handle(), "D:P(A;OICI;FA;;;WD)")?;
        drop(parent_dir);

        let child = parent.join("child.bin");
        fs::write(&child, b"inherited")?;
        let file = open_with_acl_rights(&child)?;
        verify_current_user_only(file.as_handle()).expect_err(
            "a child of an inheritable Everyone directory must not already be current-user-only",
        );
        apply_current_user_only(file.as_handle())?;
        verify_current_user_only(file.as_handle())?;
        drop(file);
        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn apply_and_verify_round_trip_on_a_new_directory() -> io::Result<()> {
        let path = temp_path("dir-round-trip");
        fs::create_dir(&path)?;
        let directory = open_directory_with_acl_rights(&path)?;
        apply_current_user_only(directory.as_handle())?;
        verify_current_user_only(directory.as_handle())?;
        let first = volume_file_identity(directory.as_handle())?;
        let second = volume_file_identity(directory.as_handle())?;
        assert_eq!(first, second);
        assert_ne!(first.1, 0);
        flush(directory.as_handle())?;
        drop(directory);
        fs::remove_dir_all(path)?;
        Ok(())
    }

    fn create_junction(link: &std::path::Path, target: &std::path::Path) -> io::Result<()> {
        let status = std::process::Command::new("cmd.exe")
            .args([
                "/C",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("mklink /J failed"))
        }
    }

    #[test]
    fn relative_open_lists_and_deletes_a_child_without_following_a_junction() -> io::Result<()> {
        let parent = temp_path("relative-parent");
        fs::create_dir(&parent)?;
        let parent_dir = open_directory_with_acl_rights(&parent)?;
        apply_current_user_only(parent_dir.as_handle())?;

        let child_path = parent.join("child.bin");
        fs::write(&child_path, b"owned-child")?;
        let child_file = open_with_acl_rights(&child_path)?;
        apply_current_user_only(child_file.as_handle())?;
        drop(child_file);

        let names = read_directory_entries(parent_dir.as_handle())?;
        assert!(names.iter().any(|entry| entry.name == "child.bin"));

        let child = open_nofollow_child(parent_dir.as_handle(), OsStr::new("child.bin"), false)?;
        verify_current_user_only(child.as_handle())?;
        let identity = inspect(child.as_handle())?;
        assert!(!identity.is_directory());
        assert!(!identity.is_reparse_point());
        assert_eq!(identity.link_count, 1);
        mark_for_delete(child.as_handle())?;
        drop(child);

        let outside = temp_path("junction-target");
        fs::create_dir(&outside)?;
        let sentinel = outside.join("must-survive.bin");
        fs::write(&sentinel, b"outside-must-survive")?;
        let junction = parent.join("trap");
        create_junction(&junction, &outside)?;
        let error = open_nofollow_child(parent_dir.as_handle(), OsStr::new("trap"), true)
            .expect_err("a directory junction must not be opened as a managed child");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&sentinel)?, b"outside-must-survive");

        drop(parent_dir);
        fs::remove_dir_all(parent)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }
}
