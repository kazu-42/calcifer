//! Bounded, path-free observation of descriptor identities in one process group.

use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::os::fd::BorrowedFd;
use std::time::Instant;

const MAX_PROCESS_SCAN_ENTRIES: usize = 131_072;
const MAX_PROCESS_GROUP_MEMBERS: usize = 4_096;
const MAX_PROCESS_DESCRIPTOR_ENTRIES: usize = 4_096;
const MAX_FORBIDDEN_DESCRIPTOR_IDENTITIES: usize = 64;

#[derive(Clone, Copy)]
struct ScanLimits {
    processes: usize,
    members: usize,
    descriptors_per_process: usize,
    forbidden: usize,
}

impl ScanLimits {
    const PRODUCTION: Self = Self {
        processes: MAX_PROCESS_SCAN_ENTRIES,
        members: MAX_PROCESS_GROUP_MEMBERS,
        descriptors_per_process: MAX_PROCESS_DESCRIPTOR_ENTRIES,
        forbidden: MAX_FORBIDDEN_DESCRIPTOR_IDENTITIES,
    };
}

/// Fixed failure classification for a cross-process descriptor observation.
///
/// No variant carries a pathname, PID, fd number, or descriptor identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessGroupDescriptorScanError {
    InvalidArgument,
    ProcessLimit,
    MemberLimit,
    DescriptorLimit,
    ForbiddenIdentityLimit,
    Deadline,
    PermissionDenied,
    ProcessUserMismatch,
    ProcessChanged,
    DescriptorChanged,
    ForbiddenDescriptor,
    UnsupportedDescriptor,
    ObservationFailed,
}

impl fmt::Display for ProcessGroupDescriptorScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "the process-group descriptor scan arguments were invalid",
            Self::ProcessLimit => "the process scan reached its fixed bound",
            Self::MemberLimit => "the process-group member scan reached its fixed bound",
            Self::DescriptorLimit => "a process descriptor scan reached its fixed bound",
            Self::ForbiddenIdentityLimit => {
                "the forbidden descriptor identity set reached its fixed bound"
            }
            Self::Deadline => "the process-group descriptor scan reached its deadline",
            Self::PermissionDenied => "the process-group descriptor scan was not permitted",
            Self::ProcessUserMismatch => {
                "a process-group member does not belong to the current user"
            }
            Self::ProcessChanged => "a process identity or group membership changed during scan",
            Self::DescriptorChanged => "a process descriptor table changed during scan",
            Self::ForbiddenDescriptor => {
                "a forbidden descriptor identity remains open in the process group"
            }
            Self::UnsupportedDescriptor => "an open descriptor could not be identified safely",
            Self::ObservationFailed => "the process-group descriptor scan was inconclusive",
        })
    }
}

impl std::error::Error for ProcessGroupDescriptorScanError {}

/// Momentary proof that two stable, complete fd-number/kind snapshots of one
/// current-user process group contained none of the requested identities.
/// Every platform-supported descriptor identity is also compared exactly;
/// unsupported non-forbidden kinds are tracked by fd number and kind only.
///
/// This is read-only evidence. It carries no process handle or signal authority.
#[must_use = "descriptor isolation proof must be projected to the readiness barrier"]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProcessGroupDescriptorIsolationProof {
    members: usize,
    descriptors: usize,
}

/// Platform-pinned identity used only for cross-process descriptor scans.
///
/// Unlike [`DescriptorIdentity`], this value may contain an opaque kernel
/// object token on platforms where `fstat(2)` identity is not exported by the
/// process-inspection API. Its fields are deliberately private, it has no
/// serialization API, and diagnostics are always redacted.
#[must_use = "the captured identity must be retained until descriptor isolation is proven"]
#[derive(Clone, Copy, Eq, PartialEq)]
struct CrossProcessDescriptorIdentity {
    kind: u32,
    token: [u64; 3],
}

/// Fixed-capacity forbidden set that keeps every source owner borrowed.
///
/// Captured opaque tokens are useful only while their source kernel objects
/// remain pinned against reuse. The lifetime prevents callers from dropping
/// those owners before the scan completes; the fixed array prevents attacker-
/// controlled growth.
///
/// ```compile_fail
/// use std::os::fd::AsFd;
/// use std::os::unix::net::UnixStream;
/// use calcifer_unix_child_fd::CrossProcessDescriptorSet;
///
/// let (source, _peer) = UnixStream::pair().unwrap();
/// let mut forbidden = CrossProcessDescriptorSet::new();
/// forbidden.capture(source.as_fd()).unwrap();
/// drop(source); // the source object stays pinned by `forbidden`
/// let _ = forbidden.len();
/// ```
#[must_use = "the source-pinned set must remain alive until descriptor isolation is proven"]
pub struct CrossProcessDescriptorSet<'source> {
    identities: [CrossProcessDescriptorIdentity; MAX_FORBIDDEN_DESCRIPTOR_IDENTITIES],
    len: usize,
    _sources: PhantomData<BorrowedFd<'source>>,
}

impl CrossProcessDescriptorSet<'_> {
    const EMPTY_IDENTITY: CrossProcessDescriptorIdentity = CrossProcessDescriptorIdentity {
        kind: 0,
        token: [0; 3],
    };

    pub const fn new() -> Self {
        Self {
            identities: [Self::EMPTY_IDENTITY; MAX_FORBIDDEN_DESCRIPTOR_IDENTITIES],
            len: 0,
            _sources: PhantomData,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_slice(&self) -> &[CrossProcessDescriptorIdentity] {
        &self.identities[..self.len]
    }
}

impl<'source> CrossProcessDescriptorSet<'source> {
    /// Captures one source without exposing either its fd number or token.
    pub fn capture(
        &mut self,
        descriptor: BorrowedFd<'source>,
    ) -> Result<(), CrossProcessDescriptorIdentityError> {
        let identity = platform_capture_descriptor_identity(descriptor)?;
        if self.as_slice().contains(&identity) {
            return Ok(());
        }
        if self.len == self.identities.len() {
            return Err(CrossProcessDescriptorIdentityError::IdentityLimit);
        }
        self.identities[self.len] = identity;
        self.len += 1;
        Ok(())
    }

    /// Builds one fixed-capacity union while keeping both source-pinned sets
    /// borrowed for the complete lifetime of the result.
    ///
    /// Duplicate kernel objects remain idempotent: two independent owners of
    /// the same object consume one comparison slot, while both owners remain
    /// pinned by their original sets.
    pub fn combined_with<'sets>(
        &'sets self,
        other: &'sets CrossProcessDescriptorSet<'_>,
    ) -> Result<CrossProcessDescriptorSet<'sets>, CrossProcessDescriptorIdentityError> {
        let mut combined = CrossProcessDescriptorSet::new();
        for identity in self.as_slice().iter().chain(other.as_slice()) {
            if combined.as_slice().contains(identity) {
                continue;
            }
            if combined.len == combined.identities.len() {
                return Err(CrossProcessDescriptorIdentityError::IdentityLimit);
            }
            combined.identities[combined.len] = *identity;
            combined.len += 1;
        }
        Ok(combined)
    }
}

impl Default for CrossProcessDescriptorSet<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CrossProcessDescriptorSet<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.identities, self.len);
        formatter.write_str("CrossProcessDescriptorSet(<redacted>)")
    }
}

impl fmt::Debug for CrossProcessDescriptorIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (self.kind, self.token);
        formatter.write_str("CrossProcessDescriptorIdentity(<redacted>)")
    }
}

/// Fixed failure classification for pinning one source descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossProcessDescriptorIdentityError {
    IdentityLimit,
    UnsupportedDescriptor,
    DescriptorChanged,
    PermissionDenied,
    ObservationFailed,
}

impl fmt::Display for CrossProcessDescriptorIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentityLimit => "the forbidden descriptor set reached its fixed bound",
            Self::UnsupportedDescriptor => {
                "the descriptor kind cannot be identified across processes"
            }
            Self::DescriptorChanged => "the descriptor changed while its identity was captured",
            Self::PermissionDenied => "descriptor identity capture was not permitted",
            Self::ObservationFailed => "descriptor identity capture was inconclusive",
        })
    }
}

impl std::error::Error for CrossProcessDescriptorIdentityError {}

impl From<CrossProcessDescriptorIdentityError> for ProcessGroupDescriptorScanError {
    fn from(error: CrossProcessDescriptorIdentityError) -> Self {
        match error {
            CrossProcessDescriptorIdentityError::IdentityLimit => Self::ForbiddenIdentityLimit,
            CrossProcessDescriptorIdentityError::UnsupportedDescriptor => {
                Self::UnsupportedDescriptor
            }
            CrossProcessDescriptorIdentityError::DescriptorChanged => Self::DescriptorChanged,
            CrossProcessDescriptorIdentityError::PermissionDenied => Self::PermissionDenied,
            CrossProcessDescriptorIdentityError::ObservationFailed => Self::ObservationFailed,
        }
    }
}

impl ProcessGroupDescriptorIsolationProof {
    pub const fn member_count(self) -> usize {
        self.members
    }

    pub const fn descriptor_count(self) -> usize {
        self.descriptors
    }
}

impl fmt::Debug for ProcessGroupDescriptorIsolationProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (self.members, self.descriptors);
        formatter.write_str("ProcessGroupDescriptorIsolationProof(<redacted>)")
    }
}

/// Verifies that a current-user process group has no open descriptor matching
/// any path-free identity in `forbidden`.
///
/// Membership, process birth identity, complete fd-number/kind tables, and all
/// supported descriptor identities are sampled twice. PID reuse in the target
/// group, permission loss, a forbidden kind that cannot be identified,
/// capacity saturation, or relevant concurrent membership/fd mutation fails
/// closed. On Linux, an observed non-target process group is discarded before
/// sealing that unrelated PID's birth metadata, so host-wide churn cannot
/// prevent a busy host from ever producing a target-group snapshot.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn verify_process_group_forbidden_descriptors_absent_before(
    process_group: i32,
    forbidden: &CrossProcessDescriptorSet<'_>,
    deadline: Instant,
) -> Result<ProcessGroupDescriptorIsolationProof, ProcessGroupDescriptorScanError> {
    verify_with_limits(
        process_group,
        forbidden.as_slice(),
        ScanLimits::PRODUCTION,
        deadline,
    )
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct ProcessIdentity {
    pid: i32,
    process_group: i32,
    uid: u32,
    birth: [u64; 3],
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DescriptorObservation {
    descriptor: i32,
    kind: u32,
    token: Option<[u64; 3]>,
}

fn verify_with_limits(
    process_group: i32,
    forbidden: &[CrossProcessDescriptorIdentity],
    limits: ScanLimits,
    deadline: Instant,
) -> Result<ProcessGroupDescriptorIsolationProof, ProcessGroupDescriptorScanError> {
    check_deadline(deadline)?;
    validate_request(process_group, forbidden, limits, deadline)?;
    let before = platform_group_snapshot(process_group, limits, deadline)?;
    validate_group_snapshot(&before, process_group, limits)?;

    let mut descriptors = 0_usize;
    for member in &before {
        check_deadline(deadline)?;
        let first = platform_descriptor_snapshot(*member, forbidden, limits, deadline)?;
        validate_descriptor_snapshot(&first, forbidden, limits)?;
        check_deadline(deadline)?;
        let current = platform_process_identity(member.pid, deadline)?;
        if current != *member {
            return Err(ProcessGroupDescriptorScanError::ProcessChanged);
        }
        let second = platform_descriptor_snapshot(*member, forbidden, limits, deadline)?;
        validate_stable_descriptor_snapshots(&first, &second, forbidden, limits)?;
        descriptors = descriptors
            .checked_add(second.len())
            .ok_or(ProcessGroupDescriptorScanError::DescriptorLimit)?;
    }

    check_deadline(deadline)?;
    let after = platform_group_snapshot(process_group, limits, deadline)?;
    validate_stable_group_snapshots(&before, &after, process_group, limits)?;
    check_deadline(deadline)?;
    Ok(ProcessGroupDescriptorIsolationProof {
        members: after.len(),
        descriptors,
    })
}

fn validate_request(
    process_group: i32,
    forbidden: &[CrossProcessDescriptorIdentity],
    limits: ScanLimits,
    deadline: Instant,
) -> Result<(), ProcessGroupDescriptorScanError> {
    check_deadline(deadline)?;
    if process_group <= 0
        || limits.processes == 0
        || limits.members == 0
        || limits.descriptors_per_process == 0
    {
        return Err(ProcessGroupDescriptorScanError::InvalidArgument);
    }
    if forbidden.len() > limits.forbidden {
        return Err(ProcessGroupDescriptorScanError::ForbiddenIdentityLimit);
    }
    for (index, identity) in forbidden.iter().enumerate() {
        check_deadline(deadline)?;
        if forbidden[index + 1..].contains(identity) {
            return Err(ProcessGroupDescriptorScanError::InvalidArgument);
        }
    }
    Ok(())
}

fn check_deadline(deadline: Instant) -> Result<(), ProcessGroupDescriptorScanError> {
    if Instant::now() >= deadline {
        Err(ProcessGroupDescriptorScanError::Deadline)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn check_optional_deadline(
    deadline: Option<Instant>,
) -> Result<(), ProcessGroupDescriptorScanError> {
    if let Some(deadline) = deadline {
        check_deadline(deadline)?;
    }
    Ok(())
}

fn validate_group_snapshot(
    members: &[ProcessIdentity],
    process_group: i32,
    limits: ScanLimits,
) -> Result<(), ProcessGroupDescriptorScanError> {
    let effective_uid = unsafe { libc::geteuid() };
    if members.is_empty()
        || !members.iter().any(|member| member.pid == process_group)
        || members
            .iter()
            .any(|member| member.process_group != process_group)
    {
        return Err(ProcessGroupDescriptorScanError::ProcessChanged);
    }
    if members.iter().any(|member| member.uid != effective_uid) {
        return Err(ProcessGroupDescriptorScanError::ProcessUserMismatch);
    }
    if members.len() > limits.members {
        return Err(ProcessGroupDescriptorScanError::MemberLimit);
    }
    if members.windows(2).any(|pair| pair[0].pid >= pair[1].pid) {
        return Err(ProcessGroupDescriptorScanError::ProcessChanged);
    }
    Ok(())
}

fn validate_stable_group_snapshots(
    before: &[ProcessIdentity],
    after: &[ProcessIdentity],
    process_group: i32,
    limits: ScanLimits,
) -> Result<(), ProcessGroupDescriptorScanError> {
    validate_group_snapshot(after, process_group, limits)?;
    if before == after {
        Ok(())
    } else {
        Err(ProcessGroupDescriptorScanError::ProcessChanged)
    }
}

fn validate_descriptor_snapshot(
    descriptors: &[DescriptorObservation],
    forbidden: &[CrossProcessDescriptorIdentity],
    limits: ScanLimits,
) -> Result<(), ProcessGroupDescriptorScanError> {
    if descriptors.len() > limits.descriptors_per_process {
        return Err(ProcessGroupDescriptorScanError::DescriptorLimit);
    }
    if descriptors
        .windows(2)
        .any(|pair| pair[0].descriptor >= pair[1].descriptor)
    {
        return Err(ProcessGroupDescriptorScanError::DescriptorChanged);
    }
    if descriptors.iter().any(|descriptor| {
        descriptor.token.is_some_and(|token| {
            forbidden
                .iter()
                .any(|identity| identity.kind == descriptor.kind && identity.token == token)
        })
    }) {
        return Err(ProcessGroupDescriptorScanError::ForbiddenDescriptor);
    }
    Ok(())
}

fn validate_stable_descriptor_snapshots(
    before: &[DescriptorObservation],
    after: &[DescriptorObservation],
    forbidden: &[CrossProcessDescriptorIdentity],
    limits: ScanLimits,
) -> Result<(), ProcessGroupDescriptorScanError> {
    validate_descriptor_snapshot(after, forbidden, limits)?;
    if before == after {
        Ok(())
    } else {
        Err(ProcessGroupDescriptorScanError::DescriptorChanged)
    }
}

fn classify_observation_error(error: &io::Error) -> ProcessGroupDescriptorScanError {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ProcessGroupDescriptorScanError::PermissionDenied,
        Some(libc::ESRCH | libc::ENOENT | libc::EBADF) => {
            ProcessGroupDescriptorScanError::ProcessChanged
        }
        _ => ProcessGroupDescriptorScanError::ObservationFailed,
    }
}

fn classify_capture_error(error: &io::Error) -> CrossProcessDescriptorIdentityError {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => CrossProcessDescriptorIdentityError::PermissionDenied,
        Some(libc::ESRCH | libc::ENOENT | libc::EBADF) => {
            CrossProcessDescriptorIdentityError::DescriptorChanged
        }
        _ => CrossProcessDescriptorIdentityError::ObservationFailed,
    }
}

#[cfg(target_os = "macos")]
fn capture_error_from_scan(
    error: ProcessGroupDescriptorScanError,
) -> CrossProcessDescriptorIdentityError {
    match error {
        ProcessGroupDescriptorScanError::UnsupportedDescriptor => {
            CrossProcessDescriptorIdentityError::UnsupportedDescriptor
        }
        ProcessGroupDescriptorScanError::PermissionDenied => {
            CrossProcessDescriptorIdentityError::PermissionDenied
        }
        ProcessGroupDescriptorScanError::ProcessChanged
        | ProcessGroupDescriptorScanError::DescriptorChanged => {
            CrossProcessDescriptorIdentityError::DescriptorChanged
        }
        ProcessGroupDescriptorScanError::InvalidArgument
        | ProcessGroupDescriptorScanError::ProcessLimit
        | ProcessGroupDescriptorScanError::MemberLimit
        | ProcessGroupDescriptorScanError::DescriptorLimit
        | ProcessGroupDescriptorScanError::ForbiddenIdentityLimit
        | ProcessGroupDescriptorScanError::Deadline
        | ProcessGroupDescriptorScanError::ProcessUserMismatch
        | ProcessGroupDescriptorScanError::ForbiddenDescriptor
        | ProcessGroupDescriptorScanError::ObservationFailed => {
            CrossProcessDescriptorIdentityError::ObservationFailed
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_capture_descriptor_identity(
    descriptor: BorrowedFd<'_>,
) -> Result<CrossProcessDescriptorIdentity, CrossProcessDescriptorIdentityError> {
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    fn read_local(
        descriptor: BorrowedFd<'_>,
    ) -> Result<CrossProcessDescriptorIdentity, CrossProcessDescriptorIdentityError> {
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe { libc::fstat(descriptor.as_raw_fd(), status.as_mut_ptr()) };
        if result == -1 {
            return Err(classify_capture_error(&io::Error::last_os_error()));
        }
        let status = unsafe { status.assume_init() };
        if status.st_ino == 0 {
            return Err(CrossProcessDescriptorIdentityError::UnsupportedDescriptor);
        }
        Ok(CrossProcessDescriptorIdentity {
            kind: status.st_mode & libc::S_IFMT,
            token: [status.st_dev, status.st_ino, 0],
        })
    }

    let before = read_local(descriptor)?;
    let metadata = fs::metadata(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
        .map_err(|error| classify_capture_error(&error))?;
    let inspected = CrossProcessDescriptorIdentity {
        kind: metadata.mode() & libc::S_IFMT,
        token: [metadata.dev(), metadata.ino(), 0],
    };
    let after = read_local(descriptor)?;
    if before == inspected && inspected == after {
        Ok(after)
    } else {
        Err(CrossProcessDescriptorIdentityError::DescriptorChanged)
    }
}

#[cfg(target_os = "linux")]
fn platform_group_snapshot(
    process_group: i32,
    limits: ScanLimits,
    deadline: Instant,
) -> Result<Vec<ProcessIdentity>, ProcessGroupDescriptorScanError> {
    use std::fs;

    let entries = fs::read_dir("/proc").map_err(|error| classify_observation_error(&error))?;
    let candidates = entries.map(|entry| {
        let entry = entry.map_err(|error| classify_observation_error(&error))?;
        Ok(entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|pid| *pid > 0))
    });
    check_deadline(deadline)?;
    collect_linux_group_members(candidates, process_group, limits, deadline, |pid| {
        linux_candidate_identity(pid, Some(process_group), deadline)
    })
}

#[cfg(any(target_os = "linux", test))]
fn collect_linux_group_members<I, F>(
    candidates: I,
    process_group: i32,
    limits: ScanLimits,
    deadline: Instant,
    mut inspect: F,
) -> Result<Vec<ProcessIdentity>, ProcessGroupDescriptorScanError>
where
    I: IntoIterator<Item = Result<Option<i32>, ProcessGroupDescriptorScanError>>,
    F: FnMut(i32) -> Result<Option<ProcessIdentity>, ProcessGroupDescriptorScanError>,
{
    let mut process_entries = 0_usize;
    let mut members = Vec::new();
    for candidate in candidates {
        check_deadline(deadline)?;
        let Some(pid) = candidate? else {
            continue;
        };
        process_entries = process_entries
            .checked_add(1)
            .ok_or(ProcessGroupDescriptorScanError::ProcessLimit)?;
        if process_entries > limits.processes {
            return Err(ProcessGroupDescriptorScanError::ProcessLimit);
        }
        let Some(identity) = inspect(pid)? else {
            // A vanished candidate owns no descriptors. Linux also returns
            // None after observing a non-target pgrp in /proc/pid/stat,
            // before an unrelated PID's birth metadata can race. Target pgrp
            // candidates remain identity-sealed and propagate every race.
            continue;
        };
        if identity.process_group == process_group {
            if members.len() == limits.members {
                return Err(ProcessGroupDescriptorScanError::MemberLimit);
            }
            members.push(identity);
        }
    }
    check_deadline(deadline)?;
    members.sort_unstable();
    Ok(members)
}

#[cfg(target_os = "linux")]
fn platform_process_identity(
    pid: i32,
    deadline: Instant,
) -> Result<ProcessIdentity, ProcessGroupDescriptorScanError> {
    linux_process_identity(pid, deadline)
}

#[cfg(target_os = "linux")]
fn linux_process_identity(
    pid: i32,
    deadline: Instant,
) -> Result<ProcessIdentity, ProcessGroupDescriptorScanError> {
    linux_candidate_identity(pid, None, deadline)?
        .ok_or(ProcessGroupDescriptorScanError::ProcessChanged)
}

#[cfg(target_os = "linux")]
fn linux_candidate_identity(
    pid: i32,
    expected_process_group: Option<i32>,
    deadline: Instant,
) -> Result<Option<ProcessIdentity>, ProcessGroupDescriptorScanError> {
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    const MAX_PROC_STAT_BYTES: u64 = 64 * 1024;
    check_deadline(deadline)?;
    let process_path = format!("/proc/{pid}");
    let before = match fs::metadata(&process_path) {
        Ok(metadata) => metadata,
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
            return Ok(None);
        }
        Err(error) => return Err(classify_observation_error(&error)),
    };
    check_deadline(deadline)?;
    if !before.file_type().is_dir() {
        return Err(ProcessGroupDescriptorScanError::ProcessChanged);
    }
    let mut stat = Vec::new();
    let file = match fs::File::open(format!("{process_path}/stat")) {
        Ok(file) => file,
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
            return Ok(None);
        }
        Err(error) => return Err(classify_observation_error(&error)),
    };
    check_deadline(deadline)?;
    if let Err(error) = file.take(MAX_PROC_STAT_BYTES + 1).read_to_end(&mut stat) {
        if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) {
            return Ok(None);
        }
        return Err(classify_observation_error(&error));
    }
    check_deadline(deadline)?;
    if stat.len() as u64 > MAX_PROC_STAT_BYTES {
        return Err(ProcessGroupDescriptorScanError::ObservationFailed);
    }
    let stat = std::str::from_utf8(&stat)
        .map_err(|_| ProcessGroupDescriptorScanError::ObservationFailed)?;
    let opening = stat
        .find('(')
        .ok_or(ProcessGroupDescriptorScanError::ObservationFailed)?;
    let closing = stat
        .rfind(") ")
        .ok_or(ProcessGroupDescriptorScanError::ObservationFailed)?;
    if opening == 0 || closing <= opening || stat[..opening].trim().parse::<i32>().ok() != Some(pid)
    {
        return Err(ProcessGroupDescriptorScanError::ProcessChanged);
    }
    let fields: Vec<&str> = stat[closing + 2..].split_ascii_whitespace().collect();
    if fields.len() <= 19 {
        return Err(ProcessGroupDescriptorScanError::ObservationFailed);
    }
    let process_group = fields[2]
        .parse::<i32>()
        .map_err(|_| ProcessGroupDescriptorScanError::ObservationFailed)?;
    let start_time = fields[19]
        .parse::<u64>()
        .map_err(|_| ProcessGroupDescriptorScanError::ObservationFailed)?;
    if expected_process_group.is_some_and(|expected| process_group != expected) {
        // The target-group scan does not need a stable birth identity for an
        // observed non-member. Filtering here avoids turning unrelated host
        // PID churn into target-group ProcessChanged retries. A process that
        // was observed in the target pgrp continues through the full
        // before/stat/after seal, so reuse or exit remains fail-closed.
        return Ok(None);
    }
    let after = match fs::metadata(&process_path) {
        Ok(metadata) => metadata,
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
            return Ok(None);
        }
        Err(error) => return Err(classify_observation_error(&error)),
    };
    check_deadline(deadline)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || !after.file_type().is_dir()
        || process_group <= 0
    {
        return Err(ProcessGroupDescriptorScanError::ProcessChanged);
    }
    Ok(Some(ProcessIdentity {
        pid,
        process_group,
        uid: before.uid(),
        birth: [start_time, before.dev(), before.ino()],
    }))
}

#[cfg(target_os = "linux")]
fn platform_descriptor_snapshot(
    process: ProcessIdentity,
    _forbidden: &[CrossProcessDescriptorIdentity],
    limits: ScanLimits,
    deadline: Instant,
) -> Result<Vec<DescriptorObservation>, ProcessGroupDescriptorScanError> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let directory = fs::read_dir(format!("/proc/{}/fd", process.pid))
        .map_err(|error| classify_observation_error(&error))?;
    check_deadline(deadline)?;
    let mut descriptors = Vec::new();
    for entry in directory {
        check_deadline(deadline)?;
        let entry = entry.map_err(|error| classify_observation_error(&error))?;
        let Some(descriptor) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|descriptor| *descriptor >= 0)
        else {
            return Err(ProcessGroupDescriptorScanError::DescriptorChanged);
        };
        if descriptors.len() == limits.descriptors_per_process {
            return Err(ProcessGroupDescriptorScanError::DescriptorLimit);
        }
        let metadata = fs::metadata(entry.path()).map_err(|error| {
            if error.raw_os_error() == Some(libc::ENOENT) {
                ProcessGroupDescriptorScanError::DescriptorChanged
            } else {
                classify_observation_error(&error)
            }
        })?;
        let kind = metadata.mode() & libc::S_IFMT;
        let token = Some([metadata.dev(), metadata.ino(), 0]);
        descriptors.push(DescriptorObservation {
            descriptor,
            kind,
            token,
        });
    }
    check_deadline(deadline)?;
    descriptors.sort_unstable_by_key(|descriptor| descriptor.descriptor);
    Ok(descriptors)
}

#[cfg(target_os = "macos")]
fn platform_group_snapshot(
    process_group: i32,
    limits: ScanLimits,
    deadline: Instant,
) -> Result<Vec<ProcessIdentity>, ProcessGroupDescriptorScanError> {
    check_deadline(deadline)?;
    let mut listed = [0_i32; MAX_PROCESS_GROUP_MEMBERS + 1];
    let buffer_size = libc::c_int::try_from(std::mem::size_of_val(&listed))
        .map_err(|_| ProcessGroupDescriptorScanError::MemberLimit)?;
    let count =
        unsafe { libc::proc_listpgrppids(process_group, listed.as_mut_ptr().cast(), buffer_size) };
    check_deadline(deadline)?;
    if count < 0 {
        return Err(classify_observation_error(&io::Error::last_os_error()));
    }
    let count =
        usize::try_from(count).map_err(|_| ProcessGroupDescriptorScanError::ObservationFailed)?;
    if count >= listed.len() || count > limits.processes || count > limits.members {
        return Err(if count > limits.processes {
            ProcessGroupDescriptorScanError::ProcessLimit
        } else {
            ProcessGroupDescriptorScanError::MemberLimit
        });
    }
    let mut members = Vec::new();
    for pid in listed.into_iter().take(count) {
        check_deadline(deadline)?;
        if pid <= 0 {
            return Err(ProcessGroupDescriptorScanError::ProcessChanged);
        }
        let identity = macos_process_identity(pid, deadline)?;
        if identity.process_group != process_group {
            return Err(ProcessGroupDescriptorScanError::ProcessChanged);
        }
        members.push(identity);
    }
    check_deadline(deadline)?;
    members.sort_unstable();
    if members.windows(2).any(|pair| pair[0].pid == pair[1].pid) {
        return Err(ProcessGroupDescriptorScanError::ProcessChanged);
    }
    Ok(members)
}

#[cfg(target_os = "macos")]
fn platform_process_identity(
    pid: i32,
    deadline: Instant,
) -> Result<ProcessIdentity, ProcessGroupDescriptorScanError> {
    macos_process_identity(pid, deadline)
}

#[cfg(target_os = "macos")]
fn macos_process_identity(
    pid: i32,
    deadline: Instant,
) -> Result<ProcessIdentity, ProcessGroupDescriptorScanError> {
    check_deadline(deadline)?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let info_size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
        .map_err(|_| ProcessGroupDescriptorScanError::ObservationFailed)?;
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            info_size,
        )
    };
    check_deadline(deadline)?;
    if read != info_size {
        return Err(if read == 0 {
            classify_observation_error(&io::Error::last_os_error())
        } else {
            ProcessGroupDescriptorScanError::ObservationFailed
        });
    }
    let info = unsafe { info.assume_init() };
    let observed_pid =
        i32::try_from(info.pbi_pid).map_err(|_| ProcessGroupDescriptorScanError::ProcessChanged)?;
    let process_group = i32::try_from(info.pbi_pgid)
        .map_err(|_| ProcessGroupDescriptorScanError::ProcessChanged)?;
    if observed_pid != pid || process_group <= 0 {
        return Err(ProcessGroupDescriptorScanError::ProcessChanged);
    }
    Ok(ProcessIdentity {
        pid,
        process_group,
        uid: info.pbi_uid,
        birth: [info.pbi_start_tvsec, info.pbi_start_tvusec, 0],
    })
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacosProcFileInfo {
    open_flags: u32,
    status: u32,
    offset: i64,
    kind: i32,
    guard_flags: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacosFdStatPrefix {
    file: MacosProcFileInfo,
    stat: libc::vinfo_stat,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacosSocketTokenPrefix {
    file: MacosProcFileInfo,
    stat: libc::vinfo_stat,
    socket: u64,
    pcb: u64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacosPipeTokenPrefix {
    file: MacosProcFileInfo,
    stat: libc::vinfo_stat,
    handle: u64,
    peer_handle: u64,
}

#[cfg(target_os = "macos")]
fn macos_list_descriptors(
    pid: i32,
    limits: ScanLimits,
    deadline: Option<Instant>,
) -> Result<Vec<libc::proc_fdinfo>, ProcessGroupDescriptorScanError> {
    const ENTRY_SIZE: usize = std::mem::size_of::<libc::proc_fdinfo>();
    const BUFFER_BYTES: usize = (MAX_PROCESS_DESCRIPTOR_ENTRIES + 1) * ENTRY_SIZE;
    const BUFFER_WORDS: usize = BUFFER_BYTES.div_ceil(std::mem::size_of::<u64>());

    check_optional_deadline(deadline)?;
    let mut buffer = [0_u64; BUFFER_WORDS];
    let buffer_size = libc::c_int::try_from(BUFFER_BYTES)
        .map_err(|_| ProcessGroupDescriptorScanError::DescriptorLimit)?;
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr().cast(),
            buffer_size,
        )
    };
    check_optional_deadline(deadline)?;
    if read <= 0 {
        return Err(classify_observation_error(&io::Error::last_os_error()));
    }
    let read =
        usize::try_from(read).map_err(|_| ProcessGroupDescriptorScanError::ObservationFailed)?;
    if read >= BUFFER_BYTES || read % ENTRY_SIZE != 0 {
        return Err(ProcessGroupDescriptorScanError::DescriptorLimit);
    }
    let count = read / ENTRY_SIZE;
    if count > limits.descriptors_per_process {
        return Err(ProcessGroupDescriptorScanError::DescriptorLimit);
    }
    let mut descriptors = Vec::with_capacity(count);
    for index in 0..count {
        check_optional_deadline(deadline)?;
        let entry = unsafe {
            std::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(index * ENTRY_SIZE)
                    .cast::<libc::proc_fdinfo>(),
            )
        };
        if entry.proc_fd < 0 {
            return Err(ProcessGroupDescriptorScanError::DescriptorChanged);
        }
        descriptors.push(entry);
    }
    check_optional_deadline(deadline)?;
    descriptors.sort_unstable_by_key(|descriptor| descriptor.proc_fd);
    Ok(descriptors)
}

#[cfg(target_os = "macos")]
fn macos_descriptor_token(
    pid: i32,
    descriptor: libc::proc_fdinfo,
    deadline: Option<Instant>,
) -> Result<[u64; 3], ProcessGroupDescriptorScanError> {
    const PROC_PIDFDVNODEINFO: i32 = 1;
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const PROC_PIDFDPSEMINFO: i32 = 4;
    const PROC_PIDFDPSHMINFO: i32 = 5;
    const PROC_PIDFDPIPEINFO: i32 = 6;
    const INFO_BUFFER_WORDS: usize = 512;

    check_optional_deadline(deadline)?;
    let (flavor, required_size) = match descriptor.proc_fdtype as i32 {
        libc::PROX_FDTYPE_VNODE => (
            PROC_PIDFDVNODEINFO,
            std::mem::size_of::<MacosFdStatPrefix>(),
        ),
        libc::PROX_FDTYPE_SOCKET => (
            PROC_PIDFDSOCKETINFO,
            std::mem::size_of::<MacosSocketTokenPrefix>(),
        ),
        libc::PROX_FDTYPE_PSHM => (PROC_PIDFDPSHMINFO, std::mem::size_of::<MacosFdStatPrefix>()),
        libc::PROX_FDTYPE_PSEM => (PROC_PIDFDPSEMINFO, std::mem::size_of::<MacosFdStatPrefix>()),
        libc::PROX_FDTYPE_PIPE => (
            PROC_PIDFDPIPEINFO,
            std::mem::size_of::<MacosPipeTokenPrefix>(),
        ),
        _ => return Err(ProcessGroupDescriptorScanError::UnsupportedDescriptor),
    };
    let mut buffer = [0_u64; INFO_BUFFER_WORDS];
    let buffer_size = libc::c_int::try_from(std::mem::size_of_val(&buffer))
        .map_err(|_| ProcessGroupDescriptorScanError::ObservationFailed)?;
    let read = unsafe {
        libc::proc_pidfdinfo(
            pid,
            descriptor.proc_fd,
            flavor,
            buffer.as_mut_ptr().cast(),
            buffer_size,
        )
    };
    check_optional_deadline(deadline)?;
    let required_size = libc::c_int::try_from(required_size)
        .map_err(|_| ProcessGroupDescriptorScanError::ObservationFailed)?;
    if read < required_size {
        return Err(if read == 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EBADF | libc::ENOENT | libc::ESRCH) => {
                    ProcessGroupDescriptorScanError::DescriptorChanged
                }
                _ => classify_observation_error(&error),
            }
        } else {
            ProcessGroupDescriptorScanError::ObservationFailed
        });
    }
    let prefix = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<MacosFdStatPrefix>()) };
    if prefix.file.kind != descriptor.proc_fdtype as i32 {
        return Err(ProcessGroupDescriptorScanError::DescriptorChanged);
    }
    match descriptor.proc_fdtype as i32 {
        libc::PROX_FDTYPE_SOCKET => {
            let socket = unsafe {
                std::ptr::read_unaligned(buffer.as_ptr().cast::<MacosSocketTokenPrefix>())
            };
            if socket.socket == 0 {
                return Err(ProcessGroupDescriptorScanError::UnsupportedDescriptor);
            }
            Ok([socket.socket, 0, 0])
        }
        libc::PROX_FDTYPE_PIPE => {
            let pipe =
                unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<MacosPipeTokenPrefix>()) };
            if pipe.handle == 0 {
                return Err(ProcessGroupDescriptorScanError::UnsupportedDescriptor);
            }
            Ok([pipe.handle, 0, 0])
        }
        libc::PROX_FDTYPE_VNODE | libc::PROX_FDTYPE_PSHM | libc::PROX_FDTYPE_PSEM => {
            if prefix.stat.vst_ino == 0 {
                return Err(ProcessGroupDescriptorScanError::UnsupportedDescriptor);
            }
            Ok([
                u64::from(prefix.stat.vst_dev),
                prefix.stat.vst_ino,
                u64::from(prefix.stat.vst_gen),
            ])
        }
        _ => Err(ProcessGroupDescriptorScanError::UnsupportedDescriptor),
    }
}

#[cfg(target_os = "macos")]
fn macos_find_descriptor(
    pid: i32,
    descriptor: i32,
) -> Result<libc::proc_fdinfo, CrossProcessDescriptorIdentityError> {
    let listed = macos_list_descriptors(pid, ScanLimits::PRODUCTION, None)
        .map_err(capture_error_from_scan)?;
    let mut matches = listed
        .into_iter()
        .filter(|candidate| candidate.proc_fd == descriptor);
    let found = matches
        .next()
        .ok_or(CrossProcessDescriptorIdentityError::DescriptorChanged)?;
    if matches.next().is_some() {
        return Err(CrossProcessDescriptorIdentityError::DescriptorChanged);
    }
    Ok(found)
}

#[cfg(target_os = "macos")]
fn platform_capture_descriptor_identity(
    descriptor: BorrowedFd<'_>,
) -> Result<CrossProcessDescriptorIdentity, CrossProcessDescriptorIdentityError> {
    use std::os::fd::AsRawFd;

    let pid = i32::try_from(std::process::id())
        .map_err(|_| CrossProcessDescriptorIdentityError::ObservationFailed)?;
    let raw_descriptor = descriptor.as_raw_fd();
    let local_before =
        super::descriptor_identity(descriptor).map_err(|error| classify_capture_error(&error))?;
    let first = macos_find_descriptor(pid, raw_descriptor)?;
    let first_identity = CrossProcessDescriptorIdentity {
        kind: first.proc_fdtype,
        token: macos_descriptor_token(pid, first, None).map_err(capture_error_from_scan)?,
    };
    let local_after =
        super::descriptor_identity(descriptor).map_err(|error| classify_capture_error(&error))?;
    let second = macos_find_descriptor(pid, raw_descriptor)?;
    let second_identity = CrossProcessDescriptorIdentity {
        kind: second.proc_fdtype,
        token: macos_descriptor_token(pid, second, None).map_err(capture_error_from_scan)?,
    };
    if local_before != local_after || first_identity != second_identity {
        return Err(CrossProcessDescriptorIdentityError::DescriptorChanged);
    }
    if matches!(
        first.proc_fdtype as i32,
        libc::PROX_FDTYPE_VNODE | libc::PROX_FDTYPE_PSHM | libc::PROX_FDTYPE_PSEM
    ) && (first_identity.token[0] != local_after.device
        || first_identity.token[1] != local_after.inode)
    {
        return Err(CrossProcessDescriptorIdentityError::DescriptorChanged);
    }
    Ok(second_identity)
}

#[cfg(target_os = "macos")]
fn platform_descriptor_snapshot(
    process: ProcessIdentity,
    forbidden: &[CrossProcessDescriptorIdentity],
    limits: ScanLimits,
    deadline: Instant,
) -> Result<Vec<DescriptorObservation>, ProcessGroupDescriptorScanError> {
    check_deadline(deadline)?;
    let current = macos_process_identity(process.pid, deadline)?;
    if current != process {
        return Err(ProcessGroupDescriptorScanError::ProcessChanged);
    }
    let listed = macos_list_descriptors(process.pid, limits, Some(deadline))?;
    let mut descriptors = Vec::with_capacity(listed.len());
    for entry in listed {
        check_deadline(deadline)?;
        let supported = matches!(
            entry.proc_fdtype as i32,
            libc::PROX_FDTYPE_VNODE
                | libc::PROX_FDTYPE_SOCKET
                | libc::PROX_FDTYPE_PSHM
                | libc::PROX_FDTYPE_PSEM
                | libc::PROX_FDTYPE_PIPE
        );
        let token = if supported {
            Some(macos_descriptor_token(process.pid, entry, Some(deadline))?)
        } else {
            if forbidden
                .iter()
                .any(|identity| identity.kind == entry.proc_fdtype)
            {
                return Err(ProcessGroupDescriptorScanError::UnsupportedDescriptor);
            }
            None
        };
        descriptors.push(DescriptorObservation {
            descriptor: entry.proc_fd,
            kind: entry.proc_fdtype,
            token,
        });
    }
    check_deadline(deadline)?;
    Ok(descriptors)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{self, OpenOptions};
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    struct SyntheticProcessGroup {
        child: Child,
        process_group: i32,
        marker: PathBuf,
    }

    impl SyntheticProcessGroup {
        fn spawn(
            inherited: Option<std::os::fd::BorrowedFd<'_>>,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let marker = std::env::temp_dir().join(format!(
                "calcifer-process-group-fd-scan-{}-{nonce}",
                std::process::id()
            ));
            let mut command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg("/bin/sleep 30 & child=$!; : > \"$CALCIFER_SCAN_READY\"; wait \"$child\"")
                .env("CALCIFER_SCAN_READY", &marker)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0);
            let child = match inherited {
                Some(descriptor) => super::super::spawn_with_inherited_fd(command, descriptor)?,
                None => command.spawn()?,
            };
            let process_group = i32::try_from(child.id())?;
            let group = Self {
                child,
                process_group,
                marker,
            };
            group.wait_until_ready()?;
            Ok(group)
        }

        fn wait_until_ready(&self) -> Result<(), Box<dyn std::error::Error>> {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let members =
                    platform_group_snapshot(self.process_group, ScanLimits::PRODUCTION, deadline);
                if self.marker.is_file()
                    && members.as_ref().is_ok_and(|members| {
                        members.len() == 2
                            && members
                                .iter()
                                .any(|member| member.pid == self.process_group)
                    })
                {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err("synthetic process group did not become stable".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for SyntheticProcessGroup {
        fn drop(&mut self) {
            unsafe {
                libc::killpg(self.process_group, libc::SIGKILL);
            }
            let _ = self.child.wait();
            let _ = fs::remove_file(&self.marker);
        }
    }

    fn pipe_pair() -> Result<(OwnedFd, OwnedFd), Box<dyn std::error::Error>> {
        let mut descriptors = [-1_i32; 2];
        let result = unsafe { libc::pipe(descriptors.as_mut_ptr()) };
        if result == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        let read_flags = super::super::descriptor_flags(read.as_raw_fd())?;
        super::super::set_close_on_exec(read.as_raw_fd(), read_flags)?;
        let write_flags = super::super::descriptor_flags(write.as_raw_fd())?;
        super::super::set_close_on_exec(write.as_raw_fd(), write_flags)?;
        Ok((read, write))
    }

    fn unlinked_vnode() -> Result<std::fs::File, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "calcifer-cross-process-vnode-{}-{nonce}",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        fs::remove_file(path)?;
        Ok(file)
    }

    fn assert_forbidden_in_direct_child_and_descendant(
        descriptor: std::os::fd::BorrowedFd<'_>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut forbidden = CrossProcessDescriptorSet::new();
        forbidden.capture(descriptor)?;
        let identity = forbidden.as_slice()[0];
        let group = SyntheticProcessGroup::spawn(Some(descriptor))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let members =
            platform_group_snapshot(group.process_group, ScanLimits::PRODUCTION, deadline)?;
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].pid, group.process_group);
        assert_ne!(members[1].pid, group.process_group);
        for member in members {
            let observations = platform_descriptor_snapshot(
                member,
                &[identity],
                ScanLimits::PRODUCTION,
                deadline,
            )?;
            assert_eq!(
                observations
                    .iter()
                    .filter(|observation| {
                        observation.kind == identity.kind
                            && observation.token == Some(identity.token)
                    })
                    .count(),
                1
            );
        }
        assert_eq!(
            verify_process_group_forbidden_descriptors_absent_before(
                group.process_group,
                &forbidden,
                deadline,
            ),
            Err(ProcessGroupDescriptorScanError::ForbiddenDescriptor)
        );
        Ok(())
    }

    #[test]
    fn scanner_rejects_inherited_socket_pipe_and_vnode_in_direct_child_and_descendant()
    -> Result<(), Box<dyn std::error::Error>> {
        let (socket, _socket_peer) = UnixStream::pair()?;
        assert_forbidden_in_direct_child_and_descendant(socket.as_fd())?;

        let (pipe, _pipe_peer) = pipe_pair()?;
        assert_forbidden_in_direct_child_and_descendant(pipe.as_fd())?;

        let vnode = unlinked_vnode()?;
        assert_forbidden_in_direct_child_and_descendant(vnode.as_fd())?;
        Ok(())
    }

    #[test]
    fn scanner_proves_cloexec_socket_pipe_and_vnode_are_absent_from_all_descendants()
    -> Result<(), Box<dyn std::error::Error>> {
        let (socket, _socket_peer) = UnixStream::pair()?;
        let (pipe, _pipe_peer) = pipe_pair()?;
        let vnode = unlinked_vnode()?;
        let mut forbidden = CrossProcessDescriptorSet::new();
        forbidden.capture(socket.as_fd())?;
        forbidden.capture(pipe.as_fd())?;
        forbidden.capture(vnode.as_fd())?;
        let group = SyntheticProcessGroup::spawn(None)?;

        let proof = verify_process_group_forbidden_descriptors_absent_before(
            group.process_group,
            &forbidden,
            Instant::now() + Duration::from_secs(5),
        )?;
        assert_eq!(proof.member_count(), 2);
        assert!(proof.descriptor_count() >= 6);
        assert_eq!(
            format!("{proof:?}"),
            "ProcessGroupDescriptorIsolationProof(<redacted>)"
        );
        assert_eq!(
            format!("{forbidden:?}"),
            "CrossProcessDescriptorSet(<redacted>)"
        );
        Ok(())
    }

    #[test]
    fn forbidden_set_deduplicates_two_owners_of_the_same_kernel_object()
    -> Result<(), Box<dyn std::error::Error>> {
        let (socket, _peer) = UnixStream::pair()?;
        let duplicate = socket.try_clone()?;
        let mut forbidden = CrossProcessDescriptorSet::new();
        forbidden.capture(socket.as_fd())?;
        forbidden.capture(duplicate.as_fd())?;

        assert_eq!(forbidden.len(), 1);
        assert!(!forbidden.is_empty());
        assert_eq!(
            format!("{forbidden:?}"),
            "CrossProcessDescriptorSet(<redacted>)"
        );
        Ok(())
    }

    #[test]
    fn combined_forbidden_set_pins_both_inputs_and_deduplicates_shared_objects()
    -> Result<(), Box<dyn std::error::Error>> {
        let (shared, _shared_peer) = UnixStream::pair()?;
        let shared_duplicate = shared.try_clone()?;
        let (distinct, _distinct_peer) = UnixStream::pair()?;
        let mut left = CrossProcessDescriptorSet::new();
        left.capture(shared.as_fd())?;
        let mut right = CrossProcessDescriptorSet::new();
        right.capture(shared_duplicate.as_fd())?;
        right.capture(distinct.as_fd())?;

        let combined = left.combined_with(&right)?;
        assert_eq!(combined.len(), 2);
        assert_eq!(
            format!("{combined:?}"),
            "CrossProcessDescriptorSet(<redacted>)"
        );
        Ok(())
    }

    #[test]
    fn forbidden_set_rejects_a_distinct_identity_past_its_fixed_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut sockets = Vec::new();
        let mut peers = Vec::new();
        for _ in 0..=MAX_FORBIDDEN_DESCRIPTOR_IDENTITIES {
            let (socket, peer) = UnixStream::pair()?;
            sockets.push(socket);
            peers.push(peer);
        }
        let mut forbidden = CrossProcessDescriptorSet::new();
        for socket in sockets.iter().take(MAX_FORBIDDEN_DESCRIPTOR_IDENTITIES) {
            forbidden.capture(socket.as_fd())?;
        }
        assert_eq!(forbidden.len(), MAX_FORBIDDEN_DESCRIPTOR_IDENTITIES);
        assert_eq!(
            forbidden.capture(sockets[MAX_FORBIDDEN_DESCRIPTOR_IDENTITIES].as_fd()),
            Err(CrossProcessDescriptorIdentityError::IdentityLimit)
        );
        drop(peers);
        Ok(())
    }

    #[test]
    fn real_process_and_member_and_fd_limits_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let (forbidden, _peer) = UnixStream::pair()?;
        let mut identities = CrossProcessDescriptorSet::new();
        identities.capture(forbidden.as_fd())?;
        let identity = identities.as_slice()[0];
        let group = SyntheticProcessGroup::spawn(None)?;

        assert_eq!(
            verify_with_limits(
                group.process_group,
                &[identity],
                ScanLimits {
                    processes: 1,
                    ..ScanLimits::PRODUCTION
                },
                Instant::now() + Duration::from_secs(5),
            ),
            Err(ProcessGroupDescriptorScanError::ProcessLimit)
        );
        assert_eq!(
            verify_with_limits(
                group.process_group,
                &[identity],
                ScanLimits {
                    members: 1,
                    ..ScanLimits::PRODUCTION
                },
                Instant::now() + Duration::from_secs(5),
            ),
            Err(ProcessGroupDescriptorScanError::MemberLimit)
        );
        assert_eq!(
            verify_with_limits(
                group.process_group,
                &[identity],
                ScanLimits {
                    descriptors_per_process: 1,
                    ..ScanLimits::PRODUCTION
                },
                Instant::now() + Duration::from_secs(5),
            ),
            Err(ProcessGroupDescriptorScanError::DescriptorLimit)
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_kqueue_is_a_stable_non_forbidden_descriptor_kind()
    -> Result<(), Box<dyn std::error::Error>> {
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let kqueue = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut unsupported = CrossProcessDescriptorSet::new();
        assert_eq!(
            unsupported.capture(kqueue.as_fd()),
            Err(CrossProcessDescriptorIdentityError::UnsupportedDescriptor)
        );
        let (forbidden, _peer) = UnixStream::pair()?;
        let mut identities = CrossProcessDescriptorSet::new();
        identities.capture(forbidden.as_fd())?;
        validate_descriptor_snapshot(
            &[DescriptorObservation {
                descriptor: std::os::fd::AsRawFd::as_raw_fd(&kqueue),
                kind: libc::PROX_FDTYPE_KQUEUE as u32,
                token: None,
            }],
            identities.as_slice(),
            ScanLimits::PRODUCTION,
        )?;
        Ok(())
    }

    #[test]
    fn stable_snapshot_validator_rejects_fd_replacement_and_pid_reuse() {
        let limits = ScanLimits::PRODUCTION;
        let first_fd = [DescriptorObservation {
            descriptor: 7,
            kind: 1,
            token: Some([10, 20, 0]),
        }];
        let replaced_fd = [DescriptorObservation {
            descriptor: 7,
            kind: 1,
            token: Some([10, 21, 0]),
        }];
        assert_eq!(
            validate_stable_descriptor_snapshots(&first_fd, &replaced_fd, &[], limits),
            Err(ProcessGroupDescriptorScanError::DescriptorChanged)
        );

        let first_member = [ProcessIdentity {
            pid: 41,
            process_group: 41,
            uid: 501,
            birth: [1, 2, 3],
        }];
        let reused_member = [ProcessIdentity {
            pid: 41,
            process_group: 41,
            uid: 501,
            birth: [2, 2, 3],
        }];
        assert_eq!(
            validate_stable_group_snapshots(&first_member, &reused_member, 41, limits),
            Err(ProcessGroupDescriptorScanError::ProcessChanged)
        );

        let wrong_user = [ProcessIdentity {
            pid: i32::try_from(std::process::id()).unwrap_or(41),
            process_group: i32::try_from(std::process::id()).unwrap_or(41),
            uid: unsafe { libc::geteuid() }.wrapping_add(1),
            birth: [1, 2, 3],
        }];
        assert_eq!(
            validate_group_snapshot(
                &wrong_user,
                wrong_user[0].process_group,
                ScanLimits::PRODUCTION,
            ),
            Err(ProcessGroupDescriptorScanError::ProcessUserMismatch)
        );
    }

    #[test]
    fn linux_candidate_collection_skips_absent_but_preserves_identity_races() {
        let member = ProcessIdentity {
            pid: 41,
            process_group: 41,
            uid: unsafe { libc::geteuid() },
            birth: [1, 2, 3],
        };
        let unrelated = ProcessIdentity {
            pid: 42,
            process_group: 99,
            uid: unsafe { libc::geteuid() },
            birth: [4, 5, 6],
        };
        let candidates = vec![Ok(Some(40)), Ok(Some(41)), Ok(Some(42))];
        let members = collect_linux_group_members(
            candidates,
            41,
            ScanLimits::PRODUCTION,
            Instant::now() + Duration::from_secs(5),
            |pid| match pid {
                40 => Ok(None),
                41 => Ok(Some(member)),
                42 => Ok(Some(unrelated)),
                _ => Err(ProcessGroupDescriptorScanError::ObservationFailed),
            },
        )
        .unwrap_or_else(|error| panic!("unexpected collection failure: {error}"));
        assert!(members == vec![member]);
        assert!(validate_group_snapshot(&members, 41, ScanLimits::PRODUCTION).is_ok());

        let inspector_race = collect_linux_group_members(
            vec![Ok(Some(42))],
            41,
            ScanLimits::PRODUCTION,
            Instant::now() + Duration::from_secs(5),
            |_| Err(ProcessGroupDescriptorScanError::ProcessChanged),
        );
        assert!(matches!(
            inspector_race,
            Err(ProcessGroupDescriptorScanError::ProcessChanged)
        ));

        let candidate_iterator_race = collect_linux_group_members(
            vec![Err(ProcessGroupDescriptorScanError::ProcessChanged)],
            41,
            ScanLimits::PRODUCTION,
            Instant::now() + Duration::from_secs(5),
            |_| Ok(None),
        );
        assert!(matches!(
            candidate_iterator_race,
            Err(ProcessGroupDescriptorScanError::ProcessChanged)
        ));

        for terminal in [
            ProcessGroupDescriptorScanError::DescriptorChanged,
            ProcessGroupDescriptorScanError::PermissionDenied,
            ProcessGroupDescriptorScanError::ObservationFailed,
            ProcessGroupDescriptorScanError::Deadline,
        ] {
            let result = collect_linux_group_members(
                vec![Ok(Some(40))],
                41,
                ScanLimits::PRODUCTION,
                Instant::now() + Duration::from_secs(5),
                |_| Err(terminal),
            );
            assert!(matches!(result, Err(error) if error == terminal));
        }
    }

    #[test]
    fn fixed_limits_and_unknown_errors_fail_closed() {
        let identity = CrossProcessDescriptorIdentity {
            kind: 1,
            token: [10, 20, 0],
        };
        assert_eq!(
            validate_request(
                41,
                &[identity],
                ScanLimits {
                    forbidden: 0,
                    ..ScanLimits::PRODUCTION
                },
                Instant::now() + Duration::from_secs(5),
            ),
            Err(ProcessGroupDescriptorScanError::ForbiddenIdentityLimit)
        );
        assert_eq!(
            validate_descriptor_snapshot(
                &[DescriptorObservation {
                    descriptor: 3,
                    kind: 1,
                    token: Some(identity.token),
                }],
                &[],
                ScanLimits {
                    descriptors_per_process: 0,
                    ..ScanLimits::PRODUCTION
                },
            ),
            Err(ProcessGroupDescriptorScanError::DescriptorLimit)
        );
        assert_eq!(
            classify_observation_error(&io::Error::from_raw_os_error(libc::EPERM)),
            ProcessGroupDescriptorScanError::PermissionDenied
        );
        assert_eq!(
            classify_observation_error(&io::Error::from_raw_os_error(libc::EIO)),
            ProcessGroupDescriptorScanError::ObservationFailed
        );
    }

    #[test]
    fn expired_and_zero_budget_deadlines_fail_before_process_observation() {
        let identity = CrossProcessDescriptorIdentity {
            kind: 1,
            token: [10, 20, 0],
        };
        let zero_budget = Instant::now();
        assert_eq!(
            verify_with_limits(41, &[identity], ScanLimits::PRODUCTION, zero_budget),
            Err(ProcessGroupDescriptorScanError::Deadline)
        );

        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap_or_else(Instant::now);
        let forbidden = CrossProcessDescriptorSet::new();
        assert_eq!(
            verify_process_group_forbidden_descriptors_absent_before(41, &forbidden, expired,),
            Err(ProcessGroupDescriptorScanError::Deadline)
        );
    }
}
