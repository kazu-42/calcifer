//! Default-unused Unix PTY and terminal-channel primitives.
//!
//! This module deliberately does not provide `Read` or `Write` implementations
//! for PTY masters or terminal-channel endpoints. Callers can move terminal
//! bytes only through [`TerminalBuffer`], whose storage is fixed at compile
//! time. This keeps transcript retention and unbounded buffering out of the
//! supervised-session boundary.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
#[cfg(test)]
use std::time::Duration;

use rustix::io::{FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd};
use rustix::net::{AddressFamily, SendFlags, SocketType};
use sha2::{Digest, Sha256};

use super::protocol::{TerminalSnapshotFingerprint, VerifiedOpenGateAck, VerifiedReady};

/// The only terminal payload allocation used by the supervisor.
pub(super) const TERMINAL_BUFFER_CAPACITY: usize = 8 * 1024;

/// A terminal window size independent of the platform `winsize` spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TerminalSize {
    rows: u16,
    columns: u16,
    xpixel: u16,
    ypixel: u16,
}

impl TerminalSize {
    pub(super) const fn new(rows: u16, columns: u16) -> Self {
        Self {
            rows,
            columns,
            xpixel: 0,
            ypixel: 0,
        }
    }

    pub(super) const fn with_pixels(rows: u16, columns: u16, xpixel: u16, ypixel: u16) -> Self {
        Self {
            rows,
            columns,
            xpixel,
            ypixel,
        }
    }

    pub(super) const fn rows(self) -> u16 {
        self.rows
    }

    pub(super) const fn columns(self) -> u16 {
        self.columns
    }
}

impl From<TerminalSize> for rustix::termios::Winsize {
    fn from(size: TerminalSize) -> Self {
        Self {
            ws_row: size.rows,
            ws_col: size.columns,
            ws_xpixel: size.xpixel,
            ws_ypixel: size.ypixel,
        }
    }
}

impl From<rustix::termios::Winsize> for TerminalSize {
    fn from(size: rustix::termios::Winsize) -> Self {
        Self::with_pixels(size.ws_row, size.ws_col, size.ws_xpixel, size.ws_ypixel)
    }
}

/// A fixed-size buffer whose debug representation never includes terminal
/// contents.
pub(super) struct TerminalBuffer {
    bytes: [u8; TERMINAL_BUFFER_CAPACITY],
}

impl TerminalBuffer {
    pub(super) const fn new() -> Self {
        Self {
            bytes: [0; TERMINAL_BUFFER_CAPACITY],
        }
    }

    /// Copies one bounded input fragment into the fixed buffer.
    #[cfg(test)]
    pub(super) fn load<'buffer>(
        &'buffer mut self,
        bytes: &[u8],
    ) -> Result<TerminalChunk<'buffer>, TerminalError> {
        if bytes.is_empty() {
            return Err(TerminalError::EmptyChunk);
        }
        if bytes.len() > self.bytes.len() {
            return Err(TerminalError::ChunkTooLarge);
        }
        self.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(TerminalChunk::new(&mut self.bytes[..bytes.len()]))
    }

    /// Reads at most one fixed buffer from a non-PTY byte source.
    #[cfg(test)]
    pub(super) fn read_from<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<TerminalRead<'_>, TerminalError> {
        read_fixed(reader, self, false)
    }
}

impl Default for TerminalBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TerminalBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.bytes;
        formatter.write_str("TerminalBuffer(<redacted>)")
    }
}

/// A non-empty, move-only fragment borrowing its exact [`TerminalBuffer`].
///
/// The lifetime prevents a chunk from being paired with a different buffer or
/// surviving a buffer refill. Partial writes retain only an in-buffer offset.
pub(super) struct TerminalChunk<'buffer> {
    bytes: &'buffer mut [u8],
    written: usize,
}

impl<'buffer> TerminalChunk<'buffer> {
    fn new(bytes: &'buffer mut [u8]) -> Self {
        debug_assert!(!bytes.is_empty());
        Self { bytes, written: 0 }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(super) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.written)
    }

    /// Compares a complete, not-yet-forwarded frame without exposing it to
    /// diagnostics or allocating a payload copy.
    pub(super) fn matches(&self, expected: &[u8]) -> bool {
        self.written == 0 && self.bytes == expected
    }

    #[cfg(test)]
    fn bytes(&self) -> &[u8] {
        self.bytes
    }

    fn remaining_bytes(&self) -> &[u8] {
        &self.bytes[self.written..]
    }

    #[cfg(test)]
    pub(super) fn remaining_bytes_for_test(&self) -> &[u8] {
        self.remaining_bytes()
    }

    fn record_write(&mut self, length: usize) -> Result<TerminalWrite, TerminalError> {
        if length == 0 || length > self.remaining() {
            return Err(TerminalError::Write);
        }
        let previous = self.written;
        self.written += length;
        self.bytes[previous..self.written].fill(0);
        if self.written == self.bytes.len() {
            Ok(TerminalWrite::Complete)
        } else {
            Ok(TerminalWrite::Progress {
                written: length,
                remaining: self.remaining(),
            })
        }
    }

    #[cfg(test)]
    pub(super) fn consume_for_test(&mut self) -> Result<TerminalWrite, TerminalError> {
        self.record_write(self.remaining())
    }
}

impl fmt::Debug for TerminalChunk<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.bytes, self.written);
        formatter.write_str("TerminalChunk(<redacted>)")
    }
}

impl Drop for TerminalChunk<'_> {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// One bounded read result. Linux PTY `EIO` and portable zero-byte reads are
/// both projected to `EndOfStream` by [`PtyMaster::read_into`].
#[derive(Debug)]
pub(super) enum TerminalRead<'buffer> {
    Data(TerminalChunk<'buffer>),
    EndOfStream,
    WouldBlock,
}

/// Result of one nonblocking write attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminalWrite {
    Complete,
    Progress { written: usize, remaining: usize },
    WouldBlock,
}

/// Owner-side PTY descriptors before the slave has been moved into a command.
#[must_use = "the PTY slave must be attached or both descriptors explicitly dropped"]
pub(super) struct PtyOwner {
    master: File,
    slave: OwnedFd,
}

impl PtyOwner {
    /// Creates a PTY with a close-on-exec master and slave and installs the
    /// initial window size before any child can observe it.
    pub(super) fn open(size: TerminalSize) -> Result<Self, TerminalError> {
        let master = open_master()?;
        set_and_verify_close_on_exec(&master)?;
        rustix::pty::grantpt(&master).map_err(|_| TerminalError::GrantPty)?;
        rustix::pty::unlockpt(&master).map_err(|_| TerminalError::UnlockPty)?;
        let slave_name =
            rustix::pty::ptsname(&master, Vec::new()).map_err(|_| TerminalError::SlaveName)?;
        let slave = rustix::fs::open(
            slave_name.as_c_str(),
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| TerminalError::SlaveOpen)?;
        set_and_verify_close_on_exec(&slave)?;
        set_terminal_size(&slave, size)?;

        let owner = Self {
            master: File::from(master),
            slave,
        };
        owner.verify_close_on_exec()?;
        if owner.size()? != size {
            return Err(TerminalError::WindowSizeMismatch);
        }
        Ok(owner)
    }

    /// Moves exactly three slave references into child stdio and returns the
    /// sole owner-side master. This method does not alter process groups: the
    /// exec'd child must call [`claim_controlling_terminal_from_stdin`] before
    /// starting threads or provider work.
    pub(super) fn configure_child(self, command: &mut Command) -> Result<PtyMaster, TerminalError> {
        self.verify_close_on_exec()?;
        let stdout =
            fcntl_dupfd_cloexec(&self.slave, 3).map_err(|_| TerminalError::DescriptorDuplicate)?;
        let stderr =
            fcntl_dupfd_cloexec(&self.slave, 3).map_err(|_| TerminalError::DescriptorDuplicate)?;
        verify_close_on_exec(&stdout)?;
        verify_close_on_exec(&stderr)?;

        command
            .stdin(Stdio::from(self.slave))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        verify_close_on_exec(&self.master)?;
        Ok(PtyMaster {
            descriptor: self.master,
        })
    }

    fn verify_close_on_exec(&self) -> Result<(), TerminalError> {
        verify_close_on_exec(&self.master)?;
        verify_close_on_exec(&self.slave)
    }

    fn size(&self) -> Result<TerminalSize, TerminalError> {
        terminal_size(&self.slave)
    }
}

impl fmt::Debug for PtyOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.master, &self.slave);
        formatter.write_str("PtyOwner(<redacted>)")
    }
}

/// The guardian's sole PTY-master authority.
#[must_use = "dropping the PTY master changes terminal liveness"]
pub(super) struct PtyMaster {
    descriptor: File,
}

impl PtyMaster {
    pub(super) fn descriptor_identity(
        &self,
    ) -> Result<calcifer_unix_child_fd::DescriptorIdentity, TerminalError> {
        calcifer_unix_child_fd::descriptor_identity(self.descriptor.as_fd())
            .map_err(|_| TerminalError::DescriptorIdentity)
    }

    /// Pins the guardian-owned PTY master as a forbidden child descriptor.
    /// The returned set borrows this owner until the process-group scan ends.
    pub(super) fn capture_forbidden_descriptor_set_before_tui(
        &self,
    ) -> Result<
        calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
        calcifer_unix_child_fd::CrossProcessDescriptorIdentityError,
    > {
        let mut forbidden = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        forbidden.capture(self.descriptor.as_fd())?;
        Ok(forbidden)
    }

    #[cfg(test)]
    pub(super) fn size(&self) -> Result<TerminalSize, TerminalError> {
        terminal_size(&self.descriptor)
    }

    pub(super) fn set_size(&self, size: TerminalSize) -> Result<(), TerminalError> {
        set_terminal_size(&self.descriptor, size)
    }

    /// Reads one fixed fragment and normalizes both PTY end-of-stream forms.
    pub(super) fn read_into<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, TerminalError> {
        let mut descriptor = &self.descriptor;
        read_fixed(&mut descriptor, buffer, true)
    }

    pub(super) fn try_write(
        &self,
        chunk: &mut TerminalChunk<'_>,
    ) -> Result<TerminalWrite, TerminalError> {
        let mut descriptor = &self.descriptor;
        try_write_file(&mut descriptor, chunk)
    }

    pub(super) fn enable_nonblocking(&self) -> Result<(), TerminalError> {
        enable_nonblocking_checked(&self.descriptor)
    }

    #[cfg(test)]
    fn verify_close_on_exec(&self) -> Result<(), TerminalError> {
        verify_close_on_exec(&self.descriptor)
    }
}

impl fmt::Debug for PtyMaster {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.descriptor;
        formatter.write_str("PtyMaster(<redacted>)")
    }
}

impl AsFd for PtyMaster {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

/// Identity proof read after an exec'd PTY child has become its own session
/// and process-group leader and has acquired stdin as its controlling terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ControllingTerminalProof {
    process: i32,
    process_group: i32,
    session: i32,
    terminal_session: i32,
    foreground_process_group: i32,
}

impl ControllingTerminalProof {
    pub(super) const fn process(self) -> i32 {
        self.process
    }

    pub(super) const fn process_group(self) -> i32 {
        self.process_group
    }

    pub(super) const fn session(self) -> i32 {
        self.session
    }

    pub(super) const fn foreground_process_group(self) -> i32 {
        self.foreground_process_group
    }

    const fn identities_match(self) -> bool {
        self.process == self.process_group
            && self.process == self.session
            && self.process == self.terminal_session
            && self.process == self.foreground_process_group
    }
}

/// Claims the already-attached PTY slave on stdin as the child's controlling
/// terminal without a post-fork `pre_exec` closure.
//
// The fake TUI calls this immediately after exec, before creating threads. The
// parent intentionally does not call `CommandExt::process_group(0)`: a process
// group leader cannot call `setsid(2)` and would fail with `EPERM`.
pub(super) fn claim_controlling_terminal_from_stdin()
-> Result<ControllingTerminalProof, TerminalError> {
    let stdin = io::stdin();
    if !rustix::termios::isatty(&stdin) {
        return Err(TerminalError::NotTerminal);
    }
    rustix::process::setsid().map_err(|_| TerminalError::CreateSession)?;
    rustix::process::ioctl_tiocsctty(&stdin)
        .map_err(|_| TerminalError::ClaimControllingTerminal)?;
    verify_controlling_terminal_from_stdin()
}

/// Revalidates the child/session/process-group/foreground identity tuple.
pub(super) fn verify_controlling_terminal_from_stdin()
-> Result<ControllingTerminalProof, TerminalError> {
    let stdin = io::stdin();
    if !rustix::termios::isatty(&stdin) {
        return Err(TerminalError::NotTerminal);
    }
    let process = rustix::process::getpid();
    let proof = ControllingTerminalProof {
        process: process.as_raw_nonzero().get(),
        process_group: rustix::process::getpgrp().as_raw_nonzero().get(),
        session: rustix::process::getsid(Some(process))
            .map_err(|_| TerminalError::SessionIdentity)?
            .as_raw_nonzero()
            .get(),
        terminal_session: rustix::termios::tcgetsid(&stdin)
            .map_err(|_| TerminalError::SessionIdentity)?
            .as_raw_nonzero()
            .get(),
        foreground_process_group: rustix::termios::tcgetpgrp(&stdin)
            .map_err(|_| TerminalError::ForegroundIdentity)?
            .as_raw_nonzero()
            .get(),
    };
    if proof.identities_match() {
        Ok(proof)
    } else {
        Err(TerminalError::ControllingTerminalMismatch)
    }
}

pub(super) fn terminal_size<Fd: AsFd>(descriptor: Fd) -> Result<TerminalSize, TerminalError> {
    rustix::termios::tcgetwinsize(descriptor)
        .map(TerminalSize::from)
        .map_err(|_| TerminalError::WindowSizeRead)
}

pub(super) fn set_terminal_size<Fd: AsFd>(
    descriptor: Fd,
    size: TerminalSize,
) -> Result<(), TerminalError> {
    rustix::termios::tcsetwinsize(descriptor, size.into())
        .map_err(|_| TerminalError::WindowSizeWrite)
}

/// Exact pre-raw outer-terminal state shared by normal and fallback recovery.
///
/// The snapshot is cloneable because coordinator and guardian recovery are
/// redundant authorities over the same immutable target state. Restoration is
/// never used as their coordination mechanism; applying this state twice is an
/// intentional idempotent operation.
#[derive(Clone)]
pub(super) struct TerminalSnapshot {
    descriptor_identity: calcifer_unix_child_fd::DescriptorIdentity,
    attributes: rustix::termios::Termios,
    size: TerminalSize,
    foreground_process_group: i32,
}

impl TerminalSnapshot {
    pub(super) fn capture<Fd: AsFd>(descriptor: Fd) -> Result<Self, TerminalError> {
        Self::capture_for_recovery(
            descriptor,
            rustix::process::getpgrp().as_raw_nonzero().get(),
        )
    }

    /// Captures the guardian's recovery snapshot while cross-checking the
    /// coordinator-published foreground group. The guardian need not itself be
    /// a member of that group; it only proves the tty has not changed hands
    /// before raw mode can begin.
    pub(super) fn capture_for_recovery<Fd: AsFd>(
        descriptor: Fd,
        expected_foreground_process_group: i32,
    ) -> Result<Self, TerminalError> {
        if expected_foreground_process_group <= 0 {
            return Err(TerminalError::ForegroundIdentity);
        }
        let descriptor = descriptor.as_fd();
        if !rustix::termios::isatty(descriptor) {
            return Err(TerminalError::NotTerminal);
        }
        let descriptor_identity = read_descriptor_identity(descriptor)?;
        let foreground_process_group = read_foreground_process_group(descriptor)?;
        if foreground_process_group != expected_foreground_process_group {
            return Err(TerminalError::NotForegroundProcessGroup);
        }
        let mut attributes = rustix::termios::tcgetattr(descriptor)
            .map_err(|_| TerminalError::TerminalAttributesRead)?;
        // PENDIN is a kernel-maintained request to reprocess queued canonical
        // input, not a stable restorable mode. Re-enabling it after TCIFLUSH
        // would violate the no-replay gate invariant, and Darwin clears it on
        // readback. Every other local-mode bit remains exact.
        attributes
            .local_modes
            .remove(rustix::termios::LocalModes::PENDIN);
        let size = terminal_size(descriptor)?;

        // Bound the capture's TOCTOU window. A caller never receives a mixed
        // identity/foreground/termios/winsize snapshot.
        if read_descriptor_identity(descriptor)? != descriptor_identity
            || read_foreground_process_group(descriptor)? != foreground_process_group
            || !termios_semantically_equal(
                &attributes,
                &rustix::termios::tcgetattr(descriptor)
                    .map_err(|_| TerminalError::TerminalAttributesRead)?,
            )
            || terminal_size(descriptor)? != size
        {
            return Err(TerminalError::SnapshotChanged);
        }

        Ok(Self {
            descriptor_identity,
            attributes,
            size,
            foreground_process_group,
        })
    }

    pub(super) const fn size(&self) -> TerminalSize {
        self.size
    }

    pub(super) const fn foreground_process_group(&self) -> i32 {
        self.foreground_process_group
    }

    pub(super) const fn descriptor_identity(&self) -> calcifer_unix_child_fd::DescriptorIdentity {
        self.descriptor_identity
    }

    /// Hashes every field that defines the immutable pre-raw recovery target.
    ///
    /// The encoding is fixed-width, big-endian, platform-tagged, and excludes
    /// only `PENDIN`, matching [`termios_semantically_equal`]. Window size is
    /// included to prove both roles observed the same initial PTY geometry,
    /// although cleanup intentionally does not overwrite a later user resize.
    pub(super) fn semantic_fingerprint(&self) -> TerminalSnapshotFingerprint {
        let mut digest = Sha256::new();
        digest.update(b"calcifer-terminal-snapshot-v1\0");
        #[cfg(target_os = "linux")]
        digest.update(b"linux\0");
        #[cfg(target_os = "macos")]
        digest.update(b"macos\0");

        digest.update(self.descriptor_identity.device.to_be_bytes());
        digest.update(self.descriptor_identity.inode.to_be_bytes());
        digest.update(canonical_mode_bits(self.attributes.input_modes.bits()));
        digest.update(canonical_mode_bits(self.attributes.output_modes.bits()));
        digest.update(canonical_mode_bits(self.attributes.control_modes.bits()));
        digest.update(canonical_mode_bits(
            stable_local_modes(self.attributes.local_modes).bits(),
        ));
        digest.update(self.attributes.input_speed().to_be_bytes());
        digest.update(self.attributes.output_speed().to_be_bytes());
        for index in COMMON_SPECIAL_CODE_INDICES {
            digest.update([self.attributes.special_codes[index]]);
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::termios::SpecialCodeIndex;
            digest.update([self.attributes.special_codes[SpecialCodeIndex::VSWTC]]);
            digest.update([self.attributes.line_discipline]);
        }
        #[cfg(target_os = "macos")]
        {
            use rustix::termios::SpecialCodeIndex;
            digest.update([self.attributes.special_codes[SpecialCodeIndex::VDSUSP]]);
            digest.update([self.attributes.special_codes[SpecialCodeIndex::VSTATUS]]);
        }
        digest.update(self.size.rows.to_be_bytes());
        digest.update(self.size.columns.to_be_bytes());
        digest.update(self.size.xpixel.to_be_bytes());
        digest.update(self.size.ypixel.to_be_bytes());
        digest.update(self.foreground_process_group.to_be_bytes());

        TerminalSnapshotFingerprint::from_digest(digest.finalize().into())
    }

    /// Discards all pre-readiness input before applying raw mode immediately.
    /// The returned proof is suitable for the higher-level open-gate handshake.
    pub(super) fn enter_raw_after_input_flush<Fd: AsFd>(
        &self,
        descriptor: Fd,
    ) -> Result<RawTerminalProof, TerminalError> {
        let descriptor = descriptor.as_fd();
        self.verify_identity(descriptor)?;
        if read_foreground_process_group(descriptor)? != self.foreground_process_group
            || self.foreground_process_group != rustix::process::getpgrp().as_raw_nonzero().get()
        {
            return Err(TerminalError::NotForegroundProcessGroup);
        }
        rustix::termios::tcflush(descriptor, rustix::termios::QueueSelector::IFlush)
            .map_err(|_| TerminalError::InputFlush)?;

        let mut raw = self.attributes.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(descriptor, rustix::termios::OptionalActions::Now, &raw)
            .map_err(|_| TerminalError::RawModeApply)?;
        let readback = rustix::termios::tcgetattr(descriptor)
            .map_err(|_| TerminalError::TerminalAttributesRead)?;
        if !termios_semantically_equal(&raw, &readback) {
            return match self.restore(descriptor) {
                Ok(_) => Err(TerminalError::RawModeMismatch),
                Err(_) => Err(TerminalError::RawModeRollback),
            };
        }
        self.verify_identity(descriptor)?;
        Ok(RawTerminalProof {
            descriptor_identity: self.descriptor_identity,
        })
    }

    /// Discards input queued through the final restoration flush, restores the
    /// exact captured termios state with `TCSANOW`, and performs a semantic
    /// readback. It intentionally does not restore the window size: Calcifer
    /// never mutates the outer tty size, and a user resize during a session
    /// must not be overwritten by cleanup.
    pub(super) fn restore<Fd: AsFd>(
        &self,
        descriptor: Fd,
    ) -> Result<RestoredTerminalProof, TerminalError> {
        let descriptor = descriptor.as_fd();
        self.verify_identity(descriptor)?;
        // Descriptor identity alone is insufficient: a living shell/anchor
        // can reclaim the same tty and start a new foreground job after the
        // snapshot was captured. Refuse before the first mutation unless the
        // captured foreground group is still selected. This numeric-PGID
        // check is not a generation capability; public integration still
        // requires the reviewed anchor/generation handoff documented by the
        // supervisor gate.
        if read_foreground_process_group(descriptor)? != self.foreground_process_group {
            return Err(TerminalError::NotForegroundProcessGroup);
        }
        // The input pump is already quiescent, but keystrokes can still reach
        // the tty while cleanup runs. Never let those unread bytes become a
        // command in the invoking shell after Calcifer restores canonical mode.
        rustix::termios::tcflush(descriptor, rustix::termios::QueueSelector::IFlush)
            .map_err(|_| TerminalError::InputFlush)?;
        rustix::termios::tcsetattr(
            descriptor,
            rustix::termios::OptionalActions::Now,
            &self.attributes,
        )
        .map_err(|_| TerminalError::RestoreApply)?;
        let readback = rustix::termios::tcgetattr(descriptor)
            .map_err(|_| TerminalError::TerminalAttributesRead)?;
        if !termios_semantically_equal(&self.attributes, &readback) {
            return Err(TerminalError::RestoreMismatch);
        }
        self.verify_identity(descriptor)?;
        if read_foreground_process_group(descriptor)? != self.foreground_process_group {
            return Err(TerminalError::NotForegroundProcessGroup);
        }
        // Close the remaining arrival window from the first flush through the
        // attribute readback. The foreground check above prevents discarding a
        // successor job's input; checks below bind the proof to the same owner.
        rustix::termios::tcflush(descriptor, rustix::termios::QueueSelector::IFlush)
            .map_err(|_| TerminalError::InputFlush)?;
        self.verify_identity(descriptor)?;
        if read_foreground_process_group(descriptor)? != self.foreground_process_group {
            return Err(TerminalError::NotForegroundProcessGroup);
        }
        Ok(RestoredTerminalProof {
            descriptor_identity: self.descriptor_identity,
        })
    }

    /// Restores while blocking job-control `SIGTTOU` on only the current
    /// thread. The audited guard aborts if restoring the prior signal mask
    /// fails, so no false terminal proof can cross that boundary.
    pub(super) fn restore_with_sigttou_block<Fd: AsFd>(
        &self,
        descriptor: Fd,
    ) -> Result<RestoredTerminalProof, TerminalError> {
        let guard = calcifer_unix_child_fd::block_sigttou_for_current_thread()
            .map_err(|_| TerminalError::SignalSafety)?;
        let restored = self.restore(descriptor);
        drop(guard);
        restored
    }

    #[cfg(feature = "internal-supervisor-fixture")]
    pub(super) fn restore_with_identity_mismatch_for_fixture<Fd: AsFd>(
        &self,
        descriptor: Fd,
    ) -> Result<RestoredTerminalProof, TerminalError> {
        let mut mismatched = self.clone();
        mismatched.descriptor_identity.inode = if mismatched.descriptor_identity.inode == u64::MAX {
            1
        } else {
            mismatched.descriptor_identity.inode + 1
        };
        mismatched.restore(descriptor)
    }

    fn verify_identity(&self, descriptor: BorrowedFd<'_>) -> Result<(), TerminalError> {
        if !rustix::termios::isatty(descriptor) {
            return Err(TerminalError::NotTerminal);
        }
        if read_descriptor_identity(descriptor)? != self.descriptor_identity {
            return Err(TerminalError::TerminalIdentityMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for TerminalSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            self.descriptor_identity,
            &self.attributes,
            self.size,
            self.foreground_process_group,
        );
        formatter.write_str("TerminalSnapshot(<redacted>)")
    }
}

/// Proof that raw mode was applied and semantically read back on the expected
/// terminal identity.
#[must_use = "raw-mode proof is required before opening terminal input"]
pub(super) struct RawTerminalProof {
    descriptor_identity: calcifer_unix_child_fd::DescriptorIdentity,
}

impl RawTerminalProof {
    pub(super) const fn descriptor_identity(&self) -> calcifer_unix_child_fd::DescriptorIdentity {
        self.descriptor_identity
    }
}

impl fmt::Debug for RawTerminalProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.descriptor_identity;
        formatter.write_str("RawTerminalProof(<redacted>)")
    }
}

/// Proof that exact snapshot restoration was semantically read back and the
/// final input flush succeeded on the captured tty identity and foreground
/// owner.
#[must_use = "restoration proof must precede terminal recovery disarm"]
pub(super) struct RestoredTerminalProof {
    descriptor_identity: calcifer_unix_child_fd::DescriptorIdentity,
}

/// Proof that the guardian's process-local fallback tty was the sole remaining
/// descriptor for its identity and was then closed (count 1 -> 0).
#[must_use = "recovery disarm proof must precede the lifecycle acknowledgement"]
pub(super) struct RecoveryDisarmProof {
    descriptor_identity: calcifer_unix_child_fd::DescriptorIdentity,
}

/// Post-close authority retained when the guardian cannot yet prove that no
/// descriptor with the recovery tty identity remains open.
///
/// The descriptor itself has already been closed, so returning a
/// [`RecoveryTty`] would be false. Keeping the identity in this move-only
/// owner lets shutdown retry one bounded scan without manufacturing a disarm
/// proof or advancing provider/build cleanup.
#[must_use = "unconfirmed recovery disarm must be retried or retained"]
pub(super) struct RecoveryDisarmUnconfirmed {
    descriptor_identity: calcifer_unix_child_fd::DescriptorIdentity,
}

#[must_use = "a failed pre-disarm proof retains the recovery tty"]
pub(super) struct RecoveryDisarmFailure {
    recovery: RecoveryTty,
    error: TerminalError,
}

impl RecoveryDisarmFailure {
    pub(super) fn into_recovery(self) -> RecoveryTty {
        self.recovery
    }
}

impl fmt::Debug for RecoveryDisarmFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.recovery;
        formatter
            .debug_struct("RecoveryDisarmFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RecoveryDisarmFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for RecoveryDisarmFailure {}

/// One exact result after the recovery descriptor has been closed.
/// `Disarmed` is the sole branch that authorizes the lifecycle acknowledgement;
/// `Unconfirmed` retains the only capability that can retry the post-close
/// identity scan.
#[must_use = "recovery disarm outcome must authorize acknowledgement or be retained"]
pub(super) enum RecoveryDisarmOutcome {
    Disarmed(RecoveryDisarmProof),
    Unconfirmed(RecoveryDisarmUnconfirmed),
}

impl fmt::Debug for RecoveryDisarmProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.descriptor_identity;
        formatter.write_str("RecoveryDisarmProof(<redacted>)")
    }
}

impl fmt::Debug for RecoveryDisarmUnconfirmed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.descriptor_identity;
        formatter.write_str("RecoveryDisarmUnconfirmed(<redacted>)")
    }
}

impl RecoveryDisarmUnconfirmed {
    /// Performs exactly one post-close identity scan. No internal retry loop
    /// can extend a caller's shutdown deadline. A nonzero count or scan error
    /// returns the same move-only authority for a later bounded shutdown turn.
    pub(super) fn retry_once(self) -> RecoveryDisarmOutcome {
        self.retry_once_with(|identity| {
            calcifer_unix_child_fd::count_open_descriptors_with_identity(identity)
                .map_err(|_| TerminalError::RecoveryAuthorityMismatch)
        })
    }

    fn retry_once_with(
        self,
        scan: impl FnOnce(calcifer_unix_child_fd::DescriptorIdentity) -> Result<usize, TerminalError>,
    ) -> RecoveryDisarmOutcome {
        classify_closed_recovery(self.descriptor_identity, scan(self.descriptor_identity))
    }
}

impl RestoredTerminalProof {
    pub(super) const fn descriptor_identity(&self) -> calcifer_unix_child_fd::DescriptorIdentity {
        self.descriptor_identity
    }
}

impl fmt::Debug for RestoredTerminalProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.descriptor_identity;
        formatter.write_str("RestoredTerminalProof(<redacted>)")
    }
}

/// Non-cloneable fallback descriptor used by the guardian to restore the
/// outer terminal if the coordinator disappears while raw mode is active.
#[must_use = "the recovery tty must remain armed until restoration is acknowledged"]
pub(super) struct RecoveryTty {
    descriptor: OwnedFd,
    descriptor_identity: calcifer_unix_child_fd::DescriptorIdentity,
}

impl RecoveryTty {
    pub(super) fn duplicate<Fd: AsFd>(descriptor: Fd) -> Result<Self, TerminalError> {
        let descriptor = descriptor.as_fd();
        if !rustix::termios::isatty(descriptor) {
            return Err(TerminalError::NotTerminal);
        }
        let expected_identity = read_descriptor_identity(descriptor)?;
        let duplicate =
            fcntl_dupfd_cloexec(descriptor, 3).map_err(|_| TerminalError::DescriptorDuplicate)?;
        Self::adopt(duplicate, expected_identity)
    }

    /// Moves inherited guardian stderr into one owned recovery descriptor.
    ///
    /// The borrowed fd 2 lifetime ends before the audited helper atomically
    /// replaces that standard stream with a close-on-exec `/dev/null`.
    /// Replacement succeeds only when fd 2 plus this duplicate are the exact
    /// two references to the expected tty identity; afterward this value is
    /// the sole remaining recovery authority.
    pub(super) fn bootstrap_from_inherited_stderr() -> Result<Self, TerminalError> {
        let stderr = io::stderr();
        let (duplicate, expected_identity) = {
            let inherited = stderr.as_fd();
            if !rustix::termios::isatty(inherited) {
                return Err(TerminalError::NotTerminal);
            }
            let expected_identity = read_descriptor_identity(inherited)?;
            let duplicate = fcntl_dupfd_cloexec(inherited, 3)
                .map_err(|_| TerminalError::DescriptorDuplicate)?;
            (duplicate, expected_identity)
        };
        calcifer_unix_child_fd::replace_inherited_stderr_with_dev_null(expected_identity)
            .map_err(|_| TerminalError::DescriptorDuplicate)?;
        Self::adopt(duplicate, expected_identity)
    }

    fn adopt(
        descriptor: OwnedFd,
        expected_identity: calcifer_unix_child_fd::DescriptorIdentity,
    ) -> Result<Self, TerminalError> {
        verify_close_on_exec(&descriptor)?;
        if !rustix::termios::isatty(&descriptor) {
            return Err(TerminalError::NotTerminal);
        }
        let descriptor_identity = read_descriptor_identity(descriptor.as_fd())?;
        if descriptor_identity != expected_identity {
            return Err(TerminalError::TerminalIdentityMismatch);
        }
        Ok(Self {
            descriptor,
            descriptor_identity,
        })
    }

    pub(super) const fn descriptor_identity(&self) -> calcifer_unix_child_fd::DescriptorIdentity {
        self.descriptor_identity
    }

    /// Appends the recovery terminal to one source-pinned child denyset
    /// without exposing its raw descriptor or kernel identity.
    pub(super) fn append_forbidden_descriptor<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        forbidden.capture(self.descriptor.as_fd())
    }

    pub(super) fn verify_invariants(&self) -> Result<(), TerminalError> {
        verify_close_on_exec(&self.descriptor)?;
        if !rustix::termios::isatty(&self.descriptor)
            || read_descriptor_identity(self.descriptor.as_fd())? != self.descriptor_identity
        {
            return Err(TerminalError::TerminalIdentityMismatch);
        }
        Ok(())
    }

    pub(super) fn restore_with_sigttou_block(
        &self,
        snapshot: &TerminalSnapshot,
    ) -> Result<RestoredTerminalProof, TerminalError> {
        self.verify_invariants()?;
        snapshot.restore_with_sigttou_block(&self.descriptor)
    }

    pub(super) fn disarm(self) -> Result<RecoveryDisarmOutcome, RecoveryDisarmFailure> {
        self.disarm_with_scan(|identity| {
            calcifer_unix_child_fd::count_open_descriptors_with_identity(identity)
                .map_err(|_| TerminalError::RecoveryAuthorityMismatch)
        })
    }

    fn disarm_with_scan(
        self,
        mut scan: impl FnMut(calcifer_unix_child_fd::DescriptorIdentity) -> Result<usize, TerminalError>,
    ) -> Result<RecoveryDisarmOutcome, RecoveryDisarmFailure> {
        if let Err(error) = self.verify_invariants() {
            return Err(RecoveryDisarmFailure {
                recovery: self,
                error,
            });
        }
        let descriptor_identity = self.descriptor_identity;
        let count = match scan(descriptor_identity) {
            Ok(count) => count,
            Err(error) => {
                return Err(RecoveryDisarmFailure {
                    recovery: self,
                    error,
                });
            }
        };
        if count != 1 {
            return Err(RecoveryDisarmFailure {
                recovery: self,
                error: TerminalError::RecoveryAuthorityMismatch,
            });
        }
        let Self {
            descriptor,
            descriptor_identity,
        } = self;
        drop(descriptor);
        Ok(classify_closed_recovery(
            descriptor_identity,
            scan(descriptor_identity),
        ))
    }

    /// Moves the recovery tty into guardian stderr for one exec boundary.
    pub(super) fn into_stdio(self) -> Result<Stdio, TerminalError> {
        self.verify_invariants()?;
        Ok(Stdio::from(self.descriptor))
    }
}

/// Builds the smallest physical terminal authority used by startup rollback
/// tests. The production constructors remain unchanged: this fixture opens a
/// real PTY, snapshots the exact slave identity, drops every slave reference
/// except the one recovery descriptor, and pairs it with a real terminal byte
/// channel. The returned master keepalive is a different descriptor identity;
/// it must remain open because Linux changes the disconnected slave's
/// observable identity after the final master closes. Normal
/// coordinator-proof tests never use the synthetic foreground field to
/// restore; they use it only to exercise the post-proof disarm gate.
#[cfg(test)]
pub(super) fn startup_failure_terminal_for_test() -> Result<
    (
        TerminalEndpoint,
        TerminalEndpoint,
        RecoveryTty,
        TerminalSnapshot,
        calcifer_unix_child_fd::DescriptorIdentity,
        File,
    ),
    TerminalError,
> {
    let PtyOwner { master, slave } = PtyOwner::open(TerminalSize::new(24, 80))?;
    let descriptor = slave.as_fd();
    let descriptor_identity = read_descriptor_identity(descriptor)?;
    let snapshot = TerminalSnapshot {
        descriptor_identity,
        attributes: rustix::termios::tcgetattr(descriptor)
            .map_err(|_| TerminalError::TerminalAttributesRead)?,
        size: terminal_size(descriptor)?,
        foreground_process_group: rustix::process::getpgrp().as_raw_nonzero().get(),
    };
    let recovery = RecoveryTty::duplicate(descriptor)?;
    let (peer, endpoint) = TerminalChannelPair::new()?.split();
    drop(slave);
    let open = calcifer_unix_child_fd::count_open_descriptors_with_identity(descriptor_identity)
        .map_err(|_| TerminalError::RecoveryAuthorityMismatch)?;
    if open != 1 {
        return Err(TerminalError::RecoveryAuthorityMismatch);
    }
    Ok((
        endpoint,
        peer,
        recovery,
        snapshot,
        descriptor_identity,
        master,
    ))
}

fn classify_closed_recovery(
    descriptor_identity: calcifer_unix_child_fd::DescriptorIdentity,
    count: Result<usize, TerminalError>,
) -> RecoveryDisarmOutcome {
    match count {
        Ok(0) => RecoveryDisarmOutcome::Disarmed(RecoveryDisarmProof {
            descriptor_identity,
        }),
        Ok(_) | Err(_) => RecoveryDisarmOutcome::Unconfirmed(RecoveryDisarmUnconfirmed {
            descriptor_identity,
        }),
    }
}

impl AsFd for RecoveryTty {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl fmt::Debug for RecoveryTty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.descriptor, self.descriptor_identity);
        formatter.write_str("RecoveryTty(<redacted>)")
    }
}

/// Coordinator-owned outer tty with an independent open-file description.
///
/// `dup(2)` would share `O_NONBLOCK` with the user's stdin and the guardian's
/// recovery descriptor. Instead this wrapper resolves the tty name, opens it
/// with `O_NOCTTY|O_CLOEXEC|O_NOFOLLOW`, and accepts it only if both descriptor
/// identities still match. Nonblocking pump I/O therefore cannot leak into the
/// invoking shell, including if Calcifer is killed abruptly.
#[must_use = "the outer tty must remain owned until pumps are quiesced"]
pub(super) struct TerminalTty {
    descriptor: File,
    descriptor_identity: calcifer_unix_child_fd::DescriptorIdentity,
}

impl TerminalTty {
    pub(super) fn open_independent<Fd: AsFd>(descriptor: Fd) -> Result<Self, TerminalError> {
        let descriptor = descriptor.as_fd();
        if !rustix::termios::isatty(descriptor) {
            return Err(TerminalError::NotTerminal);
        }
        let expected_identity = read_descriptor_identity(descriptor)?;
        let tty_name =
            rustix::termios::ttyname(descriptor, Vec::new()).map_err(|_| TerminalError::TtyName)?;
        let opened = rustix::fs::open(
            tty_name.as_c_str(),
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::NOCTTY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| TerminalError::TtyOpen)?;
        verify_close_on_exec(&opened)?;
        if !rustix::termios::isatty(&opened)
            || read_descriptor_identity(opened.as_fd())? != expected_identity
            || read_descriptor_identity(descriptor)? != expected_identity
        {
            return Err(TerminalError::TerminalIdentityMismatch);
        }
        Ok(Self {
            descriptor: File::from(opened),
            descriptor_identity: expected_identity,
        })
    }

    pub(super) fn descriptor_identity(&self) -> calcifer_unix_child_fd::DescriptorIdentity {
        self.descriptor_identity
    }

    pub(super) fn verify_invariants(&self) -> Result<(), TerminalError> {
        verify_close_on_exec(&self.descriptor)?;
        if !rustix::termios::isatty(&self.descriptor)
            || read_descriptor_identity(self.descriptor.as_fd())? != self.descriptor_identity
        {
            return Err(TerminalError::TerminalIdentityMismatch);
        }
        Ok(())
    }

    pub(super) fn enable_nonblocking(&self) -> Result<(), TerminalError> {
        self.verify_invariants()?;
        enable_nonblocking_checked(&self.descriptor)
    }

    pub(super) fn read_into<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, TerminalError> {
        let mut descriptor = &self.descriptor;
        read_fixed(&mut descriptor, buffer, false)
    }

    pub(super) fn try_write(
        &self,
        chunk: &mut TerminalChunk<'_>,
    ) -> Result<TerminalWrite, TerminalError> {
        let mut descriptor = &self.descriptor;
        try_write_file(&mut descriptor, chunk)
    }
}

impl AsFd for TerminalTty {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl fmt::Debug for TerminalTty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.descriptor, self.descriptor_identity);
        formatter.write_str("TerminalTty(<redacted>)")
    }
}

fn read_descriptor_identity(
    descriptor: BorrowedFd<'_>,
) -> Result<calcifer_unix_child_fd::DescriptorIdentity, TerminalError> {
    calcifer_unix_child_fd::descriptor_identity(descriptor)
        .map_err(|_| TerminalError::DescriptorIdentity)
}

fn read_foreground_process_group(descriptor: BorrowedFd<'_>) -> Result<i32, TerminalError> {
    rustix::termios::tcgetpgrp(descriptor)
        .map(|process_group| process_group.as_raw_nonzero().get())
        .map_err(|_| TerminalError::ForegroundIdentity)
}

/// Compares every semantic termios field exposed by rustix on Linux/macOS.
/// This helper never formats attributes or special codes into diagnostics.
pub(super) fn termios_semantically_equal(
    expected: &rustix::termios::Termios,
    actual: &rustix::termios::Termios,
) -> bool {
    termios_mismatch_code(expected, actual).is_none()
}

/// Returns only a fixed field class, never the terminal attribute value.
fn termios_mismatch_code(
    expected: &rustix::termios::Termios,
    actual: &rustix::termios::Termios,
) -> Option<u8> {
    if expected.input_modes != actual.input_modes {
        return Some(1);
    }
    if expected.output_modes != actual.output_modes {
        return Some(2);
    }
    if expected.control_modes != actual.control_modes {
        return Some(3);
    }
    let expected_local_modes = stable_local_modes(expected.local_modes);
    let actual_local_modes = stable_local_modes(actual.local_modes);
    if expected_local_modes != actual_local_modes {
        let differing_bit = (expected_local_modes ^ actual_local_modes)
            .bits()
            .trailing_zeros();
        return u8::try_from(20 + differing_bit).ok();
    }
    if expected.input_speed() != actual.input_speed() {
        return Some(5);
    }
    if expected.output_speed() != actual.output_speed() {
        return Some(6);
    }
    if !special_codes_equal(&expected.special_codes, &actual.special_codes) {
        return Some(7);
    }
    #[cfg(target_os = "linux")]
    if expected.line_discipline != actual.line_discipline {
        return Some(8);
    }
    None
}

fn stable_local_modes(mut modes: rustix::termios::LocalModes) -> rustix::termios::LocalModes {
    modes.remove(rustix::termios::LocalModes::PENDIN);
    modes
}

#[cfg(target_os = "linux")]
fn canonical_mode_bits(bits: u32) -> [u8; 8] {
    u64::from(bits).to_be_bytes()
}

#[cfg(target_os = "macos")]
fn canonical_mode_bits(bits: u64) -> [u8; 8] {
    bits.to_be_bytes()
}

use rustix::termios::SpecialCodeIndex;

const COMMON_SPECIAL_CODE_INDICES: [SpecialCodeIndex; 16] = [
    SpecialCodeIndex::VINTR,
    SpecialCodeIndex::VQUIT,
    SpecialCodeIndex::VERASE,
    SpecialCodeIndex::VKILL,
    SpecialCodeIndex::VEOF,
    SpecialCodeIndex::VTIME,
    SpecialCodeIndex::VMIN,
    SpecialCodeIndex::VSTART,
    SpecialCodeIndex::VSTOP,
    SpecialCodeIndex::VSUSP,
    SpecialCodeIndex::VEOL,
    SpecialCodeIndex::VREPRINT,
    SpecialCodeIndex::VDISCARD,
    SpecialCodeIndex::VWERASE,
    SpecialCodeIndex::VLNEXT,
    SpecialCodeIndex::VEOL2,
];

fn special_codes_equal(
    expected: &rustix::termios::SpecialCodes,
    actual: &rustix::termios::SpecialCodes,
) -> bool {
    if !COMMON_SPECIAL_CODE_INDICES
        .iter()
        .all(|index| expected[*index] == actual[*index])
    {
        return false;
    }
    #[cfg(target_os = "linux")]
    if expected[SpecialCodeIndex::VSWTC] != actual[SpecialCodeIndex::VSWTC] {
        return false;
    }
    #[cfg(target_os = "macos")]
    if expected[SpecialCodeIndex::VDSUSP] != actual[SpecialCodeIndex::VDSUSP]
        || expected[SpecialCodeIndex::VSTATUS] != actual[SpecialCodeIndex::VSTATUS]
    {
        return false;
    }
    true
}

/// Dedicated full-duplex byte channel. It is intentionally unrelated to the
/// lifecycle and lease-transfer endpoint types.
#[must_use = "the terminal pair must be split at the guardian boundary"]
pub(super) struct TerminalChannelPair {
    coordinator: TerminalEndpoint,
    guardian: TerminalEndpoint,
}

impl TerminalChannelPair {
    pub(super) fn new() -> Result<Self, TerminalError> {
        let (coordinator, guardian) = create_terminal_socket_pair()?;
        set_and_verify_close_on_exec(&coordinator)?;
        set_and_verify_close_on_exec(&guardian)?;
        Ok(Self {
            coordinator: TerminalEndpoint::adopt(coordinator)?,
            guardian: TerminalEndpoint::adopt(guardian)?,
        })
    }

    pub(super) fn split(self) -> (TerminalEndpoint, TerminalEndpoint) {
        (self.coordinator, self.guardian)
    }

    pub(super) fn coordinator_identity(
        &self,
    ) -> Result<calcifer_unix_child_fd::DescriptorIdentity, TerminalError> {
        self.coordinator.descriptor_identity()
    }

    pub(super) fn guardian_identity(
        &self,
    ) -> Result<calcifer_unix_child_fd::DescriptorIdentity, TerminalError> {
        self.guardian.descriptor_identity()
    }
}

impl fmt::Debug for TerminalChannelPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.coordinator, &self.guardian);
        formatter.write_str("TerminalChannelPair(<redacted>)")
    }
}

/// One non-cloneable terminal-byte endpoint.
#[must_use = "dropping the terminal endpoint changes pump liveness"]
pub(super) struct TerminalEndpoint {
    stream: UnixStream,
    send_flags: SendFlags,
}

impl TerminalEndpoint {
    fn adopt(stream: UnixStream) -> Result<Self, TerminalError> {
        verify_close_on_exec(&stream)?;
        verify_terminal_endpoint(&stream)?;
        let send_flags = terminal_send_flags(&stream)?;
        Ok(Self { stream, send_flags })
    }

    /// Moves inherited guardian stdout into one owned terminal-byte endpoint.
    ///
    /// The audited helper replaces fd 1 with close-on-exec `/dev/null` only
    /// after proving that fd 1 and this duplicate are the exact two references
    /// to the inherited endpoint identity.
    pub(super) fn bootstrap_from_inherited_stdout() -> Result<Self, TerminalError> {
        let stdout = io::stdout();
        let (duplicate, expected_identity) = {
            let inherited = stdout.as_fd();
            let expected_identity = read_descriptor_identity(inherited)?;
            let duplicate = fcntl_dupfd_cloexec(inherited, 3)
                .map_err(|_| TerminalError::DescriptorDuplicate)?;
            (duplicate, expected_identity)
        };
        calcifer_unix_child_fd::replace_inherited_stdout_with_dev_null(expected_identity)
            .map_err(|_| TerminalError::DescriptorDuplicate)?;
        verify_close_on_exec(&duplicate)?;
        let endpoint = Self::adopt(UnixStream::from(duplicate))?;
        if endpoint.descriptor_identity()? != expected_identity {
            return Err(TerminalError::TerminalIdentityMismatch);
        }
        Ok(endpoint)
    }

    pub(super) fn descriptor_identity(
        &self,
    ) -> Result<calcifer_unix_child_fd::DescriptorIdentity, TerminalError> {
        calcifer_unix_child_fd::descriptor_identity(self.stream.as_fd())
            .map_err(|_| TerminalError::DescriptorIdentity)
    }

    /// Appends the guardian terminal channel to one source-pinned child
    /// denyset without exposing its raw descriptor or kernel identity.
    pub(super) fn append_forbidden_descriptor<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        forbidden.capture(self.stream.as_fd())
    }

    pub(super) fn verify_invariants(&self) -> Result<(), TerminalError> {
        verify_close_on_exec(&self.stream)?;
        verify_terminal_endpoint(&self.stream)
    }

    #[cfg(test)]
    pub(super) fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), TerminalError> {
        self.stream
            .set_read_timeout(timeout)
            .map_err(|_| TerminalError::TimeoutConfiguration)
    }

    pub(super) fn read_into<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, TerminalError> {
        let mut stream = &self.stream;
        read_fixed(&mut stream, buffer, false)
    }

    pub(super) fn try_write(
        &self,
        chunk: &mut TerminalChunk<'_>,
    ) -> Result<TerminalWrite, TerminalError> {
        loop {
            match rustix::net::send(&self.stream, chunk.remaining_bytes(), self.send_flags) {
                Ok(length) => return chunk.record_write(length),
                Err(rustix::io::Errno::INTR) => {}
                Err(rustix::io::Errno::AGAIN) => return Ok(TerminalWrite::WouldBlock),
                Err(_) => return Err(TerminalError::Write),
            }
        }
    }

    pub(super) fn enable_nonblocking(&self) -> Result<(), TerminalError> {
        enable_nonblocking_checked(&self.stream)
    }

    pub(super) fn shutdown(&self, direction: TerminalShutdown) -> Result<(), TerminalError> {
        match self.stream.shutdown(direction.into()) {
            Ok(()) => Ok(()),
            // The endpoint is non-cloneable and was adopted only after an exact
            // connected-peer check. Once that exact peer closes, Darwin reports
            // ENOTCONN for SHUT_WR even though no local write can reach a peer.
            // Treat only that typed write-half condition as an idempotent close;
            // SHUT_RDWR and every other error remain fail-closed.
            Err(error)
                if direction == TerminalShutdown::Write
                    && error.kind() == io::ErrorKind::NotConnected =>
            {
                Ok(())
            }
            Err(_) => Err(TerminalError::Shutdown),
        }
    }

    /// Moves the endpoint into one guardian standard stream. The guardian must
    /// immediately bootstrap it back into a private close-on-exec descriptor.
    pub(super) fn into_stdio(self) -> Result<Stdio, TerminalError> {
        self.verify_invariants()?;
        Ok(Stdio::from(OwnedFd::from(self.stream)))
    }
}

impl fmt::Debug for TerminalEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.stream, self.send_flags);
        formatter.write_str("TerminalEndpoint(<redacted>)")
    }
}

impl AsFd for TerminalEndpoint {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminalShutdown {
    Write,
    Both,
}

impl From<TerminalShutdown> for Shutdown {
    fn from(direction: TerminalShutdown) -> Self {
        match direction {
            TerminalShutdown::Write => Self::Write,
            TerminalShutdown::Both => Self::Both,
        }
    }
}

/// Type-state marker for a gate with no trusted readiness capability.
pub(super) enum GateClosed {}

/// Type-state marker for a ready TUI whose ingress is still physically closed.
pub(super) enum GateReady {}

/// Type-state marker produced only after the open-gate acknowledgement.
pub(super) enum GateOpen {}

/// Linear input-gate capability. No state implements `Clone` or `Copy`, and
/// transitions consume the previous state.
#[must_use = "dropping an input-gate capability closes that transition path"]
pub(super) struct InputGate<State> {
    state: PhantomData<State>,
}

impl InputGate<GateClosed> {
    pub(super) const fn closed() -> Self {
        Self { state: PhantomData }
    }

    /// Consumes the closed state after higher-level readiness validation.
    pub(super) const fn mark_ready(self, readiness: VerifiedReady) -> InputGate<GateReady> {
        let _ = (self, readiness);
        InputGate { state: PhantomData }
    }
}

impl InputGate<GateReady> {
    /// Consumes the ready state and raw-mode proof only after the bounded
    /// `OPEN_GATE` ACK. It is impossible to mint an open gate without first
    /// obtaining the proof from `enter_raw_after_input_flush`.
    pub(super) const fn acknowledge_open(
        self,
        raw_terminal: RawTerminalProof,
        acknowledgement: VerifiedOpenGateAck,
    ) -> InputGate<GateOpen> {
        let _ = (self, raw_terminal, acknowledgement);
        InputGate { state: PhantomData }
    }
}

impl fmt::Debug for InputGate<GateClosed> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputGate<Closed>")
    }
}

impl fmt::Debug for InputGate<GateReady> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputGate<Ready>")
    }
}

impl fmt::Debug for InputGate<GateOpen> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputGate<Open>")
    }
}

#[cfg(target_os = "linux")]
fn open_master() -> Result<OwnedFd, TerminalError> {
    rustix::pty::openpt(
        rustix::pty::OpenptFlags::RDWR
            | rustix::pty::OpenptFlags::NOCTTY
            | rustix::pty::OpenptFlags::CLOEXEC,
    )
    .map_err(|_| TerminalError::OpenPty)
}

#[cfg(target_os = "macos")]
fn open_master() -> Result<OwnedFd, TerminalError> {
    // Darwin has no atomic `O_CLOEXEC` flag for `posix_openpt`. The descriptor
    // is marked and read back synchronously before this owner can spawn a
    // thread or child.
    rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)
        .map_err(|_| TerminalError::OpenPty)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_master() -> Result<OwnedFd, TerminalError> {
    Err(TerminalError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn create_terminal_socket_pair() -> Result<(UnixStream, UnixStream), TerminalError> {
    let (coordinator, guardian) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| TerminalError::ChannelCreate)?;
    Ok((UnixStream::from(coordinator), UnixStream::from(guardian)))
}

#[cfg(target_os = "macos")]
fn create_terminal_socket_pair() -> Result<(UnixStream, UnixStream), TerminalError> {
    // As with the lifecycle channel, both descriptors are synchronously marked
    // close-on-exec by `TerminalChannelPair::new` before they can escape.
    UnixStream::pair().map_err(|_| TerminalError::ChannelCreate)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn create_terminal_socket_pair() -> Result<(UnixStream, UnixStream), TerminalError> {
    Err(TerminalError::UnsupportedPlatform)
}

fn verify_terminal_endpoint<Fd: AsFd>(descriptor: Fd) -> Result<(), TerminalError> {
    let socket_type =
        rustix::net::sockopt::socket_type(&descriptor).map_err(|_| TerminalError::InvalidSocket)?;
    if socket_type != SocketType::STREAM {
        return Err(TerminalError::InvalidSocketType);
    }
    let local = rustix::net::getsockname(&descriptor).map_err(|_| TerminalError::InvalidSocket)?;
    if local.address_family() != AddressFamily::UNIX {
        return Err(TerminalError::InvalidSocketDomain);
    }
    let peer = rustix::net::getpeername(descriptor).map_err(|_| TerminalError::MissingPeer)?;
    match peer {
        Some(peer) if peer.address_family() == AddressFamily::UNIX => Ok(()),
        Some(_) => Err(TerminalError::InvalidPeerDomain),
        // Darwin represents an unnamed connected socketpair peer with a zero
        // address length. An unconnected stream fails `getpeername` above.
        None => Ok(()),
    }
}

#[cfg(target_os = "linux")]
fn terminal_send_flags<Fd: AsFd>(descriptor: Fd) -> Result<SendFlags, TerminalError> {
    let _ = descriptor;
    Ok(SendFlags::NOSIGNAL)
}

#[cfg(target_os = "macos")]
fn terminal_send_flags<Fd: AsFd>(descriptor: Fd) -> Result<SendFlags, TerminalError> {
    rustix::net::sockopt::set_socket_nosigpipe(&descriptor, true)
        .map_err(|_| TerminalError::SignalSafety)?;
    if !rustix::net::sockopt::socket_nosigpipe(descriptor)
        .map_err(|_| TerminalError::SignalSafety)?
    {
        return Err(TerminalError::SignalSafety);
    }
    Ok(SendFlags::empty())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn terminal_send_flags<Fd: AsFd>(descriptor: Fd) -> Result<SendFlags, TerminalError> {
    let _ = descriptor;
    Err(TerminalError::UnsupportedPlatform)
}

fn read_fixed<'buffer, R: Read>(
    reader: &mut R,
    buffer: &'buffer mut TerminalBuffer,
    normalize_pty_eio: bool,
) -> Result<TerminalRead<'buffer>, TerminalError> {
    loop {
        match reader.read(&mut buffer.bytes) {
            // Only a successfully reported prefix is terminal payload. A
            // reader can mutate this initialized buffer before returning a
            // short length or an error, so every unreported byte is erased.
            Ok(0) => {
                buffer.bytes.fill(0);
                return Ok(TerminalRead::EndOfStream);
            }
            Ok(length) => {
                buffer.bytes[length..].fill(0);
                return Ok(TerminalRead::Data(TerminalChunk::new(
                    &mut buffer.bytes[..length],
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                buffer.bytes.fill(0);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                buffer.bytes.fill(0);
                return Ok(TerminalRead::WouldBlock);
            }
            Err(error)
                if normalize_pty_eio
                    && error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) =>
            {
                buffer.bytes.fill(0);
                return Ok(TerminalRead::EndOfStream);
            }
            Err(_) => {
                buffer.bytes.fill(0);
                return Err(TerminalError::Read);
            }
        }
    }
}

fn try_write_file<W: Write>(
    writer: &mut W,
    chunk: &mut TerminalChunk<'_>,
) -> Result<TerminalWrite, TerminalError> {
    loop {
        match writer.write(chunk.remaining_bytes()) {
            Ok(length) => return chunk.record_write(length),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(TerminalWrite::WouldBlock);
            }
            Err(_) => return Err(TerminalError::Write),
        }
    }
}

fn enable_nonblocking_checked<Fd: AsFd>(descriptor: Fd) -> Result<(), TerminalError> {
    rustix::io::ioctl_fionbio(&descriptor, true)
        .map_err(|_| TerminalError::NonblockingConfiguration)?;
    let flags =
        rustix::fs::fcntl_getfl(descriptor).map_err(|_| TerminalError::NonblockingReadback)?;
    if flags.contains(rustix::fs::OFlags::NONBLOCK) {
        Ok(())
    } else {
        Err(TerminalError::NonblockingMismatch)
    }
}

fn set_and_verify_close_on_exec<Fd: AsFd>(descriptor: Fd) -> Result<(), TerminalError> {
    let flags = fcntl_getfd(&descriptor).map_err(|_| TerminalError::DescriptorFlags)?;
    fcntl_setfd(&descriptor, flags | FdFlags::CLOEXEC)
        .map_err(|_| TerminalError::DescriptorFlags)?;
    verify_close_on_exec(descriptor)
}

fn verify_close_on_exec<Fd: AsFd>(descriptor: Fd) -> Result<(), TerminalError> {
    let flags = fcntl_getfd(descriptor).map_err(|_| TerminalError::DescriptorFlags)?;
    if flags.contains(FdFlags::CLOEXEC) {
        Ok(())
    } else {
        Err(TerminalError::DescriptorInheritable)
    }
}

/// A bounded, redacted terminal-boundary failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum TerminalError {
    OpenPty,
    GrantPty,
    UnlockPty,
    SlaveName,
    SlaveOpen,
    DescriptorFlags,
    DescriptorInheritable,
    DescriptorDuplicate,
    DescriptorIdentity,
    TtyName,
    TtyOpen,
    NonblockingConfiguration,
    NonblockingReadback,
    NonblockingMismatch,
    WindowSizeRead,
    WindowSizeWrite,
    WindowSizeMismatch,
    NotTerminal,
    CreateSession,
    ClaimControllingTerminal,
    SessionIdentity,
    ForegroundIdentity,
    ControllingTerminalMismatch,
    NotForegroundProcessGroup,
    TerminalAttributesRead,
    TerminalIdentityMismatch,
    SnapshotChanged,
    InputFlush,
    RawModeApply,
    RawModeMismatch,
    RawModeRollback,
    RestoreApply,
    RestoreMismatch,
    #[cfg(test)]
    EmptyChunk,
    #[cfg(test)]
    ChunkTooLarge,
    Read,
    Write,
    ChannelCreate,
    InvalidSocket,
    InvalidSocketType,
    InvalidSocketDomain,
    InvalidPeerDomain,
    MissingPeer,
    SignalSafety,
    #[cfg(test)]
    TimeoutConfiguration,
    Shutdown,
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    UnsupportedPlatform,
    RecoveryAuthorityMismatch,
}

impl TerminalError {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::OpenPty => "open_pty",
            Self::GrantPty => "grant_pty",
            Self::UnlockPty => "unlock_pty",
            Self::SlaveName => "slave_name",
            Self::SlaveOpen => "slave_open",
            Self::DescriptorFlags => "descriptor_flags",
            Self::DescriptorInheritable => "descriptor_inheritable",
            Self::DescriptorDuplicate => "descriptor_duplicate",
            Self::DescriptorIdentity => "descriptor_identity",
            Self::TtyName => "tty_name",
            Self::TtyOpen => "tty_open",
            Self::NonblockingConfiguration => "nonblocking_configuration",
            Self::NonblockingReadback => "nonblocking_readback",
            Self::NonblockingMismatch => "nonblocking_mismatch",
            Self::WindowSizeRead => "window_size_read",
            Self::WindowSizeWrite => "window_size_write",
            Self::WindowSizeMismatch => "window_size_mismatch",
            Self::NotTerminal => "not_terminal",
            Self::CreateSession => "create_session",
            Self::ClaimControllingTerminal => "claim_controlling_terminal",
            Self::SessionIdentity => "session_identity",
            Self::ForegroundIdentity => "foreground_identity",
            Self::ControllingTerminalMismatch => "controlling_terminal_mismatch",
            Self::NotForegroundProcessGroup => "not_foreground_process_group",
            Self::TerminalAttributesRead => "terminal_attributes_read",
            Self::TerminalIdentityMismatch => "terminal_identity_mismatch",
            Self::SnapshotChanged => "snapshot_changed",
            Self::InputFlush => "input_flush",
            Self::RawModeApply => "raw_mode_apply",
            Self::RawModeMismatch => "raw_mode_mismatch",
            Self::RawModeRollback => "raw_mode_rollback",
            Self::RestoreApply => "restore_apply",
            Self::RestoreMismatch => "restore_mismatch",
            #[cfg(test)]
            Self::EmptyChunk => "empty_chunk",
            #[cfg(test)]
            Self::ChunkTooLarge => "chunk_too_large",
            Self::Read => "read",
            Self::Write => "write",
            Self::ChannelCreate => "channel_create",
            Self::InvalidSocket => "invalid_socket",
            Self::InvalidSocketType => "invalid_socket_type",
            Self::InvalidSocketDomain => "invalid_socket_domain",
            Self::InvalidPeerDomain => "invalid_peer_domain",
            Self::MissingPeer => "missing_peer",
            Self::SignalSafety => "signal_safety",
            #[cfg(test)]
            Self::TimeoutConfiguration => "timeout_configuration",
            Self::Shutdown => "shutdown",
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::RecoveryAuthorityMismatch => "recovery_authority_mismatch",
        }
    }
}

impl fmt::Debug for TerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TerminalError")
            .field(&self.code())
            .finish()
    }
}

impl fmt::Display for TerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the supervised terminal boundary failed")
    }
}

impl std::error::Error for TerminalError {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;
    use std::mem::size_of;
    use std::os::unix::process::CommandExt;
    use std::process::Child;
    use std::sync::{Arc, Barrier};
    use std::time::Instant;

    const CHILD_HELPER_ENV: &str = "CALCIFER_TERMINAL_CHILD_HELPER";
    const CHILD_MARKER: &[u8] = b"calcifer-terminal-child-ok";
    const RESTORE_FLUSH_HELPER_ENV: &str = "CALCIFER_TERMINAL_RESTORE_FLUSH_HELPER";
    const RESTORE_FLUSH_READY: &[u8] = b"calcifer-terminal-restore-flush-ready";
    const RESTORE_FLUSH_RESTORED: &[u8] = b"calcifer-terminal-restore-flush-restored";
    const RESTORE_FLUSH_SENTINEL: &[u8] = b"calcifer-queued-input-sentinel";
    const RESTORE_FLUSH_PROBE: &[u8] = b"\n";
    const PTY_SCAN_HELPER_ENV: &str = "CALCIFER_TERMINAL_PTY_SCAN_HELPER";
    const PTY_SCAN_READY: [u8; 1] = [b'R'];

    struct PtyScanGroup {
        child: Child,
        process_group: i32,
    }

    impl Drop for PtyScanGroup {
        fn drop(&mut self) {
            if let Some(process_group) = rustix::process::Pid::from_raw(self.process_group) {
                let _ = rustix::process::kill_process_group(
                    process_group,
                    rustix::process::Signal::KILL,
                );
            }
            let _ = self.child.wait();
        }
    }

    #[test]
    fn pty_pair_is_cloexec_and_preserves_initial_size() -> Result<(), Box<dyn Error>> {
        let expected = TerminalSize::new(37, 109);
        let pair = PtyOwner::open(expected)?;

        pair.verify_close_on_exec()?;
        assert_eq!(pair.size()?, expected);
        Ok(())
    }

    #[test]
    fn pty_master_resize_round_trips() -> Result<(), Box<dyn Error>> {
        let owner = PtyOwner::open(TerminalSize::new(24, 80))?;
        let mut command = Command::new("/usr/bin/true");
        let master = owner.configure_child(&mut command)?;

        let resized = TerminalSize::with_pixels(51, 132, 640, 480);
        master.set_size(resized)?;
        assert_eq!(master.size()?, resized);
        master.verify_close_on_exec()?;
        assert_ne!(master.descriptor_identity()?.inode, 0);
        Ok(())
    }

    #[test]
    fn forbidden_pty_master_does_not_alias_the_child_and_descendant_slave()
    -> Result<(), Box<dyn Error>> {
        if std::env::var_os(PTY_SCAN_HELPER_ENV).is_some() {
            let inherited = calcifer_unix_child_fd::take_inherited_readiness_fd()?;
            let mut descendant_command = Command::new("/bin/sleep");
            descendant_command.arg("30").env_remove(PTY_SCAN_HELPER_ENV);
            calcifer_unix_child_fd::scrub_readiness_fd_env(&mut descendant_command);
            let mut descendant = descendant_command.spawn()?;

            // Command::spawn has observed the descendant's successful exec,
            // and shutdown publishes EOF without closing either of this
            // leader's stable socket descriptors. The parent can therefore
            // begin its double snapshot without a readiness-related FD-table
            // mutation still pending in either process-group member.
            let mut readiness = UnixStream::from(inherited);
            readiness.write_all(&PTY_SCAN_READY)?;
            readiness.shutdown(Shutdown::Write)?;
            if !descendant.wait()?.success() {
                return Err("PTY scan descendant did not exit successfully".into());
            }
            return Ok(());
        }

        let owner = PtyOwner::open(TerminalSize::new(24, 80))?;
        let slave_copy = fcntl_dupfd_cloexec(&owner.slave, 3)?;
        let mut slave_forbidden = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        slave_forbidden.capture(slave_copy.as_fd())?;

        let (mut readiness_observer, inherited_readiness) = UnixStream::pair()?;
        readiness_observer.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "providers::codex::supervisor::terminal::tests::forbidden_pty_master_does_not_alias_the_child_and_descendant_slave",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PTY_SCAN_HELPER_ENV, "1")
            .process_group(0);
        let master = owner.configure_child(&mut command)?;
        let master_forbidden = master.capture_forbidden_descriptor_set_before_tui()?;
        let child = match calcifer_unix_child_fd::spawn_with_inherited_readiness_fd(
            command,
            inherited_readiness.as_fd(),
        ) {
            Ok(child) => child,
            Err(error) => {
                // A parent-side inheritance readback failure can race the
                // helper spawning its descendant. Transfer any started direct
                // child into the group-wide owner before returning so the
                // generic direct-child fallback cannot leave that descendant
                // alive until its sleep expires.
                if let Some(started) = error.into_started_child() {
                    let mut child = started.into_child();
                    let process_group = match i32::try_from(child.id()) {
                        Ok(process_group) => process_group,
                        Err(_) => {
                            let _ = child.kill();
                            child.wait()?;
                            return Err("PTY scan child process group was invalid".into());
                        }
                    };
                    drop(PtyScanGroup {
                        child,
                        process_group,
                    });
                }
                return Err("PTY scan child failed during inherited descriptor setup".into());
            }
        };
        drop(inherited_readiness);
        let process_group = i32::try_from(child.id())?;
        let group = PtyScanGroup {
            child,
            process_group,
        };
        let mut ready = [0_u8; PTY_SCAN_READY.len()];
        readiness_observer.read_exact(&mut ready)?;
        if ready != PTY_SCAN_READY {
            return Err("PTY scan child published invalid readiness".into());
        }
        let mut trailing = [0_u8; 1];
        if readiness_observer.read(&mut trailing)? != 0 {
            return Err("PTY scan child published trailing readiness data".into());
        }

        // Readiness has its own socket timeout. Start the scanner's absolute
        // deadline only after the complete byte-plus-EOF boundary so a loaded
        // runner cannot consume the descriptor-proof budget while waiting for
        // the child to finish its post-exec handshake.
        let deadline = Instant::now() + Duration::from_secs(5);
        let proof =
            calcifer_unix_child_fd::verify_process_group_forbidden_descriptors_absent_before(
                group.process_group,
                &master_forbidden,
                deadline,
            )?;
        assert_eq!(proof.member_count(), 2);
        assert_eq!(
            calcifer_unix_child_fd::verify_process_group_forbidden_descriptors_absent_before(
                group.process_group,
                &slave_forbidden,
                deadline,
            ),
            Err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ForbiddenDescriptor)
        );
        Ok(())
    }

    #[test]
    fn configured_child_claims_controlling_terminal_and_initial_size() -> Result<(), Box<dyn Error>>
    {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "providers::codex::supervisor::terminal::tests::pty_child_helper",
                "--nocapture",
            ])
            .env(CHILD_HELPER_ENV, "1");
        let owner = PtyOwner::open(TerminalSize::new(41, 117))?;
        let mut master = owner.configure_child(&mut command)?;
        // Keep an independent master reference until the exact child wait is
        // complete. The drainer may observe the final marker before the child
        // executes its success exit; dropping the last master in that window
        // sends SIGHUP to the controlling session on Linux.
        let master_keepalive = master.descriptor.try_clone()?;
        let mut child = command.spawn()?;
        drop(command);
        let drainer = std::thread::spawn(move || drain_for_marker(&mut master, CHILD_MARKER));

        let status = child.wait()?;
        drop(master_keepalive);
        let saw_marker = drainer
            .join()
            .map_err(|_| "terminal child drainer panicked")??;
        assert!(status.success(), "terminal child exit was {status:?}");
        assert!(saw_marker);
        Ok(())
    }

    #[test]
    fn pty_child_helper() {
        if std::env::var_os(CHILD_HELPER_ENV).is_none() {
            return;
        }

        let Ok(proof) = claim_controlling_terminal_from_stdin() else {
            std::process::exit(71);
        };
        if proof.process() != proof.process_group()
            || proof.process() != proof.session()
            || proof.process() != proof.foreground_process_group()
        {
            std::process::exit(72);
        }
        if !rustix::termios::isatty(io::stdin())
            || !rustix::termios::isatty(io::stdout())
            || !rustix::termios::isatty(io::stderr())
        {
            std::process::exit(73);
        }
        if terminal_size(io::stdin()).ok() != Some(TerminalSize::new(41, 117)) {
            std::process::exit(74);
        }
        let stdin_flags_before = match rustix::fs::fcntl_getfl(io::stdin()) {
            Ok(flags) => flags,
            Err(_) => std::process::exit(76),
        };
        let Ok(outer_tty) = TerminalTty::open_independent(io::stdin()) else {
            std::process::exit(76);
        };
        if outer_tty.descriptor_identity()
            != read_descriptor_identity(io::stdin().as_fd()).unwrap_or_else(|_| {
                std::process::exit(76);
            })
            || outer_tty.enable_nonblocking().is_err()
            || rustix::fs::fcntl_getfl(io::stdin()).ok() != Some(stdin_flags_before)
        {
            std::process::exit(76);
        }
        let mut empty_input = TerminalBuffer::new();
        if !matches!(
            outer_tty.read_into(&mut empty_input),
            Ok(TerminalRead::WouldBlock)
        ) {
            std::process::exit(76);
        }
        let Ok(snapshot) = TerminalSnapshot::capture(io::stdin()) else {
            std::process::exit(76);
        };
        if snapshot.size() != TerminalSize::new(41, 117)
            || snapshot.foreground_process_group() != proof.foreground_process_group()
            || format!("{snapshot:?}") != "TerminalSnapshot(<redacted>)"
        {
            std::process::exit(76);
        }
        let Ok(guardian_snapshot) = TerminalSnapshot::capture_for_recovery(
            io::stdin(),
            snapshot.foreground_process_group(),
        ) else {
            std::process::exit(76);
        };
        let fingerprint = snapshot.semantic_fingerprint();
        if guardian_snapshot.descriptor_identity() != snapshot.descriptor_identity()
            || !fingerprint.matches(guardian_snapshot.semantic_fingerprint())
            || format!("{fingerprint:?}") != "TerminalSnapshotFingerprint(<redacted>)"
        {
            std::process::exit(76);
        }
        let mut unstable_pendin = snapshot.clone();
        unstable_pendin
            .attributes
            .local_modes
            .insert(rustix::termios::LocalModes::PENDIN);
        if !fingerprint.matches(unstable_pendin.semantic_fingerprint()) {
            std::process::exit(76);
        }
        let mut changed_size = snapshot.clone();
        changed_size.size.rows = changed_size.size.rows.saturating_add(1);
        let mut changed_identity = snapshot.clone();
        changed_identity.descriptor_identity.inode ^= 1;
        if fingerprint.matches(changed_size.semantic_fingerprint())
            || fingerprint.matches(changed_identity.semantic_fingerprint())
        {
            std::process::exit(76);
        }
        let Ok(recovery) = RecoveryTty::duplicate(io::stdin()) else {
            std::process::exit(77);
        };
        let Ok(raw) = snapshot.enter_raw_after_input_flush(io::stdin()) else {
            std::process::exit(78);
        };
        if raw.descriptor_identity() != snapshot.descriptor_identity()
            || format!("{raw:?}") != "RawTerminalProof(<redacted>)"
        {
            std::process::exit(78);
        }
        let restored = match snapshot.restore_with_sigttou_block(io::stdin()) {
            Ok(restored) => restored,
            Err(error) => {
                std::process::exit(match error {
                    TerminalError::RestoreApply => 81,
                    TerminalError::RestoreMismatch => {
                        let Ok(readback) = rustix::termios::tcgetattr(io::stdin()) else {
                            std::process::exit(89);
                        };
                        90 + i32::from(
                            termios_mismatch_code(&snapshot.attributes, &readback).unwrap_or(9),
                        )
                    }
                    TerminalError::TerminalIdentityMismatch => 83,
                    _ => 84,
                });
            }
        };
        if restored.descriptor_identity() != snapshot.descriptor_identity()
            || format!("{restored:?}") != "RestoredTerminalProof(<redacted>)"
        {
            std::process::exit(79);
        }
        if recovery.restore_with_sigttou_block(&snapshot).is_err() {
            std::process::exit(80);
        }
        let mut marker_buffer = TerminalBuffer::new();
        let Ok(mut marker) = marker_buffer.load(CHILD_MARKER) else {
            std::process::exit(75);
        };
        if outer_tty.try_write(&mut marker).ok() != Some(TerminalWrite::Complete) {
            std::process::exit(75);
        }
        // Make the parent-side master-lifetime contract deterministic: the
        // child must remain attached briefly after publishing its last byte.
        std::thread::sleep(Duration::from_millis(50));
        std::process::exit(0);
    }

    #[test]
    fn restore_discards_input_queued_after_pump_quiescence() -> Result<(), Box<dyn Error>> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "providers::codex::supervisor::terminal::tests::restore_flush_child_helper",
                "--nocapture",
            ])
            .env(RESTORE_FLUSH_HELPER_ENV, "1");
        let owner = PtyOwner::open(TerminalSize::new(24, 80))?;
        let mut master = owner.configure_child(&mut command)?;
        let mut child = command.spawn()?;
        drop(command);

        assert!(drain_for_marker(&mut master, RESTORE_FLUSH_READY)?);
        let mut sentinel_buffer = TerminalBuffer::new();
        let mut sentinel = sentinel_buffer.load(RESTORE_FLUSH_SENTINEL)?;
        assert_eq!(master.try_write(&mut sentinel)?, TerminalWrite::Complete);

        assert!(drain_for_marker(&mut master, RESTORE_FLUSH_RESTORED)?);
        let mut probe_buffer = TerminalBuffer::new();
        let mut probe = probe_buffer.load(RESTORE_FLUSH_PROBE)?;
        assert_eq!(master.try_write(&mut probe)?, TerminalWrite::Complete);

        // Retain the sole master through exact wait. The child must verify the
        // slave queue after restoration before this descriptor can close.
        let status = child.wait()?;
        assert!(status.success(), "terminal child exit was {status:?}");
        Ok(())
    }

    #[test]
    fn restore_flush_child_helper() {
        if std::env::var_os(RESTORE_FLUSH_HELPER_ENV).is_none() {
            return;
        }

        if claim_controlling_terminal_from_stdin().is_err() {
            std::process::exit(101);
        }
        let Ok(snapshot) = TerminalSnapshot::capture(io::stdin()) else {
            std::process::exit(102);
        };
        let Ok(outer_tty) = TerminalTty::open_independent(io::stdin()) else {
            std::process::exit(103);
        };
        if snapshot.enter_raw_after_input_flush(io::stdin()).is_err() {
            std::process::exit(104);
        }

        let mut ready_buffer = TerminalBuffer::new();
        let Ok(mut ready) = ready_buffer.load(RESTORE_FLUSH_READY) else {
            std::process::exit(105);
        };
        if outer_tty.try_write(&mut ready).ok() != Some(TerminalWrite::Complete) {
            std::process::exit(106);
        }

        let stdin = io::stdin();
        if !wait_for_input(&stdin, Duration::from_secs(2)) {
            std::process::exit(108);
        }

        if snapshot.restore(&stdin).is_err() {
            std::process::exit(109);
        }
        let mut restored_buffer = TerminalBuffer::new();
        let Ok(mut restored) = restored_buffer.load(RESTORE_FLUSH_RESTORED) else {
            std::process::exit(110);
        };
        if outer_tty.try_write(&mut restored).ok() != Some(TerminalWrite::Complete) {
            std::process::exit(110);
        }

        if !wait_for_input(&stdin, Duration::from_secs(2)) {
            std::process::exit(111);
        }
        let mut received = TerminalBuffer::new();
        if !matches!(
            received.read_from(&mut io::stdin()),
            Ok(TerminalRead::Data(chunk)) if chunk.matches(RESTORE_FLUSH_PROBE)
        ) {
            std::process::exit(112);
        }
        std::process::exit(0);
    }

    #[test]
    fn closed_slave_normalizes_master_eof_or_eio() -> Result<(), Box<dyn Error>> {
        let owner = PtyOwner::open(TerminalSize::new(24, 80))?;
        let mut command = Command::new("/usr/bin/true");
        let master = owner.configure_child(&mut command)?;
        let mut child = command.spawn()?;
        drop(command);
        assert!(child.wait()?.success());

        let mut buffer = TerminalBuffer::new();
        assert!(matches!(
            master.read_into(&mut buffer)?,
            TerminalRead::EndOfStream
        ));
        Ok(())
    }

    #[test]
    fn nonblocking_pty_read_distinguishes_would_block_from_eof() -> Result<(), Box<dyn Error>> {
        let owner = PtyOwner::open(TerminalSize::new(24, 80))?;
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 0.1"]);
        let master = owner.configure_child(&mut command)?;
        master.enable_nonblocking()?;
        let mut child = command.spawn()?;
        drop(command);

        let mut buffer = TerminalBuffer::new();
        assert!(matches!(
            master.read_into(&mut buffer)?,
            TerminalRead::WouldBlock
        ));
        assert!(child.wait()?.success());
        assert!(matches!(
            master.read_into(&mut buffer)?,
            TerminalRead::EndOfStream
        ));
        Ok(())
    }

    #[test]
    fn terminal_buffer_is_fixed_bounded_and_redacted() -> Result<(), Box<dyn Error>> {
        assert_eq!(size_of::<TerminalBuffer>(), TERMINAL_BUFFER_CAPACITY);
        let mut buffer = TerminalBuffer::new();
        let chunk = buffer.load(&[0x53; TERMINAL_BUFFER_CAPACITY])?;
        assert_eq!(chunk.len(), TERMINAL_BUFFER_CAPACITY);
        assert_eq!(format!("{chunk:?}"), "TerminalChunk(<redacted>)");
        let read = TerminalRead::Data(chunk);
        assert_eq!(format!("{read:?}"), "Data(TerminalChunk(<redacted>))");
        drop(read);
        assert!(buffer.bytes.iter().all(|byte| *byte == 0));
        assert_eq!(format!("{buffer:?}"), "TerminalBuffer(<redacted>)");
        assert_eq!(
            TerminalError::Read.to_string(),
            "the supervised terminal boundary failed"
        );
        assert_eq!(
            format!("{:?}", TerminalError::Read),
            "TerminalError(\"read\")"
        );
        Ok(())
    }

    #[test]
    fn terminal_buffer_rejects_empty_and_oversized_input() {
        let mut buffer = TerminalBuffer::new();
        assert!(matches!(buffer.load(&[]), Err(TerminalError::EmptyChunk)));
        let oversized = [0_u8; TERMINAL_BUFFER_CAPACITY + 1];
        assert!(matches!(
            buffer.load(&oversized),
            Err(TerminalError::ChunkTooLarge)
        ));
    }

    #[test]
    fn failed_and_interrupted_reads_do_not_retain_unreported_bytes() -> Result<(), Box<dyn Error>> {
        struct InterruptedThenByte {
            interrupted: bool,
        }

        impl Read for InterruptedThenByte {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    bytes.fill(0x53);
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                bytes[0] = b'a';
                Ok(1)
            }
        }

        struct DirtyError(io::ErrorKind);

        impl Read for DirtyError {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                bytes.fill(0x53);
                Err(io::Error::from(self.0))
            }
        }

        let mut buffer = TerminalBuffer::new();
        let TerminalRead::Data(received) =
            buffer.read_from(&mut InterruptedThenByte { interrupted: false })?
        else {
            return Err("interrupted reader did not retry".into());
        };
        assert!(received.matches(b"a"));
        drop(received);
        assert!(buffer.bytes.iter().all(|byte| *byte == 0));

        assert!(matches!(
            buffer.read_from(&mut DirtyError(io::ErrorKind::WouldBlock))?,
            TerminalRead::WouldBlock
        ));
        assert!(buffer.bytes.iter().all(|byte| *byte == 0));

        assert!(matches!(
            buffer.read_from(&mut DirtyError(io::ErrorKind::Other)),
            Err(TerminalError::Read)
        ));
        assert!(buffer.bytes.iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn fixed_read_consumes_exactly_one_buffer_at_the_capacity_boundary()
    -> Result<(), Box<dyn Error>> {
        let input = [0x41; TERMINAL_BUFFER_CAPACITY + 1];
        let mut reader = input.as_slice();
        let mut buffer = TerminalBuffer::new();

        let TerminalRead::Data(first) = buffer.read_from(&mut reader)? else {
            return Err("capacity-sized read did not return data".into());
        };
        assert_eq!(first.len(), TERMINAL_BUFFER_CAPACITY);
        assert!(first.bytes().iter().all(|byte| *byte == 0x41));
        drop(first);
        assert!(buffer.bytes.iter().all(|byte| *byte == 0));

        let TerminalRead::Data(last) = buffer.read_from(&mut reader)? else {
            return Err("boundary byte was consumed by the first read".into());
        };
        assert_eq!(last.len(), 1);
        assert!(last.matches(b"A"));
        drop(last);
        assert!(buffer.bytes.iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn eio_is_eof_only_for_pty_reads() -> Result<(), Box<dyn Error>> {
        struct EioReader;

        impl Read for EioReader {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                bytes.fill(0x53);
                Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::IO.raw_os_error(),
                ))
            }
        }

        let mut buffer = TerminalBuffer::new();
        assert!(matches!(
            read_fixed(&mut EioReader, &mut buffer, false),
            Err(TerminalError::Read)
        ));
        assert!(buffer.bytes.iter().all(|byte| *byte == 0));

        assert!(matches!(
            read_fixed(&mut EioReader, &mut buffer, true)?,
            TerminalRead::EndOfStream
        ));
        assert!(buffer.bytes.iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn partial_write_keeps_only_a_fixed_buffer_offset_and_zeroes_progress()
    -> Result<(), Box<dyn Error>> {
        struct ThreeByteWriter;

        impl Write for ThreeByteWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len().min(3))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut buffer = TerminalBuffer::new();
        let mut chunk = buffer.load(b"abcdef")?;
        assert_eq!(
            try_write_file(&mut ThreeByteWriter, &mut chunk)?,
            TerminalWrite::Progress {
                written: 3,
                remaining: 3,
            }
        );
        assert_eq!(chunk.remaining(), 3);
        assert_eq!(&chunk.bytes()[..3], &[0; 3]);
        assert_eq!(
            try_write_file(&mut ThreeByteWriter, &mut chunk)?,
            TerminalWrite::Complete
        );
        drop(chunk);
        assert_eq!(&buffer.bytes[..6], &[0; 6]);
        Ok(())
    }

    #[test]
    fn nonblocking_terminal_channel_reports_would_block_without_allocating()
    -> Result<(), Box<dyn Error>> {
        let (coordinator, guardian) = TerminalChannelPair::new()?.split();
        coordinator.enable_nonblocking()?;
        guardian.enable_nonblocking()?;

        let mut read_buffer = TerminalBuffer::new();
        assert!(matches!(
            guardian.read_into(&mut read_buffer)?,
            TerminalRead::WouldBlock
        ));

        let payload = [0x5a; TERMINAL_BUFFER_CAPACITY];
        let mut write_buffer = TerminalBuffer::new();
        let mut chunk = write_buffer.load(&payload)?;
        let mut completed_chunks = 0_usize;
        let mut observed_backpressure = false;
        for _ in 0..4_096 {
            match coordinator.try_write(&mut chunk)? {
                TerminalWrite::Complete => {
                    completed_chunks += 1;
                    drop(chunk);
                    chunk = write_buffer.load(&payload)?;
                }
                TerminalWrite::Progress { .. } => {}
                TerminalWrite::WouldBlock => {
                    observed_backpressure = true;
                    break;
                }
            }
        }
        assert!(observed_backpressure);
        let remaining_at_backpressure = chunk.remaining();
        assert!(remaining_at_backpressure > 0);
        assert_eq!(
            coordinator.try_write(&mut chunk)?,
            TerminalWrite::WouldBlock
        );
        assert_eq!(chunk.remaining(), remaining_at_backpressure);

        let mut reverse_buffer = TerminalBuffer::new();
        let mut reverse = reverse_buffer.load(b"reverse-direction")?;
        assert_eq!(guardian.try_write(&mut reverse)?, TerminalWrite::Complete);
        drop(reverse);
        let TerminalRead::Data(reverse) = coordinator.read_into(&mut read_buffer)? else {
            return Err("reverse direction stalled under outbound backpressure".into());
        };
        assert!(reverse.matches(b"reverse-direction"));
        drop(reverse);

        let expected_bytes = (completed_chunks + 1) * TERMINAL_BUFFER_CAPACITY;
        let mut received_bytes = 0_usize;
        let mut pending_complete = false;
        for _ in 0..8_192 {
            match guardian.read_into(&mut read_buffer)? {
                TerminalRead::Data(received) => {
                    assert!(received.bytes().iter().all(|byte| *byte == 0x5a));
                    received_bytes += received.len();
                }
                TerminalRead::WouldBlock => {}
                TerminalRead::EndOfStream => {
                    return Err("terminal channel closed while draining backpressure".into());
                }
            }

            if !pending_complete {
                pending_complete =
                    matches!(coordinator.try_write(&mut chunk)?, TerminalWrite::Complete);
            }
            if pending_complete && received_bytes == expected_bytes {
                break;
            }
        }
        assert!(pending_complete);
        assert_eq!(received_bytes, expected_bytes);
        drop(chunk);
        assert!(write_buffer.bytes.iter().all(|byte| *byte == 0));
        assert!(read_buffer.bytes.iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn recovery_tty_bootstrap_replaces_stderr_and_owns_the_only_tty_reference()
    -> Result<(), Box<dyn Error>> {
        const CHILD_ENV: &str = "CALCIFER_TEST_RECOVERY_STDERR_BOOTSTRAP";

        if std::env::var_os(CHILD_ENV).is_some() {
            let inherited_identity = read_descriptor_identity(io::stderr().as_fd())?;
            assert!(rustix::termios::isatty(io::stderr()));
            assert_eq!(
                calcifer_unix_child_fd::count_open_descriptors_with_identity(inherited_identity)?,
                1
            );

            let recovery = RecoveryTty::bootstrap_from_inherited_stderr()?;
            recovery.verify_invariants()?;
            assert_eq!(recovery.descriptor_identity(), inherited_identity);
            assert_eq!(
                calcifer_unix_child_fd::count_open_descriptors_with_identity(inherited_identity)?,
                1
            );
            assert_ne!(
                read_descriptor_identity(io::stderr().as_fd())?,
                inherited_identity
            );
            assert!(fcntl_getfd(io::stderr())?.contains(FdFlags::CLOEXEC));
            assert!(!rustix::termios::isatty(io::stderr()));

            let disarmed = match recovery.disarm() {
                Ok(disarmed) => disarmed,
                Err(_) => return Err("sole recovery descriptor could not be disarmed".into()),
            };
            assert!(matches!(disarmed, RecoveryDisarmOutcome::Disarmed(_)));
            assert_eq!(
                calcifer_unix_child_fd::count_open_descriptors_with_identity(inherited_identity)?,
                0
            );
            return Ok(());
        }

        let owner = PtyOwner::open(TerminalSize::new(24, 80))?;
        let recovery = RecoveryTty::duplicate(&owner.slave)?;
        recovery.verify_invariants()?;
        assert_eq!(
            recovery.descriptor_identity(),
            read_descriptor_identity(owner.slave.as_fd())?
        );
        assert_eq!(format!("{recovery:?}"), "RecoveryTty(<redacted>)");

        let child_recovery = RecoveryTty::duplicate(&owner.slave)?;
        let mut child = Command::new(std::env::current_exe()?)
            .arg("recovery_tty_bootstrap_replaces_stderr_and_owns_the_only_tty_reference")
            .arg("--test-threads=1")
            .env(CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(child_recovery.into_stdio()?)
            .spawn()?;
        assert!(child.wait()?.success());
        Ok(())
    }

    #[test]
    fn post_close_disarm_scan_failure_retains_identity_until_zero_is_proved()
    -> Result<(), Box<dyn Error>> {
        let owner = PtyOwner::open(TerminalSize::new(24, 80))?;
        let recovery = RecoveryTty::duplicate(&owner.slave)?;
        let identity = recovery.descriptor_identity();
        let mut observations = [Ok(1), Err(TerminalError::RecoveryAuthorityMismatch)].into_iter();

        let first = recovery.disarm_with_scan(|observed| {
            assert_eq!(observed, identity);
            observations
                .next()
                .ok_or(TerminalError::RecoveryAuthorityMismatch)?
        })?;
        let unconfirmed = match first {
            RecoveryDisarmOutcome::Unconfirmed(owner) => owner,
            RecoveryDisarmOutcome::Disarmed(_) => {
                return Err("post-close scan failure fabricated a proof".into());
            }
        };
        assert_eq!(
            format!("{unconfirmed:?}"),
            "RecoveryDisarmUnconfirmed(<redacted>)"
        );

        let still_open = unconfirmed.retry_once_with(|observed| {
            assert_eq!(observed, identity);
            Ok(1)
        });
        let unconfirmed = match still_open {
            RecoveryDisarmOutcome::Unconfirmed(owner) => owner,
            RecoveryDisarmOutcome::Disarmed(_) => {
                return Err("nonzero descriptor count fabricated a proof".into());
            }
        };
        let disarmed = unconfirmed.retry_once_with(|observed| {
            assert_eq!(observed, identity);
            Ok(0)
        });
        assert!(matches!(disarmed, RecoveryDisarmOutcome::Disarmed(_)));
        Ok(())
    }

    #[test]
    fn terminal_channel_is_cloexec_connected_duplex_and_distinct() -> Result<(), Box<dyn Error>> {
        let pair = TerminalChannelPair::new()?;
        let coordinator_identity = pair.coordinator_identity()?;
        let guardian_identity = pair.guardian_identity()?;
        assert_ne!(coordinator_identity.inode, 0);
        assert_ne!(guardian_identity.inode, 0);
        assert_ne!(coordinator_identity, guardian_identity);
        let (coordinator, guardian) = pair.split();
        coordinator.verify_invariants()?;
        guardian.verify_invariants()?;
        coordinator.set_read_timeout(Some(Duration::from_secs(2)))?;
        guardian.set_read_timeout(Some(Duration::from_secs(2)))?;

        let mut write_buffer = TerminalBuffer::new();
        let mut coordinator_chunk = write_buffer.load(b"coordinator")?;
        assert_eq!(
            coordinator.try_write(&mut coordinator_chunk)?,
            TerminalWrite::Complete
        );
        drop(coordinator_chunk);
        let mut read_buffer = TerminalBuffer::new();
        let TerminalRead::Data(received) = guardian.read_into(&mut read_buffer)? else {
            return Err("guardian observed an early terminal-channel EOF".into());
        };
        assert!(received.matches(b"coordinator"));
        drop(received);

        let mut guardian_chunk = write_buffer.load(b"guardian")?;
        assert_eq!(
            guardian.try_write(&mut guardian_chunk)?,
            TerminalWrite::Complete
        );
        let TerminalRead::Data(received) = coordinator.read_into(&mut read_buffer)? else {
            return Err("coordinator observed an early terminal-channel EOF".into());
        };
        assert!(received.matches(b"guardian"));
        Ok(())
    }

    #[test]
    fn terminal_endpoint_supports_write_while_its_reader_is_blocked() -> Result<(), Box<dyn Error>>
    {
        let (coordinator, guardian) = TerminalChannelPair::new()?.split();
        coordinator.set_read_timeout(Some(Duration::from_secs(2)))?;
        guardian.set_read_timeout(Some(Duration::from_secs(2)))?;
        let coordinator = Arc::new(coordinator);
        let reader_barrier = Arc::new(Barrier::new(2));

        let reader_endpoint = Arc::clone(&coordinator);
        let reader_started = Arc::clone(&reader_barrier);
        let reader = std::thread::spawn(move || -> Result<(), TerminalError> {
            let mut buffer = TerminalBuffer::new();
            reader_started.wait();
            let TerminalRead::Data(received) = reader_endpoint.read_into(&mut buffer)? else {
                return Err(TerminalError::Read);
            };
            if !received.matches(b"response") {
                return Err(TerminalError::Read);
            }
            Ok(())
        });

        reader_barrier.wait();
        std::thread::yield_now();
        let mut write_buffer = TerminalBuffer::new();
        let mut request = write_buffer.load(b"request")?;
        assert_eq!(
            coordinator.try_write(&mut request)?,
            TerminalWrite::Complete
        );
        drop(request);

        let mut read_buffer = TerminalBuffer::new();
        let TerminalRead::Data(request) = guardian.read_into(&mut read_buffer)? else {
            return Err("guardian did not receive concurrent request".into());
        };
        assert!(request.matches(b"request"));
        drop(request);

        let mut response = write_buffer.load(b"response")?;
        assert_eq!(guardian.try_write(&mut response)?, TerminalWrite::Complete);
        reader
            .join()
            .map_err(|_| "concurrent terminal reader panicked")??;
        Ok(())
    }

    #[test]
    fn terminal_endpoint_nonblocking_flag_is_descriptor_local() -> Result<(), Box<dyn Error>> {
        let (coordinator, guardian) = TerminalChannelPair::new()?.split();
        let guardian_flags = rustix::fs::fcntl_getfl(&guardian)?;
        assert!(!guardian_flags.contains(rustix::fs::OFlags::NONBLOCK));

        coordinator.enable_nonblocking()?;
        assert!(rustix::fs::fcntl_getfl(&coordinator)?.contains(rustix::fs::OFlags::NONBLOCK));
        assert_eq!(rustix::fs::fcntl_getfl(&guardian)?, guardian_flags);
        Ok(())
    }

    #[test]
    fn terminal_channel_bootstrap_replaces_stdout_and_owns_only_endpoint()
    -> Result<(), Box<dyn Error>> {
        const CHILD_ENV: &str = "CALCIFER_TEST_TERMINAL_STDOUT_BOOTSTRAP";

        if std::env::var_os(CHILD_ENV).is_some() {
            let inherited_identity = read_descriptor_identity(io::stdout().as_fd())?;
            assert_eq!(
                calcifer_unix_child_fd::count_open_descriptors_with_identity(inherited_identity)?,
                1
            );

            let endpoint = TerminalEndpoint::bootstrap_from_inherited_stdout()?;
            endpoint.verify_invariants()?;
            assert_eq!(endpoint.descriptor_identity()?, inherited_identity);
            assert_eq!(
                calcifer_unix_child_fd::count_open_descriptors_with_identity(inherited_identity)?,
                1
            );
            assert_ne!(
                read_descriptor_identity(io::stdout().as_fd())?,
                inherited_identity
            );
            assert!(fcntl_getfd(io::stdout())?.contains(FdFlags::CLOEXEC));
            assert!(!rustix::termios::isatty(io::stdout()));

            drop(endpoint);
            assert_eq!(
                calcifer_unix_child_fd::count_open_descriptors_with_identity(inherited_identity)?,
                0
            );
            return Ok(());
        }

        let (coordinator, guardian) = TerminalChannelPair::new()?.split();
        let mut child = Command::new(std::env::current_exe()?)
            .arg("terminal_channel_bootstrap_replaces_stdout_and_owns_only_endpoint")
            .arg("--test-threads=1")
            .env(CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(guardian.into_stdio()?)
            .stderr(Stdio::null())
            .spawn()?;
        assert!(child.wait()?.success());
        drop(coordinator);
        Ok(())
    }

    #[test]
    fn terminal_channel_shutdown_is_typed_eof_and_write_is_sigpipe_safe()
    -> Result<(), Box<dyn Error>> {
        let (coordinator, guardian) = TerminalChannelPair::new()?.split();
        coordinator.set_read_timeout(Some(Duration::from_secs(2)))?;
        guardian.shutdown(TerminalShutdown::Write)?;
        let mut buffer = TerminalBuffer::new();
        assert!(matches!(
            coordinator.read_into(&mut buffer)?,
            TerminalRead::EndOfStream
        ));

        // Darwin may accept one buffered send after peer EOF, while SHUT_RDWR
        // can report ENOTCONN once either write half is already closed. Close
        // exactly our remaining write half while the peer endpoint is still
        // live, making the SIGPIPE-safe post-EOF send result deterministic.
        coordinator.shutdown(TerminalShutdown::Write)?;
        drop(guardian);

        let mut chunk = buffer.load(b"peer-closed")?;
        assert_eq!(coordinator.try_write(&mut chunk), Err(TerminalError::Write));
        Ok(())
    }

    #[test]
    fn terminal_write_shutdown_is_idempotent_after_the_exact_peer_closes()
    -> Result<(), Box<dyn Error>> {
        let (coordinator, guardian) = TerminalChannelPair::new()?.split();
        drop(guardian);

        coordinator.shutdown(TerminalShutdown::Write)?;
        coordinator.shutdown(TerminalShutdown::Write)?;
        Ok(())
    }

    #[test]
    fn closed_input_gate_has_no_runtime_authority_or_storage() {
        let closed = InputGate::<GateClosed>::closed();
        assert_eq!(format!("{closed:?}"), "InputGate<Closed>");
        assert_eq!(size_of::<InputGate<GateClosed>>(), 0);
        assert_eq!(size_of::<InputGate<GateReady>>(), 0);
        assert_eq!(size_of::<InputGate<GateOpen>>(), 0);
    }

    fn drain_for_marker(master: &mut PtyMaster, marker: &[u8]) -> Result<bool, TerminalError> {
        let mut buffer = TerminalBuffer::new();
        let mut marker_index = 0_usize;
        loop {
            match master.read_into(&mut buffer)? {
                TerminalRead::EndOfStream => return Ok(marker_index == marker.len()),
                TerminalRead::WouldBlock => continue,
                TerminalRead::Data(chunk) => {
                    for byte in chunk.bytes() {
                        if *byte == marker[marker_index] {
                            marker_index += 1;
                            if marker_index == marker.len() {
                                return Ok(true);
                            }
                        } else {
                            marker_index = usize::from(*byte == marker[0]);
                        }
                    }
                }
            }
        }
    }

    fn wait_for_input<Fd: AsFd>(descriptor: Fd, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let Ok(timeout) = rustix::event::Timespec::try_from(remaining) else {
                return false;
            };
            let mut descriptors = [rustix::event::PollFd::new(
                &descriptor,
                rustix::event::PollFlags::IN,
            )];
            match rustix::event::poll(&mut descriptors, Some(&timeout)) {
                Ok(1) => {
                    let events = descriptors[0].revents();
                    if events.intersects(
                        rustix::event::PollFlags::ERR
                            | rustix::event::PollFlags::HUP
                            | rustix::event::PollFlags::NVAL,
                    ) {
                        return false;
                    }
                    if events.contains(rustix::event::PollFlags::IN) {
                        return true;
                    }
                }
                Ok(0) => return false,
                Ok(_) => return false,
                Err(rustix::io::Errno::INTR) => {}
                Err(_) => return false,
            }
        }
    }
}
