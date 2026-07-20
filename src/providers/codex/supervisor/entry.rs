//! Internal, foreground-only process entry for one production-shaped Codex
//! supervisor generation.
//!
//! This remains default-off until the public wrapper has a reviewed shell-job
//! contract. In particular, the hidden coordinator uses a process group that
//! differs from the anchor's shell job group; this module must not be exposed
//! as a general background-job implementation.

use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus};
use std::time::{Duration, Instant};

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};

const COMPLETION_FRAME: [u8; 8] = *b"CFCMP\x01\r\n";
const RETAINED_UNRECOVERABLE_FRAME: [u8; COMPLETION_FRAME.len()] = *b"CFRET\x01\r\n";
#[cfg(test)]
const TEST_CHECKPOINT_PHASE_OFFSET: usize = 5;
#[cfg(test)]
const TEST_CHECKPOINT_FRAME: [u8; 8] = *b"CFCP\x01\0\r\n";
const RECOVERY_REQUEST_REASON_OFFSET: usize = 6;
const RECOVERY_REQUEST_GENERATION_DEVICE_OFFSET: usize = 7;
const RECOVERY_REQUEST_GENERATION_INODE_OFFSET: usize = 15;
const RECOVERY_REQUEST_TERMINATOR_OFFSET: usize = 23;
// Fixed wire template. The generation slots remain zero until the anchor
// encodes the peer identity captured with the new socketpair.
const RECOVERY_REQUEST_FRAME: [u8; 25] = recovery_request_frame_template();
const ROLE_ENV: &str = "CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE";
const PROFILE_ID_ENV: &str = "CALCIFER_INTERNAL_CODEX_PROFILE_ID";
const THREAD_ID_ENV: &str = "CALCIFER_INTERNAL_CODEX_THREAD_ID";
const CODEX_EXECUTABLE_ENV: &str = "CALCIFER_INTERNAL_CODEX_EXECUTABLE";
const FOREGROUND_PROCESS_GROUP_ENV: &str = "CALCIFER_INTERNAL_CODEX_FOREGROUND_PROCESS_GROUP";
const ANCHOR_ROLE_V1: &str = "same-profile-anchor-v1";
const COORDINATOR_ROLE_V1: &str = "same-profile-coordinator-v1";
const GUARDIAN_ROLE_V1: &str = "same-profile-guardian-v1";
const MAX_PROFILE_ID_BYTES: usize = 64;
const MAX_THREAD_ID_BYTES: usize = 64;
const MAX_EXECUTABLE_PATH_BYTES: usize = 4_096;
const MAX_WORKING_DIRECTORY_BYTES: usize = 16 * 1024;
const INHERITED_COMPLETION_DESCRIPTOR_COUNT: usize = 2;
#[cfg(test)]
const TEST_CHECKPOINT_PEER_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Test-only synchronization observations. These values carry no recovery or
/// release authority; the real generation-bound CFRCR request remains the
/// only input that can authorize retained-generation recovery.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum RecoveryCheckpoint {
    StartupQueued = 1,
    Ready = 2,
    Active = 3,
    Suspended = 4,
    RetainedQuiescing = 5,
    RetainedRestorePending = 6,
    RetainedCleanupPending = 7,
}

#[cfg(test)]
const fn encode_test_checkpoint(
    checkpoint: RecoveryCheckpoint,
) -> [u8; TEST_CHECKPOINT_FRAME.len()] {
    let mut frame = TEST_CHECKPOINT_FRAME;
    frame[TEST_CHECKPOINT_PHASE_OFFSET] = checkpoint as u8;
    frame
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum RecoveryRequestReason {
    RetainedGeneration = 1,
}

impl RecoveryRequestReason {
    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            value if value == Self::RetainedGeneration as u8 => Some(Self::RetainedGeneration),
            _ => None,
        }
    }
}

const fn recovery_request_frame_template() -> [u8; 25] {
    let mut frame = [0_u8; 25];
    frame[0] = b'C';
    frame[1] = b'F';
    frame[2] = b'R';
    frame[3] = b'C';
    frame[4] = b'R';
    frame[5] = 1;
    frame[RECOVERY_REQUEST_REASON_OFFSET] = RecoveryRequestReason::RetainedGeneration as u8;
    frame[RECOVERY_REQUEST_TERMINATOR_OFFSET] = b'\r';
    frame[RECOVERY_REQUEST_TERMINATOR_OFFSET + 1] = b'\n';
    frame
}

fn encode_recovery_request_frame(
    generation: calcifer_unix_child_fd::DescriptorIdentity,
) -> [u8; RECOVERY_REQUEST_FRAME.len()] {
    let mut frame = RECOVERY_REQUEST_FRAME;
    frame[RECOVERY_REQUEST_GENERATION_DEVICE_OFFSET..RECOVERY_REQUEST_GENERATION_INODE_OFFSET]
        .copy_from_slice(&generation.device.to_be_bytes());
    frame[RECOVERY_REQUEST_GENERATION_INODE_OFFSET..RECOVERY_REQUEST_TERMINATOR_OFFSET]
        .copy_from_slice(&generation.inode.to_be_bytes());
    frame
}

fn recovery_request_frame_is_valid(
    frame: &[u8; RECOVERY_REQUEST_FRAME.len()],
    expected_generation: calcifer_unix_child_fd::DescriptorIdentity,
) -> bool {
    if frame[..RECOVERY_REQUEST_REASON_OFFSET]
        != RECOVERY_REQUEST_FRAME[..RECOVERY_REQUEST_REASON_OFFSET]
        || RecoveryRequestReason::from_wire(frame[RECOVERY_REQUEST_REASON_OFFSET])
            != Some(RecoveryRequestReason::RetainedGeneration)
        || frame[RECOVERY_REQUEST_TERMINATOR_OFFSET..]
            != RECOVERY_REQUEST_FRAME[RECOVERY_REQUEST_TERMINATOR_OFFSET..]
    {
        return false;
    }

    let mut device = [0_u8; size_of::<u64>()];
    device.copy_from_slice(
        &frame[RECOVERY_REQUEST_GENERATION_DEVICE_OFFSET..RECOVERY_REQUEST_GENERATION_INODE_OFFSET],
    );
    let mut inode = [0_u8; size_of::<u64>()];
    inode.copy_from_slice(
        &frame[RECOVERY_REQUEST_GENERATION_INODE_OFFSET..RECOVERY_REQUEST_TERMINATOR_OFFSET],
    );
    u64::from_be_bytes(device) == expected_generation.device
        && u64::from_be_bytes(inode) == expected_generation.inode
}

use crate::profiles::{Profile, Provider, Registry};

use super::channel::{LifecyclePair, spawn_guardian_with_lifecycle_stdin_and_completion};
use super::coordinator::{CoordinatorBounds, CoordinatorRunOutcome, ProductionCoordinator};
use super::coordinator_terminal::CoordinatorTerminal;
use super::guardian::{GuardianBounds, ProductionGuardianConfig, run_production_guardian};
use super::protocol::{GuardianExitDisposition, UnixSignal};
use super::signals::{CoordinatorSignalAction, CoordinatorSignalLatches};
use super::terminal::{
    RecoveryTty, TerminalChannelPair, TerminalSnapshot, claim_controlling_terminal_from_stdin,
};

/// Redacted completion-edge error. No descriptor number, kernel identity,
/// terminal state, profile, path, or provider payload reaches diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CompletionError {
    Create,
    Descriptor,
    Inherited,
    Io,
    MissingFrame,
    InvalidFrame,
    TrailingData,
    RecoveryDeadline,
    #[cfg_attr(not(test), allow(dead_code))]
    RecoveryPeerExited,
    #[cfg_attr(not(test), allow(dead_code))]
    RecoveryReplay,
    #[cfg_attr(not(test), allow(dead_code))]
    RecoveryTooLate,
}

impl fmt::Display for CompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the supervisor completion boundary failed")
    }
}

impl std::error::Error for CompletionError {}

/// One kernel socketpair connecting the persistent terminal anchor to the
/// coordinator/guardian generation. The sender half is never reconstructed
/// from its environment advertisement.
#[must_use = "the anchor and transit completion endpoints must be consumed"]
pub(super) struct CompletionPair {
    anchor: AnchorCompletion,
    transit: CompletionTransit,
}

impl CompletionPair {
    pub(super) fn new() -> Result<Self, CompletionError> {
        let (anchor, transit) = UnixStream::pair().map_err(|_| CompletionError::Create)?;
        set_close_on_exec(&anchor)?;
        set_close_on_exec(&transit)?;
        let transit = CompletionTransit::adopt(transit)?;
        let anchor = AnchorCompletion::adopt(anchor, transit.identity)?;
        Ok(Self { anchor, transit })
    }

    pub(super) fn split(self) -> (AnchorCompletion, CompletionTransit) {
        (self.anchor, self.transit)
    }
}

impl fmt::Debug for CompletionPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.anchor, &self.transit);
        formatter.write_str("CompletionPair(<redacted>)")
    }
}

/// The only endpoint whose provider-release frame plus EOF can release the
/// shell-facing anchor after exact coordinator wait. Its distinct retained
/// frame can only select fail-closed parking.
#[must_use = "the anchor completion endpoint must be verified or retained"]
pub(super) struct AnchorCompletion {
    stream: UnixStream,
    identity: calcifer_unix_child_fd::DescriptorIdentity,
    peer_identity: calcifer_unix_child_fd::DescriptorIdentity,
    frame: [u8; COMPLETION_FRAME.len()],
    received: usize,
    terminal_frame: Option<CompletionTerminalFrame>,
    terminal_error: Option<CompletionError>,
    recovery_request_consumed: bool,
    #[cfg(test)]
    completion_decode_started: bool,
    #[cfg(test)]
    test_checkpoint_terminal: TestCheckpointTerminal,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestCheckpointTerminal {
    Available,
    Verified,
    Failed(CompletionError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CompletionPoll {
    Pending,
    Verified,
    RetainedUnrecoverable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionTerminalFrame {
    ProviderReleased,
    RetainedUnrecoverable,
}

impl AnchorCompletion {
    fn adopt(
        stream: UnixStream,
        peer_identity: calcifer_unix_child_fd::DescriptorIdentity,
    ) -> Result<Self, CompletionError> {
        verify_close_on_exec(&stream)?;
        stream
            .set_nonblocking(true)
            .map_err(|_| CompletionError::Descriptor)?;
        let identity = descriptor_identity(&stream)?;
        Ok(Self {
            stream,
            identity,
            peer_identity,
            frame: [0; COMPLETION_FRAME.len()],
            received: 0,
            terminal_frame: None,
            terminal_error: None,
            recovery_request_consumed: false,
            #[cfg(test)]
            completion_decode_started: false,
            #[cfg(test)]
            test_checkpoint_terminal: TestCheckpointTerminal::Available,
        })
    }

    /// Advances one allocation-free read turn. Either terminal outcome
    /// requires its exact fixed frame and subsequent kernel EOF; EOF alone and
    /// any trailing byte are distinct failures.
    pub(super) fn poll_once(&mut self) -> Result<CompletionPoll, CompletionError> {
        #[cfg(test)]
        {
            self.completion_decode_started = true;
        }
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        let result = self.verify_identity().and_then(|()| {
            decode_completion_once(
                &mut self.stream,
                &mut self.frame,
                &mut self.received,
                &mut self.terminal_frame,
            )
        });
        self.finish_poll(result)
    }

    #[cfg(test)]
    fn poll_once_from_reader(
        &mut self,
        reader: &mut impl Read,
    ) -> Result<CompletionPoll, CompletionError> {
        self.completion_decode_started = true;
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        let result = decode_completion_once(
            reader,
            &mut self.frame,
            &mut self.received,
            &mut self.terminal_frame,
        );
        self.finish_poll(result)
    }

    /// Waits for one test-only lifecycle observation without borrowing any of
    /// the production completion decoder's buffer or terminal state. The
    /// sender must remain alive after the exact frame: immediate EOF is a
    /// failure, while immediate `WouldBlock` proves there is no trailing byte
    /// currently queued on the live peer.
    #[cfg(test)]
    pub(super) fn await_test_checkpoint(
        &mut self,
        expected: RecoveryCheckpoint,
        deadline: Instant,
    ) -> Result<(), CompletionError> {
        self.await_test_checkpoint_while_peer_live(expected, deadline, || Ok(true))
    }

    /// Waits in short slices so the package harness can fail closed when its
    /// exact coordinator child exits but another inherited descriptor keeps
    /// the stream from reporting EOF. The liveness observation is diagnostic
    /// only: it cannot authorize a recovery request or validate a frame.
    #[cfg(test)]
    pub(super) fn await_test_checkpoint_while_peer_live<F>(
        &mut self,
        expected: RecoveryCheckpoint,
        deadline: Instant,
        mut peer_live: F,
    ) -> Result<(), CompletionError>
    where
        F: FnMut() -> Result<bool, CompletionError>,
    {
        match self.test_checkpoint_terminal {
            TestCheckpointTerminal::Verified => return Err(CompletionError::RecoveryReplay),
            TestCheckpointTerminal::Failed(error) => return Err(error),
            TestCheckpointTerminal::Available => {}
        }
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        if self.completion_decode_started
            || self.received != 0
            || self.terminal_frame.is_some()
            || self.recovery_request_consumed
        {
            return Err(CompletionError::RecoveryTooLate);
        }

        let result = self
            .verify_identity()
            .and_then(|()| self.read_test_checkpoint(expected, deadline, &mut peer_live));
        self.test_checkpoint_terminal = match result {
            Ok(()) => TestCheckpointTerminal::Verified,
            Err(error) => {
                // A malformed synchronization frame must never fall through
                // into the production completion decoder as if the test seam
                // had not observed it.
                self.terminal_error = Some(error);
                TestCheckpointTerminal::Failed(error)
            }
        };
        result
    }

    #[cfg(test)]
    fn read_test_checkpoint<F>(
        &mut self,
        expected: RecoveryCheckpoint,
        deadline: Instant,
        peer_live: &mut F,
    ) -> Result<(), CompletionError>
    where
        F: FnMut() -> Result<bool, CompletionError>,
    {
        let mut frame = [0_u8; TEST_CHECKPOINT_FRAME.len()];
        let mut received = 0_usize;
        while received < frame.len() {
            let now = Instant::now();
            if now >= deadline {
                return Err(CompletionError::RecoveryDeadline);
            }
            let poll_deadline = now
                .checked_add(TEST_CHECKPOINT_PEER_POLL_INTERVAL)
                .map(|slice| slice.min(deadline))
                .unwrap_or(deadline);
            let Some(events) =
                poll_stream_before(&self.stream, rustix::event::PollFlags::IN, poll_deadline)?
            else {
                if Instant::now() >= deadline {
                    return Err(CompletionError::RecoveryDeadline);
                }
                if !peer_live()? {
                    return Err(CompletionError::RecoveryPeerExited);
                }
                continue;
            };
            if !events.intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP) {
                return Err(CompletionError::Io);
            }
            match self.stream.read(&mut frame[received..]) {
                Ok(0) => return Err(CompletionError::MissingFrame),
                Ok(length) => {
                    received = received
                        .checked_add(length)
                        .ok_or(CompletionError::InvalidFrame)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(CompletionError::Io),
            }
        }

        if frame != encode_test_checkpoint(expected) {
            return Err(CompletionError::InvalidFrame);
        }

        loop {
            if Instant::now() >= deadline {
                return Err(CompletionError::RecoveryDeadline);
            }
            let mut trailing = [0_u8; 1];
            match self.stream.read(&mut trailing) {
                Ok(0) => return Err(CompletionError::MissingFrame),
                Ok(_) => return Err(CompletionError::TrailingData),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return Err(CompletionError::Io),
            }
        }
    }

    fn finish_poll(
        &mut self,
        result: Result<CompletionPoll, CompletionError>,
    ) -> Result<CompletionPoll, CompletionError> {
        if let Err(error) = result {
            self.terminal_error = Some(error);
        }
        result
    }

    /// Sends the sole retained-generation recovery request on the socket's
    /// reverse direction, then permanently closes only this endpoint's write
    /// half. Beginning an attempt consumes the one-shot even when the supplied
    /// deadline is already expired or a partial write later fails.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the package recovery owner is test-only until the public supervisor is enabled"
        )
    )]
    pub(super) fn request_recovery(&mut self, deadline: Instant) -> Result<(), CompletionError> {
        if self.recovery_request_consumed {
            return Err(CompletionError::RecoveryReplay);
        }
        self.recovery_request_consumed = true;

        let result = match self.terminal_error {
            Some(error) => Err(error),
            None => self.request_recovery_before(deadline),
        };
        if result.is_err() {
            // A failed or partial request can never be retried as another
            // command. Best-effort shutdown may let the guardian classify the
            // exact peer as gone, but failure leaves that boundary unknown.
            let _ = self.stream.shutdown(std::net::Shutdown::Write);
        }
        result
    }

    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "used by the package recovery owner through request_recovery"
        )
    )]
    fn request_recovery_before(&mut self, deadline: Instant) -> Result<(), CompletionError> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        if self.received != 0 || self.terminal_frame.is_some() {
            return Err(CompletionError::RecoveryTooLate);
        }
        match self.poll_once() {
            Ok(CompletionPoll::Verified | CompletionPoll::RetainedUnrecoverable) => {
                return Err(CompletionError::RecoveryTooLate);
            }
            Ok(CompletionPoll::Pending) if self.received != 0 || self.terminal_frame.is_some() => {
                return Err(CompletionError::RecoveryTooLate);
            }
            Ok(CompletionPoll::Pending) => {}
            Err(error) => return Err(error),
        }

        let request = encode_recovery_request_frame(self.peer_identity);
        let mut written = 0_usize;
        while written < request.len() {
            if Instant::now() >= deadline {
                return Err(CompletionError::RecoveryDeadline);
            }
            match self.stream.write(&request[written..]) {
                Ok(0) => return Err(CompletionError::Io),
                Ok(length) => {
                    written = written
                        .checked_add(length)
                        .ok_or(CompletionError::InvalidFrame)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let Some(events) =
                        poll_stream_before(&self.stream, rustix::event::PollFlags::OUT, deadline)?
                    else {
                        return Err(CompletionError::RecoveryDeadline);
                    };
                    if !events.contains(rustix::event::PollFlags::OUT) {
                        return Err(CompletionError::Io);
                    }
                }
                Err(_) => return Err(CompletionError::Io),
            }
        }
        self.stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| CompletionError::Io)
    }

    fn verify_identity(&self) -> Result<(), CompletionError> {
        verify_close_on_exec(&self.stream)?;
        if descriptor_identity(&self.stream)? == self.identity {
            Ok(())
        } else {
            Err(CompletionError::Descriptor)
        }
    }
}

fn decode_completion_once(
    reader: &mut impl Read,
    frame: &mut [u8; COMPLETION_FRAME.len()],
    received: &mut usize,
    terminal_frame: &mut Option<CompletionTerminalFrame>,
) -> Result<CompletionPoll, CompletionError> {
    loop {
        if *received < frame.len() {
            match reader.read(&mut frame[*received..]) {
                Ok(0) => return Err(CompletionError::MissingFrame),
                Ok(length) => {
                    *received = received
                        .checked_add(length)
                        .ok_or(CompletionError::InvalidFrame)?;
                    if *received < frame.len() {
                        continue;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(CompletionPoll::Pending);
                }
                Err(_) => return Err(CompletionError::Io),
            }
        }

        if terminal_frame.is_none() {
            *terminal_frame = Some(if *frame == COMPLETION_FRAME {
                CompletionTerminalFrame::ProviderReleased
            } else if *frame == RETAINED_UNRECOVERABLE_FRAME {
                CompletionTerminalFrame::RetainedUnrecoverable
            } else {
                return Err(CompletionError::InvalidFrame);
            });
        }

        let mut trailing = [0_u8; 1];
        match reader.read(&mut trailing) {
            Ok(0) => {
                return Ok(match terminal_frame {
                    Some(CompletionTerminalFrame::ProviderReleased) => CompletionPoll::Verified,
                    Some(CompletionTerminalFrame::RetainedUnrecoverable) => {
                        CompletionPoll::RetainedUnrecoverable
                    }
                    None => return Err(CompletionError::InvalidFrame),
                });
            }
            Ok(_) => return Err(CompletionError::TrailingData),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(CompletionPoll::Pending);
            }
            Err(_) => return Err(CompletionError::Io),
        }
    }
}

impl AsFd for AnchorCompletion {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

impl fmt::Debug for AnchorCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.stream,
            self.identity,
            self.peer_identity,
            self.received,
            self.terminal_frame,
            self.terminal_error,
            self.recovery_request_consumed,
        );
        #[cfg(test)]
        let _ = (
            self.completion_decode_started,
            self.test_checkpoint_terminal,
        );
        formatter.write_str("AnchorCompletion(<redacted>)")
    }
}

/// Move-only sender while it crosses anchor -> coordinator -> guardian. This
/// type intentionally exposes no write operation.
#[must_use = "the completion transit endpoint must be passed to the guardian"]
pub(super) struct CompletionTransit {
    stream: UnixStream,
    identity: calcifer_unix_child_fd::DescriptorIdentity,
}

impl CompletionTransit {
    fn adopt(stream: UnixStream) -> Result<Self, CompletionError> {
        verify_close_on_exec(&stream)?;
        let identity = descriptor_identity(&stream)?;
        Ok(Self { stream, identity })
    }

    /// Consumes the audited child-only fd advertisement at a single-threaded
    /// exec entry. The environment value selects no authority by itself; the
    /// returned owned duplicate is resealed and identity-read back by the
    /// support crate before this wrapper accepts it. Acceptance also requires
    /// the exact two-reference inventory created by that audited take.
    pub(super) fn take_inherited() -> Result<Self, CompletionError> {
        let inherited = calcifer_unix_child_fd::take_inherited_readiness_fd()
            .map_err(|_| CompletionError::Inherited)?;
        let transit = Self::adopt(UnixStream::from(inherited))?;
        // The support crate deliberately retains the resealed bootstrap fd
        // and returns one fresh close-on-exec owner. Any third reference means
        // that this completion capability was duplicated or cross-wired at
        // exec, so the generation cannot safely publish through it.
        let descriptor_count =
            calcifer_unix_child_fd::count_open_descriptors_with_identity(transit.identity)
                .map_err(|_| CompletionError::Inherited)?;
        if descriptor_count != INHERITED_COMPLETION_DESCRIPTOR_COUNT {
            return Err(CompletionError::Inherited);
        }
        Ok(transit)
    }

    pub(super) fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }

    pub(super) fn into_guardian(self) -> GuardianCompletion {
        GuardianCompletion {
            stream: self.stream,
            identity: self.identity,
            recovery_frame: [0; RECOVERY_REQUEST_FRAME.len()],
            recovery_received: 0,
            recovery_frame_validated: false,
            recovery_protocol_rejected: false,
            recovery_terminal: None,
        }
    }
}

impl fmt::Debug for CompletionTransit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.stream, self.identity);
        formatter.write_str("CompletionTransit(<redacted>)")
    }
}

/// Guardian-held completion authority. Construction requires the exact
/// inherited kernel endpoint; publishing consumes it and is therefore one-shot.
#[must_use = "guardian completion must select success, retained, or remain pinned with B"]
pub(super) struct GuardianCompletion {
    stream: UnixStream,
    identity: calcifer_unix_child_fd::DescriptorIdentity,
    recovery_frame: [u8; RECOVERY_REQUEST_FRAME.len()],
    recovery_received: usize,
    recovery_frame_validated: bool,
    recovery_protocol_rejected: bool,
    recovery_terminal: Option<RecoveryRequestTerminal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryRequestPoll {
    Pending,
    Verified,
    OwnerLost,
    ProtocolRejected,
    ProtocolRejectedOwnerLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryRequestTerminal {
    Verified,
    OwnerLost,
    ProtocolRejectedOwnerLost,
    Failed(CompletionError),
}

impl GuardianCompletion {
    pub(super) fn append_forbidden_descriptor<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        forbidden.capture(self.stream.as_fd())
    }

    /// Publishes a bounded, test-only lifecycle observation without closing or
    /// consuming the duplex completion capability. This frame is deliberately
    /// not accepted by the recovery-request decoder.
    #[cfg(test)]
    pub(super) fn publish_test_checkpoint(
        &mut self,
        checkpoint: RecoveryCheckpoint,
        deadline: Instant,
    ) -> Result<(), CompletionError> {
        self.verify_identity()?;
        self.stream
            .set_nonblocking(true)
            .map_err(|_| CompletionError::Descriptor)?;
        let frame = encode_test_checkpoint(checkpoint);
        let mut written = 0_usize;
        while written < frame.len() {
            if Instant::now() >= deadline {
                return Err(CompletionError::RecoveryDeadline);
            }
            match self.stream.write(&frame[written..]) {
                Ok(0) => return Err(CompletionError::Io),
                Ok(length) => {
                    written = written
                        .checked_add(length)
                        .ok_or(CompletionError::InvalidFrame)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let Some(events) =
                        poll_stream_before(&self.stream, rustix::event::PollFlags::OUT, deadline)?
                    else {
                        return Err(CompletionError::RecoveryDeadline);
                    };
                    if !events.contains(rustix::event::PollFlags::OUT) {
                        return Err(CompletionError::Io);
                    }
                }
                Err(_) => return Err(CompletionError::Io),
            }
        }
        Ok(())
    }

    /// Advances the owner-to-guardian request direction until one fixed frame
    /// plus EOF is verified or the absolute deadline is reached. The completion
    /// write direction remains open and independent throughout this read.
    pub(super) fn poll_recovery_request(
        &mut self,
        deadline: Instant,
    ) -> Result<RecoveryRequestPoll, CompletionError> {
        self.verify_identity()?;
        if let Some(terminal) = self.recovery_terminal {
            return terminal.into_result();
        }

        let result = self.poll_recovery_request_before(deadline);
        match result {
            Ok(RecoveryRequestPoll::Verified) => {
                self.recovery_terminal = Some(RecoveryRequestTerminal::Verified);
            }
            Ok(RecoveryRequestPoll::OwnerLost) => {
                self.recovery_terminal = Some(RecoveryRequestTerminal::OwnerLost);
            }
            Ok(RecoveryRequestPoll::ProtocolRejectedOwnerLost) => {
                self.recovery_terminal = Some(RecoveryRequestTerminal::ProtocolRejectedOwnerLost);
            }
            Ok(RecoveryRequestPoll::Pending | RecoveryRequestPoll::ProtocolRejected) => {}
            Err(error) => self.recovery_terminal = Some(RecoveryRequestTerminal::Failed(error)),
        }
        result
    }

    fn poll_recovery_request_before(
        &mut self,
        deadline: Instant,
    ) -> Result<RecoveryRequestPoll, CompletionError> {
        loop {
            if self.recovery_protocol_rejected {
                return self.poll_rejected_request_once(deadline);
            }
            if self.recovery_received < self.recovery_frame.len() {
                let Some(events) =
                    poll_stream_before(&self.stream, rustix::event::PollFlags::IN, deadline)?
                else {
                    return Ok(RecoveryRequestPoll::Pending);
                };
                if !events.intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP)
                {
                    return Err(CompletionError::Io);
                }
                match self
                    .stream
                    .read(&mut self.recovery_frame[self.recovery_received..])
                {
                    Ok(0) if self.recovery_received == 0 => {
                        return Ok(RecoveryRequestPoll::OwnerLost);
                    }
                    Ok(0) => return Ok(RecoveryRequestPoll::ProtocolRejectedOwnerLost),
                    Ok(length) => {
                        self.recovery_received = self
                            .recovery_received
                            .checked_add(length)
                            .ok_or(CompletionError::InvalidFrame)?;
                        if self.recovery_received < self.recovery_frame.len() {
                            continue;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(CompletionError::Io),
                }
            }

            if !self.recovery_frame_validated {
                if !recovery_request_frame_is_valid(&self.recovery_frame, self.identity) {
                    self.recovery_protocol_rejected = true;
                    continue;
                }
                self.recovery_frame_validated = true;
            }

            let Some(events) =
                poll_stream_before(&self.stream, rustix::event::PollFlags::IN, deadline)?
            else {
                return Ok(RecoveryRequestPoll::Pending);
            };
            if !events.intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP) {
                return Err(CompletionError::Io);
            }
            let mut trailing = [0_u8; 1];
            match self.stream.read(&mut trailing) {
                Ok(0) => return Ok(RecoveryRequestPoll::Verified),
                Ok(_) => self.recovery_protocol_rejected = true,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(CompletionError::Io),
            }
        }
    }

    fn poll_rejected_request_once(
        &mut self,
        deadline: Instant,
    ) -> Result<RecoveryRequestPoll, CompletionError> {
        let Some(events) =
            poll_stream_before(&self.stream, rustix::event::PollFlags::IN, deadline)?
        else {
            return Ok(RecoveryRequestPoll::ProtocolRejected);
        };
        if !events.intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP) {
            return Err(CompletionError::Io);
        }
        // Malformed payload is never retained. One fixed discard per poll keeps
        // both memory and work bounded while preserving later exact peer EOF as
        // an owner-loss cleanup trigger.
        let mut discarded = [0_u8; 64];
        match self.stream.read(&mut discarded) {
            Ok(0) => Ok(RecoveryRequestPoll::ProtocolRejectedOwnerLost),
            Ok(_) => Ok(RecoveryRequestPoll::ProtocolRejected),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                Ok(RecoveryRequestPoll::ProtocolRejected)
            }
            Err(_) => Err(CompletionError::Io),
        }
    }

    fn verify_identity(&self) -> Result<(), CompletionError> {
        verify_close_on_exec(&self.stream)?;
        if descriptor_identity(&self.stream)? == self.identity {
            Ok(())
        } else {
            Err(CompletionError::Descriptor)
        }
    }

    /// Publishes only the fixed recovery-complete frame and closes the write
    /// direction after consuming the provider-release capability. The anchor
    /// still requires EOF after every coordinator and guardian duplicate is
    /// gone.
    pub(super) fn publish_after_provider_release(
        self,
        proof: super::session::ProviderReleaseProof,
    ) -> Result<(), CompletionError> {
        proof.authorize_release();
        self.publish_frame(COMPLETION_FRAME)
    }

    /// Publishes the fixed terminal-retention outcome without accepting or
    /// creating a provider-release proof. The endpoint is consumed and its
    /// write half is shut down even when publication fails, so an EPIPE cannot
    /// turn retained authority into either a retry or a success completion.
    pub(super) fn publish_retained_unrecoverable(self) -> Result<(), CompletionError> {
        self.publish_frame(RETAINED_UNRECOVERABLE_FRAME)
    }

    /// Raw publication exists only for this module's closed-over transport
    /// fixtures. Production siblings cannot call it without first supplying a
    /// move-only provider-release proof.
    fn publish_raw(self) -> Result<(), CompletionError> {
        self.publish_frame(COMPLETION_FRAME)
    }

    fn publish_frame(mut self, frame: [u8; COMPLETION_FRAME.len()]) -> Result<(), CompletionError> {
        let publication = self.verify_identity().and_then(|()| {
            self.stream
                .write_all(&frame)
                .map_err(|_| CompletionError::Io)
        });
        let shutdown = self
            .stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| CompletionError::Io);
        publication.and(shutdown)
    }
}

impl fmt::Debug for GuardianCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.stream,
            self.identity,
            self.recovery_received,
            self.recovery_frame_validated,
            self.recovery_protocol_rejected,
            self.recovery_terminal,
        );
        formatter.write_str("GuardianCompletion(<redacted>)")
    }
}

impl RecoveryRequestTerminal {
    const fn into_result(self) -> Result<RecoveryRequestPoll, CompletionError> {
        match self {
            Self::Verified => Ok(RecoveryRequestPoll::Verified),
            Self::OwnerLost => Ok(RecoveryRequestPoll::OwnerLost),
            Self::ProtocolRejectedOwnerLost => Ok(RecoveryRequestPoll::ProtocolRejectedOwnerLost),
            Self::Failed(error) => Err(error),
        }
    }
}

fn poll_stream_before(
    stream: &UnixStream,
    requested: rustix::event::PollFlags,
    deadline: Instant,
) -> Result<Option<rustix::event::PollFlags>, CompletionError> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let timeout = rustix::event::Timespec::try_from(deadline.saturating_duration_since(now))
            .map_err(|_| CompletionError::RecoveryDeadline)?;
        let mut descriptors = [rustix::event::PollFd::new(stream, requested)];
        match rustix::event::poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Ok(None),
            Ok(_) => {
                let events = descriptors[0].revents();
                if events.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL)
                {
                    return Err(CompletionError::Io);
                }
                return Ok(Some(events));
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(CompletionError::Io),
        }
    }
}

fn descriptor_identity(
    descriptor: &impl AsFd,
) -> Result<calcifer_unix_child_fd::DescriptorIdentity, CompletionError> {
    calcifer_unix_child_fd::descriptor_identity(descriptor.as_fd())
        .map_err(|_| CompletionError::Descriptor)
}

fn set_close_on_exec(descriptor: &impl AsFd) -> Result<(), CompletionError> {
    let flags = fcntl_getfd(descriptor).map_err(|_| CompletionError::Descriptor)?;
    fcntl_setfd(descriptor, flags | FdFlags::CLOEXEC).map_err(|_| CompletionError::Descriptor)?;
    verify_close_on_exec(descriptor)
}

fn verify_close_on_exec(descriptor: &impl AsFd) -> Result<(), CompletionError> {
    let flags = fcntl_getfd(descriptor).map_err(|_| CompletionError::Descriptor)?;
    if flags.contains(FdFlags::CLOEXEC) {
        Ok(())
    } else {
        Err(CompletionError::Descriptor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionEntryError {
    Arguments,
    Environment,
    Profile,
    Executable,
    Terminal,
    Channel,
    Spawn,
}

impl fmt::Display for ProductionEntryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the internal supervised Codex entry failed")
    }
}

impl std::error::Error for ProductionEntryError {}

/// Presence selects the sealed role dispatcher even when the value is
/// malformed. An invalid internal role must fail closed instead of falling
/// through to the ordinary public CLI parser.
pub(super) fn internal_production_role_requested() -> bool {
    env::var_os(ROLE_ENV).is_some()
}

/// Dispatches only sealed production supervisor roles. Every string received
/// across an exec boundary is bounded and then revalidated against the managed
/// registry before it can mint A or B.
pub(super) fn run_internal_production_role() -> ExitCode {
    match parse_and_run_production_role() {
        Ok(code) => code,
        Err(_) => ExitCode::from(70),
    }
}

fn parse_and_run_production_role() -> Result<ExitCode, ProductionEntryError> {
    if env::args_os().count() != 1 {
        return Err(ProductionEntryError::Arguments);
    }
    match env::var(ROLE_ENV).ok().as_deref() {
        Some(ANCHOR_ROLE_V1) => parse_and_run_anchor_role(),
        Some(COORDINATOR_ROLE_V1) => parse_and_run_coordinator_role(),
        Some(GUARDIAN_ROLE_V1) => parse_and_run_guardian_role(),
        _ => Err(ProductionEntryError::Arguments),
    }
}

fn parse_and_run_anchor_role() -> Result<ExitCode, ProductionEntryError> {
    let profile_id = bounded_environment_utf8(PROFILE_ID_ENV, MAX_PROFILE_ID_BYTES)?;
    let thread_id = bounded_environment_utf8(THREAD_ID_ENV, MAX_THREAD_ID_BYTES)?;
    validate_thread_id(&thread_id)?;
    let codex_executable =
        bounded_environment_path(CODEX_EXECUTABLE_ENV, MAX_EXECUTABLE_PATH_BYTES, true)?;
    let working_directory = env::current_dir().map_err(|_| ProductionEntryError::Environment)?;
    validate_canonical_directory(&working_directory, MAX_WORKING_DIRECTORY_BYTES)?;
    let coordinator_executable =
        env::current_exe().map_err(|_| ProductionEntryError::Executable)?;
    validate_canonical_file(&coordinator_executable, MAX_EXECUTABLE_PATH_BYTES)?;
    let registry = Registry::discover().map_err(|_| ProductionEntryError::Profile)?;
    let profile = registry
        .find_by_id(Provider::Codex, &profile_id)
        .map_err(|_| ProductionEntryError::Profile)?;

    Ok(run_production_anchor(ProductionAnchorConfig {
        registry: &registry,
        profile: &profile,
        working_directory: &working_directory,
        thread_id: &thread_id,
        codex_executable: &codex_executable,
        coordinator_executable: &coordinator_executable,
    }))
}

fn parse_and_run_guardian_role() -> Result<ExitCode, ProductionEntryError> {
    let completion = CompletionTransit::take_inherited()
        .map_err(|_| ProductionEntryError::Environment)?
        .into_guardian();
    let profile_id = bounded_environment_utf8(PROFILE_ID_ENV, MAX_PROFILE_ID_BYTES)?;
    let thread_id = bounded_environment_utf8(THREAD_ID_ENV, MAX_THREAD_ID_BYTES)?;
    validate_thread_id(&thread_id)?;
    let codex_executable =
        bounded_environment_path(CODEX_EXECUTABLE_ENV, MAX_EXECUTABLE_PATH_BYTES, true)?;
    let expected_foreground_process_group = env::var(FOREGROUND_PROCESS_GROUP_ENV)
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|value| *value > 0)
        .ok_or(ProductionEntryError::Environment)?;
    let working_directory = env::current_dir().map_err(|_| ProductionEntryError::Environment)?;
    validate_canonical_directory(&working_directory, MAX_WORKING_DIRECTORY_BYTES)?;
    let runtime_parent =
        crate::profiles::managed_runtime_root().map_err(|_| ProductionEntryError::Profile)?;
    let registry = Registry::discover().map_err(|_| ProductionEntryError::Profile)?;
    let profile = registry
        .find_by_id(Provider::Codex, &profile_id)
        .map_err(|_| ProductionEntryError::Profile)?;

    Ok(run_production_guardian(ProductionGuardianConfig {
        registry: &registry,
        profile: &profile,
        working_directory: &working_directory,
        thread_id: &thread_id,
        codex_executable: &codex_executable,
        runtime_parent: &runtime_parent,
        expected_foreground_process_group,
        bounds: production_guardian_bounds(),
        completion,
    })
    .apply())
}

fn parse_and_run_coordinator_role() -> Result<ExitCode, ProductionEntryError> {
    let completion =
        CompletionTransit::take_inherited().map_err(|_| ProductionEntryError::Environment)?;
    let profile_id = bounded_environment_utf8(PROFILE_ID_ENV, MAX_PROFILE_ID_BYTES)?;
    let thread_id = bounded_environment_utf8(THREAD_ID_ENV, MAX_THREAD_ID_BYTES)?;
    validate_thread_id(&thread_id)?;
    let codex_executable =
        bounded_environment_path(CODEX_EXECUTABLE_ENV, MAX_EXECUTABLE_PATH_BYTES, true)?;
    let working_directory = env::current_dir().map_err(|_| ProductionEntryError::Environment)?;
    validate_canonical_directory(&working_directory, MAX_WORKING_DIRECTORY_BYTES)?;
    let guardian_executable = env::current_exe().map_err(|_| ProductionEntryError::Executable)?;
    validate_canonical_file(&guardian_executable, MAX_EXECUTABLE_PATH_BYTES)?;
    let registry = Registry::discover().map_err(|_| ProductionEntryError::Profile)?;
    let profile = registry
        .find_by_id(Provider::Codex, &profile_id)
        .map_err(|_| ProductionEntryError::Profile)?;

    Ok(run_production_coordinator(
        ProductionCoordinatorConfig {
            registry: &registry,
            profile: &profile,
            working_directory: &working_directory,
            thread_id: &thread_id,
            codex_executable: &codex_executable,
            guardian_executable: &guardian_executable,
        },
        completion,
    ))
}

struct ProductionAnchorConfig<'a> {
    registry: &'a Registry,
    profile: &'a Profile,
    working_directory: &'a Path,
    thread_id: &'a str,
    codex_executable: &'a Path,
    coordinator_executable: &'a Path,
}

/// Shell-facing lifetime owner for one hidden coordinator generation.
///
/// The anchor never reads or writes terminal payload bytes. It owns only the
/// immutable pre-generation terminal snapshot, the exact direct child, and the
/// completion receiver. Returning to the invoking shell requires both exact
/// child wait and the guardian's fixed completion frame followed by kernel
/// EOF.
fn run_production_anchor(config: ProductionAnchorConfig<'_>) -> ExitCode {
    match try_run_production_anchor(config) {
        Ok(code) => code,
        Err(_) => ExitCode::from(1),
    }
}

fn try_run_production_anchor(
    config: ProductionAnchorConfig<'_>,
) -> Result<ExitCode, ProductionEntryError> {
    validate_anchor_config(&config)?;
    run_anchor_command(coordinator_command(&config)?)
}

fn run_anchor_command(command: Command) -> Result<ExitCode, ProductionEntryError> {
    run_anchor_command_inner(command, None)
}

fn run_anchor_command_inner(
    mut command: Command,
    fixture_late_signal: Option<UnixSignal>,
) -> Result<ExitCode, ProductionEntryError> {
    let signals =
        CoordinatorSignalLatches::install().map_err(|_| ProductionEntryError::Terminal)?;
    let snapshot = capture_anchor_snapshot()?;
    let anchor_group = rustix::process::getpgrp();
    let (completion, transit) = CompletionPair::new()
        .map_err(|_| ProductionEntryError::Channel)?
        .split();
    command.process_group(0);
    let mut child =
        match calcifer_unix_child_fd::spawn_with_inherited_readiness_fd(command, transit.as_fd()) {
            Ok(child) => child,
            Err(error) => {
                drop((transit, completion, snapshot, signals));
                drop(error);
                return Err(ProductionEntryError::Spawn);
            }
        };
    drop(transit);

    let coordinator_group =
        match await_direct_child_group(&mut child, Instant::now() + Duration::from_secs(15)) {
            Ok(group) => group,
            Err(error) => {
                retain_or_reap_before_handoff(child, snapshot, completion);
                return Err(error);
            }
        };
    if let Err(error) = select_foreground_group(&snapshot, anchor_group, coordinator_group) {
        retain_or_reap_before_handoff(child, snapshot, completion);
        return Err(error);
    }

    let generation = AnchorGeneration {
        child,
        coordinator_group,
        anchor_group,
        snapshot,
        completion,
        signals,
        child_status: None,
        completion_verified: false,
    };
    if let Some(signal) = fixture_late_signal {
        if let Err(error) = await_direct_child_exit_without_reaping(
            &generation.child,
            Instant::now() + Duration::from_secs(15),
        ) {
            return Ok(generation.emergency_failure(error));
        }
        if let Err(error) = await_fixture_signal_latch(
            &generation.signals,
            signal,
            Instant::now() + Duration::from_secs(15),
        ) {
            return Ok(generation.emergency_failure(error));
        }
    }

    Ok(generation.drive())
}

fn await_direct_child_exit_without_reaping(
    child: &Child,
    deadline: Instant,
) -> Result<(), ProductionEntryError> {
    let pid = rustix::process::Pid::from_child(child);
    let options = rustix::process::WaitIdOptions::EXITED
        | rustix::process::WaitIdOptions::NOHANG
        | rustix::process::WaitIdOptions::NOWAIT;
    loop {
        match rustix::process::waitid(rustix::process::WaitId::Pid(pid), options) {
            Ok(Some(status)) if status.exited() || status.killed() || status.dumped() => {
                return Ok(());
            }
            Ok(Some(_)) | Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(rustix::io::Errno::INTR) if Instant::now() < deadline => {}
            Ok(Some(_)) | Ok(None) | Err(_) => return Err(ProductionEntryError::Spawn),
        }
    }
}

fn await_fixture_signal_latch(
    signals: &CoordinatorSignalLatches,
    signal: UnixSignal,
    deadline: Instant,
) -> Result<(), ProductionEntryError> {
    loop {
        if signals.has_pending_forward_for_fixture(signal) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ProductionEntryError::Terminal);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn coordinator_command(
    config: &ProductionAnchorConfig<'_>,
) -> Result<Command, ProductionEntryError> {
    let mut command = Command::new(config.coordinator_executable);
    crate::providers::codex::sanitize_managed_environment(&mut command);
    remove_internal_supervisor_environment(&mut command);
    command
        .env(ROLE_ENV, COORDINATOR_ROLE_V1)
        .env(PROFILE_ID_ENV, &config.profile.id)
        .env(THREAD_ID_ENV, config.thread_id)
        .env(CODEX_EXECUTABLE_ENV, config.codex_executable)
        .env("CALCIFER_HOME", config.registry.managed_root())
        .env_remove("CODEX_HOME")
        .current_dir(config.working_directory);
    Ok(command)
}

fn validate_anchor_config(config: &ProductionAnchorConfig<'_>) -> Result<(), ProductionEntryError> {
    if config.profile.provider != Provider::Codex
        || config.profile.id.len() > MAX_PROFILE_ID_BYTES
        || config.thread_id.len() > MAX_THREAD_ID_BYTES
    {
        return Err(ProductionEntryError::Arguments);
    }
    validate_thread_id(config.thread_id)?;
    validate_canonical_directory(config.working_directory, MAX_WORKING_DIRECTORY_BYTES)?;
    validate_canonical_file(config.codex_executable, MAX_EXECUTABLE_PATH_BYTES)?;
    validate_canonical_file(config.coordinator_executable, MAX_EXECUTABLE_PATH_BYTES)
}

fn capture_anchor_snapshot() -> Result<TerminalSnapshot, ProductionEntryError> {
    let process = rustix::process::getpid();
    let process_group = rustix::process::getpgrp();
    if process != process_group
        || rustix::termios::tcgetpgrp(io::stdin()).map_err(|_| ProductionEntryError::Terminal)?
            != process_group
        || rustix::process::getsid(Some(process)).map_err(|_| ProductionEntryError::Terminal)?
            != rustix::termios::tcgetsid(io::stdin()).map_err(|_| ProductionEntryError::Terminal)?
    {
        return Err(ProductionEntryError::Terminal);
    }
    let snapshot =
        TerminalSnapshot::capture(io::stdin()).map_err(|_| ProductionEntryError::Terminal)?;
    if snapshot.foreground_process_group() == process_group.as_raw_nonzero().get()
        && snapshot.descriptor_identity()
            == calcifer_unix_child_fd::descriptor_identity(io::stdin().as_fd())
                .map_err(|_| ProductionEntryError::Terminal)?
    {
        Ok(snapshot)
    } else {
        Err(ProductionEntryError::Terminal)
    }
}

fn await_direct_child_group(
    child: &mut Child,
    deadline: Instant,
) -> Result<rustix::process::Pid, ProductionEntryError> {
    let pid = rustix::process::Pid::from_child(&*child);
    loop {
        match rustix::process::getpgid(Some(pid)) {
            Ok(group) if group == pid => return Ok(group),
            Ok(_) | Err(rustix::io::Errno::SRCH) => {}
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(ProductionEntryError::Spawn),
        }
        match child.try_wait() {
            Ok(Some(_)) => return Err(ProductionEntryError::Spawn),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ProductionEntryError::Spawn),
        }
        if Instant::now() >= deadline {
            return Err(ProductionEntryError::Spawn);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn select_foreground_group(
    snapshot: &TerminalSnapshot,
    expected_current: rustix::process::Pid,
    selected: rustix::process::Pid,
) -> Result<(), ProductionEntryError> {
    if calcifer_unix_child_fd::descriptor_identity(io::stdin().as_fd())
        .map_err(|_| ProductionEntryError::Terminal)?
        != snapshot.descriptor_identity()
        || rustix::termios::tcgetpgrp(io::stdin()).map_err(|_| ProductionEntryError::Terminal)?
            != expected_current
    {
        return Err(ProductionEntryError::Terminal);
    }
    let guard = calcifer_unix_child_fd::block_sigttou_for_current_thread()
        .map_err(|_| ProductionEntryError::Terminal)?;
    let selected_result = rustix::termios::tcsetpgrp(io::stdin(), selected)
        .map_err(|_| ProductionEntryError::Terminal)
        .and_then(|()| {
            if rustix::termios::tcgetpgrp(io::stdin())
                .map_err(|_| ProductionEntryError::Terminal)?
                == selected
            {
                Ok(())
            } else {
                Err(ProductionEntryError::Terminal)
            }
        });
    drop(guard);
    selected_result
}

fn retain_or_reap_before_handoff(
    mut child: Child,
    snapshot: TerminalSnapshot,
    completion: AnchorCompletion,
) {
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted && Instant::now() < deadline => {}
            Ok(None) | Err(_) => RetainedAnchorState {
                child,
                snapshot,
                completion,
            }
            .park(),
        }
    }
}

struct RetainedAnchorState {
    child: Child,
    snapshot: TerminalSnapshot,
    completion: AnchorCompletion,
}

impl RetainedAnchorState {
    fn park(self) -> ! {
        let _ = (
            self.child.id(),
            self.snapshot.descriptor_identity(),
            self.completion.identity,
        );
        std::mem::forget(self);
        loop {
            std::thread::park();
        }
    }
}

struct AnchorGeneration {
    child: Child,
    coordinator_group: rustix::process::Pid,
    anchor_group: rustix::process::Pid,
    snapshot: TerminalSnapshot,
    completion: AnchorCompletion,
    signals: CoordinatorSignalLatches,
    child_status: Option<ExitStatus>,
    completion_verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnchorCompletionAction {
    Continue,
    VerifyProviderRelease,
    ParkRetained,
}

const fn anchor_completion_action(observation: CompletionPoll) -> AnchorCompletionAction {
    match observation {
        CompletionPoll::Pending => AnchorCompletionAction::Continue,
        CompletionPoll::Verified => AnchorCompletionAction::VerifyProviderRelease,
        CompletionPoll::RetainedUnrecoverable => AnchorCompletionAction::ParkRetained,
    }
}

impl AnchorGeneration {
    fn drive(mut self) -> ExitCode {
        loop {
            if self.child_status.is_none() {
                match self.child.try_wait() {
                    Ok(Some(status)) => self.child_status = Some(status),
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        return self.emergency_failure(ProductionEntryError::Spawn);
                    }
                }
            }

            if !self.completion_verified {
                match self.completion.poll_once() {
                    Ok(observation) => match anchor_completion_action(observation) {
                        AnchorCompletionAction::Continue => {}
                        AnchorCompletionAction::VerifyProviderRelease => {
                            self.completion_verified = true;
                        }
                        AnchorCompletionAction::ParkRetained => self.park(),
                    },
                    Err(_) => {
                        return self.emergency_failure(ProductionEntryError::Channel);
                    }
                }
            }

            let completed_status = if self.completion_verified {
                self.child_status.take()
            } else {
                None
            };
            if let Some(status) = completed_status {
                return self.finish_verified(status);
            }
            let signal_dispatch = if self.child_status.is_none() {
                self.dispatch_signal()
            } else {
                Ok(())
            };
            if let Err(error) = signal_dispatch {
                // The child can exit between the exact pre-dispatch wait and
                // `killpg(2)`. Reap that identity once more before classifying
                // the signal failure as infrastructure damage. A reaped child
                // is no longer a legal forwarding target; completion remains
                // the only remaining release gate.
                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        self.child_status = Some(status);
                        continue;
                    }
                    Ok(None) => return self.emergency_failure(error),
                    Err(wait_error) if wait_error.kind() == io::ErrorKind::Interrupted => {
                        continue;
                    }
                    Err(_) => return self.emergency_failure(ProductionEntryError::Spawn),
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn dispatch_signal(&mut self) -> Result<(), ProductionEntryError> {
        let Some(action) = self.signals.next_active() else {
            return Ok(());
        };
        match action {
            CoordinatorSignalAction::Forward(signal) => {
                self.signal_coordinator(rustix_signal(signal))
            }
            CoordinatorSignalAction::Suspend => self.suspend_and_resume(),
            // The foreground coordinator receives terminal-generated WINCH
            // directly. A shell-directed anchor WINCH is only a coalesced
            // notification; forwarding the signal makes it read the latest
            // validated size through its normal protocol path.
            CoordinatorSignalAction::Resize => {
                self.signal_coordinator(rustix::process::Signal::WINCH)
            }
            CoordinatorSignalAction::Continue => Err(ProductionEntryError::Terminal),
        }
    }

    fn suspend_and_resume(&mut self) -> Result<(), ProductionEntryError> {
        self.signal_coordinator(rustix::process::Signal::TSTP)?;
        self.await_coordinator_stopped()?;
        select_foreground_group(&self.snapshot, self.coordinator_group, self.anchor_group)?;

        // The coordinator's STOPPED state is reachable only after its exact
        // Suspended acknowledgement and outer-terminal restoration. Clearing a
        // stale CONT and stopping the anchor under the audited signal mask
        // preserves that ordering across the shell-facing job boundary.
        self.signals
            .stop_after_suspended_ack()
            .map_err(|_| ProductionEntryError::Terminal)?;

        loop {
            match self.signals.next_suspended() {
                Some(CoordinatorSignalAction::Continue) => break,
                Some(CoordinatorSignalAction::Forward(signal)) => {
                    self.signal_coordinator(rustix_signal(signal))?;
                }
                Some(CoordinatorSignalAction::Resize | CoordinatorSignalAction::Suspend) => {}
                None => std::thread::yield_now(),
            }
        }
        self.verify_child_still_stopped()?;
        select_foreground_group(&self.snapshot, self.anchor_group, self.coordinator_group)?;
        self.signal_coordinator(rustix::process::Signal::CONT)
    }

    fn await_coordinator_stopped(&mut self) -> Result<(), ProductionEntryError> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match self.peek_child_state()? {
                ChildKernelState::Stopped => return Ok(()),
                ChildKernelState::Exited => {
                    self.child_status = self
                        .child
                        .try_wait()
                        .map_err(|_| ProductionEntryError::Spawn)?;
                    return Err(ProductionEntryError::Spawn);
                }
                ChildKernelState::Running if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                ChildKernelState::Running => return Err(ProductionEntryError::Terminal),
            }
        }
    }

    fn verify_child_still_stopped(&self) -> Result<(), ProductionEntryError> {
        match self.peek_child_state()? {
            ChildKernelState::Stopped => Ok(()),
            ChildKernelState::Running | ChildKernelState::Exited => {
                Err(ProductionEntryError::Terminal)
            }
        }
    }

    fn peek_child_state(&self) -> Result<ChildKernelState, ProductionEntryError> {
        let options = rustix::process::WaitIdOptions::STOPPED
            | rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOHANG
            | rustix::process::WaitIdOptions::NOWAIT;
        match rustix::process::waitid(
            rustix::process::WaitId::Pid(rustix::process::Pid::from_child(&self.child)),
            options,
        ) {
            Ok(Some(status)) if status.stopped() => Ok(ChildKernelState::Stopped),
            Ok(Some(status)) if status.exited() || status.killed() || status.dumped() => {
                Ok(ChildKernelState::Exited)
            }
            Ok(Some(_)) | Ok(None) => Ok(ChildKernelState::Running),
            Err(rustix::io::Errno::INTR) => Ok(ChildKernelState::Running),
            Err(_) => Err(ProductionEntryError::Spawn),
        }
    }

    fn signal_coordinator(
        &self,
        signal: rustix::process::Signal,
    ) -> Result<(), ProductionEntryError> {
        let pid = rustix::process::Pid::from_child(&self.child);
        if pid != self.coordinator_group
            || rustix::process::getpgid(Some(pid)).map_err(|_| ProductionEntryError::Spawn)?
                != self.coordinator_group
        {
            return Err(ProductionEntryError::Spawn);
        }
        rustix::process::kill_process_group(self.coordinator_group, signal)
            .map_err(|_| ProductionEntryError::Spawn)
    }

    fn finish_verified(mut self, status: ExitStatus) -> ExitCode {
        if restore_anchor_terminal(&self.snapshot, self.anchor_group, self.coordinator_group)
            .is_err()
        {
            self.child_status = Some(status);
            self.park();
        }
        propagate_anchor_status(status)
    }

    fn emergency_failure(mut self, _error: ProductionEntryError) -> ExitCode {
        self.signals.freeze_for_shutdown();
        if self.child_status.is_none() && self.reap_after_forced_shutdown().is_err() {
            self.park();
        }
        if restore_anchor_terminal(&self.snapshot, self.anchor_group, self.coordinator_group)
            .is_err()
        {
            self.park();
        }
        // Restoring the terminal makes the controlling TTY safe, but it is
        // not a cleanup proof. A missing, malformed, or trailing completion
        // frame means the guardian may still retain B or an unproven provider
        // tree. Keep the shell-facing anchor (and its immutable completion
        // receiver) alive forever instead of turning that uncertainty into an
        // ordinary exit status.
        if !self.completion_verified {
            self.park();
        }
        ExitCode::from(1)
    }

    fn reap_after_forced_shutdown(&mut self) -> Result<(), ProductionEntryError> {
        let _ = self.signal_coordinator(rustix::process::Signal::TERM);
        if self.await_child_exit(Instant::now() + Duration::from_secs(2))? {
            return Ok(());
        }
        let _ = self.signal_coordinator(rustix::process::Signal::KILL);
        if self.await_child_exit(Instant::now() + Duration::from_secs(5))? {
            Ok(())
        } else {
            Err(ProductionEntryError::Spawn)
        }
    }

    fn await_child_exit(&mut self, deadline: Instant) -> Result<bool, ProductionEntryError> {
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.child_status = Some(status);
                    return Ok(true);
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted && Instant::now() < deadline => {}
                Ok(None) => return Ok(false),
                Err(_) => return Err(ProductionEntryError::Spawn),
            }
        }
    }

    fn park(self) -> ! {
        RetainedAnchorState {
            child: self.child,
            snapshot: self.snapshot,
            completion: self.completion,
        }
        .park()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildKernelState {
    Running,
    Stopped,
    Exited,
}

fn rustix_signal(signal: UnixSignal) -> rustix::process::Signal {
    match signal {
        UnixSignal::Hup => rustix::process::Signal::HUP,
        UnixSignal::Int => rustix::process::Signal::INT,
        UnixSignal::Quit => rustix::process::Signal::QUIT,
        UnixSignal::Term => rustix::process::Signal::TERM,
    }
}

fn restore_anchor_terminal(
    snapshot: &TerminalSnapshot,
    anchor_group: rustix::process::Pid,
    coordinator_group: rustix::process::Pid,
) -> Result<(), ProductionEntryError> {
    if rustix::process::getpgrp() != anchor_group
        || calcifer_unix_child_fd::descriptor_identity(io::stdin().as_fd())
            .map_err(|_| ProductionEntryError::Terminal)?
            != snapshot.descriptor_identity()
    {
        return Err(ProductionEntryError::Terminal);
    }
    let foreground =
        rustix::termios::tcgetpgrp(io::stdin()).map_err(|_| ProductionEntryError::Terminal)?;
    if foreground != anchor_group && foreground != coordinator_group {
        return Err(ProductionEntryError::Terminal);
    }
    if foreground != anchor_group {
        select_foreground_group(snapshot, coordinator_group, anchor_group)?;
    }
    snapshot
        .restore_with_sigttou_block(io::stdin())
        .map(|_| ())
        .map_err(|_| ProductionEntryError::Terminal)
}

fn propagate_anchor_status(status: ExitStatus) -> ExitCode {
    if let Some(code) = status.code().and_then(|code| u8::try_from(code).ok()) {
        return ExitCode::from(code);
    }
    if let Some(signal) = status.signal() {
        let _ = signal_hook::low_level::emulate_default_handler(signal);
    }
    ExitCode::from(1)
}

/// Closed-over real-exec harness for the shell-facing anchor boundary. It is
/// available only in the existing internal fixture feature and cannot select
/// a provider executable or managed profile.
pub(super) fn run_entry_anchor_fixture(scenario: &str) -> ExitCode {
    match try_run_entry_anchor_fixture(scenario) {
        Ok(code) => code,
        Err(_) => ExitCode::from(70),
    }
}

fn try_run_entry_anchor_fixture(scenario: &str) -> Result<ExitCode, ProductionEntryError> {
    validate_entry_fixture_scenario(scenario)?;
    let proof =
        claim_controlling_terminal_from_stdin().map_err(|_| ProductionEntryError::Terminal)?;
    if proof.process() != proof.process_group()
        || proof.process() != proof.session()
        || proof.process() != proof.foreground_process_group()
    {
        return Err(ProductionEntryError::Terminal);
    }
    let executable = env::current_exe().map_err(|_| ProductionEntryError::Executable)?;
    let mut command = Command::new(executable);
    remove_internal_supervisor_environment(&mut command);
    command.args(["entry-coordinator", scenario]);
    let late_signal = match scenario {
        "late-hup-after-exit" => Some(UnixSignal::Hup),
        "late-term-after-exit" => Some(UnixSignal::Term),
        _ => None,
    };
    run_anchor_command_inner(command, late_signal)
}

pub(super) fn run_entry_coordinator_fixture(scenario: &str) -> ExitCode {
    match try_run_entry_coordinator_fixture(scenario) {
        Ok(code) => code,
        Err(_) => ExitCode::from(70),
    }
}

fn try_run_entry_coordinator_fixture(scenario: &str) -> Result<ExitCode, ProductionEntryError> {
    validate_entry_fixture_scenario(scenario)?;
    let completion = CompletionTransit::take_inherited()
        .map_err(|_| ProductionEntryError::Environment)?
        .into_guardian();
    await_current_process_group_foreground(Instant::now() + Duration::from_secs(15))?;
    let snapshot =
        TerminalSnapshot::capture(io::stdin()).map_err(|_| ProductionEntryError::Terminal)?;
    let raw = snapshot
        .enter_raw_after_input_flush(io::stdin())
        .map_err(|_| ProductionEntryError::Terminal)?;
    if raw.descriptor_identity() != snapshot.descriptor_identity() {
        return Err(ProductionEntryError::Terminal);
    }

    match scenario {
        "normal" => finish_entry_fixture(snapshot, completion, ExitCode::SUCCESS),
        "nonzero" => finish_entry_fixture(snapshot, completion, ExitCode::from(42)),
        "missing" => {
            // Keep the malformed-generation raw transition externally
            // observable before the coordinator closes without a frame.
            std::thread::sleep(Duration::from_millis(100));
            drop((snapshot, completion));
            Ok(ExitCode::from(1))
        }
        "invalid" => {
            // Publish one complete, wrong fixed-width frame so the anchor's
            // invalid-frame path is exercised independently from EOF/trailing
            // validation.
            std::thread::sleep(Duration::from_millis(100));
            let mut completion = completion;
            completion
                .stream
                .write_all(b"BADFRAME")
                .map_err(|_| ProductionEntryError::Channel)?;
            completion
                .stream
                .shutdown(std::net::Shutdown::Write)
                .map_err(|_| ProductionEntryError::Channel)?;
            drop((snapshot, completion));
            Ok(ExitCode::from(1))
        }
        "trailing" => {
            // Keep the malformed-generation raw transition externally
            // observable before the invalid completion payload is published.
            std::thread::sleep(Duration::from_millis(100));
            let mut completion = completion;
            completion
                .stream
                .write_all(&COMPLETION_FRAME)
                .map_err(|_| ProductionEntryError::Channel)?;
            completion
                .stream
                .write_all(b"x")
                .map_err(|_| ProductionEntryError::Channel)?;
            completion
                .stream
                .shutdown(std::net::Shutdown::Write)
                .map_err(|_| ProductionEntryError::Channel)?;
            drop((snapshot, completion));
            Ok(ExitCode::from(1))
        }
        "hup" => finish_entry_fixture_after_signal(snapshot, completion, UnixSignal::Hup),
        "term" => finish_entry_fixture_after_signal(snapshot, completion, UnixSignal::Term),
        "late-hup-after-exit" => {
            finish_entry_fixture_with_late_anchor_signal(snapshot, completion, UnixSignal::Hup)
        }
        "late-term-after-exit" => {
            finish_entry_fixture_with_late_anchor_signal(snapshot, completion, UnixSignal::Term)
        }
        "suspend-resume" => finish_entry_fixture_after_suspend(snapshot, completion),
        "retained" => finish_retained_entry_fixture(snapshot, completion),
        _ => Err(ProductionEntryError::Arguments),
    }
}

fn validate_entry_fixture_scenario(scenario: &str) -> Result<(), ProductionEntryError> {
    match scenario {
        "normal"
        | "nonzero"
        | "missing"
        | "invalid"
        | "trailing"
        | "hup"
        | "term"
        | "late-hup-after-exit"
        | "late-term-after-exit"
        | "suspend-resume"
        | "retained" => Ok(()),
        _ => Err(ProductionEntryError::Arguments),
    }
}

fn finish_entry_fixture(
    snapshot: TerminalSnapshot,
    completion: GuardianCompletion,
    code: ExitCode,
) -> Result<ExitCode, ProductionEntryError> {
    let restored = snapshot
        .restore_with_sigttou_block(io::stdin())
        .map_err(|_| ProductionEntryError::Terminal)?;
    if restored.descriptor_identity() != snapshot.descriptor_identity() {
        return Err(ProductionEntryError::Terminal);
    }
    completion
        .publish_raw()
        .map_err(|_| ProductionEntryError::Channel)?;
    Ok(code)
}

fn finish_entry_fixture_after_signal(
    snapshot: TerminalSnapshot,
    completion: GuardianCompletion,
    expected: UnixSignal,
) -> Result<ExitCode, ProductionEntryError> {
    let signals =
        CoordinatorSignalLatches::install().map_err(|_| ProductionEntryError::Terminal)?;
    loop {
        match signals.next_active() {
            Some(CoordinatorSignalAction::Forward(signal)) if signal == expected => break,
            Some(_) => return Err(ProductionEntryError::Terminal),
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    // Makes "anchor did not exit merely because it received HUP/TERM"
    // externally observable without a marker or transcript channel.
    std::thread::sleep(Duration::from_millis(200));
    let restored = snapshot
        .restore_with_sigttou_block(io::stdin())
        .map_err(|_| ProductionEntryError::Terminal)?;
    if restored.descriptor_identity() != snapshot.descriptor_identity() {
        return Err(ProductionEntryError::Terminal);
    }
    completion
        .publish_raw()
        .map_err(|_| ProductionEntryError::Channel)?;
    let signal = unix_signal_number(expected);
    signal_hook::low_level::emulate_default_handler(signal)
        .map_err(|_| ProductionEntryError::Spawn)?;
    Ok(ExitCode::from(1))
}

fn finish_entry_fixture_with_late_anchor_signal(
    snapshot: TerminalSnapshot,
    completion: GuardianCompletion,
    signal: UnixSignal,
) -> Result<ExitCode, ProductionEntryError> {
    let restored = snapshot
        .restore_with_sigttou_block(io::stdin())
        .map_err(|_| ProductionEntryError::Terminal)?;
    if restored.descriptor_identity() != snapshot.descriptor_identity() {
        return Err(ProductionEntryError::Terminal);
    }
    completion
        .publish_raw()
        .map_err(|_| ProductionEntryError::Channel)?;
    let anchor = rustix::process::getppid().ok_or(ProductionEntryError::Spawn)?;
    if rustix::process::getpgid(Some(anchor)).map_err(|_| ProductionEntryError::Spawn)? != anchor {
        return Err(ProductionEntryError::Spawn);
    }
    rustix::process::kill_process(anchor, rustix_signal(signal))
        .map_err(|_| ProductionEntryError::Spawn)?;
    Ok(ExitCode::from(42))
}

fn unix_signal_number(signal: UnixSignal) -> i32 {
    match signal {
        UnixSignal::Hup => signal_hook::consts::signal::SIGHUP,
        UnixSignal::Int => signal_hook::consts::signal::SIGINT,
        UnixSignal::Quit => signal_hook::consts::signal::SIGQUIT,
        UnixSignal::Term => signal_hook::consts::signal::SIGTERM,
    }
}

fn finish_entry_fixture_after_suspend(
    snapshot: TerminalSnapshot,
    completion: GuardianCompletion,
) -> Result<ExitCode, ProductionEntryError> {
    let signals =
        CoordinatorSignalLatches::install().map_err(|_| ProductionEntryError::Terminal)?;
    loop {
        match signals.next_active() {
            Some(CoordinatorSignalAction::Suspend) => break,
            Some(_) => return Err(ProductionEntryError::Terminal),
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    let restored = snapshot
        .restore_with_sigttou_block(io::stdin())
        .map_err(|_| ProductionEntryError::Terminal)?;
    if restored.descriptor_identity() != snapshot.descriptor_identity() {
        return Err(ProductionEntryError::Terminal);
    }
    signals
        .stop_after_suspended_ack()
        .map_err(|_| ProductionEntryError::Terminal)?;
    let raw = snapshot
        .enter_raw_after_input_flush(io::stdin())
        .map_err(|_| ProductionEntryError::Terminal)?;
    if raw.descriptor_identity() != snapshot.descriptor_identity() {
        return Err(ProductionEntryError::Terminal);
    }
    finish_entry_fixture(snapshot, completion, ExitCode::SUCCESS)
}

fn finish_retained_entry_fixture(
    snapshot: TerminalSnapshot,
    completion: GuardianCompletion,
) -> Result<ExitCode, ProductionEntryError> {
    let signals =
        CoordinatorSignalLatches::install().map_err(|_| ProductionEntryError::Terminal)?;
    loop {
        match signals.next_active() {
            Some(CoordinatorSignalAction::Forward(UnixSignal::Term)) => {
                return finish_entry_fixture(snapshot, completion, ExitCode::from(1));
            }
            Some(_) => return Err(ProductionEntryError::Terminal),
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

struct ProductionCoordinatorConfig<'a> {
    registry: &'a Registry,
    profile: &'a Profile,
    working_directory: &'a Path,
    thread_id: &'a str,
    codex_executable: &'a Path,
    guardian_executable: &'a Path,
}

/// Concrete production-shaped coordinator path. A is acquired and refetched
/// before the guardian can acquire B; the coordinator then owns the exact
/// direct child, lifecycle endpoint, and captured outer-terminal authority.
fn run_production_coordinator(
    config: ProductionCoordinatorConfig<'_>,
    completion: CompletionTransit,
) -> ExitCode {
    match try_run_production_coordinator(config, completion) {
        Ok(outcome) => apply_coordinator_outcome(outcome),
        Err(_) => ExitCode::from(1),
    }
}

fn try_run_production_coordinator(
    config: ProductionCoordinatorConfig<'_>,
    completion: CompletionTransit,
) -> Result<CoordinatorRunOutcome, ProductionEntryError> {
    validate_coordinator_config(&config)?;
    let foreground_process_group =
        await_current_process_group_foreground(Instant::now() + Duration::from_secs(15))?;
    let authority = config
        .registry
        .lock_profile_coordinator(config.profile)
        .map_err(|_| ProductionEntryError::Profile)?;
    let current = config
        .registry
        .refetch_by_id_under_lease(Provider::Codex, &config.profile.id)
        .map_err(|_| ProductionEntryError::Profile)?;
    if &current != config.profile {
        return Err(ProductionEntryError::Profile);
    }

    let terminal_pair = TerminalChannelPair::new().map_err(|_| ProductionEntryError::Channel)?;
    let (coordinator_endpoint, guardian_endpoint) = terminal_pair.split();
    let terminal = CoordinatorTerminal::capture(io::stdin(), coordinator_endpoint)
        .map_err(|_| ProductionEntryError::Terminal)?;
    let recovery =
        RecoveryTty::duplicate(io::stdin()).map_err(|_| ProductionEntryError::Terminal)?;
    let lifecycle_pair = LifecyclePair::new().map_err(|_| ProductionEntryError::Channel)?;

    let mut command = guardian_command(&config, foreground_process_group)?;
    command
        .stdout(
            guardian_endpoint
                .into_stdio()
                .map_err(|_| ProductionEntryError::Terminal)?,
        )
        .stderr(
            recovery
                .into_stdio()
                .map_err(|_| ProductionEntryError::Terminal)?,
        )
        .process_group(0);

    let spawned = match spawn_guardian_with_lifecycle_stdin_and_completion(
        command,
        lifecycle_pair,
        completion.as_fd(),
    ) {
        Ok(spawned) => spawned,
        Err(failure) => {
            let (lifecycle, child, _error) = failure.into_parts();
            let Some(child) = child else {
                drop((authority, lifecycle, terminal, completion));
                return Err(ProductionEntryError::Spawn);
            };
            drop(completion);
            return match ProductionCoordinator::assemble(
                authority,
                child,
                lifecycle,
                terminal,
                production_coordinator_bounds()?,
            ) {
                Ok(coordinator) => Ok(coordinator.run()),
                Err(failure) => park_coordinator_setup_failure(failure),
            };
        }
    };
    let (guardian, lifecycle) = spawned.into_parts();
    drop(completion);
    let coordinator = match ProductionCoordinator::assemble(
        authority,
        guardian,
        lifecycle,
        terminal,
        production_coordinator_bounds()?,
    ) {
        Ok(coordinator) => coordinator,
        Err(failure) => park_coordinator_setup_failure(failure),
    };
    Ok(coordinator.run())
}

fn await_current_process_group_foreground(deadline: Instant) -> Result<i32, ProductionEntryError> {
    let process = rustix::process::getpid();
    let process_group = rustix::process::getpgrp();
    if process != process_group {
        return Err(ProductionEntryError::Terminal);
    }
    loop {
        match rustix::termios::tcgetpgrp(io::stdin()) {
            Ok(foreground) if foreground == process_group => {
                return Ok(process_group.as_raw_nonzero().get());
            }
            Ok(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Err(rustix::io::Errno::INTR) if Instant::now() < deadline => {}
            Ok(_) | Err(_) => return Err(ProductionEntryError::Terminal),
        }
    }
}

fn guardian_command(
    config: &ProductionCoordinatorConfig<'_>,
    foreground_process_group: i32,
) -> Result<Command, ProductionEntryError> {
    let mut command = Command::new(config.guardian_executable);
    crate::providers::codex::sanitize_managed_environment(&mut command);
    remove_internal_supervisor_environment(&mut command);
    command
        .env(ROLE_ENV, GUARDIAN_ROLE_V1)
        .env(PROFILE_ID_ENV, &config.profile.id)
        .env(THREAD_ID_ENV, config.thread_id)
        .env(CODEX_EXECUTABLE_ENV, config.codex_executable)
        .env(
            FOREGROUND_PROCESS_GROUP_ENV,
            foreground_process_group.to_string(),
        )
        .env("CALCIFER_HOME", config.registry.managed_root())
        .env_remove("CODEX_HOME")
        .current_dir(config.working_directory);
    Ok(command)
}

fn remove_internal_supervisor_environment(command: &mut Command) {
    for name in [
        ROLE_ENV,
        PROFILE_ID_ENV,
        THREAD_ID_ENV,
        CODEX_EXECUTABLE_ENV,
        FOREGROUND_PROCESS_GROUP_ENV,
        calcifer_unix_child_fd::READINESS_FD_ENV,
    ] {
        command.env_remove(name);
    }
}

fn apply_coordinator_outcome(outcome: CoordinatorRunOutcome) -> ExitCode {
    match outcome {
        CoordinatorRunOutcome::Terminal(result) => {
            let disposition = result.report().guardian_exit;
            drop(result.into_authority());
            apply_guardian_disposition(disposition)
        }
        CoordinatorRunOutcome::Retained(retained) => retained.park(),
    }
}

fn apply_guardian_disposition(disposition: GuardianExitDisposition) -> ExitCode {
    match disposition {
        GuardianExitDisposition::Code(code) => ExitCode::from(code),
        GuardianExitDisposition::InternalFailure => ExitCode::from(1),
        GuardianExitDisposition::Signal(signal) => {
            let _ = signal_hook::low_level::emulate_default_handler(i32::from(signal));
            ExitCode::from(1)
        }
    }
}

fn park_coordinator_setup_failure(failure: Box<super::coordinator::CoordinatorSetupFailure>) -> ! {
    std::mem::forget(failure);
    loop {
        std::thread::park();
    }
}

fn validate_coordinator_config(
    config: &ProductionCoordinatorConfig<'_>,
) -> Result<(), ProductionEntryError> {
    if config.profile.provider != Provider::Codex
        || config.profile.id.len() > MAX_PROFILE_ID_BYTES
        || config.thread_id.len() > MAX_THREAD_ID_BYTES
    {
        return Err(ProductionEntryError::Arguments);
    }
    validate_thread_id(config.thread_id)?;
    validate_canonical_directory(config.working_directory, MAX_WORKING_DIRECTORY_BYTES)?;
    validate_canonical_file(config.codex_executable, MAX_EXECUTABLE_PATH_BYTES)?;
    validate_canonical_file(config.guardian_executable, MAX_EXECUTABLE_PATH_BYTES)
}

fn bounded_environment_utf8(name: &str, maximum: usize) -> Result<String, ProductionEntryError> {
    let value = env::var(name).map_err(|_| ProductionEntryError::Environment)?;
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ProductionEntryError::Environment);
    }
    Ok(value)
}

fn bounded_environment_path(
    name: &str,
    maximum: usize,
    file: bool,
) -> Result<PathBuf, ProductionEntryError> {
    let value = env::var_os(name).ok_or(ProductionEntryError::Environment)?;
    if os_str_bytes(&value).is_empty() || os_str_bytes(&value).len() > maximum {
        return Err(ProductionEntryError::Environment);
    }
    let path = PathBuf::from(value);
    if file {
        validate_canonical_file(&path, maximum)?;
    } else {
        validate_canonical_directory(&path, maximum)?;
    }
    Ok(path)
}

fn validate_canonical_file(path: &Path, maximum: usize) -> Result<(), ProductionEntryError> {
    if !path.is_absolute()
        || os_str_bytes(path.as_os_str()).len() > maximum
        || fs::canonicalize(path).ok().as_deref() != Some(path)
        || !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
    {
        return Err(ProductionEntryError::Executable);
    }
    Ok(())
}

fn validate_canonical_directory(path: &Path, maximum: usize) -> Result<(), ProductionEntryError> {
    if !path.is_absolute()
        || os_str_bytes(path.as_os_str()).len() > maximum
        || fs::canonicalize(path).ok().as_deref() != Some(path)
        || !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
    {
        return Err(ProductionEntryError::Environment);
    }
    Ok(())
}

fn validate_thread_id(thread_id: &str) -> Result<(), ProductionEntryError> {
    let parsed = uuid::Uuid::parse_str(thread_id).map_err(|_| ProductionEntryError::Arguments)?;
    if parsed.to_string() == thread_id {
        Ok(())
    } else {
        Err(ProductionEntryError::Arguments)
    }
}

#[cfg(target_os = "linux")]
fn os_str_bytes(value: &OsStr) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes()
}

#[cfg(target_os = "macos")]
fn os_str_bytes(value: &OsStr) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes()
}

fn production_coordinator_bounds() -> Result<CoordinatorBounds, ProductionEntryError> {
    CoordinatorBounds::new(Duration::from_secs(15), Duration::from_millis(20))
        .map_err(|_| ProductionEntryError::Environment)
}

fn production_guardian_bounds() -> GuardianBounds {
    GuardianBounds {
        phase_timeout: Duration::from_secs(15),
        poll_interval: Duration::from_millis(20),
        startup_timeout: Duration::from_secs(120),
        compatibility_timeout: Duration::from_secs(90),
        relay_start_timeout: Duration::from_secs(15),
        containment_timeout: Duration::from_secs(15),
        tui_grace: Duration::from_secs(2),
        tui_forced: Duration::from_secs(5),
        relay_shutdown_timeout: Duration::from_secs(10),
        monitor_shutdown_timeout: Duration::from_secs(10),
        app_grace: Duration::from_secs(2),
        app_forced: Duration::from_secs(5),
        app_cleanup_timeout: Duration::from_secs(10),
        build_cleanup_timeout: Duration::from_secs(10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    enum ScriptedRead {
        Bytes(Vec<u8>),
        Error(io::ErrorKind),
        Eof,
    }

    struct ScriptedCompletionReader {
        steps: std::collections::VecDeque<ScriptedRead>,
        read_calls: usize,
    }

    impl ScriptedCompletionReader {
        fn new(steps: impl IntoIterator<Item = ScriptedRead>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                read_calls: 0,
            }
        }
    }

    impl Read for ScriptedCompletionReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.read_calls = self.read_calls.saturating_add(1);
            match self.steps.pop_front().unwrap_or(ScriptedRead::Eof) {
                ScriptedRead::Bytes(bytes) => {
                    let copied = buffer.len().min(bytes.len());
                    buffer[..copied].copy_from_slice(&bytes[..copied]);
                    if copied < bytes.len() {
                        self.steps
                            .push_front(ScriptedRead::Bytes(bytes[copied..].to_vec()));
                    }
                    Ok(copied)
                }
                ScriptedRead::Error(kind) => Err(io::Error::from(kind)),
                ScriptedRead::Eof => Ok(0),
            }
        }
    }

    fn poll_until_terminal(
        anchor: &mut AnchorCompletion,
    ) -> Result<CompletionPoll, CompletionError> {
        for _ in 0..100 {
            match anchor.poll_once()? {
                CompletionPoll::Verified => return Ok(CompletionPoll::Verified),
                CompletionPoll::RetainedUnrecoverable => {
                    return Ok(CompletionPoll::RetainedUnrecoverable);
                }
                CompletionPoll::Pending => std::thread::yield_now(),
            }
        }
        Ok(CompletionPoll::Pending)
    }

    #[test]
    fn completion_requires_exact_one_shot_frame_followed_by_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, transit) = CompletionPair::new()?.split();
        transit.into_guardian().publish_raw()?;
        assert_eq!(poll_until_terminal(&mut anchor)?, CompletionPoll::Verified);
        Ok(())
    }

    #[test]
    fn retained_unrecoverable_requires_its_distinct_exact_frame_and_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(RETAINED_UNRECOVERABLE_FRAME, *b"CFRET\x01\r\n");
        assert_eq!(RETAINED_UNRECOVERABLE_FRAME.len(), COMPLETION_FRAME.len());
        let (mut anchor, transit) = CompletionPair::new()?.split();
        transit.into_guardian().publish_retained_unrecoverable()?;
        assert_eq!(
            poll_until_terminal(&mut anchor)?,
            CompletionPoll::RetainedUnrecoverable
        );

        let (mut partial, mut transit) = CompletionPair::new()?.split();
        transit
            .stream
            .write_all(&RETAINED_UNRECOVERABLE_FRAME[..RETAINED_UNRECOVERABLE_FRAME.len() - 1])?;
        transit.stream.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(partial.poll_once(), Err(CompletionError::MissingFrame));

        let (mut trailing, mut transit) = CompletionPair::new()?.split();
        transit.stream.write_all(&RETAINED_UNRECOVERABLE_FRAME)?;
        transit.stream.write_all(b"x")?;
        transit.stream.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(trailing.poll_once(), Err(CompletionError::TrailingData));

        let (mut wrong, mut transit) = CompletionPair::new()?.split();
        let mut wrong_frame = RETAINED_UNRECOVERABLE_FRAME;
        wrong_frame[5] = 2;
        transit.stream.write_all(&wrong_frame)?;
        transit.stream.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(wrong.poll_once(), Err(CompletionError::InvalidFrame));

        let (mut raced, mut transit) = CompletionPair::new()?.split();
        transit.stream.write_all(&COMPLETION_FRAME)?;
        transit.stream.write_all(&RETAINED_UNRECOVERABLE_FRAME)?;
        transit.stream.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(raced.poll_once(), Err(CompletionError::TrailingData));
        Ok(())
    }

    #[test]
    fn retained_unrecoverable_is_never_classified_as_success_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, transit) = CompletionPair::new()?.split();
        transit.into_guardian().publish_retained_unrecoverable()?;
        let observation = poll_until_terminal(&mut anchor)?;
        assert_ne!(observation, CompletionPoll::Verified);
        assert_eq!(
            anchor_completion_action(observation),
            AnchorCompletionAction::ParkRetained
        );
        Ok(())
    }

    #[test]
    fn retained_publication_attempt_closes_after_owner_loss_without_minting_success()
    -> Result<(), Box<dyn std::error::Error>> {
        let (anchor, transit) = CompletionPair::new()?.split();
        drop(anchor);
        assert_eq!(
            transit.into_guardian().publish_retained_unrecoverable(),
            Err(CompletionError::Io)
        );
        Ok(())
    }

    #[test]
    fn provider_release_publication_epipe_consumes_authority_without_owner_success()
    -> Result<(), Box<dyn std::error::Error>> {
        let proof =
            super::super::session::SessionLifecycleProjection::failed_before_provider_start(
                super::super::startup::provider_never_started_for_completion_test(),
                None,
                super::super::protocol::WorkerJoinStatus::NotStarted,
            )
            .into_provider_release();
        let (anchor, transit) = CompletionPair::new()?.split();
        let completion = transit.into_guardian();

        // Dropping the sole anchor receiver makes the fixed frame write fail
        // with the redacted transport classification. Both the real startup
        // proof and endpoint are move-consumed by this one attempt, and no
        // owner remains that could observe Verified/shell success.
        drop(anchor);
        assert_eq!(
            completion.publish_after_provider_release(proof),
            Err(CompletionError::Io)
        );
        Ok(())
    }

    #[test]
    fn completion_rejects_eof_without_frame_and_any_trailing_byte()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut missing, transit) = CompletionPair::new()?.split();
        drop(transit);
        assert_eq!(missing.poll_once(), Err(CompletionError::MissingFrame));

        let (mut trailing, mut transit) = CompletionPair::new()?.split();
        transit.stream.write_all(&COMPLETION_FRAME)?;
        transit.stream.write_all(b"x")?;
        transit.stream.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(trailing.poll_once(), Err(CompletionError::TrailingData));
        assert_eq!(
            trailing.poll_once(),
            Err(CompletionError::TrailingData),
            "a terminal framing failure must not be re-parsed as successful EOF"
        );

        let (mut invalid, mut transit) = CompletionPair::new()?.split();
        transit.stream.write_all(b"BADFRAME")?;
        transit.stream.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(invalid.poll_once(), Err(CompletionError::InvalidFrame));
        Ok(())
    }

    #[test]
    fn completion_parse_and_transport_failures_are_sticky_terminal_outcomes()
    -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                CompletionError::MissingFrame,
                vec![
                    ScriptedRead::Eof,
                    ScriptedRead::Bytes(RETAINED_UNRECOVERABLE_FRAME.to_vec()),
                    ScriptedRead::Eof,
                ],
            ),
            (
                CompletionError::InvalidFrame,
                vec![
                    ScriptedRead::Bytes(b"BADFRAME".to_vec()),
                    ScriptedRead::Bytes(RETAINED_UNRECOVERABLE_FRAME.to_vec()),
                    ScriptedRead::Eof,
                ],
            ),
            (
                CompletionError::TrailingData,
                vec![
                    ScriptedRead::Bytes(COMPLETION_FRAME.to_vec()),
                    ScriptedRead::Bytes(b"x".to_vec()),
                    ScriptedRead::Bytes(RETAINED_UNRECOVERABLE_FRAME.to_vec()),
                    ScriptedRead::Eof,
                ],
            ),
            (
                CompletionError::Io,
                vec![
                    ScriptedRead::Bytes(COMPLETION_FRAME.to_vec()),
                    ScriptedRead::Error(io::ErrorKind::ConnectionReset),
                    ScriptedRead::Bytes(RETAINED_UNRECOVERABLE_FRAME.to_vec()),
                    ScriptedRead::Eof,
                ],
            ),
        ];

        for (expected, steps) in cases {
            let (mut anchor, _transit) = CompletionPair::new()?.split();
            let mut reader = ScriptedCompletionReader::new(steps);
            assert_eq!(anchor.poll_once_from_reader(&mut reader), Err(expected));
            let reads_at_failure = reader.read_calls;

            assert_eq!(anchor.poll_once_from_reader(&mut reader), Err(expected));
            assert_eq!(reader.read_calls, reads_at_failure);
            assert_eq!(
                anchor.request_recovery(Instant::now() + Duration::from_secs(1)),
                Err(expected)
            );
            assert_eq!(reader.read_calls, reads_at_failure);
        }
        Ok(())
    }

    #[test]
    fn interrupted_and_would_block_completion_reads_remain_retryable()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, _transit) = CompletionPair::new()?.split();
        let mut reader = ScriptedCompletionReader::new([
            ScriptedRead::Error(io::ErrorKind::Interrupted),
            ScriptedRead::Error(io::ErrorKind::WouldBlock),
            ScriptedRead::Bytes(RETAINED_UNRECOVERABLE_FRAME.to_vec()),
            ScriptedRead::Eof,
        ]);

        assert_eq!(
            anchor.poll_once_from_reader(&mut reader)?,
            CompletionPoll::Pending
        );
        assert_eq!(
            anchor.poll_once_from_reader(&mut reader)?,
            CompletionPoll::RetainedUnrecoverable
        );
        Ok(())
    }

    #[test]
    fn retained_recovery_request_is_one_shot_duplex_and_preserves_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, transit) = CompletionPair::new()?.split();
        let mut guardian = transit.into_guardian();

        anchor.request_recovery(Instant::now() + Duration::from_secs(1))?;
        assert_eq!(
            guardian.poll_recovery_request(Instant::now() + Duration::from_secs(1))?,
            RecoveryRequestPoll::Verified
        );
        assert_eq!(
            anchor.request_recovery(Instant::now() + Duration::from_secs(1)),
            Err(CompletionError::RecoveryReplay)
        );

        guardian.publish_raw()?;
        assert_eq!(poll_until_terminal(&mut anchor)?, CompletionPoll::Verified);
        Ok(())
    }

    #[test]
    fn test_checkpoint_roundtrip_precedes_real_recovery_authority_and_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, transit) = CompletionPair::new()?.split();
        let mut guardian = transit.into_guardian();
        let deadline = Instant::now() + Duration::from_secs(1);

        guardian.publish_test_checkpoint(RecoveryCheckpoint::Active, deadline)?;
        anchor.await_test_checkpoint(RecoveryCheckpoint::Active, deadline)?;

        assert_eq!(anchor.received, 0);
        assert_eq!(anchor.terminal_frame, None);
        assert_eq!(anchor.terminal_error, None);
        assert_eq!(
            guardian.poll_recovery_request(Instant::now())?,
            RecoveryRequestPoll::Pending,
            "a test checkpoint is synchronization only and grants no recovery authority"
        );

        anchor.request_recovery(deadline)?;
        assert_eq!(
            guardian.poll_recovery_request(deadline)?,
            RecoveryRequestPoll::Verified
        );
        guardian.publish_raw()?;
        assert_eq!(poll_until_terminal(&mut anchor)?, CompletionPoll::Verified);
        Ok(())
    }

    #[test]
    fn test_checkpoint_wire_is_fixed_for_all_closed_phases() {
        let cases = [
            (RecoveryCheckpoint::StartupQueued, 1),
            (RecoveryCheckpoint::Ready, 2),
            (RecoveryCheckpoint::Active, 3),
            (RecoveryCheckpoint::Suspended, 4),
            (RecoveryCheckpoint::RetainedQuiescing, 5),
            (RecoveryCheckpoint::RetainedRestorePending, 6),
            (RecoveryCheckpoint::RetainedCleanupPending, 7),
        ];

        for (checkpoint, phase) in cases {
            assert_eq!(
                encode_test_checkpoint(checkpoint),
                [b'C', b'F', b'C', b'P', 1, phase, b'\r', b'\n']
            );
        }
    }

    fn assert_test_checkpoint_failure_is_sticky(
        anchor: &mut AnchorCompletion,
        expected: CompletionError,
    ) {
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            anchor.await_test_checkpoint(RecoveryCheckpoint::Active, deadline),
            Err(expected)
        );
        assert_eq!(anchor.frame, [0; COMPLETION_FRAME.len()]);
        assert_eq!(anchor.received, 0);
        assert_eq!(anchor.terminal_frame, None);
        assert_eq!(
            anchor.await_test_checkpoint(RecoveryCheckpoint::Active, deadline),
            Err(expected),
            "checkpoint protocol failures must be sticky"
        );
        assert_eq!(
            anchor.poll_once(),
            Err(expected),
            "a rejected checkpoint must not fall through to completion"
        );
        assert_eq!(
            anchor.request_recovery(deadline),
            Err(expected),
            "a rejected checkpoint must not authorize recovery"
        );
        assert!(
            anchor.recovery_request_consumed,
            "a failed recovery boundary must still consume its one shot"
        );
        assert_eq!(
            anchor.request_recovery(deadline),
            Err(CompletionError::RecoveryReplay),
            "a failed recovery boundary must never be retried"
        );
    }

    #[test]
    fn test_checkpoint_wrong_phase_version_and_terminal_frames_are_sticky()
    -> Result<(), Box<dyn std::error::Error>> {
        for frame in [
            encode_test_checkpoint(RecoveryCheckpoint::Ready),
            [b'C', b'F', b'C', b'P', 2, 3, b'\r', b'\n'],
            COMPLETION_FRAME,
            RETAINED_UNRECOVERABLE_FRAME,
        ] {
            let (mut anchor, mut transit) = CompletionPair::new()?.split();
            transit.stream.write_all(&frame)?;
            assert_test_checkpoint_failure_is_sticky(&mut anchor, CompletionError::InvalidFrame);
        }
        Ok(())
    }

    #[test]
    fn test_checkpoint_partial_trailing_and_eof_failures_are_sticky()
    -> Result<(), Box<dyn std::error::Error>> {
        let frame = encode_test_checkpoint(RecoveryCheckpoint::Active);

        let (mut partial, mut transit) = CompletionPair::new()?.split();
        transit.stream.write_all(&frame[..frame.len() - 1])?;
        transit.stream.shutdown(std::net::Shutdown::Write)?;
        assert_test_checkpoint_failure_is_sticky(&mut partial, CompletionError::MissingFrame);

        let (mut trailing, mut transit) = CompletionPair::new()?.split();
        transit.stream.write_all(&frame)?;
        transit.stream.write_all(b"x")?;
        assert_test_checkpoint_failure_is_sticky(&mut trailing, CompletionError::TrailingData);

        let (mut exact_then_eof, mut transit) = CompletionPair::new()?.split();
        transit.stream.write_all(&frame)?;
        transit.stream.shutdown(std::net::Shutdown::Write)?;
        assert_test_checkpoint_failure_is_sticky(
            &mut exact_then_eof,
            CompletionError::MissingFrame,
        );

        let (mut eof, transit) = CompletionPair::new()?.split();
        drop(transit);
        assert_test_checkpoint_failure_is_sticky(&mut eof, CompletionError::MissingFrame);
        Ok(())
    }

    #[test]
    fn rejected_checkpoint_recovery_attempt_closes_the_exact_write_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, mut transit) = CompletionPair::new()?.split();
        transit
            .stream
            .write_all(&encode_test_checkpoint(RecoveryCheckpoint::Ready))?;
        let deadline = Instant::now() + Duration::from_secs(1);

        assert_eq!(
            anchor.await_test_checkpoint(RecoveryCheckpoint::Active, deadline),
            Err(CompletionError::InvalidFrame)
        );
        assert_eq!(
            anchor.request_recovery(deadline),
            Err(CompletionError::InvalidFrame)
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            transit.stream.read(&mut byte)?,
            0,
            "the failed one-shot must still expose owner EOF to the exact guardian"
        );
        Ok(())
    }

    #[test]
    fn test_checkpoint_peer_exit_is_bounded_sticky_and_never_authorizes_recovery()
    -> Result<(), Box<dyn std::error::Error>> {
        for partial in [false, true] {
            let (mut anchor, mut transit) = CompletionPair::new()?.split();
            if partial {
                let frame = encode_test_checkpoint(RecoveryCheckpoint::Ready);
                transit.stream.write_all(&frame[..frame.len() - 1])?;
            }
            let started = Instant::now();
            let deadline = started + Duration::from_secs(2);
            assert_eq!(
                anchor.await_test_checkpoint_while_peer_live(
                    RecoveryCheckpoint::Ready,
                    deadline,
                    || Ok(false),
                ),
                Err(CompletionError::RecoveryPeerExited)
            );
            assert!(
                started.elapsed() < Duration::from_millis(250),
                "a dead checkpoint publisher must not park until the generation deadline"
            );
            assert_test_checkpoint_failure_is_sticky(
                &mut anchor,
                CompletionError::RecoveryPeerExited,
            );
        }
        Ok(())
    }

    #[test]
    fn test_checkpoint_replay_and_completion_decode_start_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(1);
        let (mut anchor, transit) = CompletionPair::new()?.split();
        let mut guardian = transit.into_guardian();
        guardian.publish_test_checkpoint(RecoveryCheckpoint::Active, deadline)?;
        anchor.await_test_checkpoint(RecoveryCheckpoint::Active, deadline)?;
        assert_eq!(
            anchor.await_test_checkpoint(RecoveryCheckpoint::Active, deadline),
            Err(CompletionError::RecoveryReplay)
        );

        let (mut late, transit) = CompletionPair::new()?.split();
        let mut guardian = transit.into_guardian();
        assert_eq!(late.poll_once()?, CompletionPoll::Pending);
        guardian.publish_test_checkpoint(RecoveryCheckpoint::Active, deadline)?;
        assert_eq!(
            late.await_test_checkpoint(RecoveryCheckpoint::Active, deadline),
            Err(CompletionError::RecoveryTooLate)
        );
        assert_eq!(late.frame, [0; COMPLETION_FRAME.len()]);
        assert_eq!(late.received, 0);
        assert_eq!(late.terminal_frame, None);
        assert_eq!(late.terminal_error, None);
        Ok(())
    }

    #[test]
    fn test_checkpoint_does_not_authorize_recovery_without_cfrcr_and_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(1);
        let (mut anchor, transit) = CompletionPair::new()?.split();
        let mut guardian = transit.into_guardian();

        guardian.publish_test_checkpoint(RecoveryCheckpoint::Ready, deadline)?;
        anchor.await_test_checkpoint(RecoveryCheckpoint::Ready, deadline)?;
        assert_eq!(
            guardian.poll_recovery_request(Instant::now())?,
            RecoveryRequestPoll::Pending
        );

        anchor.request_recovery(deadline)?;
        assert_eq!(
            guardian.poll_recovery_request(deadline)?,
            RecoveryRequestPoll::Verified
        );
        Ok(())
    }

    #[test]
    fn test_checkpoint_publication_is_bounded_without_consuming_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, transit) = CompletionPair::new()?.split();
        let mut guardian = transit.into_guardian();
        assert_eq!(
            guardian.publish_test_checkpoint(RecoveryCheckpoint::Active, Instant::now()),
            Err(CompletionError::RecoveryDeadline)
        );

        let deadline = Instant::now() + Duration::from_secs(1);
        guardian.publish_test_checkpoint(RecoveryCheckpoint::Active, deadline)?;
        anchor.await_test_checkpoint(RecoveryCheckpoint::Active, deadline)?;
        guardian.publish_raw()?;
        assert_eq!(poll_until_terminal(&mut anchor)?, CompletionPoll::Verified);
        Ok(())
    }

    #[test]
    fn retained_recovery_request_wire_binds_reason_and_generation_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, mut transit) = CompletionPair::new()?.split();
        let expected_generation = transit.identity;

        anchor.request_recovery(Instant::now() + Duration::from_secs(1))?;
        let mut wire = Vec::new();
        transit.stream.read_to_end(&mut wire)?;

        assert_eq!(wire.len(), 25);
        assert_eq!(&wire[..6], b"CFRCR\x01");
        assert_eq!(wire[6], 1);
        assert_eq!(&wire[7..15], &expected_generation.device.to_be_bytes());
        assert_eq!(&wire[15..23], &expected_generation.inode.to_be_bytes());
        assert_eq!(&wire[23..], b"\r\n");
        Ok(())
    }

    #[test]
    fn retained_recovery_request_rejects_late_send_after_completion_started()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, mut transit) = CompletionPair::new()?.split();
        transit.stream.write_all(&COMPLETION_FRAME[..1])?;
        assert_eq!(anchor.poll_once()?, CompletionPoll::Pending);
        assert_eq!(anchor.received, 1);

        assert_eq!(
            anchor.request_recovery(Instant::now() + Duration::from_secs(1)),
            Err(CompletionError::RecoveryTooLate)
        );
        assert_eq!(
            anchor.request_recovery(Instant::now() + Duration::from_secs(1)),
            Err(CompletionError::RecoveryReplay)
        );

        let (mut anchor, transit) = CompletionPair::new()?.split();
        transit.into_guardian().publish_raw()?;
        assert_eq!(
            anchor.request_recovery(Instant::now() + Duration::from_secs(1)),
            Err(CompletionError::RecoveryTooLate)
        );
        assert_eq!(poll_until_terminal(&mut anchor)?, CompletionPoll::Verified);
        Ok(())
    }

    #[test]
    fn retained_recovery_request_classifies_owner_eof_partial_invalid_and_trailing_frames()
    -> Result<(), Box<dyn std::error::Error>> {
        let (anchor, transit) = CompletionPair::new()?.split();
        let mut guardian = transit.into_guardian();
        anchor.stream.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            guardian.poll_recovery_request(Instant::now() + Duration::from_secs(1))?,
            RecoveryRequestPoll::OwnerLost
        );

        let (mut anchor, transit) = CompletionPair::new()?.split();
        let partial = encode_recovery_request_frame(transit.identity);
        let mut guardian = transit.into_guardian();
        anchor.stream.write_all(&partial[..partial.len() - 1])?;
        anchor.stream.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            guardian.poll_recovery_request(Instant::now() + Duration::from_secs(1))?,
            RecoveryRequestPoll::ProtocolRejectedOwnerLost
        );

        let (mut anchor, transit) = CompletionPair::new()?.split();
        let mut guardian = transit.into_guardian();
        anchor.stream.write_all(b"BADFRAME")?;
        anchor.stream.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            guardian.poll_recovery_request(Instant::now() + Duration::from_secs(1))?,
            RecoveryRequestPoll::ProtocolRejectedOwnerLost
        );

        let (mut anchor, transit) = CompletionPair::new()?.split();
        let request = encode_recovery_request_frame(transit.identity);
        let mut guardian = transit.into_guardian();
        anchor.stream.write_all(&request)?;
        anchor.stream.write_all(b"x")?;
        anchor.stream.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            guardian.poll_recovery_request(Instant::now() + Duration::from_secs(1))?,
            RecoveryRequestPoll::ProtocolRejectedOwnerLost
        );
        Ok(())
    }

    #[test]
    fn retained_recovery_request_rejects_wrong_generation_invalid_reason_and_cross_wiring()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut wrong_generation_anchor, wrong_generation_transit) =
            CompletionPair::new()?.split();
        let mut wrong_generation = encode_recovery_request_frame(wrong_generation_transit.identity);
        wrong_generation[RECOVERY_REQUEST_GENERATION_INODE_OFFSET] ^= 1;
        let mut wrong_generation_guardian = wrong_generation_transit.into_guardian();
        wrong_generation_anchor
            .stream
            .write_all(&wrong_generation)?;
        wrong_generation_anchor
            .stream
            .shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            wrong_generation_guardian
                .poll_recovery_request(Instant::now() + Duration::from_secs(1))?,
            RecoveryRequestPoll::ProtocolRejectedOwnerLost
        );

        let (mut invalid_reason_anchor, invalid_reason_transit) = CompletionPair::new()?.split();
        let mut invalid_reason = encode_recovery_request_frame(invalid_reason_transit.identity);
        invalid_reason[RECOVERY_REQUEST_REASON_OFFSET] = u8::MAX;
        let mut invalid_reason_guardian = invalid_reason_transit.into_guardian();
        invalid_reason_anchor.stream.write_all(&invalid_reason)?;
        invalid_reason_anchor
            .stream
            .shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            invalid_reason_guardian
                .poll_recovery_request(Instant::now() + Duration::from_secs(1))?,
            RecoveryRequestPoll::ProtocolRejectedOwnerLost
        );

        let (mut source_anchor, mut source_transit) = CompletionPair::new()?.split();
        source_anchor.request_recovery(Instant::now() + Duration::from_secs(1))?;
        let mut source_wire = Vec::new();
        source_transit.stream.read_to_end(&mut source_wire)?;

        let (mut destination_anchor, destination_transit) = CompletionPair::new()?.split();
        let mut destination_guardian = destination_transit.into_guardian();
        destination_anchor.stream.write_all(&source_wire)?;
        destination_anchor
            .stream
            .shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            destination_guardian.poll_recovery_request(Instant::now() + Duration::from_secs(1))?,
            RecoveryRequestPoll::ProtocolRejectedOwnerLost
        );
        Ok(())
    }

    #[test]
    fn retained_recovery_request_deadlines_are_bounded_and_consume_the_one_shot()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, transit) = CompletionPair::new()?.split();
        let mut guardian = transit.into_guardian();
        let expired = Instant::now();

        assert_eq!(
            guardian.poll_recovery_request(expired)?,
            RecoveryRequestPoll::Pending
        );
        assert_eq!(
            anchor.request_recovery(expired),
            Err(CompletionError::RecoveryDeadline)
        );
        assert_eq!(
            anchor.request_recovery(Instant::now() + Duration::from_secs(1)),
            Err(CompletionError::RecoveryReplay)
        );
        assert_eq!(
            guardian.poll_recovery_request(Instant::now() + Duration::from_secs(1))?,
            RecoveryRequestPoll::OwnerLost
        );
        Ok(())
    }

    #[test]
    fn an_unrelated_kernel_endpoint_cannot_complete_the_anchor()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut anchor, transit) = CompletionPair::new()?.split();
        let (_unrelated_anchor, unrelated) = CompletionPair::new()?.split();
        unrelated.into_guardian().publish_raw()?;
        assert_eq!(anchor.poll_once()?, CompletionPoll::Pending);
        transit.into_guardian().publish_raw()?;
        assert_eq!(poll_until_terminal(&mut anchor)?, CompletionPoll::Verified);
        Ok(())
    }

    #[test]
    fn completion_transit_rejects_a_cross_wired_duplicate_after_exec()
    -> Result<(), Box<dyn std::error::Error>> {
        const ROLE_ENV: &str = "CALCIFER_TEST_COMPLETION_DUPLICATE_ROLE";
        const TEST_NAME: &str = "completion_transit_rejects_a_cross_wired_duplicate_after_exec";

        if std::env::var_os(ROLE_ENV).is_some() {
            assert!(matches!(
                CompletionTransit::take_inherited(),
                Err(CompletionError::Inherited)
            ));
            return Ok(());
        }

        let (_anchor, transit) = CompletionPair::new()?.split();
        let cross_wired = transit.stream.try_clone()?;
        verify_close_on_exec(&cross_wired)?;

        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg(TEST_NAME)
            .arg("--test-threads=1")
            .env(ROLE_ENV, "child")
            .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(
                cross_wired,
            )))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child =
            calcifer_unix_child_fd::spawn_with_inherited_readiness_fd(command, transit.as_fd())?;
        drop(transit);

        assert!(child.wait()?.success());
        Ok(())
    }

    #[test]
    fn generation_bound_recovery_request_crosses_coordinator_guardian_exec_hops()
    -> Result<(), Box<dyn std::error::Error>> {
        const ROLE_ENV: &str = "CALCIFER_TEST_GENERATION_RECOVERY_TWO_HOP_ROLE";
        const TEST_NAME: &str =
            "generation_bound_recovery_request_crosses_coordinator_guardian_exec_hops";

        let helper_command = |role: &str| -> Result<Command, Box<dyn std::error::Error>> {
            let mut command = Command::new(std::env::current_exe()?);
            command
                .arg(TEST_NAME)
                .arg("--test-threads=1")
                .env(ROLE_ENV, role)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            Ok(command)
        };

        match std::env::var(ROLE_ENV).ok().as_deref() {
            Some("guardian") => {
                let mut completion = CompletionTransit::take_inherited()?.into_guardian();
                assert_eq!(
                    completion.poll_recovery_request(Instant::now() + Duration::from_secs(5))?,
                    RecoveryRequestPoll::Verified
                );
                completion.publish_raw()?;
                return Ok(());
            }
            Some("coordinator") => {
                let transit = CompletionTransit::take_inherited()?;
                let mut guardian = calcifer_unix_child_fd::spawn_with_inherited_readiness_fd(
                    helper_command("guardian")?,
                    transit.as_fd(),
                )?;
                drop(transit);
                assert!(guardian.wait()?.success());
                return Ok(());
            }
            Some(_) => return Err("invalid generation recovery two-hop test role".into()),
            None => {}
        }

        let (mut anchor, transit) = CompletionPair::new()?.split();
        let mut coordinator = calcifer_unix_child_fd::spawn_with_inherited_readiness_fd(
            helper_command("coordinator")?,
            transit.as_fd(),
        )?;
        drop(transit);
        anchor.request_recovery(Instant::now() + Duration::from_secs(5))?;
        assert!(coordinator.wait()?.success());
        assert_eq!(poll_until_terminal(&mut anchor)?, CompletionPoll::Verified);
        Ok(())
    }

    #[test]
    fn completion_transit_crosses_parent_coordinator_guardian_exec_hops()
    -> Result<(), Box<dyn std::error::Error>> {
        const ROLE_ENV: &str = "CALCIFER_TEST_COMPLETION_TWO_HOP_ROLE";
        const TEST_NAME: &str = "completion_transit_crosses_parent_coordinator_guardian_exec_hops";

        let helper_command = |role: &str| -> Result<Command, Box<dyn std::error::Error>> {
            let mut command = Command::new(std::env::current_exe()?);
            command
                .arg(TEST_NAME)
                .arg("--test-threads=1")
                .env(ROLE_ENV, role)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            Ok(command)
        };

        match std::env::var(ROLE_ENV).ok().as_deref() {
            Some("guardian") => {
                CompletionTransit::take_inherited()?
                    .into_guardian()
                    .publish_raw()?;
                return Ok(());
            }
            Some("coordinator") => {
                let transit = CompletionTransit::take_inherited()?;
                let mut guardian = calcifer_unix_child_fd::spawn_with_inherited_readiness_fd(
                    helper_command("guardian")?,
                    transit.as_fd(),
                )?;
                drop(transit);
                assert!(guardian.wait()?.success());
                return Ok(());
            }
            Some(_) => return Err("invalid completion two-hop test role".into()),
            None => {}
        }

        let (mut anchor, transit) = CompletionPair::new()?.split();
        let mut coordinator = calcifer_unix_child_fd::spawn_with_inherited_readiness_fd(
            helper_command("coordinator")?,
            transit.as_fd(),
        )?;
        drop(transit);
        assert!(coordinator.wait()?.success());
        assert_eq!(poll_until_terminal(&mut anchor)?, CompletionPoll::Verified);
        Ok(())
    }
}
