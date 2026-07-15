//! Bounded lifecycle framing for the supervised Codex process foundation.
//!
//! This module intentionally carries only redacted control state. It has no
//! descriptor-transfer API, free-form text, path, profile, account, terminal,
//! or provider-protocol payload. Callers must configure blocking descriptors
//! with an OS read/write timeout no later than the supplied absolute deadline;
//! the generic I/O loops also enforce the deadline around every operation.

#![allow(dead_code)] // Wired to the default-off supervisor in issue #50.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::Instant;

const MAGIC: [u8; 4] = *b"CLFR";
const PROTOCOL_VERSION: u8 = 1;
const PAYLOAD_VERSION: u8 = 1;
const HEADER_BYTES: usize = 8;
const MAX_BODY_BYTES: usize = 64;
const MAX_FRAME_BYTES: usize = HEADER_BYTES + MAX_BODY_BYTES;

const DIRECTION_MASK: u8 = 0x80;
const TYPE_MASK: u8 = 0x7f;
const COORDINATOR_DIRECTION: u8 = 0x00;
const GUARDIAN_DIRECTION: u8 = 0x80;

const COORDINATOR_START: u8 = 1;
const COORDINATOR_STOP: u8 = 2;

const GUARDIAN_LEASE_COMMITTED: u8 = 1;
const GUARDIAN_CHILD_STARTED: u8 = 2;
const GUARDIAN_READY: u8 = 3;
const GUARDIAN_FAILED: u8 = 4;
const GUARDIAN_CHILDREN_REAPED: u8 = 5;

const EMPTY_BODY_BYTES: usize = 1;
const CHILD_STARTED_BODY_BYTES: usize = 10;
const FAILED_BODY_BYTES: usize = 3;
const CHILD_DISPOSITION_BYTES: usize = 4;
const CHILDREN_REAPED_BODY_BYTES: usize = 12;

/// A coordinator-to-guardian command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorCommand {
    Start,
    Stop,
}

/// A guardian-to-coordinator lifecycle event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GuardianEvent {
    LeaseCommitted,
    ChildStarted {
        role: ChildRole,
        pid: i32,
        pgid: i32,
    },
    Ready,
    Failed {
        phase: Phase,
        code: FailureCode,
    },
    ChildrenReaped {
        app: ChildDisposition,
        tui: ChildDisposition,
        worker: WorkerJoinStatus,
        cleanup: CleanupStatus,
        session: SessionStatus,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChildRole {
    AppServer,
    Tui,
}

/// A bounded guardian lifecycle phase. Values are stable only inside v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Lease,
    Runtime,
    Worker,
    AppServer,
    Tui,
    Readiness,
    Shutdown,
    Reap,
    Cleanup,
    Protocol,
}

/// A bounded, redacted failure code. No provider or user data is carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailureCode {
    Timeout,
    Descriptor,
    Lease,
    Spawn,
    EarlyExit,
    Worker,
    Containment,
    Wait,
    CleanupMismatch,
    InvalidControl,
    Internal,
}

/// The exact wait disposition of one guardian-owned direct child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChildDisposition {
    NotStarted,
    Exited {
        code: u8,
        stop_action: StopAction,
    },
    Signaled {
        signal: u8,
        core_dumped: bool,
        stop_action: StopAction,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StopAction {
    None,
    Term,
    Kill,
}

/// Every variant is terminal: no live worker handle may be represented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkerJoinStatus {
    NotStarted,
    JoinedClean,
    JoinedFailed,
    JoinedPanicked,
}

/// `CHILDREN_REAPED` is constructible only after complete runtime cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CleanupStatus {
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SessionStatus {
    Completed,
    Failed,
}

/// A redacted protocol failure. It deliberately retains no input bytes or I/O
/// error string so diagnostics cannot expose lifecycle-adjacent secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtocolError {
    Timeout,
    UnexpectedEof,
    TruncatedHeader,
    TruncatedBody,
    ZeroLength,
    OversizedBody,
    BadMagic,
    UnsupportedVersion,
    WrongDirection,
    UnknownType,
    InvalidLength,
    InvalidValue,
    TrailingData,
    UnexpectedState,
    Io,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Timeout => "the lifecycle protocol deadline expired",
            Self::UnexpectedEof => "the lifecycle channel ended unexpectedly",
            Self::TruncatedHeader => "the lifecycle frame header was truncated",
            Self::TruncatedBody => "the lifecycle frame body was truncated",
            Self::ZeroLength => "the lifecycle frame body was empty",
            Self::OversizedBody => "the lifecycle frame body exceeded its limit",
            Self::BadMagic => "the lifecycle frame magic was invalid",
            Self::UnsupportedVersion => "the lifecycle protocol version was unsupported",
            Self::WrongDirection => "the lifecycle frame direction was invalid",
            Self::UnknownType => "the lifecycle frame type was unknown",
            Self::InvalidLength => "the lifecycle frame length was invalid",
            Self::InvalidValue => "the lifecycle frame value was invalid",
            Self::TrailingData => "the lifecycle stream contained trailing data",
            Self::UnexpectedState => "the lifecycle event was out of order",
            Self::Io => "the lifecycle channel failed",
        })
    }
}

impl std::error::Error for ProtocolError {}

/// Sends one typed coordinator command without allocating.
pub(super) fn send_coordinator_command<W: Write>(
    writer: &mut W,
    command: CoordinatorCommand,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    let message_type = match command {
        CoordinatorCommand::Start => COORDINATOR_START,
        CoordinatorCommand::Stop => COORDINATOR_STOP,
    };
    let body = [PAYLOAD_VERSION];
    send_frame(
        writer,
        COORDINATOR_DIRECTION | message_type,
        &body,
        deadline,
    )
}

/// Sends one typed guardian event without allocating.
pub(super) fn send_guardian_event<W: Write>(
    writer: &mut W,
    event: GuardianEvent,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    let mut body = [0_u8; MAX_BODY_BYTES];
    body[0] = PAYLOAD_VERSION;
    let (message_type, body_len) = match event {
        GuardianEvent::LeaseCommitted => (GUARDIAN_LEASE_COMMITTED, EMPTY_BODY_BYTES),
        GuardianEvent::ChildStarted { role, pid, pgid } => {
            validate_process_group(pid, pgid)?;
            body[1] = encode_child_role(role);
            body[2..6].copy_from_slice(&pid.to_be_bytes());
            body[6..10].copy_from_slice(&pgid.to_be_bytes());
            (GUARDIAN_CHILD_STARTED, CHILD_STARTED_BODY_BYTES)
        }
        GuardianEvent::Ready => (GUARDIAN_READY, EMPTY_BODY_BYTES),
        GuardianEvent::Failed { phase, code } => {
            body[1] = encode_phase(phase);
            body[2] = encode_failure_code(code);
            (GUARDIAN_FAILED, FAILED_BODY_BYTES)
        }
        GuardianEvent::ChildrenReaped {
            app,
            tui,
            worker,
            cleanup,
            session,
        } => {
            encode_child_disposition(app, &mut body[1..5])?;
            encode_child_disposition(tui, &mut body[5..9])?;
            body[9] = encode_worker_join_status(worker);
            body[10] = encode_cleanup_status(cleanup);
            body[11] = encode_session_status(session);
            (GUARDIAN_CHILDREN_REAPED, CHILDREN_REAPED_BODY_BYTES)
        }
    };
    send_frame(
        writer,
        GUARDIAN_DIRECTION | message_type,
        &body[..body_len],
        deadline,
    )
}

/// Receives and validates the guardian event sequence observed by a
/// coordinator. A protocol error poisons this receiver; a later terminal frame
/// can never repair an invalid stream.
pub(super) struct CoordinatorReceiver<R> {
    reader: R,
    state: CoordinatorState,
    lease_committed: bool,
    app_started: bool,
    tui_started: bool,
    failure: Option<(Phase, FailureCode)>,
    poisoned: bool,
    eof_verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoordinatorState {
    AwaitLease,
    AwaitApp,
    AwaitTui,
    AwaitReady,
    Ready,
    Failed,
    Terminal,
}

impl<R: Read> CoordinatorReceiver<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader,
            state: CoordinatorState::AwaitLease,
            lease_committed: false,
            app_started: false,
            tui_started: false,
            failure: None,
            poisoned: false,
            eof_verified: false,
        }
    }

    pub(super) fn receive(&mut self, deadline: Instant) -> Result<GuardianEvent, ProtocolError> {
        if self.poisoned || self.state == CoordinatorState::Terminal {
            return Err(ProtocolError::UnexpectedState);
        }
        let event = match receive_guardian_event(&mut self.reader, deadline) {
            Ok(event) => event,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if let Err(error) = self.accept(event) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(event)
    }

    /// Verifies that the terminal frame was the final lifecycle payload.
    /// Callers perform this check after exact-waiting the guardian so a clean
    /// stream must return EOF immediately.
    pub(super) fn verify_terminal_eof(&mut self, deadline: Instant) -> Result<(), ProtocolError> {
        if self.poisoned || self.state != CoordinatorState::Terminal {
            return Err(ProtocolError::UnexpectedState);
        }
        if self.eof_verified {
            return Ok(());
        }
        let mut byte = [0_u8; 1];
        loop {
            check_deadline(deadline)?;
            match self.reader.read(&mut byte) {
                Ok(0) => {
                    if let Err(error) = check_deadline(deadline) {
                        self.poisoned = true;
                        return Err(error);
                    }
                    self.eof_verified = true;
                    return Ok(());
                }
                Ok(_) => {
                    if let Err(error) = check_deadline(deadline) {
                        self.poisoned = true;
                        return Err(error);
                    }
                    self.poisoned = true;
                    return Err(ProtocolError::TrailingData);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    wait_for_deadline_retry(deadline)?;
                }
                Err(_) => {
                    self.poisoned = true;
                    return Err(ProtocolError::Io);
                }
            }
        }
    }

    pub(super) const fn terminal_received(&self) -> bool {
        matches!(self.state, CoordinatorState::Terminal) && !self.poisoned
    }

    fn accept(&mut self, event: GuardianEvent) -> Result<(), ProtocolError> {
        match (self.state, event) {
            (CoordinatorState::AwaitLease, GuardianEvent::LeaseCommitted) => {
                self.lease_committed = true;
                self.state = CoordinatorState::AwaitApp;
            }
            (
                CoordinatorState::AwaitApp,
                GuardianEvent::ChildStarted {
                    role: ChildRole::AppServer,
                    pid,
                    pgid,
                },
            ) => {
                validate_process_group(pid, pgid)?;
                self.app_started = true;
                self.state = CoordinatorState::AwaitTui;
            }
            (
                CoordinatorState::AwaitTui,
                GuardianEvent::ChildStarted {
                    role: ChildRole::Tui,
                    pid,
                    pgid,
                },
            ) => {
                validate_process_group(pid, pgid)?;
                self.tui_started = true;
                self.state = CoordinatorState::AwaitReady;
            }
            (CoordinatorState::AwaitReady, GuardianEvent::Ready) => {
                self.state = CoordinatorState::Ready;
            }
            (
                CoordinatorState::AwaitLease
                | CoordinatorState::AwaitApp
                | CoordinatorState::AwaitTui
                | CoordinatorState::AwaitReady
                | CoordinatorState::Ready,
                GuardianEvent::Failed { phase, code },
            ) => {
                self.failure = Some((phase, code));
                self.state = CoordinatorState::Failed;
            }
            (
                CoordinatorState::Ready | CoordinatorState::Failed,
                terminal @ GuardianEvent::ChildrenReaped { .. },
            ) => {
                self.validate_terminal(terminal)?;
                self.state = CoordinatorState::Terminal;
            }
            _ => return Err(ProtocolError::UnexpectedState),
        }
        Ok(())
    }

    fn validate_terminal(&self, event: GuardianEvent) -> Result<(), ProtocolError> {
        let GuardianEvent::ChildrenReaped {
            app,
            tui,
            worker,
            cleanup: CleanupStatus::Complete,
            session,
        } = event
        else {
            return Err(ProtocolError::UnexpectedState);
        };

        let app_started = !matches!(app, ChildDisposition::NotStarted);
        let tui_started = !matches!(tui, ChildDisposition::NotStarted);
        if app_started != self.app_started || tui_started != self.tui_started {
            return Err(ProtocolError::InvalidValue);
        }
        if (app_started || tui_started) && worker == WorkerJoinStatus::NotStarted {
            return Err(ProtocolError::InvalidValue);
        }

        match self.failure {
            None => {
                if self.state != CoordinatorState::Ready
                    || session != SessionStatus::Completed
                    || worker != WorkerJoinStatus::JoinedClean
                    || !self.lease_committed
                    || !self.app_started
                    || !self.tui_started
                {
                    return Err(ProtocolError::InvalidValue);
                }
            }
            Some((phase, code)) => {
                // The strong #50 contract withholds terminal authority when
                // private runtime cleanup did not complete.
                if phase == Phase::Cleanup || code == FailureCode::CleanupMismatch {
                    return Err(ProtocolError::UnexpectedState);
                }
                if session != SessionStatus::Failed {
                    return Err(ProtocolError::InvalidValue);
                }
            }
        }
        Ok(())
    }
}

/// Receives the exact coordinator command order consumed by a guardian.
pub(super) struct GuardianCommandReceiver<R> {
    reader: R,
    state: GuardianCommandState,
    poisoned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardianCommandState {
    AwaitStart,
    Started,
    Stopped,
}

impl<R: Read> GuardianCommandReceiver<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader,
            state: GuardianCommandState::AwaitStart,
            poisoned: false,
        }
    }

    pub(super) fn receive(
        &mut self,
        deadline: Instant,
    ) -> Result<CoordinatorCommand, ProtocolError> {
        if self.poisoned || self.state == GuardianCommandState::Stopped {
            return Err(ProtocolError::UnexpectedState);
        }
        let command = match receive_coordinator_command(&mut self.reader, deadline) {
            Ok(command) => command,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let next = match (self.state, command) {
            (GuardianCommandState::AwaitStart, CoordinatorCommand::Start) => {
                GuardianCommandState::Started
            }
            (GuardianCommandState::Started, CoordinatorCommand::Stop) => {
                GuardianCommandState::Stopped
            }
            _ => {
                self.poisoned = true;
                return Err(ProtocolError::UnexpectedState);
            }
        };
        self.state = next;
        Ok(command)
    }
}

fn send_frame<W: Write>(
    writer: &mut W,
    direction_and_type: u8,
    body: &[u8],
    deadline: Instant,
) -> Result<(), ProtocolError> {
    if body.is_empty() {
        return Err(ProtocolError::ZeroLength);
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(ProtocolError::OversizedBody);
    }
    let body_len = u16::try_from(body.len()).map_err(|_| ProtocolError::OversizedBody)?;
    let mut frame = [0_u8; MAX_FRAME_BYTES];
    frame[..4].copy_from_slice(&MAGIC);
    frame[4] = PROTOCOL_VERSION;
    frame[5] = direction_and_type;
    frame[6..8].copy_from_slice(&body_len.to_be_bytes());
    frame[HEADER_BYTES..HEADER_BYTES + body.len()].copy_from_slice(body);
    write_all_before(writer, &frame[..HEADER_BYTES + body.len()], deadline)?;
    flush_before(writer, deadline)
}

fn receive_coordinator_command<R: Read>(
    reader: &mut R,
    deadline: Instant,
) -> Result<CoordinatorCommand, ProtocolError> {
    let frame = receive_frame(reader, COORDINATOR_DIRECTION, deadline)?;
    match frame.message_type {
        COORDINATOR_START => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(CoordinatorCommand::Start)
        }
        COORDINATOR_STOP => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(CoordinatorCommand::Stop)
        }
        _ => Err(ProtocolError::UnknownType),
    }
}

fn receive_guardian_event<R: Read>(
    reader: &mut R,
    deadline: Instant,
) -> Result<GuardianEvent, ProtocolError> {
    let frame = receive_frame(reader, GUARDIAN_DIRECTION, deadline)?;
    match frame.message_type {
        GUARDIAN_LEASE_COMMITTED => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(GuardianEvent::LeaseCommitted)
        }
        GUARDIAN_CHILD_STARTED => {
            frame.require_exact_len(CHILD_STARTED_BODY_BYTES)?;
            frame.require_payload_version()?;
            let role = decode_child_role(frame.body[1])?;
            let pid = read_i32(&frame.body[2..6]);
            let pgid = read_i32(&frame.body[6..10]);
            validate_process_group(pid, pgid)?;
            Ok(GuardianEvent::ChildStarted { role, pid, pgid })
        }
        GUARDIAN_READY => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(GuardianEvent::Ready)
        }
        GUARDIAN_FAILED => {
            frame.require_exact_len(FAILED_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(GuardianEvent::Failed {
                phase: decode_phase(frame.body[1])?,
                code: decode_failure_code(frame.body[2])?,
            })
        }
        GUARDIAN_CHILDREN_REAPED => {
            frame.require_exact_len(CHILDREN_REAPED_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(GuardianEvent::ChildrenReaped {
                app: decode_child_disposition(&frame.body[1..5])?,
                tui: decode_child_disposition(&frame.body[5..9])?,
                worker: decode_worker_join_status(frame.body[9])?,
                cleanup: decode_cleanup_status(frame.body[10])?,
                session: decode_session_status(frame.body[11])?,
            })
        }
        _ => Err(ProtocolError::UnknownType),
    }
}

struct ReceivedFrame {
    message_type: u8,
    body: [u8; MAX_BODY_BYTES],
    body_len: usize,
}

impl ReceivedFrame {
    fn require_exact_len(&self, expected: usize) -> Result<(), ProtocolError> {
        if self.body_len < expected {
            Err(ProtocolError::InvalidLength)
        } else if self.body_len > expected {
            Err(ProtocolError::TrailingData)
        } else {
            Ok(())
        }
    }

    fn require_payload_version(&self) -> Result<(), ProtocolError> {
        if self.body.first() == Some(&PAYLOAD_VERSION) {
            Ok(())
        } else {
            Err(ProtocolError::InvalidValue)
        }
    }
}

fn receive_frame<R: Read>(
    reader: &mut R,
    expected_direction: u8,
    deadline: Instant,
) -> Result<ReceivedFrame, ProtocolError> {
    let mut header = [0_u8; HEADER_BYTES];
    read_exact_before(reader, &mut header, ReadPart::Header, deadline)?;
    if header[..4] != MAGIC {
        return Err(ProtocolError::BadMagic);
    }
    if header[4] != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let direction_and_type = header[5];
    if direction_and_type & DIRECTION_MASK != expected_direction {
        return Err(ProtocolError::WrongDirection);
    }
    let message_type = direction_and_type & TYPE_MASK;
    if message_type == 0 {
        return Err(ProtocolError::UnknownType);
    }
    let body_len = usize::from(u16::from_be_bytes([header[6], header[7]]));
    if body_len == 0 {
        return Err(ProtocolError::ZeroLength);
    }
    if body_len > MAX_BODY_BYTES {
        return Err(ProtocolError::OversizedBody);
    }
    let mut body = [0_u8; MAX_BODY_BYTES];
    read_exact_before(reader, &mut body[..body_len], ReadPart::Body, deadline)?;
    Ok(ReceivedFrame {
        message_type,
        body,
        body_len,
    })
}

#[derive(Clone, Copy)]
enum ReadPart {
    Header,
    Body,
}

fn read_exact_before<R: Read>(
    reader: &mut R,
    output: &mut [u8],
    part: ReadPart,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    let mut offset = 0_usize;
    while offset < output.len() {
        check_deadline(deadline)?;
        match reader.read(&mut output[offset..]) {
            Ok(0) => {
                return Err(match (part, offset) {
                    (ReadPart::Header, 0) => ProtocolError::UnexpectedEof,
                    (ReadPart::Header, _) => ProtocolError::TruncatedHeader,
                    (ReadPart::Body, _) => ProtocolError::TruncatedBody,
                });
            }
            Ok(read) if read <= output.len() - offset => {
                offset += read;
                check_deadline(deadline)?;
            }
            Ok(_) => return Err(ProtocolError::Io),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                wait_for_deadline_retry(deadline)?;
            }
            Err(_) => return Err(ProtocolError::Io),
        }
    }
    Ok(())
}

fn write_all_before<W: Write>(
    writer: &mut W,
    input: &[u8],
    deadline: Instant,
) -> Result<(), ProtocolError> {
    let mut offset = 0_usize;
    while offset < input.len() {
        check_deadline(deadline)?;
        match writer.write(&input[offset..]) {
            Ok(0) => return Err(ProtocolError::Io),
            Ok(written) if written <= input.len() - offset => {
                offset += written;
                check_deadline(deadline)?;
            }
            Ok(_) => return Err(ProtocolError::Io),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                wait_for_deadline_retry(deadline)?;
            }
            Err(_) => return Err(ProtocolError::Io),
        }
    }
    Ok(())
}

fn flush_before<W: Write>(writer: &mut W, deadline: Instant) -> Result<(), ProtocolError> {
    loop {
        check_deadline(deadline)?;
        match writer.flush() {
            Ok(()) => {
                check_deadline(deadline)?;
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                wait_for_deadline_retry(deadline)?;
            }
            Err(_) => return Err(ProtocolError::Io),
        }
    }
}

fn check_deadline(deadline: Instant) -> Result<(), ProtocolError> {
    if Instant::now() >= deadline {
        Err(ProtocolError::Timeout)
    } else {
        Ok(())
    }
}

fn wait_for_deadline_retry(deadline: Instant) -> Result<(), ProtocolError> {
    check_deadline(deadline)?;
    std::thread::yield_now();
    check_deadline(deadline)
}

fn validate_process_group(pid: i32, pgid: i32) -> Result<(), ProtocolError> {
    if pid > 0 && pgid == pid {
        Ok(())
    } else {
        Err(ProtocolError::InvalidValue)
    }
}

const fn encode_child_role(role: ChildRole) -> u8 {
    match role {
        ChildRole::AppServer => 1,
        ChildRole::Tui => 2,
    }
}

fn decode_child_role(value: u8) -> Result<ChildRole, ProtocolError> {
    match value {
        1 => Ok(ChildRole::AppServer),
        2 => Ok(ChildRole::Tui),
        _ => Err(ProtocolError::InvalidValue),
    }
}

fn read_i32(bytes: &[u8]) -> i32 {
    i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn encode_child_disposition(
    disposition: ChildDisposition,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() != CHILD_DISPOSITION_BYTES {
        return Err(ProtocolError::InvalidLength);
    }
    match disposition {
        ChildDisposition::NotStarted => output.copy_from_slice(&[0, 0, 0, 0]),
        ChildDisposition::Exited { code, stop_action } => {
            output.copy_from_slice(&[1, code, encode_stop_action(stop_action), 0]);
        }
        ChildDisposition::Signaled {
            signal,
            core_dumped,
            stop_action,
        } => {
            if signal == 0 || signal > 127 {
                return Err(ProtocolError::InvalidValue);
            }
            output.copy_from_slice(&[
                2,
                signal,
                encode_stop_action(stop_action),
                u8::from(core_dumped),
            ]);
        }
    }
    Ok(())
}

fn decode_child_disposition(input: &[u8]) -> Result<ChildDisposition, ProtocolError> {
    if input.len() != CHILD_DISPOSITION_BYTES {
        return Err(ProtocolError::InvalidLength);
    }
    let stop_action = decode_stop_action(input[2])?;
    match input[0] {
        0 if input[1] == 0 && stop_action == StopAction::None && input[3] == 0 => {
            Ok(ChildDisposition::NotStarted)
        }
        1 if input[3] == 0 => Ok(ChildDisposition::Exited {
            code: input[1],
            stop_action,
        }),
        2 if (1..=127).contains(&input[1]) && input[3] <= 1 => Ok(ChildDisposition::Signaled {
            signal: input[1],
            core_dumped: input[3] == 1,
            stop_action,
        }),
        _ => Err(ProtocolError::InvalidValue),
    }
}

const fn encode_stop_action(action: StopAction) -> u8 {
    match action {
        StopAction::None => 0,
        StopAction::Term => 1,
        StopAction::Kill => 2,
    }
}

fn decode_stop_action(value: u8) -> Result<StopAction, ProtocolError> {
    match value {
        0 => Ok(StopAction::None),
        1 => Ok(StopAction::Term),
        2 => Ok(StopAction::Kill),
        _ => Err(ProtocolError::InvalidValue),
    }
}

const fn encode_phase(phase: Phase) -> u8 {
    match phase {
        Phase::Lease => 1,
        Phase::Runtime => 2,
        Phase::Worker => 3,
        Phase::AppServer => 4,
        Phase::Tui => 5,
        Phase::Readiness => 6,
        Phase::Shutdown => 7,
        Phase::Reap => 8,
        Phase::Cleanup => 9,
        Phase::Protocol => 10,
    }
}

fn decode_phase(value: u8) -> Result<Phase, ProtocolError> {
    match value {
        1 => Ok(Phase::Lease),
        2 => Ok(Phase::Runtime),
        3 => Ok(Phase::Worker),
        4 => Ok(Phase::AppServer),
        5 => Ok(Phase::Tui),
        6 => Ok(Phase::Readiness),
        7 => Ok(Phase::Shutdown),
        8 => Ok(Phase::Reap),
        9 => Ok(Phase::Cleanup),
        10 => Ok(Phase::Protocol),
        _ => Err(ProtocolError::InvalidValue),
    }
}

const fn encode_failure_code(code: FailureCode) -> u8 {
    match code {
        FailureCode::Timeout => 1,
        FailureCode::Descriptor => 2,
        FailureCode::Lease => 3,
        FailureCode::Spawn => 4,
        FailureCode::EarlyExit => 5,
        FailureCode::Worker => 6,
        FailureCode::Containment => 7,
        FailureCode::Wait => 8,
        FailureCode::CleanupMismatch => 9,
        FailureCode::InvalidControl => 10,
        FailureCode::Internal => 11,
    }
}

fn decode_failure_code(value: u8) -> Result<FailureCode, ProtocolError> {
    match value {
        1 => Ok(FailureCode::Timeout),
        2 => Ok(FailureCode::Descriptor),
        3 => Ok(FailureCode::Lease),
        4 => Ok(FailureCode::Spawn),
        5 => Ok(FailureCode::EarlyExit),
        6 => Ok(FailureCode::Worker),
        7 => Ok(FailureCode::Containment),
        8 => Ok(FailureCode::Wait),
        9 => Ok(FailureCode::CleanupMismatch),
        10 => Ok(FailureCode::InvalidControl),
        11 => Ok(FailureCode::Internal),
        _ => Err(ProtocolError::InvalidValue),
    }
}

const fn encode_worker_join_status(status: WorkerJoinStatus) -> u8 {
    match status {
        WorkerJoinStatus::NotStarted => 0,
        WorkerJoinStatus::JoinedClean => 1,
        WorkerJoinStatus::JoinedFailed => 2,
        WorkerJoinStatus::JoinedPanicked => 3,
    }
}

fn decode_worker_join_status(value: u8) -> Result<WorkerJoinStatus, ProtocolError> {
    match value {
        0 => Ok(WorkerJoinStatus::NotStarted),
        1 => Ok(WorkerJoinStatus::JoinedClean),
        2 => Ok(WorkerJoinStatus::JoinedFailed),
        3 => Ok(WorkerJoinStatus::JoinedPanicked),
        _ => Err(ProtocolError::InvalidValue),
    }
}

const fn encode_cleanup_status(status: CleanupStatus) -> u8 {
    match status {
        CleanupStatus::Complete => 1,
    }
}

fn decode_cleanup_status(value: u8) -> Result<CleanupStatus, ProtocolError> {
    match value {
        1 => Ok(CleanupStatus::Complete),
        _ => Err(ProtocolError::InvalidValue),
    }
}

const fn encode_session_status(status: SessionStatus) -> u8 {
    match status {
        SessionStatus::Completed => 1,
        SessionStatus::Failed => 2,
    }
}

fn decode_session_status(value: u8) -> Result<SessionStatus, ProtocolError> {
    match value {
        1 => Ok(SessionStatus::Completed),
        2 => Ok(SessionStatus::Failed),
        _ => Err(ProtocolError::InvalidValue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;
    use std::io::Cursor;
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    fn encode_coordinator(command: CoordinatorCommand) -> Result<Vec<u8>, ProtocolError> {
        let mut wire = Vec::new();
        send_coordinator_command(&mut wire, command, deadline())?;
        Ok(wire)
    }

    fn encode_guardian(event: GuardianEvent) -> Result<Vec<u8>, ProtocolError> {
        let mut wire = Vec::new();
        send_guardian_event(&mut wire, event, deadline())?;
        Ok(wire)
    }

    fn raw_frame(direction_and_type: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(HEADER_BYTES + body.len());
        frame.extend_from_slice(&MAGIC);
        frame.push(PROTOCOL_VERSION);
        frame.push(direction_and_type);
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }

    fn app_started() -> GuardianEvent {
        GuardianEvent::ChildStarted {
            role: ChildRole::AppServer,
            pid: 101,
            pgid: 101,
        }
    }

    fn tui_started() -> GuardianEvent {
        GuardianEvent::ChildStarted {
            role: ChildRole::Tui,
            pid: 202,
            pgid: 202,
        }
    }

    fn exited(code: u8) -> ChildDisposition {
        ChildDisposition::Exited {
            code,
            stop_action: StopAction::None,
        }
    }

    fn completed_terminal() -> GuardianEvent {
        GuardianEvent::ChildrenReaped {
            app: ChildDisposition::Signaled {
                signal: 15,
                core_dumped: false,
                stop_action: StopAction::Term,
            },
            tui: exited(0),
            worker: WorkerJoinStatus::JoinedClean,
            cleanup: CleanupStatus::Complete,
            session: SessionStatus::Completed,
        }
    }

    fn failed_terminal(app_started: bool, tui_started: bool) -> GuardianEvent {
        let app = if app_started {
            exited(17)
        } else {
            ChildDisposition::NotStarted
        };
        let tui = if tui_started {
            exited(19)
        } else {
            ChildDisposition::NotStarted
        };
        GuardianEvent::ChildrenReaped {
            app,
            tui,
            worker: if app_started || tui_started {
                WorkerJoinStatus::JoinedFailed
            } else {
                WorkerJoinStatus::NotStarted
            },
            cleanup: CleanupStatus::Complete,
            session: SessionStatus::Failed,
        }
    }

    fn append_event(wire: &mut Vec<u8>, event: GuardianEvent) -> Result<(), ProtocolError> {
        wire.extend_from_slice(&encode_guardian(event)?);
        Ok(())
    }

    #[test]
    fn coordinator_start_uses_the_fixed_binary_frame() -> Result<(), Box<dyn Error>> {
        let wire = encode_coordinator(CoordinatorCommand::Start)?;
        assert_eq!(wire, [b'C', b'L', b'F', b'R', 1, 1, 0, 1, 1]);
        Ok(())
    }

    #[test]
    fn guardian_events_round_trip_without_allocation_contract_leaks() -> Result<(), Box<dyn Error>>
    {
        for event in [
            GuardianEvent::LeaseCommitted,
            app_started(),
            tui_started(),
            GuardianEvent::Ready,
            GuardianEvent::Failed {
                phase: Phase::Readiness,
                code: FailureCode::Timeout,
            },
            completed_terminal(),
        ] {
            let wire = encode_guardian(event)?;
            let decoded = receive_guardian_event(&mut Cursor::new(wire), deadline())?;
            assert_eq!(decoded, event);
        }
        Ok(())
    }

    #[test]
    fn fragmented_reads_and_writes_preserve_one_frame() -> Result<(), Box<dyn Error>> {
        let expected = encode_guardian(app_started())?;
        let mut writer = FragmentedWriter::new(1);
        send_guardian_event(&mut writer, app_started(), deadline())?;
        assert_eq!(writer.bytes, expected);

        let mut reader = FragmentedReader::new(Cursor::new(expected), 1);
        assert_eq!(
            receive_guardian_event(&mut reader, deadline())?,
            app_started()
        );
        Ok(())
    }

    #[test]
    fn coalesced_frames_remain_separate() -> Result<(), Box<dyn Error>> {
        let mut wire = Vec::new();
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wire, app_started())?;
        append_event(&mut wire, tui_started())?;
        append_event(&mut wire, GuardianEvent::Ready)?;
        append_event(&mut wire, completed_terminal())?;
        let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::LeaseCommitted);
        assert_eq!(receiver.receive(deadline())?, app_started());
        assert_eq!(receiver.receive(deadline())?, tui_started());
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::Ready);
        assert_eq!(receiver.receive(deadline())?, completed_terminal());
        assert!(receiver.terminal_received());
        receiver.verify_terminal_eof(deadline())?;
        Ok(())
    }

    #[test]
    fn empty_partial_header_and_partial_body_are_distinct() -> Result<(), Box<dyn Error>> {
        let wire = encode_guardian(GuardianEvent::LeaseCommitted)?;
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(Vec::<u8>::new()), deadline()),
            Err(ProtocolError::UnexpectedEof)
        );
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(wire[..3].to_vec()), deadline()),
            Err(ProtocolError::TruncatedHeader)
        );
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(wire[..HEADER_BYTES].to_vec()), deadline()),
            Err(ProtocolError::TruncatedBody)
        );
        Ok(())
    }

    #[test]
    fn zero_and_oversized_bodies_fail_before_body_read() {
        let zero = raw_frame(GUARDIAN_DIRECTION | GUARDIAN_READY, &[]);
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(zero), deadline()),
            Err(ProtocolError::ZeroLength)
        );

        let at_limit = raw_frame(
            GUARDIAN_DIRECTION | GUARDIAN_READY,
            &[PAYLOAD_VERSION; MAX_BODY_BYTES],
        );
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(at_limit), deadline()),
            Err(ProtocolError::TrailingData)
        );

        let over_limit = raw_frame(
            GUARDIAN_DIRECTION | GUARDIAN_READY,
            &[PAYLOAD_VERSION; MAX_BODY_BYTES + 1],
        );
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(over_limit), deadline()),
            Err(ProtocolError::OversizedBody)
        );
    }

    #[test]
    fn header_identity_direction_type_and_version_are_strict() -> Result<(), Box<dyn Error>> {
        let valid = encode_guardian(GuardianEvent::LeaseCommitted)?;
        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 0xff;
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(bad_magic), deadline()),
            Err(ProtocolError::BadMagic)
        );

        let mut bad_version = valid.clone();
        bad_version[4] = PROTOCOL_VERSION + 1;
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(bad_version), deadline()),
            Err(ProtocolError::UnsupportedVersion)
        );

        let coordinator = encode_coordinator(CoordinatorCommand::Start)?;
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(coordinator), deadline()),
            Err(ProtocolError::WrongDirection)
        );

        let unknown = raw_frame(GUARDIAN_DIRECTION | TYPE_MASK, &[PAYLOAD_VERSION]);
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(unknown), deadline()),
            Err(ProtocolError::UnknownType)
        );
        Ok(())
    }

    #[test]
    fn per_type_length_payload_version_and_trailing_bytes_are_strict() {
        let short = raw_frame(
            GUARDIAN_DIRECTION | GUARDIAN_CHILD_STARTED,
            &[PAYLOAD_VERSION; CHILD_STARTED_BODY_BYTES - 1],
        );
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(short), deadline()),
            Err(ProtocolError::InvalidLength)
        );
        let long = raw_frame(
            GUARDIAN_DIRECTION | GUARDIAN_CHILD_STARTED,
            &[PAYLOAD_VERSION; CHILD_STARTED_BODY_BYTES + 1],
        );
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(long), deadline()),
            Err(ProtocolError::TrailingData)
        );
        let bad_payload_version = raw_frame(GUARDIAN_DIRECTION | GUARDIAN_READY, &[2]);
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(bad_payload_version), deadline()),
            Err(ProtocolError::InvalidValue)
        );
    }

    #[test]
    fn process_identifiers_are_positive_group_leaders() -> Result<(), Box<dyn Error>> {
        for invalid in [
            GuardianEvent::ChildStarted {
                role: ChildRole::AppServer,
                pid: 0,
                pgid: 0,
            },
            GuardianEvent::ChildStarted {
                role: ChildRole::AppServer,
                pid: 1,
                pgid: 9,
            },
            GuardianEvent::ChildStarted {
                role: ChildRole::Tui,
                pid: -2,
                pgid: -2,
            },
        ] {
            assert_eq!(
                send_guardian_event(&mut Vec::new(), invalid, deadline()),
                Err(ProtocolError::InvalidValue)
            );
        }

        let mut raw = encode_guardian(app_started())?;
        raw[HEADER_BYTES + 6..HEADER_BYTES + 10].copy_from_slice(&999_i32.to_be_bytes());
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(raw), deadline()),
            Err(ProtocolError::InvalidValue)
        );

        let mut invalid_role = encode_guardian(app_started())?;
        invalid_role[HEADER_BYTES + 1] = 0xff;
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(invalid_role), deadline()),
            Err(ProtocolError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn disposition_values_are_bounded() -> Result<(), Box<dyn Error>> {
        let invalid_signal = GuardianEvent::ChildrenReaped {
            app: ChildDisposition::Signaled {
                signal: 0,
                core_dumped: false,
                stop_action: StopAction::None,
            },
            tui: exited(0),
            worker: WorkerJoinStatus::JoinedClean,
            cleanup: CleanupStatus::Complete,
            session: SessionStatus::Completed,
        };
        assert_eq!(
            send_guardian_event(&mut Vec::new(), invalid_signal, deadline()),
            Err(ProtocolError::InvalidValue)
        );

        let mut raw = encode_guardian(completed_terminal())?;
        raw[HEADER_BYTES + 1] = 0;
        raw[HEADER_BYTES + 2] = 1;
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(raw), deadline()),
            Err(ProtocolError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn every_bounded_enum_rejects_unknown_wire_values() -> Result<(), Box<dyn Error>> {
        let failure = encode_guardian(GuardianEvent::Failed {
            phase: Phase::Readiness,
            code: FailureCode::Timeout,
        })?;
        for offset in [1_usize, 2_usize] {
            let mut invalid = failure.clone();
            invalid[HEADER_BYTES + offset] = 0xff;
            assert_eq!(
                receive_guardian_event(&mut Cursor::new(invalid), deadline()),
                Err(ProtocolError::InvalidValue)
            );
        }

        let terminal = encode_guardian(completed_terminal())?;
        for offset in [3_usize, 9_usize, 10_usize, 11_usize] {
            let mut invalid = terminal.clone();
            invalid[HEADER_BYTES + offset] = 0xff;
            assert_eq!(
                receive_guardian_event(&mut Cursor::new(invalid), deadline()),
                Err(ProtocolError::InvalidValue)
            );
        }
        Ok(())
    }

    #[test]
    fn coordinator_requires_the_exact_success_order() -> Result<(), Box<dyn Error>> {
        for first in [
            app_started(),
            tui_started(),
            GuardianEvent::Ready,
            completed_terminal(),
        ] {
            let wire = encode_guardian(first)?;
            let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
            assert_eq!(
                receiver.receive(deadline()),
                Err(ProtocolError::UnexpectedState)
            );
        }
        Ok(())
    }

    #[test]
    fn duplicate_events_poison_the_coordinator_stream() -> Result<(), Box<dyn Error>> {
        let mut wire = Vec::new();
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wire, app_started())?;
        let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::LeaseCommitted);
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        Ok(())
    }

    #[test]
    fn child_start_order_and_duplicate_roles_are_rejected() -> Result<(), Box<dyn Error>> {
        for sequence in [
            vec![GuardianEvent::LeaseCommitted, tui_started()],
            vec![GuardianEvent::LeaseCommitted, app_started(), app_started()],
            vec![
                GuardianEvent::LeaseCommitted,
                app_started(),
                tui_started(),
                tui_started(),
            ],
        ] {
            let mut wire = Vec::new();
            for event in &sequence {
                append_event(&mut wire, *event)?;
            }
            let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
            let mut final_result = Ok(GuardianEvent::LeaseCommitted);
            for _ in 0..sequence.len() {
                final_result = receiver.receive(deadline());
                if final_result.is_err() {
                    break;
                }
            }
            assert_eq!(final_result, Err(ProtocolError::UnexpectedState));
            assert_eq!(
                receiver.receive(deadline()),
                Err(ProtocolError::UnexpectedState)
            );
        }
        Ok(())
    }

    #[test]
    fn eof_after_app_start_never_becomes_terminal_authority() -> Result<(), Box<dyn Error>> {
        let mut wire = Vec::new();
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wire, app_started())?;
        let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::LeaseCommitted);
        assert_eq!(receiver.receive(deadline())?, app_started());
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedEof)
        );
        assert!(!receiver.terminal_received());
        Ok(())
    }

    #[test]
    fn failure_is_allowed_from_each_nonterminal_state_and_requires_failed_terminal()
    -> Result<(), Box<dyn Error>> {
        for prefix in [
            vec![],
            vec![GuardianEvent::LeaseCommitted],
            vec![GuardianEvent::LeaseCommitted, app_started()],
            vec![GuardianEvent::LeaseCommitted, app_started(), tui_started()],
            vec![
                GuardianEvent::LeaseCommitted,
                app_started(),
                tui_started(),
                GuardianEvent::Ready,
            ],
        ] {
            let observed_app = prefix.contains(&app_started());
            let observed_tui = prefix.contains(&tui_started());
            let mut wire = Vec::new();
            for event in prefix {
                append_event(&mut wire, event)?;
            }
            let failure = GuardianEvent::Failed {
                phase: Phase::Worker,
                code: FailureCode::Worker,
            };
            append_event(&mut wire, failure)?;
            append_event(&mut wire, failed_terminal(observed_app, observed_tui))?;
            let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
            loop {
                let event = receiver.receive(deadline())?;
                if event == failure {
                    break;
                }
            }
            assert_eq!(
                receiver.receive(deadline())?,
                failed_terminal(observed_app, observed_tui)
            );
            assert!(receiver.terminal_received());
        }
        Ok(())
    }

    #[test]
    fn only_children_reaped_may_follow_failure() -> Result<(), Box<dyn Error>> {
        for after in [
            GuardianEvent::LeaseCommitted,
            app_started(),
            tui_started(),
            GuardianEvent::Ready,
            GuardianEvent::Failed {
                phase: Phase::Protocol,
                code: FailureCode::InvalidControl,
            },
        ] {
            let mut wire = Vec::new();
            append_event(
                &mut wire,
                GuardianEvent::Failed {
                    phase: Phase::Lease,
                    code: FailureCode::Lease,
                },
            )?;
            append_event(&mut wire, after)?;
            let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
            let _failure = receiver.receive(deadline())?;
            assert_eq!(
                receiver.receive(deadline()),
                Err(ProtocolError::UnexpectedState)
            );
        }
        Ok(())
    }

    #[test]
    fn cleanup_failure_can_never_be_upgraded_to_terminal_authority() -> Result<(), Box<dyn Error>> {
        let mut wire = Vec::new();
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(
            &mut wire,
            GuardianEvent::Failed {
                phase: Phase::Cleanup,
                code: FailureCode::CleanupMismatch,
            },
        )?;
        append_event(&mut wire, failed_terminal(false, false))?;
        let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
        let _lease = receiver.receive(deadline())?;
        let _failure = receiver.receive(deadline())?;
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        assert!(!receiver.terminal_received());
        Ok(())
    }

    #[test]
    fn terminal_dispositions_must_match_observed_child_spawn() -> Result<(), Box<dyn Error>> {
        let mismatched = GuardianEvent::ChildrenReaped {
            app: exited(0),
            tui: ChildDisposition::NotStarted,
            worker: WorkerJoinStatus::JoinedFailed,
            cleanup: CleanupStatus::Complete,
            session: SessionStatus::Failed,
        };
        let mut wire = Vec::new();
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wire, app_started())?;
        append_event(&mut wire, tui_started())?;
        append_event(
            &mut wire,
            GuardianEvent::Failed {
                phase: Phase::Readiness,
                code: FailureCode::EarlyExit,
            },
        )?;
        append_event(&mut wire, mismatched)?;
        let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
        let _lease = receiver.receive(deadline())?;
        let _app = receiver.receive(deadline())?;
        let _tui = receiver.receive(deadline())?;
        let _failure = receiver.receive(deadline())?;
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn live_guardian_can_report_app_only_after_tui_spawn_failure() -> Result<(), Box<dyn Error>> {
        let terminal = GuardianEvent::ChildrenReaped {
            app: exited(0),
            tui: ChildDisposition::NotStarted,
            worker: WorkerJoinStatus::JoinedFailed,
            cleanup: CleanupStatus::Complete,
            session: SessionStatus::Failed,
        };
        let mut wire = Vec::new();
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wire, app_started())?;
        append_event(
            &mut wire,
            GuardianEvent::Failed {
                phase: Phase::Tui,
                code: FailureCode::Spawn,
            },
        )?;
        append_event(&mut wire, terminal)?;
        let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
        let _lease = receiver.receive(deadline())?;
        let _app = receiver.receive(deadline())?;
        let _failure = receiver.receive(deadline())?;
        assert_eq!(receiver.receive(deadline())?, terminal);
        assert!(receiver.terminal_received());
        Ok(())
    }

    #[test]
    fn successful_terminal_requires_clean_worker_and_completed_session()
    -> Result<(), Box<dyn Error>> {
        for terminal in [
            GuardianEvent::ChildrenReaped {
                app: exited(0),
                tui: exited(0),
                worker: WorkerJoinStatus::JoinedFailed,
                cleanup: CleanupStatus::Complete,
                session: SessionStatus::Completed,
            },
            GuardianEvent::ChildrenReaped {
                app: exited(0),
                tui: exited(0),
                worker: WorkerJoinStatus::JoinedClean,
                cleanup: CleanupStatus::Complete,
                session: SessionStatus::Failed,
            },
        ] {
            let mut wire = Vec::new();
            append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
            append_event(&mut wire, app_started())?;
            append_event(&mut wire, tui_started())?;
            append_event(&mut wire, GuardianEvent::Ready)?;
            append_event(&mut wire, terminal)?;
            let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
            let _lease = receiver.receive(deadline())?;
            let _app = receiver.receive(deadline())?;
            let _tui = receiver.receive(deadline())?;
            let _ready = receiver.receive(deadline())?;
            assert_eq!(
                receiver.receive(deadline()),
                Err(ProtocolError::InvalidValue)
            );
        }
        Ok(())
    }

    #[test]
    fn terminal_eof_check_rejects_trailing_bytes() -> Result<(), Box<dyn Error>> {
        let mut wire = Vec::new();
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wire, app_started())?;
        append_event(&mut wire, tui_started())?;
        append_event(&mut wire, GuardianEvent::Ready)?;
        append_event(&mut wire, completed_terminal())?;
        wire.push(b'X');
        let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
        let _lease = receiver.receive(deadline())?;
        let _app = receiver.receive(deadline())?;
        let _tui = receiver.receive(deadline())?;
        let _ready = receiver.receive(deadline())?;
        let _terminal = receiver.receive(deadline())?;
        assert_eq!(
            receiver.verify_terminal_eof(deadline()),
            Err(ProtocolError::TrailingData)
        );
        Ok(())
    }

    #[test]
    fn terminal_eof_check_obeys_its_deadline_when_guardian_stays_open() -> Result<(), Box<dyn Error>>
    {
        let mut wire = Vec::new();
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wire, app_started())?;
        append_event(&mut wire, tui_started())?;
        append_event(&mut wire, GuardianEvent::Ready)?;
        append_event(&mut wire, completed_terminal())?;
        let mut receiver = CoordinatorReceiver::new(NonClosingReader {
            inner: Cursor::new(wire),
        });
        let _lease = receiver.receive(deadline())?;
        let _app = receiver.receive(deadline())?;
        let _tui = receiver.receive(deadline())?;
        let _ready = receiver.receive(deadline())?;
        let _terminal = receiver.receive(deadline())?;
        assert_eq!(
            receiver.verify_terminal_eof(Instant::now() + Duration::from_millis(5)),
            Err(ProtocolError::Timeout)
        );
        Ok(())
    }

    #[test]
    fn eof_check_is_unavailable_before_a_trusted_terminal() -> Result<(), Box<dyn Error>> {
        let wire = encode_guardian(GuardianEvent::LeaseCommitted)?;
        let mut receiver = CoordinatorReceiver::new(Cursor::new(wire));
        let _lease = receiver.receive(deadline())?;
        assert_eq!(
            receiver.verify_terminal_eof(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        Ok(())
    }

    #[test]
    fn guardian_accepts_start_once_and_stop_only_after_start() -> Result<(), Box<dyn Error>> {
        let mut wire = encode_coordinator(CoordinatorCommand::Start)?;
        wire.extend_from_slice(&encode_coordinator(CoordinatorCommand::Stop)?);
        let mut receiver = GuardianCommandReceiver::new(Cursor::new(wire));
        assert_eq!(receiver.receive(deadline())?, CoordinatorCommand::Start);
        assert_eq!(receiver.receive(deadline())?, CoordinatorCommand::Stop);

        let mut stop_first = GuardianCommandReceiver::new(Cursor::new(encode_coordinator(
            CoordinatorCommand::Stop,
        )?));
        assert_eq!(
            stop_first.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        Ok(())
    }

    #[test]
    fn duplicate_guardian_commands_poison_the_stream() -> Result<(), Box<dyn Error>> {
        for duplicate in [CoordinatorCommand::Start, CoordinatorCommand::Stop] {
            let first = if duplicate == CoordinatorCommand::Start {
                CoordinatorCommand::Start
            } else {
                CoordinatorCommand::Stop
            };
            let mut wire = Vec::new();
            if duplicate == CoordinatorCommand::Stop {
                wire.extend_from_slice(&encode_coordinator(CoordinatorCommand::Start)?);
            }
            wire.extend_from_slice(&encode_coordinator(first)?);
            wire.extend_from_slice(&encode_coordinator(duplicate)?);
            let mut receiver = GuardianCommandReceiver::new(Cursor::new(wire));
            if duplicate == CoordinatorCommand::Stop {
                let _start = receiver.receive(deadline())?;
            }
            let _first = receiver.receive(deadline())?;
            assert_eq!(
                receiver.receive(deadline()),
                Err(ProtocolError::UnexpectedState)
            );
        }
        Ok(())
    }

    #[test]
    fn read_and_write_deadlines_are_mandatory_and_redacted() {
        let expired = Instant::now();
        assert_eq!(
            receive_guardian_event(&mut AlwaysWouldBlock, expired),
            Err(ProtocolError::Timeout)
        );
        assert_eq!(
            send_coordinator_command(&mut AlwaysWouldBlock, CoordinatorCommand::Start, expired),
            Err(ProtocolError::Timeout)
        );

        let soon = Instant::now() + Duration::from_millis(5);
        assert_eq!(
            receive_guardian_event(&mut AlwaysWouldBlock, soon),
            Err(ProtocolError::Timeout)
        );
        let soon = Instant::now() + Duration::from_millis(5);
        assert_eq!(
            send_coordinator_command(&mut AlwaysWouldBlock, CoordinatorCommand::Start, soon),
            Err(ProtocolError::Timeout)
        );
    }

    #[test]
    fn protocol_errors_never_retain_input_sentinels() {
        let sentinel = b"credential-sentinel-must-not-escape";
        let mut wire = raw_frame(GUARDIAN_DIRECTION | GUARDIAN_READY, sentinel);
        wire[0] = b'X';
        let error = receive_guardian_event(&mut Cursor::new(wire), deadline())
            .err()
            .unwrap_or(ProtocolError::Io);
        assert_eq!(error, ProtocolError::BadMagic);
        assert!(!format!("{error:?}").contains("credential-sentinel"));
        assert!(!error.to_string().contains("credential-sentinel"));
    }

    struct FragmentedReader<R> {
        inner: R,
        maximum: usize,
    }

    impl<R> FragmentedReader<R> {
        fn new(inner: R, maximum: usize) -> Self {
            Self { inner, maximum }
        }
    }

    impl<R: Read> Read for FragmentedReader<R> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let length = output.len().min(self.maximum);
            self.inner.read(&mut output[..length])
        }
    }

    struct FragmentedWriter {
        bytes: Vec<u8>,
        maximum: usize,
    }

    impl FragmentedWriter {
        fn new(maximum: usize) -> Self {
            Self {
                bytes: Vec::new(),
                maximum,
            }
        }
    }

    impl Write for FragmentedWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let length = input.len().min(self.maximum);
            self.bytes.extend_from_slice(&input[..length]);
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct AlwaysWouldBlock;

    struct NonClosingReader {
        inner: Cursor<Vec<u8>>,
    }

    impl Read for NonClosingReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            match self.inner.read(output)? {
                0 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                read => Ok(read),
            }
        }
    }

    impl Read for AlwaysWouldBlock {
        fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    impl Write for AlwaysWouldBlock {
        fn write(&mut self, _input: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }
}
