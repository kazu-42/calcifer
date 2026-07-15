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

use subtle::ConstantTimeEq;

const MAGIC: [u8; 4] = *b"CLFR";
const PROTOCOL_VERSION: u8 = 1;
const PAYLOAD_VERSION: u8 = 1;
const HEADER_BYTES: usize = 8;
const MAX_FRAME_BYTES: usize = 64;
const MAX_BODY_BYTES: usize = MAX_FRAME_BYTES - HEADER_BYTES;

const DIRECTION_MASK: u8 = 0x80;
const TYPE_MASK: u8 = 0x7f;
const COORDINATOR_DIRECTION: u8 = 0x00;
const GUARDIAN_DIRECTION: u8 = 0x80;

const COORDINATOR_START: u8 = 1;
const COORDINATOR_STOP: u8 = 2;
const COORDINATOR_OPEN_INPUT_GATE: u8 = 3;
const COORDINATOR_SIGNAL: u8 = 4;
const COORDINATOR_RESIZE: u8 = 5;
const COORDINATOR_SUSPEND: u8 = 6;
const COORDINATOR_RESUME: u8 = 7;
const COORDINATOR_TERMINAL_RESTORED: u8 = 8;
const COORDINATOR_TERMINAL_ARM_ACCEPTED: u8 = 9;

const GUARDIAN_LEASE_COMMITTED: u8 = 1;
const GUARDIAN_CHILD_STARTED: u8 = 2;
const GUARDIAN_READY: u8 = 3;
const GUARDIAN_FAILED: u8 = 4;
const GUARDIAN_CHILDREN_REAPED: u8 = 5;
const GUARDIAN_TERMINAL_ARMED: u8 = 6;
const GUARDIAN_INPUT_GATE_OPENED: u8 = 7;
const GUARDIAN_SIGNAL_FORWARDED: u8 = 8;
const GUARDIAN_RESIZE_APPLIED: u8 = 9;
const GUARDIAN_SUSPENDED: u8 = 10;
const GUARDIAN_RESUMED: u8 = 11;
const GUARDIAN_TERMINAL_QUIESCED: u8 = 12;
const GUARDIAN_TERMINAL_RECOVERY_DISARMED: u8 = 13;

const EMPTY_BODY_BYTES: usize = 1;
const SNAPSHOT_FINGERPRINT_BYTES: usize = 32;
const TERMINAL_ARMED_BODY_BYTES: usize = 1 + SNAPSHOT_FINGERPRINT_BYTES;
const SIGNAL_BODY_BYTES: usize = 2;
const TERMINAL_SIZE_BODY_BYTES: usize = 5;
const CHILD_STARTED_BODY_BYTES: usize = 10;
const FAILED_BODY_BYTES: usize = 3;
const CHILD_DISPOSITION_BYTES: usize = 4;
const CHILDREN_REAPED_BODY_BYTES: usize = 12;

/// A coordinator-to-guardian command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorCommand {
    Start,
    TerminalArmAccepted,
    Stop,
    OpenInputGate,
    Signal { signal: UnixSignal },
    Resize { rows: u16, cols: u16 },
    Suspend,
    Resume { rows: u16, cols: u16 },
    TerminalRestored,
}

/// A guardian-to-coordinator lifecycle event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GuardianEvent {
    LeaseCommitted,
    TerminalArmed {
        snapshot: TerminalSnapshotFingerprint,
    },
    ChildStarted {
        role: ChildRole,
        pid: i32,
        pgid: i32,
    },
    Ready,
    InputGateOpened,
    SignalForwarded {
        signal: UnixSignal,
    },
    ResizeApplied {
        rows: u16,
        cols: u16,
    },
    Suspended,
    Resumed {
        rows: u16,
        cols: u16,
    },
    TerminalQuiesced,
    TerminalRecoveryDisarmed,
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

/// Redacted semantic identity for one immutable pre-raw terminal snapshot.
///
/// The digest is carried only on the fixed lifecycle frame and is never
/// rendered. Equality uses a constant-time comparison so a mismatch cannot
/// reveal which terminal field first diverged.
#[derive(Clone, Copy)]
pub(super) struct TerminalSnapshotFingerprint([u8; SNAPSHOT_FINGERPRINT_BYTES]);

impl TerminalSnapshotFingerprint {
    pub(super) const fn from_digest(digest: [u8; SNAPSHOT_FINGERPRINT_BYTES]) -> Self {
        Self(digest)
    }

    pub(super) fn matches(self, other: Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }

    #[cfg(feature = "internal-supervisor-fixture")]
    pub(super) fn corrupted_for_fixture(mut self) -> Self {
        self.0[0] ^= 0x80;
        self
    }

    const fn as_bytes(&self) -> &[u8; SNAPSHOT_FINGERPRINT_BYTES] {
        &self.0
    }
}

impl PartialEq for TerminalSnapshotFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.matches(*other)
    }
}

impl Eq for TerminalSnapshotFingerprint {}

impl fmt::Debug for TerminalSnapshotFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.0;
        formatter.write_str("TerminalSnapshotFingerprint(<redacted>)")
    }
}

/// The only asynchronous Unix signals accepted by the terminal protocol.
///
/// `WINCH` is represented by [`CoordinatorCommand::Resize`], while `TSTP` and
/// `CONT` are represented by the ordered suspend/resume handshake. Keeping raw
/// signal numbers off the wire makes the allow-list explicit and portable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UnixSignal {
    Hup,
    Int,
    Quit,
    Term,
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
    Terminal,
    Pump,
    Signal,
    Restore,
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
    Terminal,
    Pump,
    Signal,
    Restore,
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

/// Allocation-free validation for the full duplex terminal transcript.
///
/// Both process roles feed their received messages and their own emitted
/// messages through the same state machine. This makes `READY`, raw-mode
/// transition, `OPEN_GATE`, and its acknowledgement distinct authorities;
/// observing only one side of the handshake can never authorize input.
#[derive(Clone, Copy, Debug)]
struct TerminalLifecycleValidator {
    state: TerminalLifecycleState,
    lease_committed: bool,
    app_started: bool,
    tui_started: bool,
    gate_ever_opened: bool,
    failure: Option<(Phase, FailureCode)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalLifecycleState {
    AwaitLeaseBeforeStart,
    AwaitStart,
    AwaitTerminalArmed,
    AwaitTerminalArmAcceptance,
    AwaitApp,
    AwaitTui,
    AwaitReady,
    ReadyForGate,
    AwaitGateOpened,
    Active,
    AwaitSignalForwarded {
        signal: UnixSignal,
        was_suspended: bool,
    },
    AwaitResizeApplied {
        rows: u16,
        cols: u16,
    },
    AwaitSuspended,
    Suspended,
    AwaitResumed {
        rows: u16,
        cols: u16,
    },
    AwaitQuiesced,
    FailedAwaitQuiesced,
    Quiesced,
    AwaitRecoveryDisarmed,
    RecoveryDisarmed,
    Terminal,
}

impl TerminalLifecycleValidator {
    const fn before_start() -> Self {
        Self {
            state: TerminalLifecycleState::AwaitLeaseBeforeStart,
            lease_committed: false,
            app_started: false,
            tui_started: false,
            gate_ever_opened: false,
            failure: None,
        }
    }

    fn accept_command(&mut self, command: CoordinatorCommand) -> Result<(), ProtocolError> {
        use CoordinatorCommand as Command;
        use TerminalLifecycleState as State;

        self.state = match (self.state, command) {
            (State::AwaitStart, Command::Start) => State::AwaitTerminalArmed,
            (State::AwaitTerminalArmAcceptance, Command::TerminalArmAccepted) => State::AwaitApp,
            (State::ReadyForGate, Command::OpenInputGate) => State::AwaitGateOpened,
            (State::Active, Command::Signal { signal }) => State::AwaitSignalForwarded {
                signal,
                was_suspended: false,
            },
            (State::Suspended, Command::Signal { signal }) => State::AwaitSignalForwarded {
                signal,
                was_suspended: true,
            },
            (State::Active, Command::Resize { rows, cols }) => {
                validate_terminal_size(rows, cols)?;
                State::AwaitResizeApplied { rows, cols }
            }
            (State::Active, Command::Suspend) => State::AwaitSuspended,
            (State::Suspended, Command::Resume { rows, cols }) => {
                validate_terminal_size(rows, cols)?;
                State::AwaitResumed { rows, cols }
            }
            (State::ReadyForGate | State::Active | State::Suspended, Command::Stop) => {
                State::AwaitQuiesced
            }
            // `TerminalQuiesced` is also the typed acknowledgement that a
            // natural TUI exit superseded one already-written foreground
            // control. The guardian may consume exactly that queued command
            // before the subsequently-written restoration command. Shutdown
            // signals are deliberately excluded because their disposition
            // requires an explicit `SignalForwarded` proof.
            (
                State::Quiesced,
                Command::Signal {
                    signal: UnixSignal::Int | UnixSignal::Quit,
                },
            ) => State::Quiesced,
            (State::Quiesced, Command::Resize { rows, cols }) => {
                validate_terminal_size(rows, cols)?;
                State::Quiesced
            }
            (State::Quiesced, Command::TerminalRestored) => State::AwaitRecoveryDisarmed,
            _ => return Err(ProtocolError::UnexpectedState),
        };
        Ok(())
    }

    fn accept_event(&mut self, event: GuardianEvent) -> Result<(), ProtocolError> {
        use GuardianEvent as Event;
        use TerminalLifecycleState as State;

        if let Event::Failed { phase, code } = event {
            return self.accept_failure(phase, code);
        }

        self.state = match (self.state, event) {
            (State::AwaitLeaseBeforeStart, Event::LeaseCommitted) => {
                self.lease_committed = true;
                State::AwaitStart
            }
            (State::AwaitTerminalArmed, Event::TerminalArmed { .. }) => {
                State::AwaitTerminalArmAcceptance
            }
            (
                State::AwaitApp,
                Event::ChildStarted {
                    role: ChildRole::AppServer,
                    pid,
                    pgid,
                },
            ) => {
                validate_process_group(pid, pgid)?;
                self.app_started = true;
                State::AwaitTui
            }
            (
                State::AwaitTui,
                Event::ChildStarted {
                    role: ChildRole::Tui,
                    pid,
                    pgid,
                },
            ) => {
                validate_process_group(pid, pgid)?;
                self.tui_started = true;
                State::AwaitReady
            }
            (State::AwaitReady, Event::Ready) => State::ReadyForGate,
            (State::AwaitGateOpened, Event::InputGateOpened) => {
                self.gate_ever_opened = true;
                State::Active
            }
            (
                State::AwaitSignalForwarded {
                    signal: expected,
                    was_suspended,
                },
                Event::SignalForwarded { signal },
            ) if signal == expected => {
                if matches!(signal, UnixSignal::Hup | UnixSignal::Term) {
                    State::AwaitQuiesced
                } else if was_suspended {
                    State::Suspended
                } else {
                    State::Active
                }
            }
            (
                State::AwaitResizeApplied {
                    rows: expected_rows,
                    cols: expected_cols,
                },
                Event::ResizeApplied { rows, cols },
            ) if rows == expected_rows && cols == expected_cols => State::Active,
            // A natural TUI exit can race a best-effort foreground control
            // after the coordinator has written it but before the guardian
            // has read it. Exact terminal quiescence supersedes only controls
            // whose Unix disposition does not define shutdown. HUP/TERM and
            // suspended controls still require their explicit acknowledgement.
            (
                State::AwaitSignalForwarded {
                    signal: UnixSignal::Int | UnixSignal::Quit,
                    was_suspended: false,
                },
                Event::TerminalQuiesced,
            ) => State::Quiesced,
            (State::AwaitResizeApplied { .. }, Event::TerminalQuiesced) => State::Quiesced,
            (State::AwaitSuspended, Event::Suspended) => State::Suspended,
            (
                State::AwaitResumed {
                    rows: expected_rows,
                    cols: expected_cols,
                },
                Event::Resumed { rows, cols },
            ) if rows == expected_rows && cols == expected_cols => State::ReadyForGate,
            // Exact TUI completion after the gate opens is itself a trusted
            // shutdown trigger. Requiring STOP here would deadlock after the
            // input path has disappeared. A stopped TUI is deliberately not
            // included: exit while suspended is unexpected and must first be
            // classified by a FAILED event.
            (State::Active, Event::TerminalQuiesced) => State::Quiesced,
            (State::AwaitQuiesced | State::FailedAwaitQuiesced, Event::TerminalQuiesced) => {
                State::Quiesced
            }
            (State::AwaitRecoveryDisarmed, Event::TerminalRecoveryDisarmed) => {
                State::RecoveryDisarmed
            }
            (State::RecoveryDisarmed, terminal @ Event::ChildrenReaped { .. }) => {
                self.validate_terminal(terminal)?;
                State::Terminal
            }
            _ => return Err(ProtocolError::UnexpectedState),
        };
        Ok(())
    }

    fn accept_failure(&mut self, phase: Phase, code: FailureCode) -> Result<(), ProtocolError> {
        use TerminalLifecycleState as State;

        // Worker join happens only after the coordinator has restored the
        // terminal and the guardian has disarmed recovery. A failed join is
        // therefore the sole new failure that may be discovered in
        // `RecoveryDisarmed`; every earlier phase must already have been
        // announced before quiescence/disarm.
        let post_recovery_worker_failure = self.state == State::RecoveryDisarmed
            && phase == Phase::Worker
            && code == FailureCode::Worker;
        if self.failure.is_some()
            || matches!(
                self.state,
                State::AwaitLeaseBeforeStart
                    | State::AwaitStart
                    | State::Terminal
                    | State::FailedAwaitQuiesced
            )
            || (self.state == State::RecoveryDisarmed && !post_recovery_worker_failure)
        {
            return Err(ProtocolError::UnexpectedState);
        }
        self.failure = Some((phase, code));
        self.state = match self.state {
            State::Quiesced | State::AwaitRecoveryDisarmed | State::RecoveryDisarmed => self.state,
            _ => State::FailedAwaitQuiesced,
        };
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
                if session != SessionStatus::Completed
                    || worker != WorkerJoinStatus::JoinedClean
                    || !self.lease_committed
                    || !self.app_started
                    || !self.tui_started
                    || !self.gate_ever_opened
                {
                    return Err(ProtocolError::InvalidValue);
                }
            }
            Some((phase, code)) => {
                // Cleanup or restoration failure cannot manufacture terminal
                // authority. The caller must retain A and preserve evidence.
                if matches!(phase, Phase::Cleanup | Phase::Restore)
                    || matches!(code, FailureCode::CleanupMismatch | FailureCode::Restore)
                {
                    return Err(ProtocolError::UnexpectedState);
                }
                if session != SessionStatus::Failed {
                    return Err(ProtocolError::InvalidValue);
                }
            }
        }
        Ok(())
    }

    const fn terminal_received(&self) -> bool {
        matches!(self.state, TerminalLifecycleState::Terminal)
    }

    const fn input_gate_opened(&self) -> bool {
        matches!(
            self.state,
            TerminalLifecycleState::Active
                | TerminalLifecycleState::AwaitSignalForwarded {
                    signal: UnixSignal::Int | UnixSignal::Quit,
                    was_suspended: false,
                }
                | TerminalLifecycleState::AwaitResizeApplied { .. }
        )
    }
}

/// Sends one typed coordinator command without allocating.
pub(super) fn send_coordinator_command<W: Write>(
    writer: &mut W,
    command: CoordinatorCommand,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    let mut body = [0_u8; MAX_BODY_BYTES];
    body[0] = PAYLOAD_VERSION;
    let (message_type, body_len) = match command {
        CoordinatorCommand::Start => (COORDINATOR_START, EMPTY_BODY_BYTES),
        CoordinatorCommand::TerminalArmAccepted => {
            (COORDINATOR_TERMINAL_ARM_ACCEPTED, EMPTY_BODY_BYTES)
        }
        CoordinatorCommand::Stop => (COORDINATOR_STOP, EMPTY_BODY_BYTES),
        CoordinatorCommand::OpenInputGate => (COORDINATOR_OPEN_INPUT_GATE, EMPTY_BODY_BYTES),
        CoordinatorCommand::Signal { signal } => {
            body[1] = encode_unix_signal(signal);
            (COORDINATOR_SIGNAL, SIGNAL_BODY_BYTES)
        }
        CoordinatorCommand::Resize { rows, cols } => {
            encode_terminal_size(rows, cols, &mut body[1..5])?;
            (COORDINATOR_RESIZE, TERMINAL_SIZE_BODY_BYTES)
        }
        CoordinatorCommand::Suspend => (COORDINATOR_SUSPEND, EMPTY_BODY_BYTES),
        CoordinatorCommand::Resume { rows, cols } => {
            encode_terminal_size(rows, cols, &mut body[1..5])?;
            (COORDINATOR_RESUME, TERMINAL_SIZE_BODY_BYTES)
        }
        CoordinatorCommand::TerminalRestored => (COORDINATOR_TERMINAL_RESTORED, EMPTY_BODY_BYTES),
    };
    send_frame(
        writer,
        COORDINATOR_DIRECTION | message_type,
        &body[..body_len],
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
        GuardianEvent::TerminalArmed { snapshot } => {
            body[1..TERMINAL_ARMED_BODY_BYTES].copy_from_slice(snapshot.as_bytes());
            (GUARDIAN_TERMINAL_ARMED, TERMINAL_ARMED_BODY_BYTES)
        }
        GuardianEvent::ChildStarted { role, pid, pgid } => {
            validate_process_group(pid, pgid)?;
            body[1] = encode_child_role(role);
            body[2..6].copy_from_slice(&pid.to_be_bytes());
            body[6..10].copy_from_slice(&pgid.to_be_bytes());
            (GUARDIAN_CHILD_STARTED, CHILD_STARTED_BODY_BYTES)
        }
        GuardianEvent::Ready => (GUARDIAN_READY, EMPTY_BODY_BYTES),
        GuardianEvent::InputGateOpened => (GUARDIAN_INPUT_GATE_OPENED, EMPTY_BODY_BYTES),
        GuardianEvent::SignalForwarded { signal } => {
            body[1] = encode_unix_signal(signal);
            (GUARDIAN_SIGNAL_FORWARDED, SIGNAL_BODY_BYTES)
        }
        GuardianEvent::ResizeApplied { rows, cols } => {
            encode_terminal_size(rows, cols, &mut body[1..5])?;
            (GUARDIAN_RESIZE_APPLIED, TERMINAL_SIZE_BODY_BYTES)
        }
        GuardianEvent::Suspended => (GUARDIAN_SUSPENDED, EMPTY_BODY_BYTES),
        GuardianEvent::Resumed { rows, cols } => {
            encode_terminal_size(rows, cols, &mut body[1..5])?;
            (GUARDIAN_RESUMED, TERMINAL_SIZE_BODY_BYTES)
        }
        GuardianEvent::TerminalQuiesced => (GUARDIAN_TERMINAL_QUIESCED, EMPTY_BODY_BYTES),
        GuardianEvent::TerminalRecoveryDisarmed => {
            (GUARDIAN_TERMINAL_RECOVERY_DISARMED, EMPTY_BODY_BYTES)
        }
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

/// Emits one fixed invalid guardian frame for the feature-gated real-exec
/// harness. Keeping the malformed bytes here prevents the harness from
/// growing an arbitrary lifecycle-byte injection surface.
#[cfg(feature = "internal-supervisor-fixture")]
pub(super) fn send_fixture_malformed_guardian_frame<W: Write>(
    writer: &mut W,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    const MALFORMED_FRAME: [u8; HEADER_BYTES] = [
        b'B',
        b'A',
        b'D',
        b'!',
        PROTOCOL_VERSION,
        GUARDIAN_DIRECTION | GUARDIAN_TERMINAL_ARMED,
        0,
        1,
    ];
    write_all_before(writer, &MALFORMED_FRAME, deadline)?;
    flush_before(writer, deadline)
}

/// Emits a syntactically framed `TerminalArmed` event with one fixed trailing
/// body byte. The receiver must reject it before accepting terminal authority.
#[cfg(feature = "internal-supervisor-fixture")]
pub(super) fn send_fixture_trailing_terminal_armed<W: Write>(
    writer: &mut W,
    snapshot: TerminalSnapshotFingerprint,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    let mut body = [0_u8; TERMINAL_ARMED_BODY_BYTES + 1];
    body[0] = PAYLOAD_VERSION;
    body[1..TERMINAL_ARMED_BODY_BYTES].copy_from_slice(snapshot.as_bytes());
    body[TERMINAL_ARMED_BODY_BYTES] = 0xa5;
    send_frame(
        writer,
        GUARDIAN_DIRECTION | GUARDIAN_TERMINAL_ARMED,
        &body,
        deadline,
    )
}

/// Receives and validates the guardian event sequence observed by a
/// coordinator. A protocol error poisons this receiver; a later terminal frame
/// can never repair an invalid stream.
pub(super) struct CoordinatorReceiver<R> {
    reader: R,
    terminal: Option<TerminalLifecycleValidator>,
    state: CoordinatorState,
    lease_committed: bool,
    app_started: bool,
    tui_started: bool,
    failure: Option<(Phase, FailureCode)>,
    poisoned: bool,
    eof_verified: bool,
    verified_ready_pending: bool,
    verified_open_gate_ack_pending: bool,
}

/// Move-only proof minted only after the coordinator receiver accepts a
/// protocol-valid initial `Ready` or post-suspend `Resumed` event.
#[must_use = "verified readiness must be consumed by the input gate"]
pub(super) struct VerifiedReady {
    _private: (),
}

/// Move-only proof minted only after the coordinator receiver accepts the
/// `InputGateOpened` acknowledgement in the expected protocol state.
#[must_use = "the open-gate acknowledgement must be consumed by the input gate"]
pub(super) struct VerifiedOpenGateAck {
    _private: (),
}

impl fmt::Debug for VerifiedReady {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedReady(<redacted>)")
    }
}

impl fmt::Debug for VerifiedOpenGateAck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedOpenGateAck(<redacted>)")
    }
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
            terminal: None,
            state: CoordinatorState::AwaitLease,
            lease_committed: false,
            app_started: false,
            tui_started: false,
            failure: None,
            poisoned: false,
            eof_verified: false,
            verified_ready_pending: false,
            verified_open_gate_ack_pending: false,
        }
    }

    /// Creates a receiver for the default-unused terminal protocol before the
    /// coordinator writes `START`. The coordinator must first receive
    /// `LeaseCommitted`, verify the #50 phase barrier, and then record `START`.
    pub(super) fn new_terminal(reader: R) -> Self {
        Self {
            reader,
            terminal: Some(TerminalLifecycleValidator::before_start()),
            state: CoordinatorState::AwaitLease,
            lease_committed: false,
            app_started: false,
            tui_started: false,
            failure: None,
            poisoned: false,
            eof_verified: false,
            verified_ready_pending: false,
            verified_open_gate_ack_pending: false,
        }
    }

    pub(super) fn receive(&mut self, deadline: Instant) -> Result<GuardianEvent, ProtocolError> {
        if self.poisoned || self.terminal_received() {
            return Err(ProtocolError::UnexpectedState);
        }
        // Proofs are valid only for the immediately preceding accepted
        // transition. Advancing the transcript without consuming one makes it
        // permanently unavailable rather than allowing a stale-cycle mint.
        self.verified_ready_pending = false;
        self.verified_open_gate_ack_pending = false;
        let event = match receive_guardian_event(&mut self.reader, deadline) {
            Ok(event) => event,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let accepted = if let Some(terminal) = self.terminal.as_mut() {
            terminal.accept_event(event)
        } else {
            self.accept(event)
        };
        if let Err(error) = accepted {
            self.poisoned = true;
            self.verified_ready_pending = false;
            self.verified_open_gate_ack_pending = false;
            return Err(error);
        }
        if self.terminal.is_some() {
            match event {
                GuardianEvent::Ready | GuardianEvent::Resumed { .. } => {
                    self.verified_ready_pending = true;
                }
                GuardianEvent::InputGateOpened => {
                    self.verified_open_gate_ack_pending = true;
                }
                _ => {}
            }
        }
        Ok(event)
    }

    /// Consumes the readiness proof created by the immediately preceding
    /// accepted readiness transition. No public or sibling constructor exists.
    pub(super) fn take_verified_ready(&mut self) -> Result<VerifiedReady, ProtocolError> {
        if self.poisoned || !std::mem::take(&mut self.verified_ready_pending) {
            return Err(ProtocolError::UnexpectedState);
        }
        Ok(VerifiedReady { _private: () })
    }

    /// Consumes the open-gate ACK proof created by the accepted protocol
    /// transition. It cannot be replayed because the pending bit is linear.
    pub(super) fn take_verified_open_gate_ack(
        &mut self,
    ) -> Result<VerifiedOpenGateAck, ProtocolError> {
        if self.poisoned || !std::mem::take(&mut self.verified_open_gate_ack_pending) {
            return Err(ProtocolError::UnexpectedState);
        }
        Ok(VerifiedOpenGateAck { _private: () })
    }

    /// Records a command emitted by the coordinator into the terminal
    /// transcript. `START` itself must be recorded only after `LeaseCommitted`
    /// and the external phase-barrier proof; later commands must be recorded
    /// before reading their acknowledgement.
    pub(super) fn record_command(
        &mut self,
        command: CoordinatorCommand,
    ) -> Result<(), ProtocolError> {
        if self.poisoned || self.terminal_received() {
            return Err(ProtocolError::UnexpectedState);
        }
        self.verified_ready_pending = false;
        self.verified_open_gate_ack_pending = false;
        let Some(terminal) = self.terminal.as_mut() else {
            self.poisoned = true;
            return Err(ProtocolError::UnexpectedState);
        };
        if let Err(error) = terminal.accept_command(command) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    pub(super) const fn input_gate_opened(&self) -> bool {
        !self.poisoned
            && match &self.terminal {
                Some(terminal) => terminal.input_gate_opened(),
                None => false,
            }
    }

    /// Verifies that the terminal frame was the final lifecycle payload.
    /// Callers perform this check after exact-waiting the guardian so a clean
    /// stream must return EOF immediately.
    pub(super) fn verify_terminal_eof(&mut self, deadline: Instant) -> Result<(), ProtocolError> {
        if self.poisoned || !self.terminal_received() {
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
        !self.poisoned
            && match &self.terminal {
                Some(terminal) => terminal.terminal_received(),
                None => matches!(self.state, CoordinatorState::Terminal),
            }
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
    terminal: Option<TerminalLifecycleValidator>,
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
            terminal: None,
            state: GuardianCommandState::AwaitStart,
            poisoned: false,
        }
    }

    /// Creates the full-duplex terminal validator. The guardian must record
    /// each event it emits so commands are accepted only after their exact
    /// prerequisite events. In particular, B must already be committed and
    /// `LeaseCommitted` recorded before the phase-barrier `START` is accepted.
    pub(super) fn new_terminal(reader: R) -> Self {
        Self {
            reader,
            terminal: Some(TerminalLifecycleValidator::before_start()),
            state: GuardianCommandState::AwaitStart,
            poisoned: false,
        }
    }

    pub(super) fn receive(
        &mut self,
        deadline: Instant,
    ) -> Result<CoordinatorCommand, ProtocolError> {
        if self.poisoned || self.state == GuardianCommandState::Stopped || self.terminal_received()
        {
            return Err(ProtocolError::UnexpectedState);
        }
        let command = match receive_coordinator_command(&mut self.reader, deadline) {
            Ok(command) => command,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if let Some(terminal) = self.terminal.as_mut() {
            if let Err(error) = terminal.accept_command(command) {
                self.poisoned = true;
                return Err(error);
            }
            return Ok(command);
        }

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

    /// Records a guardian event before it is published on the wire.
    pub(super) fn record_event(&mut self, event: GuardianEvent) -> Result<(), ProtocolError> {
        if self.poisoned {
            return Err(ProtocolError::UnexpectedState);
        }
        let Some(terminal) = self.terminal.as_mut() else {
            self.poisoned = true;
            return Err(ProtocolError::UnexpectedState);
        };
        if let Err(error) = terminal.accept_event(event) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    pub(super) const fn input_gate_opened(&self) -> bool {
        !self.poisoned
            && match &self.terminal {
                Some(terminal) => terminal.input_gate_opened(),
                None => false,
            }
    }

    pub(super) const fn terminal_received(&self) -> bool {
        !self.poisoned
            && match &self.terminal {
                Some(terminal) => terminal.terminal_received(),
                None => matches!(self.state, GuardianCommandState::Stopped),
            }
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
        COORDINATOR_OPEN_INPUT_GATE => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(CoordinatorCommand::OpenInputGate)
        }
        COORDINATOR_SIGNAL => {
            frame.require_exact_len(SIGNAL_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(CoordinatorCommand::Signal {
                signal: decode_unix_signal(frame.body[1])?,
            })
        }
        COORDINATOR_RESIZE => {
            frame.require_exact_len(TERMINAL_SIZE_BODY_BYTES)?;
            frame.require_payload_version()?;
            let (rows, cols) = decode_terminal_size(&frame.body[1..5])?;
            Ok(CoordinatorCommand::Resize { rows, cols })
        }
        COORDINATOR_SUSPEND => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(CoordinatorCommand::Suspend)
        }
        COORDINATOR_RESUME => {
            frame.require_exact_len(TERMINAL_SIZE_BODY_BYTES)?;
            frame.require_payload_version()?;
            let (rows, cols) = decode_terminal_size(&frame.body[1..5])?;
            Ok(CoordinatorCommand::Resume { rows, cols })
        }
        COORDINATOR_TERMINAL_RESTORED => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(CoordinatorCommand::TerminalRestored)
        }
        COORDINATOR_TERMINAL_ARM_ACCEPTED => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(CoordinatorCommand::TerminalArmAccepted)
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
        GUARDIAN_TERMINAL_ARMED => {
            frame.require_exact_len(TERMINAL_ARMED_BODY_BYTES)?;
            frame.require_payload_version()?;
            let mut snapshot = [0_u8; SNAPSHOT_FINGERPRINT_BYTES];
            snapshot.copy_from_slice(&frame.body[1..TERMINAL_ARMED_BODY_BYTES]);
            Ok(GuardianEvent::TerminalArmed {
                snapshot: TerminalSnapshotFingerprint::from_digest(snapshot),
            })
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
        GUARDIAN_INPUT_GATE_OPENED => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(GuardianEvent::InputGateOpened)
        }
        GUARDIAN_SIGNAL_FORWARDED => {
            frame.require_exact_len(SIGNAL_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(GuardianEvent::SignalForwarded {
                signal: decode_unix_signal(frame.body[1])?,
            })
        }
        GUARDIAN_RESIZE_APPLIED => {
            frame.require_exact_len(TERMINAL_SIZE_BODY_BYTES)?;
            frame.require_payload_version()?;
            let (rows, cols) = decode_terminal_size(&frame.body[1..5])?;
            Ok(GuardianEvent::ResizeApplied { rows, cols })
        }
        GUARDIAN_SUSPENDED => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(GuardianEvent::Suspended)
        }
        GUARDIAN_RESUMED => {
            frame.require_exact_len(TERMINAL_SIZE_BODY_BYTES)?;
            frame.require_payload_version()?;
            let (rows, cols) = decode_terminal_size(&frame.body[1..5])?;
            Ok(GuardianEvent::Resumed { rows, cols })
        }
        GUARDIAN_TERMINAL_QUIESCED => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(GuardianEvent::TerminalQuiesced)
        }
        GUARDIAN_TERMINAL_RECOVERY_DISARMED => {
            frame.require_exact_len(EMPTY_BODY_BYTES)?;
            frame.require_payload_version()?;
            Ok(GuardianEvent::TerminalRecoveryDisarmed)
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

const fn encode_unix_signal(signal: UnixSignal) -> u8 {
    match signal {
        UnixSignal::Hup => 1,
        UnixSignal::Int => 2,
        UnixSignal::Quit => 3,
        UnixSignal::Term => 4,
    }
}

fn decode_unix_signal(value: u8) -> Result<UnixSignal, ProtocolError> {
    match value {
        1 => Ok(UnixSignal::Hup),
        2 => Ok(UnixSignal::Int),
        3 => Ok(UnixSignal::Quit),
        4 => Ok(UnixSignal::Term),
        _ => Err(ProtocolError::InvalidValue),
    }
}

fn encode_terminal_size(rows: u16, cols: u16, output: &mut [u8]) -> Result<(), ProtocolError> {
    validate_terminal_size(rows, cols)?;
    if output.len() != 4 {
        return Err(ProtocolError::InvalidLength);
    }
    output[..2].copy_from_slice(&rows.to_be_bytes());
    output[2..4].copy_from_slice(&cols.to_be_bytes());
    Ok(())
}

fn decode_terminal_size(input: &[u8]) -> Result<(u16, u16), ProtocolError> {
    if input.len() != 4 {
        return Err(ProtocolError::InvalidLength);
    }
    let rows = u16::from_be_bytes([input[0], input[1]]);
    let cols = u16::from_be_bytes([input[2], input[3]]);
    validate_terminal_size(rows, cols)?;
    Ok((rows, cols))
}

fn validate_terminal_size(rows: u16, cols: u16) -> Result<(), ProtocolError> {
    if rows == 0 || cols == 0 {
        Err(ProtocolError::InvalidValue)
    } else {
        Ok(())
    }
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
        Phase::Terminal => 11,
        Phase::Pump => 12,
        Phase::Signal => 13,
        Phase::Restore => 14,
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
        11 => Ok(Phase::Terminal),
        12 => Ok(Phase::Pump),
        13 => Ok(Phase::Signal),
        14 => Ok(Phase::Restore),
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
        FailureCode::Terminal => 12,
        FailureCode::Pump => 13,
        FailureCode::Signal => 14,
        FailureCode::Restore => 15,
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
        12 => Ok(FailureCode::Terminal),
        13 => Ok(FailureCode::Pump),
        14 => Ok(FailureCode::Signal),
        15 => Ok(FailureCode::Restore),
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
    fn terminal_control_frames_are_typed_bounded_and_round_trip() -> Result<(), Box<dyn Error>> {
        for command in [
            CoordinatorCommand::TerminalArmAccepted,
            CoordinatorCommand::OpenInputGate,
            CoordinatorCommand::Signal {
                signal: UnixSignal::Hup,
            },
            CoordinatorCommand::Signal {
                signal: UnixSignal::Int,
            },
            CoordinatorCommand::Signal {
                signal: UnixSignal::Quit,
            },
            CoordinatorCommand::Signal {
                signal: UnixSignal::Term,
            },
            CoordinatorCommand::Resize { rows: 24, cols: 80 },
            CoordinatorCommand::Suspend,
            CoordinatorCommand::Resume {
                rows: 48,
                cols: 160,
            },
            CoordinatorCommand::TerminalRestored,
        ] {
            let wire = encode_coordinator(command)?;
            assert!(wire.len() <= MAX_FRAME_BYTES);
            assert_eq!(
                receive_coordinator_command(&mut Cursor::new(wire), deadline())?,
                command
            );
        }

        for event in [
            terminal_armed(),
            GuardianEvent::InputGateOpened,
            GuardianEvent::SignalForwarded {
                signal: UnixSignal::Int,
            },
            GuardianEvent::ResizeApplied { rows: 24, cols: 80 },
            GuardianEvent::Suspended,
            GuardianEvent::Resumed {
                rows: 48,
                cols: 160,
            },
            GuardianEvent::TerminalQuiesced,
            GuardianEvent::TerminalRecoveryDisarmed,
        ] {
            let wire = encode_guardian(event)?;
            assert!(wire.len() <= MAX_FRAME_BYTES);
            assert_eq!(
                receive_guardian_event(&mut Cursor::new(wire), deadline())?,
                event
            );
        }
        assert_eq!(MAX_FRAME_BYTES, 64);

        for (phase, code) in [
            (Phase::Terminal, FailureCode::Terminal),
            (Phase::Pump, FailureCode::Pump),
            (Phase::Signal, FailureCode::Signal),
            (Phase::Restore, FailureCode::Restore),
        ] {
            let event = GuardianEvent::Failed { phase, code };
            assert_eq!(
                receive_guardian_event(&mut Cursor::new(encode_guardian(event)?), deadline())?,
                event
            );
        }
        Ok(())
    }

    #[test]
    fn terminal_arm_fingerprint_is_fixed_redacted_and_constant_time_comparable()
    -> Result<(), Box<dyn Error>> {
        let expected = TerminalSnapshotFingerprint::from_digest([0x5a; SNAPSHOT_FINGERPRINT_BYTES]);
        let same = TerminalSnapshotFingerprint::from_digest([0x5a; SNAPSHOT_FINGERPRINT_BYTES]);
        let different =
            TerminalSnapshotFingerprint::from_digest([0xa5; SNAPSHOT_FINGERPRINT_BYTES]);
        assert!(expected.matches(same));
        assert!(!expected.matches(different));
        assert!(expected == same);
        assert!(expected != different);
        assert_eq!(
            format!("{expected:?}"),
            "TerminalSnapshotFingerprint(<redacted>)"
        );

        let short = raw_frame(
            GUARDIAN_DIRECTION | GUARDIAN_TERMINAL_ARMED,
            &[PAYLOAD_VERSION; TERMINAL_ARMED_BODY_BYTES - 1],
        );
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(short), deadline()),
            Err(ProtocolError::InvalidLength)
        );
        let long = raw_frame(
            GUARDIAN_DIRECTION | GUARDIAN_TERMINAL_ARMED,
            &[PAYLOAD_VERSION; TERMINAL_ARMED_BODY_BYTES + 1],
        );
        assert_eq!(
            receive_guardian_event(&mut Cursor::new(long), deadline()),
            Err(ProtocolError::TrailingData)
        );
        Ok(())
    }

    #[test]
    fn terminal_arm_acceptance_is_a_spawn_order_barrier() -> Result<(), Box<dyn Error>> {
        let mut wire = Vec::new();
        for event in [
            GuardianEvent::LeaseCommitted,
            terminal_armed(),
            app_started(),
        ] {
            append_event(&mut wire, event)?;
        }
        let mut coordinator = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        assert_eq!(
            coordinator.receive(deadline())?,
            GuardianEvent::LeaseCommitted
        );
        coordinator.record_command(CoordinatorCommand::Start)?;
        assert_eq!(coordinator.receive(deadline())?, terminal_armed());
        assert_eq!(
            coordinator.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );

        let commands = encode_coordinator(CoordinatorCommand::Start)?;
        let mut guardian = GuardianCommandReceiver::new_terminal(Cursor::new(commands));
        guardian.record_event(GuardianEvent::LeaseCommitted)?;
        assert_eq!(guardian.receive(deadline())?, CoordinatorCommand::Start);
        guardian.record_event(terminal_armed())?;
        assert_eq!(
            guardian.record_event(app_started()),
            Err(ProtocolError::UnexpectedState)
        );
        Ok(())
    }

    #[test]
    fn terminal_sizes_and_signal_wire_values_are_strict() -> Result<(), Box<dyn Error>> {
        for command in [
            CoordinatorCommand::Resize { rows: 0, cols: 80 },
            CoordinatorCommand::Resize { rows: 24, cols: 0 },
            CoordinatorCommand::Resume { rows: 0, cols: 80 },
            CoordinatorCommand::Resume { rows: 24, cols: 0 },
        ] {
            assert_eq!(
                send_coordinator_command(&mut Vec::new(), command, deadline()),
                Err(ProtocolError::InvalidValue)
            );
        }
        for event in [
            GuardianEvent::ResizeApplied { rows: 0, cols: 80 },
            GuardianEvent::Resumed { rows: 24, cols: 0 },
        ] {
            assert_eq!(
                send_guardian_event(&mut Vec::new(), event, deadline()),
                Err(ProtocolError::InvalidValue)
            );
        }

        let invalid_signal = raw_frame(
            COORDINATOR_DIRECTION | COORDINATOR_SIGNAL,
            &[PAYLOAD_VERSION, 0xff],
        );
        assert_eq!(
            receive_coordinator_command(&mut Cursor::new(invalid_signal), deadline()),
            Err(ProtocolError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn terminal_receiver_requires_arming_ready_and_gate_ack_before_input_state()
    -> Result<(), Box<dyn Error>> {
        let mut wire = Vec::new();
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wire, terminal_armed())?;
        append_event(&mut wire, app_started())?;
        append_event(&mut wire, tui_started())?;
        append_event(&mut wire, GuardianEvent::Ready)?;
        append_event(&mut wire, GuardianEvent::InputGateOpened)?;
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));

        assert!(matches!(
            receiver.take_verified_ready(),
            Err(ProtocolError::UnexpectedState)
        ));
        assert!(matches!(
            receiver.take_verified_open_gate_ack(),
            Err(ProtocolError::UnexpectedState)
        ));
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::LeaseCommitted);
        receiver.record_command(CoordinatorCommand::Start)?;
        assert_eq!(receiver.receive(deadline())?, terminal_armed());
        receiver.record_command(CoordinatorCommand::TerminalArmAccepted)?;
        for expected in [app_started(), tui_started(), GuardianEvent::Ready] {
            assert_eq!(receiver.receive(deadline())?, expected);
        }
        let readiness = receiver.take_verified_ready()?;
        assert_eq!(format!("{readiness:?}"), "VerifiedReady(<redacted>)");
        assert_eq!(std::mem::size_of_val(&readiness), 0);
        assert!(matches!(
            receiver.take_verified_ready(),
            Err(ProtocolError::UnexpectedState)
        ));
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::InputGateOpened
        );
        let acknowledgement = receiver.take_verified_open_gate_ack()?;
        assert_eq!(
            format!("{acknowledgement:?}"),
            "VerifiedOpenGateAck(<redacted>)"
        );
        assert_eq!(std::mem::size_of_val(&acknowledgement), 0);
        assert!(matches!(
            receiver.take_verified_open_gate_ack(),
            Err(ProtocolError::UnexpectedState)
        ));
        assert!(receiver.input_gate_opened());
        Ok(())
    }

    #[test]
    fn terminal_capability_proofs_expire_when_the_transcript_advances() -> Result<(), Box<dyn Error>>
    {
        let mut wire = Vec::new();
        for event in [
            GuardianEvent::LeaseCommitted,
            terminal_armed(),
            app_started(),
            tui_started(),
            GuardianEvent::Ready,
            GuardianEvent::InputGateOpened,
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::LeaseCommitted);
        receiver.record_command(CoordinatorCommand::Start)?;
        assert_eq!(receiver.receive(deadline())?, terminal_armed());
        receiver.record_command(CoordinatorCommand::TerminalArmAccepted)?;
        for expected in [app_started(), tui_started(), GuardianEvent::Ready] {
            assert_eq!(receiver.receive(deadline())?, expected);
        }

        // Advancing with the command without consuming readiness permanently
        // invalidates that proof.
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        assert!(matches!(
            receiver.take_verified_ready(),
            Err(ProtocolError::UnexpectedState)
        ));
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::InputGateOpened
        );

        // The same rule applies to an unconsumed gate acknowledgement.
        receiver.record_command(CoordinatorCommand::Stop)?;
        assert!(matches!(
            receiver.take_verified_open_gate_ack(),
            Err(ProtocolError::UnexpectedState)
        ));
        Ok(())
    }

    #[test]
    fn ready_without_terminal_arming_or_open_gate_cannot_authorize_input()
    -> Result<(), Box<dyn Error>> {
        let mut wrong_order = Vec::new();
        append_event(&mut wrong_order, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wrong_order, app_started())?;
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wrong_order));
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::LeaseCommitted);
        receiver.record_command(CoordinatorCommand::Start)?;
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        assert_eq!(
            receiver.record_command(CoordinatorCommand::OpenInputGate),
            Err(ProtocolError::UnexpectedState)
        );

        let mut ready_wire = Vec::new();
        append_event(&mut ready_wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut ready_wire, terminal_armed())?;
        append_event(&mut ready_wire, app_started())?;
        append_event(&mut ready_wire, tui_started())?;
        append_event(&mut ready_wire, GuardianEvent::Ready)?;
        append_event(
            &mut ready_wire,
            GuardianEvent::ResizeApplied { rows: 24, cols: 80 },
        )?;
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(ready_wire));
        receive_terminal_ready(&mut receiver)?;
        assert!(!receiver.input_gate_opened());
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
    fn terminal_receiver_validates_signal_resize_suspend_and_fresh_resume_gate()
    -> Result<(), Box<dyn Error>> {
        let events = [
            GuardianEvent::LeaseCommitted,
            terminal_armed(),
            app_started(),
            tui_started(),
            GuardianEvent::Ready,
            GuardianEvent::InputGateOpened,
            GuardianEvent::SignalForwarded {
                signal: UnixSignal::Int,
            },
            GuardianEvent::ResizeApplied {
                rows: 50,
                cols: 120,
            },
            GuardianEvent::Suspended,
            GuardianEvent::Resumed {
                rows: 60,
                cols: 140,
            },
            GuardianEvent::InputGateOpened,
        ];
        let mut wire = Vec::new();
        for event in events {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::InputGateOpened
        );
        receiver.record_command(CoordinatorCommand::Signal {
            signal: UnixSignal::Int,
        })?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::SignalForwarded {
                signal: UnixSignal::Int
            }
        );
        receiver.record_command(CoordinatorCommand::Resize {
            rows: 50,
            cols: 120,
        })?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::ResizeApplied {
                rows: 50,
                cols: 120
            }
        );
        receiver.record_command(CoordinatorCommand::Suspend)?;
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::Suspended);
        receiver.record_command(CoordinatorCommand::Resume {
            rows: 60,
            cols: 140,
        })?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::Resumed {
                rows: 60,
                cols: 140
            }
        );
        assert!(!receiver.input_gate_opened());
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::InputGateOpened
        );
        assert!(receiver.input_gate_opened());
        Ok(())
    }

    #[test]
    fn interrupt_and_quit_continue_while_hup_and_term_begin_shutdown() -> Result<(), Box<dyn Error>>
    {
        for signal in [UnixSignal::Int, UnixSignal::Quit] {
            let mut wire = terminal_ready_events()?;
            append_event(&mut wire, GuardianEvent::InputGateOpened)?;
            append_event(&mut wire, GuardianEvent::SignalForwarded { signal })?;
            let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
            receive_terminal_ready(&mut receiver)?;
            receiver.record_command(CoordinatorCommand::OpenInputGate)?;
            let _gate = receiver.receive(deadline())?;
            receiver.record_command(CoordinatorCommand::Signal { signal })?;
            assert_eq!(
                receiver.receive(deadline())?,
                GuardianEvent::SignalForwarded { signal }
            );
            assert!(receiver.input_gate_opened());
        }

        for signal in [UnixSignal::Hup, UnixSignal::Term] {
            let mut wire = terminal_ready_events()?;
            for event in [
                GuardianEvent::InputGateOpened,
                GuardianEvent::SignalForwarded { signal },
                GuardianEvent::TerminalQuiesced,
                GuardianEvent::TerminalRecoveryDisarmed,
                completed_terminal(),
            ] {
                append_event(&mut wire, event)?;
            }
            let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
            receive_terminal_ready(&mut receiver)?;
            receiver.record_command(CoordinatorCommand::OpenInputGate)?;
            let _gate = receiver.receive(deadline())?;
            receiver.record_command(CoordinatorCommand::Signal { signal })?;
            assert!(!receiver.input_gate_opened());
            let _forwarded = receiver.receive(deadline())?;
            assert!(!receiver.input_gate_opened());
            assert_eq!(
                receiver.receive(deadline())?,
                GuardianEvent::TerminalQuiesced
            );
            receiver.record_command(CoordinatorCommand::TerminalRestored)?;
            let _disarmed = receiver.receive(deadline())?;
            let _terminal = receiver.receive(deadline())?;
            assert!(receiver.terminal_received());
        }
        Ok(())
    }

    #[test]
    fn natural_exit_supersedes_only_foreground_interactive_controls() -> Result<(), Box<dyn Error>>
    {
        for command in [
            CoordinatorCommand::Signal {
                signal: UnixSignal::Int,
            },
            CoordinatorCommand::Signal {
                signal: UnixSignal::Quit,
            },
            CoordinatorCommand::Resize {
                rows: 41,
                cols: 123,
            },
        ] {
            let mut wire = terminal_ready_events()?;
            for event in [
                GuardianEvent::InputGateOpened,
                GuardianEvent::TerminalQuiesced,
                GuardianEvent::TerminalRecoveryDisarmed,
                completed_terminal(),
            ] {
                append_event(&mut wire, event)?;
            }
            let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
            receive_terminal_ready(&mut receiver)?;
            receiver.record_command(CoordinatorCommand::OpenInputGate)?;
            assert_eq!(
                receiver.receive(deadline())?,
                GuardianEvent::InputGateOpened
            );
            receiver.record_command(command)?;
            assert_eq!(
                receiver.receive(deadline())?,
                GuardianEvent::TerminalQuiesced
            );
            receiver.record_command(CoordinatorCommand::TerminalRestored)?;
            assert_eq!(
                receiver.receive(deadline())?,
                GuardianEvent::TerminalRecoveryDisarmed
            );
            assert_eq!(receiver.receive(deadline())?, completed_terminal());
        }

        for signal in [UnixSignal::Hup, UnixSignal::Term] {
            let mut wire = terminal_ready_events()?;
            append_event(&mut wire, GuardianEvent::InputGateOpened)?;
            append_event(&mut wire, GuardianEvent::TerminalQuiesced)?;
            let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
            receive_terminal_ready(&mut receiver)?;
            receiver.record_command(CoordinatorCommand::OpenInputGate)?;
            let _gate = receiver.receive(deadline())?;
            receiver.record_command(CoordinatorCommand::Signal { signal })?;
            assert_eq!(
                receiver.receive(deadline()),
                Err(ProtocolError::UnexpectedState)
            );
        }
        Ok(())
    }

    #[test]
    fn failure_can_precede_quiescence_while_interactive_control_is_outstanding()
    -> Result<(), Box<dyn Error>> {
        let failure = GuardianEvent::Failed {
            phase: Phase::Tui,
            code: FailureCode::EarlyExit,
        };
        let mut wire = terminal_ready_events()?;
        for event in [
            GuardianEvent::InputGateOpened,
            failure,
            GuardianEvent::TerminalQuiesced,
            GuardianEvent::TerminalRecoveryDisarmed,
            failed_terminal(true, true),
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        let _gate = receiver.receive(deadline())?;
        receiver.record_command(CoordinatorCommand::Resize {
            rows: 41,
            cols: 123,
        })?;
        assert_eq!(receiver.receive(deadline())?, failure);
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalQuiesced
        );
        receiver.record_command(CoordinatorCommand::TerminalRestored)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalRecoveryDisarmed
        );
        assert_eq!(receiver.receive(deadline())?, failed_terminal(true, true));
        Ok(())
    }

    #[test]
    fn terminal_shutdown_requires_quiesced_restored_disarmed_then_reaped()
    -> Result<(), Box<dyn Error>> {
        let mut wire = Vec::new();
        for event in [
            GuardianEvent::LeaseCommitted,
            terminal_armed(),
            app_started(),
            tui_started(),
            GuardianEvent::Ready,
            GuardianEvent::InputGateOpened,
            GuardianEvent::TerminalQuiesced,
            GuardianEvent::TerminalRecoveryDisarmed,
            completed_terminal(),
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        let _gate = receiver.receive(deadline())?;
        receiver.record_command(CoordinatorCommand::Stop)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalQuiesced
        );
        receiver.record_command(CoordinatorCommand::TerminalRestored)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalRecoveryDisarmed
        );
        assert_eq!(receiver.receive(deadline())?, completed_terminal());
        assert!(receiver.terminal_received());
        Ok(())
    }

    #[test]
    fn coordinator_accepts_trusted_natural_tui_exit_after_gate_open() -> Result<(), Box<dyn Error>>
    {
        let mut wire = terminal_ready_events()?;
        for event in [
            GuardianEvent::InputGateOpened,
            GuardianEvent::TerminalQuiesced,
            GuardianEvent::TerminalRecoveryDisarmed,
            completed_terminal(),
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::InputGateOpened
        );

        // No STOP is sent: exact TUI EOF is itself the shutdown trigger.
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalQuiesced
        );
        assert!(!receiver.input_gate_opened());
        receiver.record_command(CoordinatorCommand::TerminalRestored)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalRecoveryDisarmed
        );
        assert_eq!(receiver.receive(deadline())?, completed_terminal());
        assert!(receiver.terminal_received());
        Ok(())
    }

    #[test]
    fn guardian_accepts_trusted_natural_tui_exit_after_gate_open() -> Result<(), Box<dyn Error>> {
        let mut commands = encode_coordinator(CoordinatorCommand::Start)?;
        commands.extend_from_slice(&encode_coordinator(
            CoordinatorCommand::TerminalArmAccepted,
        )?);
        commands.extend_from_slice(&encode_coordinator(CoordinatorCommand::OpenInputGate)?);
        commands.extend_from_slice(&encode_coordinator(CoordinatorCommand::TerminalRestored)?);
        let mut receiver = GuardianCommandReceiver::new_terminal(Cursor::new(commands));
        receiver.record_event(GuardianEvent::LeaseCommitted)?;
        assert_eq!(receiver.receive(deadline())?, CoordinatorCommand::Start);
        record_guardian_terminal_ready(&mut receiver)?;
        assert_eq!(
            receiver.receive(deadline())?,
            CoordinatorCommand::OpenInputGate
        );
        receiver.record_event(GuardianEvent::InputGateOpened)?;

        // The guardian may publish exact natural completion without waiting
        // for a coordinator STOP that can no longer be caused by user input.
        receiver.record_event(GuardianEvent::TerminalQuiesced)?;
        assert_eq!(
            receiver.receive(deadline())?,
            CoordinatorCommand::TerminalRestored
        );
        receiver.record_event(GuardianEvent::TerminalRecoveryDisarmed)?;
        receiver.record_event(completed_terminal())?;
        assert!(receiver.terminal_received());
        Ok(())
    }

    #[test]
    fn worker_failure_discovered_after_recovery_disarm_remains_typed() -> Result<(), Box<dyn Error>>
    {
        let failure = GuardianEvent::Failed {
            phase: Phase::Worker,
            code: FailureCode::Worker,
        };
        let terminal = GuardianEvent::ChildrenReaped {
            app: ChildDisposition::Signaled {
                signal: 15,
                core_dumped: false,
                stop_action: StopAction::Term,
            },
            tui: exited(0),
            worker: WorkerJoinStatus::JoinedFailed,
            cleanup: CleanupStatus::Complete,
            session: SessionStatus::Failed,
        };
        let mut wire = terminal_ready_events()?;
        for event in [
            GuardianEvent::InputGateOpened,
            GuardianEvent::TerminalQuiesced,
            GuardianEvent::TerminalRecoveryDisarmed,
            failure,
            terminal,
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::InputGateOpened
        );
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalQuiesced
        );
        receiver.record_command(CoordinatorCommand::TerminalRestored)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalRecoveryDisarmed
        );
        assert_eq!(receiver.receive(deadline())?, failure);
        assert_eq!(receiver.receive(deadline())?, terminal);
        assert!(receiver.terminal_received());
        Ok(())
    }

    #[test]
    fn guardian_discards_one_queued_interactive_control_after_natural_quiescence()
    -> Result<(), Box<dyn Error>> {
        for failure in [
            None,
            Some(GuardianEvent::Failed {
                phase: Phase::Pump,
                code: FailureCode::Pump,
            }),
        ] {
            let mut commands = encode_coordinator(CoordinatorCommand::Start)?;
            commands.extend_from_slice(&encode_coordinator(
                CoordinatorCommand::TerminalArmAccepted,
            )?);
            commands.extend_from_slice(&encode_coordinator(CoordinatorCommand::OpenInputGate)?);
            commands.extend_from_slice(&encode_coordinator(CoordinatorCommand::Resize {
                rows: 41,
                cols: 123,
            })?);
            commands.extend_from_slice(&encode_coordinator(CoordinatorCommand::TerminalRestored)?);
            let mut receiver = GuardianCommandReceiver::new_terminal(Cursor::new(commands));
            receiver.record_event(GuardianEvent::LeaseCommitted)?;
            assert_eq!(receiver.receive(deadline())?, CoordinatorCommand::Start);
            record_guardian_terminal_ready(&mut receiver)?;
            assert_eq!(
                receiver.receive(deadline())?,
                CoordinatorCommand::OpenInputGate
            );
            receiver.record_event(GuardianEvent::InputGateOpened)?;
            if let Some(failure) = failure {
                receiver.record_event(failure)?;
            }
            receiver.record_event(GuardianEvent::TerminalQuiesced)?;
            assert_eq!(
                receiver.receive(deadline())?,
                CoordinatorCommand::Resize {
                    rows: 41,
                    cols: 123,
                }
            );
            assert_eq!(
                receiver.receive(deadline())?,
                CoordinatorCommand::TerminalRestored
            );
            receiver.record_event(GuardianEvent::TerminalRecoveryDisarmed)?;
            receiver.record_event(if failure.is_some() {
                failed_terminal(true, true)
            } else {
                completed_terminal()
            })?;
            assert!(receiver.terminal_received());
        }
        Ok(())
    }

    #[test]
    fn guardian_never_discards_shutdown_signal_after_quiescence() -> Result<(), Box<dyn Error>> {
        for signal in [UnixSignal::Hup, UnixSignal::Term] {
            let mut commands = encode_coordinator(CoordinatorCommand::Start)?;
            commands.extend_from_slice(&encode_coordinator(
                CoordinatorCommand::TerminalArmAccepted,
            )?);
            commands.extend_from_slice(&encode_coordinator(CoordinatorCommand::OpenInputGate)?);
            commands.extend_from_slice(&encode_coordinator(CoordinatorCommand::Signal { signal })?);
            let mut receiver = GuardianCommandReceiver::new_terminal(Cursor::new(commands));
            receiver.record_event(GuardianEvent::LeaseCommitted)?;
            assert_eq!(receiver.receive(deadline())?, CoordinatorCommand::Start);
            record_guardian_terminal_ready(&mut receiver)?;
            assert_eq!(
                receiver.receive(deadline())?,
                CoordinatorCommand::OpenInputGate
            );
            receiver.record_event(GuardianEvent::InputGateOpened)?;
            receiver.record_event(GuardianEvent::TerminalQuiesced)?;
            assert_eq!(
                receiver.receive(deadline()),
                Err(ProtocolError::UnexpectedState)
            );
        }
        Ok(())
    }

    #[test]
    fn natural_tui_exit_before_gate_open_requires_a_failure_event() -> Result<(), Box<dyn Error>> {
        let mut wire = terminal_ready_events()?;
        append_event(&mut wire, GuardianEvent::TerminalQuiesced)?;
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        assert_eq!(
            receiver.record_command(CoordinatorCommand::TerminalRestored),
            Err(ProtocolError::UnexpectedState)
        );
        Ok(())
    }

    #[test]
    fn tui_exit_while_suspended_requires_a_failure_event() -> Result<(), Box<dyn Error>> {
        let mut wire = terminal_ready_events()?;
        for event in [
            GuardianEvent::InputGateOpened,
            GuardianEvent::Suspended,
            GuardianEvent::TerminalQuiesced,
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        let _gate = receiver.receive(deadline())?;
        receiver.record_command(CoordinatorCommand::Suspend)?;
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::Suspended);
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        Ok(())
    }

    #[test]
    fn terminal_failure_before_raw_still_requires_restore_sequence() -> Result<(), Box<dyn Error>> {
        let failure = GuardianEvent::Failed {
            phase: Phase::Terminal,
            code: FailureCode::Terminal,
        };
        let mut wire = Vec::new();
        for event in [
            GuardianEvent::LeaseCommitted,
            failure,
            GuardianEvent::TerminalQuiesced,
            GuardianEvent::TerminalRecoveryDisarmed,
            failed_terminal(false, false),
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::LeaseCommitted);
        receiver.record_command(CoordinatorCommand::Start)?;
        assert_eq!(receiver.receive(deadline())?, failure);
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalQuiesced
        );
        receiver.record_command(CoordinatorCommand::TerminalRestored)?;
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalRecoveryDisarmed
        );
        assert_eq!(receiver.receive(deadline())?, failed_terminal(false, false));
        assert!(receiver.terminal_received());
        Ok(())
    }

    #[test]
    fn terminal_failure_after_gate_still_requires_restore_sequence() -> Result<(), Box<dyn Error>> {
        let failure = GuardianEvent::Failed {
            phase: Phase::Pump,
            code: FailureCode::Pump,
        };
        let mut wire = terminal_ready_events()?;
        for event in [
            GuardianEvent::InputGateOpened,
            failure,
            GuardianEvent::TerminalQuiesced,
            GuardianEvent::TerminalRecoveryDisarmed,
            failed_terminal(true, true),
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        let _gate = receiver.receive(deadline())?;
        assert_eq!(receiver.receive(deadline())?, failure);
        assert!(!receiver.input_gate_opened());
        assert_eq!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalQuiesced
        );
        receiver.record_command(CoordinatorCommand::TerminalRestored)?;
        let _disarmed = receiver.receive(deadline())?;
        assert_eq!(receiver.receive(deadline())?, failed_terminal(true, true));
        assert!(receiver.terminal_received());
        Ok(())
    }

    #[test]
    fn skipped_terminal_recovery_steps_poison_the_receiver() -> Result<(), Box<dyn Error>> {
        // DISARMED cannot replace QUIESCED.
        let mut wire = terminal_ready_events()?;
        for event in [
            GuardianEvent::InputGateOpened,
            GuardianEvent::TerminalRecoveryDisarmed,
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        let _gate = receiver.receive(deadline())?;
        receiver.record_command(CoordinatorCommand::Stop)?;
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );

        // QUIESCED cannot authorize DISARMED without RESTORED.
        let mut wire = terminal_ready_events()?;
        for event in [
            GuardianEvent::InputGateOpened,
            GuardianEvent::TerminalQuiesced,
            GuardianEvent::TerminalRecoveryDisarmed,
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        let _gate = receiver.receive(deadline())?;
        receiver.record_command(CoordinatorCommand::Stop)?;
        let _quiesced = receiver.receive(deadline())?;
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );

        // CHILDREN_REAPED cannot replace the explicit DISARMED acknowledgement.
        let mut wire = terminal_ready_events()?;
        for event in [
            GuardianEvent::InputGateOpened,
            GuardianEvent::TerminalQuiesced,
            completed_terminal(),
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        let _gate = receiver.receive(deadline())?;
        receiver.record_command(CoordinatorCommand::Stop)?;
        let _quiesced = receiver.receive(deadline())?;
        receiver.record_command(CoordinatorCommand::TerminalRestored)?;
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        Ok(())
    }

    #[test]
    fn wrong_terminal_ack_or_duplicate_command_poisons_the_receiver() -> Result<(), Box<dyn Error>>
    {
        let mut wire = Vec::new();
        for event in [
            GuardianEvent::LeaseCommitted,
            terminal_armed(),
            app_started(),
            tui_started(),
            GuardianEvent::Ready,
            GuardianEvent::InputGateOpened,
            GuardianEvent::SignalForwarded {
                signal: UnixSignal::Term,
            },
        ] {
            append_event(&mut wire, event)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        receive_terminal_ready(&mut receiver)?;
        receiver.record_command(CoordinatorCommand::OpenInputGate)?;
        let _gate = receiver.receive(deadline())?;
        receiver.record_command(CoordinatorCommand::Signal {
            signal: UnixSignal::Int,
        })?;
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        assert_eq!(
            receiver.record_command(CoordinatorCommand::Stop),
            Err(ProtocolError::UnexpectedState)
        );

        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(Vec::<u8>::new()));
        assert_eq!(
            receiver.record_command(CoordinatorCommand::OpenInputGate),
            Err(ProtocolError::UnexpectedState)
        );
        assert_eq!(
            receiver.record_command(CoordinatorCommand::OpenInputGate),
            Err(ProtocolError::UnexpectedState)
        );
        Ok(())
    }

    #[test]
    fn guardian_terminal_receiver_cross_checks_its_emitted_events() -> Result<(), Box<dyn Error>> {
        let mut commands = encode_coordinator(CoordinatorCommand::Start)?;
        commands.extend_from_slice(&encode_coordinator(
            CoordinatorCommand::TerminalArmAccepted,
        )?);
        commands.extend_from_slice(&encode_coordinator(CoordinatorCommand::OpenInputGate)?);
        let mut receiver = GuardianCommandReceiver::new_terminal(Cursor::new(commands));
        receiver.record_event(GuardianEvent::LeaseCommitted)?;
        assert_eq!(receiver.receive(deadline())?, CoordinatorCommand::Start);
        record_guardian_terminal_ready(&mut receiver)?;
        assert_eq!(
            receiver.receive(deadline())?,
            CoordinatorCommand::OpenInputGate
        );
        receiver.record_event(GuardianEvent::InputGateOpened)?;
        assert!(receiver.input_gate_opened());
        Ok(())
    }

    #[test]
    fn coordinator_terminal_receiver_requires_lease_commit_before_start()
    -> Result<(), Box<dyn Error>> {
        let lease = encode_guardian(GuardianEvent::LeaseCommitted)?;
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(lease));
        assert_eq!(
            receiver.record_command(CoordinatorCommand::Start),
            Err(ProtocolError::UnexpectedState)
        );
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );

        let mut wire = Vec::new();
        append_event(&mut wire, GuardianEvent::LeaseCommitted)?;
        append_event(&mut wire, terminal_armed())?;
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        assert_eq!(receiver.receive(deadline())?, GuardianEvent::LeaseCommitted);
        receiver.record_command(CoordinatorCommand::Start)?;
        assert_eq!(receiver.receive(deadline())?, terminal_armed());
        Ok(())
    }

    #[test]
    fn guardian_terminal_receiver_requires_lease_commit_before_start() -> Result<(), Box<dyn Error>>
    {
        let commands = encode_coordinator(CoordinatorCommand::Start)?;
        let mut receiver = GuardianCommandReceiver::new_terminal(Cursor::new(commands));
        assert_eq!(
            receiver.receive(deadline()),
            Err(ProtocolError::UnexpectedState)
        );
        assert_eq!(
            receiver.record_event(GuardianEvent::LeaseCommitted),
            Err(ProtocolError::UnexpectedState)
        );

        let commands = encode_coordinator(CoordinatorCommand::Start)?;
        let mut receiver = GuardianCommandReceiver::new_terminal(Cursor::new(commands));
        receiver.record_event(GuardianEvent::LeaseCommitted)?;
        assert_eq!(receiver.receive(deadline())?, CoordinatorCommand::Start);
        receiver.record_event(terminal_armed())?;
        Ok(())
    }

    fn terminal_ready_events() -> Result<Vec<u8>, ProtocolError> {
        let mut wire = Vec::new();
        for event in [
            GuardianEvent::LeaseCommitted,
            terminal_armed(),
            app_started(),
            tui_started(),
            GuardianEvent::Ready,
        ] {
            append_event(&mut wire, event)?;
        }
        Ok(wire)
    }

    fn terminal_armed() -> GuardianEvent {
        GuardianEvent::TerminalArmed {
            snapshot: TerminalSnapshotFingerprint::from_digest([0x5a; SNAPSHOT_FINGERPRINT_BYTES]),
        }
    }

    fn receive_terminal_ready<R: Read>(
        receiver: &mut CoordinatorReceiver<R>,
    ) -> Result<(), ProtocolError> {
        if receiver.receive(deadline())? != GuardianEvent::LeaseCommitted {
            return Err(ProtocolError::UnexpectedState);
        }
        receiver.record_command(CoordinatorCommand::Start)?;
        if !matches!(
            receiver.receive(deadline())?,
            GuardianEvent::TerminalArmed { .. }
        ) {
            return Err(ProtocolError::UnexpectedState);
        }
        receiver.record_command(CoordinatorCommand::TerminalArmAccepted)?;
        for _ in 0..3 {
            let _event = receiver.receive(deadline())?;
        }
        Ok(())
    }

    fn record_guardian_terminal_ready<R: Read>(
        receiver: &mut GuardianCommandReceiver<R>,
    ) -> Result<(), ProtocolError> {
        receiver.record_event(terminal_armed())?;
        if receiver.receive(deadline())? != CoordinatorCommand::TerminalArmAccepted {
            return Err(ProtocolError::UnexpectedState);
        }
        for event in [app_started(), tui_started(), GuardianEvent::Ready] {
            receiver.record_event(event)?;
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
