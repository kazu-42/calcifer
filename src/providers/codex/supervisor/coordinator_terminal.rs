//! Coordinator-owned half of one supervised terminal generation.
//!
//! Output is available in every state. Input does not have a buffer or a read
//! transition until exact readiness, raw-mode readback, and the guardian's
//! protocol-valid open-gate acknowledgement have all been consumed.

use std::fmt;
use std::os::fd::AsFd;
use std::thread;
use std::time::{Duration, Instant};

use super::protocol::{TerminalSnapshotFingerprint, VerifiedOpenGateAck, VerifiedReady};
use super::terminal::{
    GateClosed as InputGateClosed, GateOpen as InputGateOpen, GateReady as InputGateReady,
    InputGate, PendingTerminalOutput, PendingTerminalRead, RawTerminalProof, RestoredTerminalProof,
    TerminalBuffer, TerminalChunk, TerminalEndpoint, TerminalRead, TerminalShutdown, TerminalSize,
    TerminalSnapshot, TerminalTty, TerminalWrite, terminal_size,
};

const PUMP_RETRY: Duration = Duration::from_millis(1);

/// No readiness proof exists and no outer-terminal input reader exists.
pub(super) struct OutputOnly {
    gate: InputGate<InputGateClosed>,
}

/// Exact provider readiness exists, but the outer terminal is not raw.
pub(super) struct GateReady {
    gate: InputGate<InputGateReady>,
}

/// Raw mode was applied and read back; the guardian ACK is still absent.
pub(super) struct RawAwaitAck {
    gate: InputGate<InputGateReady>,
    raw: RawTerminalProof,
}

/// Both input directions may now exist for this exact gate generation.
pub(super) struct Active {
    _gate: InputGate<InputGateOpen>,
    input: TerminalBuffer,
}

/// Input has been destroyed before the coordinator asks the guardian to
/// suspend the TUI. The outer terminal is still raw until `Suspended` is
/// acknowledged and [`Paused::restore_for_suspend`] succeeds.
pub(super) struct Paused;

/// The shell-facing terminal is restored while the Calcifer process is
/// stopped. The contained proof is reused if shutdown wins the resume race.
pub(super) struct SuspendedRestored {
    proof: RestoredTerminalProof,
}

/// A fresh raw proof exists after `SIGCONT`, but protocol-valid resumed
/// readiness has not yet created the next gate generation.
pub(super) struct ResumeRaw {
    gate: InputGate<InputGateClosed>,
    raw: RawTerminalProof,
}

/// Input is physically absent and normal restoration may begin.
pub(super) struct Quiesced;

/// The captured outer-terminal snapshot was restored and read back.
pub(super) struct Restored {
    proof: RestoredTerminalProof,
}

/// One redacted coordinator-terminal failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorTerminalError {
    Setup,
    Deadline,
    OuterTerminalEof,
    TerminalChannelRead,
    TerminalChannelWrite,
    OuterTerminalRead,
    OuterTerminalWrite,
    RawTransition,
    Foreground,
    WindowSize,
    Restore,
    Shutdown,
}

impl fmt::Display for CoordinatorTerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the coordinator terminal boundary failed")
    }
}

impl std::error::Error for CoordinatorTerminalError {}

/// Setup failure retains the exact coordinator endpoint supplied by the
/// caller. No raw transition has occurred on this path.
#[must_use = "terminal setup failure retains the coordinator endpoint"]
pub(super) struct CoordinatorTerminalSetupFailure {
    endpoint: TerminalEndpoint,
    error: CoordinatorTerminalError,
}

impl CoordinatorTerminalSetupFailure {
    #[cfg(test)]
    pub(super) const fn error(&self) -> CoordinatorTerminalError {
        self.error
    }

    #[cfg(test)]
    #[expect(
        clippy::boxed_local,
        reason = "the setup API deliberately returns one boxed linear failure owner"
    )]
    pub(super) fn into_endpoint(self: Box<Self>) -> TerminalEndpoint {
        self.endpoint
    }
}

impl fmt::Debug for CoordinatorTerminalSetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.endpoint;
        formatter
            .debug_struct("CoordinatorTerminalSetupFailure")
            .field("error", &self.error)
            .field("retains_endpoint", &true)
            .finish()
    }
}

impl fmt::Display for CoordinatorTerminalSetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for CoordinatorTerminalSetupFailure {}

/// A failed consuming operation returns the exact prior typed owner.
#[must_use = "terminal failure retains the exact prior state owner"]
pub(super) struct CoordinatorTerminalFailure<Owner> {
    owner: Owner,
    error: CoordinatorTerminalError,
}

impl<Owner> CoordinatorTerminalFailure<Owner> {
    pub(super) const fn error(&self) -> CoordinatorTerminalError {
        self.error
    }

    #[expect(
        clippy::boxed_local,
        reason = "consuming a bounded failure must recover its possibly large exact owner"
    )]
    pub(super) fn into_owner(self: Box<Self>) -> Owner {
        self.owner
    }
}

impl<Owner> fmt::Debug for CoordinatorTerminalFailure<Owner> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.owner;
        formatter
            .debug_struct("CoordinatorTerminalFailure")
            .field("error", &self.error)
            .field("retains_owner", &true)
            .finish()
    }
}

impl<Owner> fmt::Display for CoordinatorTerminalFailure<Owner> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl<Owner> std::error::Error for CoordinatorTerminalFailure<Owner> {}

/// Observable work from one bounded, transcript-free pump turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorPumpProgress {
    Idle,
    Output,
    OutputPending,
    OutputClosed,
    Input,
}

/// Successful consuming pump turn with the same typed owner.
#[must_use = "a pump turn returns the exact terminal owner"]
pub(super) struct CoordinatorPumpTurn<Owner> {
    owner: Owner,
    progress: CoordinatorPumpProgress,
}

impl<Owner> CoordinatorPumpTurn<Owner> {
    pub(super) const fn progress(&self) -> CoordinatorPumpProgress {
        self.progress
    }

    pub(super) fn into_owner(self) -> Owner {
        self.owner
    }
}

impl<Owner> fmt::Debug for CoordinatorPumpTurn<Owner> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.owner;
        formatter
            .debug_struct("CoordinatorPumpTurn")
            .field("progress", &self.progress)
            .finish_non_exhaustive()
    }
}

/// Exact coordinator authority for one terminal generation.
///
/// `State` owns every phase-specific capability. In particular, only
/// [`Active`] contains an input buffer and only [`Restored`] contains a
/// restoration proof.
#[must_use = "the coordinator terminal must be advanced, restored, or retained"]
pub(super) struct CoordinatorTerminal<State> {
    tty: TerminalTty,
    endpoint: TerminalEndpoint,
    snapshot: TerminalSnapshot,
    output: PendingTerminalOutput,
    output_stall_deadline: Option<Instant>,
    output_closed: bool,
    state: State,
}

impl CoordinatorTerminal<OutputOnly> {
    /// Captures the pre-raw snapshot and opens an independent outer tty whose
    /// nonblocking flag cannot leak into the invoking shell's open-file
    /// description.
    pub(super) fn capture<Fd: AsFd>(
        outer_tty: Fd,
        endpoint: TerminalEndpoint,
    ) -> Result<Self, Box<CoordinatorTerminalSetupFailure>> {
        let outer_tty = outer_tty.as_fd();
        let setup = (|| {
            endpoint.verify_invariants()?;
            let snapshot = TerminalSnapshot::capture(outer_tty)?;
            let tty = TerminalTty::open_independent(outer_tty)?;
            if tty.descriptor_identity() != snapshot.descriptor_identity() {
                return Err(super::terminal::TerminalError::TerminalIdentityMismatch);
            }
            endpoint.enable_nonblocking()?;
            tty.enable_nonblocking()?;
            Ok((snapshot, tty))
        })();
        let (snapshot, tty) = match setup {
            Ok(components) => components,
            Err(_) => {
                return Err(Box::new(CoordinatorTerminalSetupFailure {
                    endpoint,
                    error: CoordinatorTerminalError::Setup,
                }));
            }
        };
        Ok(Self {
            tty,
            endpoint,
            snapshot,
            output: PendingTerminalOutput::new(),
            output_stall_deadline: None,
            output_closed: false,
            state: OutputOnly {
                gate: InputGate::closed(),
            },
        })
    }

    /// Readiness advances only the type state; it still creates no input
    /// buffer and performs no outer-terminal read.
    pub(super) fn mark_ready(self, readiness: VerifiedReady) -> CoordinatorTerminal<GateReady> {
        self.map_state(|state| GateReady {
            gate: state.gate.mark_ready(readiness),
        })
    }

    /// Early shutdown still returns through the one restoration/finish path.
    pub(super) fn quiesce(self) -> CoordinatorTerminal<Quiesced> {
        self.map_state(|_| Quiesced)
    }
}

impl CoordinatorTerminal<GateReady> {
    /// Flushes every pre-ready byte, applies raw mode, and retains the proof
    /// internally until the matching guardian ACK arrives.
    pub(super) fn enter_raw(
        self,
    ) -> Result<CoordinatorTerminal<RawAwaitAck>, Box<CoordinatorTerminalFailure<Self>>> {
        match self.snapshot.enter_raw_after_input_flush(&self.tty) {
            Ok(raw) => Ok(self.map_state(|state| RawAwaitAck {
                gate: state.gate,
                raw,
            })),
            Err(_) => Err(terminal_failure(
                self,
                CoordinatorTerminalError::RawTransition,
            )),
        }
    }

    /// Readiness failure before raw mode retains the same snapshot and tty.
    pub(super) fn quiesce(self) -> CoordinatorTerminal<Quiesced> {
        self.map_state(|_| Quiesced)
    }
}

impl CoordinatorTerminal<RawAwaitAck> {
    /// The first input buffer is constructed only in this transition, after
    /// the raw proof and protocol-valid ACK are consumed together.
    pub(super) fn open_after_ack(
        self,
        acknowledgement: VerifiedOpenGateAck,
    ) -> CoordinatorTerminal<Active> {
        self.map_state(|state| Active {
            _gate: state.gate.acknowledge_open(state.raw, acknowledgement),
            input: TerminalBuffer::new(),
        })
    }

    /// Gate timeout/disconnect after raw mode must restore through this exact
    /// owner; dropping the raw proof does not claim restoration.
    pub(super) fn quiesce(self) -> CoordinatorTerminal<Quiesced> {
        self.map_state(|_| Quiesced)
    }
}

impl CoordinatorTerminal<Active> {
    /// Pumps at most one fixed outer-terminal fragment toward the guardian.
    /// No sibling state has this method or an input buffer.
    pub(super) fn pump_input_once(
        mut self,
        deadline: Instant,
    ) -> Result<CoordinatorPumpTurn<Self>, Box<CoordinatorTerminalFailure<Self>>> {
        if Instant::now() >= deadline {
            return Err(terminal_failure(self, CoordinatorTerminalError::Deadline));
        }
        let result = match self.tty.read_into(&mut self.state.input) {
            Ok(TerminalRead::Data(mut chunk)) => {
                write_fragment_before(deadline, &mut chunk, |chunk| {
                    self.endpoint
                        .try_write(chunk)
                        .map_err(|_| CoordinatorTerminalError::TerminalChannelWrite)
                })
                .map(|()| CoordinatorPumpProgress::Input)
            }
            Ok(TerminalRead::WouldBlock) => Ok(CoordinatorPumpProgress::Idle),
            Ok(TerminalRead::EndOfStream) => Err(CoordinatorTerminalError::OuterTerminalEof),
            Err(_) => Err(CoordinatorTerminalError::OuterTerminalRead),
        };
        match result {
            Ok(progress) => Ok(CoordinatorPumpTurn {
                owner: self,
                progress,
            }),
            Err(error) => Err(terminal_failure(self, error)),
        }
    }

    /// Destroying `Active` destroys the sole input buffer/generation. Output
    /// remains available until the lifecycle protocol says it is safe to
    /// finish the terminal channel.
    pub(super) fn quiesce(self) -> CoordinatorTerminal<Quiesced> {
        self.map_state(|_| Quiesced)
    }

    /// Destroys the only input buffer before emitting `Suspend`. Output
    /// remains pumpable while the guardian reaches its suspension barrier.
    pub(super) fn pause_for_suspend(self) -> CoordinatorTerminal<Paused> {
        self.map_state(|_| Paused)
    }
}

impl CoordinatorTerminal<Paused> {
    /// Restores the exact pre-raw snapshot only after the guardian has
    /// acknowledged `Suspended`. A failed restore returns the still-owned
    /// paused generation for fail-closed recovery.
    pub(super) fn restore_for_suspend(
        self,
    ) -> Result<CoordinatorTerminal<SuspendedRestored>, Box<CoordinatorTerminalFailure<Self>>> {
        match self.snapshot.restore_with_sigttou_block(&self.tty) {
            Ok(proof) => Ok(self.map_state(|_| SuspendedRestored { proof })),
            Err(_) => Err(terminal_failure(self, CoordinatorTerminalError::Restore)),
        }
    }

    pub(super) fn quiesce(self) -> CoordinatorTerminal<Quiesced> {
        self.map_state(|_| Quiesced)
    }
}

impl CoordinatorTerminal<SuspendedRestored> {
    /// Revalidates foreground ownership, flushes bytes typed while suspended,
    /// and enters raw mode for a wholly new input-gate generation.
    ///
    /// A failed raw transition returns a `Quiesced` owner, not a false
    /// `SuspendedRestored` proof: raw application can fail after mutating the
    /// tty, so callers must run the ordinary restore path again.
    pub(super) fn enter_raw_after_continue(
        self,
    ) -> Result<
        CoordinatorTerminal<ResumeRaw>,
        Box<CoordinatorTerminalFailure<CoordinatorTerminal<Quiesced>>>,
    > {
        if !self.foreground_process_group_matches() {
            return Err(terminal_failure(
                self.map_state(|_| Quiesced),
                CoordinatorTerminalError::Foreground,
            ));
        }
        match self.snapshot.enter_raw_after_input_flush(&self.tty) {
            Ok(raw) => Ok(self.map_state(|_| ResumeRaw {
                gate: InputGate::closed(),
                raw,
            })),
            Err(_) => Err(terminal_failure(
                self.map_state(|_| Quiesced),
                CoordinatorTerminalError::RawTransition,
            )),
        }
    }

    /// If shutdown wins after a stop interval, discard the pre-stop proof and
    /// require one fresh exact restore. The foreground shell may legitimately
    /// have changed termios while Calcifer was stopped, so reusing the older
    /// proof would falsely authorize `TerminalRestored`.
    pub(super) fn quiesce_after_suspend(self) -> CoordinatorTerminal<Quiesced> {
        self.map_state(|state| {
            drop(state.proof);
            Quiesced
        })
    }
}

impl CoordinatorTerminal<ResumeRaw> {
    /// `Resumed` is the readiness authority for this new cycle. It cannot be
    /// replayed from the initial gate because the protocol proof is move-only.
    pub(super) fn mark_resumed(self, readiness: VerifiedReady) -> CoordinatorTerminal<RawAwaitAck> {
        self.map_state(|state| RawAwaitAck {
            gate: state.gate.mark_ready(readiness),
            raw: state.raw,
        })
    }

    pub(super) fn quiesce(self) -> CoordinatorTerminal<Quiesced> {
        self.map_state(|_| Quiesced)
    }
}

impl CoordinatorTerminal<Quiesced> {
    /// Applies the exact pre-raw snapshot through the coordinator-owned outer
    /// tty. Guardian recovery is deliberately absent from this module.
    pub(super) fn restore(
        self,
    ) -> Result<CoordinatorTerminal<Restored>, Box<CoordinatorTerminalFailure<Self>>> {
        match self.snapshot.restore_with_sigttou_block(&self.tty) {
            Ok(proof) => Ok(self.map_state(|_| Restored { proof })),
            Err(_) => Err(terminal_failure(self, CoordinatorTerminalError::Restore)),
        }
    }
}

impl CoordinatorTerminal<Restored> {
    /// Closes the terminal byte channel only after restoration. The local
    /// write half is synchronously disabled before the exact endpoint owner is
    /// consumed and dropped. Darwin returns `ENOTCONN` for `SHUT_RDWR` after
    /// the peer has already half-closed its writer, while `SHUT_WR` remains a
    /// reliable proof that no further coordinator-to-guardian bytes can be
    /// emitted; consuming the endpoint then closes the read half as well.
    /// Returning the move-only proof is the sole successful finish path.
    pub(super) fn finish(
        self,
    ) -> Result<RestoredTerminalProof, Box<CoordinatorTerminalFailure<Self>>> {
        if self.endpoint.shutdown(TerminalShutdown::Write).is_err() {
            return Err(terminal_failure(self, CoordinatorTerminalError::Shutdown));
        }
        let Self {
            tty,
            endpoint,
            snapshot,
            output,
            output_stall_deadline,
            output_closed,
            state,
        } = self;
        drop((
            tty,
            endpoint,
            snapshot,
            output,
            output_stall_deadline,
            output_closed,
        ));
        Ok(state.proof)
    }
}

impl<State> CoordinatorTerminal<State> {
    /// Scrubs buffered output while retaining the exact typed terminal owner,
    /// descriptors, and restoration state. This is deliberately separate from
    /// `Drop`: fail-closed retention may park the owner for process lifetime.
    pub(super) fn scrub_pending_output(mut self) -> Self {
        self.output.scrub();
        self.output_stall_deadline = None;
        self
    }

    pub(super) const fn has_pending_output(&self) -> bool {
        self.output.is_pending()
    }

    #[cfg(test)]
    pub(super) fn pending_output_is_scrubbed_for_test(&self) -> bool {
        self.output_stall_deadline.is_none() && self.output.is_zeroized_for_test()
    }

    #[cfg(test)]
    pub(super) fn pending_output_shape_for_test(&self) -> (usize, usize, bool) {
        self.output.retained_shape_for_test()
    }

    #[cfg(test)]
    pub(super) fn load_pending_output_for_test(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), super::terminal::TerminalError> {
        self.output.load_for_test(bytes)?;
        self.output_stall_deadline = Some(deadline);
        Ok(())
    }

    /// Appends both coordinator-owned terminal descriptors to a source-pinned
    /// provider-child denyset. The semantic snapshot contains no descriptor.
    pub(super) fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        forbidden.capture(self.tty.as_fd())?;
        forbidden.capture(self.endpoint.as_fd())
    }

    /// Fixed redacted identity used by the existing terminal-arm protocol.
    pub(super) fn snapshot_fingerprint(&self) -> TerminalSnapshotFingerprint {
        self.snapshot.semantic_fingerprint()
    }

    /// Reads the latest validated shell geometry. `WINCH` is intentionally a
    /// coalescing bit, so no stale size is stored in the signal handler.
    pub(super) fn current_size(&self) -> Result<TerminalSize, CoordinatorTerminalError> {
        let size = self
            .tty
            .verify_invariants()
            .and_then(|()| terminal_size(&self.tty))
            .map_err(|_| CoordinatorTerminalError::WindowSize)?;
        if size.rows() == 0 || size.columns() == 0 {
            Err(CoordinatorTerminalError::WindowSize)
        } else {
            Ok(size)
        }
    }

    fn foreground_process_group_matches(&self) -> bool {
        self.tty.verify_invariants().is_ok()
            && rustix::termios::tcgetpgrp(&self.tty)
                .is_ok_and(|foreground| foreground == rustix::process::getpgrp())
    }

    /// Pumps at most one nonblocking write from one fixed terminal-channel
    /// fragment to the outer tty in every state.
    ///
    /// A transient outer-terminal stall retains the exact fragment and offset
    /// across turns so the coordinator can service lifecycle and signal work.
    /// The first pending turn fixes one inactivity deadline. Forward progress
    /// renews that window for the remaining bytes, while `WouldBlock` never
    /// extends it; the caller's outer phase deadline remains an absolute cap.
    pub(super) fn pump_output_once(
        mut self,
        stall_timeout: Duration,
        outer_deadline: Instant,
    ) -> Result<CoordinatorPumpTurn<Self>, Box<CoordinatorTerminalFailure<Self>>> {
        if stall_timeout.is_zero() {
            return Err(terminal_failure(self, CoordinatorTerminalError::Deadline));
        }
        let result = pump_output_state_once(
            &mut self.output,
            &mut self.output_stall_deadline,
            &mut self.output_closed,
            stall_timeout,
            outer_deadline,
            Instant::now,
            |output| {
                output
                    .read_from(&self.endpoint)
                    .map_err(|_| CoordinatorTerminalError::TerminalChannelRead)
            },
            |output| {
                output
                    .try_write_to(&self.tty)
                    .map_err(|_| CoordinatorTerminalError::OuterTerminalWrite)
            },
        );
        match result {
            Ok(progress) => Ok(CoordinatorPumpTurn {
                owner: self,
                progress,
            }),
            Err(error) => Err(terminal_failure(self, error)),
        }
    }

    fn map_state<Next>(self, transition: impl FnOnce(State) -> Next) -> CoordinatorTerminal<Next> {
        let Self {
            tty,
            endpoint,
            snapshot,
            output,
            output_stall_deadline,
            output_closed,
            state,
        } = self;
        CoordinatorTerminal {
            tty,
            endpoint,
            snapshot,
            output,
            output_stall_deadline,
            output_closed,
            state: transition(state),
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the helper makes clock, read, and write observations independently testable"
)]
fn pump_output_state_once(
    output: &mut PendingTerminalOutput,
    stall_deadline: &mut Option<Instant>,
    output_closed: &mut bool,
    stall_timeout: Duration,
    outer_deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut read: impl FnMut(
        &mut PendingTerminalOutput,
    ) -> Result<PendingTerminalRead, CoordinatorTerminalError>,
    mut write: impl FnMut(&mut PendingTerminalOutput) -> Result<TerminalWrite, CoordinatorTerminalError>,
) -> Result<CoordinatorPumpProgress, CoordinatorTerminalError> {
    let observed = now();
    if output.is_pending() {
        let deadline = (*stall_deadline).ok_or(CoordinatorTerminalError::Deadline)?;
        if observed >= deadline || observed >= outer_deadline {
            return Err(CoordinatorTerminalError::Deadline);
        }
    } else {
        if observed >= outer_deadline {
            return Err(CoordinatorTerminalError::Deadline);
        }
        if *output_closed {
            return Ok(CoordinatorPumpProgress::OutputClosed);
        }
        match read(output)? {
            PendingTerminalRead::Data => {
                let observed = now();
                let local_deadline = observed
                    .checked_add(stall_timeout)
                    .ok_or(CoordinatorTerminalError::Deadline)?;
                let fixed_deadline = local_deadline.min(outer_deadline);
                *stall_deadline = Some(fixed_deadline);
                if observed >= fixed_deadline {
                    return Err(CoordinatorTerminalError::Deadline);
                }
            }
            PendingTerminalRead::WouldBlock => return Ok(CoordinatorPumpProgress::Idle),
            PendingTerminalRead::EndOfStream => {
                *output_closed = true;
                return Ok(CoordinatorPumpProgress::OutputClosed);
            }
        }
    }

    let deadline = (*stall_deadline).ok_or(CoordinatorTerminalError::Deadline)?;
    let observed = now();
    if observed >= deadline || observed >= outer_deadline {
        return Err(CoordinatorTerminalError::Deadline);
    }
    match write(output)? {
        TerminalWrite::Complete => {
            *stall_deadline = None;
            Ok(CoordinatorPumpProgress::Output)
        }
        TerminalWrite::Progress { .. } => {
            let observed = now();
            let local_deadline = observed
                .checked_add(stall_timeout)
                .ok_or(CoordinatorTerminalError::Deadline)?;
            let renewed_deadline = local_deadline.min(outer_deadline);
            *stall_deadline = Some(renewed_deadline);
            if observed >= renewed_deadline {
                Err(CoordinatorTerminalError::Deadline)
            } else {
                Ok(CoordinatorPumpProgress::OutputPending)
            }
        }
        TerminalWrite::WouldBlock => Ok(CoordinatorPumpProgress::OutputPending),
    }
}

fn terminal_failure<Owner>(
    owner: Owner,
    error: CoordinatorTerminalError,
) -> Box<CoordinatorTerminalFailure<Owner>> {
    Box::new(CoordinatorTerminalFailure { owner, error })
}

fn write_fragment_before(
    deadline: Instant,
    chunk: &mut TerminalChunk<'_>,
    mut write: impl FnMut(&mut TerminalChunk<'_>) -> Result<TerminalWrite, CoordinatorTerminalError>,
) -> Result<(), CoordinatorTerminalError> {
    while chunk.remaining() != 0 {
        if Instant::now() >= deadline {
            return Err(CoordinatorTerminalError::Deadline);
        }
        match write(chunk)? {
            TerminalWrite::Complete => return Ok(()),
            TerminalWrite::Progress { .. } => {}
            TerminalWrite::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(CoordinatorTerminalError::Deadline);
                }
                thread::sleep(PUMP_RETRY.min(remaining));
            }
        }
    }
    Ok(())
}

impl<State> fmt::Debug for CoordinatorTerminal<State> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.tty,
            &self.endpoint,
            &self.snapshot,
            &self.output,
            self.output_stall_deadline,
            self.output_closed,
            &self.state,
        );
        formatter.write_str("CoordinatorTerminal(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;
    use std::io::{BufRead, BufReader, Cursor};
    use std::process::{Command, Stdio};
    use std::sync::mpsc::{self, Receiver};

    use super::super::protocol::{
        ChildRole, CoordinatorCommand, CoordinatorReceiver, GuardianEvent, ProtocolError,
        send_guardian_event,
    };
    use super::super::terminal::{
        PtyMaster, PtyOwner, TerminalChannelPair, TerminalSize,
        claim_controlling_terminal_from_stdin,
    };

    const CHILD_HELPER_ENV: &str = "CALCIFER_COORDINATOR_TERMINAL_CHILD_HELPER";
    const OUTPUT_SENTINEL: &[u8] = b"calcifer-coordinator-output-only";
    const PRE_READY_SENTINEL: &[u8] = b"calcifer-coordinator-pre-ready";
    const POST_READY_SENTINEL: &[u8] = b"calcifer-coordinator-post-ready";
    const FINAL_OUTPUT_SENTINEL: &[u8] = b"calcifer-coordinator-final-output";
    const TEST_TIMEOUT: Duration = Duration::from_secs(3);
    type TestCoordinatorReceiver = CoordinatorReceiver<Cursor<Vec<u8>>>;

    #[test]
    fn pending_output_deadline_is_capped_once_and_expiry_performs_no_io()
    -> Result<(), Box<dyn Error>> {
        let base = Instant::now();
        let outer_deadline = base + Duration::from_millis(30);
        let mut observations = [
            base,
            base,
            base,
            base + Duration::from_millis(10),
            base + Duration::from_millis(10),
            outer_deadline,
        ]
        .into_iter();
        let mut output = PendingTerminalOutput::new();
        let mut stall_deadline = None;
        let mut output_closed = false;
        let mut reads = 0_usize;
        let mut writes = 0_usize;

        let progress = pump_output_state_once(
            &mut output,
            &mut stall_deadline,
            &mut output_closed,
            Duration::from_secs(1),
            outer_deadline,
            || {
                observations
                    .next()
                    .unwrap_or_else(|| panic!("missing test clock observation"))
            },
            |output| {
                reads += 1;
                output
                    .load_for_test(b"fixed-pending-sentinel")
                    .map_err(|_| CoordinatorTerminalError::TerminalChannelRead)?;
                Ok(PendingTerminalRead::Data)
            },
            |_| {
                writes += 1;
                Ok(TerminalWrite::WouldBlock)
            },
        )?;
        assert_eq!(progress, CoordinatorPumpProgress::OutputPending);
        assert_eq!(stall_deadline, Some(outer_deadline));

        let progress = pump_output_state_once(
            &mut output,
            &mut stall_deadline,
            &mut output_closed,
            Duration::from_secs(2),
            outer_deadline,
            || {
                observations
                    .next()
                    .unwrap_or_else(|| panic!("missing test clock observation"))
            },
            |_| {
                reads += 1;
                Ok(PendingTerminalRead::WouldBlock)
            },
            |_| {
                writes += 1;
                Ok(TerminalWrite::WouldBlock)
            },
        )?;
        assert_eq!(progress, CoordinatorPumpProgress::OutputPending);
        assert_eq!(stall_deadline, Some(outer_deadline));
        assert_eq!((reads, writes), (1, 2));

        assert_eq!(
            pump_output_state_once(
                &mut output,
                &mut stall_deadline,
                &mut output_closed,
                Duration::from_secs(2),
                outer_deadline,
                || {
                    observations
                        .next()
                        .unwrap_or_else(|| panic!("missing test clock observation"))
                },
                |_| {
                    reads += 1;
                    Ok(PendingTerminalRead::WouldBlock)
                },
                |_| {
                    writes += 1;
                    Ok(TerminalWrite::WouldBlock)
                },
            ),
            Err(CoordinatorTerminalError::Deadline)
        );
        assert_eq!((reads, writes), (1, 2));
        assert_eq!(output.remaining_bytes_for_test(), b"fixed-pending-sentinel");
        Ok(())
    }

    #[test]
    fn partial_output_progress_renews_only_the_inactivity_window() -> Result<(), Box<dyn Error>> {
        let base = Instant::now();
        let stall_timeout = Duration::from_millis(20);
        let outer_deadline = base + Duration::from_millis(100);
        let mut output = PendingTerminalOutput::new();
        let mut stall_deadline = None;
        let mut output_closed = false;
        let mut writes = 0_usize;

        let mut initial_clock = [base, base, base].into_iter();
        assert_eq!(
            pump_output_state_once(
                &mut output,
                &mut stall_deadline,
                &mut output_closed,
                stall_timeout,
                outer_deadline,
                || match initial_clock.next() {
                    Some(observed) => observed,
                    None => panic!("missing initial clock observation"),
                },
                |output| {
                    output
                        .load_for_test(b"progress-renewal-sentinel")
                        .map_err(|_| CoordinatorTerminalError::TerminalChannelRead)?;
                    Ok(PendingTerminalRead::Data)
                },
                |_| {
                    writes += 1;
                    Ok(TerminalWrite::WouldBlock)
                },
            )?,
            CoordinatorPumpProgress::OutputPending
        );
        assert_eq!(stall_deadline, Some(base + stall_timeout));

        let progress_at = base + Duration::from_millis(15);
        let observed_after_progress = base + Duration::from_millis(16);
        let mut progress_clock = [progress_at, progress_at, observed_after_progress].into_iter();
        assert_eq!(
            pump_output_state_once(
                &mut output,
                &mut stall_deadline,
                &mut output_closed,
                stall_timeout,
                outer_deadline,
                || match progress_clock.next() {
                    Some(observed) => observed,
                    None => panic!("missing progress clock observation"),
                },
                |_| panic!("pending output performed another read"),
                |_| {
                    writes += 1;
                    Ok(TerminalWrite::Progress {
                        written: 1,
                        remaining: 1,
                    })
                },
            )?,
            CoordinatorPumpProgress::OutputPending
        );
        let renewed_deadline = observed_after_progress + stall_timeout;
        assert_eq!(stall_deadline, Some(renewed_deadline));

        let would_block_at = base + Duration::from_millis(30);
        let mut blocked_clock = [would_block_at, would_block_at].into_iter();
        assert_eq!(
            pump_output_state_once(
                &mut output,
                &mut stall_deadline,
                &mut output_closed,
                stall_timeout,
                outer_deadline,
                || match blocked_clock.next() {
                    Some(observed) => observed,
                    None => panic!("missing blocked clock observation"),
                },
                |_| panic!("pending output performed another read"),
                |_| {
                    writes += 1;
                    Ok(TerminalWrite::WouldBlock)
                },
            )?,
            CoordinatorPumpProgress::OutputPending
        );
        assert_eq!(stall_deadline, Some(renewed_deadline));

        assert_eq!(
            pump_output_state_once(
                &mut output,
                &mut stall_deadline,
                &mut output_closed,
                stall_timeout,
                outer_deadline,
                || renewed_deadline,
                |_| panic!("expired pending output performed a read"),
                |_| {
                    writes += 1;
                    Ok(TerminalWrite::WouldBlock)
                },
            ),
            Err(CoordinatorTerminalError::Deadline)
        );
        assert_eq!(writes, 3);
        Ok(())
    }

    #[test]
    fn partial_output_progress_never_renews_past_the_outer_fence() -> Result<(), Box<dyn Error>> {
        let base = Instant::now();
        let outer_deadline = base + Duration::from_millis(100);
        let progress_at = base + Duration::from_millis(90);
        let observed_after_progress = base + Duration::from_millis(91);
        let mut observations = [progress_at, progress_at, observed_after_progress].into_iter();
        let mut output = PendingTerminalOutput::new();
        output.load_for_test(b"outer-fence-progress-sentinel")?;
        let mut stall_deadline = Some(base + Duration::from_millis(95));
        let mut output_closed = false;
        let mut writes = 0_usize;

        assert_eq!(
            pump_output_state_once(
                &mut output,
                &mut stall_deadline,
                &mut output_closed,
                Duration::from_millis(20),
                outer_deadline,
                || match observations.next() {
                    Some(observed) => observed,
                    None => panic!("missing capped clock observation"),
                },
                |_| panic!("pending output performed another read"),
                |_| {
                    writes += 1;
                    Ok(TerminalWrite::Progress {
                        written: 1,
                        remaining: 1,
                    })
                },
            )?,
            CoordinatorPumpProgress::OutputPending
        );
        assert_eq!(stall_deadline, Some(outer_deadline));

        assert_eq!(
            pump_output_state_once(
                &mut output,
                &mut stall_deadline,
                &mut output_closed,
                Duration::from_millis(20),
                outer_deadline,
                || outer_deadline,
                |_| panic!("expired pending output performed a read"),
                |_| {
                    writes += 1;
                    Ok(TerminalWrite::WouldBlock)
                },
            ),
            Err(CoordinatorTerminalError::Deadline)
        );
        assert_eq!(writes, 1);
        Ok(())
    }

    #[test]
    fn output_crossing_outer_fence_returns_the_exact_pending_shape_without_write()
    -> Result<(), Box<dyn Error>> {
        let before = Instant::now();
        let outer_deadline = before + Duration::from_millis(10);
        let after = outer_deadline + Duration::from_millis(1);
        let mut observations = [before, after].into_iter();
        let mut output = PendingTerminalOutput::new();
        let mut stall_deadline = None;
        let mut output_closed = false;
        let mut reads = 0_usize;
        let mut writes = 0_usize;

        assert_eq!(
            pump_output_state_once(
                &mut output,
                &mut stall_deadline,
                &mut output_closed,
                Duration::from_secs(1),
                outer_deadline,
                || {
                    observations
                        .next()
                        .unwrap_or_else(|| panic!("missing test clock observation"))
                },
                |output| {
                    reads += 1;
                    output
                        .load_for_test(b"crossed-fence-pending-frame")
                        .map_err(|_| CoordinatorTerminalError::TerminalChannelRead)?;
                    Ok(PendingTerminalRead::Data)
                },
                |_| {
                    writes += 1;
                    Ok(TerminalWrite::WouldBlock)
                },
            ),
            Err(CoordinatorTerminalError::Deadline)
        );
        assert_eq!((reads, writes), (1, 0));
        assert!(output.is_pending());

        output.scrub();
        stall_deadline = None;
        let mut empty_reads = 0_usize;
        let mut empty_writes = 0_usize;
        assert_eq!(
            pump_output_state_once(
                &mut output,
                &mut stall_deadline,
                &mut output_closed,
                Duration::from_secs(1),
                outer_deadline,
                || after,
                |_| {
                    empty_reads += 1;
                    Ok(PendingTerminalRead::WouldBlock)
                },
                |_| {
                    empty_writes += 1;
                    Ok(TerminalWrite::WouldBlock)
                },
            ),
            Err(CoordinatorTerminalError::Deadline)
        );
        assert_eq!((empty_reads, empty_writes), (0, 0));
        Ok(())
    }

    #[test]
    fn pending_output_scrub_removes_payload_without_waiting_for_drop() -> Result<(), Box<dyn Error>>
    {
        let mut output = PendingTerminalOutput::new();
        output.load_for_test(b"retained-private-terminal-sentinel")?;
        assert!(output.is_pending());
        output.scrub();
        assert!(output.is_zeroized_for_test());
        assert_eq!(output.retained_shape_for_test(), (0, 0, true));
        assert!(output.remaining_bytes_for_test().is_empty());
        Ok(())
    }

    #[test]
    fn coordinator_terminal_exposes_the_reviewed_linear_states() {
        fn assert_type<T>() {}

        assert_type::<CoordinatorTerminal<OutputOnly>>();
        assert_type::<CoordinatorTerminal<GateReady>>();
        assert_type::<CoordinatorTerminal<RawAwaitAck>>();
        assert_type::<CoordinatorTerminal<Active>>();
        assert_type::<CoordinatorTerminal<Paused>>();
        assert_type::<CoordinatorTerminal<SuspendedRestored>>();
        assert_type::<CoordinatorTerminal<ResumeRaw>>();
        assert_type::<CoordinatorTerminal<Quiesced>>();
        assert_type::<CoordinatorTerminal<Restored>>();
    }

    #[test]
    fn setup_failure_returns_the_exact_terminal_endpoint() -> Result<(), Box<dyn Error>> {
        let (coordinator, guardian) = TerminalChannelPair::new()?.split();
        let not_a_tty = std::fs::File::open("/dev/null")?;
        let failure = match CoordinatorTerminal::capture(not_a_tty, coordinator) {
            Err(failure) => failure,
            Ok(_) => return Err("a non-terminal outer descriptor was accepted".into()),
        };
        assert_eq!(failure.error(), CoordinatorTerminalError::Setup);
        assert_eq!(
            format!("{failure:?}"),
            "CoordinatorTerminalSetupFailure { error: Setup, retains_endpoint: true }"
        );
        let endpoint = failure.into_endpoint();
        endpoint.enable_nonblocking()?;
        guardian.enable_nonblocking()?;
        write_to_endpoint(&guardian, OUTPUT_SENTINEL, Instant::now() + TEST_TIMEOUT)?;
        let mut recovered = TerminalBuffer::new();
        assert!(matches!(
            endpoint.read_into(&mut recovered)?,
            TerminalRead::Data(chunk) if chunk.matches(OUTPUT_SENTINEL)
        ));
        Ok(())
    }

    #[test]
    fn output_only_flow_pre_ready_flush_ack_and_restore_use_one_linear_owner()
    -> Result<(), Box<dyn Error>> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "providers::codex::supervisor::coordinator_terminal::tests::coordinator_terminal_child_helper",
                "--nocapture",
            ])
            .env(CHILD_HELPER_ENV, "1");
        let owner = PtyOwner::open(TerminalSize::new(31, 101))?;
        let master = owner.configure_child(&mut command)?;
        // A separate bounded control stream keeps assertions out of the
        // terminal data path under test. stdin/stdout remain the same PTY.
        command.stderr(Stdio::piped());
        let mut child = command.spawn()?;
        // A reusable `Command` retains its configured PTY slave handles.
        // Release that parent-side owner so Linux can observe master EOF once
        // the exact helper exits.
        drop(command);
        let stderr = child.stderr.take().ok_or("missing helper stderr")?;
        let mut child = BoundedTestChild::new(child);
        let (line_sender, line_receiver) = mpsc::channel();
        let (reader_done_sender, reader_done_receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if line_sender.send(line).is_err() {
                    break;
                }
            }
            let _ = reader_done_sender.send(());
        });
        master.enable_nonblocking()?;

        expect_line(&line_receiver, "output-pumped")?;
        wait_for_master_marker(&master, OUTPUT_SENTINEL, Instant::now() + TEST_TIMEOUT)?;

        expect_line(&line_receiver, "pre-ready")?;
        write_to_master(&master, PRE_READY_SENTINEL, Instant::now() + TEST_TIMEOUT)?;

        expect_line(&line_receiver, "post-ready")?;
        write_to_master(&master, POST_READY_SENTINEL, Instant::now() + TEST_TIMEOUT)?;
        expect_line(&line_receiver, "restored")?;

        // Keep draining the fixed PTY buffer through exact child wait. macOS
        // can hold a session leader in exit while final harness output remains
        // queued on its controlling slave.
        let (drain_sender, drain_receiver) = mpsc::channel();
        let drainer = std::thread::spawn(move || {
            let result = drain_master_until_close(master, Instant::now() + TEST_TIMEOUT);
            let _ = drain_sender.send(result);
        });
        let status = child.wait_before(Instant::now() + TEST_TIMEOUT)?;
        assert!(
            status.success(),
            "coordinator terminal helper exited as {status}"
        );
        drain_receiver
            .recv_timeout(TEST_TIMEOUT)
            .map_err(|_| "outer PTY drainer timed out")??;
        drainer.join().map_err(|_| "outer PTY drainer panicked")?;
        reader_done_receiver
            .recv_timeout(TEST_TIMEOUT)
            .map_err(|_| "stderr reader did not observe EOF")?;
        reader.join().map_err(|_| "stderr reader panicked")?;
        Ok(())
    }

    #[test]
    fn coordinator_terminal_child_helper() {
        if std::env::var_os(CHILD_HELPER_ENV).is_none() {
            return;
        }
        if let Err(error) = run_child_helper() {
            eprintln!("helper-error:{error}");
            std::process::exit(91);
        }
    }

    fn run_child_helper() -> Result<(), Box<dyn Error>> {
        claim_controlling_terminal_from_stdin().map_err(|_| "claim controlling terminal")?;
        let (coordinator, guardian) = TerminalChannelPair::new()
            .map_err(|_| "create terminal channel")?
            .split();
        guardian
            .enable_nonblocking()
            .map_err(|_| "configure guardian terminal channel")?;
        let owner = CoordinatorTerminal::capture(std::io::stdin(), coordinator)
            .map_err(|_| "capture coordinator terminal")?;

        // An expired turn fails without losing the exact OutputOnly owner.
        let failure = match owner.pump_output_once(TEST_TIMEOUT, Instant::now()) {
            Err(failure) => failure,
            Ok(_) => return Err("expired output turn unexpectedly succeeded".into()),
        };
        assert_eq!(failure.error(), CoordinatorTerminalError::Deadline);
        let owner = failure.into_owner();
        assert_eq!(format!("{owner:?}"), "CoordinatorTerminal(<redacted>)");

        write_to_endpoint(&guardian, OUTPUT_SENTINEL, Instant::now() + TEST_TIMEOUT)
            .map_err(|_| "write initial terminal output")?;
        let turn = owner
            .pump_output_once(TEST_TIMEOUT, Instant::now() + TEST_TIMEOUT)
            .map_err(|_| "pump initial terminal output")?;
        assert_eq!(turn.progress(), CoordinatorPumpProgress::Output);
        let owner = turn.into_owner();
        eprintln!("output-pumped");

        let (readiness, mut transcript) = ready_transcript(owner.snapshot_fingerprint())?;
        eprintln!("pre-ready");
        // The parent completed its PTY-master write before this delay ends, so
        // tcflush below observes and discards the queued canonical sentinel.
        std::thread::sleep(Duration::from_millis(100));
        let ready = owner.mark_ready(readiness);
        let raw = ready.enter_raw().map_err(|failure| {
            let error = failure.error();
            drop(failure.into_owner());
            error
        })?;

        // READY and raw mode alone still cannot have forwarded a byte.
        let mut absent = TerminalBuffer::new();
        assert!(matches!(
            guardian.read_into(&mut absent)?,
            TerminalRead::WouldBlock
        ));

        transcript.record_command(CoordinatorCommand::OpenInputGate)?;
        assert_eq!(
            transcript.receive(Instant::now() + TEST_TIMEOUT)?,
            GuardianEvent::InputGateOpened
        );
        let acknowledgement = transcript.take_verified_open_gate_ack()?;
        assert!(matches!(
            transcript.take_verified_open_gate_ack(),
            Err(ProtocolError::UnexpectedState)
        ));
        let active = raw.open_after_ack(acknowledgement);

        // The first legal outer read happens only now, after the flush. It
        // must not replay the pre-ready sentinel.
        let turn = active
            .pump_input_once(Instant::now() + TEST_TIMEOUT)
            .map_err(|_| "pre-input pump")?;
        assert_eq!(turn.progress(), CoordinatorPumpProgress::Idle);
        let mut active = turn.into_owner();
        eprintln!("post-ready");

        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            let turn = active
                .pump_input_once(deadline)
                .map_err(|_| "active input pump")?;
            let progress = turn.progress();
            active = turn.into_owner();
            if progress == CoordinatorPumpProgress::Input {
                break;
            }
            if Instant::now() >= deadline {
                return Err("post-ready input did not reach the coordinator pump".into());
            }
            std::thread::sleep(PUMP_RETRY);
        }
        let mut received = TerminalBuffer::new();
        assert!(matches!(
            guardian.read_into(&mut received)?,
            TerminalRead::Data(chunk) if chunk.matches(POST_READY_SENTINEL)
        ));

        // A suspend cycle destroys the first input buffer, restores the shell
        // tty, and can reopen input only from Resumed plus a fresh gate ACK.
        let paused = active.pause_for_suspend();
        transcript.record_command(CoordinatorCommand::Suspend)?;
        assert_eq!(
            transcript.receive(Instant::now() + TEST_TIMEOUT)?,
            GuardianEvent::Suspended
        );
        let suspended = paused.restore_for_suspend().map_err(|failure| {
            drop(failure.into_owner());
            "suspend restore"
        })?;
        let size = suspended.current_size().map_err(|_| "suspend size")?;
        let resume_raw = suspended.enter_raw_after_continue().map_err(|failure| {
            drop(failure.into_owner());
            "resume raw"
        })?;
        let resume = CoordinatorCommand::Resume {
            rows: size.rows(),
            cols: size.columns(),
        };
        transcript.record_command(resume)?;
        assert_eq!(
            transcript.receive(Instant::now() + TEST_TIMEOUT)?,
            GuardianEvent::Resumed {
                rows: size.rows(),
                cols: size.columns(),
            }
        );
        let resumed_readiness = transcript.take_verified_ready()?;
        let resume_await_ack = resume_raw.mark_resumed(resumed_readiness);
        transcript.record_command(CoordinatorCommand::OpenInputGate)?;
        assert_eq!(
            transcript.receive(Instant::now() + TEST_TIMEOUT)?,
            GuardianEvent::InputGateOpened
        );
        let resumed_ack = transcript.take_verified_open_gate_ack()?;
        let resumed_active = resume_await_ack.open_after_ack(resumed_ack);

        // Guardian shutdown may publish final output, close the terminal byte
        // channel, and only then publish lifecycle TerminalQuiesced. Preserve
        // all three observations in order without treating byte EOF as the
        // quiescence authority.
        write_to_endpoint(
            &guardian,
            FINAL_OUTPUT_SENTINEL,
            Instant::now() + TEST_TIMEOUT,
        )
        .map_err(|_| "write final output")?;
        guardian
            .shutdown(TerminalShutdown::Write)
            .map_err(|_| "shutdown final output")?;
        let final_output = resumed_active
            .pump_output_once(TEST_TIMEOUT, Instant::now() + TEST_TIMEOUT)
            .map_err(|_| "pump final output")?;
        assert_eq!(final_output.progress(), CoordinatorPumpProgress::Output);
        let output_closed = final_output
            .into_owner()
            .pump_output_once(TEST_TIMEOUT, Instant::now() + TEST_TIMEOUT)
            .map_err(|_| "observe final output eof")?;
        assert_eq!(
            output_closed.progress(),
            CoordinatorPumpProgress::OutputClosed
        );
        transcript.record_command(CoordinatorCommand::Stop)?;
        assert_eq!(
            transcript.receive(Instant::now() + TEST_TIMEOUT)?,
            GuardianEvent::TerminalQuiesced
        );
        let resumed_active = output_closed.into_owner();

        let restored = resumed_active.quiesce().restore().map_err(|failure| {
            drop(failure.into_owner());
            "final restore"
        })?;
        let proof = restored.finish().map_err(|failure| {
            drop(failure.into_owner());
            "final restore proof"
        })?;
        assert_eq!(format!("{proof:?}"), "RestoredTerminalProof(<redacted>)");

        // Channel EOF is a typed, sticky output observation. It never proves
        // lifecycle quiescence, but it also cannot race a valid subsequent
        // TerminalQuiesced frame into a false infrastructure failure.
        let (coordinator, disconnected_guardian) = TerminalChannelPair::new()
            .map_err(|_| "create disconnected channel")?
            .split();
        let disconnected = CoordinatorTerminal::capture(std::io::stdin(), coordinator)
            .map_err(|_| "capture disconnected coordinator")?;
        drop(disconnected_guardian);
        let closed = disconnected
            .pump_output_once(TEST_TIMEOUT, Instant::now() + TEST_TIMEOUT)
            .map_err(|_| "observe disconnected eof")?;
        assert_eq!(closed.progress(), CoordinatorPumpProgress::OutputClosed);
        let closed = closed
            .into_owner()
            .pump_output_once(TEST_TIMEOUT, Instant::now() + TEST_TIMEOUT)
            .map_err(|_| "observe sticky disconnected eof")?;
        assert_eq!(closed.progress(), CoordinatorPumpProgress::OutputClosed);
        let disconnected = closed.into_owner();
        // Lifecycle authority remains separate; this owner still requires
        // quiescence/restoration or fail-closed retention.
        drop(disconnected);
        eprintln!("restored");
        Ok(())
    }

    fn ready_transcript(
        snapshot: TerminalSnapshotFingerprint,
    ) -> Result<(VerifiedReady, TestCoordinatorReceiver), Box<dyn Error>> {
        let mut wire = Vec::new();
        let process = rustix::process::getpid().as_raw_pid();
        let tui_process = process.checked_add(1).ok_or("test PID overflow")?;
        for event in [
            GuardianEvent::LeaseCommitted,
            GuardianEvent::TerminalArmed { snapshot },
            GuardianEvent::ChildStarted {
                role: ChildRole::AppServer,
                pid: process,
                pgid: process,
            },
            GuardianEvent::ChildStarted {
                role: ChildRole::Tui,
                pid: tui_process,
                pgid: tui_process,
            },
            GuardianEvent::Ready,
            GuardianEvent::InputGateOpened,
            GuardianEvent::Suspended,
            GuardianEvent::Resumed {
                rows: 31,
                cols: 101,
            },
            GuardianEvent::InputGateOpened,
            GuardianEvent::TerminalQuiesced,
        ] {
            send_guardian_event(&mut wire, event, Instant::now() + TEST_TIMEOUT)?;
        }
        let mut receiver = CoordinatorReceiver::new_terminal(Cursor::new(wire));
        assert_eq!(
            receiver.receive(Instant::now() + TEST_TIMEOUT)?,
            GuardianEvent::LeaseCommitted
        );
        receiver.record_command(CoordinatorCommand::Start)?;
        assert_eq!(
            receiver.receive(Instant::now() + TEST_TIMEOUT)?,
            GuardianEvent::TerminalArmed { snapshot }
        );
        receiver.record_command(CoordinatorCommand::TerminalArmAccepted)?;
        for expected in [
            GuardianEvent::ChildStarted {
                role: ChildRole::AppServer,
                pid: process,
                pgid: process,
            },
            GuardianEvent::ChildStarted {
                role: ChildRole::Tui,
                pid: tui_process,
                pgid: tui_process,
            },
            GuardianEvent::Ready,
        ] {
            assert_eq!(receiver.receive(Instant::now() + TEST_TIMEOUT)?, expected);
        }
        let readiness = receiver.take_verified_ready()?;
        Ok((readiness, receiver))
    }

    fn write_to_endpoint(
        endpoint: &TerminalEndpoint,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), Box<dyn Error>> {
        let mut buffer = TerminalBuffer::new();
        let mut chunk = buffer.load(bytes)?;
        while chunk.remaining() != 0 {
            if Instant::now() >= deadline {
                return Err("terminal endpoint write timed out".into());
            }
            match endpoint.try_write(&mut chunk)? {
                TerminalWrite::Complete => return Ok(()),
                TerminalWrite::Progress { .. } => {}
                TerminalWrite::WouldBlock => std::thread::sleep(PUMP_RETRY),
            }
        }
        Ok(())
    }

    fn write_to_master(
        master: &PtyMaster,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), Box<dyn Error>> {
        let mut buffer = TerminalBuffer::new();
        let mut chunk = buffer.load(bytes)?;
        while chunk.remaining() != 0 {
            if Instant::now() >= deadline {
                return Err("outer PTY write timed out".into());
            }
            match master.try_write(&mut chunk)? {
                TerminalWrite::Complete => return Ok(()),
                TerminalWrite::Progress { .. } => {}
                TerminalWrite::WouldBlock => std::thread::sleep(PUMP_RETRY),
            }
        }
        Ok(())
    }

    fn wait_for_master_marker(
        master: &PtyMaster,
        marker: &[u8],
        deadline: Instant,
    ) -> Result<(), Box<dyn Error>> {
        let mut matched = 0;
        let mut buffer = [0_u8; 512];
        loop {
            if Instant::now() >= deadline {
                return Err("outer PTY marker timed out".into());
            }
            match rustix::io::read(master, &mut buffer) {
                Ok(0) => return Err("outer PTY reached EOF before marker".into()),
                Ok(length) => {
                    for byte in &buffer[..length] {
                        if *byte == marker[matched] {
                            matched += 1;
                            if matched == marker.len() {
                                return Ok(());
                            }
                        } else {
                            matched = usize::from(*byte == marker[0]);
                        }
                    }
                }
                Err(rustix::io::Errno::AGAIN) => std::thread::sleep(PUMP_RETRY),
                Err(_) => return Err("outer PTY read failed".into()),
            }
        }
    }

    fn drain_master_until_close(master: PtyMaster, deadline: Instant) -> Result<(), &'static str> {
        let mut buffer = [0_u8; 512];
        loop {
            if Instant::now() >= deadline {
                return Err("outer PTY remained open after helper exit");
            }
            match rustix::io::read(&master, &mut buffer) {
                Ok(0) | Err(rustix::io::Errno::IO) => return Ok(()),
                Ok(_) => {}
                Err(rustix::io::Errno::AGAIN) => std::thread::sleep(PUMP_RETRY),
                Err(_) => return Err("outer PTY drain failed"),
            }
        }
    }

    struct BoundedTestChild {
        child: Option<std::process::Child>,
    }

    impl BoundedTestChild {
        fn new(child: std::process::Child) -> Self {
            Self { child: Some(child) }
        }

        fn wait_before(
            &mut self,
            deadline: Instant,
        ) -> Result<std::process::ExitStatus, Box<dyn Error>> {
            let child = self
                .child
                .as_mut()
                .ok_or("helper child was already reaped")?;
            loop {
                if let Some(status) = child.try_wait()? {
                    self.child = None;
                    return Ok(status);
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    self.child = None;
                    return Err("helper child exceeded its deadline".into());
                }
                std::thread::sleep(PUMP_RETRY);
            }
        }
    }

    impl Drop for BoundedTestChild {
        fn drop(&mut self) {
            if let Some(child) = self.child.as_mut() {
                let _ = child.kill();
            }
        }
    }

    fn expect_line(
        receiver: &Receiver<Result<String, std::io::Error>>,
        expected: &str,
    ) -> Result<(), Box<dyn Error>> {
        let line = receiver
            .recv_timeout(TEST_TIMEOUT)
            .map_err(|_| "helper control line timed out")??;
        if line == expected {
            Ok(())
        } else {
            Err(format!("expected helper control line {expected:?}, received {line:?}").into())
        }
    }
}
