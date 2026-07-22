//! Fixed-memory signal latches for the production terminal coordinator.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::protocol::UnixSignal;

/// One bounded action selected by the coordinator's normal-thread loop.
///
/// Signal handlers never construct this value. They only set one atomic bit;
/// ordering and lifecycle policy remain synchronous and reviewable here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorSignalAction {
    Forward(UnixSignal),
    Resize,
    Suspend,
    Continue,
}

/// Fixed, redacted installation failure. Partial registration is cleaned by
/// the already-constructed latch owners before this error is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CoordinatorSignalInstallError;

impl fmt::Display for CoordinatorSignalInstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the coordinator signal boundary could not be installed")
    }
}

impl std::error::Error for CoordinatorSignalInstallError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CoordinatorProcessStopError;

impl fmt::Display for CoordinatorProcessStopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the coordinator process stop boundary failed")
    }
}

impl std::error::Error for CoordinatorProcessStopError {}

struct SignalLatch {
    pending: Arc<AtomicBool>,
    registration: Option<signal_hook::SigId>,
}

impl SignalLatch {
    fn register(signal: i32) -> Result<Self, CoordinatorSignalInstallError> {
        let pending = Arc::new(AtomicBool::new(false));
        let registration = signal_hook::flag::register(signal, Arc::clone(&pending))
            .map_err(|_| CoordinatorSignalInstallError)?;
        Ok(Self {
            pending,
            registration: Some(registration),
        })
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            pending: Arc::new(AtomicBool::new(false)),
            registration: None,
        }
    }

    fn take(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }

    fn clear(&self) {
        self.pending.store(false, Ordering::Release);
    }

    #[cfg(test)]
    fn raise_for_test(&self) {
        self.pending.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn is_pending_for_test(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }
}

impl Drop for SignalLatch {
    fn drop(&mut self) {
        if let Some(registration) = self.registration.take() {
            let _ = signal_hook::low_level::unregister(registration);
        }
    }
}

/// Seven coalescing signal bits owned for one coordinator generation.
///
/// No signal-sized queue exists. `WINCH` therefore means only "read the latest
/// validated terminal size", and repeated termination/interactive signals
/// collapse to one pending action per class.
#[must_use = "installed signal handlers must remain owned for the terminal generation"]
pub(super) struct CoordinatorSignalLatches {
    hup: SignalLatch,
    interrupt: SignalLatch,
    quit: SignalLatch,
    term: SignalLatch,
    winch: SignalLatch,
    tstp: SignalLatch,
    cont: SignalLatch,
    frozen: AtomicBool,
}

impl CoordinatorSignalLatches {
    pub(super) fn install() -> Result<Self, CoordinatorSignalInstallError> {
        use signal_hook::consts::signal::{
            SIGCONT, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP, SIGWINCH,
        };

        // Each successful local unregisters itself if a later registration
        // fails, so installation never leaks a partially owned handler set.
        let hup = SignalLatch::register(SIGHUP)?;
        let interrupt = SignalLatch::register(SIGINT)?;
        let quit = SignalLatch::register(SIGQUIT)?;
        let term = SignalLatch::register(SIGTERM)?;
        let winch = SignalLatch::register(SIGWINCH)?;
        let tstp = SignalLatch::register(SIGTSTP)?;
        let cont = SignalLatch::register(SIGCONT)?;
        Ok(Self {
            hup,
            interrupt,
            quit,
            term,
            winch,
            tstp,
            cont,
            frozen: AtomicBool::new(false),
        })
    }

    /// Returns one action using the reviewed active-session priority. A CONT
    /// delivered before the process is actually stopped is intentionally left
    /// pending and then discarded by [`Self::prepare_process_stop`].
    pub(super) fn next_active(&self) -> Option<CoordinatorSignalAction> {
        if self.frozen.load(Ordering::Acquire) {
            return None;
        }
        if self.hup.take() {
            Some(CoordinatorSignalAction::Forward(UnixSignal::Hup))
        } else if self.term.take() {
            Some(CoordinatorSignalAction::Forward(UnixSignal::Term))
        } else if self.tstp.take() {
            Some(CoordinatorSignalAction::Suspend)
        } else if self.interrupt.take() {
            Some(CoordinatorSignalAction::Forward(UnixSignal::Int))
        } else if self.quit.take() {
            Some(CoordinatorSignalAction::Forward(UnixSignal::Quit))
        } else if self.winch.take() {
            Some(CoordinatorSignalAction::Resize)
        } else {
            None
        }
    }

    /// Clears only a pre-existing CONT after the guardian has acknowledged
    /// suspension and the coordinator has restored the outer tty, immediately
    /// before the coordinator invokes the default `SIGTSTP` disposition. A
    /// later CONT is a fresh resume capability; one that raced the suspend
    /// handshake can never make the process bounce back up.
    pub(super) fn prepare_process_stop(&self) {
        self.cont.clear();
    }

    /// Consumes resize notifications that were accumulated while the
    /// coordinator was stopped immediately before the resume-size snapshot.
    /// The snapshot itself carries the latest dimensions in `Resume`, so
    /// replaying an older WINCH after that command would only apply the same
    /// size twice. Clearing before (never after) reading the tty preserves a
    /// resize that arrives on the other side of this boundary.
    pub(super) fn prepare_resume_size_snapshot(&self) {
        self.winch.clear();
    }

    /// Atomically binds stale-CONT clearing to one uncatchable self-stop.
    ///
    /// The user-visible `TSTP` latch cannot raise `SIGTSTP` directly because
    /// signal-hook owns that disposition. Production therefore translates the
    /// reviewed suspend handshake into `SIGSTOP`. This sacrifices custom
    /// `SIGTSTP` dispositions but guarantees that the coordinator actually
    /// stops. `SIGCONT` is masked on this thread before clearing the stale
    /// latch; a continuation resumes the stopped process even while masked,
    /// then becomes visible to the latch when the exact prior mask is restored.
    pub(super) fn stop_after_suspended_ack(&self) -> Result<(), CoordinatorProcessStopError> {
        self.stop_after_suspended_ack_with(|| {})
    }

    fn stop_after_suspended_ack_with(
        &self,
        after_clear: impl FnOnce(),
    ) -> Result<(), CoordinatorProcessStopError> {
        let continue_guard = calcifer_unix_child_fd::block_sigcont_for_current_thread()
            .map_err(|_| CoordinatorProcessStopError)?;
        self.prepare_process_stop();
        // Test injection runs under the same mask and may not create a thread
        // or process. Production passes the zero-sized no-op closure above.
        after_clear();
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::STOP)
            .map_err(|_| CoordinatorProcessStopError)?;
        // `kill(SIGSTOP)` returns only after a continuation. Restoring the
        // exact prior mask delivers the pending SIGCONT to the installed bit.
        drop(continue_guard);
        Ok(())
    }

    /// While suspended, resize and TSTP bits remain coalesced for the next
    /// active generation. Termination and interactive signals keep their
    /// normal priority ahead of the one fresh CONT capability.
    pub(super) fn next_suspended(&self) -> Option<CoordinatorSignalAction> {
        if self.frozen.load(Ordering::Acquire) {
            return None;
        }
        if self.hup.take() {
            Some(CoordinatorSignalAction::Forward(UnixSignal::Hup))
        } else if self.term.take() {
            Some(CoordinatorSignalAction::Forward(UnixSignal::Term))
        } else if self.interrupt.take() {
            Some(CoordinatorSignalAction::Forward(UnixSignal::Int))
        } else if self.quit.take() {
            Some(CoordinatorSignalAction::Forward(UnixSignal::Quit))
        } else if self.cont.take() {
            Some(CoordinatorSignalAction::Continue)
        } else {
            None
        }
    }

    /// Once infrastructure failure or shutdown begins, no pending foreground
    /// control may race terminal quiescence. Bits are retained as evidence and
    /// handlers stay installed until this owner is dropped.
    pub(super) fn freeze_for_shutdown(&self) {
        self.frozen.store(true, Ordering::Release);
    }

    /// Non-consuming observation used only by the closed-over real-exec
    /// fixture to prove that a termination signal is queued before it releases
    /// an already-exited coordinator to the anchor drive loop.
    pub(super) fn has_pending_forward_for_fixture(&self, signal: UnixSignal) -> bool {
        match signal {
            UnixSignal::Hup => self.hup.pending.load(Ordering::Acquire),
            UnixSignal::Int => self.interrupt.pending.load(Ordering::Acquire),
            UnixSignal::Quit => self.quit.pending.load(Ordering::Acquire),
            UnixSignal::Term => self.term.pending.load(Ordering::Acquire),
        }
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            hup: SignalLatch::for_test(),
            interrupt: SignalLatch::for_test(),
            quit: SignalLatch::for_test(),
            term: SignalLatch::for_test(),
            winch: SignalLatch::for_test(),
            tstp: SignalLatch::for_test(),
            cont: SignalLatch::for_test(),
            frozen: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    fn raise_for_test(&self, signal: TestSignal) {
        self.latch_for_test(signal).raise_for_test();
    }

    #[cfg(test)]
    fn has_pending_for_test(&self, signal: TestSignal) -> bool {
        self.latch_for_test(signal).is_pending_for_test()
    }

    #[cfg(test)]
    fn latch_for_test(&self, signal: TestSignal) -> &SignalLatch {
        match signal {
            TestSignal::Hup => &self.hup,
            TestSignal::Interrupt => &self.interrupt,
            TestSignal::Quit => &self.quit,
            TestSignal::Term => &self.term,
            TestSignal::Winch => &self.winch,
            TestSignal::Tstp => &self.tstp,
            TestSignal::Continue => &self.cont,
        }
    }
}

impl fmt::Debug for CoordinatorSignalLatches {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoordinatorSignalLatches(<redacted>)")
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestSignal {
    Hup,
    Interrupt,
    Quit,
    Term,
    Winch,
    Tstp,
    Continue,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_signal_priority_is_fixed_and_repeated_signals_coalesce() {
        let signals = CoordinatorSignalLatches::for_test();
        signals.raise_for_test(TestSignal::Winch);
        signals.raise_for_test(TestSignal::Quit);
        signals.raise_for_test(TestSignal::Interrupt);
        signals.raise_for_test(TestSignal::Interrupt);
        signals.raise_for_test(TestSignal::Tstp);
        signals.raise_for_test(TestSignal::Term);

        assert_eq!(
            signals.next_active(),
            Some(CoordinatorSignalAction::Forward(UnixSignal::Term))
        );
        assert_eq!(
            signals.next_active(),
            Some(CoordinatorSignalAction::Suspend)
        );
        assert_eq!(
            signals.next_active(),
            Some(CoordinatorSignalAction::Forward(UnixSignal::Int))
        );
        assert_eq!(
            signals.next_active(),
            Some(CoordinatorSignalAction::Forward(UnixSignal::Quit))
        );
        assert_eq!(signals.next_active(), Some(CoordinatorSignalAction::Resize));
        assert_eq!(signals.next_active(), None);
    }

    #[test]
    fn stale_continue_is_cleared_at_the_suspend_boundary() {
        let signals = CoordinatorSignalLatches::for_test();
        signals.raise_for_test(TestSignal::Continue);
        assert_eq!(signals.next_active(), None);

        signals.prepare_process_stop();
        assert_eq!(signals.next_suspended(), None);

        signals.raise_for_test(TestSignal::Continue);
        assert_eq!(
            signals.next_suspended(),
            Some(CoordinatorSignalAction::Continue)
        );
        assert_eq!(signals.next_suspended(), None);
    }

    #[test]
    fn resume_snapshot_consumes_only_the_stale_suspended_resize() {
        let signals = CoordinatorSignalLatches::for_test();
        signals.prepare_process_stop();
        signals.raise_for_test(TestSignal::Winch);
        signals.raise_for_test(TestSignal::Winch);
        assert_eq!(signals.next_suspended(), None);

        signals.raise_for_test(TestSignal::Continue);
        assert_eq!(
            signals.next_suspended(),
            Some(CoordinatorSignalAction::Continue)
        );
        signals.prepare_resume_size_snapshot();
        assert_eq!(signals.next_active(), None);

        // A resize delivered after the clear-before-read boundary is fresh and
        // must survive for the active loop even when the size snapshot also
        // observes the new value.
        signals.raise_for_test(TestSignal::Winch);
        assert_eq!(signals.next_active(), Some(CoordinatorSignalAction::Resize));
        assert_eq!(signals.next_active(), None);
    }

    #[test]
    fn shutdown_freeze_does_not_consume_latched_controls() {
        let signals = CoordinatorSignalLatches::for_test();
        signals.raise_for_test(TestSignal::Hup);
        signals.raise_for_test(TestSignal::Winch);

        signals.freeze_for_shutdown();
        assert_eq!(signals.next_active(), None);
        assert_eq!(signals.next_suspended(), None);
        assert!(signals.has_pending_for_test(TestSignal::Hup));
        assert!(signals.has_pending_for_test(TestSignal::Winch));
    }
}
