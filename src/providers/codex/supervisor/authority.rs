//! Fail-closed ownership for a coordinator lease after guardian loss.
//!
//! Once guardian cleanup can no longer be proved, returning an ordinary error
//! would drop profile lock A during unwinding. This capability deliberately
//! leaks that one coordinator lease until process exit. The operating system
//! remains the final recovery boundary and closes the descriptor on exit.

#![allow(dead_code)] // Wired to the default-off supervisor in issue #50.

use std::fmt;

use crate::profiles::CoordinatorProfileLease;

/// A bounded reason why coordinator authority became process-lifetime state.
///
/// The variants contain no path, profile, account, process, terminal, frame,
/// provider response, or operating-system error data.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RetentionReason {
    LifecycleLost,
    ProtocolInvalid,
    GuardianExited,
    ShutdownDeadline,
    ChildrenNotReaped,
    WorkerNotJoined,
    CleanupUnconfirmed,
    InvariantUnconfirmed,
}

impl RetentionReason {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::LifecycleLost => "lifecycle_lost",
            Self::ProtocolInvalid => "protocol_invalid",
            Self::GuardianExited => "guardian_exited",
            Self::ShutdownDeadline => "shutdown_deadline",
            Self::ChildrenNotReaped => "children_not_reaped",
            Self::WorkerNotJoined => "worker_not_joined",
            Self::CleanupUnconfirmed => "cleanup_unconfirmed",
            Self::InvariantUnconfirmed => "invariant_unconfirmed",
        }
    }

    /// Losing proof that outer-terminal ingress is quiescent invalidates any
    /// more specific retention classification. Terminal restoration is still
    /// attempted, but its result cannot recover the missing quiescence proof.
    pub(super) const fn after_unconfirmed_input_quiescence(self) -> Self {
        let _ = self;
        Self::InvariantUnconfirmed
    }
}

impl fmt::Debug for RetentionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RetentionReason")
            .field(&self.code())
            .finish()
    }
}

impl fmt::Display for RetentionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Coordinator lock A retained after guardian state becomes unprovable.
///
/// Construction is private to the supervisor. Its caller must pass the A-only
/// lease returned directly by `Registry::lock_profile_coordinator`; accepting
/// an arbitrary profile lease would make it possible to leak lock B as well.
#[must_use = "guardian loss must retain or explicitly park coordinator authority"]
pub(super) struct RetainedCoordinatorLease {
    lease: Option<CoordinatorProfileLease>,
    reason: RetentionReason,
}

impl RetainedCoordinatorLease {
    /// Converts the A-only coordinator lease into process-lifetime authority.
    ///
    /// Visibility is restricted to the supervisor module so public and command
    /// code cannot mint retained authority from an arbitrary profile lease.
    pub(super) fn new(coordinator_lease: CoordinatorProfileLease, reason: RetentionReason) -> Self {
        debug_assert!(coordinator_lease.lock_file().is_ok());
        Self {
            lease: Some(coordinator_lease),
            reason,
        }
    }

    pub(super) const fn reason(&self) -> RetentionReason {
        self.reason
    }

    /// Permanently parks this coordinator process while preserving lock A.
    pub(super) fn park(self) -> ! {
        // Forget before parking so an unexpected unwind outside `thread::park`
        // cannot run the ordinary `ProfileLease` destructor.
        std::mem::forget(self);
        loop {
            std::thread::park();
        }
    }

    /// Releases A only in an in-process fixture that can prove the contender
    /// remains blocked before this call. Production has no release seam.
    #[cfg(test)]
    pub(super) fn release_for_test(mut self) {
        drop(self.lease.take());
    }
}

impl fmt::Debug for RetainedCoordinatorLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.lease;
        formatter
            .debug_struct("RetainedCoordinatorLease")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl Drop for RetainedCoordinatorLease {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            std::mem::forget(lease);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_reasons_are_bounded_and_redacted() {
        let reasons = [
            RetentionReason::LifecycleLost,
            RetentionReason::ProtocolInvalid,
            RetentionReason::GuardianExited,
            RetentionReason::ShutdownDeadline,
            RetentionReason::ChildrenNotReaped,
            RetentionReason::WorkerNotJoined,
            RetentionReason::CleanupUnconfirmed,
            RetentionReason::InvariantUnconfirmed,
        ];

        for reason in reasons {
            let rendered = format!("{reason:?}");
            assert!(rendered.starts_with("RetentionReason(\""));
            assert!(!rendered.contains('/'));
            assert!(!rendered.contains('@'));
            assert!(!rendered.contains("codex"));
        }
    }

    #[test]
    fn unconfirmed_input_quiescence_overrides_every_prior_retention_reason() {
        let reasons = [
            RetentionReason::LifecycleLost,
            RetentionReason::ProtocolInvalid,
            RetentionReason::GuardianExited,
            RetentionReason::ShutdownDeadline,
            RetentionReason::ChildrenNotReaped,
            RetentionReason::WorkerNotJoined,
            RetentionReason::CleanupUnconfirmed,
            RetentionReason::InvariantUnconfirmed,
        ];

        for reason in reasons {
            assert_eq!(
                reason.after_unconfirmed_input_quiescence(),
                RetentionReason::InvariantUnconfirmed
            );
        }
    }
}
