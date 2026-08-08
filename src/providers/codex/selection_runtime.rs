//! Codex candidate reservation and usage revalidation for guarded selection.

#![allow(dead_code)] // Wired into the public supervisor by parent issue #4.

use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::profiles::{ProfileError, Registry, VerifiedTargetReservation};
use crate::provider_identity::IdentityError;
use crate::routing::selection::{
    HandoffSelection, ReservationResult, ReservedCandidate, SelectionRuntime,
};
use crate::usage_observations::{ObservationError, ObservationSource, ObservationStore, UsageView};

use super::{read_account_usage, verify_codex_identity_adapter};

const CANDIDATE_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The final transaction adapter deliberately receives the retained target
/// reservation. Implementations may prepare and drive the issue-#34 durable
/// handoff, but have no prompt or failed-turn payload to replay.
pub(crate) trait CodexSelectionHandoff {
    type Error;

    fn execute(
        &mut self,
        selection: HandoffSelection<VerifiedTargetReservation>,
    ) -> Result<u64, Self::Error>;
}

impl<Error, Execute> CodexSelectionHandoff for Execute
where
    Execute: FnMut(HandoffSelection<VerifiedTargetReservation>) -> Result<u64, Error>,
{
    type Error = Error;

    fn execute(
        &mut self,
        selection: HandoffSelection<VerifiedTargetReservation>,
    ) -> Result<u64, Self::Error> {
        self(selection)
    }
}

pub(crate) struct CodexSelectionRuntime<'runtime, Handoff> {
    registry: &'runtime Registry,
    observations: ObservationStore,
    executable: &'runtime Path,
    neutral_working_directory: &'runtime Path,
    handoff: Handoff,
}

impl<'runtime, Handoff> CodexSelectionRuntime<'runtime, Handoff> {
    pub(crate) fn new(
        registry: &'runtime Registry,
        executable: &'runtime Path,
        neutral_working_directory: &'runtime Path,
        handoff: Handoff,
    ) -> Self {
        Self {
            registry,
            observations: ObservationStore::from_profiles(registry),
            executable,
            neutral_working_directory,
            handoff,
        }
    }
}

impl<Handoff> SelectionRuntime for CodexSelectionRuntime<'_, Handoff>
where
    Handoff: CodexSelectionHandoff,
{
    type Reservation = VerifiedTargetReservation;
    type Error = CodexSelectionRuntimeError<Handoff::Error>;

    fn cached_usage(&mut self, profile_id: &str) -> Result<Option<UsageView>, Self::Error> {
        self.observations
            .view(profile_id, current_timestamp()?)
            .map_err(CodexSelectionRuntimeError::Observation)
    }

    fn reserve_and_revalidate(
        &mut self,
        profile_id: &str,
    ) -> Result<ReservationResult<Self::Reservation>, Self::Error> {
        let profile = self
            .registry
            .find_by_id(crate::profiles::Provider::Codex, profile_id)
            .map_err(CodexSelectionRuntimeError::Profile)?;
        let reservation =
            match self
                .registry
                .reserve_verified_codex_target(&profile, |home, provider_lease| {
                    verify_codex_identity_adapter(
                        self.executable,
                        home,
                        self.neutral_working_directory,
                        CANDIDATE_PROBE_TIMEOUT,
                        provider_lease,
                    )
                    .map_err(|_| IdentityError::Unsupported.into())
                }) {
                Ok(reservation) => reservation,
                Err(ProfileError::Busy(_)) => return Ok(ReservationResult::Busy),
                Err(error) => return Err(CodexSelectionRuntimeError::Profile(error)),
            };
        let current_profile = reservation.profile().clone();
        let home = self
            .registry
            .profile_home(&current_profile)
            .map_err(CodexSelectionRuntimeError::Profile)?;
        let provider_lease = reservation
            .provider_lock_for_probe()
            .map_err(CodexSelectionRuntimeError::Profile)?;
        let observed_at = current_timestamp()?;

        match read_account_usage(
            self.executable,
            &home,
            self.neutral_working_directory,
            CANDIDATE_PROBE_TIMEOUT,
            provider_lease,
        ) {
            Ok(observation) => {
                let usage = self
                    .observations
                    .observe_usage(
                        &current_profile.id,
                        ObservationSource::IdleRead,
                        &observation.codex_version,
                        observation.usage,
                        observed_at,
                    )
                    .map_err(CodexSelectionRuntimeError::Observation)?;
                Ok(ReservationResult::ready(ReservedCandidate::new(
                    current_profile,
                    usage,
                    reservation,
                )))
            }
            Err(failure) => {
                self.observations
                    .observe_failure(
                        &current_profile.id,
                        ObservationSource::IdleRead,
                        failure.codex_version(),
                        failure.compatibility(),
                        failure.kind(),
                        observed_at,
                    )
                    .map_err(CodexSelectionRuntimeError::Observation)?;
                drop(reservation);
                Ok(ReservationResult::Unknown)
            }
        }
    }

    fn handoff(
        &mut self,
        selection: HandoffSelection<Self::Reservation>,
    ) -> Result<u64, Self::Error> {
        self.handoff
            .execute(selection)
            .map_err(CodexSelectionRuntimeError::Handoff)
    }
}

pub(crate) enum CodexSelectionRuntimeError<HandoffError> {
    Profile(ProfileError),
    Observation(ObservationError),
    Clock,
    Handoff(HandoffError),
}

impl<HandoffError> fmt::Debug for CodexSelectionRuntimeError<HandoffError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Profile(_) => "CodexSelectionRuntimeError::Profile",
            Self::Observation(_) => "CodexSelectionRuntimeError::Observation",
            Self::Clock => "CodexSelectionRuntimeError::Clock",
            Self::Handoff(_) => "CodexSelectionRuntimeError::Handoff",
        })
    }
}

impl<HandoffError> fmt::Display for CodexSelectionRuntimeError<HandoffError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Profile(_) => "the candidate profile could not be reserved or revalidated",
            Self::Observation(_) => "the usage observation cache could not be updated safely",
            Self::Clock => "the system clock cannot represent a provider observation time",
            Self::Handoff(_) => "the transactional conversation handoff failed",
        })
    }
}

impl<HandoffError: fmt::Debug> std::error::Error for CodexSelectionRuntimeError<HandoffError> {}

fn current_timestamp<HandoffError>() -> Result<i64, CodexSelectionRuntimeError<HandoffError>> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CodexSelectionRuntimeError::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| CodexSelectionRuntimeError::Clock)
}
