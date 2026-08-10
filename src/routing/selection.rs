//! One-pass policy kernel for an explicitly enabled routing pool.
//!
//! Provider I/O stays behind `SelectionRuntime`. A runtime may return a
//! candidate only while retaining its exclusive profile reservation; the
//! reservation is then moved into the single handoff call so there is no gap
//! in which another selector can choose the same target.

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use crate::conversations::HandoffReason;
use crate::profiles::{Profile, Provider};
use crate::usage_observations::{Availability, Freshness, ObservationSource, UsageView};

use super::{DefinitionError, Definitions, EnabledPool, HandoffAuthorization};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SelectionReason {
    AuthoritativeExhaustion,
    RevalidatedUsageLimit,
}

impl SelectionReason {
    pub(crate) const fn handoff_reason(self) -> HandoffReason {
        match self {
            Self::AuthoritativeExhaustion | Self::RevalidatedUsageLimit => {
                HandoffReason::ConfirmedUsageExhaustion
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectionTrigger {
    source_profile_id: String,
    reason: SelectionReason,
    observed_at: i64,
}

impl SelectionTrigger {
    pub(crate) fn authoritative_exhaustion(
        source_profile_id: &str,
        view: &UsageView,
    ) -> Result<Self, TriggerError> {
        require_authoritative_exhaustion(view)?;
        Ok(Self {
            source_profile_id: source_profile_id.to_owned(),
            reason: SelectionReason::AuthoritativeExhaustion,
            observed_at: view.observed_at,
        })
    }

    pub(crate) fn revalidated_usage_limit(
        source_profile_id: &str,
        signal_observed_at: i64,
        revalidated: &UsageView,
    ) -> Result<Self, TriggerError> {
        require_authoritative_exhaustion(revalidated)?;
        if revalidated.observed_at < signal_observed_at {
            return Err(TriggerError::RevalidationPredatesSignal);
        }
        Ok(Self {
            source_profile_id: source_profile_id.to_owned(),
            reason: SelectionReason::RevalidatedUsageLimit,
            observed_at: revalidated.observed_at,
        })
    }

    pub(crate) const fn reason(&self) -> SelectionReason {
        self.reason
    }
}

fn require_authoritative_exhaustion(view: &UsageView) -> Result<(), TriggerError> {
    if view.availability != Availability::Exhausted
        || view.freshness != Freshness::Fresh
        || !authoritative_source(view.source)
    {
        return Err(TriggerError::NotAuthoritativeExhaustion);
    }
    Ok(())
}

const fn authoritative_source(source: ObservationSource) -> bool {
    matches!(
        source,
        ObservationSource::ActiveMonitor | ObservationSource::IdleRead
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TriggerError {
    NotAuthoritativeExhaustion,
    RevalidationPredatesSignal,
}

impl fmt::Display for TriggerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotAuthoritativeExhaustion => {
                "selection requires fresh authoritative recognized exhaustion"
            }
            Self::RevalidationPredatesSignal => {
                "usage-limit revalidation must be observed at or after the signal"
            }
        })
    }
}

impl std::error::Error for TriggerError {}

pub(crate) struct ReservedCandidate<Reservation> {
    profile: Profile,
    usage: UsageView,
    reservation: Reservation,
}

impl<Reservation> ReservedCandidate<Reservation> {
    /// The runtime may construct this value only after revalidating both the
    /// immutable provider identity and a new usage read under `reservation`.
    pub(crate) fn new(profile: Profile, usage: UsageView, reservation: Reservation) -> Self {
        Self {
            profile,
            usage,
            reservation,
        }
    }
}

pub(crate) enum ReservationResult<Reservation> {
    Ready(Box<ReservedCandidate<Reservation>>),
    Busy,
    Unknown,
}

impl<Reservation> ReservationResult<Reservation> {
    pub(crate) fn ready(candidate: ReservedCandidate<Reservation>) -> Self {
        Self::Ready(Box::new(candidate))
    }
}

pub(crate) struct HandoffSelection<Reservation> {
    source: Profile,
    target: Profile,
    authorization: HandoffAuthorization,
    pool_id: String,
    reason: SelectionReason,
    trigger_observed_at: i64,
    reservation: Reservation,
}

impl<Reservation> HandoffSelection<Reservation> {
    pub(crate) fn source(&self) -> &Profile {
        &self.source
    }

    pub(crate) fn target(&self) -> &Profile {
        &self.target
    }

    pub(crate) fn trust_domain_id(&self) -> &str {
        self.authorization.trust_domain_id()
    }

    pub(crate) fn pool_id(&self) -> &str {
        &self.pool_id
    }

    pub(crate) const fn reason(&self) -> SelectionReason {
        self.reason
    }

    pub(crate) const fn trigger_observed_at(&self) -> i64 {
        self.trigger_observed_at
    }

    pub(crate) fn reservation(&self) -> &Reservation {
        &self.reservation
    }

    pub(crate) fn into_reservation(self) -> Reservation {
        self.reservation
    }
}

pub(crate) trait SelectionRuntime {
    type Reservation;
    type Error;

    /// A cache hit may only eliminate a candidate when it is still fresh and
    /// authoritatively exhausted. It never authorizes a handoff target.
    fn cached_usage(&mut self, profile_id: &str) -> Result<Option<UsageView>, Self::Error>;

    /// Revalidate provider identity and current usage while acquiring the
    /// exclusive candidate reservation returned in `Ready`.
    fn reserve_and_revalidate(
        &mut self,
        profile_id: &str,
    ) -> Result<ReservationResult<Self::Reservation>, Self::Error>;

    /// Execute the transactional conversation handoff exactly once. The
    /// candidate reservation remains owned by `selection` for the whole call.
    fn handoff(
        &mut self,
        selection: HandoffSelection<Self::Reservation>,
    ) -> Result<u64, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SelectionNotice {
    pub(crate) pool: String,
    pub(crate) trust_domain: String,
    pub(crate) source_profile: String,
    pub(crate) target_profile: String,
    pub(crate) generation: u64,
    pub(crate) reason: SelectionReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SelectionStop {
    pub(crate) pool: String,
    pub(crate) trust_domain: String,
    pub(crate) source_profile: String,
    pub(crate) reason: SelectionReason,
    pub(crate) candidates: usize,
    pub(crate) exhausted: usize,
    pub(crate) unknown: usize,
    pub(crate) busy: usize,
    pub(crate) cooldown: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(crate) enum SelectionOutcome {
    Selected(SelectionNotice),
    Exhausted(SelectionStop),
    AllUnknown(SelectionStop),
    Busy(SelectionStop),
    NoEligible(SelectionStop),
}

pub(crate) enum SelectionError<RuntimeError> {
    Policy(DefinitionError),
    Runtime(RuntimeError),
    RuntimeInvariant,
}

impl<RuntimeError> fmt::Debug for SelectionError<RuntimeError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Policy(_) => "SelectionError::Policy",
            Self::Runtime(_) => "SelectionError::Runtime",
            Self::RuntimeInvariant => "SelectionError::RuntimeInvariant",
        })
    }
}

impl<RuntimeError> fmt::Display for SelectionError<RuntimeError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(_) => formatter.write_str("routing policy changed or denied selection"),
            Self::Runtime(_) => formatter.write_str("candidate revalidation or handoff failed"),
            Self::RuntimeInvariant => {
                formatter.write_str("the reserved candidate did not match the requested profile")
            }
        }
    }
}

impl<RuntimeError: fmt::Debug> std::error::Error for SelectionError<RuntimeError> {}

/// Traverses the enabled pool at most once, beginning immediately after the
/// source. Cooldown entries come from the caller's current logical-conversation
/// generations and are never persisted here as provider state.
pub(crate) fn select_once<Runtime: SelectionRuntime>(
    definitions: &Definitions,
    pool: &EnabledPool,
    source: &Profile,
    trigger: SelectionTrigger,
    cooldown_profile_ids: &BTreeSet<String>,
    runtime: &mut Runtime,
) -> Result<SelectionOutcome, SelectionError<Runtime::Error>> {
    let current = definitions
        .enabled_pool_for_source(pool.id(), &source.id, source.provider)
        .map_err(SelectionError::Policy)?;
    if current != *pool
        || source.provider != pool.provider()
        || trigger.source_profile_id != source.id
    {
        return Err(SelectionError::RuntimeInvariant);
    }
    let members = pool.profile_ids();
    let source_index = members
        .iter()
        .position(|profile_id| profile_id == &source.id)
        .ok_or(SelectionError::RuntimeInvariant)?;
    let mut visited = BTreeSet::from([source.id.clone()]);
    let mut stop = SelectionStop {
        pool: pool.alias().to_owned(),
        trust_domain: pool.trust_domain_alias().to_owned(),
        source_profile: source.reference(),
        reason: trigger.reason,
        candidates: members.len().saturating_sub(1),
        exhausted: 0,
        unknown: 0,
        busy: 0,
        cooldown: 0,
    };

    for offset in 1..members.len() {
        let profile_id = &members[(source_index + offset) % members.len()];
        if !visited.insert(profile_id.clone()) {
            return Err(SelectionError::RuntimeInvariant);
        }
        if cooldown_profile_ids.contains(profile_id) {
            stop.cooldown += 1;
            continue;
        }
        let authorization = definitions
            .authorize_handoff(
                pool.trust_domain_id(),
                &source.id,
                profile_id,
                Provider::Codex,
            )
            .map_err(SelectionError::Policy)?;

        if runtime
            .cached_usage(profile_id)
            .map_err(SelectionError::Runtime)?
            .as_ref()
            .is_some_and(is_fresh_authoritative_exhaustion)
        {
            stop.exhausted += 1;
            continue;
        }

        match runtime
            .reserve_and_revalidate(profile_id)
            .map_err(SelectionError::Runtime)?
        {
            ReservationResult::Busy => stop.busy += 1,
            ReservationResult::Unknown => stop.unknown += 1,
            ReservationResult::Ready(candidate) => {
                if candidate.profile.id != *profile_id
                    || candidate.profile.provider != pool.provider()
                {
                    return Err(SelectionError::RuntimeInvariant);
                }
                if candidate.usage.observed_at >= trigger.observed_at
                    && is_fresh_authoritative_available(&candidate.usage)
                {
                    let target_reference = candidate.profile.reference();
                    let selection = HandoffSelection {
                        source: source.clone(),
                        target: candidate.profile,
                        authorization,
                        pool_id: pool.id().to_owned(),
                        reason: trigger.reason,
                        trigger_observed_at: trigger.observed_at,
                        reservation: candidate.reservation,
                    };
                    let generation = runtime
                        .handoff(selection)
                        .map_err(SelectionError::Runtime)?;
                    return Ok(SelectionOutcome::Selected(SelectionNotice {
                        pool: pool.alias().to_owned(),
                        trust_domain: pool.trust_domain_alias().to_owned(),
                        source_profile: source.reference(),
                        target_profile: target_reference,
                        generation,
                        reason: trigger.reason,
                    }));
                }
                if is_fresh_authoritative_exhaustion(&candidate.usage) {
                    stop.exhausted += 1;
                } else {
                    stop.unknown += 1;
                }
            }
        }
    }

    let eligible = stop.candidates.saturating_sub(stop.cooldown);
    if eligible == 0 {
        return Ok(SelectionOutcome::NoEligible(stop));
    }
    if stop.exhausted == eligible {
        return Ok(SelectionOutcome::Exhausted(stop));
    }
    if stop.busy == eligible || stop.busy > 0 {
        return Ok(SelectionOutcome::Busy(stop));
    }
    Ok(SelectionOutcome::AllUnknown(stop))
}

fn is_fresh_authoritative_available(view: &UsageView) -> bool {
    view.availability == Availability::Available
        && view.freshness == Freshness::Fresh
        && authoritative_source(view.source)
}

fn is_fresh_authoritative_exhaustion(view: &UsageView) -> bool {
    view.availability == Availability::Exhausted
        && view.freshness == Freshness::Fresh
        && authoritative_source(view.source)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};

    use crate::profiles::{Profile, Provider};
    use crate::providers::codex::CodexCompatibilityStatus;
    use crate::routing::{DefinitionMutation, Definitions};
    use crate::usage_observations::{Availability, Freshness, ObservationSource, UsageView};

    use super::*;

    const DOMAIN_ID: &str = "01900000-0000-7000-8000-000000000301";
    const POOL_ID: &str = "01900000-0000-7000-8000-000000000302";
    const PROFILE_A: &str = "01900000-0000-7000-8000-000000000311";
    const PROFILE_B: &str = "01900000-0000-7000-8000-000000000312";
    const PROFILE_C: &str = "01900000-0000-7000-8000-000000000313";

    struct FakeRuntime {
        cached: BTreeMap<String, UsageView>,
        probes: BTreeMap<String, ReservationResult<&'static str>>,
        reserved: Vec<String>,
        handoffs: Vec<String>,
        handoff_error: bool,
    }

    impl SelectionRuntime for FakeRuntime {
        type Error = &'static str;
        type Reservation = &'static str;

        fn cached_usage(&mut self, profile_id: &str) -> Result<Option<UsageView>, Self::Error> {
            Ok(self.cached.get(profile_id).cloned())
        }

        fn reserve_and_revalidate(
            &mut self,
            profile_id: &str,
        ) -> Result<ReservationResult<Self::Reservation>, Self::Error> {
            self.reserved.push(profile_id.to_owned());
            Ok(self
                .probes
                .remove(profile_id)
                .unwrap_or(ReservationResult::Unknown))
        }

        fn handoff(
            &mut self,
            selection: HandoffSelection<Self::Reservation>,
        ) -> Result<u64, Self::Error> {
            assert_eq!(selection.reservation(), &"lease");
            assert_eq!(selection.source().id, PROFILE_B);
            assert_eq!(selection.trust_domain_id(), DOMAIN_ID);
            assert_eq!(selection.pool_id(), POOL_ID);
            assert_eq!(selection.reason(), SelectionReason::AuthoritativeExhaustion);
            assert_eq!(
                selection.reason().handoff_reason(),
                HandoffReason::ConfirmedUsageExhaustion
            );
            assert_eq!(selection.trigger_observed_at(), 20);
            self.handoffs.push(selection.target().id.clone());
            assert_eq!(selection.into_reservation(), "lease");
            if self.handoff_error {
                Err("handoff failed")
            } else {
                Ok(4)
            }
        }
    }

    #[test]
    fn trigger_requires_fresh_authoritative_exhaustion_and_same_or_later_revalidation()
    -> Result<(), Box<dyn std::error::Error>> {
        for rejected in [
            usage(
                Availability::Available,
                Freshness::Fresh,
                ObservationSource::IdleRead,
                20,
            ),
            usage(
                Availability::Exhausted,
                Freshness::Stale,
                ObservationSource::IdleRead,
                20,
            ),
            usage(
                Availability::Exhausted,
                Freshness::RevalidationRequired,
                ObservationSource::UsageLimitSignal,
                20,
            ),
            usage(
                Availability::Unknown,
                Freshness::Unknown,
                ObservationSource::ActiveMonitor,
                20,
            ),
        ] {
            assert_eq!(
                SelectionTrigger::authoritative_exhaustion(PROFILE_B, &rejected).err(),
                Some(TriggerError::NotAuthoritativeExhaustion)
            );
        }

        let exhausted = usage(
            Availability::Exhausted,
            Freshness::Fresh,
            ObservationSource::ActiveMonitor,
            20,
        );
        assert_eq!(
            SelectionTrigger::authoritative_exhaustion(PROFILE_B, &exhausted)?.reason(),
            SelectionReason::AuthoritativeExhaustion
        );
        assert_eq!(
            SelectionTrigger::revalidated_usage_limit(PROFILE_B, 21, &exhausted).err(),
            Some(TriggerError::RevalidationPredatesSignal)
        );
        assert_eq!(
            SelectionTrigger::revalidated_usage_limit(PROFILE_B, 20, &exhausted)?.reason(),
            SelectionReason::RevalidatedUsageLimit
        );
        assert_eq!(
            SelectionReason::RevalidatedUsageLimit.handoff_reason(),
            HandoffReason::ConfirmedUsageExhaustion
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }

    #[test]
    fn selector_traverses_after_source_once_and_hands_off_exactly_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let (definitions, pool) = enabled_pool()?;
        let source = profile(PROFILE_B, "office");
        let trigger = SelectionTrigger::authoritative_exhaustion(
            PROFILE_B,
            &usage(
                Availability::Exhausted,
                Freshness::Fresh,
                ObservationSource::ActiveMonitor,
                20,
            ),
        )?;
        let mut runtime = FakeRuntime {
            cached: BTreeMap::from([(
                PROFILE_C.to_owned(),
                usage(
                    Availability::Unknown,
                    Freshness::Unknown,
                    ObservationSource::IdleRead,
                    19,
                ),
            )]),
            probes: BTreeMap::from([
                (
                    PROFILE_C.to_owned(),
                    ReservationResult::ready(ReservedCandidate::new(
                        profile(PROFILE_C, "team"),
                        usage(
                            Availability::Exhausted,
                            Freshness::Fresh,
                            ObservationSource::IdleRead,
                            21,
                        ),
                        "lease",
                    )),
                ),
                (
                    PROFILE_A.to_owned(),
                    ReservationResult::ready(ReservedCandidate::new(
                        profile(PROFILE_A, "personal"),
                        usage(
                            Availability::Available,
                            Freshness::Fresh,
                            ObservationSource::IdleRead,
                            22,
                        ),
                        "lease",
                    )),
                ),
            ]),
            reserved: Vec::new(),
            handoffs: Vec::new(),
            handoff_error: false,
        };

        let outcome = select_once(
            &definitions,
            &pool,
            &source,
            trigger,
            &BTreeSet::new(),
            &mut runtime,
        )?;
        let SelectionOutcome::Selected(notice) = outcome else {
            return Err("expected selection".into());
        };
        assert_eq!(runtime.reserved, [PROFILE_C, PROFILE_A]);
        assert_eq!(runtime.handoffs, [PROFILE_A]);
        assert_eq!(notice.target_profile, "codex@personal");
        assert_eq!(notice.pool, "fallback");
        assert_eq!(notice.trust_domain, "accounts");
        assert_eq!(notice.generation, 4);
        assert_eq!(notice.reason, SelectionReason::AuthoritativeExhaustion);
        Ok::<(), Box<dyn std::error::Error>>(())
    }

    #[test]
    fn stop_outcomes_are_closed_and_cached_availability_never_authorizes_selection()
    -> Result<(), Box<dyn std::error::Error>> {
        let trigger = trigger()?;
        for (probes, expected) in [
            (
                BTreeMap::from([
                    (
                        PROFILE_C.to_owned(),
                        ReservationResult::ready(ReservedCandidate::new(
                            profile(PROFILE_C, "team"),
                            usage(
                                Availability::Exhausted,
                                Freshness::Fresh,
                                ObservationSource::IdleRead,
                                21,
                            ),
                            "lease",
                        )),
                    ),
                    (
                        PROFILE_A.to_owned(),
                        ReservationResult::ready(ReservedCandidate::new(
                            profile(PROFILE_A, "personal"),
                            usage(
                                Availability::Exhausted,
                                Freshness::Fresh,
                                ObservationSource::IdleRead,
                                21,
                            ),
                            "lease",
                        )),
                    ),
                ]),
                "exhausted",
            ),
            (
                BTreeMap::from([
                    (PROFILE_C.to_owned(), ReservationResult::Unknown),
                    (PROFILE_A.to_owned(), ReservationResult::Unknown),
                ]),
                "all_unknown",
            ),
            (
                BTreeMap::from([
                    (PROFILE_C.to_owned(), ReservationResult::Busy),
                    (PROFILE_A.to_owned(), ReservationResult::Busy),
                ]),
                "busy",
            ),
        ] {
            let (definitions, pool) = enabled_pool()?;
            let mut runtime = FakeRuntime {
                cached: BTreeMap::new(),
                probes,
                reserved: Vec::new(),
                handoffs: Vec::new(),
                handoff_error: false,
            };
            let outcome = select_once(
                &definitions,
                &pool,
                &profile(PROFILE_B, "office"),
                trigger.clone(),
                &BTreeSet::new(),
                &mut runtime,
            )?;
            let encoded = serde_json::to_value(&outcome)?;
            assert_eq!(encoded["outcome"], expected);
            assert!(runtime.handoffs.is_empty());
        }

        let (definitions, pool) = enabled_pool()?;
        let mut runtime = FakeRuntime {
            cached: BTreeMap::from([(
                PROFILE_C.to_owned(),
                usage(
                    Availability::Available,
                    Freshness::Fresh,
                    ObservationSource::IdleRead,
                    21,
                ),
            )]),
            probes: BTreeMap::from([
                (
                    PROFILE_C.to_owned(),
                    ReservationResult::ready(ReservedCandidate::new(
                        profile(PROFILE_C, "team"),
                        usage(
                            Availability::Available,
                            Freshness::Fresh,
                            ObservationSource::IdleRead,
                            19,
                        ),
                        "lease",
                    )),
                ),
                (PROFILE_A.to_owned(), ReservationResult::Unknown),
            ]),
            reserved: Vec::new(),
            handoffs: Vec::new(),
            handoff_error: false,
        };
        let outcome = select_once(
            &definitions,
            &pool,
            &profile(PROFILE_B, "office"),
            trigger.clone(),
            &BTreeSet::new(),
            &mut runtime,
        )?;
        assert!(matches!(outcome, SelectionOutcome::AllUnknown(_)));
        assert_eq!(runtime.reserved, [PROFILE_C, PROFILE_A]);
        assert!(runtime.handoffs.is_empty());
        Ok(())
    }

    #[test]
    fn cooldown_skips_recent_generations_and_a_failed_handoff_is_never_retried()
    -> Result<(), Box<dyn std::error::Error>> {
        let (definitions, pool) = enabled_pool()?;
        let mut runtime = FakeRuntime {
            cached: BTreeMap::new(),
            probes: BTreeMap::new(),
            reserved: Vec::new(),
            handoffs: Vec::new(),
            handoff_error: false,
        };
        let cooldown = BTreeSet::from([PROFILE_A.to_owned(), PROFILE_C.to_owned()]);
        let outcome = select_once(
            &definitions,
            &pool,
            &profile(PROFILE_B, "office"),
            trigger()?,
            &cooldown,
            &mut runtime,
        )?;
        let SelectionOutcome::NoEligible(stop) = outcome else {
            return Err("expected cooldown stop".into());
        };
        assert_eq!(stop.cooldown, 2);
        assert!(runtime.reserved.is_empty());

        let mut runtime = FakeRuntime {
            cached: BTreeMap::new(),
            probes: BTreeMap::from([
                (
                    PROFILE_C.to_owned(),
                    ReservationResult::ready(ReservedCandidate::new(
                        profile(PROFILE_C, "team"),
                        usage(
                            Availability::Available,
                            Freshness::Fresh,
                            ObservationSource::IdleRead,
                            21,
                        ),
                        "lease",
                    )),
                ),
                (
                    PROFILE_A.to_owned(),
                    ReservationResult::ready(ReservedCandidate::new(
                        profile(PROFILE_A, "personal"),
                        usage(
                            Availability::Available,
                            Freshness::Fresh,
                            ObservationSource::IdleRead,
                            21,
                        ),
                        "lease",
                    )),
                ),
            ]),
            reserved: Vec::new(),
            handoffs: Vec::new(),
            handoff_error: true,
        };
        assert!(matches!(
            select_once(
                &definitions,
                &pool,
                &profile(PROFILE_B, "office"),
                trigger()?,
                &BTreeSet::new(),
                &mut runtime,
            ),
            Err(SelectionError::Runtime("handoff failed"))
        ));
        assert_eq!(runtime.reserved, [PROFILE_C]);
        assert_eq!(runtime.handoffs, [PROFILE_C]);
        Ok(())
    }

    #[test]
    fn stale_pool_snapshot_and_mismatched_reserved_identity_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut definitions, pool) = enabled_pool()?;
        definitions.apply(
            3,
            DefinitionMutation::SetPoolActivation {
                id: POOL_ID.to_owned(),
                enabled: false,
            },
        )?;
        let mut runtime = FakeRuntime {
            cached: BTreeMap::new(),
            probes: BTreeMap::new(),
            reserved: Vec::new(),
            handoffs: Vec::new(),
            handoff_error: false,
        };
        assert!(matches!(
            select_once(
                &definitions,
                &pool,
                &profile(PROFILE_B, "office"),
                trigger()?,
                &BTreeSet::new(),
                &mut runtime,
            ),
            Err(SelectionError::Policy(DefinitionError::PoolDisabled))
        ));

        let (definitions, pool) = enabled_pool()?;
        runtime.probes.insert(
            PROFILE_C.to_owned(),
            ReservationResult::ready(ReservedCandidate::new(
                profile(PROFILE_A, "redirected"),
                usage(
                    Availability::Available,
                    Freshness::Fresh,
                    ObservationSource::IdleRead,
                    21,
                ),
                "lease",
            )),
        );
        assert!(matches!(
            select_once(
                &definitions,
                &pool,
                &profile(PROFILE_B, "office"),
                trigger()?,
                &BTreeSet::new(),
                &mut runtime,
            ),
            Err(SelectionError::RuntimeInvariant)
        ));
        assert!(runtime.handoffs.is_empty());

        let wrong_source_trigger = SelectionTrigger::authoritative_exhaustion(
            PROFILE_A,
            &usage(
                Availability::Exhausted,
                Freshness::Fresh,
                ObservationSource::ActiveMonitor,
                22,
            ),
        )?;
        assert!(matches!(
            select_once(
                &definitions,
                &pool,
                &profile(PROFILE_B, "office"),
                wrong_source_trigger,
                &BTreeSet::new(),
                &mut runtime,
            ),
            Err(SelectionError::RuntimeInvariant)
        ));
        Ok(())
    }

    struct SharedReservation(Arc<AtomicBool>);

    impl Drop for SharedReservation {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    struct SharedRuntime {
        held: Arc<AtomicBool>,
        entered: Option<mpsc::Sender<()>>,
        release: Option<mpsc::Receiver<()>>,
    }

    impl SelectionRuntime for SharedRuntime {
        type Error = &'static str;
        type Reservation = SharedReservation;

        fn cached_usage(&mut self, _: &str) -> Result<Option<UsageView>, Self::Error> {
            Ok(None)
        }

        fn reserve_and_revalidate(
            &mut self,
            profile_id: &str,
        ) -> Result<ReservationResult<Self::Reservation>, Self::Error> {
            if self
                .held
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Ok(ReservationResult::Busy);
            }
            Ok(ReservationResult::ready(ReservedCandidate::new(
                profile(profile_id, "team"),
                usage(
                    Availability::Available,
                    Freshness::Fresh,
                    ObservationSource::IdleRead,
                    21,
                ),
                SharedReservation(Arc::clone(&self.held)),
            )))
        }

        fn handoff(
            &mut self,
            _selection: HandoffSelection<Self::Reservation>,
        ) -> Result<u64, Self::Error> {
            self.entered
                .take()
                .ok_or("unexpected handoff")?
                .send(())
                .map_err(|_| "send")?;
            self.release
                .take()
                .ok_or("missing release")?
                .recv()
                .map_err(|_| "receive")?;
            Ok(2)
        }
    }

    #[test]
    fn concurrent_selectors_cannot_choose_the_same_reserved_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let (definitions, pool) = enabled_pool()?;
        let source = profile(PROFILE_B, "office");
        let trigger = trigger()?;
        let first_trigger = trigger.clone();
        let cooldown = BTreeSet::from([PROFILE_A.to_owned()]);
        let held = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_held = Arc::clone(&held);
        let first = std::thread::spawn(move || {
            let mut runtime = SharedRuntime {
                held: first_held,
                entered: Some(entered_tx),
                release: Some(release_rx),
            };
            select_once(
                &definitions,
                &pool,
                &source,
                first_trigger,
                &cooldown,
                &mut runtime,
            )
        });
        entered_rx.recv()?;

        let (definitions, pool) = enabled_pool()?;
        let mut second_runtime = SharedRuntime {
            held,
            entered: None,
            release: None,
        };
        let second = select_once(
            &definitions,
            &pool,
            &profile(PROFILE_B, "office"),
            trigger,
            &BTreeSet::from([PROFILE_A.to_owned()]),
            &mut second_runtime,
        )?;
        let SelectionOutcome::Busy(stop) = second else {
            return Err("the concurrent selector must stop busy".into());
        };
        assert_eq!(stop.busy, 1);
        release_tx.send(())?;
        assert!(matches!(
            first.join().map_err(|_| "selector thread panicked")??,
            SelectionOutcome::Selected(_)
        ));
        Ok(())
    }

    fn enabled_pool()
    -> Result<(Definitions, crate::routing::EnabledPool), Box<dyn std::error::Error>> {
        let mut definitions = Definitions::default();
        definitions.apply(
            0,
            DefinitionMutation::CreateDomain {
                id: DOMAIN_ID.to_owned(),
                alias: "accounts".to_owned(),
                provider: Provider::Codex,
                profile_ids: vec![
                    PROFILE_A.to_owned(),
                    PROFILE_B.to_owned(),
                    PROFILE_C.to_owned(),
                ],
            },
        )?;
        definitions.apply(
            1,
            DefinitionMutation::CreatePool {
                id: POOL_ID.to_owned(),
                alias: "fallback".to_owned(),
                trust_domain_id: DOMAIN_ID.to_owned(),
                profile_ids: vec![
                    PROFILE_A.to_owned(),
                    PROFILE_B.to_owned(),
                    PROFILE_C.to_owned(),
                ],
            },
        )?;
        definitions.apply(
            2,
            DefinitionMutation::SetPoolActivation {
                id: POOL_ID.to_owned(),
                enabled: true,
            },
        )?;
        let pool = definitions.enabled_pool_for_source(POOL_ID, PROFILE_B, Provider::Codex)?;
        Ok((definitions, pool))
    }

    fn profile(id: &str, alias: &str) -> Profile {
        Profile {
            id: id.to_owned(),
            alias: alias.to_owned(),
            provider: Provider::Codex,
            created_at: 1,
        }
    }

    fn usage(
        availability: Availability,
        freshness: Freshness,
        source: ObservationSource,
        observed_at: i64,
    ) -> UsageView {
        UsageView {
            availability,
            freshness,
            observed_at,
            source,
            codex_version: Some("0.144.4".to_owned()),
            adapter_version: "codex-usage@1".to_owned(),
            compatibility: CodexCompatibilityStatus::Compatible,
            usage: None,
            next_refresh_at: observed_at + 60,
        }
    }

    fn trigger() -> Result<SelectionTrigger, TriggerError> {
        SelectionTrigger::authoritative_exhaustion(
            PROFILE_B,
            &usage(
                Availability::Exhausted,
                Freshness::Fresh,
                ObservationSource::ActiveMonitor,
                20,
            ),
        )
    }
}
