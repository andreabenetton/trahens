// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "Typed event-driven route state machines for P1 nodes."]

use protocol_registry::{
    LIMIT_BRANCH_TTL_MS, LIMIT_INGRESS_BUCKET_CAPACITY, LIMIT_INGRESS_BUCKET_REFILL_AMOUNT,
    LIMIT_INGRESS_BUCKET_REFILL_INTERVAL_MS, LIMIT_MAX_BRANCHES_GLOBAL,
    LIMIT_MAX_BRANCHES_PER_PEER, LIMIT_MAX_ROUTES_GLOBAL, LIMIT_MAX_ROUTES_PER_PEER,
    LIMIT_OFFER_TTL_MS, LIMIT_READY_HOLD_MS, LIMIT_ROUTE_TTL_MS,
};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Discovering,
    Candidate,
    /// `event-lifecycle-profile-e1.md` section 6.1: capacity is reserved and a
    /// ready-hold deadline assigned, but application data is still refused.
    PendingReady,
    Ready,
    Open,
}

impl Phase {
    /// Independent finite deadline for each state class (E1 section 8).
    #[must_use]
    pub fn lifetime_ms(self) -> u64 {
        match self {
            Self::Discovering => LIMIT_BRANCH_TTL_MS as u64,
            Self::Candidate => LIMIT_OFFER_TTL_MS as u64,
            Self::PendingReady => LIMIT_READY_HOLD_MS as u64,
            Self::Ready | Self::Open => LIMIT_ROUTE_TTL_MS as u64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    CandidateAccepted,
    CommitAccepted,
    ReadyAccepted,
    CapabilityAccepted,
    DataAccepted,
    CloseAccepted,
    CancelAccepted,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    StoreCandidate,
    ReserveRoute,
    ActivateRoute,
    OpenRendezvous,
    DeliverData,
    ReclaimState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    Missing,
    InvalidTransition,
    PeerLimit,
    GlobalLimit,
    Duplicate,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "route state missing",
            Self::InvalidTransition => "invalid route state transition",
            Self::PeerLimit => "per-peer route limit exceeded",
            Self::GlobalLimit => "global route limit exceeded",
            Self::Duplicate => "duplicate route label",
        })
    }
}

impl std::error::Error for StateError {}

/// Per-ingress-peer token bucket for fresh-branch admission (E1 section 10,
/// ADR 0013).
///
/// Capacity `b`, refill interval `r`, refill amount `a` all come from the
/// registry. One admitted fresh branch consumes one token. Buckets are scoped
/// to `(link epoch, ingress peer, receiving node)`; a node instance owns one
/// table, and the epoch and peer form the key.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u32,
    last_refill_ms: u64,
}

#[derive(Debug, Default)]
pub struct IngressAdmission {
    buckets: HashMap<(u32, u32), Bucket>,
    rejected: u64,
}

impl IngressAdmission {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to admit one fresh branch from `peer` on `epoch`.
    ///
    /// Returns false when the bucket is empty, which the caller must treat as
    /// a drop before any cryptographic work or branch allocation.
    pub fn admit(&mut self, epoch: u32, peer: u32, now_ms: u64) -> bool {
        let bucket = self.buckets.entry((epoch, peer)).or_insert(Bucket {
            tokens: LIMIT_INGRESS_BUCKET_CAPACITY as u32,
            last_refill_ms: now_ms,
        });
        let interval = LIMIT_INGRESS_BUCKET_REFILL_INTERVAL_MS as u64;
        if interval > 0 {
            let elapsed = now_ms.saturating_sub(bucket.last_refill_ms);
            let periods = elapsed / interval;
            if periods > 0 {
                let refill = periods.saturating_mul(LIMIT_INGRESS_BUCKET_REFILL_AMOUNT as u64);
                bucket.tokens = u32::try_from(
                    u64::from(bucket.tokens)
                        .saturating_add(refill)
                        .min(LIMIT_INGRESS_BUCKET_CAPACITY as u64),
                )
                .unwrap_or(LIMIT_INGRESS_BUCKET_CAPACITY as u32);
                bucket.last_refill_ms = bucket.last_refill_ms.saturating_add(periods * interval);
            }
        }
        if bucket.tokens == 0 {
            self.rejected = self.rejected.saturating_add(1);
            return false;
        }
        bucket.tokens -= 1;
        true
    }

    /// Fresh branches refused for want of a token.
    #[must_use]
    pub fn rejected(&self) -> u64 {
        self.rejected
    }
}

#[derive(Debug, Clone)]
pub struct RouteState {
    pub phase: Phase,
    pub peer: u32,
    pub generation: u32,
    pub expires_at_ms: u64,
}

/// Peak occupancy of each bounded structure, for the P1 measurement list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatePeaks {
    pub peak_routes: usize,
    pub peak_routes_per_peer: usize,
    pub peak_branches: usize,
    pub peak_pending_ready: usize,
    pub peak_active: usize,
}

#[derive(Debug, Default)]
pub struct RouteTable {
    routes: HashMap<[u8; 16], RouteState>,
    peer_counts: HashMap<u32, usize>,
    peaks: StatePeaks,
}

impl RouteTable {
    pub fn begin(
        &mut self,
        label: [u8; 16],
        peer: u32,
        generation: u32,
        expires_at_ms: u64,
    ) -> Result<(), StateError> {
        if self.routes.contains_key(&label) {
            return Err(StateError::Duplicate);
        }
        if self.routes.len() >= LIMIT_MAX_ROUTES_GLOBAL {
            return Err(StateError::GlobalLimit);
        }
        // E1 section 10 bounds branch contexts separately from routes: a
        // branch is state a peer can create before any commitment, so it has
        // the tighter ceiling.
        let branches = self
            .routes
            .values()
            .filter(|route| matches!(route.phase, Phase::Discovering | Phase::Candidate))
            .count();
        if branches >= LIMIT_MAX_BRANCHES_GLOBAL {
            return Err(StateError::GlobalLimit);
        }
        let count = self.peer_counts.get(&peer).copied().unwrap_or(0);
        if count >= LIMIT_MAX_ROUTES_PER_PEER || count >= LIMIT_MAX_BRANCHES_PER_PEER {
            return Err(StateError::PeerLimit);
        }
        self.routes.insert(
            label,
            RouteState {
                phase: Phase::Discovering,
                peer,
                generation,
                expires_at_ms,
            },
        );
        self.peer_counts.insert(peer, count + 1);
        self.observe_peaks();
        Ok(())
    }

    /// Apply an event, renewing the deadline for the resulting state class.
    ///
    /// E1 section 8: a valid transition replaces the deadline and bumps the
    /// generation, which makes any timer queued against the previous deadline
    /// stale. `expire` always compares the current deadline, so a renewed
    /// route is never reclaimed early.
    pub fn apply(
        &mut self,
        label: [u8; 16],
        event: Event,
        now_ms: u64,
    ) -> Result<Action, StateError> {
        if matches!(
            event,
            Event::CloseAccepted | Event::CancelAccepted | Event::Timeout
        ) {
            return self.remove(label).map(|()| Action::ReclaimState);
        }
        let state = self.routes.get_mut(&label).ok_or(StateError::Missing)?;
        let transition = match (state.phase, event) {
            (Phase::Discovering, Event::CandidateAccepted) => {
                state.phase = Phase::Candidate;
                Action::StoreCandidate
            }
            // Section 4: a relay creates a tentative mapping for every
            // CANDIDATE traversing it, and with fan-out several offers return
            // through one branch. A further offer is another mapping, not an
            // invalid transition, so it is stored idempotently and renews the
            // offer deadline.
            (Phase::Candidate, Event::CandidateAccepted) => Action::StoreCandidate,
            (Phase::Candidate, Event::CommitAccepted) => {
                state.phase = Phase::PendingReady;
                Action::ReserveRoute
            }
            (Phase::PendingReady, Event::ReadyAccepted) => {
                state.phase = Phase::Ready;
                Action::ActivateRoute
            }
            (Phase::Ready, Event::CapabilityAccepted) => {
                state.phase = Phase::Open;
                Action::OpenRendezvous
            }
            (Phase::Open, Event::DataAccepted) => Action::DeliverData,
            _ => return Err(StateError::InvalidTransition),
        };
        state.generation = state.generation.saturating_add(1);
        state.expires_at_ms = now_ms.saturating_add(state.phase.lifetime_ms());
        self.observe_peaks();
        Ok(transition)
    }

    /// Snapshot of peak occupancy across every bounded state class.
    #[must_use]
    pub fn peaks(&self) -> StatePeaks {
        self.peaks
    }

    fn observe_peaks(&mut self) {
        let mut branches = 0;
        let mut pending = 0;
        let mut active = 0;
        for route in self.routes.values() {
            match route.phase {
                Phase::Discovering | Phase::Candidate => branches += 1,
                Phase::PendingReady => pending += 1,
                Phase::Ready | Phase::Open => active += 1,
            }
        }
        self.peaks.peak_routes = self.peaks.peak_routes.max(self.routes.len());
        self.peaks.peak_branches = self.peaks.peak_branches.max(branches);
        self.peaks.peak_pending_ready = self.peaks.peak_pending_ready.max(pending);
        self.peaks.peak_active = self.peaks.peak_active.max(active);
        if let Some(highest) = self.peer_counts.values().copied().max() {
            self.peaks.peak_routes_per_peer = self.peaks.peak_routes_per_peer.max(highest);
        }
    }

    pub fn expire(&mut self, now_ms: u64) -> usize {
        let labels: Vec<[u8; 16]> = self
            .routes
            .iter()
            .filter_map(|(label, route)| (route.expires_at_ms <= now_ms).then_some(*label))
            .collect();
        for label in &labels {
            let _ = self.remove(*label);
        }
        labels.len()
    }

    pub fn remove(&mut self, label: [u8; 16]) -> Result<(), StateError> {
        let route = self.routes.remove(&label).ok_or(StateError::Missing)?;
        if let Some(count) = self.peer_counts.get_mut(&route.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.peer_counts.remove(&route.peer);
            }
        }
        Ok(())
    }

    pub fn get(&self, label: &[u8; 16]) -> Option<&RouteState> {
        self.routes.get(label)
    }

    pub fn live_routes(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_lifecycle_and_cleanup() -> Result<(), StateError> {
        let label = [1_u8; 16];
        let mut table = RouteTable::default();
        table.begin(label, 1, 0, 100)?;
        assert_eq!(
            table.apply(label, Event::CandidateAccepted, 0)?,
            Action::StoreCandidate
        );
        assert_eq!(
            table.apply(label, Event::CommitAccepted, 0)?,
            Action::ReserveRoute
        );
        assert_eq!(
            table.apply(label, Event::ReadyAccepted, 0)?,
            Action::ActivateRoute
        );
        assert_eq!(
            table.apply(label, Event::CapabilityAccepted, 0)?,
            Action::OpenRendezvous
        );
        assert_eq!(
            table.apply(label, Event::DataAccepted, 0)?,
            Action::DeliverData
        );
        assert_eq!(
            table.apply(label, Event::CloseAccepted, 0)?,
            Action::ReclaimState
        );
        assert_eq!(table.live_routes(), 0);
        Ok(())
    }

    #[test]
    fn branch_contexts_are_bounded_and_peaks_are_recorded() -> Result<(), StateError> {
        // E1 section 10 bounds branch contexts per peer, tighter than the
        // route ceiling, because a branch is state a peer creates before any
        // commitment.
        let mut table = RouteTable::default();
        let mut label = [0_u8; 16];
        for index in 0..LIMIT_MAX_BRANCHES_PER_PEER {
            label[0] = (index % 251) as u8;
            label[1] = (index / 251) as u8;
            table.begin(label, 1, 0, 10_000)?;
        }
        label[0] = 255;
        label[1] = 255;
        assert_eq!(
            table.begin(label, 1, 0, 10_000),
            Err(StateError::PeerLimit),
            "the per-peer branch ceiling is enforced"
        );

        let peaks = table.peaks();
        assert_eq!(peaks.peak_branches, LIMIT_MAX_BRANCHES_PER_PEER);
        assert_eq!(peaks.peak_routes_per_peer, LIMIT_MAX_BRANCHES_PER_PEER);
        assert_eq!(peaks.peak_pending_ready, 0);
        assert_eq!(peaks.peak_active, 0);

        // Advancing one route moves it out of the branch class and into the
        // pending-ready then active classes, each recorded separately.
        label[0] = 0;
        label[1] = 0;
        table.apply(label, Event::CandidateAccepted, 0)?;
        table.apply(label, Event::CommitAccepted, 0)?;
        assert_eq!(table.peaks().peak_pending_ready, 1);
        table.apply(label, Event::ReadyAccepted, 0)?;
        assert_eq!(table.peaks().peak_active, 1);
        assert_eq!(
            table.peaks().peak_branches,
            LIMIT_MAX_BRANCHES_PER_PEER,
            "the peak is a high-water mark, not a current count"
        );
        Ok(())
    }

    #[test]
    fn ingress_bucket_admits_a_burst_then_refills_over_time() {
        // E1 section 10: capacity b, refill interval r, refill amount a; one
        // admitted fresh branch consumes one token.
        let mut admission = IngressAdmission::new();
        let capacity = LIMIT_INGRESS_BUCKET_CAPACITY as u32;

        // A burst up to capacity is admitted.
        for _ in 0..capacity {
            assert!(admission.admit(1, 7, 0));
        }
        // The next fresh branch is refused, and counted.
        assert!(!admission.admit(1, 7, 0));
        assert_eq!(admission.rejected(), 1);

        // A different peer has its own bucket.
        assert!(admission.admit(1, 8, 0));
        // So does the same peer on a different link epoch.
        assert!(admission.admit(2, 7, 0));

        // One refill interval restores exactly the refill amount.
        let interval = LIMIT_INGRESS_BUCKET_REFILL_INTERVAL_MS as u64;
        for _ in 0..LIMIT_INGRESS_BUCKET_REFILL_AMOUNT {
            assert!(admission.admit(1, 7, interval));
        }
        assert!(!admission.admit(1, 7, interval), "refill is bounded by a");

        // Refill never exceeds capacity however long the peer is idle.
        let mut idle = IngressAdmission::new();
        assert!(idle.admit(1, 9, 0));
        for _ in 0..capacity {
            assert!(idle.admit(1, 9, interval * 1_000));
        }
        assert!(!idle.admit(1, 9, interval * 1_000), "capped at capacity");
    }

    #[test]
    fn each_transition_renews_its_class_deadline_and_generation() -> Result<(), StateError> {
        // E1 section 8: every state class has an independent finite deadline,
        // a valid transition replaces it, and the generation advances so an
        // already queued timer for the old deadline is recognisably stale.
        let label = [7_u8; 16];
        let mut table = RouteTable::default();
        table.begin(label, 1, 0, 50)?;
        assert_eq!(table.get(&label).map(|route| route.expires_at_ms), Some(50));

        let mut now = 1_000_u64;
        for (event, phase) in [
            (Event::CandidateAccepted, Phase::Candidate),
            (Event::CommitAccepted, Phase::PendingReady),
            (Event::ReadyAccepted, Phase::Ready),
            (Event::CapabilityAccepted, Phase::Open),
        ] {
            let before = table
                .get(&label)
                .map(|route| route.generation)
                .ok_or(StateError::Missing)?;
            table.apply(label, event, now)?;
            let route = table.get(&label).ok_or(StateError::Missing)?;
            assert_eq!(route.phase, phase);
            assert_eq!(
                route.expires_at_ms,
                now + phase.lifetime_ms(),
                "deadline renewed for {phase:?}"
            );
            assert!(route.generation > before, "generation advances");
            now += 10;
        }
        Ok(())
    }

    #[test]
    fn a_renewed_route_survives_its_previous_deadline() -> Result<(), StateError> {
        // The stale-timer rule: expiry compares the current deadline, so a
        // route renewed past an old timer must not be reclaimed by it.
        let label = [8_u8; 16];
        let mut table = RouteTable::default();
        table.begin(label, 1, 0, 100)?;
        table.apply(label, Event::CandidateAccepted, 90)?;

        // The original deadline of 100 has passed, but the transition at 90
        // replaced it with 90 + offer lifetime.
        assert_eq!(table.expire(101), 0, "stale timer must not reclaim");
        assert_eq!(table.live_routes(), 1);

        // It still expires at its replacement deadline.
        let renewed = table
            .get(&label)
            .map(|route| route.expires_at_ms)
            .ok_or(StateError::Missing)?;
        assert_eq!(table.expire(renewed), 1);
        assert_eq!(table.live_routes(), 0);
        Ok(())
    }

    #[test]
    fn a_branch_accepts_several_candidate_offers() -> Result<(), StateError> {
        // With fan-out, more than one gateway answers through the same branch.
        let label = [10_u8; 16];
        let mut table = RouteTable::default();
        table.begin(label, 1, 0, 1_000)?;
        assert_eq!(
            table.apply(label, Event::CandidateAccepted, 0)?,
            Action::StoreCandidate
        );
        assert_eq!(
            table.apply(label, Event::CandidateAccepted, 5)?,
            Action::StoreCandidate,
            "a second offer on the same branch is stored, not rejected"
        );
        let route = table.get(&label).ok_or(StateError::Missing)?;
        assert_eq!(route.phase, Phase::Candidate);
        assert_eq!(
            route.expires_at_ms,
            5 + Phase::Candidate.lifetime_ms(),
            "the offer deadline is renewed"
        );
        Ok(())
    }

    #[test]
    fn pending_ready_refuses_application_data() -> Result<(), StateError> {
        // E1 section 6.1: a relay in PENDING_READY MUST reject application
        // data; only an activated route delivers it.
        let label = [9_u8; 16];
        let mut table = RouteTable::default();
        table.begin(label, 1, 0, 1_000)?;
        table.apply(label, Event::CandidateAccepted, 0)?;
        table.apply(label, Event::CommitAccepted, 0)?;
        assert_eq!(
            table.get(&label).map(|route| route.phase),
            Some(Phase::PendingReady)
        );
        assert_eq!(
            table.apply(label, Event::DataAccepted, 0),
            Err(StateError::InvalidTransition),
            "data refused while the reservation is held"
        );
        Ok(())
    }

    #[test]
    fn invalid_transition_does_not_change_state() -> Result<(), StateError> {
        let label = [2_u8; 16];
        let mut table = RouteTable::default();
        table.begin(label, 1, 0, 100)?;
        assert_eq!(
            table.apply(label, Event::ReadyAccepted, 0),
            Err(StateError::InvalidTransition)
        );
        assert_eq!(
            table.get(&label).map(|route| route.phase),
            Some(Phase::Discovering)
        );
        Ok(())
    }
}
