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
    /// Total routes held for a peer, against `LIMIT_MAX_ROUTES_PER_PEER`.
    peer_routes: HashMap<u32, usize>,
    /// Of those, the ones still in a branch phase, against the tighter
    /// `LIMIT_MAX_BRANCHES_PER_PEER`. Counted separately because a branch is
    /// state a peer creates before any commitment, so it has its own ceiling;
    /// comparing one total against both made the smaller limit the only one
    /// that ever applied and capped a peer at 64 routes of any kind.
    peer_branches: HashMap<u32, usize>,
    peaks: StatePeaks,
}

fn bump(counts: &mut HashMap<u32, usize>, peer: u32) {
    *counts.entry(peer).or_insert(0) += 1;
}

fn drop_one(counts: &mut HashMap<u32, usize>, peer: u32) {
    if let Some(count) = counts.get_mut(&peer) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&peer);
        }
    }
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
        if self.peer_routes.get(&peer).copied().unwrap_or(0) >= LIMIT_MAX_ROUTES_PER_PEER
            || self.peer_branches.get(&peer).copied().unwrap_or(0) >= LIMIT_MAX_BRANCHES_PER_PEER
        {
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
        bump(&mut self.peer_routes, peer);
        // A fresh route always starts as a branch.
        bump(&mut self.peer_branches, peer);
        self.observe_peaks();
        Ok(())
    }

    /// Apply an event, renewing the deadline for the resulting state class.
    ///
    /// E1 section 8: a valid transition replaces the deadline and bumps the
    /// generation, which makes any timer queued against the previous deadline
    /// stale. `expire` always compares the current deadline, so a renewed
    /// route is never reclaimed early.
    pub fn apply(&mut self, label: [u8; 16], event: Event, now_ms: u64) -> Result<(), StateError> {
        if matches!(
            event,
            Event::CloseAccepted | Event::CancelAccepted | Event::Timeout
        ) {
            // Reclaim the state.
            return self.remove(label);
        }
        let state = self.routes.get_mut(&label).ok_or(StateError::Missing)?;
        let was_branch = matches!(state.phase, Phase::Discovering | Phase::Candidate);
        // Each arm is one E1 transition; the comment names the effect the
        // specification gives it. That used to be an Action value returned to
        // the caller, but no caller ever read one.
        match (state.phase, event) {
            // Store the candidate.
            (Phase::Discovering, Event::CandidateAccepted) => {
                state.phase = Phase::Candidate;
            }
            // Section 4: a relay creates a tentative mapping for every
            // CANDIDATE traversing it, and with fan-out several offers return
            // through one branch. A further offer is another mapping, not an
            // invalid transition, so it is stored idempotently and renews the
            // offer deadline.
            // Store a further candidate on the same branch.
            (Phase::Candidate, Event::CandidateAccepted) => {}
            // Reserve the route.
            (Phase::Candidate, Event::CommitAccepted) => {
                state.phase = Phase::PendingReady;
            }
            // Activate the route.
            (Phase::PendingReady, Event::ReadyAccepted) => {
                state.phase = Phase::Ready;
            }
            // Open the rendezvous.
            (Phase::Ready, Event::CapabilityAccepted) => {
                state.phase = Phase::Open;
            }
            // Deliver application data.
            (Phase::Open, Event::DataAccepted) => {}
            _ => return Err(StateError::InvalidTransition),
        }
        state.generation = state.generation.saturating_add(1);
        state.expires_at_ms = now_ms.saturating_add(state.phase.lifetime_ms());
        let peer = state.peer;
        let still_branch = matches!(state.phase, Phase::Discovering | Phase::Candidate);
        if was_branch && !still_branch {
            // Committing frees a branch slot while keeping the route slot, so
            // the peer may open another branch alongside its active routes.
            drop_one(&mut self.peer_branches, peer);
        }
        self.observe_peaks();
        Ok(())
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
        if let Some(highest) = self.peer_routes.values().copied().max() {
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

    /// Reclaim every live route, whatever phase it is in.
    ///
    /// Core v1.5 section 8 requires a node to release all state it holds on
    /// the way out, on every exit path and not only the expected one. Giving
    /// that one entry point means an unplanned exit — a transport failure or a
    /// local deadline before anything was selected — reclaims exactly what an
    /// orderly close does, and reports the same count.
    pub fn reclaim_all(&mut self, event: Event, now_ms: u64) -> usize {
        let labels: Vec<[u8; 16]> = self.routes.keys().copied().collect();
        let count = labels.len();
        for label in labels {
            let _ = self.apply(label, event, now_ms);
            // A phase that refuses the event still has to release its state.
            let _ = self.remove(label);
        }
        count
    }

    pub fn remove(&mut self, label: [u8; 16]) -> Result<(), StateError> {
        let route = self.routes.remove(&label).ok_or(StateError::Missing)?;
        drop_one(&mut self.peer_routes, route.peer);
        if matches!(route.phase, Phase::Discovering | Phase::Candidate) {
            drop_one(&mut self.peer_branches, route.peer);
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
        for (event, phase) in [
            (Event::CandidateAccepted, Phase::Candidate),
            (Event::CommitAccepted, Phase::PendingReady),
            (Event::ReadyAccepted, Phase::Ready),
            (Event::CapabilityAccepted, Phase::Open),
        ] {
            table.apply(label, event, 0)?;
            assert_eq!(table.get(&label).map(|route| route.phase), Some(phase));
        }
        // Data is delivered without moving the route on.
        table.apply(label, Event::DataAccepted, 0)?;
        assert_eq!(
            table.get(&label).map(|route| route.phase),
            Some(Phase::Open)
        );
        // Closing reclaims it.
        table.apply(label, Event::CloseAccepted, 0)?;
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
        table.apply(label, Event::CandidateAccepted, 0)?;
        table.apply(label, Event::CandidateAccepted, 5)?;
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
    fn continuous_traffic_does_not_postpone_expiry() -> Result<(), StateError> {
        // E1 section 2 ranks expiry above every message sharing its timestamp,
        // and section 9 requires it to be local and non-blocking. A node that
        // only expired while its event channel was idle would keep lapsed
        // state usable for as long as a peer kept sending, so the loop runs
        // expiry before each event. This models that order.
        let label = [3_u8; 16];
        let mut table = RouteTable::default();
        table.begin(label, 1, 0, 1_000)?;
        table.apply(label, Event::CandidateAccepted, 0)?;
        table.apply(label, Event::CommitAccepted, 0)?;
        table.apply(label, Event::ReadyAccepted, 0)?;

        let deadline = table
            .get(&label)
            .map(|route| route.expires_at_ms)
            .ok_or(StateError::Missing)?;

        // A flood of valid events on other branches, each preceded by one
        // expiry pass, exactly as the node loop now does. None of them belongs
        // to `label`, so none of them may extend its deadline.
        let mut now = 1_u64;
        let mut other = [0_u8; 16];
        while now < deadline {
            table.expire(now);
            other[0] = (now % 251) as u8;
            other[1] = (now / 251) as u8;
            if table.begin(other, 2, 0, now + 5).is_ok() {
                table.apply(other, Event::CandidateAccepted, now).ok();
            }
            now += 1;
        }

        // The very first tick at or past the deadline reclaims the route, and
        // the next control for it is refused rather than processed.
        table.expire(deadline);
        assert!(
            table.get(&label).is_none(),
            "the flood must not extend the deadline"
        );
        assert_eq!(
            table.apply(label, Event::DataAccepted, deadline),
            Err(StateError::Missing),
            "a post-deadline control finds no state"
        );
        Ok(())
    }

    #[test]
    fn reclaim_all_releases_every_phase_including_before_selection() -> Result<(), StateError> {
        // The failure paths end before anything is selected, so a cleanup that
        // only released the selected route stranded exactly the state those
        // paths create. reclaim_all releases every phase, including ones that
        // refuse the event it is given.
        let mut table = RouteTable::default();
        let mut label = [0_u8; 16];
        for (index, phase) in [
            Phase::Discovering,
            Phase::Candidate,
            Phase::PendingReady,
            Phase::Ready,
            Phase::Open,
        ]
        .into_iter()
        .enumerate()
        {
            label[0] = index as u8;
            table.begin(label, 1, 0, 10_000)?;
            let mut events = vec![
                Event::CandidateAccepted,
                Event::CommitAccepted,
                Event::ReadyAccepted,
                Event::CapabilityAccepted,
            ];
            events.truncate(index);
            for event in events {
                table.apply(label, event, 0)?;
            }
            assert_eq!(table.get(&label).map(|route| route.phase), Some(phase));
        }
        assert_eq!(table.live_routes(), 5);

        assert_eq!(table.reclaim_all(Event::Timeout, 1_000), 5);
        assert_eq!(table.live_routes(), 0, "no phase survives the funnel");

        // The per-peer counters come back with it, so a later run of the same
        // table admits fresh branches.
        label[0] = 200;
        table.begin(label, 1, 0, 10_000)?;
        assert_eq!(table.live_routes(), 1);
        Ok(())
    }

    #[test]
    fn the_route_ceiling_is_reachable_once_branches_are_committed() -> Result<(), StateError> {
        // Comparing one per-peer total against both ceilings made the smaller
        // one the only one that ever applied, so a peer could never hold more
        // than 64 routes of any kind and the 256-route ceiling was dead. The
        // two classes are counted separately: committing frees a branch slot
        // while keeping the route slot.
        let mut table = RouteTable::default();
        let mut label = [0_u8; 16];
        let mut committed = 0;
        while committed < LIMIT_MAX_ROUTES_PER_PEER {
            label[0] = (committed % 251) as u8;
            label[1] = (committed / 251) as u8;
            table.begin(label, 1, 0, 10_000)?;
            table.apply(label, Event::CandidateAccepted, 0)?;
            table.apply(label, Event::CommitAccepted, 0)?;
            committed += 1;
        }
        assert_eq!(table.live_routes(), LIMIT_MAX_ROUTES_PER_PEER);

        // The route ceiling now bites, and it is the route ceiling, not the
        // branch one.
        label[0] = 255;
        label[1] = 255;
        assert_eq!(table.begin(label, 1, 0, 10_000), Err(StateError::PeerLimit));

        // Branches are still bounded on their own: from an empty table a peer
        // may hold 64 uncommitted branches and no more.
        let mut branches = RouteTable::default();
        for index in 0..LIMIT_MAX_BRANCHES_PER_PEER {
            label[0] = (index % 251) as u8;
            label[1] = (index / 251) as u8;
            branches.begin(label, 1, 0, 10_000)?;
        }
        label[0] = 255;
        label[1] = 255;
        assert_eq!(
            branches.begin(label, 1, 0, 10_000),
            Err(StateError::PeerLimit),
            "the branch ceiling still applies"
        );
        Ok(())
    }

    #[test]
    fn a_full_route_table_refuses_rather_than_failing() {
        // A remote peer can fill a gateway's route table with canonical,
        // authenticated discoveries. The next one has to come back as a
        // resource refusal the caller counts and drops, never as an error the
        // caller propagates: letting PeerLimit escape run() meant a flood of
        // perfectly valid discoveries terminated the process.
        let mut table = RouteTable::default();
        let mut label = [0_u8; 16];
        let mut admitted = 0;
        let mut refused = 0;
        for index in 0..LIMIT_MAX_BRANCHES_PER_PEER * 2 {
            label[0] = (index % 251) as u8;
            label[1] = (index / 251) as u8;
            match table.begin(label, 1, 0, 10_000) {
                Ok(()) => admitted += 1,
                Err(StateError::PeerLimit | StateError::GlobalLimit) => refused += 1,
                Err(other) => panic!("unexpected admission error: {other}"),
            }
        }
        assert_eq!(admitted, LIMIT_MAX_BRANCHES_PER_PEER);
        assert_eq!(refused, LIMIT_MAX_BRANCHES_PER_PEER);

        // The table is still usable: another peer is unaffected, and space
        // freed by expiry is handed back.
        label[0] = 250;
        label[1] = 250;
        assert!(table.begin(label, 2, 0, 10_000).is_ok(), "another peer");
        assert!(table.expire(20_000) > 0);
        label[0] = 249;
        assert!(
            table.begin(label, 1, 0, 30_000).is_ok(),
            "space is reusable"
        );
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
