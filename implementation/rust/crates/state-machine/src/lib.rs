#![forbid(unsafe_code)]
#![doc = "Typed event-driven route state machines for P1 nodes."]

use protocol_registry::{LIMIT_MAX_ROUTES_GLOBAL, LIMIT_MAX_ROUTES_PER_PEER};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Discovering,
    Candidate,
    Committed,
    Ready,
    Open,
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

#[derive(Debug, Clone)]
pub struct RouteState {
    pub phase: Phase,
    pub peer: u32,
    pub generation: u32,
    pub expires_at_ms: u64,
}

#[derive(Debug, Default)]
pub struct RouteTable {
    routes: HashMap<[u8; 16], RouteState>,
    peer_counts: HashMap<u32, usize>,
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
        let count = self.peer_counts.get(&peer).copied().unwrap_or(0);
        if count >= LIMIT_MAX_ROUTES_PER_PEER {
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
        Ok(())
    }

    pub fn apply(&mut self, label: [u8; 16], event: Event) -> Result<Action, StateError> {
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
            (Phase::Candidate, Event::CommitAccepted) => {
                state.phase = Phase::Committed;
                Action::ReserveRoute
            }
            (Phase::Committed, Event::ReadyAccepted) => {
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
        Ok(transition)
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
            table.apply(label, Event::CandidateAccepted)?,
            Action::StoreCandidate
        );
        assert_eq!(
            table.apply(label, Event::CommitAccepted)?,
            Action::ReserveRoute
        );
        assert_eq!(
            table.apply(label, Event::ReadyAccepted)?,
            Action::ActivateRoute
        );
        assert_eq!(
            table.apply(label, Event::CapabilityAccepted)?,
            Action::OpenRendezvous
        );
        assert_eq!(
            table.apply(label, Event::DataAccepted)?,
            Action::DeliverData
        );
        assert_eq!(
            table.apply(label, Event::CloseAccepted)?,
            Action::ReclaimState
        );
        assert_eq!(table.live_routes(), 0);
        Ok(())
    }

    #[test]
    fn invalid_transition_does_not_change_state() -> Result<(), StateError> {
        let label = [2_u8; 16];
        let mut table = RouteTable::default();
        table.begin(label, 1, 0, 100)?;
        assert_eq!(
            table.apply(label, Event::ReadyAccepted),
            Err(StateError::InvalidTransition)
        );
        assert_eq!(
            table.get(&label).map(|route| route.phase),
            Some(Phase::Discovering)
        );
        Ok(())
    }
}
