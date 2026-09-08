// SPDX-License-Identifier: Apache-2.0
//! Deciding what an arriving datagram is, and what it is allowed to consume.
//!
//! A node with a listening socket receives from anyone. Every datagram that
//! reaches it is attacker-controlled until something says otherwise, so the
//! first question is what kind of thing it claims to be, and the second is
//! whether the sender may have the resource that answering it would cost.
//!
//! `link-handshake-b1.md` section 3 allocates the first byte and states the rule
//! this module exists to implement: a receiver that adds a datagram type **MUST**
//! check the reserved range before attempting W2, or the new type is eaten by
//! the cell path. A reserved byte is therefore refused here rather than falling
//! through to be tried as a cell with an unopenable epoch — which would look
//! identical in a metrics file and would silently swallow every type added
//! later.

use crate::advertisement::{decode, Advertisement};
use crate::candidates::CacheError;
use crate::gate::{GateError, Lease, ReturnRoutable};
use crate::{CandidateCache, Gate, Secrets};
use protocol_registry::{
    B12_DATAGRAM_ADVERTISEMENT, BYTES_B12_ADVERTISEMENT, BYTES_B1_RECORD, VERSION,
};

/// What the first byte says a datagram is.
///
/// This is a claim by the sender, not a fact: classifying costs one comparison
/// and commits nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `0x00` — a B1.1 handshake record; the next byte is the record type.
    Handshake,
    /// `0x01` — a B1.2 discovery advertisement.
    Advertisement,
    /// `0x02`–`0x7f` — reserved by section 3 and defined by nothing. Refused
    /// here so that a type added later is not eaten by the cell path.
    Reserved,
    /// `0x80`–`0xff` — a W2 cell, the leading byte of a derived epoch.
    Cell,
}

/// Classify by first byte alone. An empty datagram is not any of these.
#[must_use]
pub fn classify(datagram: &[u8]) -> Option<Kind> {
    match datagram.first()? {
        0x00 => Some(Kind::Handshake),
        byte if *byte == B12_DATAGRAM_ADVERTISEMENT => Some(Kind::Advertisement),
        0x01..=0x7f => Some(Kind::Reserved),
        _ => Some(Kind::Cell),
    }
}

/// Why a datagram was dropped.
///
/// A node counts these; it never tells the sender which one applied. They are
/// distinguished because "the cache is full" and "the signature is wrong" are
/// different operational facts, and a single counter for both would hide a flood
/// behind a parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Empty, or not the fixed width its claimed kind requires.
    Malformed,
    /// A first byte section 3 reserves. Never attempted as a cell.
    ReservedDiscriminator,
    /// The advertisement did not parse or did not verify under the key it
    /// carries.
    Unverified,
    /// The advertisement verified but the candidate cache would not hold it.
    Cache(CacheError),
    /// A handshake record from a source no bound would let allocate a context.
    Gate(GateError),
    /// A handshake record from a source this node has no way to admit.
    ///
    /// The manifest path needs a configured peer, and the invitation path needs
    /// a first message carrying an invitation identifier and a cookie, whose
    /// framing is not yet specified. Until it is, a stranger's handshake record
    /// is refused here, before any state.
    NoAdmissionPath,
    /// A W2 cell from a source that owns no established link. There is nothing
    /// to open it with, and allocating on an unauthenticated cell is exactly
    /// what the connected-socket topology used to make impossible.
    NoSuchLink,
}

/// What the caller should do with a datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Hand to the established link that owns this source.
    ToLink,
    /// Drive a handshake under this lease, and return it through
    /// [`Gate::succeeded`](crate::Gate::succeeded) or
    /// [`Gate::failed`](crate::Gate::failed) exactly once.
    Handshake(Lease),
    /// A verified advertisement was cached or refreshed. Nothing else happens:
    /// ADR 0045 D6 forbids discovery from allocating anything but this.
    Cached(Box<Advertisement>),
    Drop(DropReason),
}

/// The receive path of a listening socket, minus the socket.
///
/// Holds the two bounded stores an arriving datagram can touch and nothing
/// else, so the whole decision is testable against adversarial input without a
/// network.
pub struct FrontEnd {
    /// Sources with an established link, and the peer each belongs to.
    established: Vec<(Vec<u8>, u32)>,
    cache: CandidateCache,
    gate: Gate,
}

impl Default for FrontEnd {
    fn default() -> Self {
        Self::new()
    }
}

impl FrontEnd {
    #[must_use]
    pub fn new() -> Self {
        Self {
            established: Vec::new(),
            cache: CandidateCache::new(),
            gate: Gate::new(),
        }
    }

    /// Record that a source owns an established link.
    pub fn link_established(&mut self, source: &[u8], peer_id: u32) {
        self.established.retain(|(held, _)| held != source);
        self.established.push((source.to_vec(), peer_id));
    }

    pub fn link_lost(&mut self, source: &[u8]) {
        self.established.retain(|(held, _)| held != source);
    }

    #[must_use]
    pub fn peer_at(&self, source: &[u8]) -> Option<u32> {
        self.established
            .iter()
            .find(|(held, _)| held == source)
            .map(|(_, peer_id)| *peer_id)
    }

    /// Decide what one datagram is and what it may consume.
    ///
    /// `secrets` is the responder's cookie state; it is passed in rather than
    /// held because rotation is driven by the node's clock and its source of
    /// randomness, not by the receive path.
    pub fn receive(
        &mut self,
        source: &[u8],
        datagram: &[u8],
        secrets: &Secrets,
        now_ms: u64,
    ) -> Disposition {
        let Some(kind) = classify(datagram) else {
            return Disposition::Drop(DropReason::Malformed);
        };
        match kind {
            Kind::Reserved => Disposition::Drop(DropReason::ReservedDiscriminator),
            Kind::Cell => {
                if self.peer_at(source).is_some() {
                    Disposition::ToLink
                } else {
                    Disposition::Drop(DropReason::NoSuchLink)
                }
            }
            Kind::Advertisement => self.receive_advertisement(source, datagram, now_ms),
            Kind::Handshake => self.receive_handshake(source, datagram, secrets, now_ms),
        }
    }

    fn receive_advertisement(
        &mut self,
        source: &[u8],
        datagram: &[u8],
        now_ms: u64,
    ) -> Disposition {
        if datagram.len() != BYTES_B12_ADVERTISEMENT {
            return Disposition::Drop(DropReason::Malformed);
        }
        let Ok(advertisement) = decode(datagram) else {
            return Disposition::Drop(DropReason::Unverified);
        };
        if advertisement.version != VERSION {
            return Disposition::Drop(DropReason::Unverified);
        }
        match self.cache.observe(source, &advertisement, now_ms) {
            Ok(()) => Disposition::Cached(Box::new(advertisement)),
            Err(error) => Disposition::Drop(DropReason::Cache(error)),
        }
    }

    fn receive_handshake(
        &mut self,
        source: &[u8],
        datagram: &[u8],
        _secrets: &Secrets,
        now_ms: u64,
    ) -> Disposition {
        if datagram.len() != BYTES_B1_RECORD {
            return Disposition::Drop(DropReason::Malformed);
        }
        // A configured peer is vouched for by the manifest and needs no cookie;
        // it still passes the gate, because section 8's bounds are the answer to
        // an authenticated peer misbehaving, which is the case the manifest
        // cannot rule out.
        if self.peer_at(source).is_none() {
            return Disposition::Drop(DropReason::NoAdmissionPath);
        }
        match self
            .gate
            .allocate(&ReturnRoutable::established(source), now_ms)
        {
            Ok(lease) => Disposition::Handshake(lease),
            Err(error) => Disposition::Drop(DropReason::Gate(error)),
        }
    }

    #[must_use]
    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    pub fn gate_mut(&mut self) -> &mut Gate {
        &mut self.gate
    }

    #[must_use]
    pub fn cache(&self) -> &CandidateCache {
        &self.cache
    }

    pub fn cache_mut(&mut self) -> &mut CandidateCache {
        &mut self.cache
    }
}
