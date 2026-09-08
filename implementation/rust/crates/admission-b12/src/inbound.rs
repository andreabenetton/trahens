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

use crate::admission::{Admission, AdmissionError};
use crate::advertisement::{decode, Advertisement};
use crate::candidates::CacheError;
use crate::gate::{GateError, Lease, ReturnRoutable};
use crate::{issue, window_id, CandidateCache, Gate, Secrets};
use link_handshake_b1::{encode_cookie_challenge, peek_admission_header, Profile};
use protocol_registry::{
    B12_DATAGRAM_ADVERTISEMENT, B1_RECORD_ADMISSION_INITIATE, BYTES_B12_ADVERTISEMENT,
    BYTES_B12_INVITATION_ID, BYTES_B1_RECORD, VERSION,
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
    /// A handshake record from a source this node has no way to admit: not a
    /// configured peer, and not an admission initiate on a node holding
    /// admission state.
    NoAdmissionPath,
    /// The cookie verified and the invitation did not. See [`AdmissionError`]:
    /// never issued, already spent, or a key that would not derive.
    Admission(AdmissionError),
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
    /// Send this record and allocate nothing. ADR 0048 D13's challenge: the
    /// sender's cookie did not verify, which is the only thing that provokes
    /// one, and an absent cookie is not distinguished from a wrong one.
    Challenge(Vec<u8>),
    /// An admission handshake may proceed. Drive it with this grant and return
    /// its lease through the gate exactly once.
    Admit(Box<Grant>),
    Drop(DropReason),
}

/// What a caller needs to drive an admission handshake the front end approved.
#[derive(Debug, PartialEq, Eq)]
pub struct Grant {
    pub lease: Lease,
    pub invitation_id: Vec<u8>,
    pub cookie: Vec<u8>,
    /// The `psk0` this exchange keys from, found by the identifier the record
    /// carried in the clear.
    pub psk: [u8; 32],
}

/// One arriving datagram and where it came from.
///
/// Bundled because the cookie binds the source and the port separately, and a
/// receive path that took them as loose parameters could pass them in the wrong
/// order and still compile.
pub struct Datagram<'a> {
    pub source: &'a [u8],
    pub port: u16,
    pub bytes: &'a [u8],
    pub now_ms: u64,
}

/// The receive path of a listening socket, minus the socket.
///
/// Holds the bounded stores an arriving datagram can touch and nothing else, so
/// the whole decision is testable against adversarial input without a network.
pub struct FrontEnd {
    /// Sources with an established link, and the peer each belongs to.
    established: Vec<(Vec<u8>, u32)>,
    cache: CandidateCache,
    gate: Gate,
    /// `None` on a node that cannot admit. ADR 0047 D12 requires a store path
    /// for any node that can, so a node without one has no admission state and
    /// refuses an admission initiate rather than admitting without a record of
    /// what it spent.
    admission: Option<Admission>,
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
            admission: None,
        }
    }

    /// Give this node the admission state that lets it accept joiners.
    #[must_use]
    pub fn with_admission(mut self, admission: Admission) -> Self {
        self.admission = Some(admission);
        self
    }

    #[must_use]
    pub fn admission(&self) -> Option<&Admission> {
        self.admission.as_ref()
    }

    pub fn admission_mut(&mut self) -> Option<&mut Admission> {
        self.admission.as_mut()
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
    /// randomness, not by the receive path. `profile` supplies the record
    /// layout, which belongs to the crate that owns the records.
    pub fn receive(
        &mut self,
        datagram: &Datagram<'_>,
        secrets: &Secrets,
        profile: &Profile,
    ) -> Disposition {
        let Some(kind) = classify(datagram.bytes) else {
            return Disposition::Drop(DropReason::Malformed);
        };
        match kind {
            Kind::Reserved => Disposition::Drop(DropReason::ReservedDiscriminator),
            Kind::Cell => {
                if self.peer_at(datagram.source).is_some() {
                    Disposition::ToLink
                } else {
                    Disposition::Drop(DropReason::NoSuchLink)
                }
            }
            Kind::Advertisement => self.receive_advertisement(datagram),
            Kind::Handshake => self.receive_handshake(datagram, secrets, profile),
        }
    }

    fn receive_advertisement(&mut self, datagram: &Datagram<'_>) -> Disposition {
        if datagram.bytes.len() != BYTES_B12_ADVERTISEMENT {
            return Disposition::Drop(DropReason::Malformed);
        }
        let Ok(advertisement) = decode(datagram.bytes) else {
            return Disposition::Drop(DropReason::Unverified);
        };
        if advertisement.version != VERSION {
            return Disposition::Drop(DropReason::Unverified);
        }
        match self
            .cache
            .observe(datagram.source, &advertisement, datagram.now_ms)
        {
            Ok(()) => Disposition::Cached(Box::new(advertisement)),
            Err(error) => Disposition::Drop(DropReason::Cache(error)),
        }
    }

    fn receive_handshake(
        &mut self,
        datagram: &Datagram<'_>,
        secrets: &Secrets,
        profile: &Profile,
    ) -> Disposition {
        if datagram.bytes.len() != BYTES_B1_RECORD {
            return Disposition::Drop(DropReason::Malformed);
        }
        if datagram.bytes.get(1) == Some(&B1_RECORD_ADMISSION_INITIATE) {
            return self.receive_admission(datagram, secrets, profile);
        }
        // A configured peer is vouched for by the manifest and needs no cookie;
        // it still passes the gate, because section 8's bounds are the answer to
        // an authenticated peer misbehaving, which is the case the manifest
        // cannot rule out.
        if self.peer_at(datagram.source).is_none() {
            return Disposition::Drop(DropReason::NoAdmissionPath);
        }
        match self.gate.allocate(
            &ReturnRoutable::established(datagram.source),
            datagram.now_ms,
        ) {
            Ok(lease) => Disposition::Handshake(lease),
            Err(error) => Disposition::Drop(DropReason::Gate(error)),
        }
    }

    /// The admission path of `link-handshake-b1.md` section 4.1.
    ///
    /// The order is the requirement, and each step is reached only by a sender
    /// that passed the one before: read the header, verify the cookie or
    /// challenge, allocate, then find the invitation.
    ///
    /// **The invitation is looked up after the gate, not before.** Looking it up
    /// first would let anyone holding a cookie probe for valid identifiers at
    /// the cost of a hash lookup; after the gate, a probe spends the prober's
    /// own public-key budget and counts toward its backoff. The lease is
    /// returned as a failure when the lookup refuses, which is what makes that
    /// true rather than merely intended.
    fn receive_admission(
        &mut self,
        datagram: &Datagram<'_>,
        secrets: &Secrets,
        profile: &Profile,
    ) -> Disposition {
        if self.admission.is_none() {
            return Disposition::Drop(DropReason::NoAdmissionPath);
        }
        let Ok((invitation_id, cookie)) = peek_admission_header(profile, datagram.bytes) else {
            return Disposition::Drop(DropReason::Malformed);
        };

        // The cookie's `offer` is the invitation identifier: everything the
        // sender has offered in the clear at the moment one is issued, the rest
        // being encrypted under a key the cookie precedes.
        let Some(routable) = ReturnRoutable::confirm(
            secrets,
            &cookie,
            datagram.source,
            datagram.port,
            &invitation_id,
            datagram.now_ms,
        ) else {
            // Challenged before the invitation is looked up, and whether or not
            // it exists. Challenging only for known identifiers would turn the
            // reply into an oracle for which invitations a node is holding —
            // and, because a spent one stops being known, for which it has
            // already used.
            return match secrets.current() {
                Some(secret) => match issue(
                    secret,
                    datagram.source,
                    datagram.port,
                    window_id(datagram.now_ms),
                    &invitation_id,
                )
                .and_then(|fresh| {
                    encode_cookie_challenge(profile, &invitation_id, &fresh)
                        .map_err(|_| crate::CookieError)
                }) {
                    Ok(record) => Disposition::Challenge(record),
                    Err(_) => Disposition::Drop(DropReason::Malformed),
                },
                None => Disposition::Drop(DropReason::NoAdmissionPath),
            };
        };

        let lease = match self.gate.allocate(&routable, datagram.now_ms) {
            Ok(lease) => lease,
            Err(error) => return Disposition::Drop(DropReason::Gate(error)),
        };

        let Ok(identifier) = <[u8; BYTES_B12_INVITATION_ID]>::try_from(invitation_id.as_slice())
        else {
            self.gate.failed(lease, datagram.now_ms);
            return Disposition::Drop(DropReason::Malformed);
        };
        let psk = match self
            .admission
            .as_ref()
            .ok_or(AdmissionError::UnknownInvitation)
            .and_then(|admission| admission.psk_for(&identifier))
        {
            Ok(psk) => psk,
            Err(error) => {
                self.gate.failed(lease, datagram.now_ms);
                return Disposition::Drop(DropReason::Admission(error));
            }
        };

        Disposition::Admit(Box::new(Grant {
            lease,
            invitation_id,
            cookie,
            psk,
        }))
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
