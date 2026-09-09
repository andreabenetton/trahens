// SPDX-License-Identifier: Apache-2.0
//! The inviter's side of admission: which invitations are live, which are
//! spent, and which static keys have been promoted.
//!
//! ADR 0046 D8 and D9 over the store of ADR 0047. The cryptography was already
//! here — [`invitation_psk`] derives the key — and what
//! was missing is the part that decides *whether* to derive it and what to write
//! down afterwards.
//!
//! Nothing here touches a socket or a handshake. It is the decision and the
//! durable record, so it can be tested against the failures that matter without
//! a network.

use crate::invitation::{invitation_psk, Invitation};
use crate::store::{Record, Store, StoreError};
use protocol_registry::{BYTES_B12_INVITATION_ID, BYTES_X25519_PUBLIC};
use std::collections::HashMap;
use std::path::Path;

/// Why an admission was refused.
///
/// Unlike [`CookieError`](crate::CookieError), these are not returned to a
/// sender: the decision a peer sees is still one outcome. They are separated
/// because the node's own operator needs to tell "never issued" from "already
/// used" from "the disk refused the write".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// No live invitation with that identifier. Covers both an identifier this
    /// node never issued and one it has since withdrawn.
    UnknownInvitation,
    /// D8: single-use. The invitation completed a handshake already, and the
    /// spent marker survived the restart it was written for.
    AlreadySpent,
    /// The peer identifier is pinned to a different static key. Overwriting it
    /// would let a second joiner take the place of the first, so the pin has to
    /// be withdrawn deliberately first.
    PeerIdInUse,
    /// The durable record could not be written, so the admission did not
    /// happen. See [`StoreError`].
    Store(StoreError),
    /// The pre-shared key could not be derived.
    Derivation,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownInvitation => {
                formatter.write_str("no live invitation with that identifier")
            }
            Self::AlreadySpent => formatter.write_str("invitation already spent"),
            Self::PeerIdInUse => formatter.write_str("peer identifier pinned to a different key"),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Derivation => formatter.write_str("invitation key derivation failed"),
        }
    }
}

impl std::error::Error for AdmissionError {}

impl From<StoreError> for AdmissionError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// A node's admission state.
pub struct Admission {
    live: HashMap<[u8; BYTES_B12_INVITATION_ID], Invitation>,
    store: Store,
}

impl Admission {
    /// Load the durable state. ADR 0047 D12 makes the path required for any
    /// node that can admit, which is why there is no constructor without one.
    ///
    /// # Errors
    ///
    /// [`StoreError::Damaged`] if the store exists and does not parse; a node
    /// that cannot read what it already spent does not start.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            live: HashMap::new(),
            store: Store::open(path)?,
        })
    }

    /// Offer an invitation this node issued.
    ///
    /// Live invitations are not persisted: they are handed out by an operator
    /// and re-supplied at startup, and writing them down would put a secret
    /// that authenticates a joiner into a file whose whole security argument is
    /// that it holds no secrets. What must survive a restart is the *spent*
    /// marker, and that does.
    pub fn offer(&mut self, invitation: Invitation) {
        self.live.insert(invitation.identifier, invitation);
    }

    /// Withdraw an invitation before it is used. Distinct from spending it: it
    /// leaves nothing on disk, because an invitation that never completed a
    /// handshake is one a restart can simply not re-offer.
    pub fn withdraw(&mut self, identifier: &[u8; BYTES_B12_INVITATION_ID]) {
        self.live.remove(identifier);
    }

    /// The `psk0` for the handshake an initiator is asking to key.
    ///
    /// D8's consequence: the identifier arrives in the clear on the first
    /// message precisely so this is one lookup rather than a trial decryption
    /// against every live invitation. Both refusals happen before any
    /// public-key operation, so a replayed identifier costs a hash lookup.
    ///
    /// # Errors
    ///
    /// [`AdmissionError::UnknownInvitation`] or [`AdmissionError::AlreadySpent`].
    pub fn psk_for(
        &self,
        identifier: &[u8; BYTES_B12_INVITATION_ID],
    ) -> Result<[u8; 32], AdmissionError> {
        if self.store.is_spent(identifier) {
            return Err(AdmissionError::AlreadySpent);
        }
        let invitation = self
            .live
            .get(identifier)
            .ok_or(AdmissionError::UnknownInvitation)?;
        invitation_psk(identifier, &invitation.secret).map_err(|_| AdmissionError::Derivation)
    }

    /// Spend the invitation and pin the static key the joiner presented.
    ///
    /// **Call this before completing the handshake, not after.** Both records
    /// are on disk when this returns; a handshake completed first is one a crash
    /// can leave admitted with nothing written down.
    ///
    /// The spent marker is written before the pin, and the order is the
    /// fail-safe one. A crash between the two loses the pin and leaves the
    /// invitation spent, so the joiner has to be re-invited — recoverable. The
    /// reverse order would lose the spent marker while keeping the pin, which
    /// re-opens the invitation for a *second* static key. Locking a joiner out
    /// is an inconvenience; admitting an extra one is the failure D8 exists to
    /// prevent.
    ///
    /// # Errors
    ///
    /// The refusals of [`Self::psk_for`], plus
    /// [`AdmissionError::PeerIdInUse`] and any [`StoreError`].
    pub fn admit(
        &mut self,
        identifier: &[u8; BYTES_B12_INVITATION_ID],
        peer_id: u32,
        static_public: [u8; BYTES_X25519_PUBLIC],
    ) -> Result<(), AdmissionError> {
        if self.store.is_spent(identifier) {
            return Err(AdmissionError::AlreadySpent);
        }
        if !self.live.contains_key(identifier) {
            return Err(AdmissionError::UnknownInvitation);
        }
        match self.store.pinned(peer_id) {
            Some(existing) if existing != static_public => return Err(AdmissionError::PeerIdInUse),
            _ => {}
        }

        self.store.append(&Record::InvitationSpent {
            identifier: *identifier,
        })?;
        self.store.append(&Record::PeerPinned {
            peer_id,
            static_public,
        })?;
        self.live.remove(identifier);
        Ok(())
    }

    /// D9's removal: withdraw a pinned key at this node.
    ///
    /// It says nothing to any other node and does not tear down a link already
    /// established. What it does is stop the next handshake from that peer, and
    /// survive a restart, which is the whole of what B1.2 claims.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`] from recording the removal.
    pub fn remove(&mut self, peer_id: u32) -> Result<(), AdmissionError> {
        self.store.append(&Record::PeerRemoved { peer_id })?;
        Ok(())
    }

    /// The static key pinned for `peer_id`, for the manifest path of ADR 0044.
    #[must_use]
    pub fn pinned(&self, peer_id: u32) -> Option<[u8; BYTES_X25519_PUBLIC]> {
        self.store.pinned(peer_id)
    }

    /// Whether an invitation has been spent, whether or not it is still offered.
    #[must_use]
    pub fn is_spent(&self, identifier: &[u8; BYTES_B12_INVITATION_ID]) -> bool {
        self.store.is_spent(identifier)
    }

    /// How many invitations are outstanding. The bound on this is a deployment
    /// question, not a protocol one: D8's identifier-in-the-clear keeps the
    /// responder's per-message work constant however many are live.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.live.len()
    }
}
