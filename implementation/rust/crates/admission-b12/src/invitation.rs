// SPDX-License-Identifier: Apache-2.0
//! The pre-shared key a joiner arrives with.
//!
//! ADR 0046: an invitation is per-joiner, single-use, and promotes to a pinned
//! static key when the handshake it keys completes.
//!
//! The invitation is what authenticates here, which is the difference from the
//! manifest path of ADR 0044. There the static-static key is a pre-filter and
//! the pin on the presented static key authenticates; here the joiner's static
//! key is not known in advance, so nothing can be pinned against it and this
//! key carries the weight.

use crate::CookieError;
use protocol_registry::{
    BYTES_B12_INVITATION_ID, BYTES_B12_INVITATION_SECRET, BYTES_X25519_PUBLIC,
    DOMAIN_B12_INVITATION_PSK,
};
use trahens_crypto::hmac_sha256;

/// What a joiner receives out of band.
///
/// The asymmetry is deliberate: the joiner can pin the inviter, because
/// out-of-band delivery can carry the inviter's identity, while the inviter
/// cannot pin the joiner and learns its static key at the first handshake.
pub struct Invitation {
    pub identifier: [u8; BYTES_B12_INVITATION_ID],
    pub secret: [u8; BYTES_B12_INVITATION_SECRET],
    pub inviter_static_public: [u8; BYTES_X25519_PUBLIC],
}

impl Invitation {
    /// Refuse an all-zero secret, which carries no entropy and would key a
    /// handshake anyone could reproduce.
    pub fn new(
        identifier: [u8; BYTES_B12_INVITATION_ID],
        secret: [u8; BYTES_B12_INVITATION_SECRET],
        inviter_static_public: [u8; BYTES_X25519_PUBLIC],
    ) -> Result<Self, CookieError> {
        if secret == [0_u8; BYTES_B12_INVITATION_SECRET] {
            return Err(CookieError);
        }
        Ok(Self {
            identifier,
            secret,
            inviter_static_public,
        })
    }

    pub fn psk(&self) -> Result<[u8; 32], CookieError> {
        invitation_psk(&self.identifier, &self.secret)
    }
}

/// The `psk0` pre-shared key for a handshake keyed by this invitation.
///
/// The identifier is bound in as well as the secret, so a secret cannot be
/// presented under an identifier it was not issued with. It is length-prefixed
/// for the same reason the cookie's fields are: two different inputs must not
/// build the same message.
pub fn invitation_psk(
    identifier: &[u8; BYTES_B12_INVITATION_ID],
    secret: &[u8; BYTES_B12_INVITATION_SECRET],
) -> Result<[u8; 32], CookieError> {
    let mut message =
        Vec::with_capacity(DOMAIN_B12_INVITATION_PSK.len() + BYTES_B12_INVITATION_ID + 2);
    message.extend_from_slice(DOMAIN_B12_INVITATION_PSK);
    message.extend_from_slice(
        &u16::try_from(identifier.len())
            .map_err(|_| CookieError)?
            .to_be_bytes(),
    );
    message.extend_from_slice(identifier);
    Ok(hmac_sha256(secret, &message)?)
}
