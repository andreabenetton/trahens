# SPDX-License-Identifier: Apache-2.0
"""Trahens B1.2 invitation reference: the pre-shared key a joiner arrives with.

ADR 0045 chose the invitation model, and ADR 0046 fixed its scoping: an
invitation is per-joiner, single-use, and promotes to a pinned static key when
the handshake it keys completes.

The invitation is what authenticates in this case, which is the difference from
the manifest path of ADR 0044. There, the pre-shared key derived from the
static-static value is a pre-filter and the pin on the presented static key is
what authenticates. Here the joiner's static key is not known in advance -- that
is the whole point -- so nothing can be pinned against it, and the key derived
below carries the weight.

An invitation is delivered out of band as three values: an identifier, a
secret, and the inviter's static public key. The asymmetry is deliberate. The
joiner can pin the inviter, because out-of-band delivery can carry the
inviter's identity; the inviter cannot pin the joiner, and learns its static
key at the first handshake instead.

This reference exists to publish vectors. It is not independently audited and
MUST NOT be used as production security code.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from trahens_spec.generated import (
    BYTES_B12_INVITATION_ID,
    BYTES_B12_INVITATION_SECRET,
    BYTES_X25519_PUBLIC,
    DOMAIN_B12_INVITATION_PSK,
)

HASHLEN = 32


class InvitationError(ValueError):
    """Any failure. A joiner is never told which check refused it."""


@dataclass(frozen=True)
class Invitation:
    """What a joiner receives out of band.

    The identifier travels in the clear in the first message, because a
    responder must know which invitation to derive the key from before it can
    decrypt anything. Trial-decrypting against every live invitation would make
    that work linear in the number outstanding, which is the exhaustion the
    admission cookie exists to bound; ADR 0046 records the trade.

    That the identifier is acceptable on an unauthenticated datagram rests
    entirely on it being random, per-invitation and consumed at first use. It is
    not a durable handle for the joiner, and would become one if invitations
    were ever made reusable.
    """

    identifier: bytes
    secret: bytes
    inviter_static_public: bytes

    def __post_init__(self) -> None:
        if len(self.identifier) != BYTES_B12_INVITATION_ID:
            raise InvitationError("invitation identifier must be 16 bytes")
        if len(self.secret) != BYTES_B12_INVITATION_SECRET:
            raise InvitationError("invitation secret must be 32 bytes")
        if len(self.inviter_static_public) != BYTES_X25519_PUBLIC:
            raise InvitationError("inviter static public must be 32 bytes")
        if self.secret == bytes(BYTES_B12_INVITATION_SECRET):
            raise InvitationError("invitation secret must not be zero")


def invitation_psk(identifier: bytes, secret: bytes) -> bytes:
    """The psk0 pre-shared key for a handshake keyed by this invitation.

    The identifier is bound in as well as the secret, so a secret cannot be
    presented under a different identifier than the one it was issued with. It
    is length-prefixed for the same reason the cookie's fields are: two
    different inputs must not build the same message.
    """
    if len(identifier) != BYTES_B12_INVITATION_ID:
        raise InvitationError("invitation identifier must be 16 bytes")
    if len(secret) != BYTES_B12_INVITATION_SECRET:
        raise InvitationError("invitation secret must be 32 bytes")
    message = (
        DOMAIN_B12_INVITATION_PSK
        + len(identifier).to_bytes(2, "big")
        + identifier
    )
    return hmac.new(secret, message, hashlib.sha256).digest()[:HASHLEN]
