# SPDX-License-Identifier: Apache-2.0
"""Trahens end-to-end route channel reference (Core v1.7 onward).

The route channel spans the initiator and the gateway and is the only layer
whose key both of them hold. It exists because hop-by-hop replay protection
structurally cannot reject an end-to-end replay: a relay on the path can
re-send a recorded protected body inside a transmission it generates itself,
carrying a fresh adjacent-link sequence that W2 correctly admits as new link
traffic. See `spec/core-v1.8.md` section 7.1 and ADR 0041.

This reference exists to publish vectors. The layer was added to close TR-01 of
the 2026-09-04 review, and until these vectors it was the one protocol layer
with no cross-implementation check: a third-party implementer had nothing
normative to reproduce, and the Rust implementation agreed only with itself.

It is not independently audited and MUST NOT be used as production security
code.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from trahens_spec.generated import (
    BYTES_ROUTE_DIRECTION,
    BYTES_ROUTE_NONCE,
    BYTES_ROUTE_SEQUENCE,
    DOMAIN_P1_ROUTE_EXTRACT,
    DOMAIN_P1_ROUTE_KEY_E2G,
    DOMAIN_P1_ROUTE_KEY_G2E,
)

KEY_BYTES = 32
TAG_BYTES = 16

ENDPOINT_TO_GATEWAY = 0
GATEWAY_TO_ENDPOINT = 1


class RouteError(ValueError):
    """Any failure. Callers must not distinguish causes on the wire."""


def _hkdf_extract(ikm: bytes) -> bytes:
    # Salt is 32 zero bytes, matching the implementation's hkdf_extract.
    return hmac.new(bytes(KEY_BYTES), ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0 or length > 255 * hashlib.sha256().digest_size:
        raise RouteError("invalid HKDF output length")
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
        counter += 1
    return output[:length]


def _direction_domain(direction: int) -> bytes:
    if direction == ENDPOINT_TO_GATEWAY:
        return DOMAIN_P1_ROUTE_KEY_E2G
    if direction == GATEWAY_TO_ENDPOINT:
        return DOMAIN_P1_ROUTE_KEY_G2E
    raise RouteError("unknown route direction")


@dataclass(frozen=True)
class RouteKeys:
    endpoint_to_gateway: bytes
    gateway_to_endpoint: bytes

    def direction(self, direction: int) -> bytes:
        if direction == ENDPOINT_TO_GATEWAY:
            return self.endpoint_to_gateway
        if direction == GATEWAY_TO_ENDPOINT:
            return self.gateway_to_endpoint
        raise RouteError("unknown route direction")


def route_keys(route_secret: bytes, offer_transcript_hash: bytes) -> RouteKeys:
    """Derive both directional keys from the route secret.

    The selected offer's transcript hash is the expansion context, so a route
    secret presented under any other offer derives different keys and fails
    closed. An all-zero secret is refused rather than silently keying the
    channel off a value that carries no entropy.
    """
    if len(route_secret) != KEY_BYTES:
        raise RouteError("route secret must be 32 bytes")
    if route_secret == bytes(KEY_BYTES):
        raise RouteError("route secret must not be zero")
    if len(offer_transcript_hash) != KEY_BYTES:
        raise RouteError("offer transcript hash must be 32 bytes")
    prk = _hkdf_extract(DOMAIN_P1_ROUTE_EXTRACT + route_secret)
    return RouteKeys(
        endpoint_to_gateway=_hkdf_expand(
            prk, _direction_domain(ENDPOINT_TO_GATEWAY) + offer_transcript_hash, KEY_BYTES
        ),
        gateway_to_endpoint=_hkdf_expand(
            prk, _direction_domain(GATEWAY_TO_ENDPOINT) + offer_transcript_hash, KEY_BYTES
        ),
    )


def route_nonce(direction: int, sequence: int) -> bytes:
    """Direction code then sequence, both big-endian.

    The direction occupies its own field rather than a bit of the sequence, so
    the two directions cannot collide on a nonce however far either advances.
    """
    if direction not in (ENDPOINT_TO_GATEWAY, GATEWAY_TO_ENDPOINT):
        raise RouteError("unknown route direction")
    if not 0 <= sequence < 2**64:
        raise RouteError("sequence out of range")
    nonce = direction.to_bytes(BYTES_ROUTE_DIRECTION, "big") + sequence.to_bytes(
        BYTES_ROUTE_SEQUENCE, "big"
    )
    if len(nonce) != BYTES_ROUTE_NONCE:
        raise RouteError("nonce width mismatch")
    return nonce


def route_seal(key: bytes, direction: int, sequence: int, plaintext: bytes, aad: bytes) -> bytes:
    """Seal one record. The nonce is carried in front of the ciphertext."""
    if len(key) != KEY_BYTES:
        raise RouteError("route key must be 32 bytes")
    nonce = route_nonce(direction, sequence)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def route_open(key: bytes, expected_direction: int, sealed: bytes, aad: bytes) -> tuple[int, bytes]:
    """Open a record, returning its authenticated sequence and plaintext.

    The sequence is returned rather than trusted from the payload: it is what
    the caller checks against its replay window, and it is authenticated
    because the nonce is the AEAD nonce. The direction is checked first so a
    record travelling the wrong way is refused before any decryption, though
    the per-direction keys would refuse it in any case.
    """
    if len(key) != KEY_BYTES:
        raise RouteError("route key must be 32 bytes")
    if len(sealed) < BYTES_ROUTE_NONCE + TAG_BYTES:
        raise RouteError("record is too short to be sealed")
    nonce, ciphertext = sealed[:BYTES_ROUTE_NONCE], sealed[BYTES_ROUTE_NONCE:]
    direction = int.from_bytes(nonce[:BYTES_ROUTE_DIRECTION], "big")
    if direction != expected_direction:
        raise RouteError("record travels the other direction")
    sequence = int.from_bytes(nonce[BYTES_ROUTE_DIRECTION:], "big")
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as error:
        raise RouteError("authentication failed") from error
    return sequence, plaintext


def control_aad(message_type: int, generation: int) -> bytes:
    """The associated data every control record binds.

    Binding the message type stops a sealed body being presented as a different
    control message, and the generation stops one from a superseded generation
    being accepted in a later one.
    """
    if not 0 <= message_type < 256:
        raise RouteError("message type out of range")
    if not 0 <= generation < 2**32:
        raise RouteError("generation out of range")
    return bytes([message_type]) + generation.to_bytes(4, "big")
