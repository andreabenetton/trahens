# SPDX-License-Identifier: Apache-2.0
"""Trahens B1.2 discovery advertisement reference.

`network-bootstrap-b1.md` section 6 fixes what an advertisement may carry and
what it must not. ADR 0045 D4 makes it a fixed-width datagram padded to the
cell length, and D5 has it advertise under a short-lived key rather than a
long-term identity.

The datagram is one cell wide because discovery precedes any link, so there is
no encryption to hide a length under. A variable-length advertisement would
leak its shape on the wire and would make captures non-uniform, which the
harness's 1,052-byte assertion relies on.

**What is deliberately absent.** The advertisement carries no binding from the
short-lived key to the admission identity it will eventually use. That binding
is D5's "signed transition", and it cannot live here: putting the admission
static key in an unauthenticated datagram is exactly the stable network-wide
identifier section 6 forbids, and exactly what advertising under the long-term
key was rejected for. The transition belongs inside the handshake transcript,
where it is protected. This module therefore proves only that the advertiser
holds the short-lived key and that the fields have not been altered.

This reference exists to publish vectors. It is not independently audited and
MUST NOT be used as production security code.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from trahens_spec.generated import (
    B12_DATAGRAM_ADVERTISEMENT,
    BYTES_B12_ADVERTISEMENT,
    BYTES_B12_ADVERTISEMENT_BODY,
    BYTES_B12_ADVERTISEMENT_SIGNATURE,
    BYTES_B12_COOKIE,
    DOMAIN_B12_ADVERTISEMENT,
)

MAX_LIST = 8


class AdvertisementError(ValueError):
    """Any failure. A reader never says which check refused a datagram."""


@dataclass(frozen=True)
class Advertisement:
    """What section 6 permits, and nothing else.

    No descriptor, no capability, no route label, and no stable identifier:
    `key` is short-lived and is the only identity here.
    """

    version: int
    key: bytes
    expiry_ms: int
    capacity_class: int
    auth_modes: int
    w2_profiles: tuple[int, ...]
    t1_profiles: tuple[int, ...]
    t2_profiles: tuple[int, ...]
    suites: tuple[int, ...]
    cookie: bytes | None = None


def _list_bytes(values: tuple[int, ...], width: int) -> bytes:
    if not 1 <= len(values) <= MAX_LIST:
        raise AdvertisementError("profile list out of range")
    out = bytes([len(values)])
    for value in values:
        if not 0 <= value < 256**width:
            raise AdvertisementError("profile identifier out of range")
        out += value.to_bytes(width, "big")
    return out


def _take_list(data: bytes, cursor: int, width: int) -> tuple[tuple[int, ...], int]:
    if cursor >= len(data):
        raise AdvertisementError("truncated profile list")
    count = data[cursor]
    cursor += 1
    if not 1 <= count <= MAX_LIST:
        raise AdvertisementError("profile list out of range")
    values = []
    for _ in range(count):
        chunk = data[cursor : cursor + width]
        if len(chunk) != width:
            raise AdvertisementError("truncated profile list")
        values.append(int.from_bytes(chunk, "big"))
        cursor += width
    return tuple(values), cursor


def encode_body(advertisement: Advertisement) -> bytes:
    if not 0 <= advertisement.version < 256:
        raise AdvertisementError("version out of range")
    if len(advertisement.key) != 32:
        raise AdvertisementError("advertisement key must be 32 bytes")
    if not 0 <= advertisement.expiry_ms < 2**64:
        raise AdvertisementError("expiry out of range")
    if not 0 <= advertisement.capacity_class < 256:
        raise AdvertisementError("capacity class out of range")
    if not 0 <= advertisement.auth_modes < 256:
        raise AdvertisementError("auth modes out of range")
    body = (
        bytes([advertisement.version])
        + advertisement.key
        + advertisement.expiry_ms.to_bytes(8, "big")
        + bytes([advertisement.capacity_class, advertisement.auth_modes])
        + _list_bytes(advertisement.w2_profiles, 1)
        + _list_bytes(advertisement.t1_profiles, 1)
        + _list_bytes(advertisement.t2_profiles, 1)
        + _list_bytes(advertisement.suites, 2)
    )
    if advertisement.cookie is None:
        return body + bytes([0])
    if len(advertisement.cookie) != BYTES_B12_COOKIE:
        raise AdvertisementError("cookie must be the registry width")
    return body + bytes([1]) + advertisement.cookie


def decode_body(body: bytes) -> Advertisement:
    if len(body) < 44:
        raise AdvertisementError("truncated advertisement")
    version = body[0]
    key = body[1:33]
    expiry_ms = int.from_bytes(body[33:41], "big")
    capacity_class = body[41]
    auth_modes = body[42]
    cursor = 43
    w2, cursor = _take_list(body, cursor, 1)
    t1, cursor = _take_list(body, cursor, 1)
    t2, cursor = _take_list(body, cursor, 1)
    suites, cursor = _take_list(body, cursor, 2)
    if cursor >= len(body):
        raise AdvertisementError("truncated advertisement")
    present = body[cursor]
    cursor += 1
    if present == 0:
        cookie = None
    elif present == 1:
        cookie = body[cursor : cursor + BYTES_B12_COOKIE]
        if len(cookie) != BYTES_B12_COOKIE:
            raise AdvertisementError("truncated cookie")
        cursor += BYTES_B12_COOKIE
    else:
        raise AdvertisementError("cookie flag is not canonical")
    if cursor != len(body):
        raise AdvertisementError("trailing bytes after the advertisement")
    return Advertisement(
        version, key, expiry_ms, capacity_class, auth_modes, w2, t1, t2, suites, cookie
    )


def _frame(body: bytes) -> bytes:
    """Length, body, then zeros to the fixed width, as B1.1 frames a payload."""
    if len(body) + 2 > BYTES_B12_ADVERTISEMENT_BODY:
        raise AdvertisementError("advertisement does not fit its datagram")
    return (
        len(body).to_bytes(2, "big")
        + body
        + bytes(BYTES_B12_ADVERTISEMENT_BODY - 2 - len(body))
    )


def _unframe(framed: bytes) -> bytes:
    if len(framed) != BYTES_B12_ADVERTISEMENT_BODY:
        raise AdvertisementError("framed region is the wrong width")
    length = int.from_bytes(framed[:2], "big")
    if 2 + length > BYTES_B12_ADVERTISEMENT_BODY:
        raise AdvertisementError("declared length overruns the datagram")
    if framed[2 + length :] != bytes(BYTES_B12_ADVERTISEMENT_BODY - 2 - length):
        raise AdvertisementError("padding is not zero")
    return framed[2 : 2 + length]


def encode(advertisement: Advertisement, signing_seed: bytes) -> bytes:
    """One signed datagram, exactly `b12_advertisement` bytes.

    The signature covers the discriminator and the whole framed region, padding
    included, so neither the type byte nor the padding can be altered without
    detection.
    """
    if len(signing_seed) != 32:
        raise AdvertisementError("signing seed must be 32 bytes")
    framed = _frame(encode_body(advertisement))
    signed = bytes([B12_DATAGRAM_ADVERTISEMENT]) + framed
    signature = Ed25519PrivateKey.from_private_bytes(signing_seed).sign(
        DOMAIN_B12_ADVERTISEMENT + signed
    )
    datagram = signed + signature
    if len(datagram) != BYTES_B12_ADVERTISEMENT:
        raise AdvertisementError("datagram width mismatch")
    return datagram


def decode(datagram: bytes) -> Advertisement:
    """Parse and verify. The key that signed is the key the datagram carries.

    That is all this establishes: the advertiser holds the short-lived key and
    the fields are intact. It says nothing about which identity the advertiser
    will admit under, which is the transition the handshake carries.
    """
    if len(datagram) != BYTES_B12_ADVERTISEMENT:
        raise AdvertisementError("advertisement is the wrong width")
    if datagram[0] != B12_DATAGRAM_ADVERTISEMENT:
        raise AdvertisementError("not an advertisement")
    signed = datagram[: BYTES_B12_ADVERTISEMENT - BYTES_B12_ADVERTISEMENT_SIGNATURE]
    signature = datagram[BYTES_B12_ADVERTISEMENT - BYTES_B12_ADVERTISEMENT_SIGNATURE :]
    advertisement = decode_body(_unframe(signed[1:]))
    try:
        Ed25519PublicKey.from_public_bytes(advertisement.key).verify(
            signature, DOMAIN_B12_ADVERTISEMENT + signed
        )
    except (InvalidSignature, ValueError) as error:
        raise AdvertisementError("advertisement signature failed") from error
    return advertisement
