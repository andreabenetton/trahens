"""Trahens W1 fixed-size control-record codec.

The module defines the cleartext body processed after adjacent-link
authentication and a deterministic reference adjacent-link wrapper used by the
simulator. Every record has the same wire length. Message type, suite, profile,
and logical fields are contained inside the authenticated ciphertext.

This is research reference code, not a production transport implementation.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import IntEnum
from random import Random

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import C1_SUITE_ID, URE_BYTES, URECiphertext

BODY_BYTES = 1024
LINK_HEADER_BYTES = 12  # epoch: u32, sequence: u64
LINK_TAG_BYTES = 16
LINK_RECORD_BYTES = LINK_HEADER_BYTES + BODY_BYTES + LINK_TAG_BYTES

PROTOCOL_VERSION = 1
PRIVACY_PROFILE_U1 = 1
LIFECYCLE_PROFILE_E1 = 1
WIRE_PROFILE_W1 = 1

COMMON_BYTES = 8
TOKEN_BYTES = 16
LABEL_BYTES = 16
CANDIDATE_BLOB_MAX = 960
CONTROL_PROTECTED_MAX = 512


class CodecError(ValueError):
    """Uniform codec or adjacent-link authentication failure."""


class MessageType(IntEnum):
    CHAFF = 0x00
    DISCOVER = 0x20
    CANDIDATE = 0x21
    COMMIT = 0x22
    READY = 0x23
    CANCEL = 0x24
    ABORT = 0x25
    CLOSE = 0x26


@dataclass(frozen=True)
class DiscoverRecord:
    branch_token: bytes
    hop_remaining: int
    fanout_class: int
    expiry_class: int
    options: int
    reply_public_key: bytes
    eligibility_capsule: URECiphertext


@dataclass(frozen=True)
class CandidateRecord:
    candidate_token: bytes
    expiry_class: int
    layer_count: int
    candidate_blob: bytes


@dataclass(frozen=True)
class ControlRecord:
    message_type: MessageType
    local_label: bytes
    generation: int
    expiry_class: int
    protected_body: bytes


def _randbytes(rng: Random | None, length: int) -> bytes:
    if length < 0:
        raise CodecError("negative padding length")
    if rng is None:
        # Padding is not secret in this reference module, but it must be fresh.
        import os

        return os.urandom(length)
    return bytes(rng.getrandbits(8) for _ in range(length))


def _common(message_type: MessageType) -> bytes:
    return bytes(
        [
            int(message_type),
            PROTOCOL_VERSION,
            PRIVACY_PROFILE_U1,
            LIFECYCLE_PROFILE_E1,
        ]
    ) + C1_SUITE_ID + bytes([WIRE_PROFILE_W1, 0])


def _validate_common(body: bytes) -> MessageType:
    if len(body) != BODY_BYTES:
        raise CodecError("invalid fixed record length")
    try:
        message_type = MessageType(body[0])
    except ValueError as exc:
        raise CodecError("unknown message type") from exc
    if body[1] != PROTOCOL_VERSION:
        raise CodecError("unsupported protocol version")
    if body[2] != PRIVACY_PROFILE_U1:
        raise CodecError("unsupported privacy profile")
    if body[3] != LIFECYCLE_PROFILE_E1:
        raise CodecError("unsupported lifecycle profile")
    if body[4:6] != C1_SUITE_ID:
        raise CodecError("unsupported cryptographic suite")
    if body[6] != WIRE_PROFILE_W1 or body[7] != 0:
        raise CodecError("unsupported wire profile or non-zero reserved field")
    return message_type


def _require_token(value: bytes, label: str) -> bytes:
    if len(value) != TOKEN_BYTES or value == bytes(TOKEN_BYTES):
        raise CodecError(f"invalid {label}")
    return value


def _require_label(value: bytes) -> bytes:
    if len(value) != LABEL_BYTES or value == bytes(LABEL_BYTES):
        raise CodecError("invalid local label")
    return value


def encode_discover(record: DiscoverRecord, *, rng: Random | None = None) -> bytes:
    _require_token(record.branch_token, "branch token")
    if not 0 <= record.hop_remaining <= 255:
        raise CodecError("hop_remaining is out of range")
    if not 1 <= record.fanout_class <= 255:
        raise CodecError("fanout_class is out of range")
    if not 1 <= record.expiry_class <= 255:
        raise CodecError("expiry_class is out of range")
    if not 0 <= record.options <= 255:
        raise CodecError("options is out of range")
    try:
        r255.require_point(record.reply_public_key, allow_identity=False)
        capsule = record.eligibility_capsule.encode()
    except (r255.RistrettoError, ValueError) as exc:
        raise CodecError("invalid DISCOVER cryptographic field") from exc

    fixed = (
        _common(MessageType.DISCOVER)
        + record.branch_token
        + bytes(
            [
                record.hop_remaining,
                record.fanout_class,
                record.expiry_class,
                record.options,
            ]
        )
        + record.reply_public_key
        + capsule
    )
    return fixed + _randbytes(rng, BODY_BYTES - len(fixed))


def encode_candidate(record: CandidateRecord, *, rng: Random | None = None) -> bytes:
    _require_token(record.candidate_token, "candidate token")
    if not 1 <= record.expiry_class <= 255:
        raise CodecError("expiry_class is out of range")
    if not 1 <= record.layer_count <= 255:
        raise CodecError("layer_count is out of range")
    if not 1 <= len(record.candidate_blob) <= CANDIDATE_BLOB_MAX:
        raise CodecError("candidate blob is out of range")
    fixed = (
        _common(MessageType.CANDIDATE)
        + record.candidate_token
        + bytes([record.expiry_class, record.layer_count])
        + len(record.candidate_blob).to_bytes(2, "big")
        + record.candidate_blob
    )
    return fixed + _randbytes(rng, BODY_BYTES - len(fixed))


def encode_control(record: ControlRecord, *, rng: Random | None = None) -> bytes:
    if record.message_type not in {
        MessageType.COMMIT,
        MessageType.READY,
        MessageType.CANCEL,
        MessageType.ABORT,
        MessageType.CLOSE,
    }:
        raise CodecError("invalid control message type")
    _require_label(record.local_label)
    if not 0 <= record.generation <= 0xFFFFFFFF:
        raise CodecError("generation is out of range")
    if not 1 <= record.expiry_class <= 255:
        raise CodecError("expiry_class is out of range")
    if len(record.protected_body) > CONTROL_PROTECTED_MAX:
        raise CodecError("protected control body is too long")
    fixed = (
        _common(record.message_type)
        + record.local_label
        + record.generation.to_bytes(4, "big")
        + bytes([record.expiry_class])
        + len(record.protected_body).to_bytes(2, "big")
        + record.protected_body
    )
    return fixed + _randbytes(rng, BODY_BYTES - len(fixed))


def encode_chaff(*, rng: Random | None = None) -> bytes:
    fixed = _common(MessageType.CHAFF)
    return fixed + _randbytes(rng, BODY_BYTES - len(fixed))


def decode_body(body: bytes) -> DiscoverRecord | CandidateRecord | ControlRecord | MessageType:
    message_type = _validate_common(body)
    cursor = COMMON_BYTES
    if message_type is MessageType.CHAFF:
        return message_type
    if message_type is MessageType.DISCOVER:
        token = _require_token(body[cursor : cursor + TOKEN_BYTES], "branch token")
        cursor += TOKEN_BYTES
        hop_remaining, fanout_class, expiry_class, options = body[cursor : cursor + 4]
        cursor += 4
        if fanout_class == 0 or expiry_class == 0:
            raise CodecError("invalid DISCOVER bounds")
        reply_public = body[cursor : cursor + r255.POINT_BYTES]
        cursor += r255.POINT_BYTES
        try:
            r255.require_point(reply_public, allow_identity=False)
            capsule = URECiphertext.decode(body[cursor : cursor + URE_BYTES])
        except (r255.RistrettoError, ValueError) as exc:
            raise CodecError("invalid DISCOVER cryptographic field") from exc
        return DiscoverRecord(
            branch_token=token,
            hop_remaining=hop_remaining,
            fanout_class=fanout_class,
            expiry_class=expiry_class,
            options=options,
            reply_public_key=reply_public,
            eligibility_capsule=capsule,
        )
    if message_type is MessageType.CANDIDATE:
        token = _require_token(body[cursor : cursor + TOKEN_BYTES], "candidate token")
        cursor += TOKEN_BYTES
        expiry_class = body[cursor]
        layer_count = body[cursor + 1]
        blob_length = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
        cursor += 4
        if expiry_class == 0 or layer_count == 0:
            raise CodecError("invalid CANDIDATE bounds")
        if not 1 <= blob_length <= CANDIDATE_BLOB_MAX:
            raise CodecError("invalid candidate blob length")
        return CandidateRecord(
            candidate_token=token,
            expiry_class=expiry_class,
            layer_count=layer_count,
            candidate_blob=body[cursor : cursor + blob_length],
        )
    local_label = _require_label(body[cursor : cursor + LABEL_BYTES])
    cursor += LABEL_BYTES
    generation = int.from_bytes(body[cursor : cursor + 4], "big")
    cursor += 4
    expiry_class = body[cursor]
    protected_length = int.from_bytes(body[cursor + 1 : cursor + 3], "big")
    cursor += 3
    if expiry_class == 0 or protected_length > CONTROL_PROTECTED_MAX:
        raise CodecError("invalid control bounds")
    return ControlRecord(
        message_type=message_type,
        local_label=local_label,
        generation=generation,
        expiry_class=expiry_class,
        protected_body=body[cursor : cursor + protected_length],
    )


def derive_link_key(seed: int, sender: int, receiver: int) -> bytes:
    if min(seed, sender, receiver) < 0:
        raise CodecError("negative link-key input")
    material = (
        b"Trahens-W1-link-key-v1"
        + seed.to_bytes(8, "big")
        + sender.to_bytes(4, "big")
        + receiver.to_bytes(4, "big")
    )
    return hashlib.sha256(material).digest()


def seal_link_record(
    body: bytes,
    *,
    key: bytes,
    epoch: int,
    sequence: int,
) -> bytes:
    if len(body) != BODY_BYTES or len(key) != 32:
        raise CodecError("invalid link-record input")
    if not 0 <= epoch <= 0xFFFFFFFF or not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
        raise CodecError("link header value is out of range")
    header = epoch.to_bytes(4, "big") + sequence.to_bytes(8, "big")
    nonce = header
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, body, header)
    encoded = header + ciphertext
    if len(encoded) != LINK_RECORD_BYTES:
        raise AssertionError("unexpected fixed link-record size")
    return encoded


def open_link_record(
    encoded: bytes,
    *,
    key: bytes,
    expected_epoch: int | None = None,
    expected_sequence: int | None = None,
) -> tuple[int, int, bytes]:
    try:
        if len(encoded) != LINK_RECORD_BYTES or len(key) != 32:
            raise CodecError("link authentication failed")
        header = encoded[:LINK_HEADER_BYTES]
        epoch = int.from_bytes(header[:4], "big")
        sequence = int.from_bytes(header[4:], "big")
        if expected_epoch is not None and epoch != expected_epoch:
            raise CodecError("link authentication failed")
        if expected_sequence is not None and sequence != expected_sequence:
            raise CodecError("link authentication failed")
        body = ChaCha20Poly1305(key).decrypt(header, encoded[LINK_HEADER_BYTES:], header)
        if len(body) != BODY_BYTES:
            raise CodecError("link authentication failed")
        return epoch, sequence, body
    except (InvalidTag, ValueError, CodecError) as exc:
        raise CodecError("link authentication failed") from exc


def fixed_length_equal(left: bytes, right: bytes) -> bool:
    """Constant-interface equality helper used by tests and conformance code."""

    return hmac.compare_digest(left, right)
