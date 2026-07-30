"""Trahens M2 suite-agile variable-message codec and W2 fixed-cell framing.

M2 encodes protocol messages canonically without semantic padding and
length-delimits cryptographic suite payloads. W2 fragments an M2 message into one or more fixed-size adjacent-link cells, pads each cell
before encryption, and reassembles cells under explicit time and memory bounds.

The module is deterministic when supplied with ``random.Random`` and is intended
for conformance testing and the protocol simulator. It is not a deployment key
establishment or constant-time networking implementation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from math import ceil
from random import Random
from typing import Hashable

from trahens_spec.generated import (
    BYTES_CELL_BODY,
    BYTES_CELL_HEADER,
    BYTES_CELL_PAYLOAD,
    BYTES_CELL_RECORD,
    BYTES_LINK_HEADER,
    BYTES_LINK_TAG,
    DOMAIN_W2_LINK_KEY,
    LIFECYCLE_PROFILE_E1 as REG_LIFECYCLE_PROFILE_E1,
    LIMIT_MAX_CONTROL_PROTECTED_BYTES,
    LIMIT_MAX_FRAGMENTS,
    LIMIT_MAX_LOGICAL_MESSAGE_BYTES,
    LIMIT_MAX_REASSEMBLY_BYTES_GLOBAL,
    LIMIT_MAX_REASSEMBLY_MESSAGES_PER_PEER,
    LIMIT_REASSEMBLY_TIMEOUT_MS,
    MESSAGE_ABORT,
    MESSAGE_CANDIDATE,
    MESSAGE_CANCEL,
    MESSAGE_CHAFF,
    MESSAGE_CLOSE,
    MESSAGE_COMMIT,
    MESSAGE_DATA,
    MESSAGE_DISCOVER,
    MESSAGE_PROFILE_M2 as REG_MESSAGE_PROFILE_M2,
    MESSAGE_READY,
    MESSAGE_RENDEZVOUS_OPEN,
    MESSAGE_RENDEZVOUS_RESULT,
    PRIVACY_PROFILE_U1 as REG_PRIVACY_PROFILE_U1,
    VERSION as REG_PROTOCOL_VERSION,
    WIRE_PROFILE_W2 as REG_WIRE_PROFILE_W2,
)

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import C1_SUITE_ID, URE_BYTES, URECiphertext
from trahens_crypto.c2_ideal import C2_SUITE_ID, C2_SYMBOLIC_CIPHERTEXT_BYTES
from trahens_crypto.eligibility import R1_SUITE_ID, R1_DISCOVERY_NONCE_BYTES

# M2 logical-message constants.
PROTOCOL_VERSION = REG_PROTOCOL_VERSION
PRIVACY_PROFILE_U1 = REG_PRIVACY_PROFILE_U1
LIFECYCLE_PROFILE_E1 = REG_LIFECYCLE_PROFILE_E1
MESSAGE_PROFILE_M2 = REG_MESSAGE_PROFILE_M2
MESSAGE_COMMON_BYTES = 8
TOKEN_BYTES = 16
LABEL_BYTES = 16
MAX_LOGICAL_MESSAGE_BYTES = LIMIT_MAX_LOGICAL_MESSAGE_BYTES
CONTROL_PROTECTED_MAX = LIMIT_MAX_CONTROL_PROTECTED_BYTES

# W2 cell constants. The public outer length remains the same as W1, but the
# encrypted body now carries a fragment header and a variable amount of M2 data.
CELL_BODY_BYTES = BYTES_CELL_BODY
CELL_HEADER_BYTES = BYTES_CELL_HEADER
CELL_PAYLOAD_BYTES = BYTES_CELL_PAYLOAD
LINK_HEADER_BYTES = BYTES_LINK_HEADER  # epoch: u32, sequence: u64
LINK_TAG_BYTES = BYTES_LINK_TAG
CELL_RECORD_BYTES = BYTES_CELL_RECORD
WIRE_PROFILE_W2 = REG_WIRE_PROFILE_W2
MAX_FRAGMENTS = LIMIT_MAX_FRAGMENTS
DEFAULT_REASSEMBLY_TIMEOUT_MS = LIMIT_REASSEMBLY_TIMEOUT_MS
DEFAULT_REASSEMBLY_MAX_MESSAGES = LIMIT_MAX_REASSEMBLY_MESSAGES_PER_PEER
DEFAULT_REASSEMBLY_MAX_BYTES = LIMIT_MAX_REASSEMBLY_BYTES_GLOBAL


class CodecError(ValueError):
    """Uniform message, cell, or adjacent-link authentication failure."""


class MessageType(IntEnum):
    CHAFF = MESSAGE_CHAFF
    DISCOVER = MESSAGE_DISCOVER
    CANDIDATE = MESSAGE_CANDIDATE
    COMMIT = MESSAGE_COMMIT
    READY = MESSAGE_READY
    CANCEL = MESSAGE_CANCEL
    ABORT = MESSAGE_ABORT
    CLOSE = MESSAGE_CLOSE
    RENDEZVOUS_OPEN = MESSAGE_RENDEZVOUS_OPEN
    RENDEZVOUS_RESULT = MESSAGE_RENDEZVOUS_RESULT
    DATA = MESSAGE_DATA


@dataclass(frozen=True)
class DiscoverRecord:
    branch_token: bytes
    hop_remaining: int
    fanout_class: int
    expiry_class: int
    options: int
    reply_public_key: bytes
    eligibility_capsule: bytes | URECiphertext
    crypto_suite_id: bytes = C1_SUITE_ID


@dataclass(frozen=True)
class CandidateRecord:
    candidate_token: bytes
    expiry_class: int
    layer_count: int
    candidate_blob: bytes
    crypto_suite_id: bytes = C1_SUITE_ID


@dataclass(frozen=True)
class ControlRecord:
    message_type: MessageType
    local_label: bytes
    generation: int
    expiry_class: int
    protected_body: bytes
    crypto_suite_id: bytes = C1_SUITE_ID


@dataclass(frozen=True)
class CellFragment:
    crypto_suite_id: bytes
    message_local_id: bytes
    fragment_index: int
    fragment_count: int
    fragment_length: int
    total_message_length: int
    fragment: bytes


@dataclass
class _ReassemblyEntry:
    crypto_suite_id: bytes
    created_at_ms: int
    expires_at_ms: int
    fragment_count: int
    total_message_length: int
    fragments: dict[int, bytes] = field(default_factory=dict)

    @property
    def received_bytes(self) -> int:
        return sum(len(value) for value in self.fragments.values())


@dataclass(frozen=True)
class ReassemblyStats:
    completed: int
    duplicate_fragments: int
    expired_messages: int
    capacity_drops: int
    metadata_failures: int
    peak_messages: int
    peak_reserved_bytes: int


class Reassembler:
    """Bounded W2 fragment reassembler.

    ``scope`` is supplied by the caller and normally identifies one authenticated
    adjacent-link direction. The on-wire message identifier is valid only inside
    that scope and is replaced whenever a relay emits a transformed message.
    """

    def __init__(
        self,
        *,
        timeout_ms: int = DEFAULT_REASSEMBLY_TIMEOUT_MS,
        max_messages: int = DEFAULT_REASSEMBLY_MAX_MESSAGES,
        max_reserved_bytes: int = DEFAULT_REASSEMBLY_MAX_BYTES,
    ) -> None:
        if timeout_ms < 1 or max_messages < 1 or max_reserved_bytes < 1:
            raise ValueError("reassembly bounds must be positive")
        self.timeout_ms = timeout_ms
        self.max_messages = max_messages
        self.max_reserved_bytes = max_reserved_bytes
        self._entries: dict[tuple[Hashable, bytes], _ReassemblyEntry] = {}
        self.completed = 0
        self.duplicate_fragments = 0
        self.expired_messages = 0
        self.capacity_drops = 0
        self.metadata_failures = 0
        self.peak_messages = 0
        self.peak_reserved_bytes = 0

    @property
    def live_messages(self) -> int:
        return len(self._entries)

    @property
    def reserved_bytes(self) -> int:
        return sum(entry.total_message_length for entry in self._entries.values())

    def stats(self) -> ReassemblyStats:
        return ReassemblyStats(
            completed=self.completed,
            duplicate_fragments=self.duplicate_fragments,
            expired_messages=self.expired_messages,
            capacity_drops=self.capacity_drops,
            metadata_failures=self.metadata_failures,
            peak_messages=self.peak_messages,
            peak_reserved_bytes=self.peak_reserved_bytes,
        )

    def expire(self, now_ms: int) -> int:
        if now_ms < 0:
            raise ValueError("now_ms cannot be negative")
        expired = [
            key
            for key, entry in self._entries.items()
            if entry.expires_at_ms <= now_ms
        ]
        for key in expired:
            self._entries.pop(key, None)
        self.expired_messages += len(expired)
        return len(expired)

    def discard(self, scope: Hashable, message_local_id: bytes) -> None:
        self._entries.pop((scope, message_local_id), None)

    def accept(
        self,
        scope: Hashable,
        cell: CellFragment,
        *,
        now_ms: int,
    ) -> bytes | None:
        if now_ms < 0:
            raise ValueError("now_ms cannot be negative")
        self.expire(now_ms)
        key = (scope, cell.message_local_id)
        entry = self._entries.get(key)
        if entry is None:
            if self.live_messages >= self.max_messages:
                self.capacity_drops += 1
                raise CodecError("reassembly capacity exceeded")
            if self.reserved_bytes + cell.total_message_length > self.max_reserved_bytes:
                self.capacity_drops += 1
                raise CodecError("reassembly byte budget exceeded")
            entry = _ReassemblyEntry(
                crypto_suite_id=cell.crypto_suite_id,
                created_at_ms=now_ms,
                expires_at_ms=now_ms + self.timeout_ms,
                fragment_count=cell.fragment_count,
                total_message_length=cell.total_message_length,
            )
            self._entries[key] = entry
        elif (
            entry.crypto_suite_id != cell.crypto_suite_id
            or entry.fragment_count != cell.fragment_count
            or entry.total_message_length != cell.total_message_length
        ):
            self.metadata_failures += 1
            self._entries.pop(key, None)
            raise CodecError("inconsistent fragment metadata")

        existing = entry.fragments.get(cell.fragment_index)
        if existing is not None:
            if existing == cell.fragment:
                self.duplicate_fragments += 1
                return None
            self.metadata_failures += 1
            self._entries.pop(key, None)
            raise CodecError("conflicting duplicate fragment")

        entry.fragments[cell.fragment_index] = cell.fragment
        self.peak_messages = max(self.peak_messages, self.live_messages)
        self.peak_reserved_bytes = max(
            self.peak_reserved_bytes,
            self.reserved_bytes,
        )
        if len(entry.fragments) != entry.fragment_count:
            return None

        try:
            message = b"".join(
                entry.fragments[index] for index in range(entry.fragment_count)
            )
        except KeyError as exc:  # pragma: no cover - guarded by fragment count
            self.metadata_failures += 1
            self._entries.pop(key, None)
            raise CodecError("non-contiguous fragment set") from exc
        self._entries.pop(key, None)
        if len(message) != entry.total_message_length:
            self.metadata_failures += 1
            raise CodecError("reassembled length mismatch")
        self.completed += 1
        return message


def _randbytes(rng: Random | None, length: int) -> bytes:
    if length < 0:
        raise CodecError("negative padding length")
    if rng is None:
        import os

        return os.urandom(length)
    return bytes(rng.getrandbits(8) for _ in range(length))


def _require_token(value: bytes, label: str) -> bytes:
    if len(value) != TOKEN_BYTES or value == bytes(TOKEN_BYTES):
        raise CodecError(f"invalid {label}")
    return value


def _require_label(value: bytes) -> bytes:
    if len(value) != LABEL_BYTES or value == bytes(LABEL_BYTES):
        raise CodecError("invalid local label")
    return value


def encode_varuint(value: int) -> bytes:
    """Encode an unsigned integer as canonical base-128 LEB128."""

    if not 0 <= value <= 0xFFFFFFFF:
        raise CodecError("varuint is out of range")
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def decode_varuint(
    encoded: bytes,
    offset: int = 0,
    *,
    maximum: int = 0xFFFFFFFF,
) -> tuple[int, int]:
    if not 0 <= offset <= len(encoded):
        raise CodecError("varuint offset is out of range")
    value = 0
    shift = 0
    for index in range(offset, min(len(encoded), offset + 5)):
        byte = encoded[index]
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            consumed = index - offset + 1
            canonical = encode_varuint(value)
            if encoded[offset : offset + consumed] != canonical:
                raise CodecError("non-canonical varuint")
            if value > maximum:
                raise CodecError("varuint exceeds profile maximum")
            return value, index + 1
        shift += 7
    raise CodecError("unterminated or oversized varuint")


def _require_suite_id(suite_id: bytes) -> bytes:
    if suite_id not in {C1_SUITE_ID, C2_SUITE_ID, R1_SUITE_ID}:
        raise CodecError("unsupported cryptographic suite")
    return suite_id


def _message_prefix(message_type: MessageType, body_length: int, suite_id: bytes) -> bytes:
    suite_id = _require_suite_id(suite_id)
    return (
        bytes(
            [
                int(message_type),
                PROTOCOL_VERSION,
                PRIVACY_PROFILE_U1,
                LIFECYCLE_PROFILE_E1,
            ]
        )
        + suite_id
        + bytes([MESSAGE_PROFILE_M2, 0])
        + encode_varuint(body_length)
    )


def _encode_message(message_type: MessageType, body: bytes, suite_id: bytes) -> bytes:
    encoded = _message_prefix(message_type, len(body), suite_id) + body
    if len(encoded) > MAX_LOGICAL_MESSAGE_BYTES:
        raise CodecError("logical message exceeds M2 maximum")
    return encoded


def _decode_message_envelope(encoded: bytes) -> tuple[MessageType, bytes, bytes]:
    if not 1 <= len(encoded) <= MAX_LOGICAL_MESSAGE_BYTES:
        raise CodecError("invalid logical message length")
    if len(encoded) < MESSAGE_COMMON_BYTES + 1:
        raise CodecError("truncated logical message")
    try:
        message_type = MessageType(encoded[0])
    except ValueError as exc:
        raise CodecError("unknown message type") from exc
    if encoded[1] != PROTOCOL_VERSION:
        raise CodecError("unsupported protocol version")
    if encoded[2] != PRIVACY_PROFILE_U1:
        raise CodecError("unsupported privacy profile")
    if encoded[3] != LIFECYCLE_PROFILE_E1:
        raise CodecError("unsupported lifecycle profile")
    suite_id = _require_suite_id(encoded[4:6])
    if encoded[6] != MESSAGE_PROFILE_M2 or encoded[7] != 0:
        raise CodecError("unsupported message profile or non-zero reserved field")
    body_length, cursor = decode_varuint(
        encoded,
        MESSAGE_COMMON_BYTES,
        maximum=MAX_LOGICAL_MESSAGE_BYTES,
    )
    if cursor + body_length != len(encoded):
        raise CodecError("logical body length mismatch")
    return message_type, suite_id, encoded[cursor:]


def _encode_eligibility_capsule(suite_id: bytes, capsule: bytes | URECiphertext) -> bytes:
    suite_id = _require_suite_id(suite_id)
    if suite_id == C1_SUITE_ID:
        try:
            encoded = capsule.encode() if isinstance(capsule, URECiphertext) else bytes(capsule)
            URECiphertext.decode(encoded)
            return encoded
        except (ValueError, TypeError) as exc:
            raise CodecError("invalid C1 eligibility capsule") from exc
    try:
        encoded = bytes(capsule)
    except (ValueError, TypeError) as exc:
        raise CodecError("invalid eligibility capsule") from exc
    if suite_id == C2_SUITE_ID:
        if len(encoded) != C2_SYMBOLIC_CIPHERTEXT_BYTES or encoded == bytes(len(encoded)):
            raise CodecError("invalid C2 eligibility capsule")
        return encoded
    if suite_id == R1_SUITE_ID:
        if len(encoded) != R1_DISCOVERY_NONCE_BYTES or encoded == bytes(len(encoded)):
            raise CodecError("invalid R1 discovery nonce")
        return encoded
    raise CodecError("unsupported eligibility capsule suite")


def encode_discover(record: DiscoverRecord) -> bytes:
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
        capsule = _encode_eligibility_capsule(record.crypto_suite_id, record.eligibility_capsule)
    except (r255.RistrettoError, ValueError) as exc:
        raise CodecError("invalid DISCOVER cryptographic field") from exc
    body = (
        record.branch_token
        + bytes([record.hop_remaining, record.fanout_class, record.expiry_class, record.options])
        + record.reply_public_key
        + encode_varuint(len(capsule))
        + capsule
    )
    return _encode_message(MessageType.DISCOVER, body, record.crypto_suite_id)


def encode_candidate(record: CandidateRecord) -> bytes:
    _require_token(record.candidate_token, "candidate token")
    if not 1 <= record.expiry_class <= 255:
        raise CodecError("expiry_class is out of range")
    if not 1 <= record.layer_count <= 255:
        raise CodecError("layer_count is out of range")
    if not 1 <= len(record.candidate_blob) <= MAX_LOGICAL_MESSAGE_BYTES:
        raise CodecError("candidate blob is out of range")
    body = (
        record.candidate_token
        + bytes([record.expiry_class, record.layer_count])
        + encode_varuint(len(record.candidate_blob))
        + record.candidate_blob
    )
    return _encode_message(MessageType.CANDIDATE, body, record.crypto_suite_id)


def encode_control(record: ControlRecord) -> bytes:
    if record.message_type not in {
        MessageType.COMMIT,
        MessageType.READY,
        MessageType.CANCEL,
        MessageType.ABORT,
        MessageType.CLOSE,
        MessageType.RENDEZVOUS_OPEN,
        MessageType.RENDEZVOUS_RESULT,
        MessageType.DATA,
    }:
        raise CodecError("invalid control message type")
    _require_label(record.local_label)
    if not 0 <= record.generation <= 0xFFFFFFFF:
        raise CodecError("generation is out of range")
    if not 1 <= record.expiry_class <= 255:
        raise CodecError("expiry_class is out of range")
    if len(record.protected_body) > CONTROL_PROTECTED_MAX:
        raise CodecError("protected control body is too long")
    body = (
        record.local_label
        + record.generation.to_bytes(4, "big")
        + bytes([record.expiry_class])
        + encode_varuint(len(record.protected_body))
        + record.protected_body
    )
    return _encode_message(record.message_type, body, record.crypto_suite_id)


def encode_chaff(*, crypto_suite_id: bytes = C1_SUITE_ID) -> bytes:
    return _encode_message(MessageType.CHAFF, b"", crypto_suite_id)


def decode_message(
    encoded: bytes,
) -> DiscoverRecord | CandidateRecord | ControlRecord | MessageType:
    message_type, suite_id, body = _decode_message_envelope(encoded)
    if message_type is MessageType.CHAFF:
        if body:
            raise CodecError("CHAFF body must be empty")
        return message_type
    if message_type is MessageType.DISCOVER:
        minimum = TOKEN_BYTES + 4 + r255.POINT_BYTES + 1
        if len(body) < minimum:
            raise CodecError("truncated DISCOVER body")
        cursor = 0
        token = _require_token(body[cursor : cursor + TOKEN_BYTES], "branch token")
        cursor += TOKEN_BYTES
        hop_remaining, fanout_class, expiry_class, options = body[cursor : cursor + 4]
        cursor += 4
        if fanout_class == 0 or expiry_class == 0:
            raise CodecError("invalid DISCOVER bounds")
        reply_public = body[cursor : cursor + r255.POINT_BYTES]
        cursor += r255.POINT_BYTES
        capsule_length, cursor = decode_varuint(body, cursor, maximum=MAX_LOGICAL_MESSAGE_BYTES)
        if cursor + capsule_length != len(body):
            raise CodecError("eligibility capsule length mismatch")
        try:
            r255.require_point(reply_public, allow_identity=False)
            capsule = _encode_eligibility_capsule(suite_id, body[cursor:])
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
            crypto_suite_id=suite_id,
        )
    if message_type is MessageType.CANDIDATE:
        if len(body) < TOKEN_BYTES + 3:
            raise CodecError("truncated CANDIDATE body")
        cursor = 0
        token = _require_token(body[cursor : cursor + TOKEN_BYTES], "candidate token")
        cursor += TOKEN_BYTES
        expiry_class = body[cursor]
        layer_count = body[cursor + 1]
        cursor += 2
        blob_length, cursor = decode_varuint(
            body,
            cursor,
            maximum=MAX_LOGICAL_MESSAGE_BYTES,
        )
        if expiry_class == 0 or layer_count == 0 or blob_length < 1:
            raise CodecError("invalid CANDIDATE bounds")
        if cursor + blob_length != len(body):
            raise CodecError("candidate blob length mismatch")
        return CandidateRecord(
            candidate_token=token,
            expiry_class=expiry_class,
            layer_count=layer_count,
            candidate_blob=body[cursor:],
            crypto_suite_id=suite_id,
        )

    if len(body) < LABEL_BYTES + 4 + 1 + 1:
        raise CodecError("truncated control body")
    cursor = 0
    local_label = _require_label(body[cursor : cursor + LABEL_BYTES])
    cursor += LABEL_BYTES
    generation = int.from_bytes(body[cursor : cursor + 4], "big")
    cursor += 4
    expiry_class = body[cursor]
    cursor += 1
    protected_length, cursor = decode_varuint(
        body,
        cursor,
        maximum=CONTROL_PROTECTED_MAX,
    )
    if expiry_class == 0 or cursor + protected_length != len(body):
        raise CodecError("invalid control bounds")
    return ControlRecord(
        message_type=message_type,
        local_label=local_label,
        generation=generation,
        expiry_class=expiry_class,
        protected_body=body[cursor:],
        crypto_suite_id=suite_id,
    )


def _validate_message_local_id(value: bytes) -> bytes:
    if len(value) != 16 or value == bytes(16):
        raise CodecError("invalid adjacent-link message identifier")
    return value


def fragment_message(
    encoded_message: bytes,
    *,
    message_local_id: bytes,
    rng: Random | None = None,
) -> tuple[bytes, ...]:
    _validate_message_local_id(message_local_id)
    if not 1 <= len(encoded_message) <= MAX_LOGICAL_MESSAGE_BYTES:
        raise CodecError("invalid logical message length")
    if len(encoded_message) < MESSAGE_COMMON_BYTES:
        raise CodecError("truncated M2 logical message")
    suite_id = _require_suite_id(encoded_message[4:6])
    fragment_count = ceil(len(encoded_message) / CELL_PAYLOAD_BYTES)
    if not 1 <= fragment_count <= MAX_FRAGMENTS:
        raise CodecError("logical message requires too many fragments")
    cells: list[bytes] = []
    for index in range(fragment_count):
        start = index * CELL_PAYLOAD_BYTES
        fragment = encoded_message[start : start + CELL_PAYLOAD_BYTES]
        header = (
            bytes(
                [
                    WIRE_PROFILE_W2,
                    PROTOCOL_VERSION,
                    PRIVACY_PROFILE_U1,
                    LIFECYCLE_PROFILE_E1,
                ]
            )
            + suite_id
            + bytes([0, 0])
            + message_local_id
            + index.to_bytes(2, "big")
            + fragment_count.to_bytes(2, "big")
            + len(fragment).to_bytes(2, "big")
            + len(encoded_message).to_bytes(2, "big")
        )
        if len(header) != CELL_HEADER_BYTES:
            raise AssertionError("unexpected W2 cell header length")
        body = header + fragment + _randbytes(
            rng,
            CELL_PAYLOAD_BYTES - len(fragment),
        )
        if len(body) != CELL_BODY_BYTES:
            raise AssertionError("unexpected W2 cell body length")
        cells.append(body)
    return tuple(cells)


def decode_cell(body: bytes) -> CellFragment:
    if len(body) != CELL_BODY_BYTES:
        raise CodecError("invalid fixed cell length")
    if body[0] != WIRE_PROFILE_W2:
        raise CodecError("unsupported wire profile")
    if body[1] != PROTOCOL_VERSION:
        raise CodecError("unsupported protocol version")
    if body[2] != PRIVACY_PROFILE_U1:
        raise CodecError("unsupported privacy profile")
    if body[3] != LIFECYCLE_PROFILE_E1:
        raise CodecError("unsupported lifecycle profile")
    suite_id = _require_suite_id(body[4:6])
    if body[6:8] != b"\x00\x00":
        raise CodecError("non-zero W2 flags or reserved field")
    message_local_id = _validate_message_local_id(body[8:24])
    fragment_index = int.from_bytes(body[24:26], "big")
    fragment_count = int.from_bytes(body[26:28], "big")
    fragment_length = int.from_bytes(body[28:30], "big")
    total_length = int.from_bytes(body[30:32], "big")
    if not 1 <= fragment_count <= MAX_FRAGMENTS:
        raise CodecError("invalid fragment count")
    if fragment_index >= fragment_count:
        raise CodecError("fragment index is out of range")
    if not 1 <= total_length <= MAX_LOGICAL_MESSAGE_BYTES:
        raise CodecError("invalid total logical length")
    expected_count = ceil(total_length / CELL_PAYLOAD_BYTES)
    if fragment_count != expected_count:
        raise CodecError("non-canonical fragment count")
    expected_length = (
        CELL_PAYLOAD_BYTES
        if fragment_index < fragment_count - 1
        else total_length - CELL_PAYLOAD_BYTES * (fragment_count - 1)
    )
    if fragment_length != expected_length:
        raise CodecError("non-canonical fragment length")
    fragment = body[CELL_HEADER_BYTES : CELL_HEADER_BYTES + fragment_length]
    return CellFragment(
        crypto_suite_id=suite_id,
        message_local_id=message_local_id,
        fragment_index=fragment_index,
        fragment_count=fragment_count,
        fragment_length=fragment_length,
        total_message_length=total_length,
        fragment=fragment,
    )


def derive_link_key(seed: int, sender: int, receiver: int) -> bytes:
    if min(seed, sender, receiver) < 0:
        raise CodecError("negative link-key input")
    material = (
        DOMAIN_W2_LINK_KEY
        + seed.to_bytes(8, "big")
        + sender.to_bytes(4, "big")
        + receiver.to_bytes(4, "big")
    )
    return hashlib.sha256(material).digest()


def seal_link_cell(
    body: bytes,
    *,
    key: bytes,
    epoch: int,
    sequence: int,
) -> bytes:
    if len(body) != CELL_BODY_BYTES or len(key) != 32:
        raise CodecError("invalid link-cell input")
    if not 0 <= epoch <= 0xFFFFFFFF or not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
        raise CodecError("link header value is out of range")
    header = epoch.to_bytes(4, "big") + sequence.to_bytes(8, "big")
    ciphertext = ChaCha20Poly1305(key).encrypt(header, body, header)
    encoded = header + ciphertext
    if len(encoded) != CELL_RECORD_BYTES:
        raise AssertionError("unexpected fixed link-cell size")
    return encoded


def open_link_cell(
    encoded: bytes,
    *,
    key: bytes,
    expected_epoch: int | None = None,
    expected_sequence: int | None = None,
) -> tuple[int, int, bytes]:
    try:
        if len(encoded) != CELL_RECORD_BYTES or len(key) != 32:
            raise CodecError("link authentication failed")
        header = encoded[:LINK_HEADER_BYTES]
        epoch = int.from_bytes(header[:4], "big")
        sequence = int.from_bytes(header[4:], "big")
        if expected_epoch is not None and epoch != expected_epoch:
            raise CodecError("link authentication failed")
        if expected_sequence is not None and sequence != expected_sequence:
            raise CodecError("link authentication failed")
        body = ChaCha20Poly1305(key).decrypt(
            header,
            encoded[LINK_HEADER_BYTES:],
            header,
        )
        if len(body) != CELL_BODY_BYTES:
            raise CodecError("link authentication failed")
        return epoch, sequence, body
    except (InvalidTag, ValueError, CodecError) as exc:
        raise CodecError("link authentication failed") from exc


def encode_to_link_cells(
    encoded_message: bytes,
    *,
    key: bytes,
    epoch: int,
    first_sequence: int,
    message_local_id: bytes,
    rng: Random | None = None,
) -> tuple[bytes, ...]:
    bodies = fragment_message(
        encoded_message,
        message_local_id=message_local_id,
        rng=rng,
    )
    return tuple(
        seal_link_cell(
            body,
            key=key,
            epoch=epoch,
            sequence=first_sequence + index,
        )
        for index, body in enumerate(bodies)
    )
