"""Trahens T1 hop-local reliability and scheduled-cell framing.

T1 retains the 1,052-byte adjacent-link record size used by W2 but gives the
1,024-byte encrypted body three internal frame classes: DATA, ACK, and CHAFF.
The class is encrypted and therefore not visible to a passive link observer.

DATA frames carry canonical M2 fragments. ACK frames carry a selective bitmap
for one adjacent-link-local transmission identifier. CHAFF frames occupy an
otherwise idle scheduler slot. Retransmissions reuse the adjacent-link-local
transmission identifier and fragment index so that the peer can complete its
reassembly context, but every emission receives a new public sequence number,
new random padding, and a fresh AEAD ciphertext.

This module is a deterministic conformance and simulation implementation. It
is not a production link protocol or a congestion controller.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from math import ceil
from random import Random

from .m2w2 import (
    CELL_BODY_BYTES,
    CELL_HEADER_BYTES,
    CELL_PAYLOAD_BYTES,
    CELL_RECORD_BYTES,
    CodecError,
    MAX_FRAGMENTS,
    MAX_LOGICAL_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    PRIVACY_PROFILE_U1,
    LIFECYCLE_PROFILE_E1,
    _randbytes,
    _require_suite_id,
    _validate_message_local_id,
    open_link_cell,
    seal_link_cell,
)

T1_WIRE_PROFILE = 3
T1_ACK_BITMAP_BITS = 32
T1_ACK_BITMAP_BYTES = 4


class T1FrameType(IntEnum):
    DATA = 0x00
    ACK = 0x01
    CHAFF = 0x02


@dataclass(frozen=True)
class T1DataFrame:
    crypto_suite_id: bytes
    transmission_id: bytes
    fragment_index: int
    fragment_count: int
    fragment_length: int
    total_message_length: int
    fragment: bytes


@dataclass(frozen=True)
class T1AckFrame:
    crypto_suite_id: bytes
    transmission_id: bytes
    fragment_count: int
    ack_delay_ms: int
    acknowledged_bitmap: int

    @property
    def complete(self) -> bool:
        expected = (1 << self.fragment_count) - 1
        return self.acknowledged_bitmap == expected

    def acknowledges(self, fragment_index: int) -> bool:
        if not 0 <= fragment_index < self.fragment_count:
            return False
        return bool(self.acknowledged_bitmap & (1 << fragment_index))


@dataclass(frozen=True)
class T1ChaffFrame:
    crypto_suite_id: bytes
    transmission_id: bytes


T1Frame = T1DataFrame | T1AckFrame | T1ChaffFrame


def _common_header(
    frame_type: T1FrameType,
    suite_id: bytes,
    transmission_id: bytes,
) -> bytearray:
    suite_id = _require_suite_id(suite_id)
    transmission_id = _validate_message_local_id(transmission_id)
    header = bytearray(
        bytes(
            [
                T1_WIRE_PROFILE,
                PROTOCOL_VERSION,
                PRIVACY_PROFILE_U1,
                LIFECYCLE_PROFILE_E1,
            ]
        )
        + suite_id
        + bytes([int(frame_type), 0])
        + transmission_id
        + bytes(8)
    )
    if len(header) != CELL_HEADER_BYTES:
        raise AssertionError("unexpected T1 header length")
    return header


def _pad_body(header: bytes, payload: bytes, rng: Random | None) -> bytes:
    if len(header) != CELL_HEADER_BYTES:
        raise CodecError("invalid T1 header")
    if len(payload) > CELL_PAYLOAD_BYTES:
        raise CodecError("T1 payload exceeds one cell")
    body = header + payload + _randbytes(rng, CELL_PAYLOAD_BYTES - len(payload))
    if len(body) != CELL_BODY_BYTES:
        raise AssertionError("unexpected T1 body length")
    return body


def split_message(
    encoded_message: bytes,
    *,
    transmission_id: bytes,
) -> tuple[T1DataFrame, ...]:
    """Split one canonical M2 message into semantic T1 DATA frames."""

    _validate_message_local_id(transmission_id)
    if not 1 <= len(encoded_message) <= MAX_LOGICAL_MESSAGE_BYTES:
        raise CodecError("invalid logical message length")
    if len(encoded_message) < 8:
        raise CodecError("truncated M2 logical message")
    suite_id = _require_suite_id(encoded_message[4:6])
    fragment_count = ceil(len(encoded_message) / CELL_PAYLOAD_BYTES)
    if not 1 <= fragment_count <= min(MAX_FRAGMENTS, T1_ACK_BITMAP_BITS):
        raise CodecError("logical message requires too many T1 fragments")

    frames: list[T1DataFrame] = []
    for index in range(fragment_count):
        start = index * CELL_PAYLOAD_BYTES
        fragment = encoded_message[start : start + CELL_PAYLOAD_BYTES]
        frames.append(
            T1DataFrame(
                crypto_suite_id=suite_id,
                transmission_id=transmission_id,
                fragment_index=index,
                fragment_count=fragment_count,
                fragment_length=len(fragment),
                total_message_length=len(encoded_message),
                fragment=fragment,
            )
        )
    return tuple(frames)


def encode_data_body(frame: T1DataFrame, *, rng: Random | None = None) -> bytes:
    """Encode one DATA frame with fresh per-emission padding."""

    if not 1 <= frame.fragment_count <= min(MAX_FRAGMENTS, T1_ACK_BITMAP_BITS):
        raise CodecError("invalid T1 fragment count")
    if not 0 <= frame.fragment_index < frame.fragment_count:
        raise CodecError("T1 fragment index is out of range")
    if not 1 <= frame.total_message_length <= MAX_LOGICAL_MESSAGE_BYTES:
        raise CodecError("invalid T1 total logical length")
    expected_count = ceil(frame.total_message_length / CELL_PAYLOAD_BYTES)
    if frame.fragment_count != expected_count:
        raise CodecError("non-canonical T1 fragment count")
    expected_length = (
        CELL_PAYLOAD_BYTES
        if frame.fragment_index < frame.fragment_count - 1
        else frame.total_message_length
        - CELL_PAYLOAD_BYTES * (frame.fragment_count - 1)
    )
    if frame.fragment_length != expected_length or len(frame.fragment) != expected_length:
        raise CodecError("non-canonical T1 fragment length")
    header = _common_header(
        T1FrameType.DATA, frame.crypto_suite_id, frame.transmission_id
    )
    header[24:26] = frame.fragment_index.to_bytes(2, "big")
    header[26:28] = frame.fragment_count.to_bytes(2, "big")
    header[28:30] = frame.fragment_length.to_bytes(2, "big")
    header[30:32] = frame.total_message_length.to_bytes(2, "big")
    return _pad_body(bytes(header), frame.fragment, rng)


def fragment_message(
    encoded_message: bytes,
    *,
    transmission_id: bytes,
    rng: Random | None = None,
) -> tuple[bytes, ...]:
    """Fragment one canonical M2 message into unsealed T1 DATA bodies."""

    return tuple(
        encode_data_body(frame, rng=rng)
        for frame in split_message(
            encoded_message, transmission_id=transmission_id
        )
    )


def encode_ack_body(
    *,
    crypto_suite_id: bytes,
    transmission_id: bytes,
    fragment_count: int,
    acknowledged_bitmap: int,
    ack_delay_ms: int,
    rng: Random | None = None,
) -> bytes:
    """Encode one encrypted selective ACK body.

    The 32-bit bitmap is sufficient for the current M2 maximum of 17
    fragments. Bits outside ``fragment_count`` MUST be zero.
    """

    if not 1 <= fragment_count <= min(MAX_FRAGMENTS, T1_ACK_BITMAP_BITS):
        raise CodecError("invalid T1 ACK fragment count")
    if not 0 <= ack_delay_ms <= 0xFFFF:
        raise CodecError("invalid T1 ACK delay")
    if not 0 <= acknowledged_bitmap < (1 << T1_ACK_BITMAP_BITS):
        raise CodecError("invalid T1 ACK bitmap")
    if acknowledged_bitmap >> fragment_count:
        raise CodecError("T1 ACK sets bits outside fragment count")
    header = _common_header(T1FrameType.ACK, crypto_suite_id, transmission_id)
    header[24:26] = fragment_count.to_bytes(2, "big")
    header[26:28] = ack_delay_ms.to_bytes(2, "big")
    header[28:32] = acknowledged_bitmap.to_bytes(T1_ACK_BITMAP_BYTES, "big")
    return _pad_body(bytes(header), b"", rng)


def encode_chaff_body(
    *,
    crypto_suite_id: bytes,
    transmission_id: bytes,
    rng: Random | None = None,
) -> bytes:
    header = _common_header(T1FrameType.CHAFF, crypto_suite_id, transmission_id)
    return _pad_body(bytes(header), b"", rng)


def decode_body(body: bytes) -> T1Frame:
    if len(body) != CELL_BODY_BYTES:
        raise CodecError("invalid fixed T1 body length")
    if body[0] != T1_WIRE_PROFILE:
        raise CodecError("unsupported T1 wire profile")
    if body[1] != PROTOCOL_VERSION:
        raise CodecError("unsupported protocol version")
    if body[2] != PRIVACY_PROFILE_U1:
        raise CodecError("unsupported privacy profile")
    if body[3] != LIFECYCLE_PROFILE_E1:
        raise CodecError("unsupported lifecycle profile")
    suite_id = _require_suite_id(body[4:6])
    try:
        frame_type = T1FrameType(body[6])
    except ValueError as exc:
        raise CodecError("unknown T1 frame type") from exc
    if body[7] != 0:
        raise CodecError("non-zero T1 reserved field")
    transmission_id = _validate_message_local_id(body[8:24])

    if frame_type is T1FrameType.DATA:
        fragment_index = int.from_bytes(body[24:26], "big")
        fragment_count = int.from_bytes(body[26:28], "big")
        fragment_length = int.from_bytes(body[28:30], "big")
        total_length = int.from_bytes(body[30:32], "big")
        if not 1 <= fragment_count <= min(MAX_FRAGMENTS, T1_ACK_BITMAP_BITS):
            raise CodecError("invalid T1 fragment count")
        if fragment_index >= fragment_count:
            raise CodecError("T1 fragment index is out of range")
        if not 1 <= total_length <= MAX_LOGICAL_MESSAGE_BYTES:
            raise CodecError("invalid T1 total logical length")
        expected_count = ceil(total_length / CELL_PAYLOAD_BYTES)
        if fragment_count != expected_count:
            raise CodecError("non-canonical T1 fragment count")
        expected_length = (
            CELL_PAYLOAD_BYTES
            if fragment_index < fragment_count - 1
            else total_length - CELL_PAYLOAD_BYTES * (fragment_count - 1)
        )
        if fragment_length != expected_length:
            raise CodecError("non-canonical T1 fragment length")
        fragment = body[CELL_HEADER_BYTES : CELL_HEADER_BYTES + fragment_length]
        return T1DataFrame(
            crypto_suite_id=suite_id,
            transmission_id=transmission_id,
            fragment_index=fragment_index,
            fragment_count=fragment_count,
            fragment_length=fragment_length,
            total_message_length=total_length,
            fragment=fragment,
        )

    if frame_type is T1FrameType.ACK:
        fragment_count = int.from_bytes(body[24:26], "big")
        ack_delay_ms = int.from_bytes(body[26:28], "big")
        bitmap = int.from_bytes(body[28:32], "big")
        if not 1 <= fragment_count <= min(MAX_FRAGMENTS, T1_ACK_BITMAP_BITS):
            raise CodecError("invalid T1 ACK fragment count")
        if bitmap >> fragment_count:
            raise CodecError("T1 ACK sets bits outside fragment count")
        return T1AckFrame(
            crypto_suite_id=suite_id,
            transmission_id=transmission_id,
            fragment_count=fragment_count,
            ack_delay_ms=ack_delay_ms,
            acknowledged_bitmap=bitmap,
        )

    if body[24:32] != bytes(8):
        raise CodecError("non-zero T1 CHAFF control fields")
    return T1ChaffFrame(
        crypto_suite_id=suite_id,
        transmission_id=transmission_id,
    )


def seal_body(
    body: bytes,
    *,
    key: bytes,
    epoch: int,
    sequence: int,
) -> bytes:
    return seal_link_cell(body, key=key, epoch=epoch, sequence=sequence)


def open_record(
    encoded: bytes,
    *,
    key: bytes,
    expected_epoch: int | None = None,
    expected_sequence: int | None = None,
) -> tuple[int, int, T1Frame]:
    epoch, sequence, body = open_link_cell(
        encoded,
        key=key,
        expected_epoch=expected_epoch,
        expected_sequence=expected_sequence,
    )
    return epoch, sequence, decode_body(body)


def ack_bitmap(fragment_indexes: set[int], fragment_count: int) -> int:
    if not 1 <= fragment_count <= min(MAX_FRAGMENTS, T1_ACK_BITMAP_BITS):
        raise CodecError("invalid T1 fragment count")
    bitmap = 0
    for index in fragment_indexes:
        if not 0 <= index < fragment_count:
            raise CodecError("fragment index outside T1 ACK range")
        bitmap |= 1 << index
    return bitmap


def acknowledged_indexes(bitmap: int, fragment_count: int) -> tuple[int, ...]:
    if bitmap >> fragment_count:
        raise CodecError("T1 ACK sets bits outside fragment count")
    return tuple(index for index in range(fragment_count) if bitmap & (1 << index))


__all__ = [
    "CELL_RECORD_BYTES",
    "T1_ACK_BITMAP_BITS",
    "T1_WIRE_PROFILE",
    "T1FrameType",
    "T1DataFrame",
    "T1AckFrame",
    "T1ChaffFrame",
    "T1Frame",
    "split_message",
    "encode_data_body",
    "fragment_message",
    "encode_ack_body",
    "encode_chaff_body",
    "decode_body",
    "seal_body",
    "open_record",
    "ack_bitmap",
    "acknowledged_indexes",
]
