"""Trahens T2 quantized schedule-control framing.

T2 keeps the 1,052-byte adjacent-link record size of W2/T1.  The encrypted
body adds a SCHEDULE control class used to negotiate one of a finite set of
rate classes for a future fixed-length epoch.  The selected cadence is public
once used; the frame merely authenticates the peer agreement and prevents an
on-path party from injecting arbitrary schedule transitions.

This module is a deterministic conformance implementation, not a production
congestion controller.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from random import Random

from trahens_spec.generated import (
    SCHEDULE_PROFILE_T2,
    T2_ACTION_ACCEPT,
    T2_ACTION_OFFER,
    T2_ACTION_REJECT,
    T2_FRAME_SCHEDULE,
)

from .m2w2 import (
    CELL_BODY_BYTES,
    CELL_HEADER_BYTES,
    CELL_PAYLOAD_BYTES,
    CodecError,
    LIFECYCLE_PROFILE_E1,
    PRIVACY_PROFILE_U1,
    PROTOCOL_VERSION,
    _randbytes,
    _require_suite_id,
    _validate_message_local_id,
)

T2_WIRE_PROFILE = SCHEDULE_PROFILE_T2
T2_MAX_RATE_CLASSES = 8


class T2FrameType(IntEnum):
    SCHEDULE = T2_FRAME_SCHEDULE


class T2ScheduleAction(IntEnum):
    OFFER = T2_ACTION_OFFER
    ACCEPT = T2_ACTION_ACCEPT
    REJECT = T2_ACTION_REJECT


@dataclass(frozen=True)
class T2ScheduleFrame:
    crypto_suite_id: bytes
    negotiation_id: bytes
    effective_epoch: int
    current_rate_class: int
    requested_rate_class: int
    maximum_rate_class: int
    action: T2ScheduleAction


def encode_schedule_body(
    frame: T2ScheduleFrame,
    *,
    rng: Random | None = None,
) -> bytes:
    suite_id = _require_suite_id(frame.crypto_suite_id)
    negotiation_id = _validate_message_local_id(frame.negotiation_id)
    if not 0 <= frame.effective_epoch <= 0xFFFFFFFF:
        raise CodecError("T2 effective epoch is out of range")
    for name, value in (
        ("current", frame.current_rate_class),
        ("requested", frame.requested_rate_class),
        ("maximum", frame.maximum_rate_class),
    ):
        if not 0 <= value < T2_MAX_RATE_CLASSES:
            raise CodecError(f"T2 {name} rate class is out of range")
    if frame.requested_rate_class > frame.maximum_rate_class:
        raise CodecError("T2 requested class exceeds peer maximum")
    try:
        action = T2ScheduleAction(frame.action)
    except ValueError as exc:
        raise CodecError("unknown T2 schedule action") from exc

    header = bytearray(
        bytes(
            [
                T2_WIRE_PROFILE,
                PROTOCOL_VERSION,
                PRIVACY_PROFILE_U1,
                LIFECYCLE_PROFILE_E1,
            ]
        )
        + suite_id
        + bytes([int(T2FrameType.SCHEDULE), 0])
        + negotiation_id
        + frame.effective_epoch.to_bytes(4, "big")
        + bytes(
            [
                frame.current_rate_class,
                frame.requested_rate_class,
                frame.maximum_rate_class,
                int(action),
            ]
        )
    )
    if len(header) != CELL_HEADER_BYTES:
        raise AssertionError("unexpected T2 header length")
    body = bytes(header) + _randbytes(rng, CELL_PAYLOAD_BYTES)
    if len(body) != CELL_BODY_BYTES:
        raise AssertionError("unexpected T2 body length")
    return body


def decode_schedule_body(body: bytes) -> T2ScheduleFrame:
    if len(body) != CELL_BODY_BYTES:
        raise CodecError("invalid fixed T2 body length")
    if body[0] != T2_WIRE_PROFILE:
        raise CodecError("unsupported T2 wire profile")
    if body[1] != PROTOCOL_VERSION:
        raise CodecError("unsupported protocol version")
    if body[2] != PRIVACY_PROFILE_U1:
        raise CodecError("unsupported privacy profile")
    if body[3] != LIFECYCLE_PROFILE_E1:
        raise CodecError("unsupported lifecycle profile")
    suite_id = _require_suite_id(body[4:6])
    if body[6] != int(T2FrameType.SCHEDULE):
        raise CodecError("unknown T2 frame type")
    if body[7] != 0:
        raise CodecError("non-zero T2 reserved field")
    negotiation_id = _validate_message_local_id(body[8:24])
    effective_epoch = int.from_bytes(body[24:28], "big")
    current = body[28]
    requested = body[29]
    maximum = body[30]
    try:
        action = T2ScheduleAction(body[31])
    except ValueError as exc:
        raise CodecError("unknown T2 schedule action") from exc
    for name, value in (("current", current), ("requested", requested), ("maximum", maximum)):
        if value >= T2_MAX_RATE_CLASSES:
            raise CodecError(f"T2 {name} rate class is out of range")
    if requested > maximum:
        raise CodecError("T2 requested class exceeds peer maximum")
    return T2ScheduleFrame(
        crypto_suite_id=suite_id,
        negotiation_id=negotiation_id,
        effective_epoch=effective_epoch,
        current_rate_class=current,
        requested_rate_class=requested,
        maximum_rate_class=maximum,
        action=action,
    )
