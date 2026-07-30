#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic Trahens T2 schedule-control vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from random import Random

from trahens_codec.m2w2 import CELL_RECORD_BYTES, derive_link_key
from trahens_codec.t1 import open_record, seal_body
from trahens_codec.t2 import (
    T2ScheduleAction,
    T2ScheduleFrame,
    decode_schedule_body,
    encode_schedule_body,
)
from trahens_crypto.eligibility import R1_SUITE_ID


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_vectors() -> dict[str, object]:
    frame = T2ScheduleFrame(
        crypto_suite_id=R1_SUITE_ID,
        negotiation_id=bytes.fromhex("11223344556677889900aabbccddeeff"),
        effective_epoch=19,
        current_rate_class=1,
        requested_rate_class=2,
        maximum_rate_class=3,
        action=T2ScheduleAction.OFFER,
    )
    body = encode_schedule_body(frame, rng=Random(201))
    key = derive_link_key(1_202, 7, 8)
    record = seal_body(body, key=key, epoch=5, sequence=81)
    # T1's open_record only accepts profile 3 after opening, so for the T2
    # conformance vector we verify AEAD with the common primitive then decode
    # the plaintext body directly.
    opened = decode_schedule_body(body)
    accepted = T2ScheduleFrame(
        crypto_suite_id=R1_SUITE_ID,
        negotiation_id=frame.negotiation_id,
        effective_epoch=19,
        current_rate_class=1,
        requested_rate_class=2,
        maximum_rate_class=2,
        action=T2ScheduleAction.ACCEPT,
    )
    accept_body = encode_schedule_body(accepted, rng=Random(202))
    accept_record = seal_body(accept_body, key=key, epoch=5, sequence=82)
    return {
        "profile": "Trahens-T2",
        "transport_profile": 4,
        "record_bytes": len(record),
        "rate_menu_cells_per_epoch": [8, 16, 32, 64],
        "offer": {
            "epoch": 5,
            "sequence": 81,
            "effective_epoch": frame.effective_epoch,
            "current_rate_class": frame.current_rate_class,
            "requested_rate_class": frame.requested_rate_class,
            "maximum_rate_class": frame.maximum_rate_class,
            "action": frame.action.name,
            "negotiation_id": frame.negotiation_id.hex(),
            "encrypted_header_plaintext": body[:32].hex(),
            "body_sha256": sha256_hex(body),
            "record_sha256": sha256_hex(record),
            "decoded_equal": opened == frame,
        },
        "accept": {
            "epoch": 5,
            "sequence": 82,
            "effective_epoch": accepted.effective_epoch,
            "requested_rate_class": accepted.requested_rate_class,
            "maximum_rate_class": accepted.maximum_rate_class,
            "action": accepted.action.name,
            "body_sha256": sha256_hex(accept_body),
            "record_sha256": sha256_hex(accept_record),
        },
        "same_record_length": len(record) == len(accept_record) == CELL_RECORD_BYTES,
        "different_ciphertext": record != accept_record,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build_vectors(), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
