#!/usr/bin/env python3
"""Generate deterministic Trahens T1 framing and retry vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from random import Random

from trahens_codec.m2w2 import CandidateRecord, derive_link_key, encode_candidate
from trahens_codec.t1 import (
    ack_bitmap,
    encode_ack_body,
    encode_chaff_body,
    encode_data_body,
    open_record,
    seal_body,
    split_message,
)
from trahens_crypto.eligibility import R1_SUITE_ID


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_vectors() -> dict[str, object]:
    candidate_blob = bytes((index * 37 + 11) % 256 for index in range(1_600))
    message = encode_candidate(
        CandidateRecord(
            candidate_token=bytes.fromhex("00112233445566778899aabbccddeeff"),
            expiry_class=3,
            layer_count=12,
            candidate_blob=candidate_blob,
            crypto_suite_id=R1_SUITE_ID,
        )
    )
    transmission_id = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
    frames = split_message(message, transmission_id=transmission_id)
    key = derive_link_key(1_101, 4, 5)

    first_body = encode_data_body(frames[-1], rng=Random(101))
    retry_body = encode_data_body(frames[-1], rng=Random(102))
    first_record = seal_body(first_body, key=key, epoch=7, sequence=41)
    retry_record = seal_body(retry_body, key=key, epoch=7, sequence=42)

    received = {0, len(frames) - 1}
    bitmap = ack_bitmap(received, len(frames))
    ack_body = encode_ack_body(
        crypto_suite_id=R1_SUITE_ID,
        transmission_id=transmission_id,
        fragment_count=len(frames),
        acknowledged_bitmap=bitmap,
        ack_delay_ms=6,
        rng=Random(103),
    )
    ack_record = seal_body(ack_body, key=key, epoch=7, sequence=43)

    chaff_id = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    chaff_body = encode_chaff_body(
        crypto_suite_id=R1_SUITE_ID,
        transmission_id=chaff_id,
        rng=Random(104),
    )
    chaff_record = seal_body(chaff_body, key=key, epoch=7, sequence=44)

    opened_data = open_record(
        first_record, key=key, expected_epoch=7, expected_sequence=41
    )[2]
    opened_ack = open_record(
        ack_record, key=key, expected_epoch=7, expected_sequence=43
    )[2]
    opened_chaff = open_record(
        chaff_record, key=key, expected_epoch=7, expected_sequence=44
    )[2]

    return {
        "profile": "Trahens-T1",
        "transport_profile": 3,
        "crypto_suite": R1_SUITE_ID.hex(),
        "record_bytes": len(first_record),
        "logical_message": {
            "type": "CANDIDATE",
            "length": len(message),
            "sha256": sha256_hex(message),
            "fragment_count": len(frames),
            "fragment_lengths": [frame.fragment_length for frame in frames],
        },
        "data_first_emission": {
            "epoch": 7,
            "sequence": 41,
            "transmission_id": transmission_id.hex(),
            "encrypted_header_plaintext": first_body[:32].hex(),
            "body_sha256": sha256_hex(first_body),
            "record_sha256": sha256_hex(first_record),
            "decoded_frame": type(opened_data).__name__,
        },
        "data_retry": {
            "epoch": 7,
            "sequence": 42,
            "same_transmission_id": True,
            "same_fragment": True,
            "fresh_body": retry_body != first_body,
            "fresh_record": retry_record != first_record,
            "body_sha256": sha256_hex(retry_body),
            "record_sha256": sha256_hex(retry_record),
        },
        "selective_ack": {
            "epoch": 7,
            "sequence": 43,
            "acknowledged_indexes": sorted(received),
            "bitmap": bitmap,
            "ack_delay_ms": 6,
            "encrypted_header_plaintext": ack_body[:32].hex(),
            "record_sha256": sha256_hex(ack_record),
            "decoded_frame": type(opened_ack).__name__,
        },
        "chaff": {
            "epoch": 7,
            "sequence": 44,
            "transmission_id": chaff_id.hex(),
            "encrypted_header_plaintext": chaff_body[:32].hex(),
            "record_sha256": sha256_hex(chaff_record),
            "decoded_frame": type(opened_chaff).__name__,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build_vectors(), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
