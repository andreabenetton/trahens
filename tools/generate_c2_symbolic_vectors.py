#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic Trahens C2 ideal-functionality vectors.

These vectors validate protocol composition and the symbolic security-game
harness. They are not cryptographic interoperability vectors for a concrete
anonymous Rand-RCCA construction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from trahens_crypto.c2_ideal import (
    C2IdealOracle,
    C2_MARKER,
    C2_SUITE_ID,
    apply_literal_tag,
)


def hx(value: bytes) -> str:
    return value.hex()


def build_vectors() -> dict[str, object]:
    oracle = C2IdealOracle(b"Trahens-C2/symbolic-vector-seed/v1")
    destination = oracle.keygen(b"destination")
    other = oracle.keygen(b"other-destination")
    original = oracle.encrypt(destination.public)
    rerandomized = oracle.rerandomize(original)
    rerandomized_twice = oracle.rerandomize(rerandomized)
    mutated = apply_literal_tag(rerandomized, b"\x80\x40\x20\x10", offset=17)

    return {
        "profile": "Trahens C2 executable ideal functionality",
        "status": "symbolic-only; not cryptographic interoperability data",
        "suite_id": hx(C2_SUITE_ID),
        "marker": hx(C2_MARKER),
        "destination": {
            "public": hx(destination.public),
            "descriptor": hx(destination.descriptor),
            "address": hx(destination.address),
        },
        "other_destination": {
            "public": hx(other.public),
            "address": hx(other.address),
        },
        "ciphertexts": {
            "original": hx(original),
            "rerandomized": hx(rerandomized),
            "rerandomized_twice": hx(rerandomized_twice),
            "mutated": hx(mutated),
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "rerandomized_sha256": hashlib.sha256(rerandomized).hexdigest(),
            "mutated_sha256": hashlib.sha256(mutated).hexdigest(),
        },
        "outcomes": {
            "original_eligible": oracle.is_eligible(destination.secret, original),
            "rerandomized_eligible": oracle.is_eligible(destination.secret, rerandomized),
            "rerandomized_twice_eligible": oracle.is_eligible(destination.secret, rerandomized_twice),
            "wrong_recipient_eligible": oracle.is_eligible(other.secret, rerandomized),
            "mutation_eligible": oracle.is_eligible(destination.secret, mutated),
            "original_rerandomized_equivalent": oracle.equivalent_for_test(original, rerandomized),
            "rerandomizations_equivalent": oracle.equivalent_for_test(rerandomized, rerandomized_twice),
            "mutation_registered": oracle.is_registered(mutated),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build_vectors(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
