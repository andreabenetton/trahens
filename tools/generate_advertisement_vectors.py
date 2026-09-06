#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the B1.2 discovery advertisement test vectors.

Inputs are derived from fixed labels rather than randomness, so the output is
reproducible and `make check` can compare a fresh run against the committed
file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trahens_crypto.advertisement import Advertisement, decode, encode

ROOT = Path(__file__).resolve().parent.parent


def seed(label: str) -> bytes:
    return hashlib.sha256(b"Trahens/advertisement/test/" + label.encode()).digest()


def case(name: str, signing_seed: bytes, build) -> dict:
    key = (
        Ed25519PrivateKey.from_private_bytes(signing_seed)
        .public_key()
        .public_bytes_raw()
    )
    advertisement = build(key)
    datagram = encode(advertisement, signing_seed)
    # A vector is only meaningful if it round-trips, so a failure here is a
    # generator fault rather than a published value.
    if decode(datagram) != advertisement:
        raise RuntimeError(f"{name} does not round-trip")
    return {
        "name": name,
        "signing_seed": signing_seed.hex(),
        "key": key.hex(),
        "expiry_ms": advertisement.expiry_ms,
        "capacity_class": advertisement.capacity_class,
        "auth_modes": advertisement.auth_modes,
        "w2_profiles": list(advertisement.w2_profiles),
        "t1_profiles": list(advertisement.t1_profiles),
        "t2_profiles": list(advertisement.t2_profiles),
        "suites": list(advertisement.suites),
        "cookie": advertisement.cookie.hex() if advertisement.cookie else "",
        "datagram": datagram.hex(),
    }


def build() -> dict[str, object]:
    signing_seed = seed("advertiser")
    cookie = seed("cookie")

    cases = [
        case(
            "minimal",
            signing_seed,
            lambda key: Advertisement(3, key, 1_757_000_000_000, 1, 1, (2,), (3,), (4,), (0x0101,)),
        ),
        # A cookie present, which is the only optional field.
        case(
            "with_cookie",
            signing_seed,
            lambda key: Advertisement(
                3, key, 1_757_000_000_000, 1, 1, (2,), (3,), (4,), (0x0101,), cookie
            ),
        ),
        # Several profiles per class, so the list encoding is exercised beyond
        # a single entry.
        case(
            "several_profiles",
            signing_seed,
            lambda key: Advertisement(
                3, key, 1_757_000_000_000, 2, 3, (2, 5), (3, 6), (4, 7), (0x0101, 0x0003)
            ),
        ),
    ]

    distinct = {entry["datagram"] for entry in cases}
    if len(distinct) != len(cases):
        raise RuntimeError("two cases collided; the encoding is not what it claims")

    return {
        "schema": "trahens-b12-advertisement-vectors-v1",
        "cases": cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "spec/b12-advertisement-test-vectors.json"
    )
    arguments = parser.parse_args()
    arguments.output.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {arguments.output}")


if __name__ == "__main__":
    main()
