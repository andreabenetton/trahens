#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the B1.2 admission cookie test vectors.

Inputs are derived from fixed labels rather than randomness, so the output is
reproducible and `make check` can compare a fresh run against the committed
file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from trahens_crypto.cookie import issue, window_id
from trahens_spec.generated import LIMIT_COOKIE_WINDOW_MS

ROOT = Path(__file__).resolve().parent.parent


def seed(label: str) -> bytes:
    return hashlib.sha256(b"Trahens/cookie/test/" + label.encode()).digest()


def case(name: str, secret: bytes, source: bytes, port: int, window: int, offer: bytes) -> dict:
    return {
        "name": name,
        "responder_secret": secret.hex(),
        "source": source.hex(),
        "port": port,
        "window": window,
        "offer": offer.hex(),
        "cookie": issue(secret, source, port, window, offer).hex(),
    }


def build() -> dict[str, object]:
    secret = seed("responder-secret")
    previous = seed("responder-secret-previous")
    offer = seed("offer")[:20]
    ipv4 = bytes([10, 200, 0, 1])
    ipv6 = bytes.fromhex("20010db8000000000000000000000001")
    window = window_id(1_757_000_000_000)

    cases = [
        case("ipv4_current_window", secret, ipv4, 41000, window, offer),
        # Same everything but the window: a cookie must not carry across one.
        case("ipv4_previous_window", secret, ipv4, 41000, window - 1, offer),
        # Same everything but the secret, which is what rotation changes.
        case("ipv4_previous_secret", previous, ipv4, 41000, window, offer),
        # A different port is a different sender for this purpose.
        case("ipv4_other_port", secret, ipv4, 41001, window, offer),
        # An address whose length differs, to exercise the length prefix.
        case("ipv6_current_window", secret, ipv6, 41000, window, offer),
        # An empty offer still produces a cookie, and a different one.
        case("empty_offer", secret, ipv4, 41000, window, b""),
    ]

    distinct = {entry["cookie"] for entry in cases}
    if len(distinct) != len(cases):
        raise RuntimeError("two cases collided; the binding is not what it claims")

    return {
        "schema": "trahens-b12-cookie-vectors-v1",
        "window_ms": LIMIT_COOKIE_WINDOW_MS,
        "cases": cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "spec/b12-cookie-test-vectors.json")
    arguments = parser.parse_args()
    arguments.output.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {arguments.output}")


if __name__ == "__main__":
    main()
