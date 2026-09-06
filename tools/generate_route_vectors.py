#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the end-to-end route channel test vectors.

The route channel closed TR-01 of the 2026-09-04 review and was, until these
vectors, the one protocol layer with no cross-implementation check: a
third-party implementer had nothing normative to reproduce, and the Rust
implementation agreed only with itself.

Inputs are derived from fixed labels rather than randomness, so the output is
reproducible and `make check` can compare a fresh run against the committed
file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from trahens_crypto.route import (
    ENDPOINT_TO_GATEWAY,
    GATEWAY_TO_ENDPOINT,
    control_aad,
    route_keys,
    route_open,
    route_seal,
)

ROOT = Path(__file__).resolve().parent.parent

# Message types, from the registry. Named here only to label the vectors.
MESSAGE_COMMIT = 34
MESSAGE_READY = 35


def seed(label: str) -> bytes:
    return hashlib.sha256(b"Trahens/route/test/" + label.encode()).digest()


def record(
    name: str,
    keys,
    direction: int,
    sequence: int,
    message_type: int,
    generation: int,
    plaintext: bytes,
) -> dict[str, object]:
    key = keys.direction(direction)
    aad = control_aad(message_type, generation)
    sealed = route_seal(key, direction, sequence, plaintext, aad)
    # A vector is only meaningful if it round-trips, so a failure here is a
    # generator fault rather than a published value.
    opened_sequence, opened = route_open(key, direction, sealed, aad)
    if opened_sequence != sequence or opened != plaintext:
        raise RuntimeError(f"{name} does not round-trip")
    return {
        "name": name,
        "direction": direction,
        "sequence": sequence,
        "message_type": message_type,
        "generation": generation,
        "aad": aad.hex(),
        "plaintext": plaintext.hex(),
        "sealed": sealed.hex(),
    }


def build() -> dict[str, object]:
    route_secret = seed("route-secret")
    transcript = seed("offer-transcript")
    keys = route_keys(route_secret, transcript)

    # A second transcript with the same secret, to pin the property the
    # expansion context exists for: the same route secret under a different
    # selected offer derives different keys.
    other_transcript = seed("other-offer-transcript")
    other = route_keys(route_secret, other_transcript)
    if other.endpoint_to_gateway == keys.endpoint_to_gateway:
        raise RuntimeError("transcript binding is not in force")
    if keys.endpoint_to_gateway == keys.gateway_to_endpoint:
        raise RuntimeError("the two directions must not share a key")

    return {
        "schema": "trahens-route-channel-vectors-v1",
        "route_secret": route_secret.hex(),
        "offer_transcript_hash": transcript.hex(),
        "endpoint_to_gateway_key": keys.endpoint_to_gateway.hex(),
        "gateway_to_endpoint_key": keys.gateway_to_endpoint.hex(),
        "other_offer_transcript_hash": other_transcript.hex(),
        "other_endpoint_to_gateway_key": other.endpoint_to_gateway.hex(),
        "records": [
            record(
                "commit_from_endpoint",
                keys,
                ENDPOINT_TO_GATEWAY,
                0,
                MESSAGE_COMMIT,
                0,
                seed("commit-proof"),
            ),
            record(
                "ready_from_gateway",
                keys,
                GATEWAY_TO_ENDPOINT,
                0,
                MESSAGE_READY,
                0,
                seed("ready-proof"),
            ),
            # A later sequence in the same direction, so an implementation that
            # ignored the sequence in the nonce would produce the wrong bytes.
            record(
                "second_from_endpoint",
                keys,
                ENDPOINT_TO_GATEWAY,
                1,
                MESSAGE_COMMIT,
                0,
                seed("commit-proof"),
            ),
            # A non-zero generation, which the AAD binds.
            record(
                "commit_in_later_generation",
                keys,
                ENDPOINT_TO_GATEWAY,
                0,
                MESSAGE_COMMIT,
                7,
                seed("commit-proof"),
            ),
            # An empty body still seals to a tag-only ciphertext.
            record("empty_body", keys, GATEWAY_TO_ENDPOINT, 5, MESSAGE_READY, 0, b""),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "spec/route-channel-test-vectors.json"
    )
    arguments = parser.parse_args()
    arguments.output.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {arguments.output}")


if __name__ == "__main__":
    main()
