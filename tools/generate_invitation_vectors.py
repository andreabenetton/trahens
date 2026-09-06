#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the B1.2 invitation pre-shared key test vectors.

Inputs are derived from fixed labels rather than randomness, so the output is
reproducible and `make check` can compare a fresh run against the committed
file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from trahens_crypto.invitation import invitation_psk

ROOT = Path(__file__).resolve().parent.parent


def seed(label: str) -> bytes:
    return hashlib.sha256(b"Trahens/invitation/test/" + label.encode()).digest()


def case(name: str, identifier: bytes, secret: bytes) -> dict:
    return {
        "name": name,
        "identifier": identifier.hex(),
        "secret": secret.hex(),
        "psk": invitation_psk(identifier, secret).hex(),
    }


def build() -> dict[str, object]:
    first_id = seed("identifier-a")[:16]
    second_id = seed("identifier-b")[:16]
    first_secret = seed("secret-a")
    second_secret = seed("secret-b")

    cases = [
        case("first", first_id, first_secret),
        # Same secret under a different identifier: the identifier is bound, so
        # a secret cannot be presented under an identifier it was not issued
        # with.
        case("same_secret_other_identifier", second_id, first_secret),
        # Same identifier under a different secret.
        case("same_identifier_other_secret", first_id, second_secret),
    ]

    distinct = {entry["psk"] for entry in cases}
    if len(distinct) != len(cases):
        raise RuntimeError("two cases collided; the binding is not what it claims")

    return {"schema": "trahens-b12-invitation-vectors-v1", "cases": cases}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "spec/b12-invitation-test-vectors.json"
    )
    arguments = parser.parse_args()
    arguments.output.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {arguments.output}")


if __name__ == "__main__":
    main()
