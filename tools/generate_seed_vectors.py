#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish B1.2 seed manifest vectors.

Two implementations must parse the same file identically, so the encoding is
pinned here rather than left to agreement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trahens_crypto.seed import FAMILY_V4, FAMILY_V6, SeedEntry, SeedManifest, encode

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "spec" / "protocol-registry-v1.8.json"


def digest(label: bytes) -> bytes:
    return hashlib.sha256(b"Trahens/B12/seed/v1/" + label).digest()


def build(registry: dict) -> dict[str, object]:
    version = int(registry["protocol"]["version"])
    signing_seed = digest(b"seed-key")
    seed_public = (
        Ed25519PrivateKey.from_private_bytes(signing_seed).public_key().public_bytes_raw()
    )

    cases = []
    # One entry, IPv4: the smallest manifest that means anything.
    single = SeedManifest(
        version,
        1_000,
        1_000 + 3_600_000,
        (SeedEntry(digest(b"peer/one"), FAMILY_V4, bytes([10, 201, 0, 1]), 45301),),
    )
    # Both families and several entries, so the list encoding is exercised
    # beyond one element and the variable-width address is exercised at all.
    mixed = SeedManifest(
        version,
        2_000,
        2_000 + 86_400_000,
        (
            SeedEntry(digest(b"peer/one"), FAMILY_V4, bytes([10, 201, 0, 1]), 45301),
            SeedEntry(digest(b"peer/two"), FAMILY_V6, digest(b"addr/v6")[:16], 45302),
            SeedEntry(digest(b"peer/three"), FAMILY_V4, bytes([10, 201, 1, 1]), 1),
        ),
    )
    for label, manifest in (("single-v4", single), ("mixed-families", mixed)):
        cases.append(
            {
                "label": label,
                "issued_ms": manifest.issued_ms,
                "expiry_ms": manifest.expiry_ms,
                "entries": [
                    {
                        "advertisement_key": entry.advertisement_key.hex(),
                        "family": entry.family,
                        "address": entry.address.hex(),
                        "port": entry.port,
                    }
                    for entry in manifest.entries
                ],
                "document": encode(manifest, signing_seed).hex(),
            }
        )

    documents = [case["document"] for case in cases]
    if len(set(documents)) != len(documents):
        raise RuntimeError("two published manifests are byte-identical")
    return {
        "schema": "trahens-b12-seed-manifest-vectors-v1",
        "registry_version": registry["registry_version"],
        "version": version,
        # Published so an independent implementation can verify without
        # deriving it, and pinned so it must derive the same one in the end.
        "seed_signing_seed": signing_seed.hex(),
        "seed_public_key": seed_public.hex(),
        "vectors": cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "spec/b12-seed-manifest-vectors.json"
    )
    args = parser.parse_args()
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    document = build(registry)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
