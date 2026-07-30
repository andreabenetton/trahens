#!/usr/bin/env python3
"""Generate deterministic Trahens R1 rendezvous-capability vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from trahens_crypto.eligibility import (
    R1_CAPABILITY_BYTES,
    R1_DISCOVERY_NONCE_BYTES,
    R1_SERVICE_CLASS,
    R1_SUITE_ID,
    R1RendezvousSuite,
    RendezvousRegistry,
    capability_commitment,
)


def hx(value: bytes) -> str:
    return value.hex()


def digest(label: bytes) -> bytes:
    return hashlib.sha256(b"Trahens/R1/vector/v1/" + label).digest()


class DeterministicBytes:
    def __init__(self, values: list[bytes]) -> None:
        self._values = list(values)

    def __call__(self, size: int) -> bytes:
        if not self._values:
            raise RuntimeError("deterministic byte stream exhausted")
        value = self._values.pop(0)
        if len(value) != size:
            raise RuntimeError("deterministic byte stream size mismatch")
        return value


def build_vectors() -> dict[str, object]:
    capability = digest(b"capability")
    nonce_0 = digest(b"discover/0")
    nonce_1 = digest(b"discover/1")
    nonce_2 = digest(b"discover/2")
    endpoint_handle = digest(b"endpoint-handle")

    suite = R1RendezvousSuite(DeterministicBytes([nonce_0, nonce_1, nonce_2]))
    observed_0 = suite.initial_capsule()
    observed_1 = suite.transform(observed_0)
    observed_2 = suite.transform(observed_1)

    registry = RendezvousRegistry()
    record = registry.register(
        gateway_id=7,
        token=capability,
        endpoint_handle=endpoint_handle,
        now_ms=1_000,
        ttl_ms=5_000,
    )
    wrong_gateway = registry.redeem(gateway_id=8, token=capability, now_ms=2_000)
    first_redemption = registry.redeem(gateway_id=7, token=capability, now_ms=2_000)
    replay_redemption = registry.redeem(gateway_id=7, token=capability, now_ms=2_001)

    expiry_registry = RendezvousRegistry()
    expiry_registry.register(
        gateway_id=9,
        token=digest(b"expired-capability"),
        endpoint_handle=digest(b"expired-endpoint-handle"),
        now_ms=10_000,
        ttl_ms=100,
    )
    expired_redemption = expiry_registry.redeem(
        gateway_id=9,
        token=digest(b"expired-capability"),
        now_ms=10_100,
    )

    return {
        "profile": "Trahens R1 rendezvous capability profile",
        "version": 1,
        "suite_id": hx(R1_SUITE_ID),
        "service_class": hx(R1_SERVICE_CLASS),
        "sizes": {
            "capability_bytes": R1_CAPABILITY_BYTES,
            "discovery_nonce_bytes": R1_DISCOVERY_NONCE_BYTES,
        },
        "discovery": {
            "nonce_0": hx(observed_0),
            "nonce_1": hx(observed_1),
            "nonce_2": hx(observed_2),
            "all_distinct": len({observed_0, observed_1, observed_2}) == 3,
            "tagged_prefix": hx(b"tag-marker"),
            "tag_survives_replacement": observed_1.startswith(b"tag-marker"),
        },
        "capability": {
            "token": hx(capability),
            "commitment": hx(capability_commitment(capability)),
            "registry_hash": hx(record.token_hash),
            "gateway_id": record.gateway_id,
            "created_at_ms": record.created_at_ms,
            "expires_at_ms": record.expires_at_ms,
            "endpoint_handle": hx(endpoint_handle),
            "wrong_gateway_redemption": None if wrong_gateway is None else hx(wrong_gateway),
            "first_redemption": None if first_redemption is None else hx(first_redemption),
            "replay_redemption": None if replay_redemption is None else hx(replay_redemption),
            "live_records_after_redemption": registry.live_records,
            "expired_redemption": None if expired_redemption is None else hx(expired_redemption),
            "expired_live_records": expiry_registry.live_records,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_vectors(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
