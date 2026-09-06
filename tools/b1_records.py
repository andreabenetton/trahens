#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Count B1.1 handshake records by type in a capture.

Handshake records carry their type in the clear: a zero byte, then the type
from `b1_record_types`. A derived epoch never begins with a zero byte, which is
what separates a record from a W2 cell without trial decryption.

This exists to check ADR 0044 on the wire. Under `psk0` a first message that
does not decrypt is refused before any Diffie-Hellman and draws no reply, so a
run whose initiator holds the wrong pinned key must show initiate records and
no respond record. Before ADR 0044 the responder answered anything well formed,
so the same run would have shown both.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from check_pcap_cells import packets, udp_payload_length

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "spec" / "protocol-registry-v1.8.json"


def record_types() -> dict[int, str]:
    """Type byte to name, from the registry rather than restated here."""
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return {int(value): name for name, value in registry["b1_record_types"].items()}


def udp_payload(frame: bytes) -> bytes | None:
    length = udp_payload_length(frame)
    if length is None:
        return None
    return frame[len(frame) - length :] if length else b""


def counts(paths: list[Path]) -> dict[str, int]:
    names = record_types()
    found = {name: 0 for name in names.values()}
    for path in paths:
        for frame, _original in packets(path):
            payload = udp_payload(frame)
            if not payload or len(payload) < 2:
                continue
            if payload[0] != 0:
                continue
            name = names.get(payload[1])
            if name is not None:
                found[name] += 1
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", nargs="+", type=Path)
    parser.add_argument(
        "--expect-absent",
        action="append",
        default=[],
        help="record type name that must not appear; may be repeated",
    )
    parser.add_argument(
        "--expect-present",
        action="append",
        default=[],
        help="record type name that must appear at least once; may be repeated",
    )
    arguments = parser.parse_args()

    found = counts(arguments.pcaps)
    for name, count in sorted(found.items()):
        print(f"{name} {count}")

    known = set(found)
    status = 0
    for name in arguments.expect_absent:
        if name not in known:
            print(f"unknown record type {name}", flush=True)
            return 2
        if found[name]:
            print(f"expected no {name} record, found {found[name]}", flush=True)
            status = 1
    for name in arguments.expect_present:
        if name not in known:
            print(f"unknown record type {name}", flush=True)
            return 2
        if not found[name]:
            print(f"expected at least one {name} record, found none", flush=True)
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
