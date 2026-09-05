#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Print the distinct W2 link epochs a capture contains, one per line.

Since v1.8 the epoch is derived from the B1.1 handshake rather than configured,
so two runs of the same topology with the same static keys must still use
different epochs. That is what makes restarting into a used epoch impossible,
and the epoch is the one field of a W2 record on the wire in the clear, so a
capture is enough to check it.

Handshake records are skipped: they begin with a zero byte, which a derived
epoch never does.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from check_pcap_cells import packets, udp_payload_length


def udp_payload(frame: bytes) -> bytes | None:
    """The UDP payload of an IPv4 frame, or None if it is not one."""
    length = udp_payload_length(frame)
    if length is None:
        return None
    return frame[len(frame) - length :] if length else b""


def epochs(path: Path) -> set[int]:
    seen: set[int] = set()
    for frame, _original in packets(path):
        payload = udp_payload(frame)
        if not payload or len(payload) < 4:
            continue
        # A derived epoch always has its top bit set, so a leading zero byte is
        # a handshake record rather than a cell.
        if payload[0] == 0:
            continue
        seen.add(int.from_bytes(payload[:4], "big"))
    return seen


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcaps", nargs="+", type=Path)
    args = parser.parse_args()
    found: set[int] = set()
    for path in args.pcaps:
        found |= epochs(path)
    for epoch in sorted(found):
        print(f"{epoch:08x}")


if __name__ == "__main__":
    main()
