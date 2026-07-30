#!/usr/bin/env python3
"""Verify that every captured IPv4 UDP payload is one fixed-size W2 record."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path


def packets(path: Path):
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError(f"{path}: truncated pcap")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError(f"{path}: unsupported pcap format")
    network = struct.unpack_from(endian + "I", data, 20)[0]
    if network != 1:
        raise ValueError(f"{path}: expected Ethernet link type, got {network}")
    cursor = 24
    while cursor < len(data):
        if cursor + 16 > len(data):
            raise ValueError(f"{path}: truncated packet header")
        _sec, _usec, captured, original = struct.unpack_from(endian + "IIII", data, cursor)
        cursor += 16
        payload = data[cursor : cursor + captured]
        if len(payload) != captured:
            raise ValueError(f"{path}: truncated packet")
        cursor += captured
        yield payload, original


def udp_payload_length(frame: bytes) -> int | None:
    if len(frame) < 14:
        return None
    ether_type = int.from_bytes(frame[12:14], "big")
    offset = 14
    if ether_type == 0x8100 and len(frame) >= 18:
        ether_type = int.from_bytes(frame[16:18], "big")
        offset = 18
    if ether_type != 0x0800 or len(frame) < offset + 20:
        return None
    version_ihl = frame[offset]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(frame) < offset + ihl + 8 or frame[offset + 9] != 17:
        return None
    udp = offset + ihl
    udp_length = int.from_bytes(frame[udp + 4 : udp + 6], "big")
    if udp_length < 8:
        raise ValueError("invalid UDP length")
    return udp_length - 8


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcaps", nargs="+", type=Path)
    parser.add_argument("--expected", type=int, default=1052)
    args = parser.parse_args()
    udp_packets = 0
    bad: list[tuple[str, int]] = []
    for path in args.pcaps:
        for frame, _original in packets(path):
            length = udp_payload_length(frame)
            if length is None:
                continue
            udp_packets += 1
            if length != args.expected:
                bad.append((str(path), length))
    if udp_packets == 0:
        raise SystemExit("no UDP packets found in captures")
    if bad:
        raise SystemExit(f"non-fixed W2 UDP payloads found: {bad[:10]}")
    print(f"verified {udp_packets} UDP packets at {args.expected} bytes")


if __name__ == "__main__":
    main()
