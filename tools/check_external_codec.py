#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check a third-party M2 decoder against the published P1 corpus.

A second implementation can be checked here before it can speak the wire at
all, which is the cheapest place to find a disagreement.

The contract is deliberately three lines long, so that adopting it costs
nothing and it cannot itself become a source of divergence:

    - the decoder is run once per vector;
    - one vector's encoding arrives on stdin as raw bytes;
    - exit status 0 means accepted, any other status means rejected.

Anything the decoder writes to stdout or stderr is ignored, so an existing
test binary usually needs no changes.

Rejecting the noncanonical vectors is the half that matters. A decoder that
accepts one will interoperate perfectly with a correct peer and diverge only
against a hostile or buggy one, which is the failure this catches.
"""
from __future__ import annotations

import argparse
import shlex
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "spec/p1-conformance-corpus-v1.8.bin"


def vectors(path: Path) -> list[tuple[bool, str, bytes]]:
    data = path.read_bytes()
    if data[:4] != b"TP15":
        raise SystemExit(f"{path}: not a P1 conformance corpus")
    cursor = 4
    (count,) = struct.unpack_from(">H", data, cursor)
    cursor += 2
    out: list[tuple[bool, str, bytes]] = []
    for _ in range(count):
        valid = data[cursor] == 1
        name_length = data[cursor + 1]
        cursor += 2
        name = data[cursor : cursor + name_length].decode("ascii")
        cursor += name_length
        (length,) = struct.unpack_from(">H", data, cursor)
        cursor += 2
        out.append((valid, name, data[cursor : cursor + length]))
        cursor += length
    if cursor != len(data):
        raise SystemExit(f"{path}: trailing bytes after {count} vectors")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", help="decoder command; encoding arrives on stdin")
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    command = shlex.split(args.command)
    accepted_noncanonical: list[str] = []
    rejected_canonical: list[str] = []
    checked = 0

    for valid, name, encoding in vectors(args.corpus):
        try:
            result = subprocess.run(
                command,
                input=encoding,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=args.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise SystemExit(f"{name}: decoder did not terminate within {args.timeout}s")
        except FileNotFoundError:
            raise SystemExit(f"cannot run decoder: {args.command}")
        accepted = result.returncode == 0
        checked += 1
        if valid and not accepted:
            rejected_canonical.append(name)
        elif not valid and accepted:
            accepted_noncanonical.append(name)

    for name in rejected_canonical:
        print(f"REJECTED a canonical encoding: {name}", file=sys.stderr)
    for name in accepted_noncanonical:
        print(f"ACCEPTED a noncanonical encoding: {name}", file=sys.stderr)

    if rejected_canonical or accepted_noncanonical:
        raise SystemExit(
            f"{len(rejected_canonical) + len(accepted_noncanonical)} of {checked} vectors disagree"
        )
    print(f"decoder agrees with all {checked} published P1 vectors")


if __name__ == "__main__":
    main()
