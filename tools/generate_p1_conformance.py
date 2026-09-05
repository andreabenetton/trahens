#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate P1 M2 conformance vectors directly from the frozen registry.

This generator intentionally does not import simulator or implementation code.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "spec/protocol-registry-v1.8.json"


def varuint(value: int) -> bytes:
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        out.append(low | (0x80 if value else 0))
        if not value:
            return bytes(out)


def envelope(reg: dict, message_type: int, body: bytes) -> bytes:
    profiles = reg["protocol"]
    suite = int(reg["suites"]["r1"]).to_bytes(2, "big")
    prefix = bytes(
        [
            message_type,
            profiles["version"],
            profiles["privacy_profile_u1"],
            profiles["lifecycle_profile_e1"],
        ]
    ) + suite + bytes([profiles["message_profile_m2"], 0])
    return prefix + varuint(len(body)) + body


def build_vectors(reg: dict) -> list[dict]:
    ids = {key.upper(): value for key, value in reg["message_types"].items()}
    token = bytes(range(1, 17))
    label = bytes(range(17, 33))
    # Canonical compressed Ristretto255 base point; fixed independently of either runtime.
    reply = bytes.fromhex("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")
    nonce = bytes(range(65, 97))
    candidate_blob = bytes(range(97, 161))
    vectors: list[dict] = []

    # v1.6 split the suite-independent routing nonce out of the eligibility
    # field. One generator emits either profile so both vector sets stay
    # reproducible from their own registry.
    routing = bytes(range(161, 193)) if "routing_nonce" in reg["widths_bytes"] else b""
    bodies: dict[str, bytes] = {
        "CHAFF": b"",
        "DISCOVER": token
        + bytes([12, 1, 1, 0])
        + reply
        + routing
        + varuint(len(nonce))
        + nonce,
        "CANDIDATE": token + bytes([1, 2]) + varuint(len(candidate_blob)) + candidate_blob,
    }
    for name in [
        "COMMIT",
        "READY",
        "CANCEL",
        "ABORT",
        "CLOSE",
        "RENDEZVOUS_OPEN",
        "RENDEZVOUS_RESULT",
        "DATA",
    ]:
        protected = bytes([ids[name]]) + bytes(range(1, 34))
        bodies[name] = label + struct.pack(">I", 7) + bytes([1]) + varuint(len(protected)) + protected

    # P1 pins one expiry class, so any other value is noncanonical. Building
    # the bad bodies alongside the good ones avoids doing offset arithmetic on
    # an encoded message to find the byte.
    other = reg["limits"]["expiry_class_p1"] + 1
    bad_expiry: dict[str, bytes] = {
        "DISCOVER": token
        + bytes([12, 1, other, 0])
        + reply
        + routing
        + varuint(len(nonce))
        + nonce,
        "CANDIDATE": token + bytes([other, 2]) + varuint(len(candidate_blob)) + candidate_blob,
    }
    for name in [
        "COMMIT",
        "READY",
        "CANCEL",
        "ABORT",
        "CLOSE",
        "RENDEZVOUS_OPEN",
        "RENDEZVOUS_RESULT",
        "DATA",
    ]:
        protected = bytes([ids[name]]) + bytes(range(1, 34))
        bad_expiry[name] = (
            label + struct.pack(">I", 7) + bytes([other]) + varuint(len(protected)) + protected
        )

    for name, body in bodies.items():
        encoded = envelope(reg, ids[name], body)
        vectors.append(
            {
                "name": f"{name.lower()}-positive",
                "message": name,
                "valid": True,
                "encoding_hex": encoded.hex(),
            }
        )
        noncanonical = bytearray(encoded)
        noncanonical[7] = 1
        vectors.append(
            {
                "name": f"{name.lower()}-negative-reserved",
                "message": name,
                "valid": False,
                "encoding_hex": bytes(noncanonical).hex(),
                "expected_error": "unsupported_profile",
            }
        )
        if name in bad_expiry:
            vectors.append(
                {
                    "name": f"{name.lower()}-negative-expiry-class",
                    "message": name,
                    "valid": False,
                    "encoding_hex": envelope(reg, ids[name], bad_expiry[name]).hex(),
                    "expected_error": "malformed",
                }
            )

    return vectors


def write_corpus(path: Path, vectors: list[dict]) -> None:
    out = bytearray(b"TP15")
    out += struct.pack(">H", len(vectors))
    for vector in vectors:
        data = bytes.fromhex(vector["encoding_hex"])
        name = vector["name"].encode("ascii")
        out += bytes([1 if vector["valid"] else 0, len(name)])
        out += name
        out += struct.pack(">H", len(data))
        out += data
    path.write_bytes(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument("--json-output", type=Path, default=ROOT / "spec/p1-conformance-vectors-v1.8.json")
    parser.add_argument("--corpus-output", type=Path, default=ROOT / "spec/p1-conformance-corpus-v1.8.bin")
    args = parser.parse_args()
    reg = json.loads(args.registry.read_text(encoding="utf-8"))
    vectors = build_vectors(reg)
    document = {
        "schema": "trahens-p1-conformance-v1",
        "registry_version": reg["registry_version"],
        "generator_independence": f"manual encoder reads only {args.registry.name}",
        "vectors": vectors,
        "field_protection": reg["field_protection"],
    }
    args.json_output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    write_corpus(args.corpus_output, vectors)


if __name__ == "__main__":
    main()
