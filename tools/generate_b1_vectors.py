#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic Trahens B1.1 handshake vectors from the v1.8 draft registry.

Every key is derived from a labelled digest so the vectors are reproducible
without any randomness. The Rust implementation must produce these records
byte for byte, and the same records are checked against an independent Noise
implementation, so a mistake in this reference shows up as a disagreement
rather than a silently shared error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from trahens_crypto.b1 import (
    Initiator,
    Keypair,
    Offer,
    Responder,
    Selection,
    load_profile,
    static_psk,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "spec/protocol-registry-v1.8.json"


def digest(label: bytes) -> bytes:
    return hashlib.sha256(b"Trahens/B1/vector/v1/" + label).digest()


def run_handshake(profile, label: bytes, previous_export: bytes | None) -> dict[str, object]:
    initiator_static = Keypair.from_secret(digest(label + b"/initiator/static"))
    responder_static = Keypair.from_secret(digest(label + b"/responder/static"))
    initiator_ephemeral = Keypair.from_secret(digest(label + b"/initiator/ephemeral"))
    responder_ephemeral = Keypair.from_secret(digest(label + b"/responder/ephemeral"))
    offer = Offer(
        version=profile.protocol_version,
        w2_profiles=(2,),
        t1_profiles=(3,),
        t2_profiles=(4,),
        suites=(0x0101, 0x0003),
        resource_class=1,
    )
    selection = Selection(profile.protocol_version, 2, 3, 4, 0x0101, 1)

    initiator = Initiator(
        profile, initiator_static, initiator_ephemeral, responder_static.public, offer, previous_export
    )
    responder = Responder(
        profile, responder_static, responder_ephemeral, initiator_static.public, previous_export
    )
    message_1 = initiator.write_message_1()
    responder.read_message_1(message_1)
    message_2 = responder.write_message_2(selection)
    initiator.read_message_2(message_2)
    message_3, initiator_session = initiator.write_message_3()
    responder_session = responder.read_message_3(message_3)
    # The two sides derive independently; a vector is only meaningful if they
    # agree, so disagreement is a generator failure rather than a published
    # value.
    for field in ("handshake_hash", "initiator_to_responder", "responder_to_initiator", "epoch", "export_key"):
        if getattr(initiator_session, field) != getattr(responder_session, field):
            raise RuntimeError(f"reference disagrees with itself on {field}")
    return {
        "label": label.decode(),
        "rekey": previous_export is not None,
        # The export key this exchange chains to, i.e. the psk0 pre-shared key.
        # Empty for an initial handshake. Published so an independent
        # implementation can replay the rekey without deriving it first.
        "chained_export_key": (previous_export or b"").hex(),
        # The psk0 key this exchange actually runs with: the chained export key
        # for a rekey, and the static-static value for an initial handshake.
        # Published for the same reason as the line above -- an independent
        # implementation replays the records without having to reproduce the
        # derivation first -- and pinned so that it must reproduce it in the
        # end. Both ends compute it from the manifest, so it is never sent.
        "psk": (
            previous_export
            if previous_export is not None
            else static_psk(profile, initiator_static, responder_static.public)
        ).hex(),
        "initiator_static_secret": initiator_static.secret.hex(),
        "initiator_static_public": initiator_static.public.hex(),
        "responder_static_secret": responder_static.secret.hex(),
        "responder_static_public": responder_static.public.hex(),
        "initiator_ephemeral_secret": initiator_ephemeral.secret.hex(),
        "responder_ephemeral_secret": responder_ephemeral.secret.hex(),
        "offer": offer.encode(profile).hex(),
        "selection": selection.encode().hex(),
        "message_1": message_1.hex(),
        "message_2": message_2.hex(),
        "message_3": message_3.hex(),
        "handshake_hash": initiator_session.handshake_hash.hex(),
        "initiator_to_responder_key": initiator_session.initiator_to_responder.hex(),
        "responder_to_initiator_key": initiator_session.responder_to_initiator.hex(),
        "epoch": initiator_session.epoch.hex(),
        "export_key": initiator_session.export_key.hex(),
    }


def build(registry: dict) -> dict[str, object]:
    profile = load_profile(registry)
    initial = run_handshake(profile, b"initial", None)
    rekey = run_handshake(profile, b"rekey", bytes.fromhex(str(initial["export_key"])))
    return {
        "schema": "trahens-b1-handshake-vectors-v1",
        "registry_version": registry["registry_version"],
        "noise_protocol": registry["domain_separators"]["b1_noise_protocol"],
        "record_bytes": registry["widths_bytes"]["b1_record"],
        "vectors": [initial, rekey],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument("--output", type=Path, default=ROOT / "spec/b1-test-vectors.json")
    args = parser.parse_args()
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    document = build(registry)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
