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
    encode_cookie_challenge,
    load_profile,
    rekey_psk,
    static_psk,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "spec/protocol-registry-v1.8.json"


def digest(label: bytes) -> bytes:
    return hashlib.sha256(b"Trahens/B1/vector/v1/" + label).digest()


def run_handshake(
    profile,
    label: bytes,
    previous_export: bytes | None,
    admission: dict[str, bytes] | None = None,
) -> dict[str, object]:
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

    # An admission exchange keys from the invitation rather than the manifest,
    # and the inviter has nothing to pin: it passes None and learns the joiner's
    # static key from the exchange.
    admission_kwargs = {}
    responder_kwargs = {}
    if admission is not None:
        admission_kwargs = {
            "admission_psk": admission["psk"],
            "admission_identifier": admission["identifier"],
            "admission_cookie": admission["cookie"],
        }
        # ADR 0049 D16: only the responder holds one, and it holds one always.
        responder_kwargs = {"advertisement_secret": admission["advertisement_secret"]}
    initiator = Initiator(
        profile,
        initiator_static,
        initiator_ephemeral,
        responder_static.public,
        offer,
        previous_export,
        **admission_kwargs,
    )
    responder = Responder(
        profile,
        responder_static,
        None if admission is not None else initiator_static.public,
        previous_export,
        **admission_kwargs,
        **responder_kwargs,
    )
    message_1 = initiator.write_message_1()
    responder.read_message_1(message_1)
    message_2 = responder.write_message_2(responder_ephemeral, selection)
    initiator.read_message_2(message_2)
    message_3, initiator_session = initiator.write_message_3()
    responder_session = responder.read_message_3(message_3)
    # The two sides derive independently; a vector is only meaningful if they
    # agree, so disagreement is a generator failure rather than a published
    # value.
    for field in ("handshake_hash", "initiator_to_responder", "responder_to_initiator", "epoch", "export_key"):
        if getattr(initiator_session, field) != getattr(responder_session, field):
            raise RuntimeError(f"reference disagrees with itself on {field}")
    if admission is not None and responder.promoted_static != initiator_static.public:
        raise RuntimeError("the inviter did not learn the joiner's key")
    return {
        "label": label.decode(),
        "rekey": previous_export is not None,
        "admission": admission is not None,
        # Empty on the manifest and rekey paths. On an admission exchange these
        # are the cleartext header of message 1, published so an independent
        # implementation can read them without state, which is what a responder
        # must do before it has any.
        "admission_identifier": (admission["identifier"] if admission else b"").hex(),
        "admission_cookie": (admission["cookie"] if admission else b"").hex(),
        # ADR 0049. Published so an independent implementation can verify the
        # transition without deriving the key, and pinned so it must end up
        # deriving the same one.
        "advertisement_secret": (
            admission["advertisement_secret"] if admission else b""
        ).hex(),
        "advertisement_key": (initiator.advertisement_key or b"").hex(),
        # The key the inviter had no way to pin and learned from the exchange.
        "promoted_static": (responder.promoted_static or b"").hex(),
        # The export key this exchange chains to, i.e. the psk0 pre-shared key.
        # Empty for an initial handshake. Published so an independent
        # implementation can replay the rekey without deriving it first.
        "chained_export_key": (previous_export or b"").hex(),
        # The psk0 key this exchange actually runs with: derived from the
        # chained export key for a rekey, and from the static-static value for
        # an initial handshake. Published for the same reason as the line above
        # -- an independent implementation replays the records without having
        # to reproduce the derivation first -- and pinned so that it must
        # reproduce it in the end. Both ends compute it, so it is never sent.
        "psk": (
            admission["psk"]
            if admission is not None
            else rekey_psk(profile, previous_export)
            if previous_export is not None
            else static_psk(
                profile, initiator_static, responder_static.public, initiator=True
            )
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
    # Two admission exchanges: one as a joiner sends it first, with no cookie it
    # could yet hold, and one as it resends after being challenged.
    #
    # Both run under the same label, so they share every key including the
    # ephemeral. That is deliberate and is what makes them a controlled
    # comparison: the cookie is the only thing that differs, so anything that
    # differs between them was caused by the cookie. A real joiner generates a
    # fresh ephemeral when it retries.
    #
    # The consequence of sharing one is worth naming, because the vectors show
    # it. The header is mixed with MixHash, where Noise puts pre-handshake
    # public data, so it changes the transcript hash, every record, and the
    # epoch and export key derived from the hash -- but not the directional
    # cell keys, because Split derives from the chaining key and MixHash does
    # not touch it. With distinct ephemerals those would differ too, from the
    # first Diffie-Hellman on. What the cookie must be is authenticated, and the
    # hash being the AEAD's associated data is what authenticates it.
    identifier = digest(b"admission/identifier")[: registry["widths_bytes"]["b12_invitation_id"]]
    cookie = digest(b"admission/cookie")[: registry["widths_bytes"]["b12_cookie"]]
    psk = digest(b"admission/psk")
    advertisement_secret = digest(b"admission/advertisement")
    challenged = run_handshake(
        profile,
        b"admission",
        None,
        {
            "psk": psk,
            "identifier": identifier,
            "cookie": cookie,
            "advertisement_secret": advertisement_secret,
        },
    )
    first_attempt = run_handshake(
        profile,
        b"admission",
        None,
        {
            "psk": psk,
            "identifier": identifier,
            "cookie": bytes(len(cookie)),
            "advertisement_secret": advertisement_secret,
        },
    )
    first_attempt["label"] = "admission-first-attempt"
    if first_attempt["handshake_hash"] == challenged["handshake_hash"]:
        raise RuntimeError("the cookie is not bound into the transcript")
    vectors = [initial, rekey, first_attempt, challenged]
    records = [v["message_1"] for v in vectors]
    if len(set(records)) != len(records):
        raise RuntimeError("two published exchanges share a first record")
    return {
        "schema": "trahens-b1-handshake-vectors-v1",
        "registry_version": registry["registry_version"],
        "noise_protocol": registry["domain_separators"]["b1_noise_protocol"],
        "record_bytes": registry["widths_bytes"]["b1_record"],
        "cookie_challenge": encode_cookie_challenge(profile, identifier, cookie).hex(),
        "vectors": vectors,
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
