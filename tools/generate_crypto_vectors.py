#!/usr/bin/env python3
"""Generate deterministic Trahens C1 conformance vectors."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

os.environ.setdefault("TRAHENS_TEST_CRYPTO", "1")

from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import (
    C1_SUITE_ID,
    build_endpoint_keys,
    candidate_transcript_hash,
    eligibility_marker,
    reply_open,
    reply_blind_public,
    reply_blind_secret,
    ure_decrypt,
    ure_encrypt,
    ure_is_eligible,
    ure_rerandomize,
    verify_candidate_signature,
)
from vector_crypto_support import reply_seal_deterministic


def hx(value: bytes) -> str:
    return value.hex()


def build_vectors() -> dict[str, object]:
    endpoint = build_endpoint_keys(b"endpoint-alice")
    wrong_endpoint = build_endpoint_keys(b"endpoint-mallory")

    r0 = r255.scalar_from_label(b"vector/ure/r0")
    r1 = r255.scalar_from_label(b"vector/ure/r1")
    s0 = r255.scalar_from_label(b"vector/ure/s0")
    s1 = r255.scalar_from_label(b"vector/ure/s1")
    original = ure_encrypt(endpoint.eligibility_public, r0=r0, r1=r1)
    rerandomized = ure_rerandomize(original, s0=s0, s1=s1)

    x0 = r255.scalar_from_label(b"vector/reply/x0")
    X0 = r255.scalarmult_base(x0)
    blinding0 = r255.scalar_from_label(b"vector/reply/blinding0")
    x1 = reply_blind_secret(x0, blinding0)
    X1 = reply_blind_public(X0, blinding0)
    ephemeral = r255.scalar_from_label(b"vector/reply/ephemeral")
    aad = b"candidate-token=00112233445566778899aabbccddeeff"
    info = b"CANDIDATE/layer/1"
    plaintext = b"blinding-factor-and-child-capsule"
    sealed = reply_seal_deterministic(
        X1, plaintext, aad=aad, info=info, ephemeral_secret=ephemeral
    )
    opened = reply_open(x1, sealed, aad=aad, info=info)

    transcript = candidate_transcript_hash([
        endpoint.address,
        b"offer-class-01",
        b"commit-challenge-0001",
        X1,
    ])
    signature = endpoint.sign(transcript)

    return {
        "profile": "Trahens C1 research profile",
        "suite_id": hx(C1_SUITE_ID),
        "group": "ristretto255",
        "eligibility": {
            "secret": hx(endpoint.eligibility_secret),
            "public": hx(endpoint.eligibility_public),
            "signing_seed": hx(endpoint.signing_seed),
            "signing_public": hx(endpoint.signing_public),
            "descriptor": hx(endpoint.descriptor),
            "address": hx(endpoint.address),
            "marker": hx(eligibility_marker()),
            "r0": hx(r0),
            "r1": hx(r1),
            "ciphertext": hx(original.encode()),
            "s0": hx(s0),
            "s1": hx(s1),
            "rerandomized_ciphertext": hx(rerandomized.encode()),
            "decrypted_marker": hx(ure_decrypt(endpoint.eligibility_secret, rerandomized)),
            "eligible": ure_is_eligible(endpoint.eligibility_secret, rerandomized),
            "wrong_key_eligible": ure_is_eligible(wrong_endpoint.eligibility_secret, rerandomized),
        },
        "reply_kem": {
            "root_secret": hx(x0),
            "root_public": hx(X0),
            "blinding_factor": hx(blinding0),
            "blinded_secret": hx(x1),
            "blinded_public": hx(X1),
            "public_from_blinded_secret": hx(r255.scalarmult_base(x1)),
            "ephemeral_secret": hx(ephemeral),
            "aad": hx(aad),
            "info": hx(info),
            "plaintext": hx(plaintext),
            "sealed": hx(sealed),
            "opened": hx(opened),
        },
        "candidate_authentication": {
            "transcript_hash": hx(transcript),
            "signature": hx(signature),
            "verified": verify_candidate_signature(endpoint.signing_public, transcript, signature),
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
