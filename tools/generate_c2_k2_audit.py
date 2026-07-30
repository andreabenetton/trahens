#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from trahens_crypto.c2_klinear import (
    C2Ciphertext,
    audit_literal_rerandomization,
    eligibility_message,
    encrypt,
    keygen,
    mutate_component,
    parameter_summary,
    rerandomize_strands_only,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    keys = keygen(b"Trahens-C2-K2/audit-key/v1", b"destination")
    original = encrypt(
        keys.public,
        eligibility_message(),
        b"Trahens-C2-K2/audit-encryption/v1",
    )
    strand = rerandomize_strands_only(
        original,
        b"Trahens-C2-K2/audit-strands/v1",
    )
    mutated = mutate_component(original.encode(), 4, 7)
    result = {
        "profile": "C2-K2 arithmetic transcription audit",
        "source_construction": {
            "title": "Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems Resolved",
            "venue": "CRYPTO 2021",
            "doi": "10.1007/978-3-030-84259-8_10",
            "eprint": "2021/862",
            "construction": "Figure 6 k-Lin instantiation",
            "literal_tag_map_source": "Section 2, pages 5-6; Section 6.3, Figure 6",
        },
        "parameters": parameter_summary(),
        "status": audit_literal_rerandomization(
            keys,
            b"Trahens-C2-K2/audit-encryption/v1",
            b"Trahens-C2-K2/audit-full-rerandomization/v1",
        ),
        "vectors": {
            "public_key_sha256": hashlib.sha256(keys.public.encode()).hexdigest(),
            "destination_address": keys.address.hex(),
            "original_ciphertext": original.encode().hex(),
            "original_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "strand_rerandomized_ciphertext": strand.encode().hex(),
            "strand_rerandomized_sha256": hashlib.sha256(strand.encode()).hexdigest(),
            "mutated_component_4_sha256": hashlib.sha256(mutated).hexdigest(),
            "decoded_round_trip": C2Ciphertext.decode(original.encode()).encode().hex()
            == original.encode().hex(),
        },
        "interpretation": {
            "approved_for_protocol": False,
            "reason": (
                "The literal finite-field transcription validates key generation, encryption, "
                "decryption, encoding, and linear strand rerandomization. A non-identity tag "
                "multiplier does not validate because the stated integer reduction u -> u mod q "
                "is not a multiplicative homomorphism from QR*_p to Z_q. The report includes both "
                "a small exact counterexample and the deterministic conformance-parameter witness. "
                "The operational C2 backend remains the symbolic ideal functionality until a "
                "different reviewed action or a corrected independently reproduced construction "
                "is available."
            ),
        },
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
