from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import (
    CryptoError,
    URECiphertext,
    build_endpoint_keys,
    candidate_transcript_hash,
    reply_open,
    reply_seal,
    reply_tweak_public,
    reply_tweak_secret,
    ure_decrypt,
    ure_encrypt,
    ure_is_eligible,
    ure_rerandomize,
    verify_candidate_signature,
)


class C1CryptoTests(unittest.TestCase):
    def test_ure_rerandomization_preserves_marker_and_changes_encoding(self) -> None:
        endpoint = build_endpoint_keys(b"test-endpoint")
        ciphertext = ure_encrypt(
            endpoint.eligibility_public,
            r0=r255.scalar_from_label(b"test-r0"),
            r1=r255.scalar_from_label(b"test-r1"),
        )
        rerandomized = ure_rerandomize(
            ciphertext,
            s0=r255.scalar_from_label(b"test-s0"),
            s1=r255.scalar_from_label(b"test-s1"),
        )
        self.assertNotEqual(ciphertext.encode(), rerandomized.encode())
        self.assertTrue(ure_is_eligible(endpoint.eligibility_secret, rerandomized))
        self.assertEqual(ure_decrypt(endpoint.eligibility_secret, ciphertext), ure_decrypt(endpoint.eligibility_secret, rerandomized))


    def test_ure_rejects_identity_rerandomization_coins(self) -> None:
        endpoint = build_endpoint_keys(b"identity-rerandomization")
        ciphertext = ure_encrypt(
            endpoint.eligibility_public,
            r0=r255.scalar_from_label(b"identity-r0"),
            r1=r255.scalar_from_label(b"identity-r1"),
        )
        with self.assertRaisesRegex(CryptoError, "URE rerandomization failed"):
            ure_rerandomize(ciphertext, s0=bytes(32), s1=r255.scalar_from_label(b"valid-s1"))
        with self.assertRaisesRegex(CryptoError, "URE rerandomization failed"):
            ure_rerandomize(ciphertext, s0=r255.scalar_from_label(b"valid-s0"), s1=r255.SCALAR_ONE)

    def test_ure_wrong_key_and_malformed_ciphertext_fail(self) -> None:
        endpoint = build_endpoint_keys(b"target")
        wrong = build_endpoint_keys(b"wrong")
        ciphertext = ure_encrypt(
            endpoint.eligibility_public,
            r0=r255.scalar_from_label(b"r0"),
            r1=r255.scalar_from_label(b"r1"),
        )
        self.assertFalse(ure_is_eligible(wrong.eligibility_secret, ciphertext))
        with self.assertRaises(CryptoError):
            URECiphertext.decode(ciphertext.encode()[:-1])

    def test_reply_tweak_is_consistent_and_seal_opens(self) -> None:
        x0 = r255.scalar_from_label(b"x0")
        X0 = r255.scalarmult_base(x0)
        delta = r255.scalar_from_label(b"delta")
        x1 = reply_tweak_secret(x0, delta)
        X1 = reply_tweak_public(X0, delta)
        self.assertEqual(r255.scalarmult_base(x1), X1)
        sealed = reply_seal(
            X1,
            b"payload",
            aad=b"aad",
            info=b"info",
            ephemeral_secret=r255.scalar_from_label(b"ephemeral"),
        )
        self.assertEqual(reply_open(x1, sealed, aad=b"aad", info=b"info"), b"payload")

    def test_reply_tamper_and_context_mismatch_fail_uniformly(self) -> None:
        secret = r255.scalar_from_label(b"reply-secret")
        public = r255.scalarmult_base(secret)
        sealed = reply_seal(
            public,
            b"payload",
            aad=b"aad",
            info=b"info",
            ephemeral_secret=r255.scalar_from_label(b"reply-e"),
        )
        tampered = sealed[:-1] + bytes([sealed[-1] ^ 1])
        for candidate, aad, info in [
            (tampered, b"aad", b"info"),
            (sealed, b"bad-aad", b"info"),
            (sealed, b"aad", b"bad-info"),
        ]:
            with self.assertRaisesRegex(CryptoError, "reply decryption failed"):
                reply_open(secret, candidate, aad=aad, info=info)

    def test_candidate_signature_binds_transcript(self) -> None:
        endpoint = build_endpoint_keys(b"signer")
        transcript = candidate_transcript_hash([endpoint.address, b"offer", b"challenge"])
        signature = endpoint.sign(transcript)
        self.assertTrue(verify_candidate_signature(endpoint.signing_public, transcript, signature))
        other = candidate_transcript_hash([endpoint.address, b"other-offer", b"challenge"])
        self.assertFalse(verify_candidate_signature(endpoint.signing_public, other, signature))

    def test_tracked_vectors_are_reproducible(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        tracked = repository / "spec" / "crypto-test-vectors-c1.json"
        with tempfile.TemporaryDirectory() as temporary:
            generated = Path(temporary) / "vectors.json"
            subprocess.run(
                [
                    "python",
                    str(repository / "tools" / "generate_crypto_vectors.py"),
                    "--output",
                    str(generated),
                ],
                check=True,
                cwd=repository,
                env={"PYTHONPATH": str(repository / "simulator")},
            )
            self.assertEqual(json.loads(tracked.read_text()), json.loads(generated.read_text()))


if __name__ == "__main__":
    unittest.main()
