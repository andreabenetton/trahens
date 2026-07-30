# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import unittest

from trahens_crypto.c2_klinear import (
    C2_CONCRETE_CIPHERTEXT_BYTES,
    C2_K,
    C2_SUITE_ID,
    C2Ciphertext,
    C2ConformanceGap,
    C2Error,
    audit_literal_rerandomization,
    decrypt,
    eligibility_message,
    encrypt,
    is_eligible,
    keygen,
    mutate_component,
    parameter_summary,
    rerandomize,
    rerandomize_strands_only,
    small_tag_reduction_counterexample,
    tag_action_equation,
)


class C2KLinearAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alice = keygen(b"c2-k2-alice", b"alice")
        self.bob = keygen(b"c2-k2-bob", b"bob")
        self.ciphertext = encrypt(
            self.alice.public,
            eligibility_message(),
            b"c2-k2-encryption",
        )

    def test_profile_uses_k_two_and_reserved_audit_suite(self) -> None:
        self.assertEqual(C2_K, 2)
        self.assertEqual(C2_SUITE_ID, b"\x7f\x02")
        self.assertEqual(len(self.ciphertext.encode()), C2_CONCRETE_CIPHERTEXT_BYTES)

    def test_encrypt_decrypt_and_wrong_recipient(self) -> None:
        self.assertEqual(decrypt(self.alice.secret, self.ciphertext), eligibility_message())
        self.assertTrue(is_eligible(self.alice.secret, self.ciphertext.encode()))
        self.assertFalse(is_eligible(self.bob.secret, self.ciphertext.encode()))

    def test_canonical_ciphertext_round_trip(self) -> None:
        encoded = self.ciphertext.encode()
        self.assertEqual(C2Ciphertext.decode(encoded).encode(), encoded)
        with self.assertRaises(C2Error):
            C2Ciphertext.decode(encoded[:-1])
        with self.assertRaises(C2Error):
            C2Ciphertext.decode(bytes([encoded[0] ^ 1]) + encoded[1:])

    def test_component_mutation_is_rejected(self) -> None:
        for component in (0, 3, 9, 12, 15, 23):
            mutated = mutate_component(self.ciphertext.encode(), component)
            self.assertFalse(is_eligible(self.alice.secret, mutated))

    def test_linear_strand_equations_are_executable(self) -> None:
        transformed = rerandomize_strands_only(self.ciphertext, b"c2-k2-strands")
        self.assertNotEqual(transformed.encode(), self.ciphertext.encode())
        self.assertEqual(decrypt(self.alice.secret, transformed), eligibility_message())

    def test_full_backend_is_fail_closed(self) -> None:
        with self.assertRaises(C2ConformanceGap):
            rerandomize(self.ciphertext, b"c2-k2-full")

    def test_audit_records_nonhomomorphic_finite_field_result(self) -> None:
        result = audit_literal_rerandomization(
            self.alice,
            b"c2-k2-audit-encryption",
            b"c2-k2-audit-rerandomization",
        )
        self.assertTrue(result["encrypt_decrypt"])
        self.assertTrue(result["strand_rerandomization"])
        self.assertFalse(result["literal_nontrivial_tag_rerandomization"])
        self.assertFalse(result["tag_reduction_homomorphism"])
        self.assertEqual(result["status"], "finite-field-tag-reduction-nonhomomorphic")
        self.assertFalse(result["deployment_approved"])

    def test_literal_mod_q_tag_map_is_not_a_group_homomorphism(self) -> None:
        witness = small_tag_reduction_counterexample()
        self.assertEqual(witness["q"], 5)
        self.assertEqual(witness["p"], 11)
        self.assertEqual(witness["left_reduction"], 1)
        self.assertEqual(witness["right_product"], 2)
        self.assertFalse(witness["equation_holds"])

    def test_tag_action_equation_helper_rejects_false_safe_prime_relation(self) -> None:
        with self.assertRaises(ValueError):
            tag_action_equation(3, 4, q=5, p=13)

    def test_parameter_summary_is_stable(self) -> None:
        summary = parameter_summary()
        self.assertEqual(summary["k"], 2)
        self.assertEqual(summary["ciphertext_bytes"], C2_CONCRETE_CIPHERTEXT_BYTES)
        self.assertEqual(summary["suite_id"], "7f02")
        self.assertEqual(summary["deployment_status"], "not-approved")
        self.assertEqual(
            summary["interoperability_status"],
            "finite-field-tag-reduction-nonhomomorphic",
        )


if __name__ == "__main__":
    unittest.main()
