from __future__ import annotations

import unittest

from trahens_crypto.c2_ideal import (
    C2Error,
    C2IdealOracle,
    C2_MARKER,
    C2_SYMBOLIC_CIPHERTEXT_BYTES,
    apply_literal_tag,
    contains_literal_tag,
)


class C2IdealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracle = C2IdealOracle(b"c2-unit-test")
        self.alice = self.oracle.keygen(b"alice")
        self.bob = self.oracle.keygen(b"bob")

    def test_encrypt_rerandomize_decrypt(self) -> None:
        original = self.oracle.encrypt(self.alice.public)
        rerandomized = self.oracle.rerandomize(original)
        self.assertEqual(len(original), C2_SYMBOLIC_CIPHERTEXT_BYTES)
        self.assertNotEqual(original, rerandomized)
        self.assertTrue(self.oracle.equivalent_for_test(original, rerandomized))
        self.assertEqual(self.oracle.decrypt(self.alice.secret, rerandomized), C2_MARKER)
        self.assertFalse(self.oracle.is_eligible(self.bob.secret, rerandomized))

    def test_arbitrary_mutation_is_not_replay_equivalent(self) -> None:
        original = self.oracle.encrypt(self.alice.public)
        tagged = apply_literal_tag(original, b"ratio-tag")
        self.assertFalse(self.oracle.is_registered(tagged))
        with self.assertRaises(C2Error):
            self.oracle.rerandomize(tagged)
        self.assertFalse(self.oracle.is_eligible(self.alice.secret, tagged))

    def test_honest_rerandomization_does_not_preserve_literal_tag(self) -> None:
        original = self.oracle.encrypt(self.alice.public)
        rerandomized = self.oracle.rerandomize(original)
        tag = b"colluder-marker-123"
        tagged = apply_literal_tag(rerandomized, tag)
        self.assertFalse(contains_literal_tag(rerandomized, tag))
        self.assertTrue(contains_literal_tag(tagged, tag))
        self.assertFalse(self.oracle.is_registered(tagged))

    def test_ciphertext_bytes_do_not_embed_public_key(self) -> None:
        left = self.oracle.encrypt(self.alice.public)
        right = self.oracle.encrypt(self.bob.public)
        self.assertNotIn(self.alice.public, left)
        self.assertNotIn(self.bob.public, right)
        self.assertNotEqual(left, right)


if __name__ == "__main__":
    unittest.main()
