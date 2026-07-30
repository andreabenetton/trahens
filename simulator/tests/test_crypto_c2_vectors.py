from __future__ import annotations

import json
from pathlib import Path
import unittest

from tools.generate_c2_symbolic_vectors import build_vectors


class C2SymbolicVectorTests(unittest.TestCase):
    def test_tracked_symbolic_vectors_are_reproducible(self) -> None:
        tracked = json.loads(
            Path("spec/crypto-test-vectors-c2-symbolic.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(tracked, build_vectors())
        self.assertTrue(tracked["outcomes"]["rerandomized_eligible"])
        self.assertFalse(tracked["outcomes"]["mutation_eligible"])
        self.assertFalse(tracked["outcomes"]["wrong_recipient_eligible"])


if __name__ == "__main__":
    unittest.main()
