# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from trahens_codec.m2w2 import CodecError, decode_message


class P1ConformanceVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = Path(__file__).resolve().parents[2]
        cls.vector_path = cls.repository / "spec" / "p1-conformance-vectors-v1.6.json"
        cls.corpus_path = cls.repository / "spec" / "p1-conformance-corpus-v1.6.bin"
        cls.document = json.loads(cls.vector_path.read_text(encoding="utf-8"))

    def test_every_message_has_positive_and_negative_vector(self) -> None:
        coverage: dict[str, set[bool]] = {}
        for vector in self.document["vectors"]:
            coverage.setdefault(vector["message"], set()).add(vector["valid"])
        self.assertEqual(len(coverage), 11)
        self.assertTrue(all(values == {False, True} for values in coverage.values()))

    def test_python_runtime_matches_independently_encoded_vectors(self) -> None:
        for vector in self.document["vectors"]:
            encoded = bytes.fromhex(vector["encoding_hex"])
            if vector["valid"]:
                decode_message(encoded)
            else:
                with self.assertRaises(CodecError, msg=vector["name"]):
                    decode_message(encoded)

    def test_vector_generator_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated_json = root / "vectors.json"
            generated_corpus = root / "corpus.bin"
            subprocess.run(
                [
                    "python",
                    str(self.repository / "tools" / "generate_p1_conformance.py"),
                    "--json-output",
                    str(generated_json),
                    "--corpus-output",
                    str(generated_corpus),
                ],
                check=True,
                cwd=self.repository,
            )
            self.assertEqual(self.vector_path.read_bytes(), generated_json.read_bytes())
            self.assertEqual(self.corpus_path.read_bytes(), generated_corpus.read_bytes())


if __name__ == "__main__":
    unittest.main()
