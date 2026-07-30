# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from trahens_codec.m2w2 import CodecError, decode_message, encode_chaff
from trahens_crypto.c1 import C1_SUITE_ID
from trahens_spec import generated as registry


class ProtocolRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = Path(__file__).resolve().parents[2]
        cls.source = json.loads(
            (cls.repository / "spec" / "protocol-registry-v1.5.json").read_text(
                encoding="utf-8"
            )
        )

    def test_registry_constants_match_runtime(self) -> None:
        self.assertEqual(registry.REGISTRY_VERSION, self.source["registry_version"])
        self.assertEqual(C1_SUITE_ID, self.source["suites"]["c1_v2"].to_bytes(2, "big"))
        self.assertEqual(registry.BYTES_CELL_RECORD, 1052)
        self.assertEqual(registry.BYTES_CELL_PAYLOAD, 992)
        self.assertEqual(
            registry.FIXED_T2_SLOT_INTERVAL_US
            * registry.FIXED_T2_CELLS_PER_EPOCH,
            registry.FIXED_T2_EPOCH_MS * 1000,
        )
        self.assertEqual(registry.DOMAIN_C1_ELEMENT, b"Trahens-C1-element-v2")

    def test_retired_c1_suite_is_rejected_on_the_wire(self) -> None:
        encoded = bytearray(encode_chaff(crypto_suite_id=C1_SUITE_ID))
        encoded[4:6] = registry.SUITE_C1_V1_RETIRED
        with self.assertRaisesRegex(CodecError, "unsupported cryptographic suite"):
            decode_message(bytes(encoded))

    def test_test_only_crypto_is_not_installable_package_content(self) -> None:
        self.assertIsNone(importlib.util.find_spec("trahens_crypto.test_support"))
        self.assertIsNone(importlib.util.find_spec("trahens_crypto.candidate_test_support"))

    def test_generated_bindings_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            outputs = {
                "python": temporary_path / "generated.py",
                "rust": temporary_path / "generated.rs",
                "markdown": temporary_path / "registry.md",
            }
            subprocess.run(
                [
                    "python",
                    str(self.repository / "tools" / "generate_protocol_registry.py"),
                    "--python-output",
                    str(outputs["python"]),
                    "--rust-output",
                    str(outputs["rust"]),
                    "--markdown-output",
                    str(outputs["markdown"]),
                ],
                check=True,
                cwd=self.repository,
            )
            expected = {
                "python": self.repository / "simulator" / "trahens_spec" / "generated.py",
                "rust": self.repository
                / "implementation"
                / "rust"
                / "crates"
                / "protocol-registry"
                / "src"
                / "generated.rs",
                "markdown": self.repository / "spec" / "protocol-registry-v1.5.md",
            }
            for name, generated in outputs.items():
                self.assertEqual(
                    expected[name].read_bytes(),
                    generated.read_bytes(),
                    f"stale generated {name} registry binding",
                )


if __name__ == "__main__":
    unittest.main()
