# SPDX-License-Identifier: Apache-2.0

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ActiveProfileDocumentationTests(unittest.TestCase):
    """Keep active prose synchronized with the registry and executable CLI.

    These tests are intentionally precise rather than a broad ban on historical
    version strings. The repository retains v1.5 artifacts for reproducibility,
    so references to v1.5 are valid when they are explicitly historical. What
    must fail is an active v1.6 document pointing an implementer at a v1.5
    registry, corpus, acceptance gate, field model, or command-line option.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(
            (ROOT / "spec/protocol-registry-v1.6.json").read_text(encoding="utf-8")
        )
        cls.version = cls.registry["registry_version"]
        cls.series = ".".join(cls.version.split(".")[:2])

    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_active_core_points_only_at_active_normative_artifacts(self) -> None:
        core = self.read(f"spec/core-v{self.series}.md")

        required = (
            f"Registry version: {self.version}",
            f"protocol-registry-v{self.series}.json",
            f"p1-conformance-vectors-v{self.series}.json",
            f"p1-conformance-corpus-v{self.series}.bin",
            f"p1-prototype-profile-v{self.series}.md",
            "routing nonce",
            "eligibility field",
        )
        for value in required:
            self.assertIn(value, core)

        forbidden = (
            "Core v1.5 freezes",
            "Core v1.5 does not claim",
            "`protocol-registry-v1.5.json` is normative",
            "`p1-conformance-vectors-v1.5.json` and",
            "acceptance gate is defined in `p1-prototype-profile-v1.5.md`",
        )
        for value in forbidden:
            self.assertNotIn(value, core)

    def test_plain_language_overview_matches_v16(self) -> None:
        overview = self.read("FORDUMMY.md")

        for value in (
            "Trahens Core v1.6",
            "Routing nonce",
            "Eligibility field",
            "network-bootstrap-b1.md",
            "static network configuration",
            "not autonomous Trahens network",
        ):
            self.assertIn(value, overview)

        for value in (
            "Trahens Core v1.5 and its P1 prototype",
            "mandatory v1.5 path",
            "blocked from the live P1 network path",
            "cannot be converted to C1 by changing a configuration flag",
        ):
            self.assertNotIn(value, overview)

    def test_acceptance_evidence_matches_registry_and_cli(self) -> None:
        evidence = self.read("docs/p1-acceptance-evidence.md")

        self.assertIn(f"Registry: {self.version}", evidence)
        self.assertIn("32-vector", evidence)
        self.assertIn("--schedule-profile adaptive", evidence)
        self.assertIn("child routing nonce", evidence)
        self.assertNotIn("--adaptive-t2", evidence)
        self.assertNotIn("child discovery nonce", evidence)
        self.assertNotIn("Registry: 1.6.0", evidence)

    def test_implementer_guide_matches_registry(self) -> None:
        guide = self.read("docs/implementing-trahens-p1.md")

        self.assertIn(f"vectors at registry {self.version}", guide)
        self.assertIn("Bootstrap boundary", guide)
        self.assertIn("network-bootstrap-b1.md", guide)
        self.assertNotIn("vectors at registry 1.5.2", guide)

    def test_spec_index_prioritizes_active_corpus(self) -> None:
        index = self.read("spec/README.md")

        active = "p1-conformance-vectors-v1.6.json"
        historical = "p1-conformance-vectors-v1.5.json"
        self.assertIn(active, index)
        self.assertIn(historical, index)
        self.assertLess(index.index(active), index.index(historical))
        self.assertIn("network-bootstrap-b1.md", index)

    def test_obsolete_adaptive_flag_is_absent_from_active_docs(self) -> None:
        active_docs = (
            "README.md",
            "FORDUMMY.md",
            "ROADMAP.md",
            "spec/README.md",
            "spec/core-v1.6.md",
            "spec/p1-prototype-profile-v1.6.md",
            "docs/implementing-trahens-p1.md",
            "docs/p1-acceptance-evidence.md",
        )
        for relative in active_docs:
            with self.subTest(path=relative):
                self.assertNotIn("--adaptive-t2", self.read(relative))

    def test_bootstrap_boundary_is_explicit_everywhere_readers_start(self) -> None:
        bootstrap = ROOT / "spec/network-bootstrap-b1.md"
        self.assertTrue(bootstrap.is_file())

        directly_linked = (
            "README.md",
            "FORDUMMY.md",
            "ROADMAP.md",
            "spec/README.md",
            "spec/core-v1.6.md",
            "spec/p1-prototype-profile-v1.6.md",
            "docs/implementing-trahens-p1.md",
        )
        for relative in directly_linked:
            with self.subTest(path=relative):
                self.assertIn("network-bootstrap-b1.md", self.read(relative))

        evidence = self.read("docs/p1-acceptance-evidence.md")
        self.assertIn("Autonomous network bootstrap", evidence)
        self.assertIn("future B1 profile", evidence)


if __name__ == "__main__":
    unittest.main()
