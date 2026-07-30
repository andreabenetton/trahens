# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from math import log2
from pathlib import Path

from trahens_sim.anonymity_metrics import confusion_anonymity_metrics


class AnonymityMetricTests(unittest.TestCase):
    def test_uniform_uninformative_observer_retains_full_set(self) -> None:
        metrics = confusion_anonymity_metrics(((4, 4, 4, 4),) * 4)
        self.assertAlmostEqual(metrics.conditional_entropy_bits, 2.0)
        self.assertAlmostEqual(metrics.effective_anonymity_set, 4.0)
        self.assertAlmostEqual(metrics.information_leakage_bits, 0.0)
        self.assertAlmostEqual(metrics.bayes_vulnerability, 0.25)

    def test_perfect_observer_collapses_set(self) -> None:
        metrics = confusion_anonymity_metrics(
            ((10, 0, 0, 0), (0, 10, 0, 0), (0, 0, 10, 0), (0, 0, 0, 10))
        )
        self.assertAlmostEqual(metrics.prior_entropy_bits, log2(4))
        self.assertAlmostEqual(metrics.conditional_entropy_bits, 0.0)
        self.assertAlmostEqual(metrics.effective_anonymity_set, 1.0)
        self.assertAlmostEqual(metrics.bayes_vulnerability, 1.0)

    def test_tracked_report_is_reproducible(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        tracked = repository / "reports" / "v1.5-t3-anonymity-metrics.json"
        with tempfile.TemporaryDirectory() as temporary:
            generated = Path(temporary) / "metrics.json"
            subprocess.run(
                [
                    "python",
                    str(repository / "tools" / "generate_anonymity_metrics.py"),
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
