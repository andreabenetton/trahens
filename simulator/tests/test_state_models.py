# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.check_state_models import build_report


class BoundedStateModelTests(unittest.TestCase):
    def test_models_cover_required_safety_cases(self) -> None:
        report = build_report()
        self.assertGreater(report["r1"]["successful_redemptions"], 0)
        self.assertGreater(report["r1"]["replay_rejections_checked"], 0)
        self.assertGreater(report["r1"]["expiry_rejections_observed"], 0)
        self.assertGreater(report["e1"]["illegal_transitions_rejected"], 0)
        self.assertEqual(
            report["e1"]["states"], report["e1"]["cleanup_reachability_checked"]
        )

    def test_tracked_report_is_reproducible(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        tracked = repository / "reports" / "v1.5-bounded-state-models.json"
        with tempfile.TemporaryDirectory() as temporary:
            generated = Path(temporary) / "models.json"
            subprocess.run(
                [
                    "python",
                    str(repository / "tools" / "check_state_models.py"),
                    "--output",
                    str(generated),
                ],
                check=True,
                cwd=repository,
            )
            self.assertEqual(json.loads(tracked.read_text()), json.loads(generated.read_text()))


if __name__ == "__main__":
    unittest.main()
