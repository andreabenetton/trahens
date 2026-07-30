#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic entropy-based T3 anonymity measurements."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from trahens_sim.anonymity_metrics import confusion_anonymity_metrics
from trahens_sim.t3_model import T3Config, nearest_centroid_classifier, route_classification_dataset


def build_report() -> dict[str, object]:
    profiles: dict[str, object] = {}
    for profile in ("fixed", "adaptive", "hybrid"):
        training, testing, _ = route_classification_dataset(
            profile=profile,
            config=T3Config(epochs=64, seed=1_505_000),
            correlated_cross_traffic=True,
            training_per_class=16,
            testing_per_class=12,
        )
        result = nearest_centroid_classifier(training, testing)
        profiles[profile] = {
            "accuracy": result.accuracy,
            "macro_f1": result.macro_f1,
            "confusion": result.confusion,
            "anonymity": confusion_anonymity_metrics(result.confusion).to_dict(),
        }
    return {
        "profile": "Trahens v1.5 T3 entropy metrics",
        "observer": "nearest-centroid route classifier over equal-budget public traces",
        "profiles": profiles,
        "claim_boundary": "conditional on this dataset, topology, feature set, and observer",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(build_report(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
