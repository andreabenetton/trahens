#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic T4 packet-emulation conformance vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from trahens_sim.t4_model import T4Config, probe_pattern, simulate_t4_trace, trace_features


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def build_vectors() -> dict[str, object]:
    config = T4Config(epochs=32, seed=0x2468A, target_burst_cells=14)
    traces = {}
    for profile in ("fixed", "adaptive", "hybrid"):
        trace = simulate_t4_trace(
            1,
            profile=profile,
            config=config,
            churn_route_label=2,
            churn_epoch=16,
            selective_delay=True,
            probe_workload=True,
        )
        traces[profile] = {
            "sha256": _digest(trace.to_dict()),
            "total_public_cells": trace.total_public_cells,
            "expected_public_cells": trace.expected_public_cells,
            "delivered_target_cells": trace.delivered_target_cells,
            "chaff_cells": trace.chaff_cells,
            "mean_network_delay_us": trace.mean_network_delay_us,
            "p95_network_delay_us": trace.p95_network_delay_us,
            "first_link_observation_prefix": [
                asdict(item) for item in trace.observations[0][:12]
            ],
            "feature_prefix": list(trace_features(trace)[:24]),
        }
    return {
        "profile": "T4",
        "version": 1,
        "config": asdict(config),
        "route_label": 1,
        "churn_route_label": 2,
        "churn_epoch": 16,
        "selective_delay": True,
        "probe_pattern": list(probe_pattern(config, config.seed + 1)),
        "traces": traces,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build_vectors(), indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
