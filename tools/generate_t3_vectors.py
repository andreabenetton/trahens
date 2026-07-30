#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic T3 traffic-analysis conformance vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from trahens_sim.t3_model import T3Config, probe_pattern, simulate_t3_trace, trace_features


def digest_trace(trace) -> str:
    payload = json.dumps(trace.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def build_vectors() -> dict[str, object]:
    config = T3Config(epochs=32, seed=0x13579)
    traces = {}
    for profile in ("fixed", "adaptive", "hybrid"):
        trace = simulate_t3_trace(
            1,
            profile=profile,
            config=config,
            correlated_cross_traffic=True,
            active_probe=True,
        )
        traces[profile] = {
            "sha256": digest_trace(trace),
            "total_public_cells": trace.total_public_cells,
            "expected_public_cells": trace.expected_public_cells,
            "boundary_alignment": trace.boundary_alignment,
            "mean_pairwise_lag_correlation": trace.mean_pairwise_lag_correlation,
            "first_link_public_cells": list(trace.public_cells[0]),
            "last_route_link_public_cells": list(trace.public_cells[2]),
            "feature_prefix": list(trace_features(trace)[:24]),
        }
    return {
        "profile": "T3",
        "version": 1,
        "config": asdict(config),
        "route_label": 1,
        "probe_pattern": list(probe_pattern(config.epochs, config.seed + 1)),
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
