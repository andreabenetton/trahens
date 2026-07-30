"""Compare C1 ratio tagging with the symbolic C2 active-security contract."""

from __future__ import annotations

import argparse
import csv
from dataclasses import replace
from pathlib import Path
from statistics import mean

from .event_model import EventLifecycleConfig, TimedRingStep, simulate_event_lifecycle
from .model import Graph


def _line_graph(nodes: int) -> Graph:
    graph = Graph(nodes)
    for node in range(nodes - 1):
        graph.add_edge(node, node + 1)
    return graph


def run_comparison(runs: int = 100) -> list[dict[str, object]]:
    if runs < 1:
        raise ValueError("runs must be positive")
    graph = _line_graph(5)
    rows: list[dict[str, object]] = []
    scenarios = (
        ("c1-clean", "c1", False),
        ("c1-ratio-tag", "c1", True),
        ("c2-symbolic-clean", "c2-ideal", False),
        ("c2-symbolic-marker-tag", "c2-ideal", True),
    )
    for name, profile, active_tagging in scenarios:
        results = []
        for run in range(runs):
            config = EventLifecycleConfig(
                eligibility_profile=profile,
                active_tagging=active_tagging,
                rings=(TimedRingStep(4, 1, 1, 40),),
                seed=10_000 + run,
                discover_delay_min_ms=1,
                discover_delay_max_ms=2,
                candidate_delay_min_ms=1,
                candidate_delay_max_ms=2,
                control_delay_min_ms=1,
                control_delay_max_ms=2,
                responder_offer_delay_min_ms=1,
                responder_offer_delay_max_ms=2,
                max_simulation_ms=240,
            )
            results.append(
                simulate_event_lifecycle(
                    graph,
                    config,
                    responders={4},
                    malicious_nodes={1, 3},
                )
            )
        rows.append(
            {
                "scenario": name,
                "runs": runs,
                "route_success_rate": mean(int(result.success) for result in results),
                "mean_transmissions": mean(result.total_transmissions for result in results),
                "mean_wire_bytes": mean(result.wire_bytes for result in results),
                "mean_crypto_failures": mean(result.crypto_failures for result in results),
                "mean_tags_created": mean(result.tagged_branches_created for result in results),
                "mean_downstream_tag_observations": mean(result.tag_observations for result in results),
                "cleanup_rate": mean(int(result.cleanup_complete) for result in results),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/iteration-0009-c2-active-security.csv"),
    )
    args = parser.parse_args()
    rows = run_comparison(args.runs)
    write_csv(args.output, rows)
    for row in rows:
        print(row)


if __name__ == "__main__":
    main()
