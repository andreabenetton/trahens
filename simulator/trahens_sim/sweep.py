# SPDX-License-Identifier: Apache-2.0
"""Parameter sweep for bounded Trahens discovery."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, pstdev

from .model import DiscoveryConfig, Graph, simulate_discovery


@dataclass(frozen=True)
class Aggregate:
    hop_limit: int
    relay_fanout: int
    runs: int
    success_rate: float
    mean_coverage: float
    coverage_stddev: float
    mean_transmissions: float
    mean_duplicates: float
    mean_amplification: float
    mean_candidates: float


def _parse_int_list(value: str) -> list[int]:
    result = [int(item.strip()) for item in value.split(",") if item.strip()]
    if not result:
        raise argparse.ArgumentTypeError("expected at least one integer")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sweep Trahens discovery limits")
    parser.add_argument("--nodes", type=int, default=500)
    parser.add_argument("--average-degree", type=float, default=8.0)
    parser.add_argument("--hop-limits", type=_parse_int_list, default=[3, 4, 5])
    parser.add_argument("--relay-fanouts", type=_parse_int_list, default=[2, 3, 4])
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--candidate-limit", type=int, default=8)
    parser.add_argument("--responder-fraction", type=float, default=0.02)
    parser.add_argument("--seed-base", type=int, default=1000)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def run_sweep(
    *,
    nodes: int,
    average_degree: float,
    hop_limits: list[int],
    relay_fanouts: list[int],
    runs: int,
    candidate_limit: int,
    responder_fraction: float,
    seed_base: int,
) -> list[Aggregate]:
    if runs < 1:
        raise ValueError("runs must be positive")

    aggregates: list[Aggregate] = []
    for hop_limit in hop_limits:
        for relay_fanout in relay_fanouts:
            coverages: list[float] = []
            transmissions: list[int] = []
            duplicates: list[int] = []
            amplifications: list[float] = []
            candidates: list[int] = []
            successes = 0

            for run_index in range(runs):
                seed = seed_base + run_index
                graph = Graph.random_connected(nodes, average_degree, seed)
                config = DiscoveryConfig(
                    origin=0,
                    hop_limit=hop_limit,
                    initial_fanout=relay_fanout,
                    relay_fanout=relay_fanout,
                    candidate_limit=candidate_limit,
                    responder_fraction=responder_fraction,
                    seed=seed,
                )
                result = simulate_discovery(graph, config)
                coverage = result.accepted_nodes / (nodes - 1)
                coverages.append(coverage)
                transmissions.append(result.discover_transmissions)
                duplicates.append(result.duplicate_deliveries)
                amplifications.append(result.transmission_amplification)
                candidates.append(result.candidate_count)
                if result.candidate_count > 0:
                    successes += 1

            aggregates.append(
                Aggregate(
                    hop_limit=hop_limit,
                    relay_fanout=relay_fanout,
                    runs=runs,
                    success_rate=successes / runs,
                    mean_coverage=mean(coverages),
                    coverage_stddev=pstdev(coverages),
                    mean_transmissions=mean(transmissions),
                    mean_duplicates=mean(duplicates),
                    mean_amplification=mean(amplifications),
                    mean_candidates=mean(candidates),
                )
            )

    return aggregates


def main() -> None:
    args = _parser().parse_args()
    rows = run_sweep(
        nodes=args.nodes,
        average_degree=args.average_degree,
        hop_limits=args.hop_limits,
        relay_fanouts=args.relay_fanouts,
        runs=args.runs,
        candidate_limit=args.candidate_limit,
        responder_fraction=args.responder_fraction,
        seed_base=args.seed_base,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "hop_limit",
                "relay_fanout",
                "runs",
                "success_rate",
                "mean_coverage",
                "coverage_stddev",
                "mean_transmissions",
                "mean_duplicates",
                "mean_amplification",
                "mean_candidates",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.hop_limit,
                    row.relay_fanout,
                    row.runs,
                    f"{row.success_rate:.4f}",
                    f"{row.mean_coverage:.4f}",
                    f"{row.coverage_stddev:.4f}",
                    f"{row.mean_transmissions:.2f}",
                    f"{row.mean_duplicates:.2f}",
                    f"{row.mean_amplification:.4f}",
                    f"{row.mean_candidates:.2f}",
                ]
            )


if __name__ == "__main__":
    main()
