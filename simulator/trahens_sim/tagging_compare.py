# SPDX-License-Identifier: Apache-2.0
"""Reproducible M1/W2/C1 integration and active-tagging comparison."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, replace
from pathlib import Path
from statistics import mean

from .event_model import EventLifecycleConfig, TimedRingStep, simulate_event_lifecycle
from .model import Graph


@dataclass(frozen=True)
class TaggingScenario:
    name: str
    wire_tamper_probability: float = 0.0
    active_tagging: bool = False
    malicious_nodes: tuple[int, ...] = ()


@dataclass(frozen=True)
class TaggingAggregate:
    scenario: str
    runs: int
    success_rate: float
    cleanup_rate: float
    mean_setup_latency_ms: float
    mean_total_transmissions: float
    mean_wire_bytes: float
    mean_wire_auth_failures: float
    mean_codec_failures: float
    mean_crypto_failures: float
    mean_discover_transforms: float
    mean_candidate_layers: float
    mean_tags_created: float
    mean_tag_observations: float


def _line_graph(nodes: int) -> Graph:
    graph = Graph(nodes)
    for node in range(nodes - 1):
        graph.add_edge(node, node + 1)
    return graph


def default_scenarios() -> tuple[TaggingScenario, ...]:
    return (
        TaggingScenario(name="clean-integrated"),
        TaggingScenario(name="adjacent-link-tamper-2pct", wire_tamper_probability=0.02),
        TaggingScenario(name="ratio-tag-single", active_tagging=True, malicious_nodes=(1,)),
        TaggingScenario(name="ratio-tag-colluding", active_tagging=True, malicious_nodes=(1, 3)),
    )


def run_tagging_comparison(
    *,
    runs: int,
    seed_base: int,
    scenarios: tuple[TaggingScenario, ...] | None = None,
) -> list[TaggingAggregate]:
    if runs < 1:
        raise ValueError("runs must be positive")
    scenarios = default_scenarios() if scenarios is None else scenarios
    rows: list[TaggingAggregate] = []
    for scenario in scenarios:
        results = []
        for run_index in range(runs):
            graph = _line_graph(5)
            base = EventLifecycleConfig(
                rings=(TimedRingStep(4, 1, 1, 40),),
                seed=seed_base + run_index,
                discover_delay_min_ms=1,
                discover_delay_max_ms=3,
                candidate_delay_min_ms=1,
                candidate_delay_max_ms=3,
                control_delay_min_ms=1,
                control_delay_max_ms=2,
                responder_offer_delay_min_ms=1,
                responder_offer_delay_max_ms=4,
                branch_ttl_ms=90,
                offer_ttl_ms=120,
                tentative_ttl_ms=70,
                ready_hold_ms=50,
                route_setup_timeout_ms=120,
                active_lifetime_ms=60,
                max_simulation_ms=320,
                transmission_budget=200,
                branch_capacity=100,
                tentative_capacity=50,
                active_capacity=16,
                per_node_branch_limit=8,
                candidate_response_limit=8,
                enable_crypto=True,
            )
            config = replace(
                base,
                wire_tamper_probability=scenario.wire_tamper_probability,
                active_tagging=scenario.active_tagging,
            )
            results.append(
                simulate_event_lifecycle(
                    graph,
                    config,
                    responders={4},
                    malicious_nodes=set(scenario.malicious_nodes),
                )
            )
        latencies = [r.setup_latency_ms for r in results if r.setup_latency_ms is not None]
        rows.append(
            TaggingAggregate(
                scenario=scenario.name,
                runs=runs,
                success_rate=mean(int(r.success) for r in results),
                cleanup_rate=mean(int(r.cleanup_complete) for r in results),
                mean_setup_latency_ms=mean(latencies) if latencies else 0.0,
                mean_total_transmissions=mean(r.total_transmissions for r in results),
                mean_wire_bytes=mean(r.wire_bytes for r in results),
                mean_wire_auth_failures=mean(r.wire_auth_failures for r in results),
                mean_codec_failures=mean(r.codec_failures for r in results),
                mean_crypto_failures=mean(r.crypto_failures for r in results),
                mean_discover_transforms=mean(r.crypto_discover_transforms for r in results),
                mean_candidate_layers=mean(r.crypto_candidate_layers for r in results),
                mean_tags_created=mean(r.tagged_branches_created for r in results),
                mean_tag_observations=mean(r.tag_observations for r in results),
            )
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=40)
    parser.add_argument("--seed-base", type=int, default=9100)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = run_tagging_comparison(runs=args.runs, seed_base=args.seed_base)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fields = list(TaggingAggregate.__dataclass_fields__)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(fields)
        for row in rows:
            values = []
            for field in fields:
                value = getattr(row, field)
                values.append(f"{value:.4f}" if isinstance(value, float) else value)
            writer.writerow(values)
    print(f"tagging comparison written to {args.output}")


if __name__ == "__main__":
    main()
