"""Compare attempt-wide duplicate suppression with U1 branch-local discovery."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
from statistics import mean

from .model import (
    DiscoveryConfig,
    Graph,
    UnlinkableDiscoveryConfig,
    choose_responders,
    simulate_discovery,
    simulate_unlinkable_discovery,
)


@dataclass(frozen=True)
class UnlinkabilityAggregate:
    hop_limit: int
    fanout: int
    responder_fraction: float
    runs: int
    identifier_success_rate: float
    identifier_mean_transmissions: float
    identifier_mean_state: float
    identifier_mean_unique_relays: float
    u1_success_rate: float
    u1_mean_transmissions: float
    u1_mean_branch_contexts: float
    u1_mean_unique_relays: float
    u1_mean_context_amplification: float
    u1_mean_loop_context_fraction: float
    u1_mean_budget_exhaustion_rate: float
    u1_transmission_overhead_fraction: float
    u1_state_overhead_fraction: float


def _parse_int_list(value: str) -> list[int]:
    values = [int(item.strip()) for item in value.split(",") if item.strip()]
    if not values:
        raise argparse.ArgumentTypeError("expected at least one integer")
    return values


def _parse_float_list(value: str) -> list[float]:
    values = [float(item.strip()) for item in value.split(",") if item.strip()]
    if not values:
        raise argparse.ArgumentTypeError("expected at least one number")
    return values


def _overhead(baseline: float, alternative: float) -> float:
    if baseline == 0.0:
        return 0.0
    return (alternative - baseline) / baseline


def run_unlinkability_comparison(
    *,
    nodes: int,
    average_degree: float,
    runs: int,
    hop_limits: list[int],
    fanouts: list[int],
    responder_fractions: list[float],
    candidate_limit: int,
    candidate_response_limit: int,
    transmission_budget: int,
    state_budget: int,
    per_node_context_limit: int,
    seed_base: int,
) -> list[UnlinkabilityAggregate]:
    if runs < 1:
        raise ValueError("runs must be positive")

    # Graph creation is the dominant cost. Build one graph per run and reuse it
    # across all protocol parameter combinations.
    graphs = [
        Graph.random_connected(nodes, average_degree, seed_base + run_index)
        for run_index in range(runs)
    ]

    rows: list[UnlinkabilityAggregate] = []
    for responder_fraction in responder_fractions:
        responder_sets = [
            choose_responders(
                graph,
                origin=0,
                responder_fraction=responder_fraction,
                seed=seed_base + run_index,
            )
            for run_index, graph in enumerate(graphs)
        ]

        for hop_limit in hop_limits:
            for fanout in fanouts:
                identifier_successes = 0
                identifier_transmissions: list[int] = []
                identifier_state: list[int] = []
                identifier_unique: list[int] = []

                u1_successes = 0
                u1_transmissions: list[int] = []
                u1_contexts: list[int] = []
                u1_unique: list[int] = []
                u1_context_amplification: list[float] = []
                u1_loop_fraction: list[float] = []
                u1_budget_exhaustions = 0

                for run_index, graph in enumerate(graphs):
                    seed = seed_base + run_index
                    responders = responder_sets[run_index]

                    identifier = simulate_discovery(
                        graph,
                        DiscoveryConfig(
                            origin=0,
                            hop_limit=hop_limit,
                            initial_fanout=fanout,
                            relay_fanout=fanout,
                            candidate_limit=candidate_limit,
                            responder_fraction=responder_fraction,
                            seed=seed,
                            transmission_budget=transmission_budget,
                            state_budget=state_budget,
                        ),
                        responders=responders,
                    )
                    identifier_successes += int(identifier.candidate_count > 0)
                    identifier_transmissions.append(
                        identifier.discover_transmissions
                    )
                    identifier_state.append(identifier.discovery_state_entries)
                    identifier_unique.append(identifier.accepted_nodes)

                    u1 = simulate_unlinkable_discovery(
                        graph,
                        UnlinkableDiscoveryConfig(
                            origin=0,
                            hop_limit=hop_limit,
                            initial_fanout=fanout,
                            relay_fanout=fanout,
                            candidate_limit=candidate_limit,
                            candidate_response_limit=candidate_response_limit,
                            responder_fraction=responder_fraction,
                            seed=seed,
                            transmission_budget=transmission_budget,
                            state_budget=state_budget,
                            per_node_context_limit=per_node_context_limit,
                        ),
                        responders=responders,
                    )
                    u1_successes += int(u1.unique_candidate_count > 0)
                    u1_transmissions.append(u1.discover_transmissions)
                    u1_contexts.append(u1.accepted_branch_contexts)
                    u1_unique.append(u1.unique_relays)
                    u1_context_amplification.append(u1.context_amplification)
                    u1_loop_fraction.append(u1.loop_context_fraction)
                    u1_budget_exhaustions += int(
                        u1.transmission_budget_exhausted
                        or u1.state_budget_exhausted
                    )

                identifier_mean_transmissions = mean(identifier_transmissions)
                identifier_mean_state = mean(identifier_state)
                u1_mean_transmissions = mean(u1_transmissions)
                u1_mean_contexts = mean(u1_contexts)

                rows.append(
                    UnlinkabilityAggregate(
                        hop_limit=hop_limit,
                        fanout=fanout,
                        responder_fraction=responder_fraction,
                        runs=runs,
                        identifier_success_rate=identifier_successes / runs,
                        identifier_mean_transmissions=identifier_mean_transmissions,
                        identifier_mean_state=identifier_mean_state,
                        identifier_mean_unique_relays=mean(identifier_unique),
                        u1_success_rate=u1_successes / runs,
                        u1_mean_transmissions=u1_mean_transmissions,
                        u1_mean_branch_contexts=u1_mean_contexts,
                        u1_mean_unique_relays=mean(u1_unique),
                        u1_mean_context_amplification=mean(
                            u1_context_amplification
                        ),
                        u1_mean_loop_context_fraction=mean(u1_loop_fraction),
                        u1_mean_budget_exhaustion_rate=(
                            u1_budget_exhaustions / runs
                        ),
                        u1_transmission_overhead_fraction=_overhead(
                            identifier_mean_transmissions,
                            u1_mean_transmissions,
                        ),
                        u1_state_overhead_fraction=_overhead(
                            identifier_mean_state,
                            u1_mean_contexts,
                        ),
                    )
                )

    return rows


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare identifier-based and U1 unlinkable discovery"
    )
    parser.add_argument("--nodes", type=int, default=500)
    parser.add_argument("--average-degree", type=float, default=8.0)
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--hop-limits", type=_parse_int_list, default=[3, 4, 5])
    parser.add_argument("--fanouts", type=_parse_int_list, default=[2, 3, 4])
    parser.add_argument(
        "--responder-fractions",
        type=_parse_float_list,
        default=[0.02],
    )
    parser.add_argument("--candidate-limit", type=int, default=8)
    parser.add_argument("--candidate-response-limit", type=int, default=24)
    parser.add_argument("--transmission-budget", type=int, default=1200)
    parser.add_argument("--state-budget", type=int, default=1200)
    parser.add_argument("--per-node-context-limit", type=int, default=8)
    parser.add_argument("--seed-base", type=int, default=5000)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    rows = run_unlinkability_comparison(
        nodes=args.nodes,
        average_degree=args.average_degree,
        runs=args.runs,
        hop_limits=args.hop_limits,
        fanouts=args.fanouts,
        responder_fractions=args.responder_fractions,
        candidate_limit=args.candidate_limit,
        candidate_response_limit=args.candidate_response_limit,
        transmission_budget=args.transmission_budget,
        state_budget=args.state_budget,
        per_node_context_limit=args.per_node_context_limit,
        seed_base=args.seed_base,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(list(UnlinkabilityAggregate.__dataclass_fields__))
        for row in rows:
            writer.writerow(
                [
                    row.hop_limit,
                    row.fanout,
                    f"{row.responder_fraction:.4f}",
                    row.runs,
                    f"{row.identifier_success_rate:.4f}",
                    f"{row.identifier_mean_transmissions:.2f}",
                    f"{row.identifier_mean_state:.2f}",
                    f"{row.identifier_mean_unique_relays:.2f}",
                    f"{row.u1_success_rate:.4f}",
                    f"{row.u1_mean_transmissions:.2f}",
                    f"{row.u1_mean_branch_contexts:.2f}",
                    f"{row.u1_mean_unique_relays:.2f}",
                    f"{row.u1_mean_context_amplification:.4f}",
                    f"{row.u1_mean_loop_context_fraction:.4f}",
                    f"{row.u1_mean_budget_exhaustion_rate:.4f}",
                    f"{row.u1_transmission_overhead_fraction:.4f}",
                    f"{row.u1_state_overhead_fraction:.4f}",
                ]
            )

    print(f"unlinkability comparison written to {args.output}")


if __name__ == "__main__":
    main()
