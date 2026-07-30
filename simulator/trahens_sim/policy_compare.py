"""Compare fixed broad flooding with bounded expanding-ring discovery."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
from statistics import mean

from .model import (
    DiscoveryConfig,
    ExpandingRingConfig,
    Graph,
    RingStep,
    choose_responders,
    parse_ring_schedule,
    ring_schedule_to_string,
    simulate_discovery,
    simulate_expanding_ring,
)


@dataclass(frozen=True)
class PolicyAggregate:
    responder_fraction: float
    runs: int
    fixed_success_rate: float
    fixed_mean_transmissions: float
    fixed_mean_duplicates: float
    fixed_mean_state_allocations: float
    expanding_success_rate: float
    expanding_mean_transmissions: float
    expanding_mean_duplicates: float
    expanding_mean_state_allocations: float
    expanding_mean_attempts: float
    expanding_mean_multi_attempt_observer_fraction: float
    transmission_savings_fraction: float
    state_allocation_savings_fraction: float


def _parse_float_list(value: str) -> list[float]:
    result = [float(item.strip()) for item in value.split(",") if item.strip()]
    if not result:
        raise argparse.ArgumentTypeError("expected at least one number")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare fixed and expanding-ring Trahens discovery"
    )
    parser.add_argument("--nodes", type=int, default=500)
    parser.add_argument("--average-degree", type=float, default=8.0)
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument(
        "--responder-fractions",
        type=_parse_float_list,
        default=[0.01, 0.02, 0.05],
    )
    parser.add_argument("--candidate-limit", type=int, default=8)
    parser.add_argument("--required-candidates", type=int, default=1)
    parser.add_argument("--fixed-hop-limit", type=int, default=5)
    parser.add_argument("--fixed-initial-fanout", type=int, default=4)
    parser.add_argument("--fixed-relay-fanout", type=int, default=4)
    parser.add_argument(
        "--rings",
        type=parse_ring_schedule,
        default=parse_ring_schedule("2:2,3:2,4:3,5:4"),
    )
    parser.add_argument("--transmission-budget", type=int, default=1200)
    parser.add_argument("--state-budget", type=int, default=1200)
    parser.add_argument("--seed-base", type=int, default=3000)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _savings(baseline: float, alternative: float) -> float:
    if baseline == 0.0:
        return 0.0
    return (baseline - alternative) / baseline


def run_policy_comparison(
    *,
    nodes: int,
    average_degree: float,
    runs: int,
    responder_fractions: list[float],
    candidate_limit: int,
    required_candidates: int,
    fixed_hop_limit: int,
    fixed_initial_fanout: int,
    fixed_relay_fanout: int,
    rings: tuple[RingStep, ...],
    transmission_budget: int | None,
    state_budget: int | None,
    seed_base: int,
) -> list[PolicyAggregate]:
    if runs < 1:
        raise ValueError("runs must be positive")

    rows: list[PolicyAggregate] = []
    for responder_fraction in responder_fractions:
        fixed_successes = 0
        fixed_transmissions: list[int] = []
        fixed_duplicates: list[int] = []
        fixed_state: list[int] = []

        expanding_successes = 0
        expanding_transmissions: list[int] = []
        expanding_duplicates: list[int] = []
        expanding_state: list[int] = []
        expanding_attempts: list[int] = []
        expanding_observer_fraction: list[float] = []

        for run_index in range(runs):
            seed = seed_base + run_index
            graph = Graph.random_connected(nodes, average_degree, seed)
            responders = choose_responders(
                graph,
                origin=0,
                responder_fraction=responder_fraction,
                seed=seed,
            )

            fixed = simulate_discovery(
                graph,
                DiscoveryConfig(
                    origin=0,
                    hop_limit=fixed_hop_limit,
                    initial_fanout=fixed_initial_fanout,
                    relay_fanout=fixed_relay_fanout,
                    candidate_limit=candidate_limit,
                    responder_fraction=responder_fraction,
                    seed=seed,
                    transmission_budget=transmission_budget,
                    state_budget=state_budget,
                ),
                responders=responders,
            )
            fixed_successes += int(fixed.candidate_count >= required_candidates)
            fixed_transmissions.append(fixed.discover_transmissions)
            fixed_duplicates.append(fixed.duplicate_deliveries)
            fixed_state.append(fixed.discovery_state_entries)

            expanding = simulate_expanding_ring(
                graph,
                ExpandingRingConfig(
                    origin=0,
                    rings=rings,
                    candidate_limit=candidate_limit,
                    required_candidates=required_candidates,
                    responder_fraction=responder_fraction,
                    seed=seed,
                    total_transmission_budget=transmission_budget,
                    total_state_allocation_budget=state_budget,
                ),
                responders=responders,
            )
            expanding_successes += int(expanding.success)
            expanding_transmissions.append(
                expanding.total_discover_transmissions
            )
            expanding_duplicates.append(expanding.total_duplicate_deliveries)
            expanding_state.append(expanding.total_state_allocations)
            expanding_attempts.append(expanding.attempt_count)
            expanding_observer_fraction.append(
                expanding.multi_attempt_observer_fraction
            )

        fixed_mean_transmissions = mean(fixed_transmissions)
        expanding_mean_transmissions = mean(expanding_transmissions)
        fixed_mean_state = mean(fixed_state)
        expanding_mean_state = mean(expanding_state)

        rows.append(
            PolicyAggregate(
                responder_fraction=responder_fraction,
                runs=runs,
                fixed_success_rate=fixed_successes / runs,
                fixed_mean_transmissions=fixed_mean_transmissions,
                fixed_mean_duplicates=mean(fixed_duplicates),
                fixed_mean_state_allocations=fixed_mean_state,
                expanding_success_rate=expanding_successes / runs,
                expanding_mean_transmissions=expanding_mean_transmissions,
                expanding_mean_duplicates=mean(expanding_duplicates),
                expanding_mean_state_allocations=expanding_mean_state,
                expanding_mean_attempts=mean(expanding_attempts),
                expanding_mean_multi_attempt_observer_fraction=mean(
                    expanding_observer_fraction
                ),
                transmission_savings_fraction=_savings(
                    fixed_mean_transmissions,
                    expanding_mean_transmissions,
                ),
                state_allocation_savings_fraction=_savings(
                    fixed_mean_state,
                    expanding_mean_state,
                ),
            )
        )

    return rows


def main() -> None:
    args = _parser().parse_args()
    rows = run_policy_comparison(
        nodes=args.nodes,
        average_degree=args.average_degree,
        runs=args.runs,
        responder_fractions=args.responder_fractions,
        candidate_limit=args.candidate_limit,
        required_candidates=args.required_candidates,
        fixed_hop_limit=args.fixed_hop_limit,
        fixed_initial_fanout=args.fixed_initial_fanout,
        fixed_relay_fanout=args.fixed_relay_fanout,
        rings=args.rings,
        transmission_budget=args.transmission_budget,
        state_budget=args.state_budget,
        seed_base=args.seed_base,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "responder_fraction",
                "runs",
                "fixed_success_rate",
                "fixed_mean_transmissions",
                "fixed_mean_duplicates",
                "fixed_mean_state_allocations",
                "expanding_success_rate",
                "expanding_mean_transmissions",
                "expanding_mean_duplicates",
                "expanding_mean_state_allocations",
                "expanding_mean_attempts",
                "expanding_mean_multi_attempt_observer_fraction",
                "transmission_savings_fraction",
                "state_allocation_savings_fraction",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    f"{row.responder_fraction:.4f}",
                    row.runs,
                    f"{row.fixed_success_rate:.4f}",
                    f"{row.fixed_mean_transmissions:.2f}",
                    f"{row.fixed_mean_duplicates:.2f}",
                    f"{row.fixed_mean_state_allocations:.2f}",
                    f"{row.expanding_success_rate:.4f}",
                    f"{row.expanding_mean_transmissions:.2f}",
                    f"{row.expanding_mean_duplicates:.2f}",
                    f"{row.expanding_mean_state_allocations:.2f}",
                    f"{row.expanding_mean_attempts:.2f}",
                    (
                        f"{row.expanding_mean_multi_attempt_observer_fraction:.4f}"
                    ),
                    f"{row.transmission_savings_fraction:.4f}",
                    f"{row.state_allocation_savings_fraction:.4f}",
                ]
            )

    print(
        "policy comparison written to "
        f"{args.output} using rings {ring_schedule_to_string(args.rings)}"
    )


if __name__ == "__main__":
    main()
