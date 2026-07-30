# SPDX-License-Identifier: Apache-2.0
"""Aggregate event-driven Trahens lifecycle experiments."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, replace
from pathlib import Path
from statistics import mean

from .event_model import (
    EventLifecycleConfig,
    TimedRingStep,
    parse_timed_ring_schedule,
    simulate_event_lifecycle,
)
from .model import Graph, choose_responders


@dataclass(frozen=True)
class LifecycleScenario:
    name: str
    loss_probability: float = 0.0
    duplicate_probability: float = 0.0
    malicious_fraction: float = 0.0
    attack_bursts: int = 0
    attack_branches_per_burst: int = 0
    peer_bucket_capacity: int | None = None


@dataclass(frozen=True)
class LifecycleAggregate:
    scenario: str
    runs: int
    success_rate: float
    cleanup_rate: float
    mean_setup_latency_ms: float
    mean_candidates: float
    mean_late_candidates: float
    mean_candidate_race_drops: float
    mean_legitimate_transmissions: float
    mean_attack_transmissions: float
    mean_total_transmissions: float
    mean_legitimate_branch_allocations: float
    mean_attack_branch_allocations: float
    mean_peak_branch_state: float
    mean_peak_offer_state: float
    mean_peak_candidate_state: float
    mean_peak_tentative_state: float
    mean_peak_pending_state: float
    mean_peak_active_state: float
    mean_final_branch_state: float
    mean_final_offer_state: float
    mean_final_candidate_state: float
    mean_final_tentative_state: float
    mean_final_pending_state: float
    mean_final_active_state: float
    mean_token_bucket_drops: float
    mean_branch_capacity_drops: float
    mean_per_node_branch_drops: float
    mean_loss_drops: float
    mean_exact_replay_drops: float
    mean_commit_failures: float
    mean_ready_failures: float
    no_candidate_rate: float
    route_setup_failure_rate: float


def default_scenarios() -> tuple[LifecycleScenario, ...]:
    return (
        LifecycleScenario(name="clean"),
        LifecycleScenario(
            name="loss-and-duplication",
            loss_probability=0.02,
            duplicate_probability=0.05,
        ),
        LifecycleScenario(
            name="fresh-branch-attack-open",
            malicious_fraction=0.01,
            attack_bursts=6,
            attack_branches_per_burst=6,
        ),
        LifecycleScenario(
            name="fresh-branch-attack-bucket",
            malicious_fraction=0.01,
            attack_bursts=6,
            attack_branches_per_burst=6,
            peer_bucket_capacity=1,
        ),
    )


def _safe_mean(values: list[int]) -> float:
    return mean(values) if values else 0.0


def run_lifecycle_comparison(
    *,
    nodes: int,
    average_degree: float,
    runs: int,
    rings: tuple[TimedRingStep, ...],
    responder_fraction: float,
    seed_base: int,
    scenarios: tuple[LifecycleScenario, ...] | None = None,
) -> list[LifecycleAggregate]:
    if runs < 1:
        raise ValueError("runs must be positive")
    if scenarios is None:
        scenarios = default_scenarios()

    results: list[LifecycleAggregate] = []
    for scenario in scenarios:
        successes = 0
        cleanups = 0
        setup_latencies: list[int] = []
        candidates: list[int] = []
        late_candidates: list[int] = []
        race_drops: list[int] = []
        legitimate_transmissions: list[int] = []
        attack_transmissions: list[int] = []
        total_transmissions: list[int] = []
        legitimate_allocations: list[int] = []
        attack_allocations: list[int] = []
        peak_branch: list[int] = []
        peak_offer: list[int] = []
        peak_candidate: list[int] = []
        peak_tentative: list[int] = []
        peak_pending: list[int] = []
        peak_active: list[int] = []
        final_branch: list[int] = []
        final_offer: list[int] = []
        final_candidate: list[int] = []
        final_tentative: list[int] = []
        final_pending: list[int] = []
        final_active: list[int] = []
        bucket_drops: list[int] = []
        branch_capacity_drops: list[int] = []
        per_node_drops: list[int] = []
        loss_drops: list[int] = []
        replay_drops: list[int] = []
        commit_failures: list[int] = []
        ready_failures: list[int] = []
        no_candidates = 0
        route_setup_failures = 0

        for run_index in range(runs):
            seed = seed_base + run_index
            graph = Graph.random_connected(nodes, average_degree, seed)
            responders = choose_responders(
                graph,
                origin=0,
                responder_fraction=responder_fraction,
                seed=seed,
            )
            base = EventLifecycleConfig(
                origin=0,
                rings=rings,
                candidate_limit=8,
                required_candidates=1,
                responder_fraction=responder_fraction,
                seed=seed,
                discover_delay_min_ms=1,
                discover_delay_max_ms=4,
                candidate_delay_min_ms=1,
                candidate_delay_max_ms=4,
                control_delay_min_ms=1,
                control_delay_max_ms=3,
                responder_offer_delay_min_ms=1,
                responder_offer_delay_max_ms=8,
                branch_ttl_ms=70,
                offer_ttl_ms=90,
                tentative_ttl_ms=55,
                ready_hold_ms=40,
                route_setup_timeout_ms=90,
                active_lifetime_ms=80,
                max_simulation_ms=400,
                transmission_budget=2_000,
                branch_capacity=1_200,
                tentative_capacity=600,
                active_capacity=128,
                per_node_branch_limit=8,
                candidate_response_limit=64,
                attack_start_ms=0,
                attack_interval_ms=4,
                attack_hop_limit=3,
                attack_fanout=3,
                peer_bucket_refill_ms=10,
                peer_bucket_refill_amount=1,
            )
            config = replace(
                base,
                loss_probability=scenario.loss_probability,
                duplicate_probability=scenario.duplicate_probability,
                malicious_fraction=scenario.malicious_fraction,
                attack_bursts=scenario.attack_bursts,
                attack_branches_per_burst=(
                    scenario.attack_branches_per_burst
                ),
                peer_bucket_capacity=scenario.peer_bucket_capacity,
            )
            result = simulate_event_lifecycle(
                graph,
                config,
                responders=responders,
            )
            successes += int(result.success)
            cleanups += int(result.cleanup_complete)
            if result.setup_latency_ms is not None:
                setup_latencies.append(result.setup_latency_ms)
            candidates.append(result.candidates_received)
            late_candidates.append(result.late_candidates)
            race_drops.append(result.candidate_race_drops)
            legitimate_transmissions.append(result.legitimate_transmissions)
            attack_transmissions.append(result.attack_transmissions)
            total_transmissions.append(result.total_transmissions)
            legitimate_allocations.append(result.legitimate_branch_allocations)
            attack_allocations.append(result.attack_branch_allocations)
            peak_branch.append(result.peak_branch_state)
            peak_offer.append(result.peak_offer_state)
            peak_candidate.append(result.peak_candidate_state)
            peak_tentative.append(result.peak_tentative_state)
            peak_pending.append(result.peak_pending_state)
            peak_active.append(result.peak_active_state)
            final_branch.append(result.final_branch_state)
            final_offer.append(result.final_offer_state)
            final_candidate.append(result.final_candidate_state)
            final_tentative.append(result.final_tentative_state)
            final_pending.append(result.final_pending_state)
            final_active.append(result.final_active_state)
            bucket_drops.append(result.token_bucket_drops)
            branch_capacity_drops.append(result.branch_capacity_drops)
            per_node_drops.append(result.per_node_branch_drops)
            loss_drops.append(result.loss_drops)
            replay_drops.append(result.exact_replay_drops)
            commit_failures.append(result.commit_failures)
            ready_failures.append(result.ready_failures)
            no_candidates += int(result.stop_reason == "no_candidate")
            route_setup_failures += int(
                result.stop_reason
                in {
                    "commit_offer_expired",
                    "commit_missing_tentative",
                    "active_capacity",
                    "ready_missing_pending",
                    "route_setup_timeout",
                }
            )

        results.append(
            LifecycleAggregate(
                scenario=scenario.name,
                runs=runs,
                success_rate=successes / runs,
                cleanup_rate=cleanups / runs,
                mean_setup_latency_ms=_safe_mean(setup_latencies),
                mean_candidates=mean(candidates),
                mean_late_candidates=mean(late_candidates),
                mean_candidate_race_drops=mean(race_drops),
                mean_legitimate_transmissions=mean(
                    legitimate_transmissions
                ),
                mean_attack_transmissions=mean(attack_transmissions),
                mean_total_transmissions=mean(total_transmissions),
                mean_legitimate_branch_allocations=mean(
                    legitimate_allocations
                ),
                mean_attack_branch_allocations=mean(attack_allocations),
                mean_peak_branch_state=mean(peak_branch),
                mean_peak_offer_state=mean(peak_offer),
                mean_peak_candidate_state=mean(peak_candidate),
                mean_peak_tentative_state=mean(peak_tentative),
                mean_peak_pending_state=mean(peak_pending),
                mean_peak_active_state=mean(peak_active),
                mean_final_branch_state=mean(final_branch),
                mean_final_offer_state=mean(final_offer),
                mean_final_candidate_state=mean(final_candidate),
                mean_final_tentative_state=mean(final_tentative),
                mean_final_pending_state=mean(final_pending),
                mean_final_active_state=mean(final_active),
                mean_token_bucket_drops=mean(bucket_drops),
                mean_branch_capacity_drops=mean(branch_capacity_drops),
                mean_per_node_branch_drops=mean(per_node_drops),
                mean_loss_drops=mean(loss_drops),
                mean_exact_replay_drops=mean(replay_drops),
                mean_commit_failures=mean(commit_failures),
                mean_ready_failures=mean(ready_failures),
                no_candidate_rate=no_candidates / runs,
                route_setup_failure_rate=route_setup_failures / runs,
            )
        )
    return results


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare event-driven Trahens lifecycle scenarios"
    )
    parser.add_argument("--nodes", type=int, default=500)
    parser.add_argument("--average-degree", type=float, default=8.0)
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument(
        "--rings",
        type=parse_timed_ring_schedule,
        default=parse_timed_ring_schedule("2:2:18,3:2:24,4:3:32"),
    )
    parser.add_argument("--responder-fraction", type=float, default=0.02)
    parser.add_argument("--seed-base", type=int, default=7000)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    rows = run_lifecycle_comparison(
        nodes=args.nodes,
        average_degree=args.average_degree,
        runs=args.runs,
        rings=args.rings,
        responder_fraction=args.responder_fraction,
        seed_base=args.seed_base,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    field_names = list(LifecycleAggregate.__dataclass_fields__)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(field_names)
        for row in rows:
            values: list[object] = []
            for name in field_names:
                value = getattr(row, name)
                if isinstance(value, float):
                    values.append(f"{value:.4f}")
                else:
                    values.append(value)
            writer.writerow(values)
    print(f"lifecycle comparison written to {args.output}")


if __name__ == "__main__":
    main()
