# SPDX-License-Identifier: Apache-2.0
"""Reproducible comparison of W2 delivery and the T1 reliability profiles."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
from statistics import mean

from .event_model import EventLifecycleConfig, TimedRingStep, simulate_event_lifecycle
from .model import Graph
from .t1_model import T1Config, T1Result, simulate_t1_path


@dataclass(frozen=True)
class T1ComparisonRow:
    profile: str
    route_hops: int
    cell_loss_probability: float
    runs: int
    success_rate: float
    mean_success_latency_ms: float | None
    mean_data_cells: float
    mean_ack_cells: float
    mean_chaff_cells: float
    mean_retransmitted_data_cells: float
    mean_total_cells: float
    mean_wire_bytes: float
    mean_timeout_events: float
    mean_trace_rate_cv: float | None
    cleanup_rate: float


def _line_graph(nodes: int) -> Graph:
    graph = Graph(nodes)
    for node in range(nodes - 1):
        graph.add_edge(node, node + 1)
    return graph


def _w2_result(route_hops: int, loss: float, seed: int):
    graph = _line_graph(route_hops + 1)
    return simulate_event_lifecycle(
        graph,
        EventLifecycleConfig(
            eligibility_profile="r1",
            rings=(TimedRingStep(route_hops, 1, 1, 120),),
            seed=seed,
            discover_delay_min_ms=1,
            discover_delay_max_ms=3,
            candidate_delay_min_ms=1,
            candidate_delay_max_ms=3,
            control_delay_min_ms=1,
            control_delay_max_ms=2,
            responder_offer_delay_min_ms=1,
            responder_offer_delay_max_ms=2,
            branch_ttl_ms=300,
            offer_ttl_ms=340,
            tentative_ttl_ms=240,
            ready_hold_ms=160,
            route_setup_timeout_ms=300,
            active_lifetime_ms=70,
            max_simulation_ms=max(700, 50 * route_hops + 300),
            transmission_budget=10_000,
            branch_capacity=2_000,
            tentative_capacity=1_000,
            active_capacity=100,
            per_node_branch_limit=100,
            candidate_response_limit=100,
            reassembly_timeout_ms=80,
            reassembly_max_messages=256,
            reassembly_max_bytes=512 * 1024,
            loss_probability=loss,
        ),
        responders={route_hops},
    )


def _mean_latency(results: list[T1Result]) -> float | None:
    latencies = [
        result.setup_latency_ms
        for result in results
        if result.success and result.setup_latency_ms is not None
    ]
    return mean(latencies) if latencies else None


def run_comparison(
    *,
    runs: int = 30,
    route_hops: tuple[int, ...] = (2, 5, 8, 12),
    losses: tuple[float, ...] = (0.02, 0.05, 0.10),
    seed_base: int = 30_000,
) -> list[T1ComparisonRow]:
    if runs < 1:
        raise ValueError("runs must be positive")
    rows: list[T1ComparisonRow] = []
    for loss in losses:
        for hops in route_hops:
            w2 = [
                _w2_result(hops, loss, seed_base + int(loss * 1000) * 100 + hops * 10 + run)
                for run in range(runs)
            ]
            w2_latencies = [
                result.setup_latency_ms
                for result in w2
                if result.success and result.setup_latency_ms is not None
            ]
            rows.append(
                T1ComparisonRow(
                    profile="W2-no-recovery",
                    route_hops=hops,
                    cell_loss_probability=loss,
                    runs=runs,
                    success_rate=mean(int(result.success) for result in w2),
                    mean_success_latency_ms=mean(w2_latencies) if w2_latencies else None,
                    mean_data_cells=mean(result.total_transmissions for result in w2),
                    mean_ack_cells=0.0,
                    mean_chaff_cells=0.0,
                    mean_retransmitted_data_cells=0.0,
                    mean_total_cells=mean(result.total_transmissions for result in w2),
                    mean_wire_bytes=mean(result.wire_bytes for result in w2),
                    mean_timeout_events=0.0,
                    mean_trace_rate_cv=None,
                    cleanup_rate=mean(int(result.cleanup_complete) for result in w2),
                )
            )

            for profile, mode in (
                ("T1-selective-recovery", "work-conserving"),
                ("T1-fixed-schedule", "constant"),
            ):
                t1_results: list[T1Result] = []
                for run in range(runs):
                    seed = (
                        seed_base
                        + 1_000_000
                        + int(loss * 1000) * 100
                        + hops * 10
                        + run
                    )
                    t1_results.append(
                        simulate_t1_path(
                            hops,
                            T1Config(
                                seed=seed,
                                scheduler_mode=mode,
                                loss_probability=loss,
                                slot_interval_ms=2,
                                schedule_epoch_ms=max(700, 70 * hops + 400),
                                ack_delay_ms=2,
                                initial_rto_ms=14,
                                min_rto_ms=8,
                                max_rto_ms=96,
                                max_retransmission_rounds=3,
                                queue_capacity_cells=512,
                                receiver_cache_ttl_ms=100,
                            ),
                        )
                    )
                rows.append(
                    T1ComparisonRow(
                        profile=profile,
                        route_hops=hops,
                        cell_loss_probability=loss,
                        runs=runs,
                        success_rate=mean(int(result.success) for result in t1_results),
                        mean_success_latency_ms=_mean_latency(t1_results),
                        mean_data_cells=mean(result.data_cells for result in t1_results),
                        mean_ack_cells=mean(result.ack_cells for result in t1_results),
                        mean_chaff_cells=mean(result.chaff_cells for result in t1_results),
                        mean_retransmitted_data_cells=mean(
                            result.retransmitted_data_cells for result in t1_results
                        ),
                        mean_total_cells=mean(result.total_cells for result in t1_results),
                        mean_wire_bytes=mean(result.wire_bytes for result in t1_results),
                        mean_timeout_events=mean(result.timeout_events for result in t1_results),
                        mean_trace_rate_cv=mean(
                            result.external_trace_rate_cv for result in t1_results
                        ),
                        cleanup_rate=mean(
                            int(result.cleanup_complete) for result in t1_results
                        ),
                    )
                )
    return rows


def run_trace_equivalence(
    *,
    route_hops: tuple[int, ...] = (2, 5, 8, 12),
    seed: int = 44_000,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for hops in route_hops:
        config = T1Config(
            seed=seed + hops,
            scheduler_mode="constant",
            loss_probability=0.0,
            slot_interval_ms=2,
            schedule_epoch_ms=max(700, 70 * hops + 400),
        )
        active = simulate_t1_path(hops, config, start_protocol=True)
        empty = simulate_t1_path(hops, config, start_protocol=False)
        rows.append(
            {
                "route_hops": hops,
                "active_trace_cells_min": active.per_direction_trace_cells_min,
                "active_trace_cells_max": active.per_direction_trace_cells_max,
                "empty_trace_cells_min": empty.per_direction_trace_cells_min,
                "empty_trace_cells_max": empty.per_direction_trace_cells_max,
                "active_rate_cv": active.external_trace_rate_cv,
                "empty_rate_cv": empty.external_trace_rate_cv,
                "same_public_schedule": int(
                    active.per_direction_trace_cells_min
                    == active.per_direction_trace_cells_max
                    == empty.per_direction_trace_cells_min
                    == empty.per_direction_trace_cells_max
                    and active.external_trace_rate_cv == empty.external_trace_rate_cv == 0.0
                ),
                "active_real_cells": active.data_cells + active.ack_cells,
                "active_chaff_cells": active.chaff_cells,
                "empty_chaff_cells": empty.chaff_cells,
            }
        )
    return rows


def write_csv(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    dictionaries = [row.__dict__ if hasattr(row, "__dict__") else row for row in rows]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(dictionaries[0]))
        writer.writeheader()
        writer.writerows(dictionaries)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/iteration-0012-t1-reliability.csv"),
    )
    parser.add_argument(
        "--trace-output",
        type=Path,
        default=Path("reports/iteration-0012-t1-trace-equivalence.csv"),
    )
    args = parser.parse_args()
    rows = run_comparison(runs=args.runs)
    traces = run_trace_equivalence()
    write_csv(args.output, rows)
    write_csv(args.trace_output, traces)
    for row in rows:
        print(row)
    for row in traces:
        print(row)


if __name__ == "__main__":
    main()
