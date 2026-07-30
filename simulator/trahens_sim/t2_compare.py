"""Deterministic T2 congestion, leakage, burst-loss, and correlation reports."""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from pathlib import Path
import random
from statistics import mean

from .t2_model import (
    T2Config,
    T2Flow,
    schedule_presence_classifier,
    simulate_t2_link,
    simulate_two_link_trace,
    stationary_gilbert_elliott_loss,
)


@dataclass(frozen=True)
class CongestionRow:
    workload: str
    profile: str
    runs: int
    mean_delivery_rate: float
    mean_drop_rate: float
    mean_peak_queue_cells: float
    mean_delay_epochs: float
    mean_p95_delay_epochs: float
    mean_weighted_fairness: float
    mean_chaff_cells: float
    mean_rate_changes: float
    cleanup_rate: float


@dataclass(frozen=True)
class LeakageRow:
    profile: str
    runs_per_class: int
    idle_mean_cells_per_epoch: float
    active_mean_cells_per_epoch: float
    idle_mean_rate_changes: float
    active_mean_rate_changes: float
    classifier_accuracy: float
    distinguishing_advantage: float
    active_mean_chaff_cells: float


@dataclass(frozen=True)
class BurstLossRow:
    loss_model: str
    nominal_mean_loss_probability: float
    runs: int
    mean_delivery_rate: float
    mean_retry_exhaustions: float
    mean_retransmitted_cells: float
    mean_delay_epochs: float
    mean_p95_delay_epochs: float
    cleanup_rate: float


@dataclass(frozen=True)
class CorrelationRow:
    profile: str
    runs: int
    mean_lag_one_correlation: float
    mean_first_link_cells_per_epoch: float
    mean_second_link_cells_per_epoch: float


def _delivery_rate(result) -> float:
    denominator = result.admitted_cells
    return result.delivered_cells / denominator if denominator else 1.0


def _drop_rate(result) -> float:
    denominator = result.admitted_cells + result.dropped_cells
    return result.dropped_cells / denominator if denominator else 0.0


def _mean_public(result) -> float:
    return mean(result.public_cells_by_epoch) if result.public_cells_by_epoch else 0.0


def _equal_flows() -> tuple[T2Flow, ...]:
    return tuple(T2Flow(index, 1, tuple([12] * 20)) for index in range(4))


def _weighted_flows() -> tuple[T2Flow, ...]:
    return (
        T2Flow(0, 1, tuple([80] * 20)),
        T2Flow(1, 2, tuple([80] * 20)),
        T2Flow(2, 3, tuple([80] * 20)),
    )


def run_congestion_experiment(*, runs: int = 30, seed_base: int = 61_000) -> list[CongestionRow]:
    rows: list[CongestionRow] = []
    configurations = (
        (
            "equal-overload",
            _equal_flows(),
            {
                "fixed-low": dict(scheduler_mode="fixed", fixed_rate_class=1),
                "fixed-high": dict(scheduler_mode="fixed", fixed_rate_class=3),
                "adaptive-hysteresis": dict(scheduler_mode="adaptive"),
                "work-conserving": dict(scheduler_mode="work-conserving"),
            },
            dict(queue_capacity_cells=512, per_flow_capacity_cells=256, drain_epochs=20),
        ),
        (
            "weighted-saturation",
            _weighted_flows(),
            {
                "fixed-high-drr": dict(scheduler_mode="fixed", fixed_rate_class=3),
                "adaptive-drr": dict(scheduler_mode="adaptive"),
            },
            dict(queue_capacity_cells=12_000, per_flow_capacity_cells=4_000, drain_epochs=0),
        ),
    )
    for workload, flows, profiles, common in configurations:
        for profile, overrides in profiles.items():
            results = []
            for run in range(runs):
                results.append(
                    simulate_t2_link(
                        flows,
                        T2Config(
                            seed=seed_base + run + 1000 * len(rows),
                            loss_model="none",
                            **common,
                            **overrides,
                        ),
                    )
                )
            rows.append(
                CongestionRow(
                    workload=workload,
                    profile=profile,
                    runs=runs,
                    mean_delivery_rate=mean(_delivery_rate(result) for result in results),
                    mean_drop_rate=mean(_drop_rate(result) for result in results),
                    mean_peak_queue_cells=mean(result.peak_queue_cells for result in results),
                    mean_delay_epochs=mean(result.mean_delay_epochs for result in results),
                    mean_p95_delay_epochs=mean(result.p95_delay_epochs for result in results),
                    mean_weighted_fairness=mean(result.weighted_fairness for result in results),
                    mean_chaff_cells=mean(result.chaff_cells for result in results),
                    mean_rate_changes=mean(result.rate_changes for result in results),
                    cleanup_rate=mean(int(result.cleanup_complete) for result in results),
                )
            )
    return rows


def run_leakage_experiment(*, runs: int = 100, seed_base: int = 71_000) -> list[LeakageRow]:
    rows: list[LeakageRow] = []
    profiles = (
        (
            "fixed-high",
            dict(scheduler_mode="fixed", fixed_rate_class=3, initial_rate_class=3),
            3,
        ),
        (
            "adaptive-fast",
            dict(
                scheduler_mode="adaptive",
                initial_rate_class=0,
                up_consecutive_epochs=1,
                down_consecutive_epochs=2,
                minimum_hold_epochs=1,
            ),
            0,
        ),
        (
            "adaptive-hysteresis",
            dict(scheduler_mode="adaptive", initial_rate_class=0),
            0,
        ),
    )
    for profile, overrides, baseline in profiles:
        idle_results = []
        active_results = []
        predictions: list[tuple[int, int]] = []
        for run in range(runs):
            common = dict(
                seed=seed_base + run + 10_000 * len(rows),
                loss_model="none",
                drain_epochs=8,
                queue_capacity_cells=256,
                per_flow_capacity_cells=256,
                **overrides,
            )
            idle = simulate_t2_link(
                (T2Flow(0, 1, tuple([0] * 20)),), T2Config(**common)
            )
            active = simulate_t2_link(
                (T2Flow(0, 1, tuple([20] * 10 + [0] * 10)),),
                T2Config(**common),
            )
            idle_results.append(idle)
            active_results.append(active)
            predictions.append((0, schedule_presence_classifier(idle, baseline)))
            predictions.append((1, schedule_presence_classifier(active, baseline)))
        accuracy = mean(int(label == prediction) for label, prediction in predictions)
        rows.append(
            LeakageRow(
                profile=profile,
                runs_per_class=runs,
                idle_mean_cells_per_epoch=mean(_mean_public(result) for result in idle_results),
                active_mean_cells_per_epoch=mean(_mean_public(result) for result in active_results),
                idle_mean_rate_changes=mean(result.rate_changes for result in idle_results),
                active_mean_rate_changes=mean(result.rate_changes for result in active_results),
                classifier_accuracy=accuracy,
                distinguishing_advantage=max(0.0, 2.0 * accuracy - 1.0),
                active_mean_chaff_cells=mean(result.chaff_cells for result in active_results),
            )
        )
    return rows


def run_burst_loss_experiment(*, runs: int = 100, seed_base: int = 81_000) -> list[BurstLossRow]:
    ge_base = T2Config(
        scheduler_mode="adaptive",
        initial_rate_class=1,
        maximum_rate_class=3,
        queue_capacity_cells=1024,
        per_flow_capacity_cells=1024,
        drain_epochs=24,
        max_retries=2,
        loss_model="gilbert-elliott",
        good_loss_probability=0.005,
        bad_loss_probability=0.75,
        good_to_bad_probability=0.02,
        bad_to_good_probability=0.12,
    )
    mean_loss = stationary_gilbert_elliott_loss(ge_base)
    rows: list[BurstLossRow] = []
    for loss_model in ("independent", "gilbert-elliott"):
        results = []
        for run in range(runs):
            config_values = asdict(ge_base)
            config_values["seed"] = seed_base + run + (0 if loss_model == "independent" else 10_000)
            config_values["loss_model"] = loss_model
            config_values["independent_loss_probability"] = mean_loss
            result = simulate_t2_link(
                (T2Flow(0, 1, tuple([24] * 20)),),
                T2Config(**config_values),
            )
            results.append(result)
        rows.append(
            BurstLossRow(
                loss_model=loss_model,
                nominal_mean_loss_probability=mean_loss,
                runs=runs,
                mean_delivery_rate=mean(_delivery_rate(result) for result in results),
                mean_retry_exhaustions=mean(result.retry_exhaustions for result in results),
                mean_retransmitted_cells=mean(result.retransmitted_cells for result in results),
                mean_delay_epochs=mean(result.mean_delay_epochs for result in results),
                mean_p95_delay_epochs=mean(result.p95_delay_epochs for result in results),
                cleanup_rate=mean(int(result.cleanup_complete) for result in results),
            )
        )
    return rows


def run_correlation_experiment(*, runs: int = 100, seed_base: int = 91_000) -> list[CorrelationRow]:
    rows: list[CorrelationRow] = []
    for profile in ("fixed", "adaptive", "work-conserving"):
        correlations = []
        first_means = []
        second_means = []
        for run in range(runs):
            rng = random.Random(seed_base + run)
            arrivals = []
            for epoch in range(60):
                phase = epoch % 15
                if phase in {3, 4, 5, 10, 11}:
                    arrivals.append(rng.randint(20, 55))
                else:
                    arrivals.append(rng.randint(0, 6))
            first, second, correlation = simulate_two_link_trace(
                arrivals,
                mode=profile,
                config=T2Config(
                    seed=seed_base + run,
                    scheduler_mode=profile,
                    fixed_rate_class=3,
                    initial_rate_class=0,
                    maximum_rate_class=3,
                    drain_epochs=0,
                    loss_model="none",
                    queue_capacity_cells=512,
                    per_flow_capacity_cells=512,
                ),
            )
            correlations.append(correlation)
            first_means.append(mean(first))
            second_means.append(mean(second))
        rows.append(
            CorrelationRow(
                profile=profile,
                runs=runs,
                mean_lag_one_correlation=mean(correlations),
                mean_first_link_cells_per_epoch=mean(first_means),
                mean_second_link_cells_per_epoch=mean(second_means),
            )
        )
    return rows


def write_csv(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    dictionaries = [asdict(row) for row in rows]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(dictionaries[0]))
        writer.writeheader()
        writer.writerows(dictionaries)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--leak-runs", type=int, default=100)
    parser.add_argument("--burst-runs", type=int, default=100)
    parser.add_argument("--correlation-runs", type=int, default=100)
    parser.add_argument(
        "--congestion-output",
        type=Path,
        default=Path("reports/iteration-0013-t2-congestion.csv"),
    )
    parser.add_argument(
        "--leakage-output",
        type=Path,
        default=Path("reports/iteration-0013-t2-schedule-leakage.csv"),
    )
    parser.add_argument(
        "--burst-output",
        type=Path,
        default=Path("reports/iteration-0013-t2-burst-loss.csv"),
    )
    parser.add_argument(
        "--correlation-output",
        type=Path,
        default=Path("reports/iteration-0013-t2-multilink-correlation.csv"),
    )
    args = parser.parse_args()
    congestion = run_congestion_experiment(runs=args.runs)
    leakage = run_leakage_experiment(runs=args.leak_runs)
    burst = run_burst_loss_experiment(runs=args.burst_runs)
    correlation = run_correlation_experiment(runs=args.correlation_runs)
    write_csv(args.congestion_output, congestion)
    write_csv(args.leakage_output, leakage)
    write_csv(args.burst_output, burst)
    write_csv(args.correlation_output, correlation)
    for row in [*congestion, *leakage, *burst, *correlation]:
        print(row)


if __name__ == "__main__":
    main()
