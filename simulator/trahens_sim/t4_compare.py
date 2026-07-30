# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic T4 packet-emulation and adversarial reports."""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean

from .t4_model import (
    PROFILE_NAMES,
    T4Config,
    open_world_classifier,
    open_world_dataset,
    selective_delay_detection,
)


@dataclass(frozen=True)
class OpenWorldRow:
    profile: str
    scenario: str
    observation_epochs: int
    monitored_routes: int
    unknown_test_routes: int
    testing_unknown_to_monitored_ratio: float
    classifier_accuracy: float
    classifier_macro_f1: float
    monitored_true_positive_rate: float
    unknown_false_positive_rate: float
    monitored_precision: float
    rejection_threshold: float
    mean_target_delivery_rate: float
    mean_network_delay_us: float
    mean_p95_network_delay_us: float
    mean_peak_queue_cells: float
    budget_match_rate: float
    cleanup_rate: float


@dataclass(frozen=True)
class SelectiveDelayRow:
    profile: str
    route_churn: bool
    observation_epochs: int
    selective_delay_us: int
    classifier_accuracy: float
    true_positive_rate: float
    false_positive_rate: float
    absent_mean_score: float
    present_mean_score: float
    threshold: float


@dataclass(frozen=True)
class PacketEmulationRow:
    profile: str
    scenario: str
    traces: int
    mean_total_public_cells: float
    mean_chaff_cells: float
    mean_target_delivery_rate: float
    mean_dropped_cells: float
    mean_expired_cells: float
    mean_network_delay_us: float
    mean_p95_network_delay_us: float
    mean_peak_queue_cells: float
    budget_match_rate: float
    cleanup_rate: float


def _write_csv(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    dictionaries = [asdict(row) for row in rows]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(dictionaries[0]))
        writer.writeheader()
        writer.writerows(dictionaries)


def _scenario_config(name: str, *, seed: int, epochs: int) -> tuple[T4Config, bool]:
    base = dict(
        epochs=epochs,
        budget_cells_per_epoch=14,
        minimum_cells_per_epoch=7,
        maximum_cells_per_epoch=28,
        target_burst_cells=14,
        seed=seed,
    )
    if name == "ideal":
        return T4Config(
            **base,
            propagation_jitter_us=0,
            clock_skew_ppm=0,
            clock_noise_us=0,
            timestamp_quantum_us=1,
            shared_bottlenecks=False,
        ), False
    if name == "network-noise":
        return T4Config(**base), False
    if name == "partial-observation":
        return T4Config(**base, observed_links=(0, 2, 3)), False
    if name == "route-churn":
        return T4Config(**base), True
    raise ValueError("unknown scenario")


def run_open_world_experiment(
    *,
    epochs: int = 48,
    training_per_monitored: int = 10,
    calibration_per_route: int = 5,
    testing_per_monitored: int = 8,
    testing_per_unknown_route: int = 8,
    seed_base: int = 404_000,
) -> tuple[list[OpenWorldRow], list[PacketEmulationRow]]:
    classifier_rows: list[OpenWorldRow] = []
    packet_rows: list[PacketEmulationRow] = []
    scenarios = ("ideal", "network-noise", "partial-observation", "route-churn")
    for scenario_index, scenario in enumerate(scenarios):
        for profile_index, profile in enumerate(PROFILE_NAMES):
            config, churn = _scenario_config(
                scenario,
                seed=seed_base + scenario_index * 1_000_003 + profile_index * 100_003,
                epochs=epochs,
            )
            training, calibration, testing, traces = open_world_dataset(
                profile=profile,
                config=config,
                training_per_monitored=training_per_monitored,
                calibration_per_route=calibration_per_route,
                testing_per_monitored=testing_per_monitored,
                testing_per_unknown_route=testing_per_unknown_route,
                churn=churn,
            )
            result = open_world_classifier(training, calibration, testing)
            delivery_rates = [
                trace.delivered_target_cells / trace.generated_target_cells
                if trace.generated_target_cells
                else 1.0
                for trace in traces
            ]
            classifier_rows.append(
                OpenWorldRow(
                    profile=profile,
                    scenario=scenario,
                    observation_epochs=epochs,
                    monitored_routes=3,
                    unknown_test_routes=4,
                    testing_unknown_to_monitored_ratio=(
                        4 * testing_per_unknown_route / (3 * testing_per_monitored)
                    ),
                    classifier_accuracy=result.accuracy,
                    classifier_macro_f1=result.macro_f1,
                    monitored_true_positive_rate=result.monitored_true_positive_rate,
                    unknown_false_positive_rate=result.unknown_false_positive_rate,
                    monitored_precision=result.monitored_precision,
                    rejection_threshold=result.threshold,
                    mean_target_delivery_rate=mean(delivery_rates),
                    mean_network_delay_us=mean(trace.mean_network_delay_us for trace in traces),
                    mean_p95_network_delay_us=mean(trace.p95_network_delay_us for trace in traces),
                    mean_peak_queue_cells=mean(trace.peak_queue_cells for trace in traces),
                    budget_match_rate=mean(
                        int(trace.total_public_cells == trace.expected_public_cells) for trace in traces
                    ),
                    cleanup_rate=mean(int(trace.cleanup_complete) for trace in traces),
                )
            )
            packet_rows.append(
                PacketEmulationRow(
                    profile=profile,
                    scenario=scenario,
                    traces=len(traces),
                    mean_total_public_cells=mean(trace.total_public_cells for trace in traces),
                    mean_chaff_cells=mean(trace.chaff_cells for trace in traces),
                    mean_target_delivery_rate=mean(delivery_rates),
                    mean_dropped_cells=mean(trace.dropped_cells for trace in traces),
                    mean_expired_cells=mean(trace.expired_cells for trace in traces),
                    mean_network_delay_us=mean(trace.mean_network_delay_us for trace in traces),
                    mean_p95_network_delay_us=mean(trace.p95_network_delay_us for trace in traces),
                    mean_peak_queue_cells=mean(trace.peak_queue_cells for trace in traces),
                    budget_match_rate=mean(
                        int(trace.total_public_cells == trace.expected_public_cells) for trace in traces
                    ),
                    cleanup_rate=mean(int(trace.cleanup_complete) for trace in traces),
                )
            )
    return classifier_rows, packet_rows


def run_selective_delay_experiment(
    *,
    epochs: int = 48,
    training_per_class: int = 12,
    testing_per_class: int = 12,
    seed_base: int = 505_000,
) -> list[SelectiveDelayRow]:
    rows: list[SelectiveDelayRow] = []
    for churn in (False, True):
        for profile_index, profile in enumerate(PROFILE_NAMES):
            config = T4Config(
                epochs=epochs,
                budget_cells_per_epoch=14,
                minimum_cells_per_epoch=7,
                maximum_cells_per_epoch=28,
                target_burst_cells=14,
                selective_delay_us=60_000,
                seed=seed_base + profile_index * 100_003 + int(churn) * 1_000_003,
            )
            result = selective_delay_detection(
                profile=profile,
                config=config,
                training_per_class=training_per_class,
                testing_per_class=testing_per_class,
                churn=churn,
            )
            rows.append(
                SelectiveDelayRow(
                    profile=profile,
                    route_churn=churn,
                    observation_epochs=epochs,
                    selective_delay_us=config.selective_delay_us,
                    classifier_accuracy=result.accuracy,
                    true_positive_rate=result.true_positive_rate,
                    false_positive_rate=result.false_positive_rate,
                    absent_mean_score=result.absent_mean_score,
                    present_mean_score=result.present_mean_score,
                    threshold=result.threshold,
                )
            )
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--epochs", type=int, default=48)
    parser.add_argument("--training-per-monitored", type=int, default=10)
    parser.add_argument("--calibration-per-route", type=int, default=5)
    parser.add_argument("--testing-per-monitored", type=int, default=8)
    parser.add_argument("--testing-per-unknown-route", type=int, default=8)
    parser.add_argument("--probe-training", type=int, default=12)
    parser.add_argument("--probe-testing", type=int, default=12)
    parser.add_argument(
        "--open-world-output",
        type=Path,
        default=Path("reports/iteration-0015-t4-open-world.csv"),
    )
    parser.add_argument(
        "--packet-output",
        type=Path,
        default=Path("reports/iteration-0015-t4-packet-emulation.csv"),
    )
    parser.add_argument(
        "--probe-output",
        type=Path,
        default=Path("reports/iteration-0015-t4-selective-delay.csv"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    open_world, packet = run_open_world_experiment(
        epochs=args.epochs,
        training_per_monitored=args.training_per_monitored,
        calibration_per_route=args.calibration_per_route,
        testing_per_monitored=args.testing_per_monitored,
        testing_per_unknown_route=args.testing_per_unknown_route,
    )
    probing = run_selective_delay_experiment(
        epochs=args.epochs,
        training_per_class=args.probe_training,
        testing_per_class=args.probe_testing,
    )
    _write_csv(args.open_world_output, open_world)
    _write_csv(args.packet_output, packet)
    _write_csv(args.probe_output, probing)
    print(f"wrote {args.open_world_output}")
    print(f"wrote {args.packet_output}")
    print(f"wrote {args.probe_output}")


if __name__ == "__main__":
    main()
