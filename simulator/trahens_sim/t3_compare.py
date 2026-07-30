"""Deterministic T3 route-classification, probing, and boundary reports."""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean

from .t3_model import (
    PROFILE_NAMES,
    ROUTE_LINKS,
    T3Config,
    active_probe_detection,
    nearest_centroid_classifier,
    route_classification_dataset,
)


@dataclass(frozen=True)
class RouteClassificationRow:
    profile: str
    observation_epochs: int
    cross_traffic: str
    training_per_class: int
    testing_per_class: int
    classes: int
    random_baseline: float
    classifier_accuracy: float
    classifier_macro_f1: float
    advantage_over_random: float
    mean_boundary_alignment: float
    mean_pairwise_lag_correlation: float
    mean_delay_epochs: float
    mean_peak_queue_cells: float
    budget_match_rate: float
    cleanup_rate: float


@dataclass(frozen=True)
class ActiveProbeRow:
    profile: str
    observation_epochs: int
    training_per_class: int
    testing_per_class: int
    classifier_accuracy: float
    true_positive_rate: float
    false_positive_rate: float
    absent_mean_score: float
    present_mean_score: float
    threshold: float


@dataclass(frozen=True)
class EqualBudgetRow:
    profile: str
    observation_epochs: int
    traces: int
    cells_per_link: int
    expected_total_cells_per_trace: int
    minimum_total_cells: int
    maximum_total_cells: int
    all_traces_equal_budget: bool
    mean_boundary_alignment: float
    mean_pairwise_lag_correlation: float
    mean_delivery_rate: float
    cleanup_rate: float


def _write_csv(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    dictionaries = [asdict(row) for row in rows]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(dictionaries[0]))
        writer.writeheader()
        writer.writerows(dictionaries)


def run_route_classification_experiment(
    *,
    windows: tuple[int, ...] = (32, 64, 128, 256),
    training_per_class: int = 32,
    testing_per_class: int = 24,
    seed_base: int = 101_000,
) -> list[RouteClassificationRow]:
    rows: list[RouteClassificationRow] = []
    for correlated in (False, True):
        for epochs in windows:
            for profile_index, profile in enumerate(PROFILE_NAMES):
                config = T3Config(
                    epochs=epochs,
                    seed=seed_base + epochs * 97 + profile_index * 10_003 + int(correlated) * 1_000_003,
                )
                training, testing, traces = route_classification_dataset(
                    profile=profile,
                    config=config,
                    correlated_cross_traffic=correlated,
                    training_per_class=training_per_class,
                    testing_per_class=testing_per_class,
                )
                result = nearest_centroid_classifier(training, testing)
                random_baseline = 1.0 / len(ROUTE_LINKS)
                rows.append(
                    RouteClassificationRow(
                        profile=profile,
                        observation_epochs=epochs,
                        cross_traffic="correlated" if correlated else "independent",
                        training_per_class=training_per_class,
                        testing_per_class=testing_per_class,
                        classes=len(ROUTE_LINKS),
                        random_baseline=random_baseline,
                        classifier_accuracy=result.accuracy,
                        classifier_macro_f1=result.macro_f1,
                        advantage_over_random=max(0.0, result.accuracy - random_baseline),
                        mean_boundary_alignment=mean(trace.boundary_alignment for trace in traces),
                        mean_pairwise_lag_correlation=mean(
                            trace.mean_pairwise_lag_correlation for trace in traces
                        ),
                        mean_delay_epochs=mean(trace.mean_delay_epochs for trace in traces),
                        mean_peak_queue_cells=mean(trace.peak_queue_cells for trace in traces),
                        budget_match_rate=mean(
                            int(trace.total_public_cells == trace.expected_public_cells)
                            for trace in traces
                        ),
                        cleanup_rate=mean(int(trace.cleanup_complete) for trace in traces),
                    )
                )
    return rows


def run_active_probe_experiment(
    *,
    epochs: int = 128,
    training_per_class: int = 40,
    testing_per_class: int = 40,
    seed_base: int = 202_000,
) -> list[ActiveProbeRow]:
    rows: list[ActiveProbeRow] = []
    for profile_index, profile in enumerate(PROFILE_NAMES):
        result = active_probe_detection(
            profile=profile,
            config=T3Config(
                epochs=epochs,
                seed=seed_base + profile_index * 100_003,
            ),
            route_label=1,
            training_per_class=training_per_class,
            testing_per_class=testing_per_class,
            correlated_cross_traffic=True,
        )
        rows.append(
            ActiveProbeRow(
                profile=profile,
                observation_epochs=epochs,
                training_per_class=training_per_class,
                testing_per_class=testing_per_class,
                classifier_accuracy=result.accuracy,
                true_positive_rate=result.true_positive_rate,
                false_positive_rate=result.false_positive_rate,
                absent_mean_score=result.absent_mean_score,
                present_mean_score=result.present_mean_score,
                threshold=result.threshold,
            )
        )
    return rows


def run_equal_budget_experiment(
    *,
    epochs: int = 128,
    samples_per_route: int = 20,
    seed_base: int = 303_000,
) -> list[EqualBudgetRow]:
    rows: list[EqualBudgetRow] = []
    for profile_index, profile in enumerate(PROFILE_NAMES):
        _training, _testing, traces = route_classification_dataset(
            profile=profile,
            config=T3Config(
                epochs=epochs,
                seed=seed_base + profile_index * 100_003,
            ),
            correlated_cross_traffic=True,
            training_per_class=samples_per_route,
            testing_per_class=0,
        )
        totals = [trace.total_public_cells for trace in traces]
        delivered = [trace.delivered_cells for trace in traces]
        demand = [sum(sum(link) for link in trace.demand_cells) for trace in traces]
        rows.append(
            EqualBudgetRow(
                profile=profile,
                observation_epochs=epochs,
                traces=len(traces),
                cells_per_link=epochs * T3Config().budget_cells_per_epoch,
                expected_total_cells_per_trace=traces[0].expected_public_cells,
                minimum_total_cells=min(totals),
                maximum_total_cells=max(totals),
                all_traces_equal_budget=all(
                    trace.total_public_cells == trace.expected_public_cells for trace in traces
                ),
                mean_boundary_alignment=mean(trace.boundary_alignment for trace in traces),
                mean_pairwise_lag_correlation=mean(
                    trace.mean_pairwise_lag_correlation for trace in traces
                ),
                mean_delivery_rate=mean(
                    delivered_count / demand_count if demand_count else 1.0
                    for delivered_count, demand_count in zip(delivered, demand)
                ),
                cleanup_rate=mean(int(trace.cleanup_complete) for trace in traces),
            )
        )
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-per-class", type=int, default=32)
    parser.add_argument("--testing-per-class", type=int, default=24)
    parser.add_argument("--probe-training", type=int, default=40)
    parser.add_argument("--probe-testing", type=int, default=40)
    parser.add_argument("--budget-samples", type=int, default=20)
    parser.add_argument(
        "--classification-output",
        type=Path,
        default=Path("reports/iteration-0014-t3-route-classification.csv"),
    )
    parser.add_argument(
        "--probe-output",
        type=Path,
        default=Path("reports/iteration-0014-t3-active-probing.csv"),
    )
    parser.add_argument(
        "--budget-output",
        type=Path,
        default=Path("reports/iteration-0014-t3-equal-budget.csv"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    classification = run_route_classification_experiment(
        training_per_class=args.training_per_class,
        testing_per_class=args.testing_per_class,
    )
    probing = run_active_probe_experiment(
        training_per_class=args.probe_training,
        testing_per_class=args.probe_testing,
    )
    budget = run_equal_budget_experiment(samples_per_route=args.budget_samples)
    _write_csv(args.classification_output, classification)
    _write_csv(args.probe_output, probing)
    _write_csv(args.budget_output, budget)
    print(f"wrote {args.classification_output}")
    print(f"wrote {args.probe_output}")
    print(f"wrote {args.budget_output}")


if __name__ == "__main__":
    main()
