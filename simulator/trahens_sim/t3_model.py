"""Deterministic T3 multi-link traffic-analysis evaluation model.

T3 is an analysis profile layered above T2.  It does not define a new wire
ciphertext or replace T2's adjacent-link scheduler.  Instead it defines
budget-matched public schedule traces, a reproducible multi-link adversary,
route-level classifiers, correlated cross traffic, and active probing tests.

The model intentionally uses transparent statistical classifiers rather than
claiming equivalence to modern learned attacks.  Its purpose is to reject
privacy claims that fail under simple, reproducible attacks before more costly
packet-level or learned evaluation is attempted.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from math import sqrt
import random
from statistics import mean
from typing import Iterable, Sequence


ROUTE_LINKS: dict[int, tuple[int, ...]] = {
    0: (),
    1: (0, 1, 2),
    2: (0, 1, 3),
    3: (0, 2, 3),
}
PROFILE_NAMES = ("fixed", "adaptive", "hybrid")


@dataclass(frozen=True)
class T3Config:
    epochs: int = 128
    links: int = 4
    slots_per_epoch: int = 8
    budget_cells_per_epoch: int = 40
    minimum_cells_per_epoch: int = 8
    maximum_cells_per_epoch: int = 64
    queue_capacity_cells: int = 512
    base_cross_cells: int = 5
    independent_burst_probability: float = 0.08
    independent_burst_cells: int = 8
    shared_burst_probability: float = 0.12
    shared_burst_cells: int = 12
    target_burst_cells: int = 14
    probe_cells: int = 24
    hybrid_response_numerator: int = 1
    hybrid_response_denominator: int = 3
    hybrid_decoy_probability: float = 0.18
    hybrid_decoy_cells: int = 12
    seed: int = 1

    def validate(self) -> None:
        if self.epochs < 16:
            raise ValueError("epochs must be at least 16")
        if self.links < 4:
            raise ValueError("at least four observable links are required")
        if self.slots_per_epoch < 2:
            raise ValueError("slots_per_epoch must be at least two")
        if not 0 < self.minimum_cells_per_epoch <= self.budget_cells_per_epoch:
            raise ValueError("invalid minimum or budget")
        if self.budget_cells_per_epoch > self.maximum_cells_per_epoch:
            raise ValueError("budget exceeds maximum epoch allocation")
        if self.queue_capacity_cells < self.maximum_cells_per_epoch:
            raise ValueError("queue capacity is too small")
        for name in (
            "base_cross_cells",
            "independent_burst_cells",
            "shared_burst_cells",
            "target_burst_cells",
            "probe_cells",
            "hybrid_decoy_cells",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        for name in (
            "independent_burst_probability",
            "shared_burst_probability",
            "hybrid_decoy_probability",
        ):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between zero and one")
        if self.hybrid_response_denominator < 1:
            raise ValueError("hybrid response denominator must be positive")
        if not 0 <= self.hybrid_response_numerator <= self.hybrid_response_denominator:
            raise ValueError("hybrid response ratio must be in [0, 1]")


@dataclass(frozen=True)
class T3Trace:
    profile: str
    route_label: int
    epochs: int
    public_cells: tuple[tuple[int, ...], ...]
    transition_phases: tuple[tuple[int, ...], ...]
    demand_cells: tuple[tuple[int, ...], ...]
    delivered_cells: int
    dropped_cells: int
    mean_delay_epochs: float
    peak_queue_cells: int
    total_public_cells: int
    expected_public_cells: int
    boundary_alignment: float
    mean_pairwise_lag_correlation: float
    cleanup_complete: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ClassifierResult:
    accuracy: float
    macro_f1: float
    confusion: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class ProbeDetectionResult:
    accuracy: float
    true_positive_rate: float
    false_positive_rate: float
    absent_mean_score: float
    present_mean_score: float
    threshold: float


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def _target_signal(config: T3Config, rng: random.Random) -> list[int]:
    """Generate one route signal shared by every hop before hop delay.

    Each sixteen-epoch block contains one three-to-five epoch burst.  The
    position and width vary per trace so a classifier cannot memorize a single
    fixed template.
    """

    signal = [0] * config.epochs
    for block_start in range(0, config.epochs, 16):
        offset = rng.randint(2, 8)
        width = rng.randint(3, 5)
        amplitude = config.target_burst_cells + rng.randint(-2, 3)
        for epoch in range(block_start + offset, min(config.epochs, block_start + offset + width)):
            signal[epoch] += max(1, amplitude)
        # A smaller tail makes the signal less rectangular and introduces
        # observation-window dependence without relying on payload semantics.
        tail = block_start + offset + width
        if tail < config.epochs:
            signal[tail] += max(1, amplitude // 3)
    return signal


def probe_pattern(epochs: int, seed: int) -> tuple[int, ...]:
    """Return a balanced deterministic binary active-probe pattern."""

    rng = random.Random(seed ^ 0x54524148454E53)
    pattern = [0] * epochs
    # One two-epoch pulse in each twelve-epoch block, with a seed-dependent offset.
    for start in range(0, epochs, 12):
        if start >= epochs:
            break
        offset = rng.randrange(min(8, max(1, epochs - start)))
        pattern[start + offset] = 1
        if start + offset + 1 < epochs:
            pattern[start + offset + 1] = 1
    return tuple(pattern)


def _cross_traffic(
    config: T3Config,
    rng: random.Random,
    *,
    correlated: bool,
) -> list[list[int]]:
    demand = [[0] * config.epochs for _ in range(config.links)]
    shared = [0] * config.epochs
    if correlated:
        for epoch in range(config.epochs):
            if rng.random() < config.shared_burst_probability:
                width = rng.randint(2, 4)
                for target in range(epoch, min(config.epochs, epoch + width)):
                    shared[target] += config.shared_burst_cells + rng.randint(-2, 2)
    for link in range(config.links):
        for epoch in range(config.epochs):
            baseline = rng.randint(max(0, config.base_cross_cells - 2), config.base_cross_cells + 2)
            demand[link][epoch] = baseline + shared[epoch]
            if rng.random() < config.independent_burst_probability:
                demand[link][epoch] += config.independent_burst_cells + rng.randint(-2, 2)
        if not correlated:
            # Independent long bursts retain the same marginal burst rate.
            for epoch in range(config.epochs):
                if rng.random() < config.shared_burst_probability:
                    width = rng.randint(2, 4)
                    for target in range(epoch, min(config.epochs, epoch + width)):
                        demand[link][target] += config.shared_burst_cells + rng.randint(-2, 2)
    # Reserve a short observation tail for deterministic queue reclamation.
    # The tail contains only the low baseline and therefore does not introduce
    # a hidden post-window service period.
    for link in range(config.links):
        for epoch in range(max(0, config.epochs - 4), config.epochs):
            demand[link][epoch] = min(demand[link][epoch], config.base_cross_cells + 2)
    return demand


def generate_demand(
    route_label: int,
    config: T3Config,
    *,
    correlated_cross_traffic: bool,
    active_probe: bool = False,
) -> tuple[tuple[int, ...], ...]:
    config.validate()
    if route_label not in ROUTE_LINKS:
        raise ValueError("unknown route label")
    rng = random.Random(config.seed)
    demand = _cross_traffic(config, rng, correlated=correlated_cross_traffic)
    route = ROUTE_LINKS[route_label]
    if route:
        signal = _target_signal(config, rng)
        probe = probe_pattern(config.epochs, config.seed + route_label) if active_probe else (0,) * config.epochs
        for hop, link in enumerate(route):
            hop_jitter = rng.choice((-1, 0, 0, 0, 1))
            delay = max(0, hop + hop_jitter)
            for epoch, cells in enumerate(signal):
                target = epoch + delay
                if target < config.epochs:
                    demand[link][target] += cells
            for epoch, enabled in enumerate(probe):
                if not enabled:
                    continue
                target = epoch + hop
                if target < config.epochs:
                    demand[link][target] += config.probe_cells
    return tuple(tuple(values) for values in demand)


def _adaptive_raw_schedule(demand: Sequence[int], config: T3Config) -> list[int]:
    rates = (8, 16, 32, 64)
    queue_estimate = 0
    schedule: list[int] = []
    previous = config.minimum_cells_per_epoch
    high_streak = 0
    low_streak = 0
    for value in demand:
        pressure = value + min(queue_estimate, 48)
        target = next((rate for rate in rates if rate >= pressure), rates[-1])
        if target > previous:
            high_streak += 1
            low_streak = 0
            chosen = target if high_streak >= 2 else previous
        elif target < previous:
            low_streak += 1
            high_streak = 0
            chosen = target if low_streak >= 3 else previous
        else:
            high_streak = 0
            low_streak = 0
            chosen = previous
        if chosen > previous:
            chosen = min(chosen, previous * 2)
        elif chosen < previous:
            chosen = max(chosen, previous // 2)
        chosen = _clamp(chosen, config.minimum_cells_per_epoch, config.maximum_cells_per_epoch)
        schedule.append(chosen)
        queue_estimate = max(0, queue_estimate + value - chosen)
        previous = chosen
    return schedule


def _hybrid_raw_schedule(demand: Sequence[int], config: T3Config, rng: random.Random) -> list[int]:
    baseline = max(config.minimum_cells_per_epoch, config.budget_cells_per_epoch - 12)
    smoothed = float(demand[0] if demand else 0)
    schedule: list[int] = []
    decoy_remaining = 0
    for epoch, value in enumerate(demand):
        smoothed = 0.65 * smoothed + 0.35 * value
        response = int(
            smoothed
            * config.hybrid_response_numerator
            / config.hybrid_response_denominator
        )
        if decoy_remaining == 0 and rng.random() < config.hybrid_decoy_probability:
            decoy_remaining = rng.randint(2, 4)
        decoy = config.hybrid_decoy_cells if decoy_remaining > 0 else 0
        if decoy_remaining > 0:
            decoy_remaining -= 1
        # A one-epoch look-back and bounded response smooth abrupt pressure
        # changes.  Independent decoys prevent every uplift from being caused
        # by actual queue pressure.
        raw = baseline + response + decoy
        if epoch > 0:
            raw = (2 * schedule[-1] + raw) // 3
        schedule.append(_clamp(raw, config.minimum_cells_per_epoch, config.maximum_cells_per_epoch))
    return schedule


def _equalize_budget(
    raw: Sequence[int],
    config: T3Config,
    rng: random.Random,
) -> list[int]:
    """Force an exact super-epoch cell budget without changing record size.

    The operation adds or removes only CHAFF capacity.  It is an offline model
    of a precommitted super-epoch envelope, not an online congestion algorithm.
    """

    schedule = [
        _clamp(value, config.minimum_cells_per_epoch, config.maximum_cells_per_epoch)
        for value in raw
    ]
    target = config.budget_cells_per_epoch * len(schedule)
    difference = target - sum(schedule)
    order = list(range(len(schedule)))
    rng.shuffle(order)
    cursor = 0
    guard = len(schedule) * (config.maximum_cells_per_epoch + 1) * 2
    while difference != 0 and guard > 0:
        guard -= 1
        index = order[cursor % len(order)]
        cursor += 1
        if difference > 0 and schedule[index] < config.maximum_cells_per_epoch:
            schedule[index] += 1
            difference -= 1
        elif difference < 0 and schedule[index] > config.minimum_cells_per_epoch:
            schedule[index] -= 1
            difference += 1
    if difference != 0:
        raise ValueError("configured super-epoch budget is infeasible")
    return schedule


def _transition_phases(
    schedule: Sequence[int],
    profile: str,
    config: T3Config,
    rng: random.Random,
) -> list[int]:
    phases = [-1] * len(schedule)
    for epoch in range(1, len(schedule)):
        if schedule[epoch] == schedule[epoch - 1]:
            continue
        if profile == "adaptive":
            phases[epoch] = 0
        elif profile == "hybrid":
            phases[epoch] = rng.randrange(1, config.slots_per_epoch)
        else:
            phases[epoch] = 0
    return phases


def _simulate_queue(demand: Sequence[int], schedule: Sequence[int], capacity: int) -> tuple[int, int, int, int, int, bool]:
    # Queue entries are [creation_epoch, remaining_count].  Delay is
    # accumulated arithmetically rather than materialized once per cell.
    queue: list[list[int]] = []
    queued = 0
    delivered = 0
    dropped = 0
    delay_sum = 0
    delay_count = 0
    peak = 0
    for epoch, (arrivals, service) in enumerate(zip(demand, schedule)):
        admitted = min(arrivals, max(0, capacity - queued))
        dropped += arrivals - admitted
        if admitted:
            queue.append([epoch, admitted])
            queued += admitted
        remaining = service
        while remaining > 0 and queue:
            created, count = queue[0]
            take = min(remaining, count)
            remaining -= take
            count -= take
            queued -= take
            delivered += take
            delay_sum += (epoch - created) * take
            delay_count += take
            if count == 0:
                queue.pop(0)
            else:
                queue[0][1] = count
        peak = max(peak, queued)
    # A super-epoch trace does not silently discard residual queue state.
    cleanup = queued == 0
    return delivered, dropped, delay_sum, delay_count, peak, cleanup


def _lagged_correlation(left: Sequence[int], right: Sequence[int], max_lag: int = 4) -> float:
    best = 0.0
    for lag in range(max_lag + 1):
        if lag == 0:
            a, b = left, right
        else:
            a, b = left[:-lag], right[lag:]
        best = max(best, abs(pearson_correlation(a, b)))
    return best


def simulate_t3_trace(
    route_label: int,
    *,
    profile: str,
    config: T3Config,
    correlated_cross_traffic: bool = True,
    active_probe: bool = False,
) -> T3Trace:
    config.validate()
    if profile not in PROFILE_NAMES:
        raise ValueError("unsupported T3 profile")
    demand = generate_demand(
        route_label,
        config,
        correlated_cross_traffic=correlated_cross_traffic,
        active_probe=active_probe,
    )
    public: list[tuple[int, ...]] = []
    phases: list[tuple[int, ...]] = []
    total_delivered = 0
    total_dropped = 0
    total_delay_sum = 0
    total_delay_count = 0
    peak_queue = 0
    cleanup = True
    for link, link_demand in enumerate(demand):
        rng = random.Random(config.seed + 1009 * (link + 1) + 7919 * (route_label + 1))
        if profile == "fixed":
            raw = [config.budget_cells_per_epoch] * config.epochs
        elif profile == "adaptive":
            raw = _adaptive_raw_schedule(link_demand, config)
        else:
            raw = _hybrid_raw_schedule(link_demand, config, rng)
        schedule = _equalize_budget(raw, config, rng)
        link_phases = _transition_phases(schedule, profile, config, rng)
        delivered, dropped, delay_sum, delay_count, peak, link_cleanup = _simulate_queue(
            link_demand,
            schedule,
            config.queue_capacity_cells,
        )
        public.append(tuple(schedule))
        phases.append(tuple(link_phases))
        total_delivered += delivered
        total_dropped += dropped
        total_delay_sum += delay_sum
        total_delay_count += delay_count
        peak_queue = max(peak_queue, peak)
        cleanup = cleanup and link_cleanup

    transition_count = 0
    boundary_count = 0
    for link_phases in phases:
        for phase in link_phases:
            if phase >= 0:
                transition_count += 1
                if phase == 0:
                    boundary_count += 1
    alignment = boundary_count / transition_count if transition_count else 0.0

    correlations = []
    for left in range(config.links):
        for right in range(left + 1, config.links):
            correlations.append(_lagged_correlation(public[left], public[right]))

    expected = config.links * config.epochs * config.budget_cells_per_epoch
    total_public = sum(sum(link) for link in public)
    return T3Trace(
        profile=profile,
        route_label=route_label,
        epochs=config.epochs,
        public_cells=tuple(public),
        transition_phases=tuple(phases),
        demand_cells=demand,
        delivered_cells=total_delivered,
        dropped_cells=total_dropped,
        mean_delay_epochs=(total_delay_sum / total_delay_count if total_delay_count else 0.0),
        peak_queue_cells=peak_queue,
        total_public_cells=total_public,
        expected_public_cells=expected,
        boundary_alignment=alignment,
        mean_pairwise_lag_correlation=mean(correlations) if correlations else 0.0,
        cleanup_complete=cleanup,
    )


def pearson_correlation(left: Sequence[int | float], right: Sequence[int | float]) -> float:
    if len(left) != len(right):
        raise ValueError("correlation vectors must have equal length")
    if len(left) < 2:
        return 0.0
    left_mean = mean(left)
    right_mean = mean(right)
    left_dev = [float(value) - left_mean for value in left]
    right_dev = [float(value) - right_mean for value in right]
    left_norm = sqrt(sum(value * value for value in left_dev))
    right_norm = sqrt(sum(value * value for value in right_dev))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return sum(a * b for a, b in zip(left_dev, right_dev)) / (left_norm * right_norm)


def _binned(values: Sequence[int], bins: int) -> list[float]:
    if bins < 1:
        raise ValueError("bins must be positive")
    result = []
    for index in range(bins):
        start = index * len(values) // bins
        end = (index + 1) * len(values) // bins
        segment = values[start:end]
        result.append(mean(segment) if segment else 0.0)
    return result


def trace_features(trace: T3Trace, *, bins: int = 16) -> tuple[float, ...]:
    """Extract transparent count, transition, and cross-link features."""

    features: list[float] = []
    for cells, phases in zip(trace.public_cells, trace.transition_phases):
        features.extend(_binned(cells, bins))
        differences = [0] + [cells[index] - cells[index - 1] for index in range(1, len(cells))]
        features.extend(_binned(differences, bins))
        transitions = [phase for phase in phases if phase >= 0]
        features.append(float(len(transitions)))
        features.append(
            sum(1 for phase in transitions if phase == 0) / len(transitions)
            if transitions
            else 0.0
        )
    for left in range(len(trace.public_cells)):
        for right in range(left + 1, len(trace.public_cells)):
            for lag in range(4):
                if lag == 0:
                    a, b = trace.public_cells[left], trace.public_cells[right]
                else:
                    a = trace.public_cells[left][:-lag]
                    b = trace.public_cells[right][lag:]
                features.append(pearson_correlation(a, b))
    return tuple(features)


def _standardize(
    train_features: Sequence[Sequence[float]],
    test_features: Sequence[Sequence[float]],
) -> tuple[list[list[float]], list[list[float]]]:
    if not train_features:
        raise ValueError("training features cannot be empty")
    width = len(train_features[0])
    means = []
    scales = []
    for column in range(width):
        values = [row[column] for row in train_features]
        column_mean = mean(values)
        variance = mean((value - column_mean) ** 2 for value in values)
        means.append(column_mean)
        scales.append(sqrt(variance) if variance > 1e-12 else 1.0)

    def transform(rows: Sequence[Sequence[float]]) -> list[list[float]]:
        return [
            [(value - means[index]) / scales[index] for index, value in enumerate(row)]
            for row in rows
        ]

    return transform(train_features), transform(test_features)


def nearest_centroid_classifier(
    training: Sequence[tuple[int, Sequence[float]]],
    testing: Sequence[tuple[int, Sequence[float]]],
    *,
    labels: Sequence[int] = (0, 1, 2, 3),
) -> ClassifierResult:
    if not training or not testing:
        raise ValueError("training and testing sets must be non-empty")
    train_scaled, test_scaled = _standardize(
        [features for _, features in training],
        [features for _, features in testing],
    )
    width = len(train_scaled[0])
    centroids: dict[int, list[float]] = {}
    for label in labels:
        rows = [row for (sample_label, _), row in zip(training, train_scaled) if sample_label == label]
        if not rows:
            raise ValueError("every label requires training samples")
        centroids[label] = [mean(row[index] for row in rows) for index in range(width)]

    confusion = [[0 for _ in labels] for _ in labels]
    label_index = {label: index for index, label in enumerate(labels)}
    correct = 0
    for (actual, _), row in zip(testing, test_scaled):
        distances = []
        for label in labels:
            distance = sum(
                (value - centroids[label][index]) ** 2
                for index, value in enumerate(row)
            )
            distances.append((distance, label))
        predicted = min(distances)[1]
        confusion[label_index[actual]][label_index[predicted]] += 1
        correct += int(actual == predicted)

    f1_values = []
    for index, _label in enumerate(labels):
        true_positive = confusion[index][index]
        false_positive = sum(confusion[row][index] for row in range(len(labels)) if row != index)
        false_negative = sum(confusion[index][column] for column in range(len(labels)) if column != index)
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
        f1_values.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    return ClassifierResult(
        accuracy=correct / len(testing),
        macro_f1=mean(f1_values),
        confusion=tuple(tuple(row) for row in confusion),
    )


def route_classification_dataset(
    *,
    profile: str,
    config: T3Config,
    correlated_cross_traffic: bool,
    training_per_class: int,
    testing_per_class: int,
) -> tuple[list[tuple[int, tuple[float, ...]]], list[tuple[int, tuple[float, ...]]], list[T3Trace]]:
    training: list[tuple[int, tuple[float, ...]]] = []
    testing: list[tuple[int, tuple[float, ...]]] = []
    traces: list[T3Trace] = []
    for label in ROUTE_LINKS:
        for sample in range(training_per_class + testing_per_class):
            sample_config = T3Config(
                **{
                    **asdict(config),
                    "seed": config.seed + 100_003 * label + 997 * sample,
                }
            )
            trace = simulate_t3_trace(
                label,
                profile=profile,
                config=sample_config,
                correlated_cross_traffic=correlated_cross_traffic,
            )
            traces.append(trace)
            item = (label, trace_features(trace))
            if sample < training_per_class:
                training.append(item)
            else:
                testing.append(item)
    return training, testing, traces


def _probe_score(trace: T3Trace, pattern: Sequence[int], route_label: int) -> float:
    route = ROUTE_LINKS[route_label]
    if not route:
        return 0.0
    observed = trace.public_cells[route[-1]]
    differences = [0] + [max(0, observed[index] - observed[index - 1]) for index in range(1, len(observed))]
    best = 0.0
    for lag in range(0, len(route) + 5):
        if lag == 0:
            left = pattern
            levels = observed
            edges = differences
        else:
            left = pattern[:-lag]
            levels = observed[lag:]
            edges = differences[lag:]
        best = max(
            best,
            abs(pearson_correlation(left, levels)),
            abs(pearson_correlation(left, edges)),
        )
    return best


def active_probe_detection(
    *,
    profile: str,
    config: T3Config,
    route_label: int = 1,
    training_per_class: int = 40,
    testing_per_class: int = 40,
    correlated_cross_traffic: bool = True,
) -> ProbeDetectionResult:
    absent_train: list[float] = []
    present_train: list[float] = []
    absent_test: list[float] = []
    present_test: list[float] = []
    for enabled in (False, True):
        for sample in range(training_per_class + testing_per_class):
            sample_config = T3Config(
                **{
                    **asdict(config),
                    "seed": config.seed + 31_337 * int(enabled) + 1013 * sample,
                }
            )
            trace = simulate_t3_trace(
                route_label,
                profile=profile,
                config=sample_config,
                correlated_cross_traffic=correlated_cross_traffic,
                active_probe=enabled,
            )
            pattern = probe_pattern(sample_config.epochs, sample_config.seed + route_label)
            score = _probe_score(trace, pattern, route_label)
            target = present_train if enabled else absent_train
            if sample >= training_per_class:
                target = present_test if enabled else absent_test
            target.append(score)
    threshold = (mean(absent_train) + mean(present_train)) / 2.0
    true_positive = sum(score > threshold for score in present_test)
    false_positive = sum(score > threshold for score in absent_test)
    true_negative = len(absent_test) - false_positive
    return ProbeDetectionResult(
        accuracy=(true_positive + true_negative) / (len(present_test) + len(absent_test)),
        true_positive_rate=true_positive / len(present_test),
        false_positive_rate=false_positive / len(absent_test),
        absent_mean_score=mean(absent_test),
        present_mean_score=mean(present_test),
        threshold=threshold,
    )
