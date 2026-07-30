# SPDX-License-Identifier: Apache-2.0
"""Deterministic T4 packet-level traffic-analysis evaluation model.

T4 is an evaluation profile layered above T2/T3. It does not add a wire
message or change the adjacent-link scheduler. Instead it converts fixed-size
cell schedules into timestamped packet events and evaluates those events under
clock skew, timestamp quantisation, propagation jitter, shared bottlenecks,
route churn, open-world classification, and bounded selective-delay probes.

The emulator is intentionally small and transparent. It is a falsification
harness, not a replacement for ns-3, Shadow, or deployment measurements.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from collections import deque
import heapq
from math import sqrt
import random
from statistics import mean
from typing import Deque, Iterable, Sequence


PROFILE_NAMES = ("fixed", "adaptive", "hybrid")
MONITORED_ROUTES = (1, 2, 3)
TRAIN_UNKNOWN_ROUTES = (4, 5, 6)
TEST_UNKNOWN_ROUTES = (7, 8, 9, 10)
UNKNOWN_LABEL = -1

# Logical observed links. Additional route classes intentionally reuse links in
# different combinations so that unknown classes are not merely empty traces.
ROUTE_LINKS: dict[int, tuple[int, ...]] = {
    1: (0, 1, 2),
    2: (0, 1, 3),
    3: (0, 2, 3),
    4: (1, 2, 3),
    5: (0, 2),
    6: (1, 3),
    7: (0, 3),
    8: (1, 2),
    9: (0, 1),
    10: (2, 3),
}


@dataclass(frozen=True)
class T4Config:
    epochs: int = 64
    epoch_us: int = 100_000
    links: int = 4
    cell_bytes: int = 1_052
    budget_cells_per_epoch: int = 16
    minimum_cells_per_epoch: int = 8
    maximum_cells_per_epoch: int = 32
    queue_capacity_cells: int = 256
    drain_epochs: int = 6
    base_cross_cells: int = 3
    independent_burst_probability: float = 0.07
    independent_burst_cells: int = 7
    shared_burst_probability: float = 0.10
    shared_burst_cells: int = 9
    target_burst_cells: int = 14
    base_propagation_us: tuple[int, ...] = (8_000, 11_000, 14_000, 17_000)
    propagation_jitter_us: int = 2_000
    relay_processing_us: int = 400
    access_capacity_bps: int = 20_000_000
    bottleneck_capacity_bps: int = 5_000_000
    shared_bottlenecks: bool = True
    clock_skew_ppm: int = 60
    clock_offset_us: int = 30_000
    clock_noise_us: int = 80
    timestamp_quantum_us: int = 100
    selective_delay_us: int = 32_000
    probe_period_epochs: int = 10
    probe_width_epochs: int = 2
    observed_links: tuple[int, ...] = (0, 1, 2, 3)
    seed: int = 1

    def validate(self) -> None:
        if self.epochs < 24:
            raise ValueError("epochs must be at least 24")
        if self.links != 4:
            raise ValueError("the reference topology has four observed links")
        if self.epoch_us <= 0:
            raise ValueError("epoch duration must be positive")
        if self.cell_bytes <= 0:
            raise ValueError("cell size must be positive")
        if not 0 < self.minimum_cells_per_epoch <= self.budget_cells_per_epoch:
            raise ValueError("invalid minimum schedule")
        if self.budget_cells_per_epoch > self.maximum_cells_per_epoch:
            raise ValueError("budget exceeds maximum schedule")
        if self.queue_capacity_cells < self.maximum_cells_per_epoch:
            raise ValueError("queue capacity is too small")
        if not 2 <= self.drain_epochs < self.epochs // 2:
            raise ValueError("invalid drain tail")
        if len(self.base_propagation_us) != self.links:
            raise ValueError("one propagation delay is required per link")
        if any(value < 0 for value in self.base_propagation_us):
            raise ValueError("propagation delay cannot be negative")
        for name in (
            "propagation_jitter_us",
            "relay_processing_us",
            "clock_skew_ppm",
            "clock_offset_us",
            "clock_noise_us",
            "timestamp_quantum_us",
            "selective_delay_us",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.access_capacity_bps <= 0 or self.bottleneck_capacity_bps <= 0:
            raise ValueError("link capacity must be positive")
        if self.probe_period_epochs < 4:
            raise ValueError("probe period is too short")
        if not 1 <= self.probe_width_epochs < self.probe_period_epochs:
            raise ValueError("invalid probe width")
        if len(set(self.observed_links)) != len(self.observed_links):
            raise ValueError("observed links must be unique")
        if any(link < 0 or link >= self.links for link in self.observed_links):
            raise ValueError("invalid observed link")
        for name in ("independent_burst_probability", "shared_burst_probability"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]")


@dataclass(frozen=True)
class CellObservation:
    link: int
    sequence: int
    observed_time_us: int


@dataclass(frozen=True)
class T4Trace:
    profile: str
    route_label: int
    churn_route_label: int | None
    churn_epoch: int | None
    observations: tuple[tuple[CellObservation, ...], ...]
    schedule_cells: tuple[tuple[int, ...], ...]
    demand_cells: tuple[tuple[int, ...], ...]
    delivered_target_cells: int
    generated_target_cells: int
    delivered_background_cells: int
    dropped_cells: int
    expired_cells: int
    chaff_cells: int
    total_public_cells: int
    expected_public_cells: int
    mean_network_delay_us: float
    p95_network_delay_us: float
    peak_queue_cells: int
    cleanup_complete: bool
    selective_delay_enabled: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class OpenWorldResult:
    accuracy: float
    macro_f1: float
    monitored_true_positive_rate: float
    unknown_false_positive_rate: float
    monitored_precision: float
    threshold: float
    confusion: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class ProbeDetectionResult:
    accuracy: float
    true_positive_rate: float
    false_positive_rate: float
    absent_mean_score: float
    present_mean_score: float
    threshold: float


@dataclass
class _Token:
    kind: str
    path: tuple[int, ...] = ()
    hop: int = 0
    source_epoch: int = 0


@dataclass
class _LinkState:
    ready: Deque[_Token]
    remaining_budget: int
    previous_rate: int
    high_streak: int = 0
    low_streak: int = 0
    sequence: int = 0


@dataclass(frozen=True)
class _Clock:
    skew: float
    offset_us: int
    noise_us: int
    quantum_us: int

    def observe(self, true_time_us: int, rng: random.Random) -> int:
        noise = rng.randint(-self.noise_us, self.noise_us) if self.noise_us else 0
        value = true_time_us * (1.0 + self.skew) + self.offset_us + noise
        if self.quantum_us:
            return int(round(value / self.quantum_us) * self.quantum_us)
        return int(round(value))


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def _percentile(values: Sequence[int | float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    index = int(round((len(ordered) - 1) * fraction))
    return ordered[index]


def _target_signal(config: T4Config, rng: random.Random) -> list[int]:
    signal = [0] * config.epochs
    active_limit = config.epochs - config.drain_epochs
    for block_start in range(0, active_limit, 12):
        offset = rng.randint(1, 5)
        width = rng.randint(2, 4)
        amplitude = max(2, config.target_burst_cells + rng.randint(-2, 2))
        for epoch in range(block_start + offset, min(active_limit, block_start + offset + width)):
            signal[epoch] += amplitude
        tail = block_start + offset + width
        if tail < active_limit:
            signal[tail] += max(1, amplitude // 3)
    return signal


def probe_pattern(config: T4Config, seed: int) -> tuple[int, ...]:
    rng = random.Random(seed ^ 0x54345F50524F4245)
    pattern = [0] * config.epochs
    active_limit = config.epochs - config.drain_epochs
    for start in range(0, active_limit, config.probe_period_epochs):
        available = min(config.probe_period_epochs - config.probe_width_epochs, active_limit - start)
        if available <= 0:
            continue
        offset = rng.randrange(available)
        for width in range(config.probe_width_epochs):
            if start + offset + width < active_limit:
                pattern[start + offset + width] = 1
    return tuple(pattern)


def _cross_counts(config: T4Config, rng: random.Random) -> list[list[int]]:
    counts = [[0] * config.epochs for _ in range(config.links)]
    active_limit = config.epochs - config.drain_epochs
    shared = [0] * config.epochs
    for epoch in range(active_limit):
        if rng.random() < config.shared_burst_probability:
            width = rng.randint(2, 4)
            for target in range(epoch, min(active_limit, epoch + width)):
                shared[target] += max(1, config.shared_burst_cells + rng.randint(-2, 2))
    for link in range(config.links):
        for epoch in range(active_limit):
            counts[link][epoch] = rng.randint(
                max(0, config.base_cross_cells - 1), config.base_cross_cells + 1
            ) + shared[epoch]
            if rng.random() < config.independent_burst_probability:
                counts[link][epoch] += max(
                    1, config.independent_burst_cells + rng.randint(-2, 2)
                )
    return counts


def _active_path(
    route_label: int,
    source_epoch: int,
    churn_route_label: int | None,
    churn_epoch: int | None,
) -> tuple[int, ...]:
    if churn_route_label is not None and churn_epoch is not None and source_epoch >= churn_epoch:
        return ROUTE_LINKS[churn_route_label]
    return ROUTE_LINKS[route_label]


def _raw_rate(profile: str, state: _LinkState, queue_pressure: int, rng: random.Random, config: T4Config) -> int:
    if profile == "fixed":
        return config.budget_cells_per_epoch
    menu = tuple(
        sorted(
            set(
                (
                    config.minimum_cells_per_epoch,
                    max(config.minimum_cells_per_epoch, config.budget_cells_per_epoch // 2),
                    config.budget_cells_per_epoch,
                    min(config.maximum_cells_per_epoch, config.budget_cells_per_epoch * 2),
                    config.maximum_cells_per_epoch,
                )
            )
        )
    )
    target = next((rate for rate in menu if rate >= queue_pressure), menu[-1])
    previous = state.previous_rate
    if target > previous:
        state.high_streak += 1
        state.low_streak = 0
        adaptive = target if state.high_streak >= 2 else previous
    elif target < previous:
        state.low_streak += 1
        state.high_streak = 0
        adaptive = target if state.low_streak >= 3 else previous
    else:
        state.high_streak = 0
        state.low_streak = 0
        adaptive = previous
    adaptive = _clamp(adaptive, config.minimum_cells_per_epoch, config.maximum_cells_per_epoch)
    if profile == "adaptive":
        return adaptive
    if profile == "hybrid":
        delta = adaptive - config.budget_cells_per_epoch
        response = int(round(delta / 3.0))
        decoy = rng.choice((-2, -1, 0, 0, 0, 1, 2))
        return _clamp(
            config.budget_cells_per_epoch + response + decoy,
            config.minimum_cells_per_epoch,
            config.maximum_cells_per_epoch,
        )
    raise ValueError("unknown profile")


def _budgeted_rate(raw: int, state: _LinkState, epochs_remaining: int, config: T4Config) -> int:
    minimum_now = max(
        config.minimum_cells_per_epoch,
        state.remaining_budget - config.maximum_cells_per_epoch * (epochs_remaining - 1),
    )
    maximum_now = min(
        config.maximum_cells_per_epoch,
        state.remaining_budget - config.minimum_cells_per_epoch * (epochs_remaining - 1),
    )
    if minimum_now > maximum_now:
        raise RuntimeError("infeasible remaining schedule budget")
    chosen = _clamp(raw, minimum_now, maximum_now)
    state.remaining_budget -= chosen
    state.previous_rate = chosen
    return chosen


def _slot_times(profile: str, epoch: int, count: int, link: int, rng: random.Random, config: T4Config) -> list[int]:
    start = epoch * config.epoch_us
    if count <= 0:
        return []
    spacing = config.epoch_us / count
    if profile == "hybrid":
        phase = rng.uniform(0.0, spacing)
    else:
        phase = 0.5 * spacing
    result = []
    for index in range(count):
        jitter = 0
        if profile == "hybrid":
            jitter = rng.randint(-max(1, int(spacing * 0.18)), max(1, int(spacing * 0.18)))
        value = start + phase + index * spacing + jitter
        value = max(start, min(start + config.epoch_us - 1, value))
        result.append(int(value))
    result.sort()
    return result


def _enqueue(state: _LinkState, token: _Token, config: T4Config) -> bool:
    if len(state.ready) >= config.queue_capacity_cells:
        return False
    state.ready.append(token)
    return True


def simulate_t4_trace(
    route_label: int,
    *,
    profile: str,
    config: T4Config,
    churn_route_label: int | None = None,
    churn_epoch: int | None = None,
    selective_delay: bool = False,
    probe_workload: bool = False,
) -> T4Trace:
    """Run one deterministic packet-level trace.

    The same exact public cell budget is consumed on every logical link. Real
    target work is re-queued at each relay and therefore does not preserve a
    link-local cell identifier across hops.
    """

    config.validate()
    if profile not in PROFILE_NAMES:
        raise ValueError("unknown profile")
    if route_label not in ROUTE_LINKS:
        raise ValueError("unknown route")
    if churn_route_label is not None and churn_route_label not in ROUTE_LINKS:
        raise ValueError("unknown churn route")
    if (churn_route_label is None) != (churn_epoch is None):
        raise ValueError("churn route and epoch must be supplied together")
    if churn_epoch is not None and not 1 <= churn_epoch < config.epochs - config.drain_epochs:
        raise ValueError("invalid churn epoch")

    rng = random.Random(config.seed)
    cross = _cross_counts(config, rng)
    target = _target_signal(config, rng)
    if probe_workload:
        active_limit = config.epochs - config.drain_epochs
        target = [max(value, 6) if index < active_limit else 0 for index, value in enumerate(target)]
    probe = probe_pattern(config, config.seed + route_label)

    clocks: list[_Clock] = []
    clock_rngs: list[random.Random] = []
    for link in range(config.links):
        clock_rng = random.Random(config.seed ^ (0xC10C_0000 + link * 65_537))
        skew_ppm = clock_rng.randint(-config.clock_skew_ppm, config.clock_skew_ppm)
        offset = clock_rng.randint(-config.clock_offset_us, config.clock_offset_us)
        clocks.append(
            _Clock(
                skew=skew_ppm * 1e-6,
                offset_us=offset,
                noise_us=config.clock_noise_us,
                quantum_us=config.timestamp_quantum_us,
            )
        )
        clock_rngs.append(clock_rng)

    total_budget = config.epochs * config.budget_cells_per_epoch
    states = [
        _LinkState(
            ready=deque(),
            remaining_budget=total_budget,
            previous_rate=config.budget_cells_per_epoch,
        )
        for _ in range(config.links)
    ]
    schedule = [[0] * config.epochs for _ in range(config.links)]
    demand = [[0] * config.epochs for _ in range(config.links)]
    observations: list[list[CellObservation]] = [[] for _ in range(config.links)]
    bottleneck_next_free: dict[int, int] = {index: 0 for index in range(2 + config.links)}
    network_delays: list[int] = []

    # (time, priority, serial, event kind, payload)
    events: list[tuple[int, int, int, str, tuple[object, ...]]] = []
    serial = 0

    def push(time_us: int, priority: int, kind: str, *payload: object) -> None:
        nonlocal serial
        heapq.heappush(events, (time_us, priority, serial, kind, payload))
        serial += 1

    # Epoch boundaries select the next link-local schedule. Exogenous arrivals
    # use priority zero and are therefore visible to a boundary at the same time.
    for epoch in range(config.epochs):
        push(epoch * config.epoch_us, 1, "epoch", epoch)
        if epoch >= config.epochs - config.drain_epochs:
            continue
        epoch_start = epoch * config.epoch_us
        for link in range(config.links):
            for _ in range(cross[link][epoch]):
                arrival = epoch_start + rng.randrange(config.epoch_us)
                push(arrival, 0, "arrival", link, _Token("background", source_epoch=epoch))
                demand[link][epoch] += 1
        path = _active_path(route_label, epoch, churn_route_label, churn_epoch)
        if path:
            for _ in range(target[epoch]):
                arrival = epoch_start + rng.randrange(config.epoch_us)
                push(arrival, 0, "arrival", path[0], _Token("target", path=path, hop=0, source_epoch=epoch))
                demand[path[0]][epoch] += 1

    generated_target = sum(target[: config.epochs - config.drain_epochs])
    delivered_target = 0
    delivered_background = 0
    dropped = 0
    expired = 0
    chaff = 0
    peak_queue = 0

    serialization_access = max(1, int(round(config.cell_bytes * 8 * 1_000_000 / config.access_capacity_bps)))
    serialization_bottleneck = max(
        1, int(round(config.cell_bytes * 8 * 1_000_000 / config.bottleneck_capacity_bps))
    )

    while events:
        time_us, _priority, _serial, kind, payload = heapq.heappop(events)
        if kind == "arrival":
            link, token = payload
            assert isinstance(link, int) and isinstance(token, _Token)
            if not _enqueue(states[link], token, config):
                dropped += 1
            peak_queue = max(peak_queue, len(states[link].ready))
            continue

        if kind == "epoch":
            (epoch_obj,) = payload
            epoch = int(epoch_obj)
            epochs_remaining = config.epochs - epoch
            for link in range(config.links):
                pressure = len(states[link].ready) + cross[link][epoch]
                raw = _raw_rate(profile, states[link], pressure, rng, config)
                count = _budgeted_rate(raw, states[link], epochs_remaining, config)
                schedule[link][epoch] = count
                for slot_time in _slot_times(profile, epoch, count, link, rng, config):
                    push(slot_time, 2, "slot", link, epoch)
            continue

        if kind == "slot":
            link_obj, epoch_obj = payload
            link = int(link_obj)
            epoch = int(epoch_obj)
            state = states[link]
            token = state.ready.popleft() if state.ready else _Token("chaff", source_epoch=epoch)
            if token.kind == "chaff":
                chaff += 1
            actual_send = time_us
            if (
                selective_delay
                and token.kind == "target"
                and token.hop == 0
                and probe[token.source_epoch]
            ):
                actual_send += config.selective_delay_us
            push(actual_send, 3, "send", link, token)
            continue

        if kind == "send":
            link_obj, token_obj = payload
            link = int(link_obj)
            token = token_obj
            assert isinstance(token, _Token)
            jitter_in = rng.randint(-config.propagation_jitter_us, config.propagation_jitter_us) if config.propagation_jitter_us else 0
            ready = max(time_us, time_us + serialization_access + jitter_in)
            if config.shared_bottlenecks:
                group = 0 if link in (0, 1) else 1
            else:
                group = 2 + link
            start = max(ready, bottleneck_next_free[group])
            finish = start + serialization_bottleneck
            bottleneck_next_free[group] = finish
            jitter_out = rng.randint(-config.propagation_jitter_us, config.propagation_jitter_us) if config.propagation_jitter_us else 0
            arrival = max(finish, finish + config.base_propagation_us[link] + jitter_out)
            network_delays.append(arrival - time_us)
            state = states[link]
            sequence = state.sequence
            state.sequence += 1
            observed = clocks[link].observe(arrival, clock_rngs[link])
            observations[link].append(CellObservation(link, sequence, observed))

            if token.kind == "target":
                if token.hop + 1 < len(token.path):
                    next_hop = token.hop + 1
                    next_link = token.path[next_hop]
                    next_token = _Token(
                        "target",
                        path=token.path,
                        hop=next_hop,
                        source_epoch=token.source_epoch,
                    )
                    push(arrival + config.relay_processing_us, 0, "arrival", next_link, next_token)
                    target_epoch = min(config.epochs - 1, (arrival + config.relay_processing_us) // config.epoch_us)
                    demand[next_link][target_epoch] += 1
                else:
                    delivered_target += 1
            elif token.kind == "background":
                delivered_background += 1
            continue

        raise RuntimeError(f"unknown event kind {kind}")

    # Finite lifetime: all queues and delayed state are reclaimed at the end of
    # the declared observation window. This does not count as delivery.
    for state in states:
        expired += len(state.ready)
        state.ready.clear()
    cleanup = all(not state.ready and state.remaining_budget == 0 for state in states)
    public_total = sum(sum(row) for row in schedule)
    expected = config.links * total_budget

    selected_observations = []
    for link in range(config.links):
        if link in config.observed_links:
            selected_observations.append(tuple(observations[link]))
        else:
            selected_observations.append(tuple())

    return T4Trace(
        profile=profile,
        route_label=route_label,
        churn_route_label=churn_route_label,
        churn_epoch=churn_epoch,
        observations=tuple(selected_observations),
        schedule_cells=tuple(tuple(row) for row in schedule),
        demand_cells=tuple(tuple(row) for row in demand),
        delivered_target_cells=delivered_target,
        generated_target_cells=generated_target,
        delivered_background_cells=delivered_background,
        dropped_cells=dropped,
        expired_cells=expired,
        chaff_cells=chaff,
        total_public_cells=public_total,
        expected_public_cells=expected,
        mean_network_delay_us=mean(network_delays) if network_delays else 0.0,
        p95_network_delay_us=_percentile(network_delays, 0.95),
        peak_queue_cells=peak_queue,
        cleanup_complete=cleanup,
        selective_delay_enabled=selective_delay,
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


def _binned_timestamps(observations: Sequence[CellObservation], bins: int) -> list[float]:
    if bins < 1:
        raise ValueError("bins must be positive")
    if not observations:
        return [0.0] * bins
    times = [item.observed_time_us for item in observations]
    start = times[0]
    end = max(start + 1, times[-1])
    result = [0.0] * bins
    for value in times:
        index = min(bins - 1, int((value - start) * bins / (end - start + 1)))
        result[index] += 1.0
    return result


def _interarrival_features(observations: Sequence[CellObservation]) -> list[float]:
    if len(observations) < 2:
        return [0.0] * 8
    gaps = [
        observations[index].observed_time_us - observations[index - 1].observed_time_us
        for index in range(1, len(observations))
    ]
    gap_mean = mean(gaps)
    variance = mean((value - gap_mean) ** 2 for value in gaps)
    return [
        gap_mean,
        sqrt(variance),
        _percentile(gaps, 0.10),
        _percentile(gaps, 0.50),
        _percentile(gaps, 0.90),
        _percentile(gaps, 0.99),
        sum(value > 2 * gap_mean for value in gaps) / len(gaps) if gap_mean else 0.0,
        (sqrt(variance) / gap_mean) if gap_mean else 0.0,
    ]


def trace_features(trace: T4Trace, *, bins: int = 24) -> tuple[float, ...]:
    """Extract transparent packet-level features from public observations."""

    features: list[float] = []
    binned: list[list[float]] = []
    for link_observations in trace.observations:
        counts = _binned_timestamps(link_observations, bins)
        binned.append(counts)
        features.extend(counts)
        differences = [0.0] + [counts[index] - counts[index - 1] for index in range(1, bins)]
        features.extend(differences)
        features.extend(_interarrival_features(link_observations))
        features.append(float(len(link_observations)))
    for left in range(len(binned)):
        for right in range(left + 1, len(binned)):
            for lag in range(0, 5):
                if lag == 0:
                    a, b = binned[left], binned[right]
                else:
                    a, b = binned[left][:-lag], binned[right][lag:]
                features.append(pearson_correlation(a, b))
    return tuple(features)


def _fit_standardizer(rows: Sequence[Sequence[float]]) -> tuple[list[float], list[float]]:
    if not rows:
        raise ValueError("feature rows cannot be empty")
    width = len(rows[0])
    means: list[float] = []
    scales: list[float] = []
    for column in range(width):
        values = [row[column] for row in rows]
        column_mean = mean(values)
        variance = mean((value - column_mean) ** 2 for value in values)
        means.append(column_mean)
        scales.append(sqrt(variance) if variance > 1e-12 else 1.0)
    return means, scales


def _transform(rows: Sequence[Sequence[float]], means: Sequence[float], scales: Sequence[float]) -> list[list[float]]:
    return [
        [(value - means[index]) / scales[index] for index, value in enumerate(row)]
        for row in rows
    ]


def _centroids(
    labels_and_rows: Sequence[tuple[int, Sequence[float]]],
    labels: Sequence[int],
) -> dict[int, list[float]]:
    width = len(labels_and_rows[0][1])
    result: dict[int, list[float]] = {}
    for label in labels:
        rows = [row for sample_label, row in labels_and_rows if sample_label == label]
        if not rows:
            raise ValueError("each monitored label requires training rows")
        result[label] = [mean(row[index] for row in rows) for index in range(width)]
    return result


def _nearest(row: Sequence[float], centroids: dict[int, Sequence[float]]) -> tuple[float, int]:
    distances = []
    for label, centroid in centroids.items():
        distance = sqrt(sum((value - centroid[index]) ** 2 for index, value in enumerate(row)))
        distances.append((distance, label))
    return min(distances)


def _macro_f1(confusion: Sequence[Sequence[int]]) -> float:
    values = []
    for index in range(len(confusion)):
        tp = confusion[index][index]
        fp = sum(confusion[row][index] for row in range(len(confusion)) if row != index)
        fn = sum(confusion[index][column] for column in range(len(confusion)) if column != index)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        values.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    return mean(values)


def open_world_classifier(
    training: Sequence[tuple[int, Sequence[float]]],
    calibration: Sequence[tuple[int, Sequence[float]]],
    testing: Sequence[tuple[int, Sequence[float]]],
    *,
    monitored_labels: Sequence[int] = MONITORED_ROUTES,
) -> OpenWorldResult:
    if not training or not calibration or not testing:
        raise ValueError("training, calibration, and testing are required")
    means, scales = _fit_standardizer([features for _, features in training])
    train_scaled = _transform([features for _, features in training], means, scales)
    calibration_scaled = _transform([features for _, features in calibration], means, scales)
    testing_scaled = _transform([features for _, features in testing], means, scales)
    centroid_input = [
        (label, row) for (label, _features), row in zip(training, train_scaled) if label in monitored_labels
    ]
    centers = _centroids(centroid_input, monitored_labels)

    calibration_distances = [
        (_nearest(row, centers)[0], label in monitored_labels)
        for (label, _features), row in zip(calibration, calibration_scaled)
    ]
    candidates = sorted({distance for distance, _ in calibration_distances})
    if not candidates:
        raise ValueError("no calibration candidates")
    best_threshold = candidates[0]
    best_score = -1.0
    for threshold in candidates:
        tp = sum(distance <= threshold and is_monitored for distance, is_monitored in calibration_distances)
        fn = sum(distance > threshold and is_monitored for distance, is_monitored in calibration_distances)
        fp = sum(distance <= threshold and not is_monitored for distance, is_monitored in calibration_distances)
        tn = sum(distance > threshold and not is_monitored for distance, is_monitored in calibration_distances)
        tpr = tp / (tp + fn) if tp + fn else 0.0
        tnr = tn / (tn + fp) if tn + fp else 0.0
        score = 0.5 * (tpr + tnr)
        if score > best_score or (score == best_score and threshold < best_threshold):
            best_score = score
            best_threshold = threshold

    labels = tuple(monitored_labels) + (UNKNOWN_LABEL,)
    index = {label: position for position, label in enumerate(labels)}
    confusion = [[0 for _ in labels] for _ in labels]
    monitored_total = 0
    monitored_correct = 0
    unknown_total = 0
    unknown_false_positive = 0
    monitored_predictions = 0
    correct_monitored_predictions = 0
    correct = 0
    for (actual_label, _features), row in zip(testing, testing_scaled):
        distance, nearest_label = _nearest(row, centers)
        predicted = nearest_label if distance <= best_threshold else UNKNOWN_LABEL
        actual = actual_label if actual_label in monitored_labels else UNKNOWN_LABEL
        confusion[index[actual]][index[predicted]] += 1
        correct += int(actual == predicted)
        if actual in monitored_labels:
            monitored_total += 1
            monitored_correct += int(predicted == actual)
        else:
            unknown_total += 1
            unknown_false_positive += int(predicted != UNKNOWN_LABEL)
        if predicted in monitored_labels:
            monitored_predictions += 1
            correct_monitored_predictions += int(predicted == actual)

    return OpenWorldResult(
        accuracy=correct / len(testing),
        macro_f1=_macro_f1(confusion),
        monitored_true_positive_rate=monitored_correct / monitored_total if monitored_total else 0.0,
        unknown_false_positive_rate=unknown_false_positive / unknown_total if unknown_total else 0.0,
        monitored_precision=(
            correct_monitored_predictions / monitored_predictions if monitored_predictions else 0.0
        ),
        threshold=best_threshold,
        confusion=tuple(tuple(row) for row in confusion),
    )


def open_world_dataset(
    *,
    profile: str,
    config: T4Config,
    training_per_monitored: int,
    calibration_per_route: int,
    testing_per_monitored: int,
    testing_per_unknown_route: int,
    churn: bool = False,
) -> tuple[
    list[tuple[int, tuple[float, ...]]],
    list[tuple[int, tuple[float, ...]]],
    list[tuple[int, tuple[float, ...]]],
    list[T4Trace],
]:
    training: list[tuple[int, tuple[float, ...]]] = []
    calibration: list[tuple[int, tuple[float, ...]]] = []
    testing: list[tuple[int, tuple[float, ...]]] = []
    traces: list[T4Trace] = []

    def make_trace(route: int, sample: int, phase: int, *, unknown_test: bool = False) -> T4Trace:
        seed = config.seed + sample * 1009 + phase * 10_000_019
        sample_config = T4Config(**{**asdict(config), "seed": seed})
        churn_route = None
        churn_epoch = None
        if churn:
            alternatives = [value for value in ROUTE_LINKS if value != route]
            churn_route = alternatives[(sample + route) % len(alternatives)]
            churn_epoch = config.epochs // 2 + ((sample % 5) - 2)
        return simulate_t4_trace(
            route,
            profile=profile,
            config=sample_config,
            churn_route_label=churn_route,
            churn_epoch=churn_epoch,
        )

    for route in MONITORED_ROUTES:
        for sample in range(training_per_monitored):
            trace = make_trace(route, sample, 1)
            traces.append(trace)
            training.append((route, trace_features(trace)))
        for sample in range(calibration_per_route):
            trace = make_trace(route, sample, 2)
            traces.append(trace)
            calibration.append((route, trace_features(trace)))
        for sample in range(testing_per_monitored):
            trace = make_trace(route, sample, 3)
            traces.append(trace)
            testing.append((route, trace_features(trace)))

    for route in TRAIN_UNKNOWN_ROUTES:
        for sample in range(max(1, training_per_monitored // len(TRAIN_UNKNOWN_ROUTES))):
            trace = make_trace(route, sample, 4)
            traces.append(trace)
            training.append((UNKNOWN_LABEL, trace_features(trace)))
        for sample in range(calibration_per_route):
            trace = make_trace(route, sample, 5)
            traces.append(trace)
            calibration.append((UNKNOWN_LABEL, trace_features(trace)))

    for route in TEST_UNKNOWN_ROUTES:
        for sample in range(testing_per_unknown_route):
            trace = make_trace(route, sample, 6, unknown_test=True)
            traces.append(trace)
            testing.append((UNKNOWN_LABEL, trace_features(trace)))

    return training, calibration, testing, traces


def _probe_score(trace: T4Trace, config: T4Config, route_label: int) -> float:
    """Score a known delay pattern after bounded clock-phase search.

    The detector does not use semantic cell labels. It bins downstream public
    timestamps using the known epoch duration, searches eight possible local
    clock phases, and evaluates level, edge, and gap-energy correlations over
    bounded path lags. This is still an intentionally transparent upper-bound
    detector rather than a learned attack.
    """

    path = ROUTE_LINKS[route_label]
    if not path:
        return 0.0
    observations = trace.observations[path[-1]]
    if len(observations) < 2:
        return 0.0
    times = [item.observed_time_us for item in observations]
    anchor = times[0]
    pattern = probe_pattern(config, config.seed + route_label)
    best = 0.0
    phase_step = max(1, config.epoch_us // 8)
    for phase in range(0, config.epoch_us, phase_step):
        counts = [0.0] * config.epochs
        gap_energy = [0.0] * config.epochs
        previous = None
        for value in times:
            index = int((value - anchor + phase) // config.epoch_us)
            if 0 <= index < config.epochs:
                counts[index] += 1.0
                if previous is not None:
                    gap_energy[index] += max(0.0, value - previous)
            previous = value
        edges = [0.0] + [counts[index] - counts[index - 1] for index in range(1, config.epochs)]
        deficits = [max(0.0, counts[index - 1] - counts[index]) if index else 0.0 for index in range(config.epochs)]
        for lag in range(0, len(path) + 7):
            if lag == 0:
                probe_values = pattern
                series = (counts, edges, deficits, gap_energy)
            else:
                probe_values = pattern[:-lag]
                series = (counts[lag:], edges[lag:], deficits[lag:], gap_energy[lag:])
            for values in series:
                best = max(best, abs(pearson_correlation(probe_values, values)))
    return best


def selective_delay_detection(
    *,
    profile: str,
    config: T4Config,
    route_label: int = 1,
    training_per_class: int = 16,
    testing_per_class: int = 16,
    churn: bool = False,
) -> ProbeDetectionResult:
    absent_train: list[float] = []
    present_train: list[float] = []
    absent_test: list[float] = []
    present_test: list[float] = []
    for enabled in (False, True):
        for sample in range(training_per_class + testing_per_class):
            sample_config = T4Config(
                **{
                    **asdict(config),
                    "seed": config.seed + int(enabled) * 1_000_003 + sample * 1013,
                }
            )
            churn_route = 2 if churn else None
            churn_epoch = config.epochs // 2 if churn else None
            trace = simulate_t4_trace(
                route_label,
                profile=profile,
                config=sample_config,
                churn_route_label=churn_route,
                churn_epoch=churn_epoch,
                selective_delay=enabled,
                probe_workload=True,
            )
            score = _probe_score(trace, sample_config, route_label)
            if sample < training_per_class:
                (present_train if enabled else absent_train).append(score)
            else:
                (present_test if enabled else absent_test).append(score)
    threshold = (mean(absent_train) + mean(present_train)) / 2.0
    tp = sum(value > threshold for value in present_test)
    fp = sum(value > threshold for value in absent_test)
    tn = len(absent_test) - fp
    return ProbeDetectionResult(
        accuracy=(tp + tn) / (len(present_test) + len(absent_test)),
        true_positive_rate=tp / len(present_test),
        false_positive_rate=fp / len(absent_test),
        absent_mean_score=mean(absent_test),
        present_mean_score=mean(present_test),
        threshold=threshold,
    )
