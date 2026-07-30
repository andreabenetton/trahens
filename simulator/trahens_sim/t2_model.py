"""Deterministic T2 congestion, fairness, and schedule-adaptation model.

T2 extends the T1 fixed-cell transport with finite schedule epochs, a small
public menu of rate classes, bounded one-step transitions, hysteresis, and
weighted deficit round robin among admitted link-local transmissions.  The
model intentionally exposes the selected rate class: cadence is observable on
the link even though the encrypted SCHEDULE cell is not.

This is a protocol-analysis model.  It is not a production congestion
controller and it does not establish traffic-flow unlinkability.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from math import sqrt
import random
from statistics import mean
from typing import Iterable, Sequence

from trahens_codec.m2w2 import CELL_RECORD_BYTES


@dataclass(frozen=True)
class T2Flow:
    flow_id: int
    weight: int
    arrivals: tuple[int, ...]

    def validate(self) -> None:
        if self.flow_id < 0:
            raise ValueError("flow_id must be non-negative")
        if self.weight < 1:
            raise ValueError("flow weight must be positive")
        if any(value < 0 for value in self.arrivals):
            raise ValueError("flow arrivals cannot be negative")


@dataclass(frozen=True)
class T2Config:
    epoch_ms: int = 200
    rate_cells_per_epoch: tuple[int, ...] = (8, 16, 32, 64)
    scheduler_mode: str = "adaptive"  # adaptive | fixed | work-conserving
    initial_rate_class: int = 1
    fixed_rate_class: int = 3
    maximum_rate_class: int = 3
    up_threshold: float = 0.55
    down_threshold: float = 0.10
    up_consecutive_epochs: int = 2
    down_consecutive_epochs: int = 4
    minimum_hold_epochs: int = 2
    queue_capacity_cells: int = 512
    per_flow_capacity_cells: int = 256
    quantum_cells: int = 1
    max_retries: int = 3
    loss_model: str = "independent"  # independent | gilbert-elliott | none
    independent_loss_probability: float = 0.0
    good_loss_probability: float = 0.0
    bad_loss_probability: float = 0.35
    good_to_bad_probability: float = 0.04
    bad_to_good_probability: float = 0.25
    drain_epochs: int = 12
    seed: int = 1

    def validate(self) -> None:
        if self.epoch_ms < 1:
            raise ValueError("epoch_ms must be positive")
        if not self.rate_cells_per_epoch:
            raise ValueError("at least one rate class is required")
        if any(value < 1 for value in self.rate_cells_per_epoch):
            raise ValueError("rate classes must be positive")
        if tuple(sorted(set(self.rate_cells_per_epoch))) != self.rate_cells_per_epoch:
            raise ValueError("rate classes must be strictly increasing")
        last = len(self.rate_cells_per_epoch) - 1
        for name in ("initial_rate_class", "fixed_rate_class", "maximum_rate_class"):
            value = getattr(self, name)
            if not 0 <= value <= last:
                raise ValueError(f"{name} is out of range")
        if self.initial_rate_class > self.maximum_rate_class:
            raise ValueError("initial rate exceeds maximum")
        if self.scheduler_mode not in {"adaptive", "fixed", "work-conserving"}:
            raise ValueError("unsupported scheduler_mode")
        if not 0.0 <= self.down_threshold < self.up_threshold <= 1.0:
            raise ValueError("queue thresholds are inconsistent")
        for name in (
            "up_consecutive_epochs",
            "down_consecutive_epochs",
            "minimum_hold_epochs",
            "queue_capacity_cells",
            "per_flow_capacity_cells",
            "quantum_cells",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")
        if self.per_flow_capacity_cells > self.queue_capacity_cells:
            raise ValueError("per-flow queue exceeds global queue")
        if self.drain_epochs < 0:
            raise ValueError("drain_epochs cannot be negative")
        if self.max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if self.loss_model not in {"none", "independent", "gilbert-elliott"}:
            raise ValueError("unsupported loss model")
        for name in (
            "independent_loss_probability",
            "good_loss_probability",
            "bad_loss_probability",
            "good_to_bad_probability",
            "bad_to_good_probability",
        ):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between zero and one")


@dataclass
class _Cell:
    flow_id: int
    created_epoch: int
    attempts: int = 0


@dataclass
class _FlowState:
    flow: T2Flow
    queue: deque[_Cell] = field(default_factory=deque)
    deficit: int = 0
    admitted: int = 0
    delivered: int = 0
    dropped: int = 0
    retry_exhausted: int = 0
    delays: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class T2Result:
    scheduler_mode: str
    epochs: int
    rate_classes: tuple[int, ...]
    public_cells_by_epoch: tuple[int, ...]
    queue_cells_by_epoch: tuple[int, ...]
    admitted_cells: int
    delivered_cells: int
    dropped_cells: int
    retry_exhaustions: int
    retransmitted_cells: int
    lost_cells: int
    chaff_cells: int
    schedule_control_cells: int
    total_cells: int
    wire_bytes: int
    peak_queue_cells: int
    overload_epochs: int
    rate_changes: int
    mean_delay_epochs: float
    p95_delay_epochs: float
    weighted_fairness: float
    per_flow_delivered: tuple[int, ...]
    per_flow_dropped: tuple[int, ...]
    cleanup_complete: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class _LossProcess:
    def __init__(self, config: T2Config, rng: random.Random) -> None:
        self.config = config
        self.rng = rng
        self.bad = False

    def lost(self) -> bool:
        if self.config.loss_model == "none":
            return False
        if self.config.loss_model == "independent":
            return self.rng.random() < self.config.independent_loss_probability
        # Transition before sampling the current cell.  This convention is
        # deterministic and is recorded in the T2 specification.
        if self.bad:
            if self.rng.random() < self.config.bad_to_good_probability:
                self.bad = False
        elif self.rng.random() < self.config.good_to_bad_probability:
            self.bad = True
        probability = (
            self.config.bad_loss_probability
            if self.bad
            else self.config.good_loss_probability
        )
        return self.rng.random() < probability


class _T2Link:
    def __init__(self, flows: Sequence[T2Flow], config: T2Config) -> None:
        config.validate()
        if not flows:
            raise ValueError("at least one flow is required")
        for flow in flows:
            flow.validate()
        if len({flow.flow_id for flow in flows}) != len(flows):
            raise ValueError("flow identifiers must be unique")
        self.config = config
        self.rng = random.Random(config.seed)
        self.loss = _LossProcess(config, self.rng)
        self.states = {flow.flow_id: _FlowState(flow) for flow in flows}
        self.order = deque(sorted(self.states))
        self.rate_class = (
            config.fixed_rate_class
            if config.scheduler_mode == "fixed"
            else config.initial_rate_class
        )
        self.hold_epochs = config.minimum_hold_epochs
        self.high_streak = 0
        self.low_streak = 0
        self.rate_changes = 0
        self.schedule_control_cells = 0
        self.pending_schedule_controls = 0
        self.retransmitted_cells = 0
        self.lost_cells = 0
        self.chaff_cells = 0
        self.overload_epochs = 0
        self.peak_queue = 0
        self.public_cells: list[int] = []
        self.queue_cells: list[int] = []
        self._rate_history: list[int] = []

    def total_queued(self) -> int:
        return sum(len(state.queue) for state in self.states.values())

    def admit(self, epoch: int) -> None:
        for state in self.states.values():
            count = state.flow.arrivals[epoch] if epoch < len(state.flow.arrivals) else 0
            for _ in range(count):
                if (
                    len(state.queue) >= self.config.per_flow_capacity_cells
                    or self.total_queued() >= self.config.queue_capacity_cells
                ):
                    state.dropped += 1
                    continue
                state.queue.append(_Cell(state.flow.flow_id, epoch))
                state.admitted += 1

    def _next_cell(self) -> _Cell | None:
        # Fixed-size cells use one deficit unit. A flow remains at the head
        # while its current deficit pays for another cell, so weights affect
        # service rather than merely accumulating unused credit.
        if not any(state.queue for state in self.states.values()):
            return None
        visits = 0
        maximum_visits = max(1, len(self.order) * 4)
        while visits < maximum_visits:
            visits += 1
            flow_id = self.order[0]
            state = self.states[flow_id]
            if not state.queue:
                state.deficit = 0
                self.order.rotate(-1)
                continue
            if state.deficit < 1:
                state.deficit += state.flow.weight * self.config.quantum_cells
            if state.deficit < 1:
                self.order.rotate(-1)
                continue
            state.deficit -= 1
            cell = state.queue.popleft()
            if state.deficit < 1 or not state.queue:
                self.order.rotate(-1)
            return cell
        raise AssertionError("DRR failed to select a backlogged flow")

    def _requeue_retry(self, cell: _Cell) -> None:
        state = self.states[cell.flow_id]
        if cell.attempts > self.config.max_retries:
            state.retry_exhausted += 1
            state.dropped += 1
            return
        state.queue.append(cell)

    def _current_slots(self) -> int:
        if self.config.scheduler_mode == "work-conserving":
            return self.total_queued()
        return self.config.rate_cells_per_epoch[self.rate_class]

    def serve_epoch(self, epoch: int) -> int:
        slots = self._current_slots()
        real_attempts = 0
        for _ in range(slots):
            if self.pending_schedule_controls > 0:
                self.pending_schedule_controls -= 1
                self.schedule_control_cells += 1
                continue
            cell = self._next_cell()
            if cell is None:
                if self.config.scheduler_mode != "work-conserving":
                    self.chaff_cells += 1
                continue
            real_attempts += 1
            cell.attempts += 1
            if cell.attempts > 1:
                self.retransmitted_cells += 1
            if self.loss.lost():
                self.lost_cells += 1
                self._requeue_retry(cell)
                continue
            state = self.states[cell.flow_id]
            state.delivered += 1
            state.delays.append(epoch - cell.created_epoch)
        if self.config.scheduler_mode == "work-conserving":
            public = real_attempts
        else:
            public = slots
        self.public_cells.append(public)
        queued = self.total_queued()
        self.queue_cells.append(queued)
        self.peak_queue = max(self.peak_queue, queued)
        service_capacity = max(slots, 1)
        if queued >= service_capacity:
            self.overload_epochs += 1
        return public

    def adapt(self) -> None:
        if self.config.scheduler_mode != "adaptive":
            return
        current_capacity = self.config.rate_cells_per_epoch[self.rate_class]
        occupancy = min(self.total_queued() / max(current_capacity, 1), 1.0)
        if occupancy >= self.config.up_threshold:
            self.high_streak += 1
            self.low_streak = 0
        elif occupancy <= self.config.down_threshold:
            self.low_streak += 1
            self.high_streak = 0
        else:
            self.high_streak = 0
            self.low_streak = 0
        self.hold_epochs += 1
        requested = self.rate_class
        if (
            self.high_streak >= self.config.up_consecutive_epochs
            and self.hold_epochs >= self.config.minimum_hold_epochs
            and self.rate_class < self.config.maximum_rate_class
        ):
            requested = self.rate_class + 1
        elif (
            self.low_streak >= self.config.down_consecutive_epochs
            and self.hold_epochs >= self.config.minimum_hold_epochs
            and self.rate_class > 0
        ):
            requested = self.rate_class - 1
        if requested != self.rate_class:
            # T2 permits only one class step and assumes a matching encrypted
            # OFFER/ACCEPT exchange before the next epoch boundary.
            self.rate_class = requested
            self.rate_changes += 1
            self.pending_schedule_controls += 2
            self.hold_epochs = 0
            self.high_streak = 0
            self.low_streak = 0

    def result(self, epochs: int) -> T2Result:
        delays = [delay for state in self.states.values() for delay in state.delays]
        delivered = [state.delivered for state in self.states.values()]
        normalized = [
            state.delivered / state.flow.weight
            for state in self.states.values()
            if state.admitted > 0
        ]
        fairness = jain_fairness(normalized)
        p95 = percentile(delays, 0.95)
        admitted = sum(state.admitted for state in self.states.values())
        dropped = sum(state.dropped for state in self.states.values())
        total_real_attempts = sum(delivered) + self.lost_cells
        total_cells = total_real_attempts + self.chaff_cells + self.schedule_control_cells
        return T2Result(
            scheduler_mode=self.config.scheduler_mode,
            epochs=epochs,
            rate_classes=tuple(self._rate_history),
            public_cells_by_epoch=tuple(self.public_cells),
            queue_cells_by_epoch=tuple(self.queue_cells),
            admitted_cells=admitted,
            delivered_cells=sum(delivered),
            dropped_cells=dropped,
            retry_exhaustions=sum(state.retry_exhausted for state in self.states.values()),
            retransmitted_cells=self.retransmitted_cells,
            lost_cells=self.lost_cells,
            chaff_cells=self.chaff_cells,
            schedule_control_cells=self.schedule_control_cells,
            total_cells=total_cells,
            wire_bytes=total_cells * CELL_RECORD_BYTES,
            peak_queue_cells=self.peak_queue,
            overload_epochs=self.overload_epochs,
            rate_changes=self.rate_changes,
            mean_delay_epochs=mean(delays) if delays else 0.0,
            p95_delay_epochs=p95,
            weighted_fairness=fairness,
            per_flow_delivered=tuple(delivered),
            per_flow_dropped=tuple(state.dropped for state in self.states.values()),
            cleanup_complete=self.total_queued() == 0,
        )



def percentile(values: Sequence[int | float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * q + 0.999999)))
    return ordered[index]


def jain_fairness(values: Iterable[float]) -> float:
    samples = [float(value) for value in values if value >= 0.0]
    if not samples:
        return 1.0
    denominator = len(samples) * sum(value * value for value in samples)
    if denominator == 0.0:
        return 1.0
    return (sum(samples) ** 2) / denominator


def pearson_correlation(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right):
        raise ValueError("correlation vectors must have equal length")
    if len(left) < 2:
        return 0.0
    left_mean = mean(left)
    right_mean = mean(right)
    left_dev = [value - left_mean for value in left]
    right_dev = [value - right_mean for value in right]
    left_norm = sqrt(sum(value * value for value in left_dev))
    right_norm = sqrt(sum(value * value for value in right_dev))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return sum(a * b for a, b in zip(left_dev, right_dev)) / (left_norm * right_norm)


def simulate_t2_link(flows: Sequence[T2Flow], config: T2Config) -> T2Result:
    link = _T2Link(flows, config)
    link._rate_history = []
    arrival_epochs = max((len(flow.arrivals) for flow in flows), default=0)
    total_epochs = arrival_epochs + config.drain_epochs
    for epoch in range(total_epochs):
        link._rate_history.append(link.rate_class)
        link.admit(epoch)
        link.serve_epoch(epoch)
        link.adapt()
    return link.result(total_epochs)


def stationary_gilbert_elliott_loss(config: T2Config) -> float:
    denominator = config.good_to_bad_probability + config.bad_to_good_probability
    if denominator == 0.0:
        bad_fraction = 0.0
    else:
        bad_fraction = config.good_to_bad_probability / denominator
    return (
        (1.0 - bad_fraction) * config.good_loss_probability
        + bad_fraction * config.bad_loss_probability
    )


def schedule_presence_classifier(result: T2Result, baseline_class: int) -> int:
    """Return one when the public class trace indicates activity.

    This intentionally weak distinguisher observes only whether any epoch uses
    a class above the configured idle baseline.  It demonstrates schedule-
    boundary leakage; it is not a state-of-the-art traffic classifier.
    """

    return int(any(value > baseline_class for value in result.rate_classes))


def simulate_two_link_trace(
    arrivals: Sequence[int],
    *,
    mode: str,
    config: T2Config,
) -> tuple[tuple[int, ...], tuple[int, ...], float]:
    """Simulate public per-epoch cell counts on two serial schedulers.

    The second link receives the first link's successful real-cell count one
    epoch later.  The experiment measures lag-one Pearson correlation of the
    public cell-count sequences.  Constant traces are assigned correlation
    zero because they contain no variance for a timing matcher.
    """

    if mode not in {"adaptive", "fixed", "work-conserving"}:
        raise ValueError("unsupported chain mode")
    first_flow = T2Flow(0, 1, tuple(arrivals))
    first_config = T2Config(**{**asdict(config), "scheduler_mode": mode, "drain_epochs": 0})
    first = _T2Link((first_flow,), first_config)
    first._rate_history = []
    downstream_arrivals: list[int] = [0]
    first_public: list[int] = []
    second_public: list[int] = []

    second_flow = T2Flow(0, 1, tuple())
    second_config = T2Config(
        **{
            **asdict(config),
            "scheduler_mode": mode,
            "seed": config.seed + 1,
            "drain_epochs": 0,
        }
    )
    second = _T2Link((second_flow,), second_config)
    second._rate_history = []

    for epoch, count in enumerate(arrivals):
        first._rate_history.append(first.rate_class)
        # Manual admission keeps the flow object immutable.
        first.states[0].flow = T2Flow(0, 1, (count,))
        first.admit(0)
        before = first.states[0].delivered
        first_public.append(first.serve_epoch(epoch))
        first.adapt()
        delivered_now = first.states[0].delivered - before
        downstream_arrivals.append(delivered_now)

        second._rate_history.append(second.rate_class)
        second.states[0].flow = T2Flow(0, 1, (downstream_arrivals[epoch],))
        second.admit(0)
        second_public.append(second.serve_epoch(epoch))
        second.adapt()

    if len(first_public) > 1:
        correlation = pearson_correlation(first_public[:-1], second_public[1:])
    else:
        correlation = 0.0
    return tuple(first_public), tuple(second_public), correlation
