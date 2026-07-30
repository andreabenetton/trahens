"""Deterministic models for bounded Trahens discovery policies.

The simulator intentionally excludes cryptography and traffic-shaping profiles.
It evaluates graph reachability, first-parent duplicate suppression, resource
budgets, and the cost/linkability trade-off of expanding-ring discovery.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import asdict, dataclass, field
import random
from typing import Iterable, Sequence


class Graph:
    """Simple undirected graph with deterministic neighbor ordering."""

    def __init__(self, node_count: int) -> None:
        if node_count < 2:
            raise ValueError("node_count must be at least 2")
        self._adjacency: list[set[int]] = [set() for _ in range(node_count)]

    @property
    def node_count(self) -> int:
        return len(self._adjacency)

    def add_edge(self, left: int, right: int) -> None:
        self._validate_node(left)
        self._validate_node(right)
        if left == right:
            raise ValueError("self edges are not allowed")
        self._adjacency[left].add(right)
        self._adjacency[right].add(left)

    def neighbors(self, node: int) -> tuple[int, ...]:
        self._validate_node(node)
        return tuple(sorted(self._adjacency[node]))

    def degree(self, node: int) -> int:
        return len(self.neighbors(node))

    def edge_count(self) -> int:
        return sum(len(peers) for peers in self._adjacency) // 2

    def _validate_node(self, node: int) -> None:
        if node < 0 or node >= self.node_count:
            raise ValueError(f"invalid node: {node}")

    @classmethod
    def random_connected(
        cls,
        node_count: int,
        average_degree: float,
        seed: int,
    ) -> "Graph":
        """Build a connected random graph without external dependencies.

        A random spanning tree guarantees connectivity. Additional edges are
        sampled until the requested approximate average degree is reached.
        """

        if average_degree < 2.0:
            raise ValueError("average_degree must be at least 2.0")
        if average_degree > node_count - 1:
            raise ValueError("average_degree cannot exceed node_count - 1")

        rng = random.Random(seed)
        graph = cls(node_count)

        # Random recursive tree.
        order = list(range(node_count))
        rng.shuffle(order)
        for index in range(1, node_count):
            node = order[index]
            parent = order[rng.randrange(index)]
            graph.add_edge(node, parent)

        target_edges = min(
            node_count * (node_count - 1) // 2,
            max(node_count - 1, round(node_count * average_degree / 2)),
        )

        possible = [
            (left, right)
            for left in range(node_count)
            for right in range(left + 1, node_count)
            if right not in graph._adjacency[left]
        ]
        rng.shuffle(possible)
        for left, right in possible:
            if graph.edge_count() >= target_edges:
                break
            graph.add_edge(left, right)

        return graph


@dataclass(frozen=True)
class DiscoveryConfig:
    origin: int = 0
    hop_limit: int = 4
    initial_fanout: int = 4
    relay_fanout: int = 3
    candidate_limit: int = 4
    responder_fraction: float = 0.05
    seed: int = 1
    transmission_budget: int | None = None
    state_budget: int | None = None

    def validate(self, graph: Graph) -> None:
        if self.origin < 0 or self.origin >= graph.node_count:
            raise ValueError("origin is outside the graph")
        if self.hop_limit < 1:
            raise ValueError("hop_limit must be positive")
        if self.initial_fanout < 1:
            raise ValueError("initial_fanout must be positive")
        if self.relay_fanout < 1:
            raise ValueError("relay_fanout must be positive")
        if self.candidate_limit < 1:
            raise ValueError("candidate_limit must be positive")
        if not 0.0 <= self.responder_fraction <= 1.0:
            raise ValueError("responder_fraction must be between 0 and 1")
        if self.transmission_budget is not None and self.transmission_budget < 0:
            raise ValueError("transmission_budget cannot be negative")
        if self.state_budget is not None and self.state_budget < 0:
            raise ValueError("state_budget cannot be negative")


@dataclass(frozen=True)
class RingStep:
    """One expanding-ring attempt policy."""

    hop_limit: int
    initial_fanout: int
    relay_fanout: int

    def validate(self) -> None:
        if self.hop_limit < 1:
            raise ValueError("ring hop_limit must be positive")
        if self.initial_fanout < 1:
            raise ValueError("ring initial_fanout must be positive")
        if self.relay_fanout < 1:
            raise ValueError("ring relay_fanout must be positive")


@dataclass(frozen=True)
class ExpandingRingConfig:
    origin: int = 0
    rings: tuple[RingStep, ...] = (
        RingStep(2, 2, 2),
        RingStep(3, 2, 2),
        RingStep(4, 3, 3),
        RingStep(5, 4, 4),
    )
    candidate_limit: int = 8
    required_candidates: int = 1
    responder_fraction: float = 0.05
    seed: int = 1
    total_transmission_budget: int | None = None
    total_state_allocation_budget: int | None = None

    def validate(self, graph: Graph) -> None:
        if self.origin < 0 or self.origin >= graph.node_count:
            raise ValueError("origin is outside the graph")
        if not self.rings:
            raise ValueError("at least one ring is required")
        previous_hop_limit = 0
        previous_initial_fanout = 0
        previous_relay_fanout = 0
        for ring in self.rings:
            ring.validate()
            if ring.hop_limit < previous_hop_limit:
                raise ValueError("ring hop limits must be non-decreasing")
            if ring.initial_fanout < previous_initial_fanout:
                raise ValueError("ring initial fan-out must be non-decreasing")
            if ring.relay_fanout < previous_relay_fanout:
                raise ValueError("ring relay fan-out must be non-decreasing")
            previous_hop_limit = ring.hop_limit
            previous_initial_fanout = ring.initial_fanout
            previous_relay_fanout = ring.relay_fanout
        if self.candidate_limit < 1:
            raise ValueError("candidate_limit must be positive")
        if self.required_candidates < 1:
            raise ValueError("required_candidates must be positive")
        if self.required_candidates > self.candidate_limit:
            raise ValueError("required_candidates cannot exceed candidate_limit")
        if not 0.0 <= self.responder_fraction <= 1.0:
            raise ValueError("responder_fraction must be between 0 and 1")
        if (
            self.total_transmission_budget is not None
            and self.total_transmission_budget < 0
        ):
            raise ValueError("total_transmission_budget cannot be negative")
        if (
            self.total_state_allocation_budget is not None
            and self.total_state_allocation_budget < 0
        ):
            raise ValueError("total_state_allocation_budget cannot be negative")


@dataclass(frozen=True)
class Candidate:
    responder: int
    hop_count: int
    path: tuple[int, ...]


@dataclass(frozen=True)
class DiscoveryResult:
    node_count: int
    edge_count: int
    accepted_nodes: int
    discover_transmissions: int
    duplicate_deliveries: int
    state_budget_drops: int
    candidate_count: int
    max_depth: int
    discovery_state_entries: int
    replay_cache_entries: int
    transmission_budget_exhausted: bool
    state_budget_exhausted: bool
    candidates: tuple[Candidate, ...]
    accepted_node_ids: tuple[int, ...] = field(repr=False)

    @property
    def transmission_amplification(self) -> float:
        if self.accepted_nodes == 0:
            return 0.0
        return self.discover_transmissions / self.accepted_nodes

    def to_dict(self, *, include_node_ids: bool = False) -> dict[str, object]:
        data = asdict(self)
        data["transmission_amplification"] = self.transmission_amplification
        if not include_node_ids:
            data.pop("accepted_node_ids", None)
        return data


@dataclass(frozen=True)
class RingAttemptResult:
    attempt_number: int
    ring: RingStep
    discovery: DiscoveryResult
    new_candidate_responders: tuple[int, ...]
    repeated_candidate_responders: tuple[int, ...]
    cumulative_candidate_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt_number": self.attempt_number,
            "ring": asdict(self.ring),
            "discovery": self.discovery.to_dict(),
            "new_candidate_responders": list(self.new_candidate_responders),
            "repeated_candidate_responders": list(
                self.repeated_candidate_responders
            ),
            "cumulative_candidate_count": self.cumulative_candidate_count,
        }


@dataclass(frozen=True)
class ExpandingRingResult:
    node_count: int
    edge_count: int
    success: bool
    stop_reason: str
    attempt_count: int
    total_discover_transmissions: int
    total_duplicate_deliveries: int
    total_state_budget_drops: int
    total_state_allocations: int
    unique_candidate_count: int
    candidate_responders: tuple[int, ...]
    relays_observing_any_attempt: int
    relays_observing_multiple_attempts: int
    repeated_relay_observations: int
    attempts: tuple[RingAttemptResult, ...]

    @property
    def multi_attempt_observer_fraction(self) -> float:
        if self.relays_observing_any_attempt == 0:
            return 0.0
        return (
            self.relays_observing_multiple_attempts
            / self.relays_observing_any_attempt
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "success": self.success,
            "stop_reason": self.stop_reason,
            "attempt_count": self.attempt_count,
            "total_discover_transmissions": self.total_discover_transmissions,
            "total_duplicate_deliveries": self.total_duplicate_deliveries,
            "total_state_budget_drops": self.total_state_budget_drops,
            "total_state_allocations": self.total_state_allocations,
            "unique_candidate_count": self.unique_candidate_count,
            "candidate_responders": list(self.candidate_responders),
            "relays_observing_any_attempt": self.relays_observing_any_attempt,
            "relays_observing_multiple_attempts": (
                self.relays_observing_multiple_attempts
            ),
            "repeated_relay_observations": self.repeated_relay_observations,
            "multi_attempt_observer_fraction": (
                self.multi_attempt_observer_fraction
            ),
            "attempts": [attempt.to_dict() for attempt in self.attempts],
        }


def choose_responders(
    graph: Graph,
    *,
    origin: int,
    responder_fraction: float,
    seed: int,
) -> set[int]:
    """Select a deterministic responder set for one graph and logical request."""

    if origin < 0 or origin >= graph.node_count:
        raise ValueError("origin is outside the graph")
    if not 0.0 <= responder_fraction <= 1.0:
        raise ValueError("responder_fraction must be between 0 and 1")

    rng = random.Random(seed ^ 0xA5A5A5A5)
    return {
        node
        for node in range(graph.node_count)
        if node != origin and rng.random() < responder_fraction
    }


def _bounded_sample(
    values: Iterable[int],
    limit: int,
    rng: random.Random,
) -> list[int]:
    candidates = list(values)
    rng.shuffle(candidates)
    return candidates[: min(limit, len(candidates))]


def _remaining(limit: int | None, consumed: int) -> int | None:
    if limit is None:
        return None
    return max(0, limit - consumed)


def _sample_for_transmission(
    values: Iterable[int],
    *,
    fanout: int,
    remaining_budget: int | None,
    rng: random.Random,
) -> tuple[list[int], bool]:
    candidates = list(values)
    rng.shuffle(candidates)
    desired_count = min(fanout, len(candidates))
    allowed_count = desired_count
    if remaining_budget is not None:
        allowed_count = min(allowed_count, remaining_budget)
    return candidates[:allowed_count], allowed_count < desired_count


def simulate_discovery(
    graph: Graph,
    config: DiscoveryConfig,
    *,
    responders: set[int] | None = None,
) -> DiscoveryResult:
    """Simulate one first-parent, bounded-fanout discovery attempt.

    The origin is not counted as relay discovery state. Every other node accepts
    only the first delivery. Later deliveries are duplicate-cache observations.
    Transmission and state budgets bound the accepted work for this attempt.
    """

    config.validate(graph)
    rng = random.Random(config.seed)
    if responders is None:
        responders = choose_responders(
            graph,
            origin=config.origin,
            responder_fraction=config.responder_fraction,
            seed=config.seed,
        )
    else:
        invalid = {
            node
            for node in responders
            if node < 0 or node >= graph.node_count or node == config.origin
        }
        if invalid:
            raise ValueError(f"invalid responders: {sorted(invalid)}")

    parent: dict[int, int] = {}
    depth: dict[int, int] = {config.origin: 0}
    accepted: set[int] = {config.origin}
    replay_seen: set[tuple[int, int]] = set()
    queue: deque[tuple[int, int, int]] = deque()

    initial_children, transmission_budget_exhausted = _sample_for_transmission(
        graph.neighbors(config.origin),
        fanout=config.initial_fanout,
        remaining_budget=config.transmission_budget,
        rng=rng,
    )
    for child in initial_children:
        queue.append((config.origin, child, 1))

    transmissions = len(initial_children)
    duplicates = 0
    state_budget_drops = 0
    state_budget_exhausted = False
    candidates: list[Candidate] = []
    max_depth = 0

    while queue:
        previous, node, hop_count = queue.popleft()

        if hop_count > config.hop_limit:
            raise AssertionError("queued event exceeded hop_limit")

        if node in accepted:
            duplicates += 1
            replay_seen.add((previous, node))
            continue

        accepted_relays = len(accepted) - 1
        if (
            config.state_budget is not None
            and accepted_relays >= config.state_budget
        ):
            state_budget_drops += 1
            state_budget_exhausted = True
            continue

        accepted.add(node)
        parent[node] = previous
        depth[node] = hop_count
        max_depth = max(max_depth, hop_count)

        if node in responders and len(candidates) < config.candidate_limit:
            path = [node]
            cursor = node
            while cursor != config.origin:
                cursor = parent[cursor]
                path.append(cursor)
            path.reverse()
            candidates.append(
                Candidate(responder=node, hop_count=hop_count, path=tuple(path))
            )

        if hop_count >= config.hop_limit:
            continue

        remaining_budget = _remaining(config.transmission_budget, transmissions)
        children = (
            peer for peer in graph.neighbors(node) if peer != previous
        )
        selected, truncated = _sample_for_transmission(
            children,
            fanout=config.relay_fanout,
            remaining_budget=remaining_budget,
            rng=rng,
        )
        transmission_budget_exhausted = (
            transmission_budget_exhausted or truncated
        )
        for child in selected:
            queue.append((node, child, hop_count + 1))
        transmissions += len(selected)

    accepted_relays = len(accepted) - 1
    return DiscoveryResult(
        node_count=graph.node_count,
        edge_count=graph.edge_count(),
        accepted_nodes=accepted_relays,
        discover_transmissions=transmissions,
        duplicate_deliveries=duplicates,
        state_budget_drops=state_budget_drops,
        candidate_count=len(candidates),
        max_depth=max_depth,
        discovery_state_entries=accepted_relays,
        replay_cache_entries=len(replay_seen),
        transmission_budget_exhausted=transmission_budget_exhausted,
        state_budget_exhausted=state_budget_exhausted,
        candidates=tuple(candidates),
        accepted_node_ids=tuple(sorted(accepted - {config.origin})),
    )


def simulate_expanding_ring(
    graph: Graph,
    config: ExpandingRingConfig,
    *,
    responders: set[int] | None = None,
) -> ExpandingRingResult:
    """Simulate a bounded logical discovery using fresh per-ring attempts.

    Responders remain fixed across attempts. Relay selection is independently
    randomized for each ring. Budgets apply to the entire logical discovery,
    not independently to each attempt.
    """

    config.validate(graph)
    if responders is None:
        responders = choose_responders(
            graph,
            origin=config.origin,
            responder_fraction=config.responder_fraction,
            seed=config.seed,
        )

    attempts: list[RingAttemptResult] = []
    candidate_paths: dict[int, Candidate] = {}
    relay_observations: Counter[int] = Counter()
    total_transmissions = 0
    total_duplicates = 0
    total_state_budget_drops = 0
    total_state_allocations = 0
    stop_reason = "rings_exhausted"

    for attempt_index, ring in enumerate(config.rings, start=1):
        remaining_transmissions = _remaining(
            config.total_transmission_budget,
            total_transmissions,
        )
        remaining_state = _remaining(
            config.total_state_allocation_budget,
            total_state_allocations,
        )

        if remaining_transmissions == 0:
            stop_reason = "transmission_budget"
            break
        if remaining_state == 0:
            stop_reason = "state_budget"
            break

        # Derive an independent deterministic attempt seed. This represents a
        # fresh wire attempt identifier and independently selected forwarding
        # peers, while preserving reproducibility.
        attempt_seed = config.seed ^ (attempt_index * 0x9E3779B1)
        attempt_config = DiscoveryConfig(
            origin=config.origin,
            hop_limit=ring.hop_limit,
            initial_fanout=ring.initial_fanout,
            relay_fanout=ring.relay_fanout,
            candidate_limit=config.candidate_limit,
            responder_fraction=config.responder_fraction,
            seed=attempt_seed,
            transmission_budget=remaining_transmissions,
            state_budget=remaining_state,
        )
        result = simulate_discovery(
            graph,
            attempt_config,
            responders=responders,
        )

        total_transmissions += result.discover_transmissions
        total_duplicates += result.duplicate_deliveries
        total_state_budget_drops += result.state_budget_drops
        total_state_allocations += result.discovery_state_entries
        relay_observations.update(result.accepted_node_ids)

        new_responders: list[int] = []
        repeated_responders: list[int] = []
        for candidate in result.candidates:
            if candidate.responder in candidate_paths:
                repeated_responders.append(candidate.responder)
            elif len(candidate_paths) < config.candidate_limit:
                candidate_paths[candidate.responder] = candidate
                new_responders.append(candidate.responder)

        attempts.append(
            RingAttemptResult(
                attempt_number=attempt_index,
                ring=ring,
                discovery=result,
                new_candidate_responders=tuple(sorted(new_responders)),
                repeated_candidate_responders=tuple(
                    sorted(set(repeated_responders))
                ),
                cumulative_candidate_count=len(candidate_paths),
            )
        )

        if len(candidate_paths) >= config.required_candidates:
            stop_reason = "required_candidates"
            break
        if (
            config.total_transmission_budget is not None
            and total_transmissions >= config.total_transmission_budget
        ):
            stop_reason = "transmission_budget"
            break
        if (
            config.total_state_allocation_budget is not None
            and total_state_allocations
            >= config.total_state_allocation_budget
        ):
            stop_reason = "state_budget"
            break

    relays_observing_multiple = sum(
        1 for count in relay_observations.values() if count > 1
    )
    repeated_observations = sum(
        count - 1 for count in relay_observations.values() if count > 1
    )

    return ExpandingRingResult(
        node_count=graph.node_count,
        edge_count=graph.edge_count(),
        success=len(candidate_paths) >= config.required_candidates,
        stop_reason=stop_reason,
        attempt_count=len(attempts),
        total_discover_transmissions=total_transmissions,
        total_duplicate_deliveries=total_duplicates,
        total_state_budget_drops=total_state_budget_drops,
        total_state_allocations=total_state_allocations,
        unique_candidate_count=len(candidate_paths),
        candidate_responders=tuple(sorted(candidate_paths)),
        relays_observing_any_attempt=len(relay_observations),
        relays_observing_multiple_attempts=relays_observing_multiple,
        repeated_relay_observations=repeated_observations,
        attempts=tuple(attempts),
    )


def parse_ring_schedule(value: str) -> tuple[RingStep, ...]:
    """Parse ``hop:initial:relay`` or ``hop:fanout`` comma-separated rings."""

    rings: list[RingStep] = []
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            continue
        fields = [int(field.strip()) for field in item.split(":")]
        if len(fields) == 2:
            hop_limit, fanout = fields
            rings.append(RingStep(hop_limit, fanout, fanout))
        elif len(fields) == 3:
            hop_limit, initial_fanout, relay_fanout = fields
            rings.append(RingStep(hop_limit, initial_fanout, relay_fanout))
        else:
            raise ValueError(
                "each ring must be hop:fanout or hop:initial_fanout:relay_fanout"
            )
    if not rings:
        raise ValueError("at least one ring is required")
    return tuple(rings)


def ring_schedule_to_string(rings: Sequence[RingStep]) -> str:
    return ",".join(
        f"{ring.hop_limit}:{ring.initial_fanout}:{ring.relay_fanout}"
        for ring in rings
    )
