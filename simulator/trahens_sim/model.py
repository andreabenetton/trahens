"""A small deterministic model of bounded Trahens discovery.

The model intentionally excludes cryptography and timing-cover profiles. It tests
Core v0.1 graph behavior, first-parent duplicate suppression, fan-out limits,
and discovery-state growth.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from collections import deque
import random
from typing import Iterable


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

        A random spanning tree guarantees connectivity. Additional edges are then
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
    candidate_count: int
    max_depth: int
    discovery_state_entries: int
    replay_cache_entries: int
    candidates: tuple[Candidate, ...]

    @property
    def transmission_amplification(self) -> float:
        if self.accepted_nodes == 0:
            return 0.0
        return self.discover_transmissions / self.accepted_nodes

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["transmission_amplification"] = self.transmission_amplification
        return data


def _choose_responders(graph: Graph, config: DiscoveryConfig) -> set[int]:
    rng = random.Random(config.seed ^ 0xA5A5A5A5)
    responders = {
        node
        for node in range(graph.node_count)
        if node != config.origin and rng.random() < config.responder_fraction
    }
    return responders


def _bounded_sample(
    values: Iterable[int],
    limit: int,
    rng: random.Random,
) -> list[int]:
    candidates = list(values)
    rng.shuffle(candidates)
    return candidates[: min(limit, len(candidates))]


def simulate_discovery(graph: Graph, config: DiscoveryConfig) -> DiscoveryResult:
    """Simulate one first-parent, bounded-fanout discovery.

    The origin is not counted as relay discovery state. Every other node accepts
    only the first delivery. Later deliveries are duplicate-cache observations.
    """

    config.validate(graph)
    rng = random.Random(config.seed)
    responders = _choose_responders(graph, config)

    parent: dict[int, int] = {}
    depth: dict[int, int] = {config.origin: 0}
    accepted: set[int] = {config.origin}
    replay_seen: set[tuple[int, int]] = set()
    queue: deque[tuple[int, int, int]] = deque()

    initial_children = _bounded_sample(
        graph.neighbors(config.origin),
        config.initial_fanout,
        rng,
    )
    for child in initial_children:
        queue.append((config.origin, child, 1))

    transmissions = len(initial_children)
    duplicates = 0
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

        children = (
            peer
            for peer in graph.neighbors(node)
            if peer != previous
        )
        selected = _bounded_sample(children, config.relay_fanout, rng)
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
        candidate_count=len(candidates),
        max_depth=max_depth,
        discovery_state_entries=accepted_relays,
        replay_cache_entries=len(replay_seen),
        candidates=tuple(candidates),
    )
