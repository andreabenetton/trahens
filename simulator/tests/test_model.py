from __future__ import annotations

import unittest

from trahens_sim.model import DiscoveryConfig, Graph, simulate_discovery


class GraphTests(unittest.TestCase):
    def test_random_graph_is_connected_by_discovery_with_full_fanout(self) -> None:
        graph = Graph.random_connected(50, 4.0, seed=9)
        config = DiscoveryConfig(
            hop_limit=50,
            initial_fanout=50,
            relay_fanout=50,
            responder_fraction=0.0,
            seed=9,
        )
        result = simulate_discovery(graph, config)
        self.assertEqual(result.accepted_nodes, 49)


class DiscoveryTests(unittest.TestCase):
    def test_result_is_reproducible(self) -> None:
        graph = Graph.random_connected(100, 5.0, seed=3)
        config = DiscoveryConfig(seed=22)
        self.assertEqual(
            simulate_discovery(graph, config),
            simulate_discovery(graph, config),
        )

    def test_depth_never_exceeds_limit(self) -> None:
        graph = Graph.random_connected(200, 8.0, seed=5)
        config = DiscoveryConfig(hop_limit=3, seed=5)
        result = simulate_discovery(graph, config)
        self.assertLessEqual(result.max_depth, 3)
        for candidate in result.candidates:
            self.assertLessEqual(candidate.hop_count, 3)
            self.assertEqual(len(candidate.path) - 1, candidate.hop_count)

    def test_state_is_one_entry_per_accepted_relay(self) -> None:
        graph = Graph.random_connected(80, 6.0, seed=2)
        result = simulate_discovery(graph, DiscoveryConfig(seed=2))
        self.assertEqual(result.discovery_state_entries, result.accepted_nodes)

    def test_transmissions_are_bounded_by_configured_fanout(self) -> None:
        graph = Graph.random_connected(150, 12.0, seed=11)
        config = DiscoveryConfig(
            initial_fanout=5,
            relay_fanout=3,
            hop_limit=5,
            seed=11,
        )
        result = simulate_discovery(graph, config)
        upper_bound = config.initial_fanout + result.accepted_nodes * config.relay_fanout
        self.assertLessEqual(result.discover_transmissions, upper_bound)

    def test_candidate_limit_is_enforced(self) -> None:
        graph = Graph.random_connected(100, 7.0, seed=15)
        config = DiscoveryConfig(
            candidate_limit=2,
            responder_fraction=1.0,
            seed=15,
        )
        result = simulate_discovery(graph, config)
        self.assertLessEqual(result.candidate_count, 2)


if __name__ == "__main__":
    unittest.main()
