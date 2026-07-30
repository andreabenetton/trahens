from __future__ import annotations

import unittest

from trahens_sim.model import (
    DiscoveryConfig,
    ExpandingRingConfig,
    Graph,
    RingStep,
    parse_ring_schedule,
    simulate_discovery,
    simulate_expanding_ring,
)


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
        self.assertEqual(len(result.accepted_node_ids), result.accepted_nodes)

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

    def test_transmission_budget_is_hard_limit(self) -> None:
        graph = Graph.random_connected(100, 9.0, seed=33)
        config = DiscoveryConfig(
            hop_limit=6,
            initial_fanout=8,
            relay_fanout=8,
            transmission_budget=17,
            seed=33,
        )
        result = simulate_discovery(graph, config)
        self.assertLessEqual(result.discover_transmissions, 17)
        self.assertTrue(result.transmission_budget_exhausted)

    def test_state_budget_is_hard_limit(self) -> None:
        graph = Graph.random_connected(100, 9.0, seed=44)
        config = DiscoveryConfig(
            hop_limit=6,
            initial_fanout=8,
            relay_fanout=8,
            state_budget=5,
            seed=44,
        )
        result = simulate_discovery(graph, config)
        self.assertEqual(result.accepted_nodes, 5)
        self.assertTrue(result.state_budget_exhausted)
        self.assertGreater(result.state_budget_drops, 0)


class ExpandingRingTests(unittest.TestCase):
    @staticmethod
    def _path_graph(length: int) -> Graph:
        graph = Graph(length)
        for node in range(length - 1):
            graph.add_edge(node, node + 1)
        return graph

    def test_result_is_reproducible(self) -> None:
        graph = Graph.random_connected(100, 5.0, seed=8)
        config = ExpandingRingConfig(seed=8)
        self.assertEqual(
            simulate_expanding_ring(graph, config),
            simulate_expanding_ring(graph, config),
        )

    def test_stops_after_first_successful_ring(self) -> None:
        graph = self._path_graph(4)
        config = ExpandingRingConfig(
            rings=(RingStep(1, 1, 1), RingStep(3, 1, 1)),
            required_candidates=1,
            seed=1,
        )
        result = simulate_expanding_ring(graph, config, responders={1})
        self.assertTrue(result.success)
        self.assertEqual(result.attempt_count, 1)
        self.assertEqual(result.stop_reason, "required_candidates")
        self.assertEqual(result.candidate_responders, (1,))

    def test_expands_until_distant_responder_is_reached(self) -> None:
        graph = self._path_graph(4)
        config = ExpandingRingConfig(
            rings=(
                RingStep(1, 1, 1),
                RingStep(2, 1, 1),
                RingStep(3, 1, 1),
            ),
            required_candidates=1,
            seed=2,
        )
        result = simulate_expanding_ring(graph, config, responders={3})
        self.assertTrue(result.success)
        self.assertEqual(result.attempt_count, 3)
        self.assertEqual(result.candidate_responders, (3,))
        self.assertGreater(result.relays_observing_multiple_attempts, 0)

    def test_candidates_are_deduplicated_across_attempts(self) -> None:
        graph = self._path_graph(3)
        config = ExpandingRingConfig(
            rings=(RingStep(1, 1, 1), RingStep(2, 1, 1)),
            candidate_limit=2,
            required_candidates=2,
            seed=3,
        )
        result = simulate_expanding_ring(graph, config, responders={1})
        self.assertFalse(result.success)
        self.assertEqual(result.unique_candidate_count, 1)
        self.assertEqual(
            result.attempts[1].repeated_candidate_responders,
            (1,),
        )

    def test_total_transmission_budget_stops_expansion(self) -> None:
        graph = self._path_graph(4)
        config = ExpandingRingConfig(
            rings=(RingStep(1, 1, 1), RingStep(3, 1, 1)),
            required_candidates=1,
            total_transmission_budget=1,
            seed=4,
        )
        result = simulate_expanding_ring(graph, config, responders={3})
        self.assertFalse(result.success)
        self.assertEqual(result.total_discover_transmissions, 1)
        self.assertEqual(result.stop_reason, "transmission_budget")
        self.assertEqual(result.attempt_count, 1)

    def test_total_state_budget_is_shared_by_attempts(self) -> None:
        graph = self._path_graph(5)
        config = ExpandingRingConfig(
            rings=(RingStep(1, 1, 1), RingStep(4, 1, 1)),
            required_candidates=1,
            total_state_allocation_budget=2,
            seed=5,
        )
        result = simulate_expanding_ring(graph, config, responders={4})
        self.assertFalse(result.success)
        self.assertLessEqual(result.total_state_allocations, 2)
        self.assertEqual(result.stop_reason, "state_budget")

    def test_ring_schedule_parser(self) -> None:
        self.assertEqual(
            parse_ring_schedule("2:2,3:2:3"),
            (RingStep(2, 2, 2), RingStep(3, 2, 3)),
        )


class SweepTests(unittest.TestCase):
    def test_small_policy_comparison_is_deterministic(self) -> None:
        from trahens_sim.policy_compare import run_policy_comparison

        kwargs = dict(
            nodes=40,
            average_degree=4.0,
            runs=3,
            responder_fractions=[0.1],
            candidate_limit=3,
            required_candidates=1,
            fixed_hop_limit=4,
            fixed_initial_fanout=3,
            fixed_relay_fanout=3,
            rings=(RingStep(1, 1, 1), RingStep(3, 2, 2)),
            transmission_budget=100,
            state_budget=100,
            seed_base=90,
        )
        self.assertEqual(
            run_policy_comparison(**kwargs),
            run_policy_comparison(**kwargs),
        )

    def test_small_sweep_is_deterministic(self) -> None:
        from trahens_sim.sweep import run_sweep

        first = run_sweep(
            nodes=30,
            average_degree=4.0,
            hop_limits=[2],
            relay_fanouts=[2],
            runs=3,
            candidate_limit=2,
            responder_fraction=0.1,
            seed_base=50,
        )
        second = run_sweep(
            nodes=30,
            average_degree=4.0,
            hop_limits=[2],
            relay_fanouts=[2],
            runs=3,
            candidate_limit=2,
            responder_fraction=0.1,
            seed_base=50,
        )
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
