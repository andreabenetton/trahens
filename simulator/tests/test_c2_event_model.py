from __future__ import annotations

import unittest
from dataclasses import replace

from trahens_sim.event_model import EventLifecycleConfig, TimedRingStep, simulate_event_lifecycle
from trahens_sim.model import Graph


class C2EventModelTests(unittest.TestCase):
    def _line(self, count: int) -> Graph:
        graph = Graph(count)
        for node in range(count - 1):
            graph.add_edge(node, node + 1)
        return graph

    def test_clean_c2_symbolic_route_activates(self) -> None:
        graph = self._line(5)
        config = EventLifecycleConfig(
            eligibility_profile="c2-ideal",
            rings=(TimedRingStep(4, 1, 1, 40),),
            seed=71,
            discover_delay_min_ms=1,
            discover_delay_max_ms=1,
            candidate_delay_min_ms=1,
            candidate_delay_max_ms=1,
            control_delay_min_ms=1,
            control_delay_max_ms=1,
            responder_offer_delay_min_ms=1,
            responder_offer_delay_max_ms=1,
            max_simulation_ms=220,
        )
        result = simulate_event_lifecycle(graph, config, responders={4})
        self.assertTrue(result.success)
        self.assertEqual(result.selected_hop_count, 4)
        self.assertGreater(result.wire_bytes, 0)
        self.assertTrue(result.cleanup_complete)

    def test_c2_mutation_is_dropped_before_downstream_colluder(self) -> None:
        graph = self._line(5)
        base = EventLifecycleConfig(
            eligibility_profile="c2-ideal",
            rings=(TimedRingStep(4, 1, 1, 40),),
            seed=73,
            discover_delay_min_ms=1,
            discover_delay_max_ms=1,
            candidate_delay_min_ms=1,
            candidate_delay_max_ms=1,
            control_delay_min_ms=1,
            control_delay_max_ms=1,
            responder_offer_delay_min_ms=1,
            responder_offer_delay_max_ms=1,
            max_simulation_ms=220,
        )
        clean = simulate_event_lifecycle(
            graph,
            base,
            responders={4},
            malicious_nodes={1, 3},
        )
        attacked = simulate_event_lifecycle(
            graph,
            replace(base, active_tagging=True),
            responders={4},
            malicious_nodes={1, 3},
        )
        self.assertTrue(clean.success)
        self.assertFalse(attacked.success)
        self.assertGreater(attacked.tagged_branches_created, 0)
        self.assertEqual(attacked.tag_observations, 0)
        self.assertGreater(attacked.crypto_failures, 0)
        self.assertTrue(attacked.cleanup_complete)

    def test_c2_results_are_deterministic(self) -> None:
        graph = self._line(4)
        config = EventLifecycleConfig(
            eligibility_profile="c2-ideal",
            rings=(TimedRingStep(3, 1, 1, 30),),
            seed=79,
            max_simulation_ms=180,
        )
        left = simulate_event_lifecycle(graph, config, responders={3}).to_dict()
        right = simulate_event_lifecycle(graph, config, responders={3}).to_dict()
        self.assertEqual(left, right)


if __name__ == "__main__":
    unittest.main()

class C2ComparisonTests(unittest.TestCase):
    def test_small_c2_comparison_is_deterministic(self) -> None:
        from trahens_sim.c2_compare import run_comparison

        self.assertEqual(run_comparison(3), run_comparison(3))
