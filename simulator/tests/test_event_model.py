from __future__ import annotations

from dataclasses import replace
import unittest

from trahens_sim.event_model import (
    EventLifecycleConfig,
    TimedRingStep,
    parse_timed_ring_schedule,
    simulate_event_lifecycle,
)
from trahens_sim.lifecycle_compare import (
    LifecycleScenario,
    run_lifecycle_comparison,
)
from trahens_sim.model import Graph


def line_graph(node_count: int) -> Graph:
    graph = Graph(node_count)
    for node in range(node_count - 1):
        graph.add_edge(node, node + 1)
    return graph


def deterministic_config(
    *,
    rings: tuple[TimedRingStep, ...] = (TimedRingStep(3, 1, 1, 12),),
    **overrides: object,
) -> EventLifecycleConfig:
    config = EventLifecycleConfig(
        rings=rings,
        seed=7,
        discover_delay_min_ms=1,
        discover_delay_max_ms=1,
        candidate_delay_min_ms=1,
        candidate_delay_max_ms=1,
        control_delay_min_ms=1,
        control_delay_max_ms=1,
        responder_offer_delay_min_ms=1,
        responder_offer_delay_max_ms=1,
        branch_ttl_ms=50,
        offer_ttl_ms=60,
        tentative_ttl_ms=30,
        ready_hold_ms=20,
        route_setup_timeout_ms=40,
        active_lifetime_ms=20,
        max_simulation_ms=140,
        transmission_budget=500,
        branch_capacity=200,
        tentative_capacity=100,
        active_capacity=20,
        per_node_branch_limit=20,
        candidate_response_limit=20,
    )
    return replace(config, **overrides)


class EventLifecycleTests(unittest.TestCase):
    def test_result_is_reproducible(self) -> None:
        graph = Graph.random_connected(60, 5.0, seed=11)
        config = EventLifecycleConfig(seed=19)
        first = simulate_event_lifecycle(graph, config)
        second = simulate_event_lifecycle(graph, config)
        self.assertEqual(first, second)

    def test_candidate_at_window_deadline_is_eligible(self) -> None:
        graph = line_graph(2)
        config = deterministic_config(
            rings=(TimedRingStep(1, 1, 1, 3),),
            responder_offer_delay_min_ms=1,
            responder_offer_delay_max_ms=1,
        )
        result = simulate_event_lifecycle(graph, config, responders={1})
        self.assertTrue(result.success)
        self.assertEqual(result.candidates_received, 1)
        self.assertEqual(result.selected_responder, 1)

    def test_delayed_candidate_from_earlier_ring_can_be_selected(self) -> None:
        graph = line_graph(2)
        config = deterministic_config(
            rings=(
                TimedRingStep(1, 1, 1, 2),
                TimedRingStep(1, 1, 1, 6),
            ),
            responder_offer_delay_min_ms=3,
            responder_offer_delay_max_ms=3,
        )
        result = simulate_event_lifecycle(
            graph,
            config,
            responders={1},
            responder_offer_delays={1: 3},
        )
        self.assertTrue(result.success)
        self.assertEqual(result.rings_started, 2)
        self.assertEqual(result.selected_ring_index, 0)

    def test_cancellation_can_overtake_a_delayed_candidate(self) -> None:
        graph = Graph(3)
        graph.add_edge(0, 1)
        graph.add_edge(0, 2)
        config = deterministic_config(
            rings=(TimedRingStep(1, 2, 1, 5),),
        )
        result = simulate_event_lifecycle(
            graph,
            config,
            responders={1, 2},
            responder_offer_delays={1: 1, 2: 5},
        )
        self.assertTrue(result.success)
        self.assertEqual(result.selected_responder, 1)
        self.assertGreaterEqual(result.candidate_race_drops, 1)
        self.assertTrue(result.cleanup_complete)

    def test_commit_ready_activates_then_expires_route_state(self) -> None:
        graph = line_graph(3)
        config = deterministic_config()
        result = simulate_event_lifecycle(graph, config, responders={2})
        self.assertTrue(result.success)
        self.assertEqual(result.stop_reason, "ready")
        self.assertEqual(result.selected_hop_count, 2)
        self.assertEqual(result.peak_pending_state, 1)
        self.assertEqual(result.peak_active_state, 1)
        self.assertTrue(result.cleanup_complete)
        self.assertEqual(result.final_active_state, 0)

    def test_tentative_expiry_causes_commit_failure(self) -> None:
        graph = line_graph(3)
        config = deterministic_config(
            rings=(TimedRingStep(2, 1, 1, 9),),
            tentative_ttl_ms=1,
        )
        result = simulate_event_lifecycle(graph, config, responders={2})
        self.assertFalse(result.success)
        self.assertEqual(result.stop_reason, "commit_missing_tentative")
        self.assertEqual(result.commit_failures, 1)
        self.assertTrue(result.cleanup_complete)

    def test_expired_offer_and_candidate_state_are_reclaimed(self) -> None:
        graph = line_graph(2)
        config = deterministic_config(
            rings=(TimedRingStep(1, 1, 1, 20),),
            offer_ttl_ms=4,
        )
        result = simulate_event_lifecycle(graph, config, responders={1})
        self.assertFalse(result.success)
        self.assertEqual(result.stop_reason, "no_candidate")
        self.assertEqual(result.candidates_received, 1)
        self.assertGreaterEqual(result.peak_offer_state, 1)
        self.assertGreaterEqual(result.peak_candidate_state, 1)
        self.assertEqual(result.final_offer_state, 0)
        self.assertEqual(result.final_candidate_state, 0)
        self.assertTrue(result.cleanup_complete)

    def test_pending_ready_extension_ignores_stale_tentative_expiry(self) -> None:
        graph = line_graph(3)
        config = deterministic_config(
            rings=(TimedRingStep(2, 1, 1, 12),),
            tentative_ttl_ms=10,
            ready_hold_ms=20,
        )
        result = simulate_event_lifecycle(graph, config, responders={2})
        self.assertTrue(result.success)
        self.assertEqual(result.stop_reason, "ready")
        self.assertEqual(result.ready_failures, 0)
        self.assertTrue(result.cleanup_complete)

    def test_divergent_subtree_cancel_uses_an_adjacent_parent(self) -> None:
        graph = Graph(4)
        graph.add_edge(0, 1)
        graph.add_edge(1, 2)
        graph.add_edge(1, 3)
        config = deterministic_config(
            rings=(TimedRingStep(2, 1, 2, 8),),
        )
        result = simulate_event_lifecycle(
            graph,
            config,
            responders={2, 3},
            responder_offer_delays={2: 1, 3: 5},
        )
        self.assertTrue(result.success)
        self.assertTrue(result.cleanup_complete)

    def test_lost_ready_times_out_and_cleans_pending_state(self) -> None:
        graph = line_graph(3)
        config = deterministic_config(forced_drop_types=("READY",))
        result = simulate_event_lifecycle(graph, config, responders={2})
        self.assertFalse(result.success)
        self.assertEqual(result.stop_reason, "route_setup_timeout")
        self.assertGreaterEqual(result.ready_failures, 1)
        self.assertGreaterEqual(result.loss_drops, 1)
        self.assertTrue(result.cleanup_complete)

    def test_exact_link_duplicates_do_not_allocate_new_contexts(self) -> None:
        graph = line_graph(3)
        config = deterministic_config(duplicate_probability=1.0)
        result = simulate_event_lifecycle(graph, config, responders={2})
        self.assertTrue(result.success)
        self.assertEqual(result.legitimate_branch_allocations, 2)
        self.assertGreater(result.exact_replay_drops, 0)

    def test_peer_token_bucket_bounds_fresh_branch_attack(self) -> None:
        graph = Graph.random_connected(30, 4.0, seed=21)
        base = deterministic_config(
            rings=(TimedRingStep(2, 2, 2, 8),),
            attack_bursts=4,
            attack_interval_ms=2,
            attack_branches_per_burst=8,
            attack_hop_limit=2,
            attack_fanout=2,
            branch_capacity=500,
            per_node_branch_limit=100,
            max_simulation_ms=120,
        )
        undefended = simulate_event_lifecycle(
            graph,
            base,
            responders=set(),
            malicious_nodes={1},
        )
        defended = simulate_event_lifecycle(
            graph,
            replace(
                base,
                peer_bucket_capacity=2,
                peer_bucket_refill_ms=10,
                peer_bucket_refill_amount=1,
            ),
            responders=set(),
            malicious_nodes={1},
        )
        self.assertLess(
            defended.attack_branch_allocations,
            undefended.attack_branch_allocations,
        )
        self.assertGreater(defended.token_bucket_drops, 0)
        self.assertTrue(defended.cleanup_complete)

    def test_transmission_budget_is_hard_limit_under_attack(self) -> None:
        graph = Graph.random_connected(20, 4.0, seed=31)
        config = deterministic_config(
            rings=(TimedRingStep(2, 2, 2, 6),),
            transmission_budget=20,
            attack_bursts=5,
            attack_interval_ms=1,
            attack_branches_per_burst=20,
            attack_hop_limit=3,
            attack_fanout=3,
        )
        result = simulate_event_lifecycle(
            graph,
            config,
            responders=set(),
            malicious_nodes={1, 2},
        )
        self.assertLessEqual(result.total_transmissions, 20)
        self.assertGreater(result.transmission_budget_drops, 0)

    def test_small_lifecycle_comparison_is_deterministic(self) -> None:
        kwargs = dict(
            nodes=30,
            average_degree=4.0,
            runs=2,
            rings=(TimedRingStep(2, 2, 2, 10),),
            responder_fraction=0.1,
            seed_base=91,
            scenarios=(LifecycleScenario(name="clean"),),
        )
        first = run_lifecycle_comparison(**kwargs)
        second = run_lifecycle_comparison(**kwargs)
        self.assertEqual(first, second)

    def test_timed_ring_schedule_parser(self) -> None:
        parsed = parse_timed_ring_schedule("2:2:10,4:3:2:25")
        self.assertEqual(
            parsed,
            (
                TimedRingStep(2, 2, 2, 10),
                TimedRingStep(4, 3, 2, 25),
            ),
        )
        with self.assertRaises(ValueError):
            parse_timed_ring_schedule("2:3")


if __name__ == "__main__":
    unittest.main()
