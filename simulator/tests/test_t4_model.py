# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import asdict
import unittest

from trahens_sim.t4_model import (
    T4Config,
    open_world_classifier,
    open_world_dataset,
    probe_pattern,
    selective_delay_detection,
    simulate_t4_trace,
    trace_features,
)


class T4ModelTests(unittest.TestCase):
    def test_exact_public_budget_on_every_profile(self) -> None:
        totals = []
        for profile in ("fixed", "adaptive", "hybrid"):
            trace = simulate_t4_trace(1, profile=profile, config=T4Config(epochs=32, seed=11))
            self.assertEqual(trace.total_public_cells, trace.expected_public_cells)
            self.assertTrue(trace.cleanup_complete)
            totals.append(trace.total_public_cells)
        self.assertEqual(len(set(totals)), 1)

    def test_clock_noise_is_deterministic(self) -> None:
        config = T4Config(epochs=32, seed=17)
        first = simulate_t4_trace(2, profile="hybrid", config=config)
        second = simulate_t4_trace(2, profile="hybrid", config=T4Config(**asdict(config)))
        self.assertEqual(first, second)

    def test_partial_observation_hides_unselected_link(self) -> None:
        config = T4Config(epochs=32, observed_links=(0, 2, 3), seed=19)
        trace = simulate_t4_trace(1, profile="adaptive", config=config)
        self.assertEqual(trace.observations[1], ())
        self.assertGreater(len(trace.observations[0]), 0)

    def test_route_churn_changes_trace(self) -> None:
        config = T4Config(epochs=32, seed=23, target_burst_cells=14, base_cross_cells=2)
        stable = simulate_t4_trace(1, profile="adaptive", config=config)
        churned = simulate_t4_trace(
            1,
            profile="adaptive",
            config=config,
            churn_route_label=2,
            churn_epoch=16,
        )
        self.assertNotEqual(trace_features(stable), trace_features(churned))

    def test_open_world_dataset_uses_disjoint_unknown_routes(self) -> None:
        training, calibration, testing, _ = open_world_dataset(
            profile="hybrid",
            config=T4Config(epochs=32, seed=29),
            training_per_monitored=2,
            calibration_per_route=1,
            testing_per_monitored=1,
            testing_per_unknown_route=1,
        )
        self.assertTrue(training)
        self.assertTrue(calibration)
        self.assertTrue(testing)
        result = open_world_classifier(training, calibration, testing)
        self.assertGreaterEqual(result.accuracy, 0.0)
        self.assertLessEqual(result.accuracy, 1.0)
        self.assertGreaterEqual(result.unknown_false_positive_rate, 0.0)

    def test_fixed_probe_is_not_more_visible_than_adaptive_in_reference_model(self) -> None:
        config = T4Config(epochs=32, seed=31, selective_delay_us=40_000)
        fixed = selective_delay_detection(
            profile="fixed",
            config=config,
            training_per_class=3,
            testing_per_class=3,
        )
        adaptive = selective_delay_detection(
            profile="adaptive",
            config=config,
            training_per_class=3,
            testing_per_class=3,
        )
        self.assertLessEqual(fixed.accuracy, adaptive.accuracy + 0.34)

    def test_probe_pattern_is_bounded_and_deterministic(self) -> None:
        config = T4Config(epochs=32, seed=37)
        first = probe_pattern(config, 99)
        second = probe_pattern(config, 99)
        self.assertEqual(first, second)
        self.assertTrue(all(value in (0, 1) for value in first))
        self.assertEqual(first[-config.drain_epochs :], (0,) * config.drain_epochs)

    def test_invalid_churn_parameters_fail(self) -> None:
        with self.assertRaises(ValueError):
            simulate_t4_trace(
                1,
                profile="fixed",
                config=T4Config(epochs=32),
                churn_route_label=2,
            )

    def test_invalid_profile_fails(self) -> None:
        with self.assertRaises(ValueError):
            simulate_t4_trace(1, profile="unknown", config=T4Config(epochs=32))


if __name__ == "__main__":
    unittest.main()
