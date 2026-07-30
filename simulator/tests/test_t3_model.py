# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import asdict
import unittest

from trahens_sim.t3_model import (
    T3Config,
    active_probe_detection,
    nearest_centroid_classifier,
    route_classification_dataset,
    simulate_t3_trace,
)


class T3ModelTests(unittest.TestCase):
    def test_all_profiles_use_the_exact_same_super_epoch_budget(self) -> None:
        totals = []
        for profile in ("fixed", "adaptive", "hybrid"):
            trace = simulate_t3_trace(
                1,
                profile=profile,
                config=T3Config(epochs=64, seed=17),
                correlated_cross_traffic=True,
            )
            self.assertEqual(trace.total_public_cells, trace.expected_public_cells)
            totals.append(trace.total_public_cells)
        self.assertEqual(len(set(totals)), 1)

    def test_fixed_public_trace_is_route_independent(self) -> None:
        traces = [
            simulate_t3_trace(
                label,
                profile="fixed",
                config=T3Config(epochs=64, seed=23 + label),
                correlated_cross_traffic=True,
            )
            for label in range(4)
        ]
        for trace in traces[1:]:
            self.assertEqual(trace.public_cells, traces[0].public_cells)
            self.assertEqual(trace.boundary_alignment, 0.0)

    def test_adaptive_transitions_are_boundary_aligned(self) -> None:
        trace = simulate_t3_trace(
            1,
            profile="adaptive",
            config=T3Config(epochs=64, seed=31),
            correlated_cross_traffic=True,
        )
        self.assertGreater(trace.boundary_alignment, 0.95)

    def test_hybrid_transitions_are_not_boundary_aligned(self) -> None:
        trace = simulate_t3_trace(
            1,
            profile="hybrid",
            config=T3Config(epochs=64, seed=37),
            correlated_cross_traffic=True,
        )
        self.assertLess(trace.boundary_alignment, 0.25)

    def test_route_classifier_has_random_fixed_baseline_and_adaptive_signal(self) -> None:
        fixed_training, fixed_testing, _ = route_classification_dataset(
            profile="fixed",
            config=T3Config(epochs=64, seed=41),
            correlated_cross_traffic=True,
            training_per_class=8,
            testing_per_class=8,
        )
        adaptive_training, adaptive_testing, _ = route_classification_dataset(
            profile="adaptive",
            config=T3Config(epochs=64, seed=41),
            correlated_cross_traffic=True,
            training_per_class=12,
            testing_per_class=8,
        )
        fixed = nearest_centroid_classifier(fixed_training, fixed_testing)
        adaptive = nearest_centroid_classifier(adaptive_training, adaptive_testing)
        self.assertAlmostEqual(fixed.accuracy, 0.25)
        self.assertGreater(adaptive.accuracy, fixed.accuracy)

    def test_active_probe_is_not_visible_in_fixed_count_trace(self) -> None:
        result = active_probe_detection(
            profile="fixed",
            config=T3Config(epochs=64, seed=47),
            training_per_class=8,
            testing_per_class=8,
        )
        self.assertEqual(result.present_mean_score, 0.0)
        self.assertEqual(result.absent_mean_score, 0.0)
        self.assertEqual(result.accuracy, 0.5)

    def test_adaptive_probe_detector_outperforms_fixed_detector(self) -> None:
        fixed = active_probe_detection(
            profile="fixed",
            config=T3Config(epochs=64, seed=53),
            training_per_class=12,
            testing_per_class=12,
        )
        adaptive = active_probe_detection(
            profile="adaptive",
            config=T3Config(epochs=64, seed=53),
            training_per_class=12,
            testing_per_class=12,
        )
        self.assertGreaterEqual(adaptive.accuracy, fixed.accuracy)

    def test_trace_generation_is_deterministic(self) -> None:
        config = T3Config(epochs=64, seed=59)
        first = simulate_t3_trace(2, profile="hybrid", config=config)
        second = simulate_t3_trace(2, profile="hybrid", config=T3Config(**asdict(config)))
        self.assertEqual(first, second)

    def test_invalid_profile_fails(self) -> None:
        with self.assertRaises(ValueError):
            simulate_t3_trace(0, profile="unknown", config=T3Config())


if __name__ == "__main__":
    unittest.main()
