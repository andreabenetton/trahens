# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import unittest

from trahens_sim.t2_model import (
    T2Config,
    T2Flow,
    schedule_presence_classifier,
    simulate_t2_link,
    simulate_two_link_trace,
)


class T2ModelTests(unittest.TestCase):
    def test_adaptive_schedule_changes_only_one_class_at_epoch_boundary(self) -> None:
        result = simulate_t2_link(
            (T2Flow(0, 1, tuple([20] * 10 + [0] * 10)),),
            T2Config(
                scheduler_mode="adaptive",
                initial_rate_class=0,
                maximum_rate_class=3,
                loss_model="none",
                drain_epochs=8,
                seed=7,
            ),
        )
        deltas = [abs(b - a) for a, b in zip(result.rate_classes, result.rate_classes[1:])]
        self.assertTrue(any(delta == 1 for delta in deltas))
        self.assertTrue(all(delta <= 1 for delta in deltas))
        self.assertTrue(result.cleanup_complete)

    def test_queue_and_drop_behavior_are_bounded_under_overload(self) -> None:
        result = simulate_t2_link(
            tuple(T2Flow(index, 1, tuple([30] * 20)) for index in range(4)),
            T2Config(
                scheduler_mode="fixed",
                fixed_rate_class=0,
                queue_capacity_cells=128,
                per_flow_capacity_cells=64,
                loss_model="none",
                drain_epochs=4,
                seed=8,
            ),
        )
        self.assertLessEqual(result.peak_queue_cells, 128)
        self.assertGreater(result.dropped_cells, 0)
        self.assertGreater(result.overload_epochs, 0)

    def test_weighted_drr_is_nearly_fair_when_all_flows_are_backlogged(self) -> None:
        result = simulate_t2_link(
            (
                T2Flow(0, 1, tuple([80] * 20)),
                T2Flow(1, 2, tuple([80] * 20)),
                T2Flow(2, 3, tuple([80] * 20)),
            ),
            T2Config(
                scheduler_mode="fixed",
                fixed_rate_class=3,
                queue_capacity_cells=12_000,
                per_flow_capacity_cells=4_000,
                loss_model="none",
                drain_epochs=0,
                seed=9,
            ),
        )
        self.assertGreater(result.weighted_fairness, 0.999)
        a, b, c = result.per_flow_delivered
        self.assertLess(abs(b - 2 * a), 4)
        self.assertLess(abs(c - 3 * a), 5)

    def test_fixed_schedule_hides_presence_from_simple_class_distinguisher(self) -> None:
        config = T2Config(
            scheduler_mode="fixed",
            fixed_rate_class=3,
            initial_rate_class=3,
            loss_model="none",
            drain_epochs=8,
            seed=10,
        )
        idle = simulate_t2_link((T2Flow(0, 1, tuple([0] * 20)),), config)
        active = simulate_t2_link((T2Flow(0, 1, tuple([20] * 10 + [0] * 10)),), config)
        self.assertEqual(idle.public_cells_by_epoch, active.public_cells_by_epoch)
        self.assertEqual(schedule_presence_classifier(idle, 3), 0)
        self.assertEqual(schedule_presence_classifier(active, 3), 0)

    def test_adaptive_schedule_exposes_activity_to_simple_distinguisher(self) -> None:
        config = T2Config(
            scheduler_mode="adaptive",
            initial_rate_class=0,
            loss_model="none",
            drain_epochs=8,
            seed=11,
        )
        idle = simulate_t2_link((T2Flow(0, 1, tuple([0] * 20)),), config)
        active = simulate_t2_link((T2Flow(0, 1, tuple([20] * 10 + [0] * 10)),), config)
        self.assertEqual(schedule_presence_classifier(idle, 0), 0)
        self.assertEqual(schedule_presence_classifier(active, 0), 1)

    def test_multilink_fixed_trace_has_no_variance_and_work_conserving_correlates(self) -> None:
        arrivals = [0, 0, 5, 20, 40, 20, 5, 0, 0, 30, 50, 10, 0, 0] * 3
        fixed = simulate_two_link_trace(
            arrivals,
            mode="fixed",
            config=T2Config(scheduler_mode="fixed", fixed_rate_class=3, drain_epochs=0),
        )
        work = simulate_two_link_trace(
            arrivals,
            mode="work-conserving",
            config=T2Config(scheduler_mode="work-conserving", drain_epochs=0),
        )
        self.assertEqual(fixed[2], 0.0)
        self.assertGreater(work[2], 0.95)


if __name__ == "__main__":
    unittest.main()
