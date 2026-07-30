# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import unittest

from trahens_sim.t1_model import T1Config, simulate_t1_path


class T1ModelTests(unittest.TestCase):
    def test_selective_recovery_improves_deterministic_loss_case(self) -> None:
        base = T1Config(
            seed=1,
            scheduler_mode="work-conserving",
            loss_probability=0.12,
            schedule_epoch_ms=800,
            max_retransmission_rounds=0,
        )
        unreliable = simulate_t1_path(5, base)
        recovered = simulate_t1_path(
            5,
            T1Config(
                **{
                    **base.__dict__,
                    "max_retransmission_rounds": 3,
                }
            ),
        )
        self.assertFalse(unreliable.success)
        self.assertEqual(unreliable.stop_reason, "retransmission_limit")
        self.assertTrue(recovered.success)
        self.assertGreater(recovered.retransmitted_data_cells, 0)
        self.assertTrue(recovered.cleanup_complete)

    def test_constant_schedule_has_same_public_shape_with_or_without_traffic(self) -> None:
        config = T1Config(
            seed=19,
            scheduler_mode="constant",
            loss_probability=0.0,
            slot_interval_ms=2,
            schedule_epoch_ms=500,
        )
        active = simulate_t1_path(4, config, start_protocol=True)
        empty = simulate_t1_path(4, config, start_protocol=False)
        self.assertTrue(active.success)
        self.assertEqual(active.external_trace_rate_cv, 0.0)
        self.assertEqual(empty.external_trace_rate_cv, 0.0)
        self.assertEqual(
            active.per_direction_trace_cells_min,
            active.per_direction_trace_cells_max,
        )
        self.assertEqual(
            active.per_direction_trace_cells_min,
            empty.per_direction_trace_cells_min,
        )
        self.assertEqual(
            active.per_direction_trace_cells_max,
            empty.per_direction_trace_cells_max,
        )
        self.assertGreater(active.chaff_cells, 0)
        self.assertEqual(empty.data_cells, 0)
        self.assertEqual(empty.ack_cells, 0)

    def test_deep_candidate_fragments_and_recovers(self) -> None:
        result = simulate_t1_path(
            12,
            T1Config(
                seed=22,
                scheduler_mode="work-conserving",
                loss_probability=0.05,
                schedule_epoch_ms=1_200,
                max_retransmission_rounds=4,
            ),
        )
        self.assertTrue(result.success)
        self.assertGreater(result.fragmented_messages, 0)
        self.assertGreater(result.ack_cells, 0)
        self.assertTrue(result.cleanup_complete)

    def test_total_loss_exhausts_bounded_retries(self) -> None:
        result = simulate_t1_path(
            2,
            T1Config(
                seed=3,
                scheduler_mode="work-conserving",
                loss_probability=1.0,
                schedule_epoch_ms=400,
                max_retransmission_rounds=2,
            ),
        )
        self.assertFalse(result.success)
        self.assertEqual(result.stop_reason, "retransmission_limit")
        self.assertEqual(result.retransmission_rounds, 2)
        self.assertEqual(result.retry_exhaustions, 1)
        self.assertTrue(result.cleanup_complete)


if __name__ == "__main__":
    unittest.main()
