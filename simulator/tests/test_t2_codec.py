from __future__ import annotations

import json
from pathlib import Path
from random import Random
import unittest

from trahens_codec.m2w2 import CELL_BODY_BYTES, CELL_RECORD_BYTES
from trahens_codec.t2 import (
    T2ScheduleAction,
    T2ScheduleFrame,
    decode_schedule_body,
    encode_schedule_body,
)
from trahens_crypto.eligibility import R1_SUITE_ID
from tools.generate_t2_vectors import build_vectors


class T2CodecTests(unittest.TestCase):
    def _frame(self) -> T2ScheduleFrame:
        return T2ScheduleFrame(
            crypto_suite_id=R1_SUITE_ID,
            negotiation_id=b"S" * 16,
            effective_epoch=12,
            current_rate_class=1,
            requested_rate_class=2,
            maximum_rate_class=3,
            action=T2ScheduleAction.OFFER,
        )

    def test_schedule_frame_round_trip_and_fixed_body(self) -> None:
        frame = self._frame()
        body = encode_schedule_body(frame, rng=Random(1))
        self.assertEqual(len(body), CELL_BODY_BYTES)
        self.assertEqual(decode_schedule_body(body), frame)

    def test_schedule_frame_rejects_noncanonical_rate(self) -> None:
        frame = self._frame()
        with self.assertRaisesRegex(ValueError, "requested class exceeds"):
            encode_schedule_body(
                T2ScheduleFrame(
                    **{
                        **frame.__dict__,
                        "requested_rate_class": 3,
                        "maximum_rate_class": 2,
                    }
                )
            )

    def test_tracked_t2_vectors_are_reproducible(self) -> None:
        tracked = json.loads(Path("spec/t2-test-vectors.json").read_text())
        self.assertEqual(tracked, build_vectors())
        self.assertEqual(tracked["record_bytes"], CELL_RECORD_BYTES)
        self.assertTrue(tracked["same_record_length"])
        self.assertTrue(tracked["different_ciphertext"])


if __name__ == "__main__":
    unittest.main()
