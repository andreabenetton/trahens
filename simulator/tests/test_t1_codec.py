# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path
import unittest
from random import Random

from trahens_codec.m2w2 import (
    CELL_RECORD_BYTES,
    DiscoverRecord,
    derive_link_key,
    encode_discover,
)
from trahens_codec.t1 import (
    T1AckFrame,
    T1ChaffFrame,
    T1DataFrame,
    ack_bitmap,
    decode_body,
    encode_ack_body,
    encode_chaff_body,
    encode_data_body,
    open_record,
    seal_body,
    split_message,
)
from trahens_crypto import ristretto as r255
from trahens_crypto.eligibility import R1_SUITE_ID
from tools.generate_t1_vectors import build_vectors


class T1CodecTests(unittest.TestCase):
    def _message(self) -> bytes:
        return encode_discover(
            DiscoverRecord(
                branch_token=b"B" * 16,
                hop_remaining=4,
                fanout_class=2,
                expiry_class=1,
                depth=0,
                routing_nonce=bytes(range(1, 33)),
                reply_public_key=r255.scalarmult_base(
                    r255.scalar_from_label(b"t1-codec-reply")
                ),
                eligibility_capsule=b"N" * 32,
                crypto_suite_id=R1_SUITE_ID,
            )
        )

    def test_data_ack_and_chaff_are_equal_sized_encrypted_records(self) -> None:
        message = self._message()
        frame = split_message(message, transmission_id=b"T" * 16)[0]
        bitmap = ack_bitmap({0}, 1)
        bodies = (
            encode_data_body(frame, rng=Random(1)),
            encode_ack_body(
                crypto_suite_id=R1_SUITE_ID,
                transmission_id=b"T" * 16,
                fragment_count=1,
                acknowledged_bitmap=bitmap,
                ack_delay_ms=2,
                rng=Random(2),
            ),
            encode_chaff_body(
                crypto_suite_id=R1_SUITE_ID,
                transmission_id=b"C" * 16,
                rng=Random(3),
            ),
        )
        key = derive_link_key(7, 1, 2)
        records = tuple(
            seal_body(body, key=key, epoch=1, sequence=index + 10)
            for index, body in enumerate(bodies)
        )
        self.assertEqual({len(record) for record in records}, {CELL_RECORD_BYTES})
        decoded = tuple(
            open_record(
                record,
                key=key,
                expected_epoch=1,
                expected_sequence=index + 10,
            )[2]
            for index, record in enumerate(records)
        )
        self.assertIsInstance(decoded[0], T1DataFrame)
        self.assertIsInstance(decoded[1], T1AckFrame)
        self.assertIsInstance(decoded[2], T1ChaffFrame)
        self.assertTrue(decoded[1].complete)

    def test_retransmission_uses_fresh_padding_and_ciphertext(self) -> None:
        frame = split_message(self._message(), transmission_id=b"R" * 16)[0]
        first_body = encode_data_body(frame, rng=Random(10))
        second_body = encode_data_body(frame, rng=Random(11))
        self.assertNotEqual(first_body, second_body)
        self.assertEqual(decode_body(first_body), decode_body(second_body))
        key = derive_link_key(5, 0, 1)
        first = seal_body(first_body, key=key, epoch=1, sequence=1)
        second = seal_body(second_body, key=key, epoch=1, sequence=2)
        self.assertNotEqual(first, second)

    def test_ack_rejects_bits_outside_fragment_count(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside fragment count"):
            encode_ack_body(
                crypto_suite_id=R1_SUITE_ID,
                transmission_id=b"A" * 16,
                fragment_count=2,
                acknowledged_bitmap=0b100,
                ack_delay_ms=0,
            )

    def test_tracked_t1_vectors_are_reproducible(self) -> None:
        tracked = json.loads(
            Path("spec/t1-test-vectors.json").read_text(encoding="utf-8")
        )
        self.assertEqual(tracked, build_vectors())
        self.assertEqual(tracked["record_bytes"], CELL_RECORD_BYTES)
        self.assertTrue(tracked["data_retry"]["fresh_body"])
        self.assertTrue(tracked["data_retry"]["fresh_record"])


if __name__ == "__main__":
    unittest.main()
