from __future__ import annotations

import unittest
from random import Random

from trahens_codec.m1w2 import (
    CELL_PAYLOAD_BYTES,
    CELL_RECORD_BYTES,
    CandidateRecord,
    CodecError,
    ControlRecord,
    DiscoverRecord,
    MessageType,
    Reassembler,
    decode_cell,
    decode_message,
    decode_varuint,
    derive_link_key,
    encode_candidate,
    encode_chaff,
    encode_control,
    encode_discover,
    encode_to_link_cells,
    encode_varuint,
    fragment_message,
    open_link_cell,
)
from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import build_endpoint_keys, ure_encrypt


class M1MessageCodecTests(unittest.TestCase):
    def test_varuint_is_minimal_and_canonical(self) -> None:
        for value in (0, 1, 127, 128, 255, 16_383, 16_384, 0xFFFFFFFF):
            encoded = encode_varuint(value)
            decoded, cursor = decode_varuint(encoded)
            self.assertEqual(decoded, value)
            self.assertEqual(cursor, len(encoded))
        with self.assertRaisesRegex(CodecError, "non-canonical"):
            decode_varuint(b"\x80\x00")
        with self.assertRaises(CodecError):
            decode_varuint(b"\x80")

    def test_discover_roundtrip_has_no_semantic_padding(self) -> None:
        endpoint = build_endpoint_keys(b"m1-discover")
        reply_secret = r255.scalar_from_label(b"m1-reply")
        original = DiscoverRecord(
            branch_token=b"D" * 16,
            hop_remaining=4,
            fanout_class=3,
            expiry_class=2,
            options=1,
            reply_public_key=r255.scalarmult_base(reply_secret),
            eligibility_capsule=ure_encrypt(
                endpoint.eligibility_public,
                r0=r255.scalar_from_label(b"m1-r0"),
                r1=r255.scalar_from_label(b"m1-r1"),
            ),
        )
        encoded = encode_discover(original)
        self.assertLess(len(encoded), CELL_PAYLOAD_BYTES)
        self.assertEqual(decode_message(encoded), original)
        with self.assertRaises(CodecError):
            decode_message(encoded + b"\x00")

    def test_variable_candidate_and_control_roundtrip(self) -> None:
        candidate = CandidateRecord(
            candidate_token=b"C" * 16,
            expiry_class=1,
            layer_count=11,
            candidate_blob=bytes(range(256)) * 20,
        )
        encoded_candidate = encode_candidate(candidate)
        self.assertGreater(len(encoded_candidate), CELL_PAYLOAD_BYTES)
        self.assertEqual(decode_message(encoded_candidate), candidate)

        control = ControlRecord(
            message_type=MessageType.COMMIT,
            local_label=b"L" * 16,
            generation=7,
            expiry_class=1,
            protected_body=b"proof" * 300,
        )
        self.assertEqual(decode_message(encode_control(control)), control)
        self.assertEqual(decode_message(encode_chaff()), MessageType.CHAFF)


class W2CellCodecTests(unittest.TestCase):
    def test_every_encrypted_cell_has_one_fixed_length(self) -> None:
        messages = (
            encode_chaff(),
            encode_control(
                ControlRecord(
                    message_type=MessageType.READY,
                    local_label=b"R" * 16,
                    generation=1,
                    expiry_class=1,
                    protected_body=b"ready",
                )
            ),
            encode_candidate(
                CandidateRecord(
                    candidate_token=b"Q" * 16,
                    expiry_class=1,
                    layer_count=9,
                    candidate_blob=b"x" * 3_000,
                )
            ),
        )
        key = derive_link_key(9, 1, 2)
        sequence = 1
        counts = []
        for index, message in enumerate(messages, start=1):
            cells = encode_to_link_cells(
                message,
                key=key,
                epoch=1,
                first_sequence=sequence,
                message_local_id=index.to_bytes(16, "big"),
                rng=Random(index),
            )
            counts.append(len(cells))
            self.assertEqual({len(cell) for cell in cells}, {CELL_RECORD_BYTES})
            sequence += len(cells)
        self.assertEqual(counts[0], 1)
        self.assertEqual(counts[1], 1)
        self.assertGreater(counts[2], 1)

    def test_out_of_order_reassembly_and_link_authentication(self) -> None:
        original = encode_candidate(
            CandidateRecord(
                candidate_token=b"A" * 16,
                expiry_class=1,
                layer_count=12,
                candidate_blob=b"candidate" * 700,
            )
        )
        key = derive_link_key(5, 3, 4)
        wire = list(
            encode_to_link_cells(
                original,
                key=key,
                epoch=2,
                first_sequence=10,
                message_local_id=b"M" * 16,
                rng=Random(5),
            )
        )
        fragments = []
        for offset, encoded in enumerate(wire):
            _, _, body = open_link_cell(
                encoded,
                key=key,
                expected_epoch=2,
                expected_sequence=10 + offset,
            )
            fragments.append(decode_cell(body))
        reassembler = Reassembler(timeout_ms=20)
        completed = None
        for fragment in reversed(fragments):
            candidate = reassembler.accept((3, 4), fragment, now_ms=1)
            if candidate is not None:
                completed = candidate
        self.assertEqual(completed, original)
        self.assertEqual(decode_message(completed), decode_message(original))
        self.assertEqual(reassembler.stats().completed, 1)

        tampered = wire[0][:-1] + bytes([wire[0][-1] ^ 1])
        with self.assertRaisesRegex(CodecError, "link authentication failed"):
            open_link_cell(tampered, key=key)

    def test_duplicate_conflict_timeout_and_capacity_are_bounded(self) -> None:
        message = encode_candidate(
            CandidateRecord(
                candidate_token=b"B" * 16,
                expiry_class=1,
                layer_count=7,
                candidate_blob=b"z" * 2_000,
            )
        )
        bodies = fragment_message(
            message,
            message_local_id=b"I" * 16,
            rng=Random(2),
        )
        first = decode_cell(bodies[0])
        second = decode_cell(bodies[1])
        reassembler = Reassembler(
            timeout_ms=5,
            max_messages=1,
            max_reserved_bytes=4_000,
        )
        self.assertIsNone(reassembler.accept("peer", first, now_ms=0))
        self.assertIsNone(reassembler.accept("peer", first, now_ms=1))
        self.assertEqual(reassembler.stats().duplicate_fragments, 1)
        self.assertEqual(reassembler.expire(5), 1)
        self.assertEqual(reassembler.stats().expired_messages, 1)

        # Recreate the first message, then exceed the one-message capacity with
        # a distinct adjacent-link-local identifier.
        self.assertIsNone(reassembler.accept("peer", first, now_ms=6))
        other = decode_cell(
            fragment_message(
                message,
                message_local_id=b"J" * 16,
                rng=Random(3),
            )[0]
        )
        with self.assertRaisesRegex(CodecError, "capacity"):
            reassembler.accept("peer", other, now_ms=6)

        # A conflicting duplicate invalidates the complete context.
        altered = type(first)(
            message_local_id=first.message_local_id,
            fragment_index=first.fragment_index,
            fragment_count=first.fragment_count,
            fragment_length=first.fragment_length,
            total_message_length=first.total_message_length,
            fragment=bytes([first.fragment[0] ^ 1]) + first.fragment[1:],
        )
        with self.assertRaisesRegex(CodecError, "conflicting"):
            reassembler.accept("peer", altered, now_ms=7)
        self.assertEqual(reassembler.live_messages, 0)
        self.assertEqual(reassembler.stats().metadata_failures, 1)

        # Silence unused variable warning while retaining explicit second-fragment
        # construction as a shape check for the fixture.
        self.assertGreater(second.fragment_length, 0)


if __name__ == "__main__":
    unittest.main()
