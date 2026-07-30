from __future__ import annotations

import unittest
from random import Random

from trahens_codec.m2w2 import (
    CELL_PAYLOAD_BYTES,
    CELL_RECORD_BYTES,
    CandidateRecord,
    CodecError,
    DiscoverRecord,
    MessageType,
    Reassembler,
    decode_cell,
    decode_message,
    derive_link_key,
    encode_candidate,
    encode_discover,
    encode_to_link_cells,
    fragment_message,
    open_link_cell,
)
from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import C1_SUITE_ID, build_endpoint_keys, ure_encrypt
from trahens_crypto.c2_ideal import C2IdealOracle, C2_SUITE_ID
from trahens_crypto.eligibility import R1_SUITE_ID, R1_DISCOVERY_NONCE_BYTES


class M2SuiteAgilityTests(unittest.TestCase):
    def test_c1_and_c2_discover_roundtrip(self) -> None:
        reply_public = r255.scalarmult_base(r255.scalar_from_label(b"m2-reply"))
        c1_endpoint = build_endpoint_keys(b"m2-c1")
        c1 = DiscoverRecord(
            branch_token=b"A" * 16,
            hop_remaining=3,
            fanout_class=2,
            expiry_class=1,
            options=0,
            reply_public_key=reply_public,
            eligibility_capsule=ure_encrypt(
                c1_endpoint.eligibility_public,
                r0=r255.scalar_from_label(b"m2-r0"),
                r1=r255.scalar_from_label(b"m2-r1"),
            ),
            crypto_suite_id=C1_SUITE_ID,
        )
        encoded_c1 = encode_discover(c1)
        decoded_c1 = decode_message(encoded_c1)
        self.assertEqual(decoded_c1.crypto_suite_id, C1_SUITE_ID)
        self.assertEqual(bytes(decoded_c1.eligibility_capsule), c1.eligibility_capsule.encode())

        oracle = C2IdealOracle(b"m2-c2")
        endpoint = oracle.keygen(b"target")
        capsule = oracle.encrypt(endpoint.public)
        c2 = DiscoverRecord(
            branch_token=b"B" * 16,
            hop_remaining=5,
            fanout_class=3,
            expiry_class=1,
            options=0,
            reply_public_key=reply_public,
            eligibility_capsule=capsule,
            crypto_suite_id=C2_SUITE_ID,
        )
        encoded_c2 = encode_discover(c2)
        decoded_c2 = decode_message(encoded_c2)
        self.assertEqual(decoded_c2, c2)
        self.assertLess(len(encoded_c1), CELL_PAYLOAD_BYTES)
        self.assertLess(len(encoded_c2), CELL_PAYLOAD_BYTES)


    def test_r1_discover_roundtrip_and_no_capability_bytes(self) -> None:
        reply_public = r255.scalarmult_base(r255.scalar_from_label(b"m2-r1-reply"))
        capability = b"private-capability-never-on-discover"[:32]
        nonce = b"R" * R1_DISCOVERY_NONCE_BYTES
        record = DiscoverRecord(
            branch_token=b"F" * 16,
            hop_remaining=4,
            fanout_class=2,
            expiry_class=1,
            options=0,
            reply_public_key=reply_public,
            eligibility_capsule=nonce,
            crypto_suite_id=R1_SUITE_ID,
        )
        encoded = encode_discover(record)
        self.assertEqual(decode_message(encoded), record)
        self.assertNotIn(capability, encoded)
        with self.assertRaises(CodecError):
            encode_discover(
                DiscoverRecord(
                    branch_token=b"F" * 16,
                    hop_remaining=4,
                    fanout_class=2,
                    expiry_class=1,
                    options=0,
                    reply_public_key=reply_public,
                    eligibility_capsule=b"short",
                    crypto_suite_id=R1_SUITE_ID,
                )
            )

    def test_w2_preserves_suite_across_fragment_reassembly(self) -> None:
        candidate = CandidateRecord(
            candidate_token=b"C" * 16,
            expiry_class=1,
            layer_count=12,
            candidate_blob=b"candidate" * 700,
            crypto_suite_id=C2_SUITE_ID,
        )
        message = encode_candidate(candidate)
        key = derive_link_key(8, 1, 2)
        cells = encode_to_link_cells(
            message,
            key=key,
            epoch=1,
            first_sequence=10,
            message_local_id=b"M" * 16,
            rng=Random(8),
        )
        self.assertGreater(len(cells), 1)
        self.assertEqual({len(cell) for cell in cells}, {CELL_RECORD_BYTES})
        fragments = []
        for index, cell in enumerate(cells):
            _, _, body = open_link_cell(
                cell,
                key=key,
                expected_epoch=1,
                expected_sequence=10 + index,
            )
            fragment = decode_cell(body)
            self.assertEqual(fragment.crypto_suite_id, C2_SUITE_ID)
            fragments.append(fragment)
        reassembler = Reassembler(timeout_ms=20)
        assembled = None
        for fragment in reversed(fragments):
            value = reassembler.accept("link", fragment, now_ms=1)
            if value is not None:
                assembled = value
        self.assertEqual(assembled, message)
        self.assertEqual(decode_message(assembled), candidate)

    def test_fragment_suite_mismatch_invalidates_context(self) -> None:
        c1_message = encode_candidate(
            CandidateRecord(
                candidate_token=b"D" * 16,
                expiry_class=1,
                layer_count=1,
                candidate_blob=b"x" * 1500,
                crypto_suite_id=C1_SUITE_ID,
            )
        )
        c2_message = encode_candidate(
            CandidateRecord(
                candidate_token=b"E" * 16,
                expiry_class=1,
                layer_count=1,
                candidate_blob=b"y" * 1500,
                crypto_suite_id=C2_SUITE_ID,
            )
        )
        first = decode_cell(
            fragment_message(c1_message, message_local_id=b"Z" * 16, rng=Random(1))[0]
        )
        second = decode_cell(
            fragment_message(c2_message, message_local_id=b"Z" * 16, rng=Random(2))[1]
        )
        reassembler = Reassembler(timeout_ms=10)
        self.assertIsNone(reassembler.accept("link", first, now_ms=0))
        with self.assertRaisesRegex(CodecError, "inconsistent"):
            reassembler.accept("link", second, now_ms=1)
        self.assertEqual(reassembler.live_messages, 0)


if __name__ == "__main__":
    unittest.main()
