from __future__ import annotations

import unittest
from random import Random

from trahens_codec.c1 import (
    BODY_BYTES,
    LINK_RECORD_BYTES,
    CandidateRecord,
    CodecError,
    DiscoverRecord,
    MessageType,
    decode_body,
    derive_link_key,
    encode_candidate,
    encode_chaff,
    encode_discover,
    open_link_record,
    seal_link_record,
)
from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import build_endpoint_keys, ure_encrypt


class WireCodecTests(unittest.TestCase):
    def test_all_bodies_and_link_records_have_one_constant_length(self) -> None:
        rng = Random(7)
        endpoint = build_endpoint_keys(b"wire-size")
        reply_secret = r255.scalar_from_label(b"wire-reply")
        discover = encode_discover(
            DiscoverRecord(
                branch_token=b"B" * 16,
                hop_remaining=3,
                fanout_class=2,
                expiry_class=1,
                options=0,
                reply_public_key=r255.scalarmult_base(reply_secret),
                eligibility_capsule=ure_encrypt(
                    endpoint.eligibility_public,
                    r0=r255.scalar_from_label(b"wire-r0"),
                    r1=r255.scalar_from_label(b"wire-r1"),
                ),
            ),
            rng=rng,
        )
        candidate = encode_candidate(
            CandidateRecord(
                candidate_token=b"C" * 16,
                expiry_class=1,
                layer_count=2,
                candidate_blob=b"candidate",
            ),
            rng=rng,
        )
        chaff = encode_chaff(rng=rng)
        self.assertEqual({len(discover), len(candidate), len(chaff)}, {BODY_BYTES})

        key = derive_link_key(1, 2, 3)
        sealed = [
            seal_link_record(body, key=key, epoch=1, sequence=index)
            for index, body in enumerate((discover, candidate, chaff), start=1)
        ]
        self.assertEqual({len(record) for record in sealed}, {LINK_RECORD_BYTES})
        self.assertEqual(len(set(sealed)), 3)

    def test_discover_roundtrip_and_link_authentication(self) -> None:
        endpoint = build_endpoint_keys(b"wire-roundtrip")
        reply_secret = r255.scalar_from_label(b"wire-roundtrip-reply")
        original = DiscoverRecord(
            branch_token=b"D" * 16,
            hop_remaining=4,
            fanout_class=3,
            expiry_class=2,
            options=1,
            reply_public_key=r255.scalarmult_base(reply_secret),
            eligibility_capsule=ure_encrypt(
                endpoint.eligibility_public,
                r0=r255.scalar_from_label(b"wire-roundtrip-r0"),
                r1=r255.scalar_from_label(b"wire-roundtrip-r1"),
            ),
        )
        body = encode_discover(original, rng=Random(9))
        key = derive_link_key(11, 0, 1)
        wire = seal_link_record(body, key=key, epoch=1, sequence=5)
        _, _, opened = open_link_record(
            wire,
            key=key,
            expected_epoch=1,
            expected_sequence=5,
        )
        decoded = decode_body(opened)
        self.assertEqual(decoded, original)

        tampered = wire[:-1] + bytes([wire[-1] ^ 1])
        with self.assertRaisesRegex(CodecError, "link authentication failed"):
            open_link_record(tampered, key=key)

    def test_candidate_length_is_canonical(self) -> None:
        body = encode_candidate(
            CandidateRecord(
                candidate_token=b"E" * 16,
                expiry_class=1,
                layer_count=1,
                candidate_blob=b"payload",
            ),
            rng=Random(1),
        )
        decoded = decode_body(body)
        self.assertEqual(decoded.candidate_blob, b"payload")
        self.assertEqual(decoded.layer_count, 1)
        with self.assertRaises(CodecError):
            decode_body(body[:-1])

    def test_message_type_is_inside_link_ciphertext(self) -> None:
        body = encode_chaff(rng=Random(2))
        self.assertEqual(body[0], MessageType.CHAFF)
        key = derive_link_key(2, 4, 5)
        wire = seal_link_record(body, key=key, epoch=3, sequence=8)
        self.assertEqual(wire[:12], (3).to_bytes(4, "big") + (8).to_bytes(8, "big"))
        self.assertNotEqual(wire[12 : 12 + BODY_BYTES], body)


if __name__ == "__main__":
    unittest.main()
