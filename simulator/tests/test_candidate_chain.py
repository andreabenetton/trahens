# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import unittest

os.environ.setdefault("TRAHENS_TEST_CRYPTO", "1")

from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import build_endpoint_keys, reply_blind_public
from trahens_crypto.candidate import (
    build_responder_payload,
    commit_proof,
    open_candidate_chain,
    ready_proof,
)
from tools.vector_candidate_support import (
    seal_responder_candidate_deterministic,
    wrap_relay_candidate_deterministic,
)


class CandidateChainTests(unittest.TestCase):
    def test_nested_candidate_chain_opens_and_verifies(self) -> None:
        endpoint = build_endpoint_keys(b"candidate-chain")
        x0 = r255.scalar_from_label(b"candidate-x0")
        x0_public = r255.scalarmult_base(x0)
        b1 = r255.scalar_from_label(b"candidate-b1")
        b2 = r255.scalar_from_label(b"candidate-b2")
        x1_public = reply_blind_public(x0_public, b1)
        x2_public = reply_blind_public(x1_public, b2)
        challenge = b"Q" * 32
        payload = build_responder_payload(
            endpoint,
            responder_id=12,
            offer_expires_ms=500,
            final_reply_public=x2_public,
            commit_challenge=challenge,
            responder_nonce=b"N" * 16,
        )
        blob = seal_responder_candidate_deterministic(
            x2_public,
            payload,
            ephemeral_secret=r255.scalar_from_label(b"candidate-e2"),
        )
        blob = wrap_relay_candidate_deterministic(
            x1_public,
            blinding_factor=b2,
            child_candidate_token=b"2" * 16,
            forward_label=b"F" * 16,
            child_blob=blob,
            ephemeral_secret=r255.scalar_from_label(b"candidate-e1"),
        )
        blob = wrap_relay_candidate_deterministic(
            x0_public,
            blinding_factor=b1,
            child_candidate_token=b"1" * 16,
            forward_label=b"G" * 16,
            child_blob=blob,
            ephemeral_secret=r255.scalar_from_label(b"candidate-e0"),
        )
        opened = open_candidate_chain(
            x0,
            blob,
            expected_address=endpoint.address,
            expected_descriptor=endpoint.descriptor,
        )
        self.assertEqual(opened.layer_count, 3)
        self.assertEqual(opened.payload.responder_id, 12)
        self.assertEqual(opened.payload.commit_challenge, challenge)
        self.assertEqual(r255.scalarmult_base(opened.final_reply_secret), x2_public)
        self.assertNotEqual(commit_proof(challenge, endpoint.address), ready_proof(challenge, endpoint.address))


if __name__ == "__main__":
    unittest.main()
