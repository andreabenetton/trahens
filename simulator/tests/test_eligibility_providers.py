# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import random
import unittest

from trahens_crypto.c1 import build_endpoint_keys
from trahens_crypto.eligibility import (
    C2K2ExperimentalDisabledSuite,
    EligibilityError,
    R1_CAPABILITY_BYTES,
    R1_DISCOVERY_NONCE_BYTES,
    R1_SUITE_ID,
    R1RendezvousSuite,
    RendezvousRegistry,
    capability_commitment,
    issue_capability,
    make_suite,
)
from trahens_crypto import ristretto as r255
from trahens_sim.event_model import EventLifecycleConfig, TimedRingStep, simulate_event_lifecycle
from trahens_sim.model import Graph


class EligibilityProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rng = random.Random(101)
        self.randbytes = lambda n: bytes(self.rng.getrandbits(8) for _ in range(n))
        self.scalar = lambda label: r255.scalar_from_label(
            self.randbytes(32), dst=b"Trahens-test/" + label
        )
        self.endpoint = build_endpoint_keys(b"eligibility-provider-test")

    def test_r1_replaces_nonsemantic_discovery_nonce(self) -> None:
        suite = R1RendezvousSuite(self.randbytes)
        first = suite.initial_capsule()
        second = suite.transform(first)
        third = suite.transform(second)
        self.assertEqual(suite.suite_id, R1_SUITE_ID)
        self.assertEqual(len(first), R1_DISCOVERY_NONCE_BYTES)
        self.assertEqual(len({first, second, third}), 3)
        self.assertTrue(suite.accepts(third))

    def test_r1_literal_tag_does_not_survive_honest_replacement(self) -> None:
        suite = R1RendezvousSuite(self.randbytes)
        tag = b"tag-marker"
        tagged = suite.apply_test_tag(suite.initial_capsule(), tag)
        self.assertTrue(suite.recognizes_test_tag(tagged, tag))
        transformed = suite.transform(tagged)
        self.assertFalse(suite.recognizes_test_tag(transformed, tag))

    def test_rendezvous_capability_is_one_time_and_expires(self) -> None:
        registry = RendezvousRegistry()
        token = issue_capability(self.randbytes)
        self.assertEqual(len(token), R1_CAPABILITY_BYTES)
        self.assertEqual(len(capability_commitment(token)), 32)
        registry.register(
            gateway_id=7,
            token=token,
            endpoint_handle=b"ephemeral-endpoint-handle",
            now_ms=10,
            ttl_ms=20,
        )
        self.assertEqual(registry.live_records, 1)
        self.assertIsNone(registry.redeem(gateway_id=8, token=token, now_ms=11))
        self.assertEqual(
            registry.redeem(gateway_id=7, token=token, now_ms=12),
            b"ephemeral-endpoint-handle",
        )
        self.assertIsNone(registry.redeem(gateway_id=7, token=token, now_ms=13))
        self.assertEqual(registry.live_records, 0)

        token2 = issue_capability(self.randbytes)
        registry.register(
            gateway_id=7,
            token=token2,
            endpoint_handle=b"other",
            now_ms=20,
            ttl_ms=5,
        )
        self.assertIsNone(registry.redeem(gateway_id=7, token=token2, now_ms=25))
        self.assertEqual(registry.live_records, 0)

    def test_duplicate_and_zero_capabilities_are_rejected(self) -> None:
        registry = RendezvousRegistry()
        token = issue_capability(self.randbytes)
        registry.register(
            gateway_id=1,
            token=token,
            endpoint_handle=b"endpoint",
            now_ms=0,
            ttl_ms=10,
        )
        with self.assertRaises(EligibilityError):
            registry.register(
                gateway_id=1,
                token=token,
                endpoint_handle=b"endpoint",
                now_ms=1,
                ttl_ms=10,
            )
        with self.assertRaises(EligibilityError):
            registry.token_hash(bytes(R1_CAPABILITY_BYTES))

    def test_provider_registry_defaults_can_build_r1(self) -> None:
        suite = make_suite(
            "r1",
            random_bytes=self.randbytes,
            scalar=self.scalar,
            endpoint_keys=self.endpoint,
            seed=b"seed",
        )
        self.assertTrue(suite.network_enabled)
        self.assertFalse(suite.endpoint_specific)


    def test_r1_event_model_erases_cross_hop_literal_tag(self) -> None:
        graph = Graph(5)
        for node in range(4):
            graph.add_edge(node, node + 1)
        result = simulate_event_lifecycle(
            graph,
            EventLifecycleConfig(
                eligibility_profile="r1",
                active_tagging=True,
                rings=(TimedRingStep(4, 1, 1, 40),),
                seed=303,
                discover_delay_min_ms=1,
                discover_delay_max_ms=1,
                candidate_delay_min_ms=1,
                candidate_delay_max_ms=1,
                control_delay_min_ms=1,
                control_delay_max_ms=1,
                responder_offer_delay_min_ms=1,
                responder_offer_delay_max_ms=1,
                max_simulation_ms=240,
            ),
            responders={4},
            malicious_nodes={1, 3},
        )
        self.assertTrue(result.success)
        self.assertGreater(result.tagged_branches_created, 0)
        self.assertEqual(result.tag_observations, 0)
        self.assertTrue(result.cleanup_complete)

    def test_k2_provider_fails_closed(self) -> None:
        suite = C2K2ExperimentalDisabledSuite()
        self.assertFalse(suite.network_enabled)
        self.assertFalse(suite.accepts(b"anything"))
        with self.assertRaises(EligibilityError):
            suite.initial_capsule()
        with self.assertRaises(EligibilityError):
            suite.transform(b"anything")


if __name__ == "__main__":
    unittest.main()
