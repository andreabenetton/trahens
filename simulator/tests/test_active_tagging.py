# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import unittest
from dataclasses import replace

from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import build_endpoint_keys, ure_encrypt, ure_is_eligible, ure_rerandomize
from trahens_crypto.tagging import apply_ratio_tag, matches_ratio_tag
from trahens_sim.event_model import EventLifecycleConfig, TimedRingStep, simulate_event_lifecycle
from trahens_sim.model import Graph


class ActiveTaggingTests(unittest.TestCase):
    def test_ratio_tag_survives_honest_rerandomization(self) -> None:
        endpoint = build_endpoint_keys(b"tag-target")
        tag_scalar = r255.scalar_from_label(b"known-tag")
        capsule = ure_encrypt(
            endpoint.eligibility_public,
            r0=r255.scalar_from_label(b"tag-r0"),
            r1=r255.scalar_from_label(b"tag-r1"),
        )
        tagged = apply_ratio_tag(capsule, tag_scalar)
        washed = ure_rerandomize(
            tagged,
            s0=r255.scalar_from_label(b"tag-s0"),
            s1=r255.scalar_from_label(b"tag-s1"),
        )
        self.assertTrue(matches_ratio_tag(washed, tag_scalar))
        self.assertFalse(ure_is_eligible(endpoint.eligibility_secret, washed))

    def test_integrated_model_exposes_colluding_ratio_tag(self) -> None:
        graph = Graph(4)
        graph.add_edge(0, 1)
        graph.add_edge(1, 2)
        graph.add_edge(2, 3)
        base = EventLifecycleConfig(
            rings=(TimedRingStep(3, 1, 1, 30),),
            seed=19,
            eligibility_profile="c1",
            discover_delay_min_ms=1,
            discover_delay_max_ms=1,
            candidate_delay_min_ms=1,
            candidate_delay_max_ms=1,
            control_delay_min_ms=1,
            control_delay_max_ms=1,
            responder_offer_delay_min_ms=1,
            responder_offer_delay_max_ms=1,
            max_simulation_ms=180,
        )
        clean = simulate_event_lifecycle(
            graph,
            base,
            responders={3},
            malicious_nodes={1, 2},
        )
        tagged = simulate_event_lifecycle(
            graph,
            replace(base, active_tagging=True),
            responders={3},
            malicious_nodes={1, 2},
        )
        self.assertTrue(clean.success)
        self.assertFalse(tagged.success)
        self.assertGreater(tagged.tagged_branches_created, 0)
        self.assertGreater(tagged.tag_observations, 0)
        self.assertGreater(tagged.crypto_failures, 0)

    def test_adjacent_link_tampering_is_rejected_before_protocol_processing(self) -> None:
        graph = Graph(2)
        graph.add_edge(0, 1)
        config = EventLifecycleConfig(
            rings=(TimedRingStep(1, 1, 1, 10),),
            seed=27,
            wire_tamper_probability=1.0,
            max_simulation_ms=80,
        )
        result = simulate_event_lifecycle(graph, config, responders={1})
        self.assertFalse(result.success)
        self.assertGreater(result.wire_auth_failures, 0)
        self.assertEqual(result.legitimate_branch_allocations, 0)


if __name__ == "__main__":
    unittest.main()
