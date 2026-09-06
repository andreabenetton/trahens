# SPDX-License-Identifier: Apache-2.0

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from trahens_crypto.route import (
    ENDPOINT_TO_GATEWAY,
    GATEWAY_TO_ENDPOINT,
    RouteError,
    control_aad,
    route_keys,
    route_nonce,
    route_open,
    route_seal,
)
from trahens_spec.generated import (
    BYTES_ROUTE_NONCE,
    DOMAIN_P1_CONTROL,
)

ROOT = Path(__file__).resolve().parents[2]


class RouteChannelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = bytes(range(32))
        self.transcript = bytes(range(32, 64))
        self.keys = route_keys(self.secret, self.transcript)

    def test_the_two_directions_do_not_share_a_key(self) -> None:
        self.assertNotEqual(self.keys.endpoint_to_gateway, self.keys.gateway_to_endpoint)

    def test_a_different_offer_transcript_derives_different_keys(self) -> None:
        # The property the expansion context exists for: a route secret is
        # usable only under the offer that was actually selected.
        other = route_keys(self.secret, bytes(range(64, 96)))
        self.assertNotEqual(other.endpoint_to_gateway, self.keys.endpoint_to_gateway)
        self.assertNotEqual(other.gateway_to_endpoint, self.keys.gateway_to_endpoint)

    def test_a_zero_route_secret_is_refused(self) -> None:
        with self.assertRaises(RouteError):
            route_keys(bytes(32), self.transcript)

    def test_the_nonce_is_direction_then_sequence(self) -> None:
        nonce = route_nonce(GATEWAY_TO_ENDPOINT, 0x0102030405060708)
        self.assertEqual(len(nonce), BYTES_ROUTE_NONCE)
        self.assertEqual(nonce, bytes([0, 0, 0, 1]) + bytes.fromhex("0102030405060708"))

    def test_the_directions_cannot_collide_on_a_nonce(self) -> None:
        # The direction has its own field rather than a bit of the sequence, so
        # no sequence in one direction reaches a nonce used by the other.
        forward = {route_nonce(ENDPOINT_TO_GATEWAY, n) for n in range(64)}
        reverse = {route_nonce(GATEWAY_TO_ENDPOINT, n) for n in range(64)}
        self.assertFalse(forward & reverse)

    def test_the_control_aad_carries_its_domain(self) -> None:
        aad = control_aad(34, 7)
        self.assertTrue(aad.startswith(DOMAIN_P1_CONTROL))
        self.assertEqual(aad[len(DOMAIN_P1_CONTROL) :], bytes([34]) + (7).to_bytes(4, "big"))

    def test_a_record_round_trips_with_its_sequence(self) -> None:
        aad = control_aad(34, 0)
        sealed = route_seal(
            self.keys.direction(ENDPOINT_TO_GATEWAY), ENDPOINT_TO_GATEWAY, 9, b"body", aad
        )
        sequence, plaintext = route_open(
            self.keys.direction(ENDPOINT_TO_GATEWAY), ENDPOINT_TO_GATEWAY, sealed, aad
        )
        self.assertEqual(sequence, 9)
        self.assertEqual(plaintext, b"body")

    def test_a_reflected_record_does_not_open(self) -> None:
        aad = control_aad(34, 0)
        sealed = route_seal(
            self.keys.direction(ENDPOINT_TO_GATEWAY), ENDPOINT_TO_GATEWAY, 0, b"body", aad
        )
        with self.assertRaises(RouteError):
            route_open(
                self.keys.direction(GATEWAY_TO_ENDPOINT), GATEWAY_TO_ENDPOINT, sealed, aad
            )

    def test_a_record_does_not_open_under_another_message_type(self) -> None:
        # The AAD binds the message type, so a sealed body cannot be presented
        # as a different control message.
        sealed = route_seal(
            self.keys.direction(ENDPOINT_TO_GATEWAY),
            ENDPOINT_TO_GATEWAY,
            0,
            b"body",
            control_aad(34, 0),
        )
        with self.assertRaises(RouteError):
            route_open(
                self.keys.direction(ENDPOINT_TO_GATEWAY),
                ENDPOINT_TO_GATEWAY,
                sealed,
                control_aad(35, 0),
            )

    def test_a_record_does_not_open_under_another_generation(self) -> None:
        sealed = route_seal(
            self.keys.direction(ENDPOINT_TO_GATEWAY),
            ENDPOINT_TO_GATEWAY,
            0,
            b"body",
            control_aad(34, 0),
        )
        with self.assertRaises(RouteError):
            route_open(
                self.keys.direction(ENDPOINT_TO_GATEWAY),
                ENDPOINT_TO_GATEWAY,
                sealed,
                control_aad(34, 1),
            )

    def test_a_truncated_record_is_refused(self) -> None:
        with self.assertRaises(RouteError):
            route_open(
                self.keys.direction(ENDPOINT_TO_GATEWAY),
                ENDPOINT_TO_GATEWAY,
                bytes(BYTES_ROUTE_NONCE),
                b"",
            )

    def test_vector_generator_is_reproducible(self) -> None:
        published = ROOT / "spec/route-channel-test-vectors.json"
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory) / "vectors.json"
            subprocess.run(
                [
                    "python",
                    str(ROOT / "tools/generate_route_vectors.py"),
                    "--output",
                    str(generated),
                ],
                check=True,
                cwd=ROOT,
                env={"PYTHONPATH": str(ROOT / "simulator"), "PATH": "/usr/bin:/bin"},
            )
            self.assertEqual(published.read_bytes(), generated.read_bytes())

    def test_the_published_vectors_reproduce(self) -> None:
        document = json.loads(
            (ROOT / "spec/route-channel-test-vectors.json").read_text(encoding="utf-8")
        )
        keys = route_keys(
            bytes.fromhex(document["route_secret"]),
            bytes.fromhex(document["offer_transcript_hash"]),
        )
        self.assertEqual(keys.endpoint_to_gateway.hex(), document["endpoint_to_gateway_key"])
        self.assertEqual(keys.gateway_to_endpoint.hex(), document["gateway_to_endpoint_key"])
        for record in document["records"]:
            direction = record["direction"]
            aad = control_aad(record["message_type"], record["generation"])
            self.assertEqual(aad.hex(), record["aad"], record["name"])
            sealed = route_seal(
                keys.direction(direction),
                direction,
                record["sequence"],
                bytes.fromhex(record["plaintext"]),
                aad,
            )
            self.assertEqual(sealed.hex(), record["sealed"], record["name"])


if __name__ == "__main__":
    unittest.main()
