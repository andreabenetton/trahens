# SPDX-License-Identifier: Apache-2.0

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trahens_crypto.advertisement import (
    Advertisement,
    AdvertisementError,
    decode,
    encode,
)
from trahens_spec.generated import (
    B12_DATAGRAM_ADVERTISEMENT,
    BYTES_B12_ADVERTISEMENT,
)

ROOT = Path(__file__).resolve().parents[2]


def public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


class AdvertisementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.seed = bytes(range(32))
        self.key = public(self.seed)
        self.advertisement = Advertisement(
            3, self.key, 1_757_000_000_000, 1, 1, (2,), (3,), (4,), (0x0101,)
        )

    def test_a_datagram_is_exactly_one_cell(self) -> None:
        # Discovery precedes any link, so there is no encryption to hide a
        # length under; a variable width would leak shape on the wire.
        datagram = encode(self.advertisement, self.seed)
        self.assertEqual(len(datagram), BYTES_B12_ADVERTISEMENT)

    def test_it_carries_the_reserved_discriminator(self) -> None:
        # 0x01-0x7f is reachable by neither a handshake record nor a W2 cell.
        datagram = encode(self.advertisement, self.seed)
        self.assertEqual(datagram[0], B12_DATAGRAM_ADVERTISEMENT)
        self.assertNotEqual(datagram[0], 0)
        self.assertLess(datagram[0], 0x80)

    def test_it_round_trips(self) -> None:
        self.assertEqual(decode(encode(self.advertisement, self.seed)), self.advertisement)

    def test_tampering_with_any_field_is_refused(self) -> None:
        datagram = bytearray(encode(self.advertisement, self.seed))
        # The signature covers the discriminator and the whole framed region,
        # padding included, so a change anywhere before it is caught.
        for offset in (0, 1, 40, 300, 900):
            tampered = bytearray(datagram)
            tampered[offset] ^= 0x01
            with self.assertRaises(AdvertisementError, msg=f"offset {offset}"):
                decode(bytes(tampered))

    def test_a_tampered_signature_is_refused(self) -> None:
        datagram = bytearray(encode(self.advertisement, self.seed))
        datagram[-1] ^= 0x01
        with self.assertRaises(AdvertisementError):
            decode(bytes(datagram))

    def test_non_zero_padding_is_refused(self) -> None:
        # The padding is inside the signed region, so this is caught at the
        # frame check rather than by the signature; both must refuse it.
        datagram = bytearray(encode(self.advertisement, self.seed))
        datagram[900] = 0x7F
        with self.assertRaises(AdvertisementError):
            decode(bytes(datagram))

    def test_a_wrong_width_is_refused(self) -> None:
        datagram = encode(self.advertisement, self.seed)
        with self.assertRaises(AdvertisementError):
            decode(datagram[:-1])

    def test_another_datagram_type_is_refused(self) -> None:
        datagram = bytearray(encode(self.advertisement, self.seed))
        datagram[0] = 0
        with self.assertRaises(AdvertisementError):
            decode(bytes(datagram))

    def test_a_signature_by_another_key_is_refused(self) -> None:
        # The key that signs must be the key the datagram carries, or an
        # advertisement could be replayed under someone else's identity.
        with self.assertRaises(AdvertisementError):
            decode(encode(self.advertisement, bytes(range(1, 33))))

    def test_an_empty_profile_list_is_refused(self) -> None:
        with self.assertRaises(AdvertisementError):
            encode(
                Advertisement(3, self.key, 1, 1, 1, (), (3,), (4,), (0x0101,)), self.seed
            )

    def test_a_cookie_of_the_wrong_width_is_refused(self) -> None:
        with self.assertRaises(AdvertisementError):
            encode(
                Advertisement(3, self.key, 1, 1, 1, (2,), (3,), (4,), (0x0101,), b"short"),
                self.seed,
            )

    def test_vector_generator_is_reproducible(self) -> None:
        published = ROOT / "spec/b12-advertisement-test-vectors.json"
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory) / "vectors.json"
            subprocess.run(
                [
                    "python",
                    str(ROOT / "tools/generate_advertisement_vectors.py"),
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
            (ROOT / "spec/b12-advertisement-test-vectors.json").read_text(encoding="utf-8")
        )
        for entry in document["cases"]:
            seed = bytes.fromhex(entry["signing_seed"])
            cookie = bytes.fromhex(entry["cookie"]) if entry["cookie"] else None
            advertisement = Advertisement(
                3,
                bytes.fromhex(entry["key"]),
                entry["expiry_ms"],
                entry["capacity_class"],
                entry["auth_modes"],
                tuple(entry["w2_profiles"]),
                tuple(entry["t1_profiles"]),
                tuple(entry["t2_profiles"]),
                tuple(entry["suites"]),
                cookie,
            )
            self.assertEqual(
                encode(advertisement, seed).hex(), entry["datagram"], entry["name"]
            )


if __name__ == "__main__":
    unittest.main()
