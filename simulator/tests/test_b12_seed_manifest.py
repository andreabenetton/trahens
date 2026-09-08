# SPDX-License-Identifier: Apache-2.0
"""The seed manifest, and what refusing to parse one protects.

ADR 0050. Most of these are refusals, because a manifest is a file an attacker
may hand a joiner and the reader is the only thing standing between the two.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trahens_crypto.seed import (
    FAMILY_V4,
    FAMILY_V6,
    SeedEntry,
    SeedError,
    SeedManifest,
    decode,
    encode,
)
from trahens_spec.generated import LIMIT_MAX_SEED_ENTRIES, LIMIT_SEED_MANIFEST_TTL_MS, VERSION

ROOT = Path(__file__).resolve().parents[2]
SEED = bytes.fromhex("5a" * 32)
OTHER_SEED = bytes.fromhex("a5" * 32)


def public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def entry(index: int = 0, family: int = FAMILY_V4) -> SeedEntry:
    address = bytes([10, 201, 0, index + 1]) if family == FAMILY_V4 else bytes([index]) * 16
    return SeedEntry(bytes([0xC0 + index]) * 32, family, address, 45301 + index)


def manifest(entries=None, issued: int = 1_000, expiry: int | None = None) -> SeedManifest:
    return SeedManifest(
        VERSION,
        issued,
        issued + 3_600_000 if expiry is None else expiry,
        tuple(entries if entries is not None else (entry(),)),
    )


class SeedManifestTests(unittest.TestCase):
    def test_it_round_trips(self) -> None:
        original = manifest((entry(0), entry(1, FAMILY_V6)))
        parsed = decode(encode(original, SEED), public(SEED), 2_000)
        self.assertEqual(parsed, original)

    def test_a_signature_by_another_key_is_refused(self) -> None:
        document = encode(manifest(), OTHER_SEED)
        with self.assertRaises(SeedError):
            decode(document, public(SEED), 2_000)

    def test_tampering_with_any_byte_is_refused(self) -> None:
        # The signature covers the whole body, so no field is alterable --
        # including the count, which is what stops an entry being dropped.
        document = bytearray(encode(manifest((entry(0), entry(1))), SEED))
        for position in range(0, len(document), 7):
            mutated = bytearray(document)
            mutated[position] ^= 0x01
            with self.subTest(position=position):
                with self.assertRaises(SeedError):
                    decode(bytes(mutated), public(SEED), 2_000)

    def test_an_expired_manifest_is_refused(self) -> None:
        document = encode(manifest(issued=1_000, expiry=2_000), SEED)
        self.assertTrue(decode(document, public(SEED), 1_999))
        with self.assertRaises(SeedError):
            decode(document, public(SEED), 2_000)

    def test_an_unbounded_lifetime_cannot_be_issued(self) -> None:
        # Without this the expiry would be decoration: an issuer could write one
        # that never lapses.
        with self.assertRaises(SeedError):
            encode(
                manifest(issued=0, expiry=LIMIT_SEED_MANIFEST_TTL_MS + 1),
                SEED,
            )

    def test_too_many_entries_cannot_be_issued(self) -> None:
        entries = tuple(entry(index % 200) for index in range(LIMIT_MAX_SEED_ENTRIES + 1))
        with self.assertRaises(SeedError):
            encode(manifest(entries), SEED)

    def test_an_empty_manifest_is_refused(self) -> None:
        with self.assertRaises(SeedError):
            encode(manifest(()), SEED)

    def test_a_declared_count_beyond_the_bound_is_refused_before_parsing(self) -> None:
        # The count is attacker-chosen, so it is checked before any entry is
        # read: a reader must not be made to work for a number it was handed.
        body = bytearray(manifest().body())
        body[17] = LIMIT_MAX_SEED_ENTRIES + 1
        signature = Ed25519PrivateKey.from_private_bytes(SEED).sign(
            b"Trahens-B12-seed-manifest-v1" + bytes(body)
        )
        with self.assertRaises(SeedError):
            decode(bytes(body) + signature, public(SEED), 2_000)

    def test_an_unknown_address_family_is_refused(self) -> None:
        body = bytearray(manifest().body())
        body[18 + 32] = 7
        signature = Ed25519PrivateKey.from_private_bytes(SEED).sign(
            b"Trahens-B12-seed-manifest-v1" + bytes(body)
        )
        with self.assertRaises(SeedError):
            decode(bytes(body) + signature, public(SEED), 2_000)

    def test_trailing_bytes_after_the_declared_entries_are_refused(self) -> None:
        # A reader that ignored a tail would accept a document whose signed
        # region it only partly read.
        body = manifest().body() + b"\x00"
        signature = Ed25519PrivateKey.from_private_bytes(SEED).sign(
            b"Trahens-B12-seed-manifest-v1" + body
        )
        with self.assertRaises(SeedError):
            decode(body + signature, public(SEED), 2_000)

    def test_an_address_that_does_not_match_its_family_is_refused(self) -> None:
        with self.assertRaises(SeedError):
            SeedEntry(bytes(32), FAMILY_V6, bytes(4), 1).encode()

    def test_a_manifest_is_not_padded(self) -> None:
        # ADR 0050 D18: a file has no observer its length would inform, so the
        # advertisement's fixed width does not carry over. Two manifests with
        # different entry counts must differ in length.
        one = len(encode(manifest((entry(0),)), SEED))
        two = len(encode(manifest((entry(0), entry(1))), SEED))
        self.assertNotEqual(one, two)

    def test_the_published_vectors_reproduce(self) -> None:
        published = json.loads(
            (ROOT / "spec/b12-seed-manifest-vectors.json").read_text(encoding="utf-8")
        )
        seed_public = bytes.fromhex(published["seed_public_key"])
        for case in published["vectors"]:
            with self.subTest(label=case["label"]):
                parsed = decode(
                    bytes.fromhex(case["document"]), seed_public, case["issued_ms"]
                )
                self.assertEqual(parsed.issued_ms, case["issued_ms"])
                self.assertEqual(parsed.expiry_ms, case["expiry_ms"])
                self.assertEqual(len(parsed.entries), len(case["entries"]))
                for got, want in zip(parsed.entries, case["entries"]):
                    self.assertEqual(got.advertisement_key.hex(), want["advertisement_key"])
                    self.assertEqual(got.family, want["family"])
                    self.assertEqual(got.address.hex(), want["address"])
                    self.assertEqual(got.port, want["port"])

    def test_vector_generator_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory) / "vectors.json"
            subprocess.run(
                [
                    "python",
                    str(ROOT / "tools/generate_seed_vectors.py"),
                    "--output",
                    str(generated),
                ],
                check=True,
                cwd=ROOT,
                env={"PYTHONPATH": str(ROOT / "simulator"), "PATH": "/usr/bin:/bin:/usr/local/bin"},
            )
            self.assertEqual(
                generated.read_bytes(),
                (ROOT / "spec/b12-seed-manifest-vectors.json").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
