# SPDX-License-Identifier: Apache-2.0

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from trahens_crypto.cookie import CookieError, issue, verify, window_id
from trahens_spec.generated import (
    BYTES_B12_COOKIE,
    LIMIT_COOKIE_WINDOWS_ACCEPTED,
    LIMIT_COOKIE_WINDOW_MS,
)

ROOT = Path(__file__).resolve().parents[2]


class CookieTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = bytes(range(32))
        self.previous = bytes(range(32, 64))
        self.source = bytes([10, 200, 0, 1])
        self.port = 41000
        self.offer = b"offered-parameters"
        self.now = 1_757_000_000_000

    def test_a_cookie_verifies_in_the_window_it_was_issued(self) -> None:
        cookie = issue(self.secret, self.source, self.port, window_id(self.now), self.offer)
        self.assertTrue(
            verify([self.secret], cookie, self.source, self.port, self.offer, self.now)
        )

    def test_a_cookie_is_refused_for_another_source(self) -> None:
        cookie = issue(self.secret, self.source, self.port, window_id(self.now), self.offer)
        self.assertFalse(
            verify([self.secret], cookie, bytes([10, 200, 0, 2]), self.port, self.offer, self.now)
        )

    def test_a_cookie_is_refused_for_another_port(self) -> None:
        cookie = issue(self.secret, self.source, self.port, window_id(self.now), self.offer)
        self.assertFalse(
            verify([self.secret], cookie, self.source, self.port + 1, self.offer, self.now)
        )

    def test_a_cookie_is_refused_for_another_offer(self) -> None:
        # Binding the offered parameters is what stops a cookie obtained for
        # one set being spent on another.
        cookie = issue(self.secret, self.source, self.port, window_id(self.now), self.offer)
        self.assertFalse(
            verify([self.secret], cookie, self.source, self.port, b"different", self.now)
        )

    def test_a_cookie_survives_one_rotation_and_then_expires(self) -> None:
        # Issued in the current window, then time moves on. It must still be
        # accepted one window later -- otherwise every rotation would reject
        # senders mid-exchange -- and refused after that.
        cookie = issue(self.secret, self.source, self.port, window_id(self.now), self.offer)
        secrets = [self.secret, self.secret]
        later = self.now + LIMIT_COOKIE_WINDOW_MS
        self.assertTrue(verify(secrets, cookie, self.source, self.port, self.offer, later))
        beyond = self.now + LIMIT_COOKIE_WINDOW_MS * LIMIT_COOKIE_WINDOWS_ACCEPTED
        self.assertFalse(verify(secrets, cookie, self.source, self.port, self.offer, beyond))

    def test_a_cookie_from_a_retired_secret_is_refused(self) -> None:
        # Rotation discards the secret, so a cookie under it stops verifying
        # even inside a window the responder would otherwise accept.
        cookie = issue(self.previous, self.source, self.port, window_id(self.now), self.offer)
        self.assertFalse(
            verify([self.secret], cookie, self.source, self.port, self.offer, self.now)
        )

    def test_the_length_prefix_separates_source_from_offer(self) -> None:
        # Without length prefixes these two inputs would build the same
        # message, and a cookie for one would verify for the other.
        first = issue(self.secret, b"AB", self.port, 7, b"CD")
        second = issue(self.secret, b"ABC", self.port, 7, b"D")
        self.assertNotEqual(first, second)

    def test_a_wrong_length_cookie_is_refused(self) -> None:
        self.assertFalse(
            verify([self.secret], b"short", self.source, self.port, self.offer, self.now)
        )

    def test_a_bad_secret_length_is_refused(self) -> None:
        with self.assertRaises(CookieError):
            issue(b"too-short", self.source, self.port, 1, self.offer)

    def test_the_cookie_is_the_registry_width(self) -> None:
        cookie = issue(self.secret, self.source, self.port, 1, self.offer)
        self.assertEqual(len(cookie), BYTES_B12_COOKIE)

    def test_vector_generator_is_reproducible(self) -> None:
        published = ROOT / "spec/b12-cookie-test-vectors.json"
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory) / "vectors.json"
            subprocess.run(
                [
                    "python",
                    str(ROOT / "tools/generate_cookie_vectors.py"),
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
            (ROOT / "spec/b12-cookie-test-vectors.json").read_text(encoding="utf-8")
        )
        for entry in document["cases"]:
            cookie = issue(
                bytes.fromhex(entry["responder_secret"]),
                bytes.fromhex(entry["source"]),
                entry["port"],
                entry["window"],
                bytes.fromhex(entry["offer"]),
            )
            self.assertEqual(cookie.hex(), entry["cookie"], entry["name"])


if __name__ == "__main__":
    unittest.main()
