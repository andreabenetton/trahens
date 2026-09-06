# SPDX-License-Identifier: Apache-2.0

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from trahens_crypto.invitation import Invitation, InvitationError, invitation_psk
from trahens_spec.generated import (
    BYTES_B12_INVITATION_ID,
    BYTES_B12_INVITATION_SECRET,
)

ROOT = Path(__file__).resolve().parents[2]


class InvitationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identifier = bytes(range(BYTES_B12_INVITATION_ID))
        self.secret = bytes(range(BYTES_B12_INVITATION_SECRET))
        self.inviter = bytes(range(32, 64))

    def test_the_psk_is_thirty_two_bytes(self) -> None:
        self.assertEqual(len(invitation_psk(self.identifier, self.secret)), 32)

    def test_the_identifier_is_bound(self) -> None:
        # A secret must not be presentable under an identifier it was not
        # issued with, or two invitations sharing a secret by accident would
        # be interchangeable.
        other = bytes(range(1, BYTES_B12_INVITATION_ID + 1))
        self.assertNotEqual(
            invitation_psk(self.identifier, self.secret),
            invitation_psk(other, self.secret),
        )

    def test_the_secret_is_bound(self) -> None:
        other = bytes(range(1, BYTES_B12_INVITATION_SECRET + 1))
        self.assertNotEqual(
            invitation_psk(self.identifier, self.secret),
            invitation_psk(self.identifier, other),
        )

    def test_a_wrong_width_is_refused(self) -> None:
        with self.assertRaises(InvitationError):
            invitation_psk(b"short", self.secret)
        with self.assertRaises(InvitationError):
            invitation_psk(self.identifier, b"short")

    def test_an_invitation_validates_its_fields(self) -> None:
        Invitation(self.identifier, self.secret, self.inviter)
        with self.assertRaises(InvitationError):
            Invitation(b"short", self.secret, self.inviter)
        with self.assertRaises(InvitationError):
            Invitation(self.identifier, self.secret, b"short")

    def test_a_zero_secret_is_refused(self) -> None:
        # An all-zero secret carries no entropy, and an invitation built from
        # one would key a handshake anyone could reproduce.
        with self.assertRaises(InvitationError):
            Invitation(self.identifier, bytes(BYTES_B12_INVITATION_SECRET), self.inviter)

    def test_vector_generator_is_reproducible(self) -> None:
        published = ROOT / "spec/b12-invitation-test-vectors.json"
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory) / "vectors.json"
            subprocess.run(
                [
                    "python",
                    str(ROOT / "tools/generate_invitation_vectors.py"),
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
            (ROOT / "spec/b12-invitation-test-vectors.json").read_text(encoding="utf-8")
        )
        for entry in document["cases"]:
            psk = invitation_psk(
                bytes.fromhex(entry["identifier"]), bytes.fromhex(entry["secret"])
            )
            self.assertEqual(psk.hex(), entry["psk"], entry["name"])


if __name__ == "__main__":
    unittest.main()
