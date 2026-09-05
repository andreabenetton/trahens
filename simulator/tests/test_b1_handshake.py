# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from trahens_crypto.b1 import (
    HandshakeError,
    Initiator,
    Keypair,
    Offer,
    Responder,
    Selection,
    load_profile,
)

ROOT = Path(__file__).resolve().parents[2]


def seed(label: str) -> bytes:
    return hashlib.sha256(b"Trahens/B1/test/" + label.encode()).digest()


class B1HandshakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(
            (ROOT / "spec/protocol-registry-v1.8.json").read_text(encoding="utf-8")
        )
        cls.profile = load_profile(cls.registry)
        cls.record_bytes = cls.registry["widths_bytes"]["b1_record"]

    def parties(self, previous_export=None, pin_initiator=None, pin_responder=None):
        i_static = Keypair.from_secret(seed("i/static"))
        r_static = Keypair.from_secret(seed("r/static"))
        offer = Offer(self.profile.protocol_version, (2,), (3,), (4,), (0x0101,), 1)
        initiator = Initiator(
            self.profile,
            i_static,
            Keypair.from_secret(seed("i/ephemeral")),
            pin_responder if pin_responder is not None else r_static.public,
            offer,
            previous_export,
        )
        responder = Responder(
            self.profile,
            r_static,
            Keypair.from_secret(seed("r/ephemeral")),
            pin_initiator if pin_initiator is not None else i_static.public,
            previous_export,
        )
        return initiator, responder

    def complete(self, initiator, responder):
        m1 = initiator.write_message_1()
        responder.read_message_1(m1)
        m2 = responder.write_message_2(Selection(self.profile.protocol_version, 2, 3, 4, 0x0101, 1))
        initiator.read_message_2(m2)
        m3, i_session = initiator.write_message_3()
        r_session = responder.read_message_3(m3)
        return (m1, m2, m3), i_session, r_session

    def test_both_ends_derive_the_same_session_and_every_record_is_one_cell(self) -> None:
        records, i_session, r_session = self.complete(*self.parties())
        for record in records:
            self.assertEqual(len(record), self.record_bytes)
            self.assertEqual(record[0], 0, "handshake records begin with a zero byte")
        for name in ("handshake_hash", "initiator_to_responder", "responder_to_initiator", "epoch", "export_key"):
            self.assertEqual(getattr(i_session, name), getattr(r_session, name), name)
        self.assertNotEqual(i_session.initiator_to_responder, i_session.responder_to_initiator)
        self.assertEqual(i_session.epoch[0] & 0x80, 0x80, "derived epochs set the top bit")

    def test_padding_tampering_is_refused_at_parse(self) -> None:
        initiator, responder = self.parties()
        m1 = bytearray(initiator.write_message_1())
        m1[-1] ^= 0x01  # inside the zero padding
        with self.assertRaises(HandshakeError):
            responder.read_message_1(bytes(m1))

    def test_first_message_tampering_breaks_the_transcript(self) -> None:
        # The offer travels in the clear in an initial handshake, since XX has
        # no key yet. It is still mixed into the transcript, so a modification
        # the responder accepts leaves the two sides with different hashes and
        # the second message fails to authenticate.
        initiator, responder = self.parties()
        m1 = bytearray(initiator.write_message_1())
        m1[2] ^= 0x01  # the responder's view of the initiator ephemeral
        responder.read_message_1(bytes(m1))
        m2 = responder.write_message_2(Selection(self.profile.protocol_version, 2, 3, 4, 0x0101, 1))
        with self.assertRaises(HandshakeError):
            initiator.read_message_2(m2)

    def test_a_rekey_binds_the_chain_into_the_traffic_keys(self) -> None:
        # Same statics, same ephemerals, differing only in the chained export
        # key. If the chain reached the transcript but not the chaining key,
        # these would be identical and a rekey would derive the keys it
        # replaced.
        _, first, _ = self.complete(*self.parties())
        _, chained, _ = self.complete(*self.parties(previous_export=first.export_key))
        _, unrelated, _ = self.complete(*self.parties(previous_export=seed("unrelated")))
        self.assertNotEqual(first.initiator_to_responder, chained.initiator_to_responder)
        self.assertNotEqual(chained.initiator_to_responder, unrelated.initiator_to_responder)

    def test_a_retired_suite_cannot_be_offered(self) -> None:
        with self.assertRaises(HandshakeError):
            Offer(self.profile.protocol_version, (2,), (3,), (4,), (0x0001,), 1).encode(self.profile)

    def test_selection_outside_the_offer_is_refused(self) -> None:
        initiator, responder = self.parties()
        responder.read_message_1(initiator.write_message_1())
        with self.assertRaises(HandshakeError):
            responder.write_message_2(Selection(self.profile.protocol_version, 2, 3, 4, 0x0003, 1))

    def test_a_responder_whose_static_is_not_pinned_is_refused(self) -> None:
        wrong = Keypair.from_secret(seed("someone-else")).public
        initiator, responder = self.parties(pin_responder=wrong)
        responder.read_message_1(initiator.write_message_1())
        m2 = responder.write_message_2(Selection(self.profile.protocol_version, 2, 3, 4, 0x0101, 1))
        # The key authenticated fine; it is simply not the one the manifest
        # names for this peer, which is the whole point of the pin under XX.
        with self.assertRaises(HandshakeError):
            initiator.read_message_2(m2)

    def test_an_initiator_whose_static_is_not_pinned_is_refused(self) -> None:
        wrong = Keypair.from_secret(seed("someone-else")).public
        initiator, responder = self.parties(pin_initiator=wrong)
        responder.read_message_1(initiator.write_message_1())
        initiator.read_message_2(
            responder.write_message_2(Selection(self.profile.protocol_version, 2, 3, 4, 0x0101, 1))
        )
        m3, _ = initiator.write_message_3()
        with self.assertRaises(HandshakeError):
            responder.read_message_3(m3)

    def test_a_rekey_is_chained_to_the_previous_session(self) -> None:
        _, first, _ = self.complete(*self.parties())
        _, second_i, second_r = self.complete(*self.parties(previous_export=first.export_key))
        self.assertEqual(second_i.export_key, second_r.export_key)
        self.assertNotEqual(first.epoch, second_i.epoch)

        # A rekey chained to a session the responder does not hold must not
        # complete. Because psk0 gives message 1 a key, this is refused on the
        # first record, before the responder performs any Diffie-Hellman --
        # earlier than a prologue-only binding could manage.
        initiator, _ = self.parties(previous_export=first.export_key)
        _, responder = self.parties(previous_export=seed("unrelated"))
        with self.assertRaises(HandshakeError):
            responder.read_message_1(initiator.write_message_1())

    def test_vector_generator_is_reproducible(self) -> None:
        published = ROOT / "spec/b1-test-vectors.json"
        with tempfile.TemporaryDirectory() as temporary:
            generated = Path(temporary) / "vectors.json"
            subprocess.run(
                ["python", str(ROOT / "tools/generate_b1_vectors.py"), "--output", str(generated)],
                check=True,
                cwd=ROOT,
                env={"PYTHONPATH": str(ROOT / "simulator"), "PATH": "/usr/bin:/bin:/usr/local/bin"},
            )
            self.assertEqual(published.read_bytes(), generated.read_bytes())


if __name__ == "__main__":
    unittest.main()
