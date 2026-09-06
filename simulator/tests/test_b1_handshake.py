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

    def test_first_message_tampering_is_refused_on_the_spot(self) -> None:
        # Under psk0 the first message is encrypted under a key derived from
        # the static-static value, so a modification is refused where it
        # arrives rather than surfacing two messages later as a transcript
        # mismatch. Nothing is answered, so nothing is disclosed.
        initiator, responder = self.parties()
        m1 = bytearray(initiator.write_message_1())
        m1[2] ^= 0x01  # the responder's view of the initiator ephemeral
        with self.assertRaises(HandshakeError):
            responder.read_message_1(bytes(m1))

    def test_a_first_message_without_the_static_psk_is_refused(self) -> None:
        # The property the psk0 change exists for. A sender who can reach the
        # port but does not hold the static-static value cannot produce a first
        # message the responder will act on, so it performs no Diffie-Hellman
        # and never reveals its own static key to a stranger.
        _, responder = self.parties()
        outsider = Initiator(
            self.profile,
            Keypair.from_secret(seed("stranger-static")),
            Keypair.from_secret(seed("stranger-ephemeral")),
            Keypair.from_secret(seed("r/static")).public,
            Offer(self.profile.protocol_version, (2,), (3,), (4,), (0x0101,), 1),
        )
        with self.assertRaises(HandshakeError):
            responder.read_message_1(outsider.write_message_1())

    def admission_parties(self, joiner_psk, inviter_psk):
        """A joiner with no manifest entry at the inviter.

        The joiner still pins the inviter, because an invitation carries the
        inviter's static public key out of band. The inviter passes None: it
        has nothing to pin and learns the joiner's key from the exchange.
        """
        joiner_static = Keypair.from_secret(seed("joiner/static"))
        inviter_static = Keypair.from_secret(seed("inviter/static"))
        offer = Offer(self.profile.protocol_version, (2,), (3,), (4,), (0x0101,), 1)
        joiner = Initiator(
            self.profile,
            joiner_static,
            Keypair.from_secret(seed("joiner/ephemeral")),
            inviter_static.public,
            offer,
            admission_psk=joiner_psk,
        )
        inviter = Responder(
            self.profile,
            inviter_static,
            Keypair.from_secret(seed("inviter/ephemeral")),
            None,
            admission_psk=inviter_psk,
        )
        return joiner, inviter, joiner_static

    def test_an_admission_handshake_promotes_the_presented_key(self) -> None:
        psk = seed("admission")
        joiner, inviter, joiner_static = self.admission_parties(psk, psk)
        _, i_session, r_session = self.complete(joiner, inviter)
        self.assertEqual(i_session.handshake_hash, r_session.handshake_hash)
        # The inviter learned the key it had no way to pin, and it is the
        # joiner's real one.
        self.assertEqual(inviter.promoted_static, joiner_static.public)

    def test_the_manifest_path_promotes_nothing(self) -> None:
        # Promotion must not be reachable where a pin already applies, or a
        # pinned peer would be indistinguishable from a newly learned one.
        _, responder = self.parties()
        self.complete(*self.parties())
        initiator, responder = self.parties()
        self.complete(initiator, responder)
        self.assertIsNone(responder.promoted_static)

    def test_an_admission_handshake_needs_the_right_key(self) -> None:
        # The admission key is what authenticates here, so a joiner without it
        # is refused at the first record and the inviter answers nothing.
        joiner, inviter, _ = self.admission_parties(seed("admission"), seed("other"))
        with self.assertRaises(HandshakeError):
            inviter.read_message_1(joiner.write_message_1())

    def test_a_responder_without_a_peer_static_needs_an_admission_key(self) -> None:
        # Omitting the pin is only permitted where an admission key replaces
        # it. Without either there is nothing authenticating the peer at all.
        with self.assertRaises(HandshakeError):
            Responder(
                self.profile,
                Keypair.from_secret(seed("r/static")),
                Keypair.from_secret(seed("r/ephemeral")),
                None,
            )

    def test_a_rekey_has_no_admission_key(self) -> None:
        with self.assertRaises(HandshakeError):
            Responder(
                self.profile,
                Keypair.from_secret(seed("r/static")),
                Keypair.from_secret(seed("r/ephemeral")),
                None,
                previous_export=seed("export"),
                admission_psk=seed("admission"),
            )

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
        # The pin now refuses at the first record rather than the second. The
        # static-static value the psk0 key derives from is computed against the
        # pinned key, so a wrong pin produces a first message the peer cannot
        # decrypt -- earlier than the manifest check in message 2, and without
        # the responder answering. That check still exists and is still what
        # authenticates; this is a mismatch caught before it.
        wrong = Keypair.from_secret(seed("someone-else")).public
        initiator, responder = self.parties(pin_responder=wrong)
        with self.assertRaises(HandshakeError):
            responder.read_message_1(initiator.write_message_1())

    def test_an_initiator_whose_static_is_not_pinned_is_refused(self) -> None:
        wrong = Keypair.from_secret(seed("someone-else")).public
        initiator, responder = self.parties(pin_initiator=wrong)
        with self.assertRaises(HandshakeError):
            responder.read_message_1(initiator.write_message_1())

    def test_the_manifest_check_still_refuses_a_key_the_psk_agreed_on(self) -> None:
        # Both ends hold the right static-static value, so the psk0 filter
        # passes, and the responder then presents a static key that is not the
        # pinned one. Only the manifest check in message 2 can refuse that, so
        # this is what shows the pin is still doing its job rather than having
        # been replaced by the pre-filter.
        i_static = Keypair.from_secret(seed("i/static"))
        r_static = Keypair.from_secret(seed("r/static"))
        offer = Offer(self.profile.protocol_version, (2,), (3,), (4,), (0x0101,), 1)
        initiator = Initiator(
            self.profile,
            i_static,
            Keypair.from_secret(seed("i/ephemeral")),
            r_static.public,
            offer,
        )
        responder = Responder(
            self.profile,
            r_static,
            Keypair.from_secret(seed("r/ephemeral")),
            i_static.public,
        )
        responder.read_message_1(initiator.write_message_1())
        m2 = responder.write_message_2(Selection(self.profile.protocol_version, 2, 3, 4, 0x0101, 1))
        initiator.expected_peer_static = Keypair.from_secret(seed("someone-else")).public
        with self.assertRaises(HandshakeError):
            initiator.read_message_2(m2)

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
