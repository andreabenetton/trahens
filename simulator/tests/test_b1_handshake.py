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
    decode_cookie_challenge,
    encode_cookie_challenge,
    load_profile,
    peek_admission_header,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]

INVITATION_ID = bytes.fromhex("a1" * 16)
ADVERTISEMENT_SECRET = bytes.fromhex("c3" * 32)


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

    def admission_parties(self, joiner_psk, inviter_psk, cookie=None):
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
            admission_identifier=INVITATION_ID,
            admission_cookie=cookie,
        )
        inviter = Responder(
            self.profile,
            inviter_static,
            Keypair.from_secret(seed("inviter/ephemeral")),
            None,
            admission_psk=inviter_psk,
            admission_identifier=INVITATION_ID,
            admission_cookie=cookie,
            advertisement_secret=ADVERTISEMENT_SECRET,
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

    def test_an_admission_initiate_carries_a_readable_header(self) -> None:
        # ADR 0046 D8 and ADR 0048 D14: both fields must be readable with no
        # state at all, because a responder needs them before it has any.
        cookie = bytes.fromhex("c0" * 32)
        joiner, _, _ = self.admission_parties(seed("admission"), seed("admission"), cookie)
        record = joiner.write_message_1()
        identifier, found = peek_admission_header(self.profile, record)
        self.assertEqual(identifier, INVITATION_ID)
        self.assertEqual(found, cookie)

    def test_an_admission_initiate_is_still_one_cell(self) -> None:
        joiner, _, _ = self.admission_parties(seed("admission"), seed("admission"))
        self.assertEqual(len(joiner.write_message_1()), self.record_bytes)

    def test_the_admission_header_is_inside_the_transcript(self) -> None:
        # Cleartext is not unprotected. Altering either field must make the
        # payload fail to open, or a man in the middle could strip the cookie or
        # move it onto another invitation.
        for position in (2, 2 + 16):
            joiner, inviter, _ = self.admission_parties(seed("admission"), seed("admission"))
            record = bytearray(joiner.write_message_1())
            record[position] ^= 0x01
            with self.assertRaises(HandshakeError):
                inviter.read_message_1(bytes(record))

    def test_a_header_the_responder_did_not_act_on_is_refused(self) -> None:
        # The responder found its key from one identifier and verified a cookie
        # for it. A record carrying different ones is a different record.
        joiner, _, _ = self.admission_parties(seed("admission"), seed("admission"))
        record = joiner.write_message_1()
        inviter = Responder(
            self.profile,
            Keypair.from_secret(seed("inviter/static")),
            Keypair.from_secret(seed("inviter/ephemeral")),
            None,
            admission_psk=seed("admission"),
            admission_identifier=bytes.fromhex("b2" * 16),
            advertisement_secret=ADVERTISEMENT_SECRET,
        )
        with self.assertRaises(HandshakeError):
            inviter.read_message_1(record)

    def test_a_first_attempt_carries_a_zero_cookie(self) -> None:
        # ADR 0048 D13: a joiner has no cookie until it is challenged, and an
        # absent cookie is not a special case — it is simply one that will not
        # verify, which is the one thing that provokes a challenge.
        joiner, _, _ = self.admission_parties(seed("admission"), seed("admission"))
        _, cookie = peek_admission_header(self.profile, joiner.write_message_1())
        self.assertEqual(cookie, bytes(self.profile.cookie_bytes))

    def test_the_cookie_changes_the_transcript(self) -> None:
        # A cookie issued for one attempt cannot be carried into another: the
        # attempts do not share a transcript.
        without, _, _ = self.admission_parties(seed("admission"), seed("admission"))
        with_cookie, _, _ = self.admission_parties(
            seed("admission"), seed("admission"), bytes.fromhex("c0" * 32)
        )
        self.assertNotEqual(without.write_message_1(), with_cookie.write_message_1())

    def test_a_cookie_challenge_round_trips(self) -> None:
        cookie = bytes.fromhex("c0" * 32)
        record = encode_cookie_challenge(self.profile, INVITATION_ID, cookie)
        self.assertEqual(len(record), self.record_bytes)
        self.assertEqual(decode_cookie_challenge(self.profile, record), (INVITATION_ID, cookie))

    def test_a_cookie_challenge_is_one_cell(self) -> None:
        # ADR 0048 D13's amplification argument is exactly this: the answer is
        # the same width as the message that provoked it, so a responder that
        # answers a spoofed source amplifies by one.
        joiner, _, _ = self.admission_parties(seed("admission"), seed("admission"))
        challenge = encode_cookie_challenge(self.profile, INVITATION_ID, bytes(32))
        self.assertEqual(len(challenge), len(joiner.write_message_1()))

    def test_a_challenge_with_hidden_padding_is_refused(self) -> None:
        record = bytearray(encode_cookie_challenge(self.profile, INVITATION_ID, bytes(32)))
        record[-1] = 0x01
        with self.assertRaises(HandshakeError):
            decode_cookie_challenge(self.profile, bytes(record))

    def test_a_challenge_is_not_read_as_an_initiate(self) -> None:
        # The two share a first byte and differ in the second, which is what
        # section 3's allocation relies on.
        record = encode_cookie_challenge(self.profile, INVITATION_ID, bytes(32))
        with self.assertRaises(HandshakeError):
            peek_admission_header(self.profile, record)

    def test_a_manifest_initiate_is_not_read_as_an_admission_one(self) -> None:
        initiator, _ = self.parties()
        with self.assertRaises(HandshakeError):
            peek_admission_header(self.profile, initiator.write_message_1())

    def test_an_admission_handshake_needs_its_identifier(self) -> None:
        with self.assertRaises(HandshakeError):
            Responder(
                self.profile,
                Keypair.from_secret(seed("r/static")),
                Keypair.from_secret(seed("r/ephemeral")),
                None,
                admission_psk=seed("admission"),
            )

    def test_an_admission_exchange_binds_the_advertisement_key(self) -> None:
        # ADR 0049 D15. The joiner ends holding the key the responder proved it
        # controls, which is what a cached advertisement is compared against.
        psk = seed("admission")
        joiner, inviter, _ = self.admission_parties(psk, psk)
        self.complete(joiner, inviter)
        self.assertEqual(joiner.advertisement_key, inviter.advertisement_public)

    def test_the_manifest_path_carries_no_transition(self) -> None:
        # D16: absent everywhere but admission, so v1.8's published records do
        # not move and a node with discovery disabled speaks what it always did.
        initiator, responder = self.parties()
        self.complete(initiator, responder)
        self.assertIsNone(initiator.advertisement_key)

    def test_a_transition_from_another_key_is_refused(self) -> None:
        # The signature is checked against the key the payload carries, so this
        # is the case where a responder signs with a key it does not hold.
        psk = seed("admission")
        joiner, inviter, _ = self.admission_parties(psk, psk)
        inviter.read_message_1(joiner.write_message_1())
        selection = Selection(self.profile.protocol_version, 2, 3, 4, 0x0101, 1)
        record = bytearray(inviter.write_message_2(selection))
        # Flip a byte inside the encrypted payload: the AEAD refuses first,
        # which is the outer guarantee. The inner one is checked below.
        record[-1] ^= 0x01
        with self.assertRaises(HandshakeError):
            joiner.read_message_2(bytes(record))

    def test_a_transition_signed_over_another_transcript_is_refused(self) -> None:
        # The reason the transcript is signed rather than the static key: a
        # signature over anything an attacker can replay would be a standing
        # certificate. Signing a different hash must not verify here.
        from trahens_crypto.b1 import sign_transition, verify_transition

        wrong = sign_transition(self.profile, ADVERTISEMENT_SECRET, seed("other/transcript"))
        public = (
            Ed25519PrivateKey.from_private_bytes(ADVERTISEMENT_SECRET)
            .public_key()
            .public_bytes_raw()
        )
        with self.assertRaises(HandshakeError):
            verify_transition(self.profile, public, seed("this/transcript"), wrong)

    def test_a_responder_cannot_carry_a_key_it_cannot_sign_for(self) -> None:
        # The attack the transition exists to stop: copy someone's advertised
        # key and attract joiners to an address you control. The responder can
        # carry the key, because it is public, and cannot sign for it.
        psk = seed("admission")
        joiner, inviter, _ = self.admission_parties(psk, psk)
        victim = (
            Ed25519PrivateKey.from_private_bytes(seed("someone/else"))
            .public_key()
            .public_bytes_raw()
        )
        inviter.advertisement_public = victim
        inviter.read_message_1(joiner.write_message_1())
        selection = Selection(self.profile.protocol_version, 2, 3, 4, 0x0101, 1)
        record = inviter.write_message_2(selection)
        with self.assertRaises(HandshakeError):
            joiner.read_message_2(record)

    def test_an_admission_responder_needs_an_advertisement_key(self) -> None:
        # D16 again, as a refusal: there is no way to admit without binding.
        with self.assertRaises(HandshakeError):
            Responder(
                self.profile,
                Keypair.from_secret(seed("r/static")),
                Keypair.from_secret(seed("r/ephemeral")),
                None,
                admission_psk=seed("admission"),
                admission_identifier=INVITATION_ID,
            )

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
