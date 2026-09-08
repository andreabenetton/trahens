# SPDX-License-Identifier: Apache-2.0
"""Trahens B1.1 authenticated adjacent-link handshake: Noise XXpsk0 reference.

The reference exists to make the record encodings, the negotiation payloads
and the key/epoch derivations precise enough to publish vectors against. It is
Noise revision 34 pattern XX under the psk0 modifier, instantiated as
Noise_XXpsk0_25519_ChaChaPoly_SHA256, with the B1.1 additions layered on top:
fixed 1,052-byte records, a transcript-bound profile negotiation, a manifest
pin on the presented static key, and epoch/export derivation from the finished
handshake.

Both exchanges are psk0 and differ only in where the pre-shared key comes from:
a rekey chains to the session it replaces through its export key, an initial
handshake uses the static-static Diffie-Hellman both peers can compute offline.

It is not independently audited and MUST NOT be used as production security
code. The Rust implementation is checked against the vectors this produces,
and those vectors are in turn checked against an independent Noise
implementation.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

HASHLEN = 32
DHLEN = 32
TAGLEN = 16
SIGNATURE_BYTES = 64
SELECTION_BYTES = 7


class HandshakeError(ValueError):
    """Any failure; callers must not distinguish causes on the wire."""


# --------------------------------------------------------------------------
# Profile: everything the handshake takes from the registry.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class B1Profile:
    protocol_version: int
    noise_protocol: bytes
    prologue_domain: bytes
    rekey_chain_domain: bytes
    rekey_psk_domain: bytes
    static_psk_domain: bytes
    epoch_domain: bytes
    export_domain: bytes
    transition_domain: bytes
    record_bytes: int
    initiate_payload_psk_bytes: int
    admission_header_bytes: int
    admission_payload_bytes: int
    respond_payload_bytes: int
    finish_payload_bytes: int
    record_types: dict[str, int]
    invitation_id_bytes: int
    cookie_bytes: int
    max_offered_per_class: int
    rejected_suites: frozenset[int]


def load_profile(registry: dict) -> B1Profile:
    domains = registry["domain_separators"]
    widths = registry["widths_bytes"]
    suites = registry["suites"]
    # Retired and disabled suites, and the symbolic control, may never be
    # offered: rejecting them at parse is what keeps them out of negotiation.
    rejected = frozenset(
        value
        for key, value in suites.items()
        if key.endswith("_retired") or key.endswith("_disabled") or key == "c2_symbolic"
    )
    return B1Profile(
        protocol_version=int(registry["protocol"]["version"]),
        noise_protocol=domains["b1_noise_protocol"].encode(),
        prologue_domain=domains["b1_prologue"].encode(),
        rekey_chain_domain=domains["b1_rekey_chain"].encode(),
        rekey_psk_domain=domains["b1_rekey_psk"].encode(),
        static_psk_domain=domains["b1_static_psk"].encode(),
        epoch_domain=domains["b1_epoch"].encode(),
        export_domain=domains["b1_export"].encode(),
        transition_domain=domains["b1_transition"].encode(),
        record_bytes=int(widths["b1_record"]),
        initiate_payload_psk_bytes=int(widths["b1_initiate_payload_psk"]),
        admission_header_bytes=int(widths["b1_admission_header"]),
        admission_payload_bytes=int(widths["b1_admission_payload"]),
        respond_payload_bytes=int(widths["b1_respond_payload"]),
        finish_payload_bytes=int(widths["b1_finish_payload"]),
        record_types=dict(registry["b1_record_types"]),
        invitation_id_bytes=int(widths["b12_invitation_id"]),
        cookie_bytes=int(widths["b12_cookie"]),
        max_offered_per_class=int(registry["limits"]["max_offered_profiles_per_class"]),
        rejected_suites=rejected,
    )


# --------------------------------------------------------------------------
# Primitives, exactly as Noise specifies them.
# --------------------------------------------------------------------------


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def noise_hkdf(chaining_key: bytes, input_key_material: bytes, count: int) -> list[bytes]:
    """HKDF as written in the Noise specification section 4.3."""
    temp = _hmac(chaining_key, input_key_material)
    outputs = [_hmac(temp, b"\x01")]
    for index in range(2, count + 1):
        outputs.append(_hmac(temp, outputs[-1] + bytes([index])))
    return outputs


def rfc5869_hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF as RFC 5869 defines it, both stages, each input in its own field.

    Distinct from `noise_hkdf` above, which is the variant the Noise
    specification writes in section 4.3 and applies to the chaining key. This is
    the one to reach for outside the handshake state machine, where the salt is
    the field for a domain separator and the info is the field for context.
    """
    if length > 255 * HASHLEN:
        raise HandshakeError("invalid HKDF output length")
    prk = _hmac(salt, ikm)
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = _hmac(prk, block + info + bytes([counter]))
        output += block
        counter += 1
    return output[:length]


def _nonce(counter: int) -> bytes:
    # ChaChaPoly in Noise: 32 zero bits then the 64-bit counter little-endian.
    return b"\x00" * 4 + counter.to_bytes(8, "little")


@dataclass
class Keypair:
    secret: bytes
    public: bytes

    @classmethod
    def from_secret(cls, secret: bytes) -> "Keypair":
        if len(secret) != DHLEN:
            raise HandshakeError("x25519 secret must be 32 bytes")
        private = X25519PrivateKey.from_private_bytes(secret)
        return cls(secret, private.public_key().public_bytes_raw())


def dh(keypair: Keypair, public: bytes) -> bytes:
    if len(public) != DHLEN:
        raise HandshakeError("x25519 public must be 32 bytes")
    try:
        private = X25519PrivateKey.from_private_bytes(keypair.secret)
        return private.exchange(X25519PublicKey.from_public_bytes(public))
    except ValueError as error:
        raise HandshakeError("invalid x25519 exchange") from error


# --------------------------------------------------------------------------
# Noise state objects (specification section 5).
# --------------------------------------------------------------------------


@dataclass
class CipherState:
    key: bytes | None = None
    counter: int = 0

    def initialize_key(self, key: bytes) -> None:
        self.key = key
        self.counter = 0

    def has_key(self) -> bool:
        return self.key is not None

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.key is None:
            return plaintext
        if self.counter >= 2**64 - 1:
            raise HandshakeError("nonce exhausted")
        output = ChaCha20Poly1305(self.key).encrypt(_nonce(self.counter), plaintext, ad)
        self.counter += 1
        return output

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.key is None:
            return ciphertext
        if self.counter >= 2**64 - 1:
            raise HandshakeError("nonce exhausted")
        try:
            output = ChaCha20Poly1305(self.key).decrypt(_nonce(self.counter), ciphertext, ad)
        except InvalidTag as error:
            raise HandshakeError("authentication failed") from error
        self.counter += 1
        return output


@dataclass
class SymmetricState:
    cipher: CipherState = field(default_factory=CipherState)
    chaining_key: bytes = b""
    handshake_hash: bytes = b""

    @classmethod
    def initialize(cls, protocol_name: bytes) -> "SymmetricState":
        if len(protocol_name) <= HASHLEN:
            h = protocol_name + b"\x00" * (HASHLEN - len(protocol_name))
        else:
            h = _hash(protocol_name)
        return cls(chaining_key=h, handshake_hash=h)

    def mix_key(self, input_key_material: bytes) -> None:
        self.chaining_key, temp_k = noise_hkdf(self.chaining_key, input_key_material, 2)
        self.cipher.initialize_key(temp_k)

    def mix_hash(self, data: bytes) -> None:
        self.handshake_hash = _hash(self.handshake_hash + data)

    def mix_key_and_hash(self, input_key_material: bytes) -> None:
        """Noise section 5.2. Used by the psk0 modifier for rekeys.

        Unlike a prologue, this enters the chaining key as well as the hash, so
        the material actually reaches Split() and therefore the traffic keys.
        """
        self.chaining_key, temp_h, temp_k = noise_hkdf(self.chaining_key, input_key_material, 3)
        self.mix_hash(temp_h)
        self.cipher.initialize_key(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt_with_ad(self.handshake_hash, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt_with_ad(self.handshake_hash, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> tuple[bytes, bytes]:
        temp_k1, temp_k2 = noise_hkdf(self.chaining_key, b"", 2)
        return temp_k1, temp_k2


# --------------------------------------------------------------------------
# Negotiation payloads (link-handshake-b1.md section 5).
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Offer:
    version: int
    w2_profiles: tuple[int, ...]
    t1_profiles: tuple[int, ...]
    t2_profiles: tuple[int, ...]
    suites: tuple[int, ...]
    resource_class: int

    def encode(self, profile: B1Profile) -> bytes:
        for group in (self.w2_profiles, self.t1_profiles, self.t2_profiles, self.suites):
            if not group or len(group) > profile.max_offered_per_class:
                raise HandshakeError("offered profile class out of bounds")
        if any(suite in profile.rejected_suites for suite in self.suites):
            raise HandshakeError("a retired or disabled suite may not be offered")
        out = bytes([self.version])
        for group in (self.w2_profiles, self.t1_profiles, self.t2_profiles):
            out += bytes([len(group)]) + bytes(group)
        out += bytes([len(self.suites)])
        for suite in self.suites:
            out += suite.to_bytes(2, "big")
        out += bytes([self.resource_class])
        return out

    @classmethod
    def decode(cls, profile: B1Profile, data: bytes) -> "Offer":
        cursor = 0

        def take(count: int) -> bytes:
            nonlocal cursor
            if cursor + count > len(data):
                raise HandshakeError("truncated offer")
            piece = data[cursor : cursor + count]
            cursor += count
            return piece

        def take_list(width: int) -> tuple[int, ...]:
            count = take(1)[0]
            if count == 0 or count > profile.max_offered_per_class:
                raise HandshakeError("offered profile class out of bounds")
            return tuple(int.from_bytes(take(width), "big") for _ in range(count))

        version = take(1)[0]
        if version != profile.protocol_version:
            raise HandshakeError("unsupported protocol version")
        w2 = take_list(1)
        t1 = take_list(1)
        t2 = take_list(1)
        suites = take_list(2)
        if any(suite in profile.rejected_suites for suite in suites):
            raise HandshakeError("a retired or disabled suite may not be offered")
        resource_class = take(1)[0]
        if cursor != len(data):
            raise HandshakeError("trailing bytes in offer")
        return cls(version, w2, t1, t2, suites, resource_class)


@dataclass(frozen=True)
class Selection:
    version: int
    w2_profile: int
    t1_profile: int
    t2_profile: int
    suite: int
    resource_class: int

    def encode(self) -> bytes:
        return (
            bytes([self.version, self.w2_profile, self.t1_profile, self.t2_profile])
            + self.suite.to_bytes(2, "big")
            + bytes([self.resource_class])
        )

    @classmethod
    def decode(cls, data: bytes) -> "Selection":
        if len(data) != 7:
            raise HandshakeError("malformed selection")
        return cls(data[0], data[1], data[2], data[3], int.from_bytes(data[4:6], "big"), data[6])

    def within(self, offer: Offer) -> bool:
        return (
            self.version == offer.version
            and self.w2_profile in offer.w2_profiles
            and self.t1_profile in offer.t1_profiles
            and self.t2_profile in offer.t2_profiles
            and self.suite in offer.suites
            and self.resource_class == offer.resource_class
        )


def _frame_payload(body: bytes, width: int) -> bytes:
    """Length-prefix and zero-pad a payload to the fixed width the record needs.

    The padding is inside the region Noise hashes (and, from message 2 on,
    encrypts), so it is authenticated rather than ignorable.
    """
    if len(body) + 2 > width:
        raise HandshakeError("payload exceeds record")
    return len(body).to_bytes(2, "big") + body + b"\x00" * (width - 2 - len(body))


def _unframe_payload(framed: bytes, width: int) -> bytes:
    if len(framed) != width:
        raise HandshakeError("payload width mismatch")
    length = int.from_bytes(framed[:2], "big")
    if 2 + length > width or any(framed[2 + length :]):
        raise HandshakeError("malformed payload padding")
    return framed[2 : 2 + length]


# --------------------------------------------------------------------------
# The admission header and the cookie challenge (ADR 0048).
# --------------------------------------------------------------------------


def admission_header(profile: B1Profile, identifier: bytes, cookie: bytes) -> bytes:
    """The cleartext prefix of an admission initiate.

    ADR 0046 D8 puts the invitation identifier in the clear so a responder can
    find the key to decrypt under without trial-decrypting against every live
    invitation. ADR 0048 D14 puts the cookie beside it, because both must be
    readable before anything is allocated.

    It is cleartext but not unprotected: it is mixed into the transcript before
    the ephemeral, so altering either field makes the payload fail to open. A
    man in the middle cannot strip the cookie or move it to another invitation.
    """
    if len(identifier) != profile.invitation_id_bytes:
        raise HandshakeError("invitation identifier width mismatch")
    if len(cookie) != profile.cookie_bytes:
        raise HandshakeError("cookie width mismatch")
    header = identifier + cookie
    if len(header) != profile.admission_header_bytes:
        raise HandshakeError("admission header width mismatch")
    return header


def sign_transition(profile: B1Profile, signing_seed: bytes, handshake_hash: bytes) -> bytes:
    """Bind an advertisement key to the exchange that is completing.

    ADR 0049 D15. The transcript is signed, not the static key: a signature over
    the static key alone would be a standing certificate, replayable into any
    exchange by anyone who saw it once. `handshake_hash` already covers both
    ephemerals, the responder's static key and the cleartext admission header,
    so one signature binds the advertisement key to this responder, this joiner
    and this exchange together.
    """
    message = profile.transition_domain + handshake_hash
    return Ed25519PrivateKey.from_private_bytes(signing_seed).sign(message)


def verify_transition(
    profile: B1Profile, advertisement_key: bytes, handshake_hash: bytes, signature: bytes
) -> None:
    """Raise unless `advertisement_key` signed this exchange."""
    message = profile.transition_domain + handshake_hash
    try:
        Ed25519PublicKey.from_public_bytes(advertisement_key).verify(signature, message)
    except Exception as error:  # noqa: BLE001 -- one outcome, as everywhere here
        raise HandshakeError("advertisement transition does not verify") from error


def peek_admission_header(profile: B1Profile, record: bytes) -> tuple[bytes, bytes]:
    """Read the cleartext header of an admission initiate, holding no state.

    This is what a responder calls first: it needs the identifier to find the
    invitation the key comes from, and the cookie to decide whether to allocate
    at all. Both happen before any Diffie-Hellman, which is the point of putting
    them in the clear.
    """
    if len(record) != profile.record_bytes:
        raise HandshakeError("record width mismatch")
    if record[:2] != _record_prefix(profile, "admission_initiate"):
        raise HandshakeError("unexpected record")
    cursor = 2
    identifier = record[cursor : cursor + profile.invitation_id_bytes]
    cursor += profile.invitation_id_bytes
    cookie = record[cursor : cursor + profile.cookie_bytes]
    return identifier, cookie


def encode_cookie_challenge(profile: B1Profile, identifier: bytes, cookie: bytes) -> bytes:
    """The responder's answer to a first message whose cookie did not verify.

    ADR 0048 D13. It allocates nothing and proves nothing: a joiner that acts on
    a forged one echoes a cookie that will not verify and is challenged again.
    It is one cell wide like every other record, so answering a spoofed source
    amplifies by a factor of one.
    """
    record = _record_prefix(profile, "cookie_challenge")
    record += admission_header(profile, identifier, cookie)
    record += b"\x00" * (profile.record_bytes - len(record))
    if len(record) != profile.record_bytes:
        raise HandshakeError("record width mismatch")
    return record


def decode_cookie_challenge(profile: B1Profile, record: bytes) -> tuple[bytes, bytes]:
    """Parse a challenge into (identifier, cookie).

    The padding is checked because a receiver must not accept a record with
    anything hidden behind its declared fields, even one that carries no
    authentication of its own.
    """
    if len(record) != profile.record_bytes:
        raise HandshakeError("record width mismatch")
    if record[:2] != _record_prefix(profile, "cookie_challenge"):
        raise HandshakeError("unexpected record")
    cursor = 2
    identifier = record[cursor : cursor + profile.invitation_id_bytes]
    cursor += profile.invitation_id_bytes
    cookie = record[cursor : cursor + profile.cookie_bytes]
    cursor += profile.cookie_bytes
    if any(record[cursor:]):
        raise HandshakeError("malformed challenge padding")
    return identifier, cookie


# --------------------------------------------------------------------------
# The handshake itself.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Session:
    handshake_hash: bytes
    initiator_to_responder: bytes
    responder_to_initiator: bytes
    epoch: bytes
    export_key: bytes
    peer_static: bytes
    selection: Selection


def prologue(profile: B1Profile, rekey: bool) -> bytes:
    """The Noise prologue, which is domain separation only.

    The previous session's export key is NOT carried here. A prologue reaches
    only the handshake hash, so binding the chain that way would prevent an
    unrelated exchange being spliced in as a rekey while leaving the traffic
    keys themselves unchained: with the same ephemerals a rekey would derive
    the same W2 keys as the session it replaced. The export key therefore
    enters through the psk0 modifier instead, which mixes it into the chaining
    key as well.
    """
    return profile.rekey_chain_domain if rekey else profile.prologue_domain


def _mix_ephemeral(state: SymmetricState, public: bytes) -> None:
    """Process an `e` token.

    Noise section 9: in a PSK handshake an `e` token must also `MixKey` the
    public ephemeral, not only `MixHash` it. The PSK supplies key material
    before any Diffie-Hellman has happened, so without this the ephemeral would
    contribute nothing to the chaining key for the first message and two
    exchanges differing only in their ephemerals could share a key stream.

    Both B1.1 exchanges are `psk0`, so this always applies.
    """
    state.mix_hash(public)
    state.mix_key(public)


def static_psk(
    profile: B1Profile, static: Keypair, peer_static: bytes, *, initiator: bool
) -> bytes:
    """The pre-shared key for an initial handshake.

    Derived from the static-static Diffie-Hellman, which both peers can compute
    offline from the manifest they already hold: neither has to be told it and
    nothing carries it on the wire.

    This is what gates the first message. Under plain `XX` that message was
    unencrypted, so anyone able to reach the port could produce one and the
    responder answered with its own static key -- an identity handed to a
    stranger. Under `psk0` a forgery fails at the first decryption and draws no
    reply.

    A gate rather than authentication of the sender, in two ways spec section
    4.2 sets out: the message carries no responder freshness, so a recorded one
    replays; and a responder computes the static-static value and its own public
    keys when it builds its state, before it reads anything.

    It is a pre-filter, not the authentication: the presented static key is
    still checked against the manifest, and the ephemeral Diffie-Hellman still
    supplies forward secrecy. Someone holding this value alone cannot complete
    an exchange.

    RFC 5869 HKDF, with each input where RFC 5869 puts it: the shared secret is
    the input keying material, the domain is the salt, and the context -- the
    domain again, then both public keys in role order -- is the info. The
    previous form was `HMAC(ss, domain)`, which is a defensible KDF but put the
    domain in the message field and bound no public keys at all, so the same
    value came out for every pair sharing a secret and nothing in it said which
    two keys it belonged to. An external review raised both; the domain carries
    `-v2` because the value on the wire changes.

    The keys go in as initiator then responder rather than sorted, because the
    exchange already has an asymmetry to name and sorting hides it: two peers
    that swap roles derive different values, which is what a transcript binding
    should do.
    """
    ordered = (
        static.public + peer_static if initiator else peer_static + static.public
    )
    return rfc5869_hkdf(
        _hash(profile.static_psk_domain),
        dh(static, peer_static),
        profile.static_psk_domain + ordered,
        HASHLEN,
    )


def rekey_psk(profile: B1Profile, previous_export: bytes) -> bytes:
    """The pre-shared key for a rekey, from the export key it chains to.

    The export key is a session output: what the handshake hands to whoever
    holds the session, for whatever the next thing is. Feeding it straight in
    as the next exchange's psk0 made it also a handshake input, and one value
    serving two constructions is the pattern that lets a later use of the
    export key interact with the rekey chain. One HKDF step under its own
    domain keeps the two apart: the export key remains the thing a session
    produces, and this is the thing a rekey consumes.

    Same shape as `static_psk`: the export key is the input keying material,
    the domain hashed is the salt, the domain is the info. Nothing else goes in
    the info because there is nothing else to bind -- the export key already
    carries the whole previous transcript.
    """
    if len(previous_export) != HASHLEN:
        raise HandshakeError("export key must be 32 bytes")
    return rfc5869_hkdf(
        _hash(profile.rekey_psk_domain),
        previous_export,
        profile.rekey_psk_domain,
        HASHLEN,
    )


def _begin(profile: B1Profile, rekey: bool, psk: bytes) -> SymmetricState:
    """Both exchanges are `psk0`; only where the key comes from differs.

    A rekey chains to the session it replaces, through its export key. An
    initial handshake has no predecessor, so it uses the static-static value
    instead. Either way the key reaches the chaining key rather than only the
    hash, so two exchanges with the same ephemerals but different keys cannot
    derive the same traffic keys.
    """
    if len(psk) != HASHLEN:
        raise HandshakeError("pre-shared key must be 32 bytes")
    state = SymmetricState.initialize(profile.noise_protocol)
    state.mix_hash(prologue(profile, rekey))
    state.mix_key_and_hash(psk)
    return state


def _record_prefix(profile: B1Profile, name: str) -> bytes:
    # First byte zero is what lets a receiver tell a handshake record from a
    # W2 cell without trial decryption: derived epochs have their top bit set.
    return b"\x00" + bytes([profile.record_types[name]])


def _finish(state: SymmetricState, profile: B1Profile, initiator: bool, peer_static: bytes, selection: Selection) -> Session:
    k1, k2 = state.split()
    h = state.handshake_hash
    export_key = noise_hkdf(state.chaining_key, profile.export_domain + h, 1)[0]
    epoch = bytearray(noise_hkdf(state.chaining_key, profile.epoch_domain + h, 1)[0][:4])
    epoch[0] |= 0x80
    return Session(
        handshake_hash=h,
        initiator_to_responder=k1,
        responder_to_initiator=k2,
        epoch=bytes(epoch),
        export_key=export_key,
        peer_static=peer_static,
        selection=selection,
    )


class Initiator:
    def __init__(
        self,
        profile: B1Profile,
        static: Keypair,
        ephemeral: Keypair,
        expected_peer_static: bytes,
        offer: Offer,
        previous_export: bytes | None = None,
        admission_psk: bytes | None = None,
        admission_identifier: bytes | None = None,
        admission_cookie: bytes | None = None,
    ) -> None:
        """See `Responder` for the three modes.

        A joiner still pins its peer even on an admission handshake: an
        invitation is delivered out of band and can carry the inviter's static
        public key, so only the inviter is left learning an identity it did
        not already hold.
        """
        if previous_export is not None and admission_psk is not None:
            raise HandshakeError("a rekey has no admission key")
        if (admission_psk is None) != (admission_identifier is None):
            raise HandshakeError("an admission handshake needs its invitation identifier")
        self.profile = profile
        self.static = static
        self.ephemeral = ephemeral
        self.expected_peer_static = expected_peer_static
        self.offer = offer
        self.rekey = previous_export is not None
        self.admission = admission_psk is not None
        # The first attempt carries no cookie, because a joiner has none until
        # it is challenged. A zero cookie is not a special case: it simply fails
        # to verify, which is the one thing that provokes a challenge.
        self.admission_identifier = admission_identifier
        self.admission_cookie = admission_cookie or bytes(profile.cookie_bytes)
        if previous_export is not None:
            psk = rekey_psk(profile, previous_export)
        elif admission_psk is not None:
            psk = admission_psk
        else:
            psk = static_psk(profile, static, expected_peer_static, initiator=True)
        self.state = _begin(profile, self.rekey, psk)
        self.remote_ephemeral: bytes | None = None
        self.selection: Selection | None = None
        # Set by read_message_2 on an admission handshake, once the responder
        # has proved it holds this advertisement key. Comparing it against a
        # cached candidate is the caller's step: this only says the exchange was
        # bound to it.
        self.advertisement_key: bytes | None = None

    def _type(self, stage: str) -> str:
        if self.admission and stage == "initiate":
            return "admission_initiate"
        return ("rekey_" if self.rekey else "handshake_") + stage

    def _initiate_width(self) -> int:
        # Under psk0 there is a key from the start, so the first payload is
        # encrypted and its ciphertext carries a tag. The admission initiate
        # spends 48 of those bytes on its cleartext header, so it frames a
        # narrower payload; the record is one cell either way.
        if self.admission:
            return self.profile.admission_payload_bytes
        return self.profile.initiate_payload_psk_bytes

    def write_message_1(self) -> bytes:
        # -> [header] e
        record = _record_prefix(self.profile, self._type("initiate"))
        if self.admission:
            header = admission_header(
                self.profile, self.admission_identifier, self.admission_cookie
            )
            # Mixed before the ephemeral, so the cleartext header is inside the
            # transcript: altering it makes the payload fail to open.
            self.state.mix_hash(header)
            record += header
        _mix_ephemeral(self.state, self.ephemeral.public)
        payload = _frame_payload(self.offer.encode(self.profile), self._initiate_width())
        record += self.ephemeral.public
        record += self.state.encrypt_and_hash(payload)
        if len(record) != self.profile.record_bytes:
            raise HandshakeError("record width mismatch")
        return record

    def read_message_2(self, record: bytes) -> None:
        # <- e, ee, s, es
        p = self.profile
        if len(record) != p.record_bytes or record[:2] != _record_prefix(p, self._type("respond")):
            raise HandshakeError("unexpected record")
        cursor = 2
        re = record[cursor : cursor + DHLEN]
        cursor += DHLEN
        _mix_ephemeral(self.state, re)
        self.state.mix_key(dh(self.ephemeral, re))
        rs = self.state.decrypt_and_hash(record[cursor : cursor + DHLEN + TAGLEN])
        cursor += DHLEN + TAGLEN
        self.state.mix_key(dh(self.ephemeral, rs))
        # Captured before the payload is decrypted, because that is the value
        # the responder signed and the one the AEAD is about to consume as
        # associated data. Reading it afterwards would read a hash that already
        # covers the signature verifying against it.
        signed_hash = self.state.handshake_hash
        framed = self.state.decrypt_and_hash(record[cursor:])
        body = _unframe_payload(framed, p.respond_payload_bytes)
        if self.admission:
            # ADR 0049: selection, then the advertisement key and its signature.
            if len(body) != SELECTION_BYTES + DHLEN + SIGNATURE_BYTES:
                raise HandshakeError("malformed admission respond payload")
            advertisement_key = body[SELECTION_BYTES : SELECTION_BYTES + DHLEN]
            signature = body[SELECTION_BYTES + DHLEN :]
            verify_transition(p, advertisement_key, signed_hash, signature)
            self.advertisement_key = advertisement_key
            body = body[:SELECTION_BYTES]
        selection = Selection.decode(body)
        # The pin check comes after authentication of the presented key and
        # before any key is derived: a mismatch aborts here.
        if not hmac.compare_digest(rs, self.expected_peer_static):
            raise HandshakeError("responder static key does not match the manifest")
        if not selection.within(self.offer):
            raise HandshakeError("selection is not within the offer")
        self.remote_ephemeral = re
        self.selection = selection

    def write_message_3(self) -> tuple[bytes, Session]:
        # -> s, se
        p = self.profile
        if self.remote_ephemeral is None or self.selection is None:
            raise HandshakeError("message 2 not processed")
        record = _record_prefix(p, self._type("finish"))
        record += self.state.encrypt_and_hash(self.static.public)
        self.state.mix_key(dh(self.static, self.remote_ephemeral))
        payload = _frame_payload(b"", p.finish_payload_bytes)
        record += self.state.encrypt_and_hash(payload)
        if len(record) != p.record_bytes:
            raise HandshakeError("record width mismatch")
        return record, _finish(self.state, p, True, self.expected_peer_static, self.selection)


class Responder:
    def __init__(
        self,
        profile: B1Profile,
        static: Keypair,
        ephemeral: Keypair,
        expected_peer_static: bytes | None,
        previous_export: bytes | None = None,
        admission_psk: bytes | None = None,
        admission_identifier: bytes | None = None,
        admission_cookie: bytes | None = None,
        advertisement_secret: bytes | None = None,
    ) -> None:
        """A responder in one of three modes, distinguished by its key source.

        `previous_export` is a rekey. `admission_psk` is an admission handshake
        with a peer this responder has no manifest entry for: the key comes
        from whatever admitted it, and the presented static key is *recorded*
        rather than checked, because there is nothing yet to check it against.
        Neither means the manifest path, where the key is derived from the
        static-static value and the presented key is pinned.

        The caller supplies the admission key rather than this module deriving
        it, so B1.1 does not have to know what B1.2 admits with.
        """
        if previous_export is not None and admission_psk is not None:
            raise HandshakeError("a rekey has no admission key")
        if expected_peer_static is None and admission_psk is None:
            raise HandshakeError("only an admission handshake may omit the peer static")
        if (admission_psk is None) != (admission_identifier is None):
            raise HandshakeError("an admission handshake needs its invitation identifier")
        # ADR 0049 D16: unconditional on the admission path. A responder that
        # could decline to bind itself would present the joiner with exactly the
        # case it cannot tell apart from an attack, so there is no way to admit
        # without one.
        if (admission_psk is None) != (advertisement_secret is None):
            raise HandshakeError("an admission handshake needs an advertisement key")
        self.profile = profile
        self.static = static
        self.ephemeral = ephemeral
        self.expected_peer_static = expected_peer_static
        self.admission = admission_psk is not None
        if advertisement_secret is not None:
            self.advertisement_secret = advertisement_secret
            self.advertisement_public = (
                Ed25519PrivateKey.from_private_bytes(advertisement_secret)
                .public_key()
                .public_bytes_raw()
            )
        self.rekey = previous_export is not None
        if previous_export is not None:
            psk = rekey_psk(profile, previous_export)
        elif admission_psk is not None:
            psk = admission_psk
        else:
            psk = static_psk(profile, static, expected_peer_static, initiator=False)
        self.state = _begin(profile, self.rekey, psk)
        # What the caller already read from the record's cleartext header and
        # acted on: the identifier it found the key from, and the cookie it
        # verified. read_message_1 confirms the record carries exactly these,
        # so the key and the routability proof belong to the record being read.
        self.admission_identifier = admission_identifier
        self.admission_cookie = admission_cookie or bytes(profile.cookie_bytes)
        self.remote_ephemeral: bytes | None = None
        self.offer: Offer | None = None
        self.selection: Selection | None = None
        # Set only on an admission handshake that completed, and only there, so
        # a caller cannot mistake a pinned peer for a newly learned one. This
        # is the value ADR 0046 D8 promotes into the manifest.
        self.promoted_static: bytes | None = None

    def _type(self, stage: str) -> str:
        if self.admission and stage == "initiate":
            return "admission_initiate"
        return ("rekey_" if self.rekey else "handshake_") + stage

    def _initiate_width(self) -> int:
        if self.admission:
            return self.profile.admission_payload_bytes
        return self.profile.initiate_payload_psk_bytes

    def read_message_1(self, record: bytes) -> Offer:
        p = self.profile
        if len(record) != p.record_bytes or record[:2] != _record_prefix(p, self._type("initiate")):
            raise HandshakeError("unexpected record")
        cursor = 2
        if self.admission:
            expected = admission_header(p, self.admission_identifier, self.admission_cookie)
            found = record[cursor : cursor + p.admission_header_bytes]
            # A record whose header is not the one the caller acted on is a
            # different record: the key would be right and the routability proof
            # would belong to something else.
            if not hmac.compare_digest(found, expected):
                raise HandshakeError("admission header does not match")
            self.state.mix_hash(found)
            cursor += p.admission_header_bytes
        re = record[cursor : cursor + DHLEN]
        cursor += DHLEN
        _mix_ephemeral(self.state, re)
        framed = self.state.decrypt_and_hash(record[cursor:])
        offer = Offer.decode(p, _unframe_payload(framed, self._initiate_width()))
        self.remote_ephemeral = re
        self.offer = offer
        return offer

    def write_message_2(self, selection: Selection) -> bytes:
        p = self.profile
        if self.remote_ephemeral is None or self.offer is None:
            raise HandshakeError("message 1 not processed")
        if not selection.within(self.offer):
            raise HandshakeError("selection is not within the offer")
        _mix_ephemeral(self.state, self.ephemeral.public)
        self.state.mix_key(dh(self.ephemeral, self.remote_ephemeral))
        record = _record_prefix(p, self._type("respond")) + self.ephemeral.public
        record += self.state.encrypt_and_hash(self.static.public)
        self.state.mix_key(dh(self.static, self.remote_ephemeral))
        body = selection.encode()
        if self.admission:
            # ADR 0049 D15/D16. Signed over the transcript as it stands here,
            # which is the value the AEAD below uses as associated data, so the
            # initiator holds the same one before it decrypts.
            body += self.advertisement_public
            body += sign_transition(p, self.advertisement_secret, self.state.handshake_hash)
        payload = _frame_payload(body, p.respond_payload_bytes)
        record += self.state.encrypt_and_hash(payload)
        if len(record) != p.record_bytes:
            raise HandshakeError("record width mismatch")
        self.selection = selection
        return record

    def read_message_3(self, record: bytes) -> Session:
        p = self.profile
        if self.selection is None:
            raise HandshakeError("message 2 not sent")
        if len(record) != p.record_bytes or record[:2] != _record_prefix(p, self._type("finish")):
            raise HandshakeError("unexpected record")
        cursor = 2
        rs = self.state.decrypt_and_hash(record[cursor : cursor + DHLEN + TAGLEN])
        cursor += DHLEN + TAGLEN
        self.state.mix_key(dh(self.ephemeral, rs))
        framed = self.state.decrypt_and_hash(record[cursor:])
        if _unframe_payload(framed, p.finish_payload_bytes) != b"":
            raise HandshakeError("unexpected finish payload")
        if self.admission:
            # There is no manifest entry to check against -- that is what
            # makes this an admission -- so the key is recorded for promotion
            # instead. What authenticated the peer is the admission key the
            # whole exchange ran under; without holding it, nothing reaches
            # this line, because message 1 would not have decrypted.
            self.promoted_static = rs
        elif not hmac.compare_digest(rs, self.expected_peer_static):
            raise HandshakeError("initiator static key does not match the manifest")
        return _finish(self.state, p, False, rs, self.selection)
