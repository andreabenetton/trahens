# SPDX-License-Identifier: Apache-2.0
"""Trahens B1.1 authenticated adjacent-link handshake: Noise XX reference.

The reference exists to make the record encodings, the negotiation payloads
and the key/epoch derivations precise enough to publish vectors against. It is
Noise revision 34 pattern XX instantiated as Noise_XX_25519_ChaChaPoly_SHA256,
with the B1.1 additions layered on top: fixed 1,052-byte records, a
transcript-bound profile negotiation, a manifest pin on the presented static
key, and epoch/export derivation from the finished handshake.

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
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

HASHLEN = 32
DHLEN = 32
TAGLEN = 16


class HandshakeError(ValueError):
    """Any failure; callers must not distinguish causes on the wire."""


# --------------------------------------------------------------------------
# Profile: everything the handshake takes from the registry.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class B1Profile:
    protocol_version: int
    noise_protocol: bytes
    noise_protocol_rekey: bytes
    prologue_domain: bytes
    rekey_chain_domain: bytes
    epoch_domain: bytes
    export_domain: bytes
    record_bytes: int
    initiate_payload_bytes: int
    initiate_payload_psk_bytes: int
    respond_payload_bytes: int
    finish_payload_bytes: int
    record_types: dict[str, int]
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
        noise_protocol_rekey=domains["b1_noise_protocol_rekey"].encode(),
        prologue_domain=domains["b1_prologue"].encode(),
        rekey_chain_domain=domains["b1_rekey_chain"].encode(),
        epoch_domain=domains["b1_epoch"].encode(),
        export_domain=domains["b1_export"].encode(),
        record_bytes=int(widths["b1_record"]),
        initiate_payload_bytes=int(widths["b1_initiate_payload"]),
        initiate_payload_psk_bytes=int(widths["b1_initiate_payload_psk"]),
        respond_payload_bytes=int(widths["b1_respond_payload"]),
        finish_payload_bytes=int(widths["b1_finish_payload"]),
        record_types=dict(registry["b1_record_types"]),
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


def _begin(profile: B1Profile, previous_export: bytes | None) -> SymmetricState:
    rekey = previous_export is not None
    name = profile.noise_protocol_rekey if rekey else profile.noise_protocol
    state = SymmetricState.initialize(name)
    state.mix_hash(prologue(profile, rekey))
    if previous_export is not None:
        if len(previous_export) != HASHLEN:
            raise HandshakeError("export key must be 32 bytes")
        state.mix_key_and_hash(previous_export)
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
    ) -> None:
        self.profile = profile
        self.static = static
        self.ephemeral = ephemeral
        self.expected_peer_static = expected_peer_static
        self.offer = offer
        self.rekey = previous_export is not None
        self.state = _begin(profile, previous_export)
        self.remote_ephemeral: bytes | None = None
        self.selection: Selection | None = None

    def _type(self, stage: str) -> str:
        return ("rekey_" if self.rekey else "handshake_") + stage

    def _initiate_width(self) -> int:
        # Under psk0 there is a key from the start, so the first payload is
        # encrypted and its ciphertext carries a tag. The record stays one
        # cell either way; the framed body region is what shrinks.
        return (
            self.profile.initiate_payload_psk_bytes
            if self.rekey
            else self.profile.initiate_payload_bytes
        )

    def write_message_1(self) -> bytes:
        # -> e
        self.state.mix_hash(self.ephemeral.public)
        payload = _frame_payload(self.offer.encode(self.profile), self._initiate_width())
        record = _record_prefix(self.profile, self._type("initiate")) + self.ephemeral.public
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
        self.state.mix_hash(re)
        self.state.mix_key(dh(self.ephemeral, re))
        rs = self.state.decrypt_and_hash(record[cursor : cursor + DHLEN + TAGLEN])
        cursor += DHLEN + TAGLEN
        self.state.mix_key(dh(self.ephemeral, rs))
        framed = self.state.decrypt_and_hash(record[cursor:])
        selection = Selection.decode(_unframe_payload(framed, p.respond_payload_bytes))
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
        expected_peer_static: bytes,
        previous_export: bytes | None = None,
    ) -> None:
        self.profile = profile
        self.static = static
        self.ephemeral = ephemeral
        self.expected_peer_static = expected_peer_static
        self.rekey = previous_export is not None
        self.state = _begin(profile, previous_export)
        self.remote_ephemeral: bytes | None = None
        self.offer: Offer | None = None
        self.selection: Selection | None = None

    def _type(self, stage: str) -> str:
        return ("rekey_" if self.rekey else "handshake_") + stage

    def _initiate_width(self) -> int:
        return (
            self.profile.initiate_payload_psk_bytes
            if self.rekey
            else self.profile.initiate_payload_bytes
        )

    def read_message_1(self, record: bytes) -> Offer:
        p = self.profile
        if len(record) != p.record_bytes or record[:2] != _record_prefix(p, self._type("initiate")):
            raise HandshakeError("unexpected record")
        re = record[2 : 2 + DHLEN]
        self.state.mix_hash(re)
        framed = self.state.decrypt_and_hash(record[2 + DHLEN :])
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
        self.state.mix_hash(self.ephemeral.public)
        self.state.mix_key(dh(self.ephemeral, self.remote_ephemeral))
        record = _record_prefix(p, self._type("respond")) + self.ephemeral.public
        record += self.state.encrypt_and_hash(self.static.public)
        self.state.mix_key(dh(self.static, self.remote_ephemeral))
        payload = _frame_payload(selection.encode(), p.respond_payload_bytes)
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
        if not hmac.compare_digest(rs, self.expected_peer_static):
            raise HandshakeError("initiator static key does not match the manifest")
        return _finish(self.state, p, False, rs, self.selection)
