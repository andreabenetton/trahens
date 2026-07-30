"""Trahens C1 research cryptographic profile.

The implementation exists to make encodings and deterministic vectors precise.
It is not independently audited and MUST NOT be used as production security code.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Iterable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import ristretto as r255

C1_SUITE_ID = b"\x00\x01"
C1_VERSION = b"\x01"
URE_BYTES = 4 * r255.POINT_BYTES
REPLY_ENC_BYTES = r255.POINT_BYTES
AEAD_TAG_BYTES = 16

_LABEL_PREFIX = b"Trahens-C1-v1"
_MARKER = r255.point_from_label(b"eligibility-marker")


class CryptoError(ValueError):
    """Uniform public error for malformed or unauthenticated cryptographic input."""


def _lp16(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise CryptoError("field is too long")
    return len(value).to_bytes(2, "big") + value


def _encode_fields(label: bytes, fields: Iterable[bytes]) -> bytes:
    body = _LABEL_PREFIX + _lp16(label)
    for field in fields:
        body += _lp16(field)
    return body


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = bytes(hashlib.sha256().digest_size)
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0 or length > 255 * hashlib.sha256().digest_size:
        raise CryptoError("invalid HKDF output length")
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
        counter += 1
    return output[:length]


def _derive_reply_context(dh_point: bytes, encapsulated: bytes, recipient_public: bytes, info: bytes) -> tuple[bytes, bytes]:
    context = _encode_fields(b"reply-kem-context", [C1_SUITE_ID, encapsulated, recipient_public, info])
    prk = _hkdf_extract(b"", _encode_fields(b"reply-kem-dh", [dh_point]))
    secret = _hkdf_expand(prk, _encode_fields(b"reply-kem-secret", [context]), 32)
    key = _hkdf_expand(secret, _encode_fields(b"reply-aead-key", [context]), 32)
    nonce = _hkdf_expand(secret, _encode_fields(b"reply-aead-nonce", [context]), 12)
    return key, nonce


@dataclass(frozen=True)
class URECiphertext:
    """Additive-notation Golle-Jakobsson-Juels-Syverson URE ciphertext."""

    u0: bytes
    v0: bytes
    u1: bytes
    v1: bytes

    def encode(self) -> bytes:
        for point in (self.u0, self.v0, self.u1, self.v1):
            r255.require_point(point)
        return self.u0 + self.v0 + self.u1 + self.v1

    @classmethod
    def decode(cls, encoded: bytes) -> "URECiphertext":
        if len(encoded) != URE_BYTES:
            raise CryptoError("invalid URE ciphertext")
        points = [encoded[index:index + 32] for index in range(0, URE_BYTES, 32)]
        try:
            for point in points:
                r255.require_point(point)
        except r255.RistrettoError as exc:
            raise CryptoError("invalid URE ciphertext") from exc
        return cls(*points)


@dataclass(frozen=True)
class EndpointKeys:
    eligibility_secret: bytes
    eligibility_public: bytes
    signing_seed: bytes
    signing_public: bytes
    descriptor: bytes
    address: bytes

    def sign(self, transcript_hash: bytes) -> bytes:
        if len(transcript_hash) != 32:
            raise CryptoError("transcript hash must be 32 bytes")
        return Ed25519PrivateKey.from_private_bytes(self.signing_seed).sign(transcript_hash)


def build_endpoint_keys(label: bytes) -> EndpointKeys:
    eligibility_secret = r255.scalar_from_label(b"eligibility-key/" + label)
    eligibility_public = r255.scalarmult_base(eligibility_secret)
    signing_seed = hashlib.sha256(_LABEL_PREFIX + b"/signing-seed/" + label).digest()
    signing_private = Ed25519PrivateKey.from_private_bytes(signing_seed)
    signing_public = signing_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    descriptor = C1_VERSION + C1_SUITE_ID + eligibility_public + signing_public
    address = hashlib.sha256(_encode_fields(b"endpoint-address", [descriptor])).digest()
    return EndpointKeys(
        eligibility_secret=eligibility_secret,
        eligibility_public=eligibility_public,
        signing_seed=signing_seed,
        signing_public=signing_public,
        descriptor=descriptor,
        address=address,
    )


def eligibility_marker() -> bytes:
    return _MARKER


def ure_encrypt(
    recipient_public: bytes,
    *,
    plaintext: bytes | None = None,
    r0: bytes | None = None,
    r1: bytes | None = None,
) -> URECiphertext:
    try:
        r255.require_point(recipient_public, allow_identity=False)
        message = _MARKER if plaintext is None else r255.require_point(plaintext)
        r0 = r255.scalar_from_label(os.urandom(32), dst=b"Trahens-C1-ure-r0") if r0 is None else r255.require_scalar(r0)
        r1 = r255.scalar_from_label(os.urandom(32), dst=b"Trahens-C1-ure-r1") if r1 is None else r255.require_scalar(r1)
        u0 = r255.point_add(message, r255.scalarmult(r0, recipient_public))
        v0 = r255.scalarmult_base(r0)
        u1 = r255.scalarmult(r1, recipient_public)
        v1 = r255.scalarmult_base(r1)
        return URECiphertext(u0, v0, u1, v1)
    except r255.RistrettoError as exc:
        raise CryptoError("URE encryption failed") from exc


def ure_rerandomize(
    ciphertext: URECiphertext,
    *,
    s0: bytes | None = None,
    s1: bytes | None = None,
) -> URECiphertext:
    try:
        encoded = ciphertext.encode()
        ciphertext = URECiphertext.decode(encoded)
        s0 = r255.scalar_from_label(os.urandom(32), dst=b"Trahens-C1-ure-s0") if s0 is None else r255.require_scalar(s0)
        if s1 is None:
            while True:
                s1 = r255.scalar_from_label(os.urandom(32), dst=b"Trahens-C1-ure-s1")
                if s1 != r255.SCALAR_ONE:
                    break
        else:
            s1 = r255.require_scalar(s1)
            if s1 == r255.SCALAR_ONE:
                raise r255.RistrettoError("identity rerandomization scalar is not allowed")
        rerandomized = URECiphertext(
            u0=r255.point_add(ciphertext.u0, r255.scalarmult(s0, ciphertext.u1)),
            v0=r255.point_add(ciphertext.v0, r255.scalarmult(s0, ciphertext.v1)),
            u1=r255.scalarmult(s1, ciphertext.u1),
            v1=r255.scalarmult(s1, ciphertext.v1),
        )
        if hmac.compare_digest(encoded, rerandomized.encode()):
            raise r255.RistrettoError("rerandomization did not change the ciphertext")
        return rerandomized
    except r255.RistrettoError as exc:
        raise CryptoError("URE rerandomization failed") from exc


def ure_decrypt(recipient_secret: bytes, ciphertext: URECiphertext) -> bytes:
    try:
        secret = r255.require_scalar(recipient_secret)
        ciphertext = URECiphertext.decode(ciphertext.encode())
        check = r255.point_sub(ciphertext.u1, r255.scalarmult(secret, ciphertext.v1))
        if not hmac.compare_digest(check, r255.IDENTITY):
            raise CryptoError("URE decryption failed")
        message = r255.point_sub(ciphertext.u0, r255.scalarmult(secret, ciphertext.v0))
        return message
    except (r255.RistrettoError, CryptoError) as exc:
        raise CryptoError("URE decryption failed") from exc


def ure_is_eligible(recipient_secret: bytes, ciphertext: URECiphertext) -> bool:
    try:
        message = ure_decrypt(recipient_secret, ciphertext)
        return hmac.compare_digest(message, _MARKER)
    except CryptoError:
        return False


def reply_tweak_public(public: bytes, delta: bytes) -> bytes:
    try:
        r255.require_point(public, allow_identity=False)
        delta = r255.require_scalar(delta)
        tweaked = r255.point_add(public, r255.scalarmult_base(delta))
        return r255.require_point(tweaked, allow_identity=False)
    except r255.RistrettoError as exc:
        raise CryptoError("reply public-key tweak failed") from exc


def reply_tweak_secret(secret: bytes, delta: bytes) -> bytes:
    try:
        secret = r255.require_scalar(secret)
        delta = r255.require_scalar(delta)
        tweaked = r255.scalar_add(secret, delta)
        return r255.require_scalar(tweaked)
    except r255.RistrettoError as exc:
        raise CryptoError("reply secret-key tweak failed") from exc


def reply_seal(
    recipient_public: bytes,
    plaintext: bytes,
    *,
    aad: bytes,
    info: bytes,
    ephemeral_secret: bytes | None = None,
) -> bytes:
    try:
        recipient_public = r255.require_point(recipient_public, allow_identity=False)
        ephemeral_secret = (
            r255.scalar_from_label(os.urandom(32), dst=b"Trahens-C1-reply-ephemeral")
            if ephemeral_secret is None
            else r255.require_scalar(ephemeral_secret)
        )
        encapsulated = r255.scalarmult_base(ephemeral_secret)
        dh_point = r255.scalarmult(ephemeral_secret, recipient_public)
        key, nonce = _derive_reply_context(dh_point, encapsulated, recipient_public, info)
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
        return encapsulated + ciphertext
    except (r255.RistrettoError, ValueError) as exc:
        raise CryptoError("reply encryption failed") from exc


def reply_open(
    recipient_secret: bytes,
    sealed: bytes,
    *,
    aad: bytes,
    info: bytes,
) -> bytes:
    try:
        recipient_secret = r255.require_scalar(recipient_secret)
        if len(sealed) < REPLY_ENC_BYTES + AEAD_TAG_BYTES:
            raise CryptoError("reply decryption failed")
        encapsulated = sealed[:REPLY_ENC_BYTES]
        ciphertext = sealed[REPLY_ENC_BYTES:]
        r255.require_point(encapsulated, allow_identity=False)
        recipient_public = r255.scalarmult_base(recipient_secret)
        dh_point = r255.scalarmult(recipient_secret, encapsulated)
        key, nonce = _derive_reply_context(dh_point, encapsulated, recipient_public, info)
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except (r255.RistrettoError, InvalidTag, ValueError, CryptoError) as exc:
        raise CryptoError("reply decryption failed") from exc


def candidate_transcript_hash(fields: Iterable[bytes]) -> bytes:
    return hashlib.sha256(_encode_fields(b"candidate-transcript", fields)).digest()


def verify_candidate_signature(signing_public: bytes, transcript_hash: bytes, signature: bytes) -> bool:
    try:
        if len(signing_public) != 32 or len(transcript_hash) != 32 or len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(signing_public).verify(signature, transcript_hash)
        return True
    except (InvalidSignature, ValueError):
        return False
