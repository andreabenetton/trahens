# SPDX-License-Identifier: Apache-2.0
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

from trahens_spec.generated import (
    BYTES_REPLY_AEAD_TAG,
    BYTES_REPLY_ENCAPSULATION,
    BYTES_REPLY_KEY_COMMITMENT,
    DOMAIN_C1_LABEL_PREFIX,
    DOMAIN_C1_REPLY_COMMIT,
    DOMAIN_C1_REPLY_EPHEMERAL,
    DOMAIN_C1_URE_R0,
    DOMAIN_C1_URE_R1,
    DOMAIN_C1_URE_S0,
    DOMAIN_C1_URE_S1,
    SUITE_C1_V2,
)

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import ristretto as r255

C1_SUITE_ID = SUITE_C1_V2
C1_VERSION = b"\x02"
URE_BYTES = 4 * r255.POINT_BYTES
REPLY_ENC_BYTES = BYTES_REPLY_ENCAPSULATION
AEAD_TAG_BYTES = BYTES_REPLY_AEAD_TAG
REPLY_COMMIT_BYTES = BYTES_REPLY_KEY_COMMITMENT

_LABEL_PREFIX = DOMAIN_C1_LABEL_PREFIX
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


def _derive_reply_context(dh_point: bytes, encapsulated: bytes, recipient_public: bytes, info: bytes) -> tuple[bytes, bytes, bytes]:
    """Derive one AEAD key and nonce with one RFC 5869 Extract/Expand schedule.

    The 76-byte output is split into a 32-byte ChaCha20-Poly1305 key, a
    12-byte nonce, and a 32-byte explicit key-commitment key. No HKDF output
    is reused as a new PRK.
    """
    context = _encode_fields(b"reply-kem-context", [C1_SUITE_ID, encapsulated, recipient_public, info])
    prk = _hkdf_extract(b"", _encode_fields(b"reply-kem-dh", [dh_point]))
    okm = _hkdf_expand(prk, _encode_fields(b"reply-kem-key-schedule", [context]), 76)
    return okm[:32], okm[32:44], okm[44:]


@dataclass(frozen=True)
class URECiphertext:
    """Additive-notation Golle-Jakobsson-Juels-Syverson URE ciphertext."""

    u0: bytes
    v0: bytes
    u1: bytes
    v1: bytes

    def encode(self) -> bytes:
        for point in (self.u0, self.v0, self.u1, self.v1):
            r255.require_point(point, allow_identity=False)
        return self.u0 + self.v0 + self.u1 + self.v1

    @classmethod
    def decode(cls, encoded: bytes) -> "URECiphertext":
        if len(encoded) != URE_BYTES:
            raise CryptoError("invalid URE ciphertext")
        points = [encoded[index:index + 32] for index in range(0, URE_BYTES, 32)]
        try:
            for point in points:
                r255.require_point(point, allow_identity=False)
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
        r0 = r255.scalar_from_label(os.urandom(32), dst=DOMAIN_C1_URE_R0) if r0 is None else r255.require_scalar(r0)
        r1 = r255.scalar_from_label(os.urandom(32), dst=DOMAIN_C1_URE_R1) if r1 is None else r255.require_scalar(r1)
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
        s0 = r255.scalar_from_label(os.urandom(32), dst=DOMAIN_C1_URE_S0) if s0 is None else r255.require_scalar(s0)
        if s1 is None:
            while True:
                s1 = r255.scalar_from_label(os.urandom(32), dst=DOMAIN_C1_URE_S1)
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


def reply_blind_public(public: bytes, factor: bytes) -> bytes:
    """Apply Sphinx-style multiplicative blinding to a reply public key."""
    try:
        public = r255.require_point(public, allow_identity=False)
        factor = r255.require_scalar(factor)
        return r255.require_point(r255.scalarmult(factor, public), allow_identity=False)
    except r255.RistrettoError as exc:
        raise CryptoError("reply public-key blinding failed") from exc


def reply_blind_secret(secret: bytes, factor: bytes) -> bytes:
    """Apply the same non-zero blinding factor to the reply secret scalar."""
    try:
        secret = r255.require_scalar(secret)
        factor = r255.require_scalar(factor)
        return r255.scalar_mul(secret, factor)
    except r255.RistrettoError as exc:
        raise CryptoError("reply secret-key blinding failed") from exc


def _reply_commitment(
    commitment_key: bytes,
    *,
    encapsulated: bytes,
    recipient_public: bytes,
    aad: bytes,
    info: bytes,
    ciphertext: bytes,
) -> bytes:
    transcript = _encode_fields(
        b"reply-key-commitment",
        [DOMAIN_C1_REPLY_COMMIT, encapsulated, recipient_public, aad, info, ciphertext],
    )
    return hmac.new(commitment_key, transcript, hashlib.sha256).digest()


def reply_seal(
    recipient_public: bytes,
    plaintext: bytes,
    *,
    aad: bytes,
    info: bytes,
) -> bytes:
    """Seal one reply layer with fresh operating-system entropy.

    The returned object is ``encapsulation || AEAD ciphertext || commitment``.
    The explicit commitment makes accidental or adversarial cross-key
    acceptance negligible even though ChaCha20-Poly1305 is not itself a
    committing AEAD. The production-facing API has no deterministic-ephemeral
    argument; deterministic vectors live outside the installed package.
    """
    try:
        recipient_public = r255.require_point(recipient_public, allow_identity=False)
        ephemeral_secret = r255.scalar_from_label(
            os.urandom(32), dst=DOMAIN_C1_REPLY_EPHEMERAL
        )
        encapsulated = r255.scalarmult_base(ephemeral_secret)
        dh_point = r255.scalarmult(ephemeral_secret, recipient_public)
        key, nonce, commitment_key = _derive_reply_context(
            dh_point, encapsulated, recipient_public, info
        )
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
        commitment = _reply_commitment(
            commitment_key,
            encapsulated=encapsulated,
            recipient_public=recipient_public,
            aad=aad,
            info=info,
            ciphertext=ciphertext,
        )
        return encapsulated + ciphertext + commitment
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
        if len(sealed) < REPLY_ENC_BYTES + AEAD_TAG_BYTES + REPLY_COMMIT_BYTES:
            raise CryptoError("reply decryption failed")
        encapsulated = sealed[:REPLY_ENC_BYTES]
        ciphertext = sealed[REPLY_ENC_BYTES:-REPLY_COMMIT_BYTES]
        commitment = sealed[-REPLY_COMMIT_BYTES:]
        r255.require_point(encapsulated, allow_identity=False)
        recipient_public = r255.scalarmult_base(recipient_secret)
        dh_point = r255.scalarmult(recipient_secret, encapsulated)
        key, nonce, commitment_key = _derive_reply_context(
            dh_point, encapsulated, recipient_public, info
        )
        expected_commitment = _reply_commitment(
            commitment_key,
            encapsulated=encapsulated,
            recipient_public=recipient_public,
            aad=aad,
            info=info,
            ciphertext=ciphertext,
        )
        commitment_ok = hmac.compare_digest(commitment, expected_commitment)
        plaintext: bytes | None = None
        aead_ok = False
        try:
            plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
            aead_ok = True
        except InvalidTag:
            pass
        if not commitment_ok or not aead_ok or plaintext is None:
            raise CryptoError("reply decryption failed")
        return plaintext
    except (r255.RistrettoError, ValueError, CryptoError) as exc:
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
