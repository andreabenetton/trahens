"""Symbolic C2 anonymous rerandomizable RCCA functionality.

This module is an executable *ideal functionality* used to integrate the C2
security contract into the Trahens simulator.  It is deliberately not a
cryptographic construction.  A process-local oracle records the semantic
meaning of opaque fixed-length ciphertext strings, permits only public
rerandomization of registered ciphertexts, and rejects all other mutations.

The concrete target selected by the protocol specification is the anonymous
rerandomizable RCCA-secure PKE framework of Wang et al. (CRYPTO 2021).  The
symbolic backend exists to test protocol composition, active-tagging games,
codec sizing, and failure normalization before a reviewed implementation of a
concrete instantiation is available.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Final

from trahens_spec.generated import SUITE_C2_SYMBOLIC

C2_SUITE_ID: Final[bytes] = SUITE_C2_SYMBOLIC
C2_VERSION: Final[bytes] = b"\x01"
# The k=1 sizing budget models twenty 32-byte group encodings.  It is a
# conservative protocol budget, not a normative encoding of the CRYPTO 2021
# construction.
C2_SYMBOLIC_CIPHERTEXT_BYTES: Final[int] = 640
C2_MARKER: Final[bytes] = hashlib.sha256(
    b"Trahens-C2/eligibility-marker/v1"
).digest()


class C2Error(ValueError):
    """Uniform public error for invalid symbolic C2 operations."""


@dataclass(frozen=True)
class C2EndpointKeys:
    secret: bytes
    public: bytes
    descriptor: bytes
    address: bytes


@dataclass(frozen=True)
class _Record:
    recipient_public: bytes
    plaintext: bytes
    equivalence_class: bytes


class C2IdealOracle:
    """Deterministic process-local model of anonymous Rand-RCCA encryption.

    Ciphertexts are opaque pseudorandom byte strings.  The public
    ``rerandomize`` operation creates an independently distributed string that
    is registered as replay-equivalent to the input.  Any bit-level mutation
    outside that operation is unregistered and therefore rejected.  No public
    method exposes the receiver or equivalence class.
    """

    def __init__(self, seed: bytes = b"Trahens-C2-ideal-default-seed") -> None:
        if not seed:
            raise ValueError("seed must not be empty")
        self._seed = hashlib.sha256(seed).digest()
        self._counter = 0
        self._records: dict[bytes, _Record] = {}
        self._secret_to_public: dict[bytes, bytes] = {}
        self._public_keys: set[bytes] = set()

    def _expand(self, label: bytes, length: int) -> bytes:
        if length < 1:
            raise ValueError("length must be positive")
        self._counter += 1
        context = self._counter.to_bytes(8, "big") + label
        output = bytearray()
        block = 0
        while len(output) < length:
            output.extend(
                hmac.new(
                    self._seed,
                    context + block.to_bytes(4, "big"),
                    hashlib.sha512,
                ).digest()
            )
            block += 1
        return bytes(output[:length])

    @staticmethod
    def _handle(ciphertext: bytes) -> bytes:
        return hashlib.sha256(b"Trahens-C2/handle/v1" + ciphertext).digest()

    def keygen(self, label: bytes) -> C2EndpointKeys:
        if not label:
            raise C2Error("C2 key label must not be empty")
        secret = hashlib.sha256(
            b"Trahens-C2/secret/v1" + self._seed + label
        ).digest()
        public = hashlib.sha256(
            b"Trahens-C2/public/v1" + secret
        ).digest()
        descriptor = C2_VERSION + C2_SUITE_ID + public
        address = hashlib.sha256(
            b"Trahens-C2/address/v1" + descriptor
        ).digest()
        self._secret_to_public[secret] = public
        self._public_keys.add(public)
        return C2EndpointKeys(secret, public, descriptor, address)

    def encrypt(
        self,
        recipient_public: bytes,
        plaintext: bytes = C2_MARKER,
    ) -> bytes:
        if recipient_public not in self._public_keys:
            raise C2Error("unknown C2 recipient public key")
        if not plaintext:
            raise C2Error("C2 plaintext must not be empty")
        equivalence_class = self._expand(b"equivalence-class", 32)
        ciphertext = self._fresh_ciphertext(b"encrypt")
        self._records[self._handle(ciphertext)] = _Record(
            recipient_public=recipient_public,
            plaintext=bytes(plaintext),
            equivalence_class=equivalence_class,
        )
        return ciphertext

    def _fresh_ciphertext(self, label: bytes) -> bytes:
        for _ in range(16):
            ciphertext = self._expand(label, C2_SYMBOLIC_CIPHERTEXT_BYTES)
            if self._handle(ciphertext) not in self._records:
                return ciphertext
        raise C2Error("unable to generate unique C2 ciphertext")

    def rerandomize(self, ciphertext: bytes) -> bytes:
        record = self._records.get(self._handle(ciphertext))
        if record is None or len(ciphertext) != C2_SYMBOLIC_CIPHERTEXT_BYTES:
            raise C2Error("C2 rerandomization failed")
        rerandomized = self._fresh_ciphertext(b"rerandomize")
        self._records[self._handle(rerandomized)] = record
        if hmac.compare_digest(ciphertext, rerandomized):
            raise C2Error("C2 rerandomization did not change ciphertext")
        return rerandomized

    def decrypt(self, recipient_secret: bytes, ciphertext: bytes) -> bytes:
        recipient_public = self._secret_to_public.get(recipient_secret)
        record = self._records.get(self._handle(ciphertext))
        if (
            recipient_public is None
            or record is None
            or len(ciphertext) != C2_SYMBOLIC_CIPHERTEXT_BYTES
            or not hmac.compare_digest(record.recipient_public, recipient_public)
        ):
            raise C2Error("C2 decryption failed")
        return record.plaintext

    def is_eligible(self, recipient_secret: bytes, ciphertext: bytes) -> bool:
        try:
            plaintext = self.decrypt(recipient_secret, ciphertext)
            return hmac.compare_digest(plaintext, C2_MARKER)
        except C2Error:
            return False

    def is_registered(self, ciphertext: bytes) -> bool:
        """Return whether an input is valid in the ideal model.

        This method is for conformance tests and simulator instrumentation only;
        it is not part of the protocol-visible C2 interface.
        """

        return (
            len(ciphertext) == C2_SYMBOLIC_CIPHERTEXT_BYTES
            and self._handle(ciphertext) in self._records
        )

    def equivalent_for_test(self, left: bytes, right: bytes) -> bool:
        """Test replay equivalence for conformance code only."""

        a = self._records.get(self._handle(left))
        b = self._records.get(self._handle(right))
        return a is not None and b is not None and hmac.compare_digest(
            a.equivalence_class, b.equivalence_class
        )


def apply_literal_tag(ciphertext: bytes, tag: bytes, *, offset: int = 0) -> bytes:
    """Install a colluder-recognizable mutation in an opaque C2 ciphertext.

    The attacker overwrites a bounded byte range with a shared marker.  The
    result preserves the ciphertext length but is not an output of
    ``rerandomize`` and is therefore invalid in the ideal functionality.  The
    literal marker makes the negative-path harness meaningful: a downstream
    colluder would recognize the mutation if an honest transform incorrectly
    forwarded it.
    """

    if len(ciphertext) != C2_SYMBOLIC_CIPHERTEXT_BYTES:
        raise C2Error("invalid C2 ciphertext length")
    if not tag:
        raise C2Error("tag must not be empty")
    if offset < 0 or offset + len(tag) > len(ciphertext):
        raise C2Error("tag offset is out of range")
    output = bytearray(ciphertext)
    output[offset : offset + len(tag)] = tag
    return bytes(output)


def contains_literal_tag(ciphertext: bytes, tag: bytes) -> bool:
    """A deliberately weak colluder test used by the symbolic attack model."""

    return bool(tag) and tag in ciphertext
