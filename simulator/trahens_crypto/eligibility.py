"""Eligibility-suite boundary for Trahens discovery.

The active R1 profile deliberately removes endpoint-specific cryptography from
DISCOVER.  Discovery selects a generic rendezvous-gateway service.  A private,
short-lived, single-use capability is presented only after a route to a gateway
has reached READY.

C1 and the symbolic C2 oracle remain available as research controls.  The
literal C2 k=2 transcription is exposed only as a disabled provider and fails
closed.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Callable, Final, Protocol, runtime_checkable

from . import ristretto as r255
from .c1 import (
    C1_SUITE_ID,
    CryptoError,
    EndpointKeys,
    URECiphertext,
    ure_encrypt,
    ure_is_eligible,
    ure_rerandomize,
)
from .c2_ideal import (
    C2Error,
    C2IdealOracle,
    C2_SUITE_ID,
    apply_literal_tag,
    contains_literal_tag,
)

R1_SUITE_ID: Final[bytes] = b"\x01\x01"
R1_DISCOVERY_NONCE_BYTES: Final[int] = 32
R1_CAPABILITY_BYTES: Final[int] = 32
R1_SERVICE_CLASS: Final[bytes] = b"Trahens/R1/rendezvous-gateway"
C2_K2_DISABLED_SUITE_ID: Final[bytes] = b"\x7f\x02"


class EligibilityError(ValueError):
    """Uniform provider-boundary failure."""


@runtime_checkable
class EligibilitySuite(Protocol):
    """Protocol-facing discovery eligibility interface.

    ``initial_capsule`` and ``transform`` are called only for DISCOVER.  A
    provider may implement endpoint-specific eligibility (research controls) or
    generic service discovery (R1).  The route lifecycle is intentionally
    independent from the provider internals.
    """

    name: str
    suite_id: bytes
    network_enabled: bool
    endpoint_specific: bool

    def initial_capsule(self) -> bytes: ...

    def transform(self, capsule: bytes) -> bytes: ...

    def accepts(self, capsule: bytes) -> bool: ...

    def apply_test_tag(self, capsule: bytes, tag: bytes) -> bytes: ...

    def recognizes_test_tag(self, capsule: bytes, tag: bytes) -> bool: ...


@dataclass(frozen=True)
class RendezvousRegistration:
    gateway_id: int
    token_hash: bytes
    created_at_ms: int
    expires_at_ms: int
    endpoint_handle: bytes


class RendezvousRegistry:
    """Deterministic model of the gateway-side R1 capability table.

    The raw token is never retained.  The table is local to a rendezvous
    gateway and indexes H(domain || token).  A successful redemption removes
    the record before returning the endpoint handle.
    """

    def __init__(self, *, domain: bytes = b"Trahens-R1-capability-v1") -> None:
        if not domain:
            raise ValueError("domain must not be empty")
        self._domain = bytes(domain)
        self._records: dict[tuple[int, bytes], RendezvousRegistration] = {}

    def token_hash(self, token: bytes) -> bytes:
        if len(token) != R1_CAPABILITY_BYTES or token == bytes(R1_CAPABILITY_BYTES):
            raise EligibilityError("invalid R1 capability")
        return hashlib.sha256(self._domain + token).digest()

    def register(
        self,
        *,
        gateway_id: int,
        token: bytes,
        endpoint_handle: bytes,
        now_ms: int,
        ttl_ms: int,
    ) -> RendezvousRegistration:
        if gateway_id < 0 or now_ms < 0 or ttl_ms < 1:
            raise EligibilityError("invalid R1 registration bounds")
        if not endpoint_handle:
            raise EligibilityError("endpoint handle must not be empty")
        token_hash = self.token_hash(token)
        key = (gateway_id, token_hash)
        if key in self._records:
            raise EligibilityError("duplicate R1 capability")
        record = RendezvousRegistration(
            gateway_id=gateway_id,
            token_hash=token_hash,
            created_at_ms=now_ms,
            expires_at_ms=now_ms + ttl_ms,
            endpoint_handle=bytes(endpoint_handle),
        )
        self._records[key] = record
        return record

    def redeem(self, *, gateway_id: int, token: bytes, now_ms: int) -> bytes | None:
        if now_ms < 0:
            raise EligibilityError("now_ms cannot be negative")
        token_hash = self.token_hash(token)
        key = (gateway_id, token_hash)
        record = self._records.pop(key, None)
        if record is None or not (record.created_at_ms <= now_ms < record.expires_at_ms):
            return None
        return record.endpoint_handle

    def expire(self, now_ms: int) -> int:
        if now_ms < 0:
            raise EligibilityError("now_ms cannot be negative")
        expired = [
            key for key, record in self._records.items()
            if record.expires_at_ms <= now_ms
        ]
        for key in expired:
            self._records.pop(key, None)
        return len(expired)

    @property
    def live_records(self) -> int:
        return len(self._records)


class R1RendezvousSuite:
    """Active generic-gateway discovery profile.

    The DISCOVER field is a fresh non-semantic nonce.  A relay replaces it
    rather than attempting to preserve or rerandomize a destination selector.
    Eligibility is determined by the node's local rendezvous-gateway role.  The
    endpoint-specific capability is used only after READY and therefore never
    appears in a DISCOVER message.
    """

    name = "r1-rendezvous"
    suite_id = R1_SUITE_ID
    network_enabled = True
    endpoint_specific = False

    def __init__(self, random_bytes: Callable[[int], bytes]) -> None:
        self._random_bytes = random_bytes

    def _fresh_nonce(self) -> bytes:
        for _ in range(32):
            value = self._random_bytes(R1_DISCOVERY_NONCE_BYTES)
            if value != bytes(R1_DISCOVERY_NONCE_BYTES):
                return value
        raise EligibilityError("unable to generate R1 discovery nonce")

    def initial_capsule(self) -> bytes:
        return self._fresh_nonce()

    def transform(self, capsule: bytes) -> bytes:
        if len(capsule) != R1_DISCOVERY_NONCE_BYTES:
            raise EligibilityError("invalid R1 discovery nonce")
        return self._fresh_nonce()

    def accepts(self, capsule: bytes) -> bool:
        return (
            len(capsule) == R1_DISCOVERY_NONCE_BYTES
            and capsule != bytes(R1_DISCOVERY_NONCE_BYTES)
        )

    def apply_test_tag(self, capsule: bytes, tag: bytes) -> bytes:
        if not self.accepts(capsule) or not tag or len(tag) > len(capsule):
            raise EligibilityError("invalid R1 tag input")
        output = bytearray(capsule)
        output[: len(tag)] = tag
        return bytes(output)

    def recognizes_test_tag(self, capsule: bytes, tag: bytes) -> bool:
        return bool(tag) and len(capsule) == R1_DISCOVERY_NONCE_BYTES and capsule.startswith(tag)


class C1NegativeControlSuite:
    name = "c1-negative-control"
    suite_id = C1_SUITE_ID
    network_enabled = False
    endpoint_specific = True

    def __init__(
        self,
        endpoint_keys: EndpointKeys,
        scalar: Callable[[bytes], bytes],
    ) -> None:
        self._keys = endpoint_keys
        self._scalar = scalar

    def initial_capsule(self) -> bytes:
        return ure_encrypt(
            self._keys.eligibility_public,
            r0=self._scalar(b"ure-root-r0"),
            r1=self._scalar(b"ure-root-r1"),
        ).encode()

    def transform(self, capsule: bytes) -> bytes:
        return ure_rerandomize(
            URECiphertext.decode(capsule),
            s0=self._scalar(b"ure-s0"),
            s1=self._non_identity_scalar(),
        ).encode()

    def _non_identity_scalar(self) -> bytes:
        for _ in range(32):
            value = self._scalar(b"ure-s1")
            if value != r255.SCALAR_ONE:
                return value
        raise EligibilityError("unable to generate non-identity C1 scalar")

    def accepts(self, capsule: bytes) -> bool:
        try:
            return ure_is_eligible(
                self._keys.eligibility_secret,
                URECiphertext.decode(capsule),
            )
        except (CryptoError, ValueError):
            return False

    def apply_test_tag(self, capsule: bytes, tag: bytes) -> bytes:
        from .tagging import apply_ratio_tag

        if len(tag) != 32:
            raise EligibilityError("C1 test tag must encode one scalar")
        return apply_ratio_tag(URECiphertext.decode(capsule), tag).encode()

    def recognizes_test_tag(self, capsule: bytes, tag: bytes) -> bool:
        from .tagging import matches_ratio_tag

        try:
            return matches_ratio_tag(URECiphertext.decode(capsule), tag)
        except (CryptoError, ValueError):
            return False


class C2SymbolicControlSuite:
    name = "c2-symbolic-control"
    suite_id = C2_SUITE_ID
    network_enabled = False
    endpoint_specific = True

    def __init__(self, seed: bytes) -> None:
        self._oracle = C2IdealOracle(seed)
        self._keys = self._oracle.keygen(b"target")

    def initial_capsule(self) -> bytes:
        try:
            return self._oracle.encrypt(self._keys.public)
        except C2Error as exc:
            raise EligibilityError("C2 symbolic initialization failed") from exc

    def transform(self, capsule: bytes) -> bytes:
        try:
            return self._oracle.rerandomize(capsule)
        except C2Error as exc:
            raise EligibilityError("C2 symbolic transformation failed") from exc

    def accepts(self, capsule: bytes) -> bool:
        return self._oracle.is_eligible(self._keys.secret, capsule)

    def apply_test_tag(self, capsule: bytes, tag: bytes) -> bytes:
        try:
            return apply_literal_tag(capsule, tag)
        except C2Error as exc:
            raise EligibilityError("C2 symbolic tag failed") from exc

    def recognizes_test_tag(self, capsule: bytes, tag: bytes) -> bool:
        return contains_literal_tag(capsule, tag)


class C2K2ExperimentalDisabledSuite:
    """Reserved audit provider; every protocol operation fails closed."""

    name = "c2-k2-experimental-disabled"
    suite_id = C2_K2_DISABLED_SUITE_ID
    network_enabled = False
    endpoint_specific = True

    @staticmethod
    def _disabled() -> EligibilityError:
        return EligibilityError(
            "C2 k=2 audit provider is disabled: unresolved finite-field group action"
        )

    def initial_capsule(self) -> bytes:
        raise self._disabled()

    def transform(self, capsule: bytes) -> bytes:
        del capsule
        raise self._disabled()

    def accepts(self, capsule: bytes) -> bool:
        del capsule
        return False

    def apply_test_tag(self, capsule: bytes, tag: bytes) -> bytes:
        del capsule, tag
        raise self._disabled()

    def recognizes_test_tag(self, capsule: bytes, tag: bytes) -> bool:
        del capsule, tag
        return False


def make_suite(
    name: str,
    *,
    random_bytes: Callable[[int], bytes],
    scalar: Callable[[bytes], bytes],
    endpoint_keys: EndpointKeys,
    seed: bytes,
) -> EligibilitySuite:
    if name == "r1":
        return R1RendezvousSuite(random_bytes)
    if name == "c1":
        return C1NegativeControlSuite(endpoint_keys, scalar)
    if name == "c2-ideal":
        return C2SymbolicControlSuite(seed)
    if name == "c2-k2-disabled":
        return C2K2ExperimentalDisabledSuite()
    raise EligibilityError(f"unknown eligibility suite: {name}")


def issue_capability(
    random_bytes: Callable[[int], bytes],
) -> bytes:
    """Generate one non-zero R1 capability for private delivery to a client."""

    for _ in range(32):
        token = random_bytes(R1_CAPABILITY_BYTES)
        if token != bytes(R1_CAPABILITY_BYTES):
            return token
    raise EligibilityError("unable to generate R1 capability")


def capability_commitment(token: bytes) -> bytes:
    if len(token) != R1_CAPABILITY_BYTES or token == bytes(R1_CAPABILITY_BYTES):
        raise EligibilityError("invalid R1 capability")
    return hashlib.sha256(b"Trahens-R1-capability-commitment-v1" + token).digest()


def equal_capability(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)
