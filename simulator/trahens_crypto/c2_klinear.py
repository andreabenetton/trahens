# SPDX-License-Identifier: Apache-2.0
"""Literal k=2 transcription and interoperability audit for Trahens C2.

The formulas in this module follow Figure 6 of Wang, Chen, Yang, Huang, Wang,
and Yung, *Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems
Resolved*, CRYPTO 2021, full version IACR ePrint 2021/862.  Theorem 6.10 of
that paper requires k >= 2; the audit therefore fixes k=2 and uses the related
quadratic-residue groups proposed in Section 6.3.

This is deliberately **not** a deployable cryptosystem.  It serves three
purposes: (1) pin down dimensions and canonical encodings, (2) exercise the
key-generation, encryption, and decryption equations, and (3) test the literal
finite-field tag map used by the non-trivial rerandomization step.  That map,
``mu(u) = u mod q``, is not a multiplicative homomorphism from ``QR*_p`` to
``Z_q`` under ordinary group multiplication; the module records both a minimal
counterexample and a deterministic large-parameter witness.  The repository
therefore refuses to select this backend for protocol traffic.  This finding
blocks the literal finite-field instantiation audited here; it is not a proof
against the paper's generic Re-T-SPHF framework or any corrected construction.

The 128-bit Cunningham chain is only a fast conformance parameter set.  It
does not provide a modern security level.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Final, Iterable, Sequence

C2_SUITE_ID: Final[bytes] = b"\x7f\x02"
C2_VERSION: Final[int] = 1
C2_PARAMETER_SET_ID: Final[int] = 1
# 0x7f02 is reserved for the non-deployable audit encoding and is never
# accepted as an M2/W2 network suite.
C2_K: Final[int] = 2

# Deterministically searched Cunningham chain of the first kind, length 3.
# q, p=2q+1, r=4q+3 are all prime.  This is a conformance parameter set only.
C2_TEST_Q: Final[int] = 175513086009046434629810696245711941989
C2_TEST_P: Final[int] = 351026172018092869259621392491423883979
C2_TEST_R: Final[int] = 702052344036185738519242784982847767959

# Header: version(1), suite(2), parameter-set(1).
C2_CIPHERTEXT_HEADER_BYTES: Final[int] = 4
C2_PUBLIC_KEY_HEADER_BYTES: Final[int] = 4

# The Figure 6 ciphertext contains 12 outer and 12 inner group elements when
# k=2: two (k+1)-element language vectors, four scalar hash values per level,
# and the six analogous inner components.
C2_OUTER_ELEMENTS: Final[int] = 12
C2_INNER_ELEMENTS: Final[int] = 12

C2_ELIGIBILITY_LABEL: Final[bytes] = b"Trahens-C2/eligibility-marker/v2"


class C2Error(ValueError):
    """Uniform public error for malformed or invalid C2 inputs."""


class C2ConformanceGap(RuntimeError):
    """Raised when the unaudited tag action would be used as cryptography."""


class _DRBG:
    """Small deterministic HMAC-SHA-512 generator for conformance vectors."""

    def __init__(self, seed: bytes, label: bytes) -> None:
        if not seed:
            raise ValueError("seed must not be empty")
        self._key = hashlib.sha512(b"Trahens-C2/DRBG/v1" + label + seed).digest()
        self._counter = 0

    def bytes(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("length cannot be negative")
        output = bytearray()
        while len(output) < length:
            self._counter += 1
            output.extend(
                hmac.new(
                    self._key,
                    self._counter.to_bytes(8, "big"),
                    hashlib.sha512,
                ).digest()
            )
        return bytes(output[:length])

    def scalar(self, modulus: int, *, nonzero: bool = False) -> int:
        if modulus < 2:
            raise ValueError("invalid modulus")
        width = (modulus.bit_length() + 15) // 8
        while True:
            candidate = int.from_bytes(self.bytes(width), "big") % modulus
            if not nonzero or candidate != 0:
                return candidate


@dataclass(frozen=True)
class QRGroup:
    """Prime-order subgroup of quadratic residues modulo a safe prime."""

    order: int
    modulus: int
    generator: int

    @property
    def element_bytes(self) -> int:
        return (self.modulus.bit_length() + 7) // 8

    def validate(self) -> None:
        if self.modulus != 2 * self.order + 1:
            raise ValueError("group modulus is not a safe-prime modulus")
        if not (1 < self.generator < self.modulus):
            raise ValueError("invalid group generator")
        if pow(self.generator, self.order, self.modulus) != 1:
            raise ValueError("generator is outside the order-q subgroup")
        if self.generator == 1:
            raise ValueError("identity cannot be a generator")

    def is_element(self, value: int) -> bool:
        return (
            1 <= value < self.modulus
            and pow(value, self.order, self.modulus) == 1
        )

    def require_element(self, value: int) -> int:
        if not self.is_element(value):
            raise C2Error("C2 validation failed")
        return value

    def mul(self, left: int, right: int) -> int:
        return (left * right) % self.modulus

    def inv(self, value: int) -> int:
        self.require_element(value)
        return pow(value, self.modulus - 2, self.modulus)

    def div(self, numerator: int, denominator: int) -> int:
        return self.mul(numerator, self.inv(denominator))

    def exp(self, value: int, scalar: int) -> int:
        self.require_element(value)
        return pow(value, scalar % self.order, self.modulus)

    def from_scalar(self, scalar: int) -> int:
        return pow(self.generator, scalar % self.order, self.modulus)

    def sample_element(self, rng: _DRBG, *, non_identity: bool = False) -> int:
        return self.from_scalar(rng.scalar(self.order, nonzero=non_identity))

    def encode(self, value: int) -> bytes:
        self.require_element(value)
        return value.to_bytes(self.element_bytes, "big")

    def decode(self, encoded: bytes) -> int:
        if len(encoded) != self.element_bytes:
            raise C2Error("C2 validation failed")
        value = int.from_bytes(encoded, "big")
        return self.require_element(value)


def _first_qr_generator(order: int, modulus: int) -> int:
    for candidate in range(2, modulus):
        value = pow(candidate, 2, modulus)
        if value != 1 and pow(value, order, modulus) == 1:
            return value
    raise ValueError("unable to select QR generator")


INNER_GROUP = QRGroup(
    order=C2_TEST_Q,
    modulus=C2_TEST_P,
    generator=_first_qr_generator(C2_TEST_Q, C2_TEST_P),
)
OUTER_GROUP = QRGroup(
    order=C2_TEST_P,
    modulus=C2_TEST_R,
    generator=_first_qr_generator(C2_TEST_P, C2_TEST_R),
)
INNER_GROUP.validate()
OUTER_GROUP.validate()

C2_CONCRETE_CIPHERTEXT_BYTES: Final[int] = (
    C2_CIPHERTEXT_HEADER_BYTES
    + C2_OUTER_ELEMENTS * OUTER_GROUP.element_bytes
    + C2_INNER_ELEMENTS * INNER_GROUP.element_bytes
)


def _hash_scalar(domain: bytes, value: bytes, modulus: int, *, nonzero: bool = False) -> int:
    counter = 0
    while True:
        digest = hashlib.sha512(
            b"Trahens-C2/hash-scalar/v1" + domain + counter.to_bytes(4, "big") + value
        ).digest()
        scalar = int.from_bytes(digest, "big") % modulus
        if not nonzero or scalar != 0:
            return scalar
        counter += 1


def _matrix_for(group: QRGroup, label: bytes) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    # P=(diag(g1,g2) | g3) in exponent representation, as in the k-Lin
    # instantiation.  Values are deterministically derived for reproducible
    # conformance parameters and are all nonzero.
    g1 = _hash_scalar(label + b"/g1", group.modulus.to_bytes(group.element_bytes, "big"), group.order, nonzero=True)
    g2 = _hash_scalar(label + b"/g2", group.modulus.to_bytes(group.element_bytes, "big"), group.order, nonzero=True)
    g3 = _hash_scalar(label + b"/g3", group.modulus.to_bytes(group.element_bytes, "big"), group.order, nonzero=True)
    return ((g1, 0, g3), (0, g2, g3))


def _lambdas(group: QRGroup, label: bytes) -> tuple[tuple[int, int], tuple[int, int]]:
    seed = group.modulus.to_bytes(group.element_bytes, "big")
    left = (
        _hash_scalar(label + b"/l1/0", seed, group.order),
        _hash_scalar(label + b"/l1/1", seed, group.order),
    )
    right = (
        _hash_scalar(label + b"/l2/0", seed, group.order),
        _hash_scalar(label + b"/l2/1", seed, group.order),
    )
    if left == right:
        right = (right[0], (right[1] + 1) % group.order)
    return left, right


P_OUTER = _matrix_for(OUTER_GROUP, b"Trahens-C2/P/outer/v1")
P_INNER = _matrix_for(INNER_GROUP, b"Trahens-C2/P/inner/v1")
LAMBDA_OUTER = _lambdas(OUTER_GROUP, b"Trahens-C2/lambda/outer/v1")
LAMBDA_INNER = _lambdas(INNER_GROUP, b"Trahens-C2/lambda/inner/v1")


def _vector_add(left: Sequence[int], right: Sequence[int], modulus: int) -> tuple[int, ...]:
    if len(left) != len(right):
        raise ValueError("vector length mismatch")
    return tuple((a + b) % modulus for a, b in zip(left, right, strict=True))


def _vector_scale(values: Sequence[int], scalar: int, modulus: int) -> tuple[int, ...]:
    return tuple((scalar * value) % modulus for value in values)


def _matrix_witness(
    witness: Sequence[int],
    matrix: Sequence[Sequence[int]],
    modulus: int,
) -> tuple[int, ...]:
    if len(witness) != C2_K or len(matrix) != C2_K:
        raise ValueError("invalid k-Lin dimensions")
    return tuple(
        sum(witness[row] * matrix[row][column] for row in range(C2_K)) % modulus
        for column in range(C2_K + 1)
    )


def _matrix_secret(
    matrix: Sequence[Sequence[int]],
    secret: Sequence[int],
    modulus: int,
) -> tuple[int, ...]:
    if len(secret) != C2_K + 1:
        raise ValueError("invalid secret dimension")
    return tuple(
        sum(matrix[row][column] * secret[column] for column in range(C2_K + 1)) % modulus
        for row in range(C2_K)
    )


def _encode_exponent_vector(group: QRGroup, exponents: Sequence[int]) -> tuple[int, ...]:
    return tuple(group.from_scalar(value) for value in exponents)


def _public_projection(
    group: QRGroup,
    matrix: Sequence[Sequence[int]],
    secret: Sequence[int],
) -> tuple[int, ...]:
    return _encode_exponent_vector(group, _matrix_secret(matrix, secret, group.order))


def _dot_public(group: QRGroup, public: Sequence[int], coefficients: Sequence[int]) -> int:
    if len(public) != len(coefficients):
        raise ValueError("public projection length mismatch")
    result = 1
    for element, coefficient in zip(public, coefficients, strict=True):
        result = group.mul(result, group.exp(element, coefficient))
    return result


def _hash_private(group: QRGroup, x: Sequence[int], secret: Sequence[int]) -> int:
    if len(x) != len(secret):
        raise ValueError("private hash dimension mismatch")
    result = 1
    for element, coefficient in zip(x, secret, strict=True):
        result = group.mul(result, group.exp(element, coefficient))
    return result


def _public_linear_combination(
    group: QRGroup,
    left: Sequence[int],
    right: Sequence[int],
    right_scalar: int,
) -> tuple[int, ...]:
    if len(left) != len(right):
        raise ValueError("public vector length mismatch")
    return tuple(
        group.mul(a, group.exp(b, right_scalar))
        for a, b in zip(left, right, strict=True)
    )


def _cipher_vector_combine(
    group: QRGroup,
    left: Sequence[int],
    right: Sequence[int],
    scalar: int,
) -> tuple[int, ...]:
    if len(left) != len(right):
        raise ValueError("cipher vector length mismatch")
    return tuple(
        group.mul(a, group.exp(b, scalar))
        for a, b in zip(left, right, strict=True)
    )


def _cipher_vector_scale(group: QRGroup, values: Sequence[int], scalar: int) -> tuple[int, ...]:
    return tuple(group.exp(value, scalar) for value in values)


def _private_tag_hash(
    group: QRGroup,
    x: Sequence[int],
    matrix: Sequence[Sequence[int]],
    lam: Sequence[int] | None,
    secret: Sequence[int],
    tag_scalar: int,
) -> int:
    if len(x) != C2_K + 1 or len(secret) != C2_K + 1:
        raise ValueError("tag hash dimension mismatch")
    result = _hash_private(
        group,
        x,
        tuple((tag_scalar * value) % group.order for value in secret),
    )
    if lam is None:
        return result
    p_secret = _matrix_secret(matrix, secret, group.order)
    extra_exponent = sum(lam[i] * p_secret[i] for i in range(C2_K)) % group.order
    return group.mul(result, group.from_scalar(tag_scalar * extra_exponent))


def _sample_secret(rng: _DRBG, modulus: int) -> tuple[int, int, int]:
    return tuple(rng.scalar(modulus) for _ in range(C2_K + 1))  # type: ignore[return-value]


def _sample_witness(rng: _DRBG, modulus: int) -> tuple[int, int]:
    return tuple(rng.scalar(modulus) for _ in range(C2_K))  # type: ignore[return-value]


def _message_hash(message: int) -> int:
    return _hash_scalar(
        b"Trahens-C2/psi/v1",
        OUTER_GROUP.encode(message),
        OUTER_GROUP.order,
    )


def eligibility_message() -> int:
    scalar = _hash_scalar(
        b"Trahens-C2/eligibility-message/v1",
        C2_ELIGIBILITY_LABEL,
        OUTER_GROUP.order,
        nonzero=True,
    )
    return OUTER_GROUP.from_scalar(scalar)


@dataclass(frozen=True)
class C2PublicKey:
    A: tuple[int, int]
    B: tuple[int, int]
    C: tuple[int, int]
    D: tuple[int, int]
    E: tuple[int, int]
    inner_A: tuple[int, int]
    inner_B: tuple[int, int]
    inner_C: tuple[int, int]

    def encode(self) -> bytes:
        output = bytearray((C2_VERSION,))
        output.extend(C2_SUITE_ID)
        output.append(C2_PARAMETER_SET_ID)
        for vector, group in (
            (self.A, OUTER_GROUP),
            (self.B, OUTER_GROUP),
            (self.C, OUTER_GROUP),
            (self.D, OUTER_GROUP),
            (self.E, OUTER_GROUP),
            (self.inner_A, INNER_GROUP),
            (self.inner_B, INNER_GROUP),
            (self.inner_C, INNER_GROUP),
        ):
            for element in vector:
                output.extend(group.encode(element))
        return bytes(output)

    @classmethod
    def decode(cls, encoded: bytes) -> "C2PublicKey":
        expected = C2_PUBLIC_KEY_HEADER_BYTES + 10 * OUTER_GROUP.element_bytes + 6 * INNER_GROUP.element_bytes
        if len(encoded) != expected:
            raise C2Error("C2 validation failed")
        if encoded[:1] != bytes((C2_VERSION,)) or encoded[1:3] != C2_SUITE_ID or encoded[3] != C2_PARAMETER_SET_ID:
            raise C2Error("C2 validation failed")
        offset = C2_PUBLIC_KEY_HEADER_BYTES

        def take(group: QRGroup, count: int) -> tuple[int, ...]:
            nonlocal offset
            values = []
            for _ in range(count):
                end = offset + group.element_bytes
                values.append(group.decode(encoded[offset:end]))
                offset = end
            return tuple(values)

        return cls(
            A=take(OUTER_GROUP, 2),  # type: ignore[arg-type]
            B=take(OUTER_GROUP, 2),  # type: ignore[arg-type]
            C=take(OUTER_GROUP, 2),  # type: ignore[arg-type]
            D=take(OUTER_GROUP, 2),  # type: ignore[arg-type]
            E=take(OUTER_GROUP, 2),  # type: ignore[arg-type]
            inner_A=take(INNER_GROUP, 2),  # type: ignore[arg-type]
            inner_B=take(INNER_GROUP, 2),  # type: ignore[arg-type]
            inner_C=take(INNER_GROUP, 2),  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class C2SecretKey:
    a: tuple[int, int, int]
    b: tuple[int, int, int]
    c: tuple[int, int, int]
    d: tuple[int, int, int]
    e: tuple[int, int, int]
    inner_a: tuple[int, int, int]
    inner_b: tuple[int, int, int]
    inner_c: tuple[int, int, int]


@dataclass(frozen=True)
class C2EndpointKeys:
    secret: C2SecretKey
    public: C2PublicKey
    descriptor: bytes
    address: bytes


@dataclass(frozen=True)
class C2Ciphertext:
    x1: tuple[int, int, int]
    e1: int
    pi_b11: int
    pi_b12: int
    x2: tuple[int, int, int]
    pi2: int
    pi_e21: int
    pi_e22: int
    x3: tuple[int, int, int]
    e3: int
    pi_b31: int
    pi_b32: int
    x4: tuple[int, int, int]
    pi4: int
    pi_e41: int
    pi_e42: int

    def outer_elements(self) -> tuple[int, ...]:
        return (
            *self.x1,
            self.e1,
            self.pi_b11,
            self.pi_b12,
            *self.x2,
            self.pi2,
            self.pi_e21,
            self.pi_e22,
        )

    def inner_elements(self) -> tuple[int, ...]:
        return (
            *self.x3,
            self.e3,
            self.pi_b31,
            self.pi_b32,
            *self.x4,
            self.pi4,
            self.pi_e41,
            self.pi_e42,
        )

    def encode(self) -> bytes:
        output = bytearray((C2_VERSION,))
        output.extend(C2_SUITE_ID)
        output.append(C2_PARAMETER_SET_ID)
        for element in self.outer_elements():
            output.extend(OUTER_GROUP.encode(element))
        for element in self.inner_elements():
            output.extend(INNER_GROUP.encode(element))
        if len(output) != C2_CONCRETE_CIPHERTEXT_BYTES:
            raise AssertionError("unexpected C2 ciphertext length")
        return bytes(output)

    @classmethod
    def decode(cls, encoded: bytes) -> "C2Ciphertext":
        if len(encoded) != C2_CONCRETE_CIPHERTEXT_BYTES:
            raise C2Error("C2 validation failed")
        if encoded[:1] != bytes((C2_VERSION,)) or encoded[1:3] != C2_SUITE_ID or encoded[3] != C2_PARAMETER_SET_ID:
            raise C2Error("C2 validation failed")
        offset = C2_CIPHERTEXT_HEADER_BYTES

        def take(group: QRGroup, count: int) -> tuple[int, ...]:
            nonlocal offset
            values = []
            for _ in range(count):
                end = offset + group.element_bytes
                values.append(group.decode(encoded[offset:end]))
                offset = end
            return tuple(values)

        outer = take(OUTER_GROUP, C2_OUTER_ELEMENTS)
        inner = take(INNER_GROUP, C2_INNER_ELEMENTS)
        if offset != len(encoded):
            raise C2Error("C2 validation failed")
        return cls(
            x1=outer[0:3],  # type: ignore[arg-type]
            e1=outer[3],
            pi_b11=outer[4],
            pi_b12=outer[5],
            x2=outer[6:9],  # type: ignore[arg-type]
            pi2=outer[9],
            pi_e21=outer[10],
            pi_e22=outer[11],
            x3=inner[0:3],  # type: ignore[arg-type]
            e3=inner[3],
            pi_b31=inner[4],
            pi_b32=inner[5],
            x4=inner[6:9],  # type: ignore[arg-type]
            pi4=inner[9],
            pi_e41=inner[10],
            pi_e42=inner[11],
        )


def keygen(seed: bytes, label: bytes = b"endpoint") -> C2EndpointKeys:
    rng = _DRBG(seed, b"keygen/" + label)
    a, b, c, d, e = (_sample_secret(rng, OUTER_GROUP.order) for _ in range(5))
    inner_a, inner_b, inner_c = (_sample_secret(rng, INNER_GROUP.order) for _ in range(3))
    public = C2PublicKey(
        A=_public_projection(OUTER_GROUP, P_OUTER, a),  # type: ignore[arg-type]
        B=_public_projection(OUTER_GROUP, P_OUTER, b),  # type: ignore[arg-type]
        C=_public_projection(OUTER_GROUP, P_OUTER, c),  # type: ignore[arg-type]
        D=_public_projection(OUTER_GROUP, P_OUTER, d),  # type: ignore[arg-type]
        E=_public_projection(OUTER_GROUP, P_OUTER, e),  # type: ignore[arg-type]
        inner_A=_public_projection(INNER_GROUP, P_INNER, inner_a),  # type: ignore[arg-type]
        inner_B=_public_projection(INNER_GROUP, P_INNER, inner_b),  # type: ignore[arg-type]
        inner_C=_public_projection(INNER_GROUP, P_INNER, inner_c),  # type: ignore[arg-type]
    )
    secret = C2SecretKey(a, b, c, d, e, inner_a, inner_b, inner_c)
    public_encoded = public.encode()
    descriptor = bytes((C2_VERSION,)) + C2_SUITE_ID + bytes((C2_PARAMETER_SET_ID,)) + public_encoded
    address = hashlib.sha256(b"Trahens-C2/address/v2" + descriptor).digest()
    return C2EndpointKeys(secret, public, descriptor, address)


def tag_reduction(value: int, order: int = C2_TEST_Q) -> int:
    """Return the literal integer-reduction tag map stated in the source.

    Section 2 of Wang et al. (CRYPTO 2021, ePrint 2021/862) describes an
    inner validity exponent using ``u mod q`` and states that the modular
    operation supplies the homomorphism required by rerandomization. This
    helper names that literal map so its algebraic obligation can be tested
    independently of the rest of the transcription.
    """

    if order <= 1:
        raise ValueError("invalid reduction order")
    return value % order


def tag_action_equation(multiplier: int, tag: int, *, q: int, p: int) -> tuple[int, int]:
    """Evaluate both sides of the literal finite-field tag-action equation."""

    if p != 2 * q + 1:
        raise ValueError("expected safe-prime relation p = 2q + 1")
    product = (multiplier * tag) % p
    return tag_reduction(product, q), (
        tag_reduction(multiplier, q) * tag_reduction(tag, q)
    ) % q


def small_tag_reduction_counterexample() -> dict[str, int | bool]:
    """Return a minimal reproducible counterexample in QR*_11.

    For q=5 and p=11, 3 and 4 are quadratic residues. Their product is 1
    modulo 11, but reducing representatives modulo 5 gives 1 on the left and
    2 on the multiplicative right. This does not attack the generic
    Re-T-SPHF framework; it shows that the literal integer-reduction map is
    not a multiplicative group homomorphism.
    """

    q = 5
    p = 11
    multiplier = 3
    tag = 4
    if pow(multiplier, q, p) != 1 or pow(tag, q, p) != 1:
        raise AssertionError("counterexample values are not in QR*_11")
    left, right = tag_action_equation(multiplier, tag, q=q, p=p)
    return {
        "q": q,
        "p": p,
        "multiplier": multiplier,
        "tag": tag,
        "group_product": (multiplier * tag) % p,
        "left_reduction": left,
        "right_product": right,
        "equation_holds": left == right,
    }


def _sample_inner_tag(rng: _DRBG) -> int:
    # The numeric representative is used as an outer scalar and, under the
    # source's literal finite-field reading, reduced modulo q for the inner
    # Re-T-SPHF tag. Exclude the exceptional zero reduction.
    for _ in range(256):
        value = INNER_GROUP.sample_element(rng, non_identity=True)
        if tag_reduction(value) != 0:
            return value
    raise C2Error("C2 randomness generation failed")


def encrypt(
    public: C2PublicKey,
    message: int,
    seed: bytes,
) -> C2Ciphertext:
    OUTER_GROUP.require_element(message)
    # Round-trip the public key to enforce canonical and subgroup validation.
    public = C2PublicKey.decode(public.encode())
    rng = _DRBG(seed, b"encrypt")

    w1 = _sample_witness(rng, OUTER_GROUP.order)
    w2 = _sample_witness(rng, OUTER_GROUP.order)
    x1_exp = _matrix_witness(w1, P_OUTER, OUTER_GROUP.order)
    x2_exp = _matrix_witness(w2, P_OUTER, OUTER_GROUP.order)
    x1 = _encode_exponent_vector(OUTER_GROUP, x1_exp)
    x2 = _encode_exponent_vector(OUTER_GROUP, x2_exp)

    u = _sample_inner_tag(rng)
    m = _message_hash(message)
    u_outer = u % OUTER_GROUP.order

    e1 = OUTER_GROUP.mul(message, _dot_public(OUTER_GROUP, public.A, w1))
    pi2 = _dot_public(OUTER_GROUP, public.A, w2)
    bc = _public_linear_combination(OUTER_GROUP, public.B, public.C, m)
    de = _public_linear_combination(OUTER_GROUP, public.D, public.E, m)
    pi_b11 = _dot_public(
        OUTER_GROUP,
        bc,
        tuple(u_outer * ((w1[i] + LAMBDA_OUTER[0][i]) % OUTER_GROUP.order) % OUTER_GROUP.order for i in range(C2_K)),
    )
    pi_b12 = _dot_public(
        OUTER_GROUP,
        de,
        tuple(u_outer * ((w1[i] + LAMBDA_OUTER[1][i]) % OUTER_GROUP.order) % OUTER_GROUP.order for i in range(C2_K)),
    )
    pi_e21 = _dot_public(
        OUTER_GROUP,
        bc,
        tuple(u_outer * value % OUTER_GROUP.order for value in w2),
    )
    pi_e22 = _dot_public(
        OUTER_GROUP,
        de,
        tuple(u_outer * value % OUTER_GROUP.order for value in w2),
    )

    w3 = _sample_witness(rng, INNER_GROUP.order)
    w4 = _sample_witness(rng, INNER_GROUP.order)
    x3_exp = _matrix_witness(w3, P_INNER, INNER_GROUP.order)
    x4_exp = _matrix_witness(w4, P_INNER, INNER_GROUP.order)
    x3 = _encode_exponent_vector(INNER_GROUP, x3_exp)
    x4 = _encode_exponent_vector(INNER_GROUP, x4_exp)
    u_inner = u % INNER_GROUP.order

    e3 = INNER_GROUP.mul(u, _dot_public(INNER_GROUP, public.inner_A, w3))
    pi4 = _dot_public(INNER_GROUP, public.inner_A, w4)
    pi_b31 = _dot_public(
        INNER_GROUP,
        public.inner_B,
        tuple(u_inner * ((w3[i] + LAMBDA_INNER[0][i]) % INNER_GROUP.order) % INNER_GROUP.order for i in range(C2_K)),
    )
    pi_b32 = _dot_public(
        INNER_GROUP,
        public.inner_C,
        tuple(u_inner * ((w3[i] + LAMBDA_INNER[1][i]) % INNER_GROUP.order) % INNER_GROUP.order for i in range(C2_K)),
    )
    pi_e41 = _dot_public(
        INNER_GROUP,
        public.inner_B,
        tuple(u_inner * value % INNER_GROUP.order for value in w4),
    )
    pi_e42 = _dot_public(
        INNER_GROUP,
        public.inner_C,
        tuple(u_inner * value % INNER_GROUP.order for value in w4),
    )

    return C2Ciphertext(
        x1=x1,  # type: ignore[arg-type]
        e1=e1,
        pi_b11=pi_b11,
        pi_b12=pi_b12,
        x2=x2,  # type: ignore[arg-type]
        pi2=pi2,
        pi_e21=pi_e21,
        pi_e22=pi_e22,
        x3=x3,  # type: ignore[arg-type]
        e3=e3,
        pi_b31=pi_b31,
        pi_b32=pi_b32,
        x4=x4,  # type: ignore[arg-type]
        pi4=pi4,
        pi_e41=pi_e41,
        pi_e42=pi_e42,
    )


def _decrypt_inner(secret: C2SecretKey, ciphertext: C2Ciphertext) -> int:
    u = INNER_GROUP.div(ciphertext.e3, _hash_private(INNER_GROUP, ciphertext.x3, secret.inner_a))
    u_scalar = u % INNER_GROUP.order
    if u_scalar == 0:
        raise C2Error("C2 decryption failed")
    expected_pi4 = _hash_private(INNER_GROUP, ciphertext.x4, secret.inner_a)
    expected_b31 = _private_tag_hash(
        INNER_GROUP,
        ciphertext.x3,
        P_INNER,
        LAMBDA_INNER[0],
        secret.inner_b,
        u_scalar,
    )
    expected_b32 = _private_tag_hash(
        INNER_GROUP,
        ciphertext.x3,
        P_INNER,
        LAMBDA_INNER[1],
        secret.inner_c,
        u_scalar,
    )
    expected_e41 = _private_tag_hash(
        INNER_GROUP,
        ciphertext.x4,
        P_INNER,
        None,
        secret.inner_b,
        u_scalar,
    )
    expected_e42 = _private_tag_hash(
        INNER_GROUP,
        ciphertext.x4,
        P_INNER,
        None,
        secret.inner_c,
        u_scalar,
    )
    if not all(
        hmac.compare_digest(INNER_GROUP.encode(left), INNER_GROUP.encode(right))
        for left, right in (
            (expected_pi4, ciphertext.pi4),
            (expected_b31, ciphertext.pi_b31),
            (expected_b32, ciphertext.pi_b32),
            (expected_e41, ciphertext.pi_e41),
            (expected_e42, ciphertext.pi_e42),
        )
    ):
        raise C2Error("C2 decryption failed")
    return u


def decrypt(secret: C2SecretKey, ciphertext: C2Ciphertext) -> int:
    # Canonical decoding validates all 24 elements before secret-dependent work.
    ciphertext = C2Ciphertext.decode(ciphertext.encode())
    try:
        u = _decrypt_inner(secret, ciphertext)
        message = OUTER_GROUP.div(
            ciphertext.e1,
            _hash_private(OUTER_GROUP, ciphertext.x1, secret.a),
        )
        m = _message_hash(message)
        u_scalar = u % OUTER_GROUP.order
        bc_secret = tuple((secret.b[i] + m * secret.c[i]) % OUTER_GROUP.order for i in range(C2_K + 1))
        de_secret = tuple((secret.d[i] + m * secret.e[i]) % OUTER_GROUP.order for i in range(C2_K + 1))
        expected_pi2 = _hash_private(OUTER_GROUP, ciphertext.x2, secret.a)
        expected_b11 = _private_tag_hash(
            OUTER_GROUP,
            ciphertext.x1,
            P_OUTER,
            LAMBDA_OUTER[0],
            bc_secret,
            u_scalar,
        )
        expected_b12 = _private_tag_hash(
            OUTER_GROUP,
            ciphertext.x1,
            P_OUTER,
            LAMBDA_OUTER[1],
            de_secret,
            u_scalar,
        )
        expected_e21 = _private_tag_hash(
            OUTER_GROUP,
            ciphertext.x2,
            P_OUTER,
            None,
            bc_secret,
            u_scalar,
        )
        expected_e22 = _private_tag_hash(
            OUTER_GROUP,
            ciphertext.x2,
            P_OUTER,
            None,
            de_secret,
            u_scalar,
        )
        if not all(
            hmac.compare_digest(OUTER_GROUP.encode(left), OUTER_GROUP.encode(right))
            for left, right in (
                (expected_pi2, ciphertext.pi2),
                (expected_b11, ciphertext.pi_b11),
                (expected_b12, ciphertext.pi_b12),
                (expected_e21, ciphertext.pi_e21),
                (expected_e22, ciphertext.pi_e22),
            )
        ):
            raise C2Error("C2 decryption failed")
        return message
    except (C2Error, ValueError, OverflowError) as exc:
        raise C2Error("C2 decryption failed") from exc


def rerandomize_literal(ciphertext: C2Ciphertext, seed: bytes) -> C2Ciphertext:
    ciphertext = C2Ciphertext.decode(ciphertext.encode())
    rng = _DRBG(seed, b"rerandomize")

    r1 = rng.scalar(OUTER_GROUP.order)
    r2 = rng.scalar(OUTER_GROUP.order, nonzero=True)
    r_star = _sample_inner_tag(rng)
    r_star_outer = r_star % OUTER_GROUP.order
    r_star_inner = r_star % INNER_GROUP.order

    x1 = _cipher_vector_combine(OUTER_GROUP, ciphertext.x1, ciphertext.x2, r1)
    e1 = OUTER_GROUP.mul(ciphertext.e1, OUTER_GROUP.exp(ciphertext.pi2, r1))
    pi_b11 = OUTER_GROUP.exp(
        OUTER_GROUP.mul(ciphertext.pi_b11, OUTER_GROUP.exp(ciphertext.pi_e21, r1)),
        r_star_outer,
    )
    pi_b12 = OUTER_GROUP.exp(
        OUTER_GROUP.mul(ciphertext.pi_b12, OUTER_GROUP.exp(ciphertext.pi_e22, r1)),
        r_star_outer,
    )
    x2 = _cipher_vector_scale(OUTER_GROUP, ciphertext.x2, r2)
    pi2 = OUTER_GROUP.exp(ciphertext.pi2, r2)
    pi_e21 = OUTER_GROUP.exp(ciphertext.pi_e21, r2 * r_star_outer)
    pi_e22 = OUTER_GROUP.exp(ciphertext.pi_e22, r2 * r_star_outer)

    # Maul(%, r*) followed by MRerand(%), matching Figure 6.
    e3_maul = INNER_GROUP.mul(r_star, ciphertext.e3)
    pi_b31_maul = INNER_GROUP.exp(ciphertext.pi_b31, r_star_inner)
    pi_b32_maul = INNER_GROUP.exp(ciphertext.pi_b32, r_star_inner)
    pi_e41_maul = INNER_GROUP.exp(ciphertext.pi_e41, r_star_inner)
    pi_e42_maul = INNER_GROUP.exp(ciphertext.pi_e42, r_star_inner)

    r3 = rng.scalar(INNER_GROUP.order)
    r4 = rng.scalar(INNER_GROUP.order, nonzero=True)
    x3 = _cipher_vector_combine(INNER_GROUP, ciphertext.x3, ciphertext.x4, r3)
    e3 = INNER_GROUP.mul(e3_maul, INNER_GROUP.exp(ciphertext.pi4, r3))
    pi_b31 = INNER_GROUP.mul(pi_b31_maul, INNER_GROUP.exp(pi_e41_maul, r3))
    pi_b32 = INNER_GROUP.mul(pi_b32_maul, INNER_GROUP.exp(pi_e42_maul, r3))
    x4 = _cipher_vector_scale(INNER_GROUP, ciphertext.x4, r4)
    pi4 = INNER_GROUP.exp(ciphertext.pi4, r4)
    pi_e41 = INNER_GROUP.exp(pi_e41_maul, r4)
    pi_e42 = INNER_GROUP.exp(pi_e42_maul, r4)

    output = C2Ciphertext(
        x1=x1,  # type: ignore[arg-type]
        e1=e1,
        pi_b11=pi_b11,
        pi_b12=pi_b12,
        x2=x2,  # type: ignore[arg-type]
        pi2=pi2,
        pi_e21=pi_e21,
        pi_e22=pi_e22,
        x3=x3,  # type: ignore[arg-type]
        e3=e3,
        pi_b31=pi_b31,
        pi_b32=pi_b32,
        x4=x4,  # type: ignore[arg-type]
        pi4=pi4,
        pi_e41=pi_e41,
        pi_e42=pi_e42,
    )
    if hmac.compare_digest(output.encode(), ciphertext.encode()):
        raise C2Error("C2 rerandomization failed")
    return output


def rerandomize_strands_only(ciphertext: C2Ciphertext, seed: bytes) -> C2Ciphertext:
    """Rerandomize both linear strands while fixing the tag multiplier to one.

    This restricted operation is useful for checking the linear strand
    equations.  It is not the full Figure 6 distribution and MUST NOT be used
    to claim receiver-anonymous Rand-RCCA security.
    """

    ciphertext = C2Ciphertext.decode(ciphertext.encode())
    rng = _DRBG(seed, b"rerandomize-strands-only")

    r1 = rng.scalar(OUTER_GROUP.order)
    r2 = rng.scalar(OUTER_GROUP.order, nonzero=True)
    x1 = _cipher_vector_combine(OUTER_GROUP, ciphertext.x1, ciphertext.x2, r1)
    e1 = OUTER_GROUP.mul(ciphertext.e1, OUTER_GROUP.exp(ciphertext.pi2, r1))
    pi_b11 = OUTER_GROUP.mul(ciphertext.pi_b11, OUTER_GROUP.exp(ciphertext.pi_e21, r1))
    pi_b12 = OUTER_GROUP.mul(ciphertext.pi_b12, OUTER_GROUP.exp(ciphertext.pi_e22, r1))
    x2 = _cipher_vector_scale(OUTER_GROUP, ciphertext.x2, r2)
    pi2 = OUTER_GROUP.exp(ciphertext.pi2, r2)
    pi_e21 = OUTER_GROUP.exp(ciphertext.pi_e21, r2)
    pi_e22 = OUTER_GROUP.exp(ciphertext.pi_e22, r2)

    r3 = rng.scalar(INNER_GROUP.order)
    r4 = rng.scalar(INNER_GROUP.order, nonzero=True)
    x3 = _cipher_vector_combine(INNER_GROUP, ciphertext.x3, ciphertext.x4, r3)
    e3 = INNER_GROUP.mul(ciphertext.e3, INNER_GROUP.exp(ciphertext.pi4, r3))
    pi_b31 = INNER_GROUP.mul(ciphertext.pi_b31, INNER_GROUP.exp(ciphertext.pi_e41, r3))
    pi_b32 = INNER_GROUP.mul(ciphertext.pi_b32, INNER_GROUP.exp(ciphertext.pi_e42, r3))
    x4 = _cipher_vector_scale(INNER_GROUP, ciphertext.x4, r4)
    pi4 = INNER_GROUP.exp(ciphertext.pi4, r4)
    pi_e41 = INNER_GROUP.exp(ciphertext.pi_e41, r4)
    pi_e42 = INNER_GROUP.exp(ciphertext.pi_e42, r4)

    output = C2Ciphertext(
        x1=x1, e1=e1, pi_b11=pi_b11, pi_b12=pi_b12,
        x2=x2, pi2=pi2, pi_e21=pi_e21, pi_e22=pi_e22,
        x3=x3, e3=e3, pi_b31=pi_b31, pi_b32=pi_b32,
        x4=x4, pi4=pi4, pi_e41=pi_e41, pi_e42=pi_e42,
    )
    if hmac.compare_digest(output.encode(), ciphertext.encode()):
        raise C2Error("C2 strand rerandomization failed")
    return output


def rerandomize(ciphertext: C2Ciphertext, seed: bytes) -> C2Ciphertext:
    """Refuse full use until the related-group tag action is independently fixed.

    ``rerandomize_literal`` is retained for the audit report and reproduces the
    direct finite-field reading under test.  It is intentionally not exposed as
    the protocol implementation.
    """

    del ciphertext, seed
    raise C2ConformanceGap(
        "full C2 k=2 rerandomization is not approved: the literal finite-field "
        "map u -> u mod q is non-homomorphic under ordinary QR-group multiplication"
    )


def audit_literal_rerandomization(
    keys: C2EndpointKeys,
    encryption_seed: bytes,
    rerandomization_seed: bytes,
) -> dict[str, bool | str | int | dict[str, int | bool]]:
    """Return a deterministic audit result without treating a gap as success."""

    original = encrypt(keys.public, eligibility_message(), encryption_seed)
    original_valid = decrypt(keys.secret, original) == eligibility_message()
    original_tag = _decrypt_inner(keys.secret, original)

    # Reproduce the first three Figure 6 randomness draws so the audit records
    # the exact non-identity multiplier used by ``rerandomize_literal``.
    rerand_rng = _DRBG(rerandomization_seed, b"rerandomize")
    rerand_rng.scalar(OUTER_GROUP.order)
    rerand_rng.scalar(OUTER_GROUP.order, nonzero=True)
    multiplier = _sample_inner_tag(rerand_rng)
    left, right = tag_action_equation(
        multiplier,
        original_tag,
        q=C2_TEST_Q,
        p=C2_TEST_P,
    )

    strand = rerandomize_strands_only(original, rerandomization_seed)
    strand_valid = decrypt(keys.secret, strand) == eligibility_message()
    literal = rerandomize_literal(original, rerandomization_seed)
    try:
        literal_valid = decrypt(keys.secret, literal) == eligibility_message()
    except C2Error:
        literal_valid = False
    return {
        "k": C2_K,
        "ciphertext_bytes": C2_CONCRETE_CIPHERTEXT_BYTES,
        "encrypt_decrypt": original_valid,
        "strand_rerandomization": strand_valid,
        "literal_nontrivial_tag_rerandomization": literal_valid,
        "tag_reduction_homomorphism": left == right,
        "large_parameter_tag": original_tag,
        "large_parameter_multiplier": multiplier,
        "large_parameter_product": (multiplier * original_tag) % C2_TEST_P,
        "large_parameter_left_reduction": left,
        "large_parameter_right_product": right,
        "small_counterexample": small_tag_reduction_counterexample(),
        "deployment_approved": False,
        "status": "finite-field-tag-reduction-nonhomomorphic",
    }


def encrypt_eligibility(public: C2PublicKey, seed: bytes) -> bytes:
    return encrypt(public, eligibility_message(), seed).encode()


def rerandomize_eligibility(encoded: bytes, seed: bytes) -> bytes:
    return rerandomize(C2Ciphertext.decode(encoded), seed).encode()


def is_eligible(secret: C2SecretKey, encoded: bytes) -> bool:
    try:
        message = decrypt(secret, C2Ciphertext.decode(encoded))
        return hmac.compare_digest(
            OUTER_GROUP.encode(message),
            OUTER_GROUP.encode(eligibility_message()),
        )
    except C2Error:
        return False


def mutate_component(encoded: bytes, component_index: int, factor: int = 2) -> bytes:
    """Conformance-only active mutation of one encoded group component."""

    ciphertext = C2Ciphertext.decode(encoded)
    outer = list(ciphertext.outer_elements())
    inner = list(ciphertext.inner_elements())
    if 0 <= component_index < len(outer):
        outer[component_index] = OUTER_GROUP.mul(
            outer[component_index], OUTER_GROUP.from_scalar(factor)
        )
    elif len(outer) <= component_index < len(outer) + len(inner):
        index = component_index - len(outer)
        inner[index] = INNER_GROUP.mul(
            inner[index], INNER_GROUP.from_scalar(factor)
        )
    else:
        raise C2Error("component index out of range")
    mutated = C2Ciphertext(
        x1=tuple(outer[0:3]),  # type: ignore[arg-type]
        e1=outer[3],
        pi_b11=outer[4],
        pi_b12=outer[5],
        x2=tuple(outer[6:9]),  # type: ignore[arg-type]
        pi2=outer[9],
        pi_e21=outer[10],
        pi_e22=outer[11],
        x3=tuple(inner[0:3]),  # type: ignore[arg-type]
        e3=inner[3],
        pi_b31=inner[4],
        pi_b32=inner[5],
        x4=tuple(inner[6:9]),  # type: ignore[arg-type]
        pi4=inner[9],
        pi_e41=inner[10],
        pi_e42=inner[11],
    )
    return mutated.encode()


def parameter_summary() -> dict[str, int | str]:
    return {
        "suite_id": C2_SUITE_ID.hex(),
        "parameter_set_id": C2_PARAMETER_SET_ID,
        "k": C2_K,
        "q": C2_TEST_Q,
        "p": C2_TEST_P,
        "r": C2_TEST_R,
        "inner_generator": INNER_GROUP.generator,
        "outer_generator": OUTER_GROUP.generator,
        "inner_element_bytes": INNER_GROUP.element_bytes,
        "outer_element_bytes": OUTER_GROUP.element_bytes,
        "ciphertext_bytes": C2_CONCRETE_CIPHERTEXT_BYTES,
        "deployment_status": "not-approved",
        "interoperability_status": "finite-field-tag-reduction-nonhomomorphic",
    }
