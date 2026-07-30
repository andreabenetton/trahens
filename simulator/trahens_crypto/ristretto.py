# SPDX-License-Identifier: Apache-2.0
"""Minimal ristretto255 wrapper over libsodium.

The wrapper exposes only the operations needed by the C1 reference profile.
It deliberately rejects non-canonical scalars and invalid point encodings.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
from dataclasses import dataclass

from trahens_spec.generated import DOMAIN_C1_ELEMENT, DOMAIN_C1_SCALAR

SCALAR_BYTES = 32
POINT_BYTES = 32
HASH_BYTES = 64
GROUP_ORDER = 2**252 + 27742317777372353535851937790883648493
IDENTITY = bytes(POINT_BYTES)
SCALAR_ONE = (1).to_bytes(SCALAR_BYTES, "little")


class RistrettoError(ValueError):
    """Raised when a scalar or point is invalid."""


_lib_name = ctypes.util.find_library("sodium")
if _lib_name is None:
    raise RuntimeError("libsodium is required for the Trahens C1 reference profile")
_lib = ctypes.cdll.LoadLibrary(_lib_name)
if _lib.sodium_init() < 0:
    raise RuntimeError("libsodium initialization failed")

_U8P = ctypes.POINTER(ctypes.c_ubyte)

_lib.crypto_core_ristretto255_is_valid_point.argtypes = [_U8P]
_lib.crypto_core_ristretto255_is_valid_point.restype = ctypes.c_int
_lib.crypto_core_ristretto255_from_hash.argtypes = [_U8P, _U8P]
_lib.crypto_core_ristretto255_from_hash.restype = ctypes.c_int
_lib.crypto_core_ristretto255_add.argtypes = [_U8P, _U8P, _U8P]
_lib.crypto_core_ristretto255_add.restype = ctypes.c_int
_lib.crypto_core_ristretto255_sub.argtypes = [_U8P, _U8P, _U8P]
_lib.crypto_core_ristretto255_sub.restype = ctypes.c_int
_lib.crypto_core_ristretto255_scalar_reduce.argtypes = [_U8P, _U8P]
_lib.crypto_core_ristretto255_scalar_reduce.restype = None
_lib.crypto_core_ristretto255_scalar_add.argtypes = [_U8P, _U8P, _U8P]
_lib.crypto_core_ristretto255_scalar_add.restype = None
_lib.crypto_core_ristretto255_scalar_mul.argtypes = [_U8P, _U8P, _U8P]
_lib.crypto_core_ristretto255_scalar_mul.restype = None
_lib.crypto_scalarmult_ristretto255.argtypes = [_U8P, _U8P, _U8P]
_lib.crypto_scalarmult_ristretto255.restype = ctypes.c_int
_lib.crypto_scalarmult_ristretto255_base.argtypes = [_U8P, _U8P]
_lib.crypto_scalarmult_ristretto255_base.restype = ctypes.c_int


def _arr(data: bytes) -> ctypes.Array[ctypes.c_ubyte]:
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def _out(size: int) -> ctypes.Array[ctypes.c_ubyte]:
    return (ctypes.c_ubyte * size)()


def is_valid_point(point: bytes) -> bool:
    return len(point) == POINT_BYTES and _lib.crypto_core_ristretto255_is_valid_point(_arr(point)) == 1


def require_point(point: bytes, *, allow_identity: bool = True) -> bytes:
    if not is_valid_point(point):
        raise RistrettoError("invalid ristretto255 point encoding")
    if not allow_identity and point == IDENTITY:
        raise RistrettoError("identity point is not allowed")
    return point


def require_scalar(scalar: bytes, *, allow_zero: bool = False) -> bytes:
    if len(scalar) != SCALAR_BYTES:
        raise RistrettoError("scalar must be 32 bytes")
    value = int.from_bytes(scalar, "little")
    if value >= GROUP_ORDER:
        raise RistrettoError("scalar is not canonically encoded")
    if not allow_zero and value == 0:
        raise RistrettoError("zero scalar is not allowed")
    return scalar


def scalar_reduce(uniform: bytes) -> bytes:
    if len(uniform) != HASH_BYTES:
        raise RistrettoError("scalar reduction input must be 64 bytes")
    result = _out(SCALAR_BYTES)
    _lib.crypto_core_ristretto255_scalar_reduce(result, _arr(uniform))
    return bytes(result)


def scalar_from_label(label: bytes, *, dst: bytes = DOMAIN_C1_SCALAR) -> bytes:
    for counter in range(256):
        uniform = hashlib.sha512(dst + bytes([counter]) + label).digest()
        scalar = scalar_reduce(uniform)
        if scalar != bytes(SCALAR_BYTES):
            return scalar
    raise RuntimeError("failed to derive a non-zero scalar")


def point_from_label(label: bytes, *, dst: bytes = DOMAIN_C1_ELEMENT) -> bytes:
    uniform = hashlib.sha512(dst + label).digest()
    result = _out(POINT_BYTES)
    if _lib.crypto_core_ristretto255_from_hash(result, _arr(uniform)) != 0:
        raise RistrettoError("ristretto255 element derivation failed")
    return bytes(result)


def point_add(left: bytes, right: bytes) -> bytes:
    require_point(left)
    require_point(right)
    result = _out(POINT_BYTES)
    if _lib.crypto_core_ristretto255_add(result, _arr(left), _arr(right)) != 0:
        raise RistrettoError("ristretto255 addition failed")
    return bytes(result)


def point_sub(left: bytes, right: bytes) -> bytes:
    require_point(left)
    require_point(right)
    result = _out(POINT_BYTES)
    if _lib.crypto_core_ristretto255_sub(result, _arr(left), _arr(right)) != 0:
        raise RistrettoError("ristretto255 subtraction failed")
    return bytes(result)


def scalar_add(left: bytes, right: bytes) -> bytes:
    require_scalar(left, allow_zero=True)
    require_scalar(right, allow_zero=True)
    result = _out(SCALAR_BYTES)
    _lib.crypto_core_ristretto255_scalar_add(result, _arr(left), _arr(right))
    return bytes(result)


def scalar_mul(left: bytes, right: bytes) -> bytes:
    """Multiply two canonical scalars modulo the ristretto255 group order."""
    require_scalar(left)
    require_scalar(right)
    result = _out(SCALAR_BYTES)
    _lib.crypto_core_ristretto255_scalar_mul(result, _arr(left), _arr(right))
    return require_scalar(bytes(result))


def scalarmult_base(scalar: bytes) -> bytes:
    require_scalar(scalar)
    result = _out(POINT_BYTES)
    if _lib.crypto_scalarmult_ristretto255_base(result, _arr(scalar)) != 0:
        raise RistrettoError("ristretto255 base multiplication failed")
    return bytes(result)


def scalarmult(scalar: bytes, point: bytes) -> bytes:
    require_scalar(scalar)
    require_point(point, allow_identity=False)
    result = _out(POINT_BYTES)
    if _lib.crypto_scalarmult_ristretto255(result, _arr(scalar), _arr(point)) != 0:
        raise RistrettoError("ristretto255 scalar multiplication failed")
    return bytes(result)


@dataclass(frozen=True)
class KeyPair:
    secret: bytes
    public: bytes


def keypair_from_label(label: bytes) -> KeyPair:
    secret = scalar_from_label(label)
    return KeyPair(secret=secret, public=scalarmult_base(secret))
