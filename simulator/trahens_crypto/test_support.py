"""Explicitly gated deterministic helpers for vectors and simulator tests.

This module is not exported by :mod:`trahens_crypto`.  Callers must opt in by
setting ``TRAHENS_TEST_CRYPTO=1``.  Production-facing encryption APIs do not
accept caller-chosen ephemeral secrets.
"""

from __future__ import annotations

import os

from .c1 import _reply_seal_with_secret


def reply_seal_deterministic(
    recipient_public: bytes,
    plaintext: bytes,
    *,
    aad: bytes,
    info: bytes,
    ephemeral_secret: bytes,
) -> bytes:
    if os.environ.get("TRAHENS_TEST_CRYPTO") != "1":
        raise RuntimeError("deterministic reply encryption is test-only")
    return _reply_seal_with_secret(
        recipient_public,
        plaintext,
        aad=aad,
        info=info,
        ephemeral_secret=ephemeral_secret,
    )
