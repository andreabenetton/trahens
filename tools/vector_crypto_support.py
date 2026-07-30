# SPDX-License-Identifier: Apache-2.0
"""Deterministic C1 reply encryption for repository vectors and tests only.

This module is outside the installed ``trahens_crypto`` package. It exists so
tracked vectors can choose an ephemeral scalar without exposing that operation
through the runtime API.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import (
    CryptoError,
    _derive_reply_context,
    _reply_commitment,
)


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
    try:
        recipient_public = r255.require_point(recipient_public, allow_identity=False)
        ephemeral_secret = r255.require_scalar(ephemeral_secret)
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
