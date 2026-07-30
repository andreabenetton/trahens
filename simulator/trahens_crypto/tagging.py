# SPDX-License-Identifier: Apache-2.0
"""Active-tagging probes for the C1 universal rerandomization construction.

The helpers intentionally implement an attack, not a protocol feature. A
malicious relay replaces the URE consistency pair with a known scalar ratio.
Honest rerandomization scales both elements and therefore preserves the ratio,
allowing a colluding downstream relay to recognize the tag.
"""

from __future__ import annotations

import hmac

from . import ristretto as r255
from .c1 import CryptoError, URECiphertext


def apply_ratio_tag(ciphertext: URECiphertext, tag_scalar: bytes) -> URECiphertext:
    try:
        tag_scalar = r255.require_scalar(tag_scalar)
        decoded = URECiphertext.decode(ciphertext.encode())
        tagged = URECiphertext(
            u0=decoded.u0,
            v0=decoded.v0,
            u1=r255.scalarmult(tag_scalar, decoded.v1),
            v1=decoded.v1,
        )
        return URECiphertext.decode(tagged.encode())
    except r255.RistrettoError as exc:
        raise CryptoError("active tag construction failed") from exc


def matches_ratio_tag(ciphertext: URECiphertext, tag_scalar: bytes) -> bool:
    try:
        tag_scalar = r255.require_scalar(tag_scalar)
        decoded = URECiphertext.decode(ciphertext.encode())
        expected = r255.scalarmult(tag_scalar, decoded.v1)
        return hmac.compare_digest(decoded.u1, expected)
    except (r255.RistrettoError, CryptoError):
        return False
