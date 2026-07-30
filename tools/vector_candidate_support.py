"""Deterministic candidate-layer builders for vectors and tests only."""

from __future__ import annotations

from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import CryptoError
from trahens_crypto.candidate import (
    CANDIDATE_AAD,
    CANDIDATE_INFO,
    RELAY_LAYER,
    RESPONDER_PAYLOAD_BYTES,
)
from tools.vector_crypto_support import reply_seal_deterministic


def seal_responder_candidate_deterministic(
    reply_public: bytes,
    payload: bytes,
    *,
    ephemeral_secret: bytes,
) -> bytes:
    if len(payload) != RESPONDER_PAYLOAD_BYTES:
        raise CryptoError("invalid responder payload")
    return reply_seal_deterministic(
        reply_public,
        payload,
        aad=CANDIDATE_AAD,
        info=CANDIDATE_INFO,
        ephemeral_secret=ephemeral_secret,
    )


def wrap_relay_candidate_deterministic(
    parent_reply_public: bytes,
    *,
    blinding_factor: bytes,
    child_candidate_token: bytes,
    forward_label: bytes,
    child_blob: bytes,
    ephemeral_secret: bytes,
) -> bytes:
    try:
        blinding_factor = r255.require_scalar(blinding_factor)
    except r255.RistrettoError as exc:
        raise CryptoError("invalid candidate reply blinding factor") from exc
    if len(child_candidate_token) != 16 or len(forward_label) != 16:
        raise CryptoError("invalid candidate local capability")
    if not 1 <= len(child_blob) <= 0xFFFF:
        raise CryptoError("invalid child candidate blob")
    plaintext = (
        bytes([RELAY_LAYER])
        + blinding_factor
        + child_candidate_token
        + forward_label
        + len(child_blob).to_bytes(2, "big")
        + child_blob
    )
    return reply_seal_deterministic(
        parent_reply_public,
        plaintext,
        aad=CANDIDATE_AAD,
        info=CANDIDATE_INFO,
        ephemeral_secret=ephemeral_secret,
    )
