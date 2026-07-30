"""Deterministic candidate-layer helpers for vectors and simulator tests only."""

from __future__ import annotations

from .candidate import (
    _seal_responder_candidate_with,
    _wrap_relay_candidate_with,
)
from .test_support import reply_seal_deterministic


def _sealer(ephemeral_secret: bytes):
    def seal(recipient_public: bytes, plaintext: bytes, *, aad: bytes, info: bytes) -> bytes:
        return reply_seal_deterministic(
            recipient_public,
            plaintext,
            aad=aad,
            info=info,
            ephemeral_secret=ephemeral_secret,
        )

    return seal


def seal_responder_candidate_deterministic(
    reply_public: bytes,
    payload: bytes,
    *,
    ephemeral_secret: bytes,
) -> bytes:
    return _seal_responder_candidate_with(_sealer(ephemeral_secret), reply_public, payload)


def wrap_relay_candidate_deterministic(
    parent_reply_public: bytes,
    *,
    blinding_factor: bytes,
    child_candidate_token: bytes,
    forward_label: bytes,
    child_blob: bytes,
    ephemeral_secret: bytes,
) -> bytes:
    return _wrap_relay_candidate_with(
        _sealer(ephemeral_secret),
        parent_reply_public,
        blinding_factor=blinding_factor,
        child_candidate_token=child_candidate_token,
        forward_label=forward_label,
        child_blob=child_blob,
    )
