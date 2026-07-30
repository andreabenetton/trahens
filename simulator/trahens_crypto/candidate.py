"""C1 candidate-layer construction for the event-driven simulator.

A responder payload is sealed to the final reply public key. Each reverse relay
wraps the child blob under its incoming reply public key and includes the
non-zero multiplicative blinding factor needed by the initiator to derive the
next reply secret. The result is a nested chain that only the initiator can peel.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from trahens_spec.generated import (
    DOMAIN_C1_CANDIDATE_AAD,
    DOMAIN_C1_CANDIDATE_INFO,
    DOMAIN_C1_COMMIT,
    DOMAIN_C1_LABEL_PREFIX,
    DOMAIN_C1_READY,
)

from . import ristretto as r255
from .c1 import (
    CryptoError,
    EndpointKeys,
    candidate_transcript_hash,
    reply_open,
    reply_seal,
    reply_blind_secret,
    verify_candidate_signature,
)

RESPONDER_LAYER = 0x01
RELAY_LAYER = 0x02
RESPONDER_PAYLOAD_BYTES = 256
CANDIDATE_AAD = DOMAIN_C1_CANDIDATE_AAD
CANDIDATE_INFO = DOMAIN_C1_CANDIDATE_INFO


@dataclass(frozen=True)
class ResponderPayload:
    responder_id: int
    offer_expires_ms: int
    endpoint_address: bytes
    endpoint_descriptor: bytes
    final_reply_public: bytes
    commit_challenge: bytes
    responder_nonce: bytes
    signature: bytes


@dataclass(frozen=True)
class CandidateOpenResult:
    payload: ResponderPayload
    final_reply_secret: bytes
    layer_count: int


def _endpoint_address(descriptor: bytes) -> bytes:
    prefix = DOMAIN_C1_LABEL_PREFIX
    label = b"endpoint-address"
    encoded = prefix + len(label).to_bytes(2, "big") + label
    encoded += len(descriptor).to_bytes(2, "big") + descriptor
    return hashlib.sha256(encoded).digest()


def _transcript_fields(
    *,
    responder_id: int,
    offer_expires_ms: int,
    endpoint_address: bytes,
    endpoint_descriptor: bytes,
    final_reply_public: bytes,
    commit_challenge: bytes,
    responder_nonce: bytes,
) -> list[bytes]:
    return [
        responder_id.to_bytes(4, "big"),
        offer_expires_ms.to_bytes(8, "big"),
        endpoint_address,
        endpoint_descriptor,
        final_reply_public,
        commit_challenge,
        responder_nonce,
    ]


def build_responder_payload(
    endpoint: EndpointKeys,
    *,
    responder_id: int,
    offer_expires_ms: int,
    final_reply_public: bytes,
    commit_challenge: bytes,
    responder_nonce: bytes,
) -> bytes:
    if not 0 <= responder_id <= 0xFFFFFFFF:
        raise CryptoError("responder identifier is out of range")
    if not 0 <= offer_expires_ms <= 0xFFFFFFFFFFFFFFFF:
        raise CryptoError("offer expiry is out of range")
    if len(endpoint.address) != 32 or len(endpoint.descriptor) != 67:
        raise CryptoError("invalid endpoint descriptor")
    try:
        r255.require_point(final_reply_public, allow_identity=False)
    except r255.RistrettoError as exc:
        raise CryptoError("invalid final reply public key") from exc
    if len(commit_challenge) != 32 or len(responder_nonce) != 16:
        raise CryptoError("invalid candidate nonce or challenge")
    fields = _transcript_fields(
        responder_id=responder_id,
        offer_expires_ms=offer_expires_ms,
        endpoint_address=endpoint.address,
        endpoint_descriptor=endpoint.descriptor,
        final_reply_public=final_reply_public,
        commit_challenge=commit_challenge,
        responder_nonce=responder_nonce,
    )
    transcript = candidate_transcript_hash(fields)
    signature = endpoint.sign(transcript)
    encoded = (
        bytes([RESPONDER_LAYER])
        + responder_id.to_bytes(4, "big")
        + offer_expires_ms.to_bytes(8, "big")
        + endpoint.address
        + endpoint.descriptor
        + final_reply_public
        + commit_challenge
        + responder_nonce
        + signature
    )
    if len(encoded) != RESPONDER_PAYLOAD_BYTES:
        raise AssertionError("unexpected responder payload length")
    return encoded


def parse_responder_payload(
    encoded: bytes,
    *,
    expected_address: bytes,
    expected_descriptor: bytes,
    expected_final_reply_public: bytes,
) -> ResponderPayload:
    if len(encoded) != RESPONDER_PAYLOAD_BYTES or encoded[0] != RESPONDER_LAYER:
        raise CryptoError("candidate verification failed")
    cursor = 1
    responder_id = int.from_bytes(encoded[cursor : cursor + 4], "big")
    cursor += 4
    offer_expires_ms = int.from_bytes(encoded[cursor : cursor + 8], "big")
    cursor += 8
    endpoint_address = encoded[cursor : cursor + 32]
    cursor += 32
    endpoint_descriptor = encoded[cursor : cursor + 67]
    cursor += 67
    final_reply_public = encoded[cursor : cursor + 32]
    cursor += 32
    commit_challenge = encoded[cursor : cursor + 32]
    cursor += 32
    responder_nonce = encoded[cursor : cursor + 16]
    cursor += 16
    signature = encoded[cursor : cursor + 64]
    if cursor + 64 != RESPONDER_PAYLOAD_BYTES:
        raise AssertionError("candidate parser offset mismatch")
    try:
        r255.require_point(final_reply_public, allow_identity=False)
    except r255.RistrettoError as exc:
        raise CryptoError("candidate verification failed") from exc
    if not hmac.compare_digest(endpoint_address, expected_address):
        raise CryptoError("candidate verification failed")
    if not hmac.compare_digest(endpoint_descriptor, expected_descriptor):
        raise CryptoError("candidate verification failed")
    if not hmac.compare_digest(_endpoint_address(endpoint_descriptor), endpoint_address):
        raise CryptoError("candidate verification failed")
    if not hmac.compare_digest(final_reply_public, expected_final_reply_public):
        raise CryptoError("candidate verification failed")
    signing_public = endpoint_descriptor[-32:]
    fields = _transcript_fields(
        responder_id=responder_id,
        offer_expires_ms=offer_expires_ms,
        endpoint_address=endpoint_address,
        endpoint_descriptor=endpoint_descriptor,
        final_reply_public=final_reply_public,
        commit_challenge=commit_challenge,
        responder_nonce=responder_nonce,
    )
    transcript = candidate_transcript_hash(fields)
    if not verify_candidate_signature(signing_public, transcript, signature):
        raise CryptoError("candidate verification failed")
    return ResponderPayload(
        responder_id=responder_id,
        offer_expires_ms=offer_expires_ms,
        endpoint_address=endpoint_address,
        endpoint_descriptor=endpoint_descriptor,
        final_reply_public=final_reply_public,
        commit_challenge=commit_challenge,
        responder_nonce=responder_nonce,
        signature=signature,
    )


def seal_responder_candidate(reply_public: bytes, payload: bytes) -> bytes:
    """Seal a responder layer using the production-facing random sealer."""
    if len(payload) != RESPONDER_PAYLOAD_BYTES:
        raise CryptoError("invalid responder payload")
    return reply_seal(
        reply_public,
        payload,
        aad=CANDIDATE_AAD,
        info=CANDIDATE_INFO,
    )


def wrap_relay_candidate(
    parent_reply_public: bytes,
    *,
    blinding_factor: bytes,
    child_candidate_token: bytes,
    forward_label: bytes,
    child_blob: bytes,
) -> bytes:
    """Wrap one relay layer using a multiplicative reply-key factor."""
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
    return reply_seal(
        parent_reply_public,
        plaintext,
        aad=CANDIDATE_AAD,
        info=CANDIDATE_INFO,
    )

def open_candidate_chain(
    root_reply_secret: bytes,
    blob: bytes,
    *,
    expected_address: bytes,
    expected_descriptor: bytes,
    max_layers: int = 8,
) -> CandidateOpenResult:
    try:
        secret = r255.require_scalar(root_reply_secret)
    except r255.RistrettoError as exc:
        raise CryptoError("candidate verification failed") from exc
    current = blob
    for layer_count in range(1, max_layers + 1):
        plaintext = reply_open(
            secret,
            current,
            aad=CANDIDATE_AAD,
            info=CANDIDATE_INFO,
        )
        if not plaintext:
            raise CryptoError("candidate verification failed")
        if plaintext[0] == RESPONDER_LAYER:
            expected_public = r255.scalarmult_base(secret)
            payload = parse_responder_payload(
                plaintext,
                expected_address=expected_address,
                expected_descriptor=expected_descriptor,
                expected_final_reply_public=expected_public,
            )
            return CandidateOpenResult(payload, secret, layer_count)
        if plaintext[0] != RELAY_LAYER or len(plaintext) < 67:
            raise CryptoError("candidate verification failed")
        blinding_factor = plaintext[1:33]
        child_length = int.from_bytes(plaintext[65:67], "big")
        if child_length < 1 or len(plaintext) != 67 + child_length:
            raise CryptoError("candidate verification failed")
        current = plaintext[67:]
        secret = reply_blind_secret(secret, blinding_factor)
    raise CryptoError("candidate verification failed")


def commit_proof(commit_challenge: bytes, endpoint_address: bytes) -> bytes:
    if len(commit_challenge) != 32 or len(endpoint_address) != 32:
        raise CryptoError("invalid commit proof input")
    return hmac.new(
        commit_challenge,
        DOMAIN_C1_COMMIT + endpoint_address,
        hashlib.sha256,
    ).digest()


def ready_proof(commit_challenge: bytes, endpoint_address: bytes) -> bytes:
    if len(commit_challenge) != 32 or len(endpoint_address) != 32:
        raise CryptoError("invalid ready proof input")
    return hmac.new(
        commit_challenge,
        DOMAIN_C1_READY + endpoint_address,
        hashlib.sha256,
    ).digest()
