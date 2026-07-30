"""Fixed-size Trahens control-record codec."""

from .c1 import (
    BODY_BYTES,
    CANDIDATE_BLOB_MAX,
    LINK_RECORD_BYTES,
    CandidateRecord,
    CodecError,
    ControlRecord,
    DiscoverRecord,
    MessageType,
    decode_body,
    derive_link_key,
    encode_candidate,
    encode_chaff,
    encode_control,
    encode_discover,
    open_link_record,
    seal_link_record,
)

__all__ = [
    "BODY_BYTES",
    "CANDIDATE_BLOB_MAX",
    "LINK_RECORD_BYTES",
    "CandidateRecord",
    "CodecError",
    "ControlRecord",
    "DiscoverRecord",
    "MessageType",
    "decode_body",
    "derive_link_key",
    "encode_candidate",
    "encode_chaff",
    "encode_control",
    "encode_discover",
    "open_link_record",
    "seal_link_record",
]
