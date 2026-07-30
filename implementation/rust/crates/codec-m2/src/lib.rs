#![forbid(unsafe_code)]
#![doc = "Canonical Trahens M2 logical-message and P1 payload codec."]

use protocol_registry::*;
use trahens_crypto::require_point;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    Malformed,
    UnsupportedVersion,
    UnsupportedProfile,
    UnsupportedSuite,
    ResourceLimit,
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed message",
            Self::UnsupportedVersion => "unsupported protocol version",
            Self::UnsupportedProfile => "unsupported protocol profile",
            Self::UnsupportedSuite => "unsupported cryptographic suite",
            Self::ResourceLimit => "message resource limit exceeded",
        })
    }
}

impl std::error::Error for CodecError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Chaff = MESSAGE_CHAFF,
    Discover = MESSAGE_DISCOVER,
    Candidate = MESSAGE_CANDIDATE,
    Commit = MESSAGE_COMMIT,
    Ready = MESSAGE_READY,
    Cancel = MESSAGE_CANCEL,
    Abort = MESSAGE_ABORT,
    Close = MESSAGE_CLOSE,
    RendezvousOpen = MESSAGE_RENDEZVOUS_OPEN,
    RendezvousResult = MESSAGE_RENDEZVOUS_RESULT,
    Data = MESSAGE_DATA,
}

impl TryFrom<u8> for MessageType {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            MESSAGE_CHAFF => Ok(Self::Chaff),
            MESSAGE_DISCOVER => Ok(Self::Discover),
            MESSAGE_CANDIDATE => Ok(Self::Candidate),
            MESSAGE_COMMIT => Ok(Self::Commit),
            MESSAGE_READY => Ok(Self::Ready),
            MESSAGE_CANCEL => Ok(Self::Cancel),
            MESSAGE_ABORT => Ok(Self::Abort),
            MESSAGE_CLOSE => Ok(Self::Close),
            MESSAGE_RENDEZVOUS_OPEN => Ok(Self::RendezvousOpen),
            MESSAGE_RENDEZVOUS_RESULT => Ok(Self::RendezvousResult),
            MESSAGE_DATA => Ok(Self::Data),
            _ => Err(CodecError::Malformed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discover {
    pub branch_token: [u8; 16],
    pub hop_remaining: u8,
    pub fanout_class: u8,
    pub expiry_class: u8,
    pub options: u8,
    pub reply_public_key: [u8; 32],
    pub discovery_field: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub candidate_token: [u8; 16],
    pub expiry_class: u8,
    pub layer_count: u8,
    pub candidate_blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub message_type: MessageType,
    pub local_label: [u8; 16],
    pub generation: u32,
    pub expiry_class: u8,
    pub protected_body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Chaff,
    Discover(Discover),
    Candidate(Candidate),
    Control(Control),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub suite_id: [u8; 2],
    pub message: Message,
}

fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn canonical_reply_field(suite: [u8; 2], public: &[u8; 32], field: &[u8]) -> bool {
    if require_point(public).is_err() {
        return false;
    }
    match suite {
        SUITE_R1 => field.len() == BYTES_R1_DISCOVERY_NONCE && nonzero(field),
        SUITE_C1_V2 => {
            field.len() == 128
                && field.chunks_exact(32).all(|chunk| {
                    let Ok(point) = <&[u8; 32]>::try_from(chunk) else {
                        return false;
                    };
                    require_point(point).is_ok()
                })
        }
        SUITE_C2_SYMBOLIC => field.len() == 640 && nonzero(field),
        _ => false,
    }
}

fn require_suite(suite: [u8; 2]) -> Result<(), CodecError> {
    if suite_is_network_valid(suite) {
        Ok(())
    } else {
        Err(CodecError::UnsupportedSuite)
    }
}

pub fn encode_varuint(mut value: u32, output: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            output.push(low);
            return;
        }
        output.push(low | 0x80);
    }
}

pub fn decode_varuint(input: &[u8], cursor: &mut usize, maximum: u32) -> Result<u32, CodecError> {
    let start = *cursor;
    let mut value = 0_u32;
    let mut shift = 0_u32;
    for _ in 0..5 {
        let byte = *input.get(*cursor).ok_or(CodecError::Malformed)?;
        *cursor += 1;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let mut canonical = Vec::new();
            encode_varuint(value, &mut canonical);
            if input.get(start..*cursor) != Some(canonical.as_slice()) || value > maximum {
                return Err(CodecError::Malformed);
            }
            return Ok(value);
        }
        shift += 7;
    }
    Err(CodecError::Malformed)
}

fn common_prefix(
    message_type: MessageType,
    suite: [u8; 2],
    body_len: usize,
) -> Result<Vec<u8>, CodecError> {
    require_suite(suite)?;
    if body_len > LIMIT_MAX_LOGICAL_MESSAGE_BYTES {
        return Err(CodecError::ResourceLimit);
    }
    let mut output = Vec::with_capacity(9 + body_len);
    output.extend_from_slice(&[
        message_type as u8,
        VERSION,
        PRIVACY_PROFILE_U1,
        LIFECYCLE_PROFILE_E1,
    ]);
    output.extend_from_slice(&suite);
    output.extend_from_slice(&[MESSAGE_PROFILE_M2, 0]);
    encode_varuint(body_len as u32, &mut output);
    Ok(output)
}

pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, CodecError> {
    let (message_type, body) = match &envelope.message {
        Message::Chaff => (MessageType::Chaff, Vec::new()),
        Message::Discover(message) => {
            if !nonzero(&message.branch_token)
                || message.fanout_class == 0
                || message.expiry_class == 0
                || !nonzero(&message.reply_public_key)
            {
                return Err(CodecError::Malformed);
            }
            if !canonical_reply_field(
                envelope.suite_id,
                &message.reply_public_key,
                &message.discovery_field,
            ) {
                return Err(CodecError::Malformed);
            }
            let mut body = Vec::with_capacity(69 + message.discovery_field.len());
            body.extend_from_slice(&message.branch_token);
            body.extend_from_slice(&[
                message.hop_remaining,
                message.fanout_class,
                message.expiry_class,
                message.options,
            ]);
            body.extend_from_slice(&message.reply_public_key);
            encode_varuint(message.discovery_field.len() as u32, &mut body);
            body.extend_from_slice(&message.discovery_field);
            (MessageType::Discover, body)
        }
        Message::Candidate(message) => {
            if !nonzero(&message.candidate_token)
                || message.expiry_class == 0
                || message.layer_count == 0
                || message.candidate_blob.is_empty()
            {
                return Err(CodecError::Malformed);
            }
            let mut body = Vec::with_capacity(19 + message.candidate_blob.len());
            body.extend_from_slice(&message.candidate_token);
            body.extend_from_slice(&[message.expiry_class, message.layer_count]);
            encode_varuint(message.candidate_blob.len() as u32, &mut body);
            body.extend_from_slice(&message.candidate_blob);
            (MessageType::Candidate, body)
        }
        Message::Control(message) => {
            if matches!(
                message.message_type,
                MessageType::Chaff | MessageType::Discover | MessageType::Candidate
            ) || !nonzero(&message.local_label)
                || message.expiry_class == 0
                || message.protected_body.len() > LIMIT_MAX_CONTROL_PROTECTED_BYTES
            {
                return Err(CodecError::Malformed);
            }
            let mut body = Vec::with_capacity(22 + message.protected_body.len());
            body.extend_from_slice(&message.local_label);
            body.extend_from_slice(&message.generation.to_be_bytes());
            body.push(message.expiry_class);
            encode_varuint(message.protected_body.len() as u32, &mut body);
            body.extend_from_slice(&message.protected_body);
            (message.message_type, body)
        }
    };
    let mut output = common_prefix(message_type, envelope.suite_id, body.len())?;
    output.extend_from_slice(&body);
    if output.len() > LIMIT_MAX_LOGICAL_MESSAGE_BYTES {
        return Err(CodecError::ResourceLimit);
    }
    Ok(output)
}

fn take_array<const N: usize>(input: &[u8], cursor: &mut usize) -> Result<[u8; N], CodecError> {
    let end = cursor.checked_add(N).ok_or(CodecError::Malformed)?;
    let source = input.get(*cursor..end).ok_or(CodecError::Malformed)?;
    let mut output = [0_u8; N];
    output.copy_from_slice(source);
    *cursor = end;
    Ok(output)
}

pub fn decode(input: &[u8]) -> Result<Envelope, CodecError> {
    if input.len() < 9 || input.len() > LIMIT_MAX_LOGICAL_MESSAGE_BYTES {
        return Err(CodecError::Malformed);
    }
    let message_type = MessageType::try_from(input[0])?;
    if input[1] != VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    if input[2] != PRIVACY_PROFILE_U1
        || input[3] != LIFECYCLE_PROFILE_E1
        || input[6] != MESSAGE_PROFILE_M2
        || input[7] != 0
    {
        return Err(CodecError::UnsupportedProfile);
    }
    let suite = [input[4], input[5]];
    require_suite(suite)?;
    let mut cursor = 8;
    let body_len =
        decode_varuint(input, &mut cursor, LIMIT_MAX_LOGICAL_MESSAGE_BYTES as u32)? as usize;
    let body_end = cursor.checked_add(body_len).ok_or(CodecError::Malformed)?;
    if body_end != input.len() {
        return Err(CodecError::Malformed);
    }
    let body = &input[cursor..body_end];
    let message = match message_type {
        MessageType::Chaff => {
            if !body.is_empty() {
                return Err(CodecError::Malformed);
            }
            Message::Chaff
        }
        MessageType::Discover => {
            let mut at = 0;
            let branch_token = take_array::<16>(body, &mut at)?;
            let hop_remaining = *body.get(at).ok_or(CodecError::Malformed)?;
            let fanout_class = *body.get(at + 1).ok_or(CodecError::Malformed)?;
            let expiry_class = *body.get(at + 2).ok_or(CodecError::Malformed)?;
            let options = *body.get(at + 3).ok_or(CodecError::Malformed)?;
            at += 4;
            let reply_public_key = take_array::<32>(body, &mut at)?;
            let field_len =
                decode_varuint(body, &mut at, LIMIT_MAX_LOGICAL_MESSAGE_BYTES as u32)? as usize;
            let field_end = at.checked_add(field_len).ok_or(CodecError::Malformed)?;
            if field_end != body.len()
                || !nonzero(&branch_token)
                || fanout_class == 0
                || expiry_class == 0
                || !nonzero(&reply_public_key)
            {
                return Err(CodecError::Malformed);
            }
            let discovery_field = body[at..field_end].to_vec();
            if !canonical_reply_field(suite, &reply_public_key, &discovery_field) {
                return Err(CodecError::Malformed);
            }
            Message::Discover(Discover {
                branch_token,
                hop_remaining,
                fanout_class,
                expiry_class,
                options,
                reply_public_key,
                discovery_field,
            })
        }
        MessageType::Candidate => {
            let mut at = 0;
            let candidate_token = take_array::<16>(body, &mut at)?;
            let expiry_class = *body.get(at).ok_or(CodecError::Malformed)?;
            let layer_count = *body.get(at + 1).ok_or(CodecError::Malformed)?;
            at += 2;
            let blob_len =
                decode_varuint(body, &mut at, LIMIT_MAX_LOGICAL_MESSAGE_BYTES as u32)? as usize;
            let blob_end = at.checked_add(blob_len).ok_or(CodecError::Malformed)?;
            if blob_end != body.len()
                || !nonzero(&candidate_token)
                || expiry_class == 0
                || layer_count == 0
                || blob_len == 0
            {
                return Err(CodecError::Malformed);
            }
            Message::Candidate(Candidate {
                candidate_token,
                expiry_class,
                layer_count,
                candidate_blob: body[at..blob_end].to_vec(),
            })
        }
        control_type => {
            let mut at = 0;
            let local_label = take_array::<16>(body, &mut at)?;
            let generation = u32::from_be_bytes(take_array::<4>(body, &mut at)?);
            let expiry_class = *body.get(at).ok_or(CodecError::Malformed)?;
            at += 1;
            let protected_len =
                decode_varuint(body, &mut at, LIMIT_MAX_CONTROL_PROTECTED_BYTES as u32)? as usize;
            let protected_end = at.checked_add(protected_len).ok_or(CodecError::Malformed)?;
            if protected_end != body.len() || !nonzero(&local_label) || expiry_class == 0 {
                return Err(CodecError::Malformed);
            }
            Message::Control(Control {
                message_type: control_type,
                local_label,
                generation,
                expiry_class,
                protected_body: body[at..protected_end].to_vec(),
            })
        }
    };
    Ok(Envelope {
        suite_id: suite,
        message,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P1Payload {
    GatewayOffer {
        gateway_id: u32,
        expires_at_ms: u64,
        gateway_pseudonym: [u8; 16],
        route_secret: [u8; 32],
        commit_challenge: [u8; 32],
        discovery_nonce: [u8; 32],
        signing_public: [u8; 32],
        signature: [u8; 64],
    },
    RelayLayer {
        blinding_factor: [u8; 32],
        child_candidate_token: [u8; 16],
        forward_label: [u8; 16],
        parent_discovery_nonce: [u8; 32],
        child_discovery_nonce: [u8; 32],
        child_blob: Vec<u8>,
    },
    Commit {
        proof: [u8; 32],
    },
    Ready {
        proof: [u8; 32],
    },
    RendezvousOpen {
        gateway_pseudonym: [u8; 16],
        capability: [u8; 32],
    },
    RendezvousResult {
        status: u16,
    },
    Data {
        direction: u8,
        sequence: u64,
        payload: Vec<u8>,
    },
    Close {
        reason: u16,
    },
}

pub fn encode_p1(payload: &P1Payload) -> Result<Vec<u8>, CodecError> {
    let mut output = Vec::new();
    match payload {
        P1Payload::GatewayOffer {
            gateway_id,
            expires_at_ms,
            gateway_pseudonym,
            route_secret,
            commit_challenge,
            discovery_nonce,
            signing_public,
            signature,
        } => {
            if !nonzero(gateway_pseudonym)
                || !nonzero(route_secret)
                || !nonzero(commit_challenge)
                || !nonzero(discovery_nonce)
            {
                return Err(CodecError::Malformed);
            }
            output.push(P1_PAYLOAD_GATEWAY_OFFER);
            output.extend_from_slice(&gateway_id.to_be_bytes());
            output.extend_from_slice(&expires_at_ms.to_be_bytes());
            output.extend_from_slice(gateway_pseudonym);
            output.extend_from_slice(route_secret);
            output.extend_from_slice(commit_challenge);
            output.extend_from_slice(discovery_nonce);
            output.extend_from_slice(signing_public);
            output.extend_from_slice(signature);
        }
        P1Payload::RelayLayer {
            blinding_factor,
            child_candidate_token,
            forward_label,
            parent_discovery_nonce,
            child_discovery_nonce,
            child_blob,
        } => {
            if !nonzero(blinding_factor)
                || !nonzero(child_candidate_token)
                || !nonzero(forward_label)
                || !nonzero(parent_discovery_nonce)
                || !nonzero(child_discovery_nonce)
                || child_blob.is_empty()
                || child_blob.len() > u16::MAX as usize
            {
                return Err(CodecError::Malformed);
            }
            output.push(P1_PAYLOAD_RELAY_CANDIDATE_LAYER);
            output.extend_from_slice(blinding_factor);
            output.extend_from_slice(child_candidate_token);
            output.extend_from_slice(forward_label);
            output.extend_from_slice(parent_discovery_nonce);
            output.extend_from_slice(child_discovery_nonce);
            output.extend_from_slice(&(child_blob.len() as u16).to_be_bytes());
            output.extend_from_slice(child_blob);
        }
        P1Payload::Commit { proof } => {
            output.push(P1_PAYLOAD_COMMIT);
            output.extend_from_slice(proof);
        }
        P1Payload::Ready { proof } => {
            output.push(P1_PAYLOAD_READY);
            output.extend_from_slice(proof);
        }
        P1Payload::RendezvousOpen {
            gateway_pseudonym,
            capability,
        } => {
            if !nonzero(gateway_pseudonym) || !nonzero(capability) {
                return Err(CodecError::Malformed);
            }
            output.push(P1_PAYLOAD_RENDEZVOUS_OPEN);
            output.extend_from_slice(gateway_pseudonym);
            output.extend_from_slice(capability);
        }
        P1Payload::RendezvousResult { status } => {
            output.push(P1_PAYLOAD_RENDEZVOUS_RESULT);
            output.extend_from_slice(&status.to_be_bytes());
        }
        P1Payload::Data {
            direction,
            sequence,
            payload,
        } => {
            if *direction > 1 || payload.len() > u16::MAX as usize {
                return Err(CodecError::Malformed);
            }
            output.push(P1_PAYLOAD_DATA);
            output.push(*direction);
            output.extend_from_slice(&sequence.to_be_bytes());
            output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            output.extend_from_slice(payload);
        }
        P1Payload::Close { reason } => {
            output.push(P1_PAYLOAD_CLOSE);
            output.extend_from_slice(&reason.to_be_bytes());
        }
    }
    Ok(output)
}

pub fn decode_p1(input: &[u8]) -> Result<P1Payload, CodecError> {
    let kind = *input.first().ok_or(CodecError::Malformed)?;
    let mut cursor = 1;
    let value = match kind {
        P1_PAYLOAD_GATEWAY_OFFER => {
            let gateway_id = u32::from_be_bytes(take_array::<4>(input, &mut cursor)?);
            let expires_at_ms = u64::from_be_bytes(take_array::<8>(input, &mut cursor)?);
            let gateway_pseudonym = take_array::<16>(input, &mut cursor)?;
            let route_secret = take_array::<32>(input, &mut cursor)?;
            let commit_challenge = take_array::<32>(input, &mut cursor)?;
            let discovery_nonce = take_array::<32>(input, &mut cursor)?;
            let signing_public = take_array::<32>(input, &mut cursor)?;
            let signature = take_array::<64>(input, &mut cursor)?;
            if !nonzero(&gateway_pseudonym)
                || !nonzero(&route_secret)
                || !nonzero(&commit_challenge)
                || !nonzero(&discovery_nonce)
            {
                return Err(CodecError::Malformed);
            }
            P1Payload::GatewayOffer {
                gateway_id,
                expires_at_ms,
                gateway_pseudonym,
                route_secret,
                commit_challenge,
                discovery_nonce,
                signing_public,
                signature,
            }
        }
        P1_PAYLOAD_RELAY_CANDIDATE_LAYER => {
            let blinding_factor = take_array::<32>(input, &mut cursor)?;
            let child_candidate_token = take_array::<16>(input, &mut cursor)?;
            let forward_label = take_array::<16>(input, &mut cursor)?;
            let parent_discovery_nonce = take_array::<32>(input, &mut cursor)?;
            let child_discovery_nonce = take_array::<32>(input, &mut cursor)?;
            let child_len = u16::from_be_bytes(take_array::<2>(input, &mut cursor)?) as usize;
            let end = cursor.checked_add(child_len).ok_or(CodecError::Malformed)?;
            if end != input.len()
                || child_len == 0
                || !nonzero(&blinding_factor)
                || !nonzero(&child_candidate_token)
                || !nonzero(&forward_label)
                || !nonzero(&parent_discovery_nonce)
                || !nonzero(&child_discovery_nonce)
            {
                return Err(CodecError::Malformed);
            }
            cursor = end;
            P1Payload::RelayLayer {
                blinding_factor,
                child_candidate_token,
                forward_label,
                parent_discovery_nonce,
                child_discovery_nonce,
                child_blob: input[end - child_len..end].to_vec(),
            }
        }
        P1_PAYLOAD_COMMIT => P1Payload::Commit {
            proof: take_array::<32>(input, &mut cursor)?,
        },
        P1_PAYLOAD_READY => P1Payload::Ready {
            proof: take_array::<32>(input, &mut cursor)?,
        },
        P1_PAYLOAD_RENDEZVOUS_OPEN => {
            let gateway_pseudonym = take_array::<16>(input, &mut cursor)?;
            let capability = take_array::<32>(input, &mut cursor)?;
            if !nonzero(&gateway_pseudonym) || !nonzero(&capability) {
                return Err(CodecError::Malformed);
            }
            P1Payload::RendezvousOpen {
                gateway_pseudonym,
                capability,
            }
        }
        P1_PAYLOAD_RENDEZVOUS_RESULT => P1Payload::RendezvousResult {
            status: u16::from_be_bytes(take_array::<2>(input, &mut cursor)?),
        },
        P1_PAYLOAD_DATA => {
            let direction = *input.get(cursor).ok_or(CodecError::Malformed)?;
            cursor += 1;
            let sequence = u64::from_be_bytes(take_array::<8>(input, &mut cursor)?);
            let payload_len = u16::from_be_bytes(take_array::<2>(input, &mut cursor)?) as usize;
            let end = cursor
                .checked_add(payload_len)
                .ok_or(CodecError::Malformed)?;
            if end != input.len() || direction > 1 {
                return Err(CodecError::Malformed);
            }
            cursor = end;
            P1Payload::Data {
                direction,
                sequence,
                payload: input[end - payload_len..end].to_vec(),
            }
        }
        P1_PAYLOAD_CLOSE => P1Payload::Close {
            reason: u16::from_be_bytes(take_array::<2>(input, &mut cursor)?),
        },
        _ => return Err(CodecError::Malformed),
    };
    if cursor != input.len() {
        return Err(CodecError::Malformed);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_point() -> [u8; 32] {
        [
            0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00,
            0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45,
            0xe0, 0x8d, 0x2d, 0x76,
        ]
    }

    #[test]
    fn varuint_rejects_noncanonical_encoding() {
        let mut cursor = 0;
        assert_eq!(
            decode_varuint(&[0x80, 0x00], &mut cursor, u32::MAX),
            Err(CodecError::Malformed)
        );
    }

    #[test]
    fn discover_round_trip() -> Result<(), CodecError> {
        let message = Envelope {
            suite_id: SUITE_R1,
            message: Message::Discover(Discover {
                branch_token: [1; 16],
                hop_remaining: 12,
                fanout_class: 1,
                expiry_class: 1,
                options: 0,
                reply_public_key: hex_point(),
                discovery_field: vec![3; 32],
            }),
        };
        assert_eq!(decode(&encode(&message)?)?, message);
        Ok(())
    }

    #[test]
    fn retired_suite_is_rejected() {
        let mut encoded = encode(&Envelope {
            suite_id: SUITE_R1,
            message: Message::Chaff,
        })
        .unwrap_or_default();
        encoded[4..6].copy_from_slice(&SUITE_C1_V1_RETIRED);
        assert_eq!(decode(&encoded), Err(CodecError::UnsupportedSuite));
    }
}
