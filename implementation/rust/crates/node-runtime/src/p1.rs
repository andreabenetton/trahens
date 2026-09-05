// SPDX-License-Identifier: Apache-2.0
#![doc = "P1 candidate-chain and end-to-end control helpers."]

use codec_m2::{decode_p1, encode_p1, CodecError, MessageType, P1Payload};
use protocol_registry::{
    DOMAIN_C1_CANDIDATE_AAD, DOMAIN_C1_CANDIDATE_INFO, DOMAIN_C1_COMMIT, DOMAIN_C1_READY,
    LIMIT_MAX_CANDIDATE_LAYERS, LIMIT_MAX_CANDIDATE_RESPONSES_PER_DISCOVERY,
    LIMIT_ROUTE_REPLAY_WINDOW,
};
use std::collections::BTreeSet;
use trahens_crypto::{
    blind_secret, constant_time_equal, hmac_sha256, keyed_proof, reply_open, reply_seal,
    route_open, route_seal, scalar_base, sha256, sign, verify, zeroize_slice, CryptoError,
    RouteDirection, SecretBytes,
};

#[derive(Debug)]
pub enum P1Error {
    Codec(CodecError),
    Crypto(CryptoError),
    InvalidOffer,
    TooManyLayers,
    WrongPayload,
    RouteReplay,
    RouteSequenceExhausted,
}

impl From<CodecError> for P1Error {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<CryptoError> for P1Error {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl std::fmt::Display for P1Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "P1 codec error: {error}"),
            Self::Crypto(error) => write!(formatter, "P1 cryptographic error: {error}"),
            Self::InvalidOffer => formatter.write_str("invalid P1 gateway offer"),
            Self::TooManyLayers => formatter.write_str("too many P1 candidate layers"),
            Self::WrongPayload => formatter.write_str("unexpected P1 payload"),
            Self::RouteReplay => formatter.write_str("replayed P1 route record"),
            Self::RouteSequenceExhausted => {
                formatter.write_str("P1 route sequence space exhausted")
            }
        }
    }
}

impl std::error::Error for P1Error {}

/// An unwrapped gateway offer.
///
/// Deliberately not `Clone`: the route secret and commit challenge are key
/// material, and a candidate that loses the selection or expires is dropped
/// without ever being used. Holding them in `SecretBytes` means those copies
/// are wiped on drop rather than left in the initiator's heap, and refusing
/// `Clone` means there is only ever one copy to wipe.
pub struct OpenedOffer {
    pub gateway_id: u32,
    pub expires_at_ms: u64,
    pub gateway_pseudonym: [u8; 16],
    pub route_secret: SecretBytes<32>,
    pub commit_challenge: SecretBytes<32>,
    pub routing_nonce: [u8; 32],
    /// Token the innermost relay used towards the gateway. Diagnostic only:
    /// control is addressed with the tentative selector each relay mints per
    /// returned offer, which is what disambiguates a fanned-out branch.
    pub gateway_candidate_token: Option<[u8; 16]>,
    pub layer_count: usize,
    /// Hash of the v2 transcript this offer was signed over. The route key
    /// schedule is derived against it, so both ends bind the same offer.
    pub transcript_hash: [u8; 32],
}

/// How many offer labels a node keeps registered per child at once.
///
/// Offers may arrive out of order within the window; the window slides as each
/// is consumed, so live state stays small while the total per child is still
/// bounded by `LIMIT_MAX_CANDIDATE_RESPONSES_PER_DISCOVERY`.
pub const OFFER_LABEL_WINDOW: u16 = 4;

/// Parent-facing label for the `index`-th offer returned on one branch.
///
/// `core-v0.1.md` section 11 has a relay create a tentative mapping from a
/// parent-facing label to a child-facing one, and receive COMMIT on that
/// parent-facing label. For the parent to resolve a label it did not mint, the
/// two ends need a shared secret to derive it from, and they already have
/// one: the routing nonce the parent independently replaced for this child and
/// sent in the DISCOVER. Deriving from it keeps successive labels unlinkable to
/// anyone who has not seen the nonce, which a counter or an XOR of the branch
/// token would not.
///
/// Since v1.6 this is the routing nonce rather than the eligibility field, so
/// the derivation is unchanged whatever suite the link runs.
pub fn offer_label(routing_nonce: &[u8; 32], index: u16) -> Result<[u8; 16], P1Error> {
    if usize::from(index) >= LIMIT_MAX_CANDIDATE_RESPONSES_PER_DISCOVERY {
        return Err(P1Error::TooManyLayers);
    }
    let mut input = b"Trahens-P1-offer-label-v1".to_vec();
    input.extend_from_slice(&index.to_be_bytes());
    let full = hmac_sha256(routing_nonce, &input).map_err(|_| P1Error::InvalidOffer)?;
    let mut label = [0_u8; 16];
    label.copy_from_slice(&full[..16]);
    // A zero label is not a valid token anywhere in M2.
    if label == [0_u8; 16] {
        return Err(P1Error::InvalidOffer);
    }
    Ok(label)
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), P1Error> {
    let length = u16::try_from(value.len()).map_err(|_| P1Error::InvalidOffer)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

/// Digest of the profile parameters both ends must already agree on.
///
/// Binding this into the signed offer is what makes the agreed parameter set
/// part of what the gateway signature covers, rather than something each side
/// assumes separately from its own registry.
fn profile_parameter_digest() -> Result<[u8; 32], P1Error> {
    let mut input = b"Trahens-P1-profile-parameters-v2".to_vec();
    input.push(protocol_registry::VERSION);
    input.push(protocol_registry::PRIVACY_PROFILE_U1);
    input.push(protocol_registry::LIFECYCLE_PROFILE_E1);
    input.push(protocol_registry::MESSAGE_PROFILE_M2);
    input.push(protocol_registry::WIRE_PROFILE_W2);
    input.push(protocol_registry::TRANSPORT_PROFILE_T1);
    input.push(protocol_registry::SCHEDULE_PROFILE_T2);
    for value in [
        protocol_registry::FIXED_T2_EPOCH_MS,
        protocol_registry::FIXED_T2_CELLS_PER_EPOCH,
        protocol_registry::FIXED_T2_SLOT_INTERVAL_US,
    ] {
        let encoded = u32::try_from(value).map_err(|_| P1Error::InvalidOffer)?;
        input.extend_from_slice(&encoded.to_be_bytes());
    }
    Ok(sha256(&input)?)
}

/// The v2 gateway-offer transcript.
///
/// v1 signed neither the protocol version, the suite, the reply key the offer
/// is sealed to, nor the parameter digest, so the paper's authentication
/// argument reasoned over a wider field set than the signature actually
/// covered. v2 binds all four, in one canonical order, and its hash is what the
/// route key schedule is derived against.
#[allow(clippy::too_many_arguments)]
fn offer_transcript(
    suite_id: &[u8; 2],
    gateway_id: u32,
    expires_at_ms: u64,
    gateway_pseudonym: &[u8; 16],
    reply_public_key: &[u8; 32],
    route_secret: &[u8; 32],
    commit_challenge: &[u8; 32],
    routing_nonce: &[u8; 32],
    signing_public: &[u8; 32],
) -> Result<Vec<u8>, P1Error> {
    let mut output = protocol_registry::DOMAIN_P1_GATEWAY_OFFER.to_vec();
    append_field(&mut output, &[protocol_registry::VERSION])?;
    append_field(&mut output, suite_id)?;
    append_field(&mut output, &gateway_id.to_be_bytes())?;
    append_field(&mut output, gateway_pseudonym)?;
    append_field(&mut output, &expires_at_ms.to_be_bytes())?;
    append_field(&mut output, reply_public_key)?;
    append_field(&mut output, route_secret)?;
    append_field(&mut output, commit_challenge)?;
    append_field(&mut output, routing_nonce)?;
    append_field(&mut output, signing_public)?;
    append_field(&mut output, &profile_parameter_digest()?)?;
    Ok(output)
}

fn candidate_context(layer: u8) -> (Vec<u8>, Vec<u8>) {
    let mut aad = DOMAIN_C1_CANDIDATE_AAD.to_vec();
    aad.push(layer);
    let mut info = DOMAIN_C1_CANDIDATE_INFO.to_vec();
    info.push(layer);
    (aad, info)
}

/// Seal a gateway offer, returning the sealed blob and the transcript hash.
///
/// The hash is returned rather than recomputed by the caller because it is the
/// binding the route keys are derived against; both ends must use the same one.
#[allow(clippy::too_many_arguments)]
pub fn seal_gateway_offer(
    recipient_public: &[u8; 32],
    suite_id: &[u8; 2],
    gateway_id: u32,
    expires_at_ms: u64,
    gateway_pseudonym: [u8; 16],
    route_secret: [u8; 32],
    commit_challenge: [u8; 32],
    routing_nonce: [u8; 32],
    signing_public: [u8; 32],
    signing_secret: &SecretBytes<64>,
) -> Result<(Vec<u8>, [u8; 32]), P1Error> {
    let mut transcript = offer_transcript(
        suite_id,
        gateway_id,
        expires_at_ms,
        &gateway_pseudonym,
        recipient_public,
        &route_secret,
        &commit_challenge,
        &routing_nonce,
        &signing_public,
    )?;
    let transcript_hash = sha256(&transcript)?;
    let signature_result = sign(signing_secret, &transcript);
    zeroize_slice(&mut transcript);
    let signature = signature_result?;
    let mut plaintext = encode_p1(&P1Payload::GatewayOffer {
        gateway_id,
        expires_at_ms,
        gateway_pseudonym,
        route_secret,
        commit_challenge,
        routing_nonce,
        signing_public,
        signature,
    })?;
    let (aad, info) = candidate_context(0);
    let result = reply_seal(recipient_public, &plaintext, &aad, &info);
    zeroize_slice(&mut plaintext);
    Ok((result?, transcript_hash))
}

pub fn wrap_candidate(
    recipient_public: &[u8; 32],
    layer_index: u8,
    blinding_factor: [u8; 32],
    child_candidate_token: [u8; 16],
    forward_label: [u8; 16],
    parent_routing_nonce: [u8; 32],
    child_routing_nonce: [u8; 32],
    child_blob: Vec<u8>,
) -> Result<Vec<u8>, P1Error> {
    if layer_index == 0 || usize::from(layer_index) > LIMIT_MAX_CANDIDATE_LAYERS {
        return Err(P1Error::TooManyLayers);
    }
    let mut plaintext = encode_p1(&P1Payload::RelayLayer {
        blinding_factor,
        child_candidate_token,
        forward_label,
        parent_routing_nonce,
        child_routing_nonce,
        child_blob,
    })?;
    let (aad, info) = candidate_context(layer_index);
    let result = reply_seal(recipient_public, &plaintext, &aad, &info);
    zeroize_slice(&mut plaintext);
    Ok(result?)
}

pub fn open_candidate_chain(
    root_secret: &[u8; 32],
    suite_id: &[u8; 2],
    candidate_blob: &[u8],
    advertised_layers: u8,
    expected_gateway_public: &[u8; 32],
    expected_routing_nonce: &[u8; 32],
    now_ms: u64,
) -> Result<OpenedOffer, P1Error> {
    if advertised_layers == 0 || usize::from(advertised_layers) > LIMIT_MAX_CANDIDATE_LAYERS + 1 {
        return Err(P1Error::TooManyLayers);
    }
    let mut secret = SecretBytes(*root_secret);
    let mut blob = candidate_blob.to_vec();
    let mut gateway_candidate_token = None;
    let mut relay_layers = 0_usize;
    let mut expected_nonce = *expected_routing_nonce;

    loop {
        let layer_index = if relay_layers + 1 == usize::from(advertised_layers) {
            0
        } else {
            u8::try_from(relay_layers + 1).map_err(|_| P1Error::TooManyLayers)?
        };
        let (aad, info) = candidate_context(layer_index);
        let mut plaintext = reply_open(&secret.0, &blob, &aad, &info)?;
        let decoded = decode_p1(&plaintext);
        zeroize_slice(&mut plaintext);
        match decoded? {
            P1Payload::GatewayOffer {
                gateway_id,
                expires_at_ms,
                gateway_pseudonym,
                route_secret,
                commit_challenge,
                routing_nonce,
                signing_public,
                signature,
            } => {
                if relay_layers + 1 != usize::from(advertised_layers)
                    || signing_public != *expected_gateway_public
                    || routing_nonce != expected_nonce
                    || now_ms >= expires_at_ms
                {
                    return Err(P1Error::InvalidOffer);
                }
                // The gateway sealed to the blinded reply key that reached it,
                // which is exactly the public counterpart of the secret this
                // layer opened with. Recomputing it here is what lets the
                // initiator check a transcript that binds the recipient key.
                let recipient_public = scalar_base(&secret.0)?;
                let mut transcript = offer_transcript(
                    suite_id,
                    gateway_id,
                    expires_at_ms,
                    &gateway_pseudonym,
                    &recipient_public,
                    &route_secret,
                    &commit_challenge,
                    &routing_nonce,
                    &signing_public,
                )?;
                let transcript_hash = sha256(&transcript)?;
                let verification = verify(&signing_public, &transcript, &signature);
                zeroize_slice(&mut transcript);
                verification?;
                return Ok(OpenedOffer {
                    gateway_id,
                    expires_at_ms,
                    gateway_pseudonym,
                    route_secret: SecretBytes(route_secret),
                    commit_challenge: SecretBytes(commit_challenge),
                    routing_nonce,
                    gateway_candidate_token,
                    layer_count: relay_layers + 1,
                    transcript_hash,
                });
            }
            P1Payload::RelayLayer {
                blinding_factor,
                child_candidate_token,
                forward_label: _,
                parent_routing_nonce,
                child_routing_nonce,
                child_blob,
            } => {
                relay_layers = relay_layers.saturating_add(1);
                if relay_layers > LIMIT_MAX_CANDIDATE_LAYERS {
                    return Err(P1Error::TooManyLayers);
                }
                if parent_routing_nonce != expected_nonce {
                    return Err(P1Error::InvalidOffer);
                }
                expected_nonce = child_routing_nonce;
                gateway_candidate_token = Some(child_candidate_token);
                secret = SecretBytes(blind_secret(&secret.0, &blinding_factor)?);
                blob = child_blob;
            }
            _ => return Err(P1Error::WrongPayload),
        }
    }
}

pub fn commit_proof(
    route_secret: &[u8; 32],
    challenge: &[u8; 32],
    pseudonym: &[u8; 16],
) -> Result<[u8; 32], P1Error> {
    Ok(keyed_proof(
        route_secret,
        DOMAIN_C1_COMMIT,
        &[challenge, pseudonym],
    )?)
}

pub fn ready_proof(
    route_secret: &[u8; 32],
    challenge: &[u8; 32],
    pseudonym: &[u8; 16],
) -> Result<[u8; 32], P1Error> {
    Ok(keyed_proof(
        route_secret,
        DOMAIN_C1_READY,
        &[challenge, pseudonym],
    )?)
}

pub fn verify_proof(expected: &[u8; 32], actual: &[u8; 32]) -> Result<(), P1Error> {
    if constant_time_equal(expected, actual) {
        Ok(())
    } else {
        Err(P1Error::InvalidOffer)
    }
}

pub fn control_aad(message_type: MessageType, generation: u32) -> Vec<u8> {
    let mut aad = b"Trahens-P1-control-v1".to_vec();
    aad.push(message_type as u8);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

pub fn seal_control(
    key: &[u8; 32],
    direction: RouteDirection,
    sequence: u64,
    message_type: MessageType,
    generation: u32,
    payload: &P1Payload,
) -> Result<Vec<u8>, P1Error> {
    let mut plaintext = encode_p1(payload)?;
    let result = route_seal(
        key,
        direction,
        sequence,
        &plaintext,
        &control_aad(message_type, generation),
    );
    zeroize_slice(&mut plaintext);
    Ok(result?)
}

/// Open a route record and return it with its authenticated sequence number.
pub fn open_control(
    key: &[u8; 32],
    expected_direction: RouteDirection,
    message_type: MessageType,
    generation: u32,
    protected: &[u8],
) -> Result<(u64, P1Payload), P1Error> {
    let (sequence, mut plaintext) = route_open(
        key,
        expected_direction,
        protected,
        &control_aad(message_type, generation),
    )?;
    let decoded = decode_p1(&plaintext);
    zeroize_slice(&mut plaintext);
    Ok((sequence, decoded?))
}

/// Per-direction acceptance window for one route channel.
///
/// End-to-end replay is not covered by the adjacent-link replay window: a relay
/// can re-send a recorded protected body inside a genuinely new T1 transmission
/// with a fresh W2 sequence, which W2 correctly regards as new link traffic.
/// The route channel therefore keeps its own bounded window, sized by the
/// registry, and commits to a sequence only after the record authenticates.
#[derive(Debug, Default)]
pub struct RouteReplayWindow {
    highest: Option<u64>,
    admitted: BTreeSet<u64>,
}

impl RouteReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept `sequence` unless it was already seen or has fallen out of the
    /// window. Call only on a record that has already authenticated.
    pub fn admit(&mut self, sequence: u64) -> Result<(), P1Error> {
        let width = LIMIT_ROUTE_REPLAY_WINDOW as u64;
        if self.admitted.contains(&sequence) {
            return Err(P1Error::RouteReplay);
        }
        if let Some(highest) = self.highest {
            if sequence.saturating_add(width) <= highest {
                return Err(P1Error::RouteReplay);
            }
        }
        self.admitted.insert(sequence);
        self.highest = Some(self.highest.map_or(sequence, |top| top.max(sequence)));
        if let Some(highest) = self.highest {
            let floor = highest.saturating_sub(width);
            self.admitted = self.admitted.split_off(&floor);
        }
        Ok(())
    }
}

/// Monotonic sequence source for one outgoing direction.
#[derive(Debug, Default)]
pub struct RouteSequencer {
    next: u64,
}

impl RouteSequencer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sequences start at zero and never repeat under one key. Exhaustion fails
    /// closed rather than wrapping into a reused nonce.
    pub fn next(&mut self) -> Result<u64, P1Error> {
        let value = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or(P1Error::RouteSequenceExhausted)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trahens_crypto::{
        blind_public, random_nonzero_16, random_scalar, route_keys, scalar_base, signing_keypair,
    };

    /// The defect this profile exists to fix: a relay that keeps a protected
    /// body and re-sends it later inside its own fresh transmission. Nothing at
    /// the link layer can reject that, because the carrying transmission really
    /// is new, so the route window has to.
    #[test]
    fn a_recorded_route_record_cannot_be_replayed() -> Result<(), Box<dyn std::error::Error>> {
        let keys = route_keys(&[7_u8; 32], &[9_u8; 32])?;
        let key = keys.direction(RouteDirection::EndpointToGateway);
        let payload = P1Payload::Close { reason: 0 };
        let sealed = seal_control(
            key,
            RouteDirection::EndpointToGateway,
            0,
            MessageType::Close,
            0,
            &payload,
        )?;

        let mut window = RouteReplayWindow::new();
        let (sequence, _) = open_control(
            key,
            RouteDirection::EndpointToGateway,
            MessageType::Close,
            0,
            &sealed,
        )?;
        window.admit(sequence)?;

        // The captured bytes still authenticate -- that is the point, the
        // attacker did not have to forge anything -- so only the window stops
        // the second delivery.
        let (replayed, _) = open_control(
            key,
            RouteDirection::EndpointToGateway,
            MessageType::Close,
            0,
            &sealed,
        )?;
        assert!(
            window.admit(replayed).is_err(),
            "a recorded route record must not be delivered twice"
        );
        Ok(())
    }

    #[test]
    fn a_record_cannot_be_reflected_back_along_the_route() -> Result<(), Box<dyn std::error::Error>>
    {
        let keys = route_keys(&[7_u8; 32], &[9_u8; 32])?;
        let sealed = seal_control(
            keys.direction(RouteDirection::EndpointToGateway),
            RouteDirection::EndpointToGateway,
            0,
            MessageType::Close,
            0,
            &P1Payload::Close { reason: 0 },
        )?;
        assert!(
            open_control(
                keys.direction(RouteDirection::GatewayToEndpoint),
                RouteDirection::GatewayToEndpoint,
                MessageType::Close,
                0,
                &sealed,
            )
            .is_err(),
            "a record sealed towards the gateway must not open as one from it"
        );
        Ok(())
    }

    #[test]
    fn route_keys_are_bound_to_the_offer_transcript() -> Result<(), Box<dyn std::error::Error>> {
        let secret = [7_u8; 32];
        let chosen = route_keys(&secret, &[9_u8; 32])?;
        let other = route_keys(&secret, &[10_u8; 32])?;
        let sealed = seal_control(
            chosen.direction(RouteDirection::EndpointToGateway),
            RouteDirection::EndpointToGateway,
            0,
            MessageType::Close,
            0,
            &P1Payload::Close { reason: 0 },
        )?;
        // Same route secret, different selected offer: the channel must not open.
        assert!(
            open_control(
                other.direction(RouteDirection::EndpointToGateway),
                RouteDirection::EndpointToGateway,
                MessageType::Close,
                0,
                &sealed,
            )
            .is_err(),
            "a route secret must be unusable under any other offer"
        );
        Ok(())
    }

    #[test]
    fn the_route_window_accepts_reordering_but_not_repeats(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut window = RouteReplayWindow::new();
        window.admit(4)?;
        window.admit(2)?;
        window.admit(3)?;
        assert!(window.admit(2).is_err(), "a repeat is refused");

        // Once the highest accepted sequence is a full window ahead, anything
        // at or below the floor has aged out and is refused whether or not it
        // was ever seen.
        let width = LIMIT_ROUTE_REPLAY_WINDOW as u64;
        window.admit(1_000)?;
        assert!(
            window.admit(1_000 - width).is_err(),
            "a sequence at the window floor is refused"
        );
        window.admit(1_000 - width + 1)?;
        Ok(())
    }

    #[test]
    fn two_relay_candidate_chain_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let root_secret = random_scalar()?;
        let root_public = scalar_base(&root_secret)?;
        let factor1 = random_scalar()?;
        let public1 = blind_public(&root_public, &factor1)?;
        let factor2 = random_scalar()?;
        let public2 = blind_public(&public1, &factor2)?;
        let seed = [7_u8; 32];
        let (signing_public, signing_secret) = signing_keypair(&seed)?;
        let nonce = [8_u8; 32];
        let child2 = random_nonzero_16()?;
        let child1 = random_nonzero_16()?;
        let nonce1 = [9_u8; 32];
        let nonce2 = [10_u8; 32];
        let forward2 = random_nonzero_16()?;
        let forward1 = random_nonzero_16()?;
        let (offer, _) = seal_gateway_offer(
            &public2,
            &protocol_registry::SUITE_R1,
            9,
            u64::MAX,
            [1; 16],
            [2; 32],
            [3; 32],
            nonce2,
            signing_public,
            &signing_secret,
        )?;
        let layer2 = wrap_candidate(
            &public1, 2, factor2, child2, forward2, nonce1, nonce2, offer,
        )?;
        let layer1 = wrap_candidate(
            &root_public,
            1,
            factor1,
            child1,
            forward1,
            nonce,
            nonce1,
            layer2,
        )?;
        let opened = open_candidate_chain(
            &root_secret,
            &protocol_registry::SUITE_R1,
            &layer1,
            3,
            &signing_public,
            &nonce,
            1,
        )?;
        assert_eq!(opened.gateway_id, 9);
        assert_eq!(opened.gateway_candidate_token, Some(child2));
        assert_eq!(opened.layer_count, 3);
        Ok(())
    }

    #[test]
    fn an_opened_offer_owns_its_secrets_and_cannot_be_copied(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A losing or expired candidate is dropped without ever being used.
        // Its route secret and commit challenge are key material, so they live
        // in SecretBytes and are wiped on drop. OpenedOffer is not Clone, so
        // there is only ever the one copy to wipe: were it Clone, the
        // initiator's held candidates would each leave a plain array behind.
        let root_secret = random_scalar()?;
        let root_public = scalar_base(&root_secret)?;
        let seed = [21_u8; 32];
        let (signing_public, signing_secret) = signing_keypair(&seed)?;
        let nonce = [22_u8; 32];
        let secret = [23_u8; 32];
        let challenge = [24_u8; 32];
        let (offer, _) = seal_gateway_offer(
            &root_public,
            &protocol_registry::SUITE_R1,
            5,
            u64::MAX,
            [25; 16],
            secret,
            challenge,
            nonce,
            signing_public,
            &signing_secret,
        )?;

        let opened = open_candidate_chain(
            &root_secret,
            &protocol_registry::SUITE_R1,
            &offer,
            1,
            &signing_public,
            &nonce,
            1,
        )?;
        assert_eq!(opened.route_secret.0, secret);
        assert_eq!(opened.commit_challenge.0, challenge);

        // Selection consumes the offer rather than copying out of it, so the
        // secrets have exactly one owner all the way to the active route.
        let moved = opened.route_secret;
        assert_eq!(moved.0, secret);
        Ok(())
    }

    #[test]
    fn direct_gateway_offer_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let root_secret = random_scalar()?;
        let root_public = scalar_base(&root_secret)?;
        let seed = [12_u8; 32];
        let (signing_public, signing_secret) = signing_keypair(&seed)?;
        let nonce = [13_u8; 32];
        let (offer, sealed_hash) = seal_gateway_offer(
            &root_public,
            &protocol_registry::SUITE_R1,
            7,
            u64::MAX,
            [1; 16],
            [2; 32],
            [3; 32],
            nonce,
            signing_public,
            &signing_secret,
        )?;
        let opened = open_candidate_chain(
            &root_secret,
            &protocol_registry::SUITE_R1,
            &offer,
            1,
            &signing_public,
            &nonce,
            1,
        )?;
        // Both ends must derive the same transcript hash, or the route key
        // schedule would silently diverge and every sealed record would fail.
        assert_eq!(opened.transcript_hash, sealed_hash);
        assert_eq!(opened.gateway_id, 7);
        assert_eq!(opened.gateway_candidate_token, None);
        assert_eq!(opened.layer_count, 1);
        Ok(())
    }
}
