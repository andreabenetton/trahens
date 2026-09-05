// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "B1.1 authenticated adjacent-link handshake (Noise XX / XXpsk0)."]

//! Implements `spec/link-handshake-b1.md`: Noise revision 34 pattern `XX`,
//! instantiated as `Noise_XX_25519_ChaChaPoly_SHA256`, with `psk0` for rekeys,
//! carried in fixed-width records and extended with a transcript-bound profile
//! negotiation, a manifest pin on the presented static key, and epoch/export
//! derivation from the finished exchange.
//!
//! Nothing here hardcodes a width, a domain or a record type. v1.8 is a draft
//! profile that generates no registry bindings, and a second copy of values the
//! registry owns is exactly the drift the generated-bindings rule exists to
//! prevent, so the caller supplies a [`Profile`]. When v1.8 becomes active this
//! is built from the generated constants instead of from JSON.
//!
//! `spec/b1-test-vectors.json` is normative for the encoding, and
//! `tests/cross_check_snow.rs` checks those vectors against an independent
//! Noise implementation.

use trahens_crypto::{
    aead_open, aead_seal, constant_time_equal, hmac_sha256, sha256, x25519, x25519_base,
    zeroize_slice, CryptoError, SecretBytes,
};

pub const HASH_BYTES: usize = 32;
pub const DH_BYTES: usize = 32;
pub const TAG_BYTES: usize = 16;

/// Every failure is one outcome. A peer is never told which check refused it,
/// so a prober learns nothing from the distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeError;

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("B1 handshake failed")
    }
}

impl std::error::Error for HandshakeError {}

impl From<CryptoError> for HandshakeError {
    fn from(_value: CryptoError) -> Self {
        Self
    }
}

type Result<T> = std::result::Result<T, HandshakeError>;

/// Which stage of the exchange a record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Initiate,
    Respond,
    Finish,
}

/// The registry values the handshake needs.
#[derive(Debug, Clone)]
pub struct Profile {
    pub protocol_version: u8,
    pub noise_protocol: Vec<u8>,
    pub noise_protocol_rekey: Vec<u8>,
    pub prologue_domain: Vec<u8>,
    pub rekey_chain_domain: Vec<u8>,
    pub epoch_domain: Vec<u8>,
    pub export_domain: Vec<u8>,
    pub record_bytes: usize,
    pub record_prefix_bytes: usize,
    pub initiate_payload_bytes: usize,
    pub initiate_payload_psk_bytes: usize,
    pub respond_payload_bytes: usize,
    pub finish_payload_bytes: usize,
    /// Initiate, respond, finish for an initial handshake.
    pub handshake_record_types: [u8; 3],
    /// The same three for a rekey.
    pub rekey_record_types: [u8; 3],
    pub max_offered_per_class: usize,
    /// Suites that may never be offered: retired, disabled, or the symbolic
    /// control.
    pub rejected_suites: Vec<[u8; 2]>,
}

impl Profile {
    fn record_type(&self, rekey: bool, stage: Stage) -> u8 {
        let table = if rekey {
            &self.rekey_record_types
        } else {
            &self.handshake_record_types
        };
        match stage {
            Stage::Initiate => table[0],
            Stage::Respond => table[1],
            Stage::Finish => table[2],
        }
    }

    fn payload_bytes(&self, rekey: bool, stage: Stage) -> usize {
        match stage {
            Stage::Initiate if rekey => self.initiate_payload_psk_bytes,
            Stage::Initiate => self.initiate_payload_bytes,
            Stage::Respond => self.respond_payload_bytes,
            Stage::Finish => self.finish_payload_bytes,
        }
    }
}

// --------------------------------------------------------------------------
// Noise primitives, exactly as the specification writes them.
// --------------------------------------------------------------------------

/// HKDF from Noise section 4.3. `N` is 2 or 3 outputs.
fn noise_hkdf<const N: usize>(chaining_key: &[u8; 32], material: &[u8]) -> Result<[[u8; 32]; N]> {
    let temp = hmac_sha256(chaining_key, material)?;
    let mut outputs = [[0_u8; 32]; N];
    let mut previous = Vec::with_capacity(33);
    for (index, slot) in outputs.iter_mut().enumerate() {
        let counter = u8::try_from(index + 1).map_err(|_| HandshakeError)?;
        previous.push(counter);
        *slot = hmac_sha256(&temp, &previous)?;
        previous.clear();
        previous.extend_from_slice(slot);
    }
    Ok(outputs)
}

/// Noise's ChaChaPoly nonce: 32 zero bits then the counter, little-endian.
fn noise_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[derive(Debug, Default)]
struct CipherState {
    key: Option<[u8; 32]>,
    counter: u64,
}

impl CipherState {
    fn initialize_key(&mut self, key: [u8; 32]) {
        self.key = Some(key);
        self.counter = 0;
    }

    fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let Some(key) = self.key else {
            return Ok(plaintext.to_vec());
        };
        let nonce = noise_nonce(self.counter);
        let output = aead_seal(&key, &nonce, plaintext, ad)?;
        self.counter = self.counter.checked_add(1).ok_or(HandshakeError)?;
        Ok(output)
    }

    fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let Some(key) = self.key else {
            return Ok(ciphertext.to_vec());
        };
        let nonce = noise_nonce(self.counter);
        let output = aead_open(&key, &nonce, ciphertext, ad)?;
        self.counter = self.counter.checked_add(1).ok_or(HandshakeError)?;
        Ok(output)
    }
}

#[derive(Debug)]
struct SymmetricState {
    cipher: CipherState,
    chaining_key: [u8; 32],
    handshake_hash: [u8; 32],
}

impl SymmetricState {
    fn initialize(protocol_name: &[u8]) -> Result<Self> {
        let mut h = [0_u8; 32];
        if protocol_name.len() <= HASH_BYTES {
            h[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            h = sha256(protocol_name)?;
        }
        Ok(Self {
            cipher: CipherState::default(),
            chaining_key: h,
            handshake_hash: h,
        })
    }

    fn mix_key(&mut self, material: &[u8]) -> Result<()> {
        let [ck, temp_k] = noise_hkdf::<2>(&self.chaining_key, material)?;
        self.chaining_key = ck;
        self.cipher.initialize_key(temp_k);
        Ok(())
    }

    fn mix_hash(&mut self, data: &[u8]) -> Result<()> {
        let mut input = Vec::with_capacity(self.handshake_hash.len() + data.len());
        input.extend_from_slice(&self.handshake_hash);
        input.extend_from_slice(data);
        self.handshake_hash = sha256(&input)?;
        Ok(())
    }

    /// Noise section 5.2, used by `psk0`. Unlike a prologue this reaches the
    /// chaining key, so the chained material actually influences `split`.
    fn mix_key_and_hash(&mut self, material: &[u8]) -> Result<()> {
        let [ck, temp_h, temp_k] = noise_hkdf::<3>(&self.chaining_key, material)?;
        self.chaining_key = ck;
        self.mix_hash(&temp_h)?;
        self.cipher.initialize_key(temp_k);
        Ok(())
    }

    /// An `e` token. Noise section 9 requires a PSK handshake to mix the public
    /// ephemeral into the key as well as the hash: under `psk0` a key exists
    /// before any Diffie-Hellman, so without this the ephemeral would
    /// contribute nothing to the first message's key.
    fn mix_ephemeral(&mut self, public: &[u8; 32], psk_mode: bool) -> Result<()> {
        self.mix_hash(public)?;
        if psk_mode {
            self.mix_key(public)?;
        }
        Ok(())
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let hash = self.handshake_hash;
        let ciphertext = self.cipher.encrypt_with_ad(&hash, plaintext)?;
        self.mix_hash(&ciphertext)?;
        Ok(ciphertext)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let hash = self.handshake_hash;
        let plaintext = self.cipher.decrypt_with_ad(&hash, ciphertext)?;
        self.mix_hash(ciphertext)?;
        Ok(plaintext)
    }

    fn split(&self) -> Result<([u8; 32], [u8; 32])> {
        let [k1, k2] = noise_hkdf::<2>(&self.chaining_key, &[])?;
        Ok((k1, k2))
    }
}

// --------------------------------------------------------------------------
// Negotiation.
// --------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub version: u8,
    pub w2_profiles: Vec<u8>,
    pub t1_profiles: Vec<u8>,
    pub t2_profiles: Vec<u8>,
    pub suites: Vec<[u8; 2]>,
    pub resource_class: u8,
}

impl Offer {
    fn encode(&self, profile: &Profile) -> Result<Vec<u8>> {
        let classes = [&self.w2_profiles, &self.t1_profiles, &self.t2_profiles];
        for group in classes {
            if group.is_empty() || group.len() > profile.max_offered_per_class {
                return Err(HandshakeError);
            }
        }
        if self.suites.is_empty() || self.suites.len() > profile.max_offered_per_class {
            return Err(HandshakeError);
        }
        if self
            .suites
            .iter()
            .any(|suite| profile.rejected_suites.contains(suite))
        {
            return Err(HandshakeError);
        }
        let mut out = vec![self.version];
        for group in classes {
            out.push(u8::try_from(group.len()).map_err(|_| HandshakeError)?);
            out.extend_from_slice(group);
        }
        out.push(u8::try_from(self.suites.len()).map_err(|_| HandshakeError)?);
        for suite in &self.suites {
            out.extend_from_slice(suite);
        }
        out.push(self.resource_class);
        Ok(out)
    }

    fn decode(profile: &Profile, data: &[u8]) -> Result<Self> {
        let mut cursor = 0_usize;
        let mut take = |count: usize| -> Result<&[u8]> {
            let end = cursor.checked_add(count).ok_or(HandshakeError)?;
            let piece = data.get(cursor..end).ok_or(HandshakeError)?;
            cursor = end;
            Ok(piece)
        };
        let version = *take(1)?.first().ok_or(HandshakeError)?;
        if version != profile.protocol_version {
            return Err(HandshakeError);
        }
        let mut classes: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for group in &mut classes {
            let count = usize::from(*take(1)?.first().ok_or(HandshakeError)?);
            if count == 0 || count > profile.max_offered_per_class {
                return Err(HandshakeError);
            }
            group.extend_from_slice(take(count)?);
        }
        let suite_count = usize::from(*take(1)?.first().ok_or(HandshakeError)?);
        if suite_count == 0 || suite_count > profile.max_offered_per_class {
            return Err(HandshakeError);
        }
        let mut suites = Vec::with_capacity(suite_count);
        for _ in 0..suite_count {
            let bytes = take(2)?;
            let suite = [
                *bytes.first().ok_or(HandshakeError)?,
                *bytes.get(1).ok_or(HandshakeError)?,
            ];
            if profile.rejected_suites.contains(&suite) {
                return Err(HandshakeError);
            }
            suites.push(suite);
        }
        let resource_class = *take(1)?.first().ok_or(HandshakeError)?;
        if cursor != data.len() {
            return Err(HandshakeError);
        }
        let [w2_profiles, t1_profiles, t2_profiles] = classes;
        Ok(Self {
            version,
            w2_profiles,
            t1_profiles,
            t2_profiles,
            suites,
            resource_class,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    pub version: u8,
    pub w2_profile: u8,
    pub t1_profile: u8,
    pub t2_profile: u8,
    pub suite: [u8; 2],
    pub resource_class: u8,
}

impl Selection {
    fn encode(self) -> Vec<u8> {
        vec![
            self.version,
            self.w2_profile,
            self.t1_profile,
            self.t2_profile,
            self.suite[0],
            self.suite[1],
            self.resource_class,
        ]
    }

    fn decode(data: &[u8]) -> Result<Self> {
        let field = |index: usize| -> Result<u8> { data.get(index).copied().ok_or(HandshakeError) };
        if data.len() != 7 {
            return Err(HandshakeError);
        }
        Ok(Self {
            version: field(0)?,
            w2_profile: field(1)?,
            t1_profile: field(2)?,
            t2_profile: field(3)?,
            suite: [field(4)?, field(5)?],
            resource_class: field(6)?,
        })
    }

    fn within(self, offer: &Offer) -> bool {
        self.version == offer.version
            && offer.w2_profiles.contains(&self.w2_profile)
            && offer.t1_profiles.contains(&self.t1_profile)
            && offer.t2_profiles.contains(&self.t2_profile)
            && offer.suites.contains(&self.suite)
            && self.resource_class == offer.resource_class
    }
}

// --------------------------------------------------------------------------
// Payload framing.
// --------------------------------------------------------------------------

fn frame(body: &[u8], width: usize) -> Result<Vec<u8>> {
    let length = u16::try_from(body.len()).map_err(|_| HandshakeError)?;
    if body.len().checked_add(2).ok_or(HandshakeError)? > width {
        return Err(HandshakeError);
    }
    let mut out = Vec::with_capacity(width);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
    out.resize(width, 0);
    Ok(out)
}

fn unframe(framed: &[u8], width: usize) -> Result<Vec<u8>> {
    if framed.len() != width {
        return Err(HandshakeError);
    }
    let length = usize::from(u16::from_be_bytes([
        *framed.first().ok_or(HandshakeError)?,
        *framed.get(1).ok_or(HandshakeError)?,
    ]));
    let end = length.checked_add(2).ok_or(HandshakeError)?;
    let body = framed.get(2..end).ok_or(HandshakeError)?;
    // Padding is inside the region Noise authenticates, so a receiver that
    // ignored it would accept a record whose bytes differ from the sender's.
    if framed
        .get(end..)
        .is_some_and(|tail| tail.iter().any(|b| *b != 0))
    {
        return Err(HandshakeError);
    }
    Ok(body.to_vec())
}

// --------------------------------------------------------------------------
// Session output.
// --------------------------------------------------------------------------

/// What a completed handshake yields.
pub struct Session {
    pub handshake_hash: [u8; 32],
    /// Initiator's send key, responder's receive key.
    pub initiator_to_responder: SecretBytes<32>,
    /// Responder's send key, initiator's receive key.
    pub responder_to_initiator: SecretBytes<32>,
    /// The W2 epoch, with the top bit set so no derived epoch begins with a
    /// zero byte and a handshake record stays distinguishable from a cell.
    pub epoch: u32,
    /// Chains the next rekey.
    pub export_key: SecretBytes<32>,
    pub peer_static: [u8; 32],
    pub selection: Selection,
}

fn finish(
    profile: &Profile,
    state: &SymmetricState,
    peer_static: [u8; 32],
    selection: Selection,
) -> Result<Session> {
    let (k1, k2) = state.split()?;
    let hash = state.handshake_hash;

    let mut export_info = profile.export_domain.clone();
    export_info.extend_from_slice(&hash);
    let [export_key] = noise_hkdf::<1>(&state.chaining_key, &export_info)?;

    let mut epoch_info = profile.epoch_domain.clone();
    epoch_info.extend_from_slice(&hash);
    let [epoch_bytes] = noise_hkdf::<1>(&state.chaining_key, &epoch_info)?;
    let epoch = u32::from_be_bytes([
        epoch_bytes.first().copied().ok_or(HandshakeError)? | 0x80,
        epoch_bytes.get(1).copied().ok_or(HandshakeError)?,
        epoch_bytes.get(2).copied().ok_or(HandshakeError)?,
        epoch_bytes.get(3).copied().ok_or(HandshakeError)?,
    ]);

    Ok(Session {
        handshake_hash: hash,
        initiator_to_responder: SecretBytes(k1),
        responder_to_initiator: SecretBytes(k2),
        epoch,
        export_key: SecretBytes(export_key),
        peer_static,
        selection,
    })
}

fn begin(profile: &Profile, previous_export: Option<&[u8; 32]>) -> Result<SymmetricState> {
    let (name, prologue) = match previous_export {
        Some(_) => (&profile.noise_protocol_rekey, &profile.rekey_chain_domain),
        None => (&profile.noise_protocol, &profile.prologue_domain),
    };
    let mut state = SymmetricState::initialize(name)?;
    state.mix_hash(prologue)?;
    if let Some(export) = previous_export {
        state.mix_key_and_hash(export)?;
    }
    Ok(state)
}

fn prefix(profile: &Profile, rekey: bool, stage: Stage) -> Vec<u8> {
    // The leading zero is what lets a receiver tell a handshake record from a
    // W2 cell without trial decryption: derived epochs have their top bit set.
    let mut out = vec![0_u8; profile.record_prefix_bytes];
    if let Some(slot) = out.last_mut() {
        *slot = profile.record_type(rekey, stage);
    }
    out
}

fn split_record<'a>(
    profile: &Profile,
    record: &'a [u8],
    rekey: bool,
    stage: Stage,
) -> Result<&'a [u8]> {
    if record.len() != profile.record_bytes {
        return Err(HandshakeError);
    }
    let expected = prefix(profile, rekey, stage);
    if record.get(..expected.len()) != Some(expected.as_slice()) {
        return Err(HandshakeError);
    }
    record.get(expected.len()..).ok_or(HandshakeError)
}

fn take_static(body: &[u8], cursor: &mut usize) -> Result<Vec<u8>> {
    let end = cursor
        .checked_add(DH_BYTES + TAG_BYTES)
        .ok_or(HandshakeError)?;
    let piece = body.get(*cursor..end).ok_or(HandshakeError)?;
    *cursor = end;
    Ok(piece.to_vec())
}

fn as_key(value: &[u8]) -> Result<[u8; 32]> {
    value.try_into().map_err(|_| HandshakeError)
}

// --------------------------------------------------------------------------
// Initiator.
// --------------------------------------------------------------------------

pub struct Initiator {
    profile: Profile,
    static_secret: SecretBytes<32>,
    static_public: [u8; 32],
    ephemeral_secret: SecretBytes<32>,
    ephemeral_public: [u8; 32],
    expected_peer_static: [u8; 32],
    offer: Offer,
    rekey: bool,
    state: SymmetricState,
    remote_ephemeral: Option<[u8; 32]>,
    selection: Option<Selection>,
}

impl Initiator {
    pub fn new(
        profile: Profile,
        static_secret: [u8; 32],
        ephemeral_secret: [u8; 32],
        expected_peer_static: [u8; 32],
        offer: Offer,
        previous_export: Option<&[u8; 32]>,
    ) -> Result<Self> {
        let state = begin(&profile, previous_export)?;
        Ok(Self {
            static_public: x25519_base(&static_secret)?,
            ephemeral_public: x25519_base(&ephemeral_secret)?,
            static_secret: SecretBytes(static_secret),
            ephemeral_secret: SecretBytes(ephemeral_secret),
            expected_peer_static,
            offer,
            rekey: previous_export.is_some(),
            state,
            remote_ephemeral: None,
            selection: None,
            profile,
        })
    }

    /// `-> e`
    pub fn write_initiate(&mut self) -> Result<Vec<u8>> {
        self.state
            .mix_ephemeral(&self.ephemeral_public, self.rekey)?;
        let width = self.profile.payload_bytes(self.rekey, Stage::Initiate);
        let mut payload = frame(&self.offer.encode(&self.profile)?, width)?;
        let sealed = self.state.encrypt_and_hash(&payload);
        zeroize_slice(&mut payload);

        let mut record = prefix(&self.profile, self.rekey, Stage::Initiate);
        record.extend_from_slice(&self.ephemeral_public);
        record.extend_from_slice(&sealed?);
        if record.len() != self.profile.record_bytes {
            return Err(HandshakeError);
        }
        Ok(record)
    }

    /// `<- e, ee, s, es`
    pub fn read_respond(&mut self, record: &[u8]) -> Result<()> {
        let body = split_record(&self.profile, record, self.rekey, Stage::Respond)?;
        let mut cursor = 0_usize;
        let remote_ephemeral = as_key(body.get(..DH_BYTES).ok_or(HandshakeError)?)?;
        cursor += DH_BYTES;
        self.state.mix_ephemeral(&remote_ephemeral, self.rekey)?;
        self.state
            .mix_key(&x25519(&self.ephemeral_secret.0, &remote_ephemeral)?)?;

        let sealed_static = take_static(body, &mut cursor)?;
        let remote_static = as_key(&self.state.decrypt_and_hash(&sealed_static)?)?;
        self.state
            .mix_key(&x25519(&self.ephemeral_secret.0, &remote_static)?)?;

        let framed = self
            .state
            .decrypt_and_hash(body.get(cursor..).ok_or(HandshakeError)?)?;
        let width = self.profile.payload_bytes(self.rekey, Stage::Respond);
        let selection = Selection::decode(&unframe(&framed, width)?)?;

        // The key authenticated; the question is whether it is the one the
        // manifest names for this peer. Checked before any key is derived.
        if !constant_time_equal(&remote_static, &self.expected_peer_static) {
            return Err(HandshakeError);
        }
        if !selection.within(&self.offer) {
            return Err(HandshakeError);
        }
        self.remote_ephemeral = Some(remote_ephemeral);
        self.selection = Some(selection);
        Ok(())
    }

    /// `-> s, se`
    pub fn write_finish(&mut self) -> Result<(Vec<u8>, Session)> {
        let remote_ephemeral = self.remote_ephemeral.ok_or(HandshakeError)?;
        let selection = self.selection.ok_or(HandshakeError)?;

        let sealed_static = self.state.encrypt_and_hash(&self.static_public)?;
        self.state
            .mix_key(&x25519(&self.static_secret.0, &remote_ephemeral)?)?;
        let width = self.profile.payload_bytes(self.rekey, Stage::Finish);
        let sealed_payload = self.state.encrypt_and_hash(&frame(&[], width)?)?;

        let mut record = prefix(&self.profile, self.rekey, Stage::Finish);
        record.extend_from_slice(&sealed_static);
        record.extend_from_slice(&sealed_payload);
        if record.len() != self.profile.record_bytes {
            return Err(HandshakeError);
        }
        let session = finish(
            &self.profile,
            &self.state,
            self.expected_peer_static,
            selection,
        )?;
        Ok((record, session))
    }
}

// --------------------------------------------------------------------------
// Responder.
// --------------------------------------------------------------------------

pub struct Responder {
    profile: Profile,
    static_secret: SecretBytes<32>,
    static_public: [u8; 32],
    ephemeral_secret: SecretBytes<32>,
    ephemeral_public: [u8; 32],
    expected_peer_static: [u8; 32],
    rekey: bool,
    state: SymmetricState,
    remote_ephemeral: Option<[u8; 32]>,
    offer: Option<Offer>,
    selection: Option<Selection>,
}

impl Responder {
    pub fn new(
        profile: Profile,
        static_secret: [u8; 32],
        ephemeral_secret: [u8; 32],
        expected_peer_static: [u8; 32],
        previous_export: Option<&[u8; 32]>,
    ) -> Result<Self> {
        let state = begin(&profile, previous_export)?;
        Ok(Self {
            static_public: x25519_base(&static_secret)?,
            ephemeral_public: x25519_base(&ephemeral_secret)?,
            static_secret: SecretBytes(static_secret),
            ephemeral_secret: SecretBytes(ephemeral_secret),
            expected_peer_static,
            rekey: previous_export.is_some(),
            state,
            remote_ephemeral: None,
            offer: None,
            selection: None,
            profile,
        })
    }

    pub fn read_initiate(&mut self, record: &[u8]) -> Result<Offer> {
        let body = split_record(&self.profile, record, self.rekey, Stage::Initiate)?;
        let remote_ephemeral = as_key(body.get(..DH_BYTES).ok_or(HandshakeError)?)?;
        self.state.mix_ephemeral(&remote_ephemeral, self.rekey)?;
        let framed = self
            .state
            .decrypt_and_hash(body.get(DH_BYTES..).ok_or(HandshakeError)?)?;
        let width = self.profile.payload_bytes(self.rekey, Stage::Initiate);
        let offer = Offer::decode(&self.profile, &unframe(&framed, width)?)?;
        self.remote_ephemeral = Some(remote_ephemeral);
        self.offer = Some(offer.clone());
        Ok(offer)
    }

    pub fn write_respond(&mut self, selection: Selection) -> Result<Vec<u8>> {
        let remote_ephemeral = self.remote_ephemeral.ok_or(HandshakeError)?;
        let offer = self.offer.as_ref().ok_or(HandshakeError)?;
        if !selection.within(offer) {
            return Err(HandshakeError);
        }
        self.state
            .mix_ephemeral(&self.ephemeral_public, self.rekey)?;
        self.state
            .mix_key(&x25519(&self.ephemeral_secret.0, &remote_ephemeral)?)?;
        let sealed_static = self.state.encrypt_and_hash(&self.static_public)?;
        self.state
            .mix_key(&x25519(&self.static_secret.0, &remote_ephemeral)?)?;
        let width = self.profile.payload_bytes(self.rekey, Stage::Respond);
        let sealed_payload = self
            .state
            .encrypt_and_hash(&frame(&selection.encode(), width)?)?;

        let mut record = prefix(&self.profile, self.rekey, Stage::Respond);
        record.extend_from_slice(&self.ephemeral_public);
        record.extend_from_slice(&sealed_static);
        record.extend_from_slice(&sealed_payload);
        if record.len() != self.profile.record_bytes {
            return Err(HandshakeError);
        }
        self.selection = Some(selection);
        Ok(record)
    }

    pub fn read_finish(&mut self, record: &[u8]) -> Result<Session> {
        let selection = self.selection.ok_or(HandshakeError)?;
        let body = split_record(&self.profile, record, self.rekey, Stage::Finish)?;
        let mut cursor = 0_usize;

        let sealed_static = take_static(body, &mut cursor)?;
        let remote_static = as_key(&self.state.decrypt_and_hash(&sealed_static)?)?;
        self.state
            .mix_key(&x25519(&self.ephemeral_secret.0, &remote_static)?)?;

        let framed = self
            .state
            .decrypt_and_hash(body.get(cursor..).ok_or(HandshakeError)?)?;
        let width = self.profile.payload_bytes(self.rekey, Stage::Finish);
        if !unframe(&framed, width)?.is_empty() {
            return Err(HandshakeError);
        }
        if !constant_time_equal(&remote_static, &self.expected_peer_static) {
            return Err(HandshakeError);
        }
        finish(&self.profile, &self.state, remote_static, selection)
    }
}
