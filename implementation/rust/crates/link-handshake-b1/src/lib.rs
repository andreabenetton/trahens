// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "B1.1 authenticated adjacent-link handshake (Noise XXpsk0)."]

//! Implements `spec/link-handshake-b1.md`: Noise revision 34 pattern `XX` under
//! the `psk0` modifier, instantiated as
//! `Noise_XXpsk0_25519_ChaChaPoly_SHA256`, carried in fixed-width records and
//! extended with a transcript-bound profile negotiation, a manifest pin on the
//! presented static key, and epoch/export derivation from the finished
//! exchange.
//!
//! Both exchanges are `psk0` and differ only in where the pre-shared key comes
//! from: a rekey chains to the session it replaces through its export key, and
//! an initial handshake uses the static-static Diffie-Hellman that both peers
//! can compute offline from the manifest. That is what authenticates the first
//! message, which plain `XX` leaves open to anyone able to reach the port.
//!
//! Nothing here hardcodes a width, a domain or a record type: a second copy of
//! values the registry owns is exactly the drift the generated-bindings rule
//! exists to prevent, so the caller supplies a [`Profile`]. `node_runtime`
//! builds one from the generated constants.
//!
//! `spec/b1-test-vectors.json` is normative for the encoding, and
//! `tests/cross_check_snow.rs` checks those vectors against an independent
//! Noise implementation.

use trahens_crypto::{
    aead_open, aead_seal, constant_time_equal, hkdf, hmac_sha256, sha256, sign, signing_keypair,
    verify, x25519, x25519_base, zeroize_slice, CryptoError, SecretBytes,
};

/// An Ed25519 signature, and the selection that precedes it in an admission
/// exchange's second message.
pub const SIGNATURE_BYTES: usize = 64;
const SELECTION_BYTES: usize = 7;

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

/// Which of the three exchanges a record belongs to.
///
/// A second boolean beside `rekey` would have admitted a state that means
/// nothing -- a rekey that is also an admission -- so the two are one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Manifest,
    Rekey,
    Admission,
}

/// The registry values the handshake needs.
#[derive(Debug, Clone)]
pub struct Profile {
    pub protocol_version: u8,
    pub noise_protocol: Vec<u8>,
    pub prologue_domain: Vec<u8>,
    pub rekey_chain_domain: Vec<u8>,
    pub rekey_psk_domain: Vec<u8>,
    pub static_psk_domain: Vec<u8>,
    pub epoch_domain: Vec<u8>,
    pub export_domain: Vec<u8>,
    pub record_bytes: usize,
    pub record_prefix_bytes: usize,
    pub initiate_payload_psk_bytes: usize,
    pub respond_payload_bytes: usize,
    pub finish_payload_bytes: usize,
    /// The cleartext header an admission initiate carries, and the narrower
    /// payload it frames because of it (ADR 0048 D14).
    pub admission_header_bytes: usize,
    pub admission_payload_bytes: usize,
    pub invitation_id_bytes: usize,
    pub cookie_bytes: usize,
    pub transition_domain: Vec<u8>,
    pub admission_initiate_type: u8,
    pub cookie_challenge_type: u8,
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
    fn record_type(&self, mode: Mode, stage: Stage) -> u8 {
        // Only the first message of an admission exchange differs. Its second
        // and third are ordinary handshake records, because by then the peers
        // are inside a transcript and nothing distinguishes the paths.
        if mode == Mode::Admission && stage == Stage::Initiate {
            return self.admission_initiate_type;
        }
        let table = if mode == Mode::Rekey {
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

    fn payload_bytes(&self, mode: Mode, stage: Stage) -> usize {
        match stage {
            // Both exchanges are psk0, so both encrypt this payload and both
            // carry its tag; the record is one cell either way. An admission
            // initiate frames a narrower one, having spent bytes on its header.
            Stage::Initiate if mode == Mode::Admission => self.admission_payload_bytes,
            Stage::Initiate => self.initiate_payload_psk_bytes,
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

#[derive(Debug, Default, Clone)]
struct CipherState {
    key: Option<[u8; 32]>,
    counter: u64,
}

impl Drop for CipherState {
    fn drop(&mut self) {
        if let Some(key) = self.key.as_mut() {
            zeroize_slice(key);
        }
    }
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

/// Cloneable so a reader can validate a record against a scratch copy and
/// commit only once the whole record has proved good; see `read_initiate`.
/// Both copies wipe their key material on drop, so the scratch leaves nothing
/// behind when a record is discarded.
#[derive(Clone)]
struct SymmetricState {
    cipher: CipherState,
    chaining_key: [u8; 32],
    handshake_hash: [u8; 32],
}

impl Drop for SymmetricState {
    fn drop(&mut self) {
        zeroize_slice(&mut self.chaining_key);
    }
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
    /// contribute nothing to the first message's key. Both B1.1 exchanges are
    /// `psk0`, so this always applies.
    fn mix_ephemeral(&mut self, public: &[u8; 32]) -> Result<()> {
        self.mix_hash(public)?;
        self.mix_key(public)
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

/// Where a handshake's `psk0` key comes from, and what it implies about the
/// peer's static key.
///
/// One value rather than several optional parameters, so the combinations that
/// do not mean anything cannot be written: a rekey carrying an admission key,
/// or a responder with neither a manifest entry nor an admission key, which
/// would authenticate the peer by nothing at all.
pub enum Keying<'a> {
    /// The manifest path of ADR 0044. The key is the static-static value and
    /// the presented static key is pinned against `peer_static`.
    Manifest { peer_static: [u8; 32] },
    /// A rekey, chained through the previous session's export key.
    Rekey {
        previous_export: &'a [u8; 32],
        peer_static: [u8; 32],
    },
    /// B1.2 admission. The key comes from whatever admitted the peer, and
    /// `peer_static` is `None` for a responder with no manifest entry, which
    /// records the presented key instead of checking it. An initiator always
    /// supplies one.
    Admission {
        psk: &'a [u8; 32],
        peer_static: Option<[u8; 32]>,
        /// The invitation this exchange is keyed by, in the clear on the first
        /// record so a responder can find the key without trial-decrypting
        /// against every live invitation (ADR 0046 D8).
        invitation_id: &'a [u8],
        /// The cookie echoed back to the responder. All zero on a first
        /// attempt, which is not a special case: it fails to verify, and
        /// failing is what provokes a challenge (ADR 0048 D13).
        cookie: &'a [u8],
        /// The advertisement signing seed, for a responder. ADR 0049 D16 makes
        /// the transition unconditional on this path, so a [`Responder`] built
        /// without one is refused; an [`Initiator`] passes `None`, having
        /// nothing to sign and only a signature to check.
        advertisement_secret: Option<&'a [u8; 32]>,
    },
}

impl Keying<'_> {
    fn peer_static(&self) -> Option<[u8; 32]> {
        match self {
            Self::Manifest { peer_static } | Self::Rekey { peer_static, .. } => Some(*peer_static),
            Self::Admission { peer_static, .. } => *peer_static,
        }
    }

    fn mode(&self) -> Mode {
        match self {
            Self::Manifest { .. } => Mode::Manifest,
            Self::Rekey { .. } => Mode::Rekey,
            Self::Admission { .. } => Mode::Admission,
        }
    }

    /// The cleartext header this keying puts on the first record, if any.
    fn header(&self, profile: &Profile) -> Result<Vec<u8>> {
        match self {
            Self::Admission {
                invitation_id,
                cookie,
                ..
            } => admission_header(profile, invitation_id, cookie),
            _ => Ok(Vec::new()),
        }
    }

    fn is_rekey(&self) -> bool {
        matches!(self, Self::Rekey { .. })
    }

    fn is_admission(&self) -> bool {
        matches!(self, Self::Admission { .. })
    }

    fn psk(&self, profile: &Profile, static_secret: &[u8; 32], role: Role) -> Result<[u8; 32]> {
        match self {
            Self::Manifest { peer_static } => static_psk(profile, static_secret, peer_static, role),
            Self::Rekey {
                previous_export, ..
            } => rekey_psk(profile, previous_export),
            Self::Admission { psk, .. } => Ok(**psk),
        }
    }
}

/// The pre-shared key for a rekey, from the export key of the session it
/// replaces.
///
/// The export key is a session output: the value the handshake hands to whoever
/// holds the session, for whatever the next thing is. Feeding it straight in as
/// the next exchange's `psk0` made it also a handshake input, and one value
/// serving two constructions is the pattern that lets a later use of the export
/// key interact with the rekey chain. One HKDF step under its own domain keeps
/// the two apart: the export key remains the thing a session produces, and
/// this is the thing a rekey consumes.
///
/// Same shape as [`static_psk`]: the export key is the input keying material,
/// the domain hashed is the salt, the domain is the info. Nothing else goes in
/// the info because there is nothing else to bind — the export key already
/// carries the whole previous transcript.
fn rekey_psk(profile: &Profile, previous_export: &[u8; 32]) -> Result<[u8; 32]> {
    let salt = sha256(&profile.rekey_psk_domain)?;
    let mut derived = hkdf(&salt, previous_export, &profile.rekey_psk_domain, 32)?;
    let mut psk = [0_u8; 32];
    psk.copy_from_slice(&derived);
    zeroize_slice(&mut derived);
    Ok(psk)
}

/// Which end of the exchange the local static key belongs to.
///
/// The static-static Diffie-Hellman is symmetric, so a derivation over it alone
/// gives both peers the same value however the keys are arranged. Naming the
/// roles is what lets the two public keys enter the derivation in an order both
/// peers agree on without sorting them.
#[derive(Clone, Copy)]
enum Role {
    Initiator,
    Responder,
}

/// The pre-shared key for an initial handshake, from the static-static
/// Diffie-Hellman.
///
/// Both peers compute it offline from the manifest they already hold, so
/// nothing carries it on the wire. It gates the first message: under plain `XX`
/// that message was unencrypted, so anyone who could reach the port could
/// produce one and the responder answered with its own static key. Under `psk0`
/// a forgery fails at the first decryption and draws no reply.
///
/// A gate, not authentication of the sender, and `spec/link-handshake-b1.md`
/// section 4.2 says how far it falls short: the message carries no responder
/// freshness, so a recorded one replays onto a later attempt; and a responder
/// computes this value and its own public keys when it builds its state, before
/// it reads any record. The presented static key is still checked against the
/// manifest and the ephemeral Diffie-Hellman still supplies forward secrecy, so
/// this value alone completes nothing.
///
/// RFC 5869 HKDF, with each input where RFC 5869 puts it: the shared secret is
/// the input keying material, the domain is the salt, and the context — the
/// domain again, then both public keys in role order — is the info. The previous
/// form was `HMAC(ss, domain)`, which is a defensible KDF but put the domain in
/// the message field and bound no public keys at all, so the same value came out
/// for every pair sharing a secret and nothing in it said which two keys it
/// belonged to. An external review raised both; the domain carries `-v2` because
/// the value on the wire changes.
///
/// The keys go in as `initiator || responder` rather than sorted, because the
/// exchange already has an asymmetry to name and sorting hides it: two peers
/// that swap roles derive different values, which is what a transcript binding
/// should do.
fn static_psk(
    profile: &Profile,
    static_secret: &[u8; 32],
    peer_static: &[u8; 32],
    role: Role,
) -> Result<[u8; 32]> {
    let local_static = x25519_base(static_secret)?;
    let (initiator, responder) = match role {
        Role::Initiator => (local_static, *peer_static),
        Role::Responder => (*peer_static, local_static),
    };
    let mut info = Vec::with_capacity(profile.static_psk_domain.len() + 64);
    info.extend_from_slice(&profile.static_psk_domain);
    info.extend_from_slice(&initiator);
    info.extend_from_slice(&responder);
    let salt = sha256(&profile.static_psk_domain)?;
    let mut shared = x25519(static_secret, peer_static)?;
    let derived = hkdf(&salt, &shared, &info, 32);
    zeroize_slice(&mut shared);
    let mut derived = derived?;
    let mut psk = [0_u8; 32];
    psk.copy_from_slice(&derived);
    zeroize_slice(&mut derived);
    Ok(psk)
}

/// Both exchanges are `psk0`; only where the key comes from differs. A rekey
/// chains to the session it replaces through a key derived from its export
/// key; an initial handshake has no predecessor and derives one from the
/// static-static value instead.
fn begin(profile: &Profile, rekey: bool, psk: &[u8; 32]) -> Result<SymmetricState> {
    let prologue = if rekey {
        &profile.rekey_chain_domain
    } else {
        &profile.prologue_domain
    };
    let mut state = SymmetricState::initialize(&profile.noise_protocol)?;
    state.mix_hash(prologue)?;
    state.mix_key_and_hash(psk)?;
    Ok(state)
}

/// Bind an advertisement key to the exchange that is completing.
///
/// ADR 0049 D15. The transcript is signed, not the static key: a signature over
/// the static key alone would be a standing certificate, replayable into any
/// exchange by anyone who saw it once.
///
/// # Errors
///
/// [`HandshakeError`] if the seed does not yield a signing key.
pub fn sign_transition(
    profile: &Profile,
    signing_seed: &[u8; 32],
    handshake_hash: &[u8; 32],
) -> Result<[u8; SIGNATURE_BYTES]> {
    let (_, secret) = signing_keypair(signing_seed)?;
    let mut message = Vec::with_capacity(profile.transition_domain.len() + handshake_hash.len());
    message.extend_from_slice(&profile.transition_domain);
    message.extend_from_slice(handshake_hash);
    Ok(sign(&secret, &message)?)
}

/// Whether `advertisement_key` signed this exchange.
///
/// # Errors
///
/// [`HandshakeError`] unless the signature verifies.
pub fn verify_transition(
    profile: &Profile,
    advertisement_key: &[u8; 32],
    handshake_hash: &[u8; 32],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<()> {
    let mut message = Vec::with_capacity(profile.transition_domain.len() + handshake_hash.len());
    message.extend_from_slice(&profile.transition_domain);
    message.extend_from_slice(handshake_hash);
    Ok(verify(advertisement_key, &message, signature)?)
}

/// The cleartext prefix of an admission initiate: identifier then cookie.
///
/// Cleartext but not unprotected. It is mixed into the transcript before the
/// ephemeral, so altering either field makes the payload fail to open, and a
/// man in the middle can neither strip the cookie nor move it onto another
/// invitation.
///
/// # Errors
///
/// [`HandshakeError`] if either field is not the width the registry fixes.
pub fn admission_header(profile: &Profile, invitation_id: &[u8], cookie: &[u8]) -> Result<Vec<u8>> {
    if invitation_id.len() != profile.invitation_id_bytes || cookie.len() != profile.cookie_bytes {
        return Err(HandshakeError);
    }
    let mut header = Vec::with_capacity(profile.admission_header_bytes);
    header.extend_from_slice(invitation_id);
    header.extend_from_slice(cookie);
    if header.len() != profile.admission_header_bytes {
        return Err(HandshakeError);
    }
    Ok(header)
}

/// Read the cleartext header of an admission initiate, holding no state.
///
/// What a responder calls first: it needs the identifier to find the invitation
/// the key comes from, and the cookie to decide whether to allocate at all.
/// Both happen before any Diffie-Hellman, which is why they are in the clear.
///
/// # Errors
///
/// [`HandshakeError`] if the record is not an admission initiate of the right
/// width.
pub fn peek_admission_header(profile: &Profile, record: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let body = split_record(profile, record, Mode::Admission, Stage::Initiate)?;
    let identifier = body
        .get(..profile.invitation_id_bytes)
        .ok_or(HandshakeError)?
        .to_vec();
    let cookie = body
        .get(profile.invitation_id_bytes..profile.admission_header_bytes)
        .ok_or(HandshakeError)?
        .to_vec();
    Ok((identifier, cookie))
}

/// The responder's answer to a first message whose cookie did not verify.
///
/// ADR 0048 D13. It allocates nothing and authenticates nothing: a joiner that
/// acts on a forged one echoes a cookie that will not verify and is challenged
/// again. One cell wide like every other record, so answering a spoofed source
/// amplifies by a factor of one.
///
/// # Errors
///
/// [`HandshakeError`] if either field is the wrong width.
pub fn encode_cookie_challenge(
    profile: &Profile,
    invitation_id: &[u8],
    cookie: &[u8],
) -> Result<Vec<u8>> {
    let mut record = vec![0_u8; profile.record_prefix_bytes];
    if let Some(slot) = record.last_mut() {
        *slot = profile.cookie_challenge_type;
    }
    record.extend_from_slice(&admission_header(profile, invitation_id, cookie)?);
    record.resize(profile.record_bytes, 0);
    Ok(record)
}

/// Parse a challenge into its identifier and cookie.
///
/// The padding is checked because a receiver must not accept a record with
/// anything hidden behind its declared fields, even one carrying no
/// authentication of its own.
///
/// # Errors
///
/// [`HandshakeError`] on a wrong width, a wrong type, or non-zero padding.
pub fn decode_cookie_challenge(profile: &Profile, record: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if record.len() != profile.record_bytes {
        return Err(HandshakeError);
    }
    let mut expected = vec![0_u8; profile.record_prefix_bytes];
    if let Some(slot) = expected.last_mut() {
        *slot = profile.cookie_challenge_type;
    }
    if record.get(..expected.len()) != Some(expected.as_slice()) {
        return Err(HandshakeError);
    }
    let body = record.get(expected.len()..).ok_or(HandshakeError)?;
    let identifier = body
        .get(..profile.invitation_id_bytes)
        .ok_or(HandshakeError)?
        .to_vec();
    let cookie = body
        .get(profile.invitation_id_bytes..profile.admission_header_bytes)
        .ok_or(HandshakeError)?
        .to_vec();
    if body
        .get(profile.admission_header_bytes..)
        .ok_or(HandshakeError)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(HandshakeError);
    }
    Ok((identifier, cookie))
}

fn prefix(profile: &Profile, mode: Mode, stage: Stage) -> Vec<u8> {
    // The leading zero is what lets a receiver tell a handshake record from a
    // W2 cell without trial decryption: derived epochs have their top bit set.
    let mut out = vec![0_u8; profile.record_prefix_bytes];
    if let Some(slot) = out.last_mut() {
        *slot = profile.record_type(mode, stage);
    }
    out
}

fn split_record<'a>(
    profile: &Profile,
    record: &'a [u8],
    mode: Mode,
    stage: Stage,
) -> Result<&'a [u8]> {
    if record.len() != profile.record_bytes {
        return Err(HandshakeError);
    }
    let expected = prefix(profile, mode, stage);
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
    mode: Mode,
    /// Empty on every path but admission.
    header: Vec<u8>,
    /// Set by `read_respond` on an admission exchange, once the responder has
    /// proved it holds this advertisement key. Comparing it against a cached
    /// candidate is the caller's step; this only says the exchange was bound.
    advertisement_key: Option<[u8; 32]>,
    state: SymmetricState,
    remote_ephemeral: Option<[u8; 32]>,
    selection: Option<Selection>,
}

impl Initiator {
    pub fn new(
        profile: Profile,
        static_secret: [u8; 32],
        ephemeral_secret: [u8; 32],
        offer: Offer,
        keying: Keying<'_>,
    ) -> Result<Self> {
        // An initiator always pins its peer, on every path. Even joining under
        // an invitation it knows the inviter's static key, because an
        // out-of-band invitation can carry it; only the inviter is left
        // learning an identity it did not already hold.
        let expected_peer_static = keying.peer_static().ok_or(HandshakeError)?;
        let psk = keying.psk(&profile, &static_secret, Role::Initiator)?;
        let header = keying.header(&profile)?;
        let state = begin(&profile, keying.is_rekey(), &psk)?;
        Ok(Self {
            static_public: x25519_base(&static_secret)?,
            ephemeral_public: x25519_base(&ephemeral_secret)?,
            static_secret: SecretBytes(static_secret),
            ephemeral_secret: SecretBytes(ephemeral_secret),
            expected_peer_static,
            offer,
            mode: keying.mode(),
            header,
            advertisement_key: None,
            state,
            remote_ephemeral: None,
            selection: None,
            profile,
        })
    }

    /// The advertisement key this exchange was bound to, once message 2 has
    /// been read. `None` on every path but admission.
    #[must_use]
    pub fn advertisement_key(&self) -> Option<[u8; 32]> {
        self.advertisement_key
    }

    /// `-> [header] e`
    pub fn write_initiate(&mut self) -> Result<Vec<u8>> {
        // Mixed before the ephemeral, so the cleartext header is inside the
        // transcript and altering it makes the payload fail to open.
        if !self.header.is_empty() {
            self.state.mix_hash(&self.header)?;
        }
        self.state.mix_ephemeral(&self.ephemeral_public)?;
        let width = self.profile.payload_bytes(self.mode, Stage::Initiate);
        let mut payload = frame(&self.offer.encode(&self.profile)?, width)?;
        let sealed = self.state.encrypt_and_hash(&payload);
        zeroize_slice(&mut payload);

        let mut record = prefix(&self.profile, self.mode, Stage::Initiate);
        record.extend_from_slice(&self.header);
        record.extend_from_slice(&self.ephemeral_public);
        record.extend_from_slice(&sealed?);
        if record.len() != self.profile.record_bytes {
            return Err(HandshakeError);
        }
        Ok(record)
    }

    /// `<- e, ee, s, es`
    /// A record that does not validate leaves this initiator exactly as it was,
    /// for the reason given on [`Responder::read_initiate`]: the caller retries
    /// on the same object while the peer resends, and a poisoned transcript
    /// makes every one of those retries fail.
    pub fn read_respond(&mut self, record: &[u8]) -> Result<()> {
        let mut state = self.state.clone();
        let body = split_record(&self.profile, record, self.mode, Stage::Respond)?;
        let mut cursor = 0_usize;
        let remote_ephemeral = as_key(body.get(..DH_BYTES).ok_or(HandshakeError)?)?;
        cursor += DH_BYTES;
        state.mix_ephemeral(&remote_ephemeral)?;
        state.mix_key(&x25519(&self.ephemeral_secret.0, &remote_ephemeral)?)?;

        let sealed_static = take_static(body, &mut cursor)?;
        let remote_static = as_key(&state.decrypt_and_hash(&sealed_static)?)?;
        state.mix_key(&x25519(&self.ephemeral_secret.0, &remote_static)?)?;

        // Captured before the payload is decrypted, because that is the value
        // the responder signed and the one the AEAD is about to consume as
        // associated data. Reading it afterwards would read a hash that already
        // covers the signature verifying against it.
        let signed_hash = state.handshake_hash;
        let framed = state.decrypt_and_hash(body.get(cursor..).ok_or(HandshakeError)?)?;
        let width = self.profile.payload_bytes(self.mode, Stage::Respond);
        let mut payload = unframe(&framed, width)?;
        if self.mode == Mode::Admission {
            // ADR 0049: selection, then the advertisement key and its signature.
            if payload.len() != SELECTION_BYTES + DH_BYTES + SIGNATURE_BYTES {
                return Err(HandshakeError);
            }
            let key = as_key(
                payload
                    .get(SELECTION_BYTES..SELECTION_BYTES + DH_BYTES)
                    .ok_or(HandshakeError)?,
            )?;
            let signature: [u8; SIGNATURE_BYTES] = payload
                .get(SELECTION_BYTES + DH_BYTES..)
                .ok_or(HandshakeError)?
                .try_into()
                .map_err(|_| HandshakeError)?;
            verify_transition(&self.profile, &key, &signed_hash, &signature)?;
            self.advertisement_key = Some(key);
            payload.truncate(SELECTION_BYTES);
        }
        let selection = Selection::decode(&payload)?;

        // The key authenticated; the question is whether it is the one the
        // manifest names for this peer. Checked before any key is derived.
        if !constant_time_equal(&remote_static, &self.expected_peer_static) {
            return Err(HandshakeError);
        }
        if !selection.within(&self.offer) {
            return Err(HandshakeError);
        }
        self.state = state;
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
        let width = self.profile.payload_bytes(self.mode, Stage::Finish);
        let sealed_payload = self.state.encrypt_and_hash(&frame(&[], width)?)?;

        let mut record = prefix(&self.profile, self.mode, Stage::Finish);
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
    /// What the caller already read from the record's cleartext header and
    /// acted on: the identifier it found the key from, and the cookie it
    /// verified. `read_initiate` confirms the record carries exactly these, so
    /// the key and the routability proof belong to the record being read.
    header: Vec<u8>,
    mode: Mode,
    /// The advertisement signing seed. Present on every admission exchange and
    /// on no other, because D16 leaves a responder no way to decline to bind
    /// itself.
    advertisement_secret: Option<SecretBytes<32>>,
    /// `None` only on an admission handshake, which has no manifest entry.
    expected_peer_static: Option<[u8; 32]>,
    admission: bool,
    promoted_static: Option<[u8; 32]>,
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
        keying: Keying<'_>,
    ) -> Result<Self> {
        let psk = keying.psk(&profile, &static_secret, Role::Responder)?;
        // ADR 0049 D16: unconditional on the admission path. A responder that
        // could decline to bind itself would present a joiner with exactly the
        // case it cannot tell apart from an attack, so there is no way to
        // construct one that admits without an advertisement key.
        let advertisement_secret = match &keying {
            Keying::Admission {
                advertisement_secret,
                ..
            } => Some(SecretBytes(*(*advertisement_secret).ok_or(HandshakeError)?)),
            _ => None,
        };
        let state = begin(&profile, keying.is_rekey(), &psk)?;
        Ok(Self {
            static_public: x25519_base(&static_secret)?,
            ephemeral_public: x25519_base(&ephemeral_secret)?,
            static_secret: SecretBytes(static_secret),
            ephemeral_secret: SecretBytes(ephemeral_secret),
            expected_peer_static: keying.peer_static(),
            admission: keying.is_admission(),
            header: keying.header(&profile)?,
            mode: keying.mode(),
            advertisement_secret,
            promoted_static: None,
            state,
            remote_ephemeral: None,
            offer: None,
            selection: None,
            profile,
        })
    }

    /// The static key an admission handshake learned, once it completed.
    ///
    /// `None` on every other path and before completion, so a caller cannot
    /// mistake a pinned peer for a newly learned one. This is the value ADR
    /// 0046 D8 promotes into the manifest.
    #[must_use]
    pub fn promoted_static(&self) -> Option<[u8; 32]> {
        self.promoted_static
    }

    /// A record that does not validate leaves this responder exactly as it was.
    ///
    /// Callers retry on the same object -- section 4 has a responder keep
    /// waiting rather than tear the link down, because a record that fails to
    /// open is usually loss-induced garbage. Mixing the offered ephemeral into
    /// the live state before the rest of the record has proved good makes that
    /// retry useless: the transcript has already absorbed the bad record, so
    /// the genuine one that follows can no longer agree with the peer's. One
    /// malformed datagram would end the exchange. Ordinary loss produces such
    /// records without an attacker, and an attacker holding the pre-shared key
    /// -- or one recorded message that opened under it -- can produce them
    /// deliberately.
    pub fn read_initiate(&mut self, record: &[u8]) -> Result<Offer> {
        let mut state = self.state.clone();
        let body = split_record(&self.profile, record, self.mode, Stage::Initiate)?;
        let mut cursor = 0_usize;
        if !self.header.is_empty() {
            let found = body
                .get(..self.profile.admission_header_bytes)
                .ok_or(HandshakeError)?;
            // A record whose header is not the one the caller acted on is a
            // different record: the key would be right and the routability
            // proof would belong to something else.
            if !constant_time_equal(found, &self.header) {
                return Err(HandshakeError);
            }
            state.mix_hash(found)?;
            cursor += self.profile.admission_header_bytes;
        }
        let remote_ephemeral = as_key(body.get(cursor..cursor + DH_BYTES).ok_or(HandshakeError)?)?;
        cursor += DH_BYTES;
        state.mix_ephemeral(&remote_ephemeral)?;
        let framed = state.decrypt_and_hash(body.get(cursor..).ok_or(HandshakeError)?)?;
        let width = self.profile.payload_bytes(self.mode, Stage::Initiate);
        let offer = Offer::decode(&self.profile, &unframe(&framed, width)?)?;
        self.state = state;
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
        self.state.mix_ephemeral(&self.ephemeral_public)?;
        self.state
            .mix_key(&x25519(&self.ephemeral_secret.0, &remote_ephemeral)?)?;
        let sealed_static = self.state.encrypt_and_hash(&self.static_public)?;
        self.state
            .mix_key(&x25519(&self.static_secret.0, &remote_ephemeral)?)?;
        let width = self.profile.payload_bytes(self.mode, Stage::Respond);
        let mut body = selection.encode();
        if self.mode == Mode::Admission {
            // ADR 0049 D15/D16. Signed over the transcript as it stands here,
            // which is the value the AEAD below takes as associated data, so the
            // initiator holds the same one before it decrypts.
            let seed = self.advertisement_secret.as_ref().ok_or(HandshakeError)?.0;
            let (public, _) = signing_keypair(&seed)?;
            let signature = sign_transition(&self.profile, &seed, &self.state.handshake_hash)?;
            body.extend_from_slice(&public);
            body.extend_from_slice(&signature);
        }
        let sealed_payload = self.state.encrypt_and_hash(&frame(&body, width)?)?;

        let mut record = prefix(&self.profile, self.mode, Stage::Respond);
        record.extend_from_slice(&self.ephemeral_public);
        record.extend_from_slice(&sealed_static);
        record.extend_from_slice(&sealed_payload);
        if record.len() != self.profile.record_bytes {
            return Err(HandshakeError);
        }
        self.selection = Some(selection);
        Ok(record)
    }

    /// A record that does not validate leaves this responder exactly as it was,
    /// for the reason given on [`Self::read_initiate`]. This one matters most:
    /// the responder sits here resending its respond record until the finish
    /// arrives, so a poisoned transcript strands it for the whole handshake
    /// while the peer keeps answering.
    pub fn read_finish(&mut self, record: &[u8]) -> Result<Session> {
        let selection = self.selection.ok_or(HandshakeError)?;
        let mut state = self.state.clone();
        let body = split_record(&self.profile, record, self.mode, Stage::Finish)?;
        let mut cursor = 0_usize;

        let sealed_static = take_static(body, &mut cursor)?;
        let remote_static = as_key(&state.decrypt_and_hash(&sealed_static)?)?;
        state.mix_key(&x25519(&self.ephemeral_secret.0, &remote_static)?)?;

        let framed = state.decrypt_and_hash(body.get(cursor..).ok_or(HandshakeError)?)?;
        let width = self.profile.payload_bytes(self.mode, Stage::Finish);
        if !unframe(&framed, width)?.is_empty() {
            return Err(HandshakeError);
        }
        // An admission handshake has no manifest entry to check against, so it
        // records the key for promotion instead. What authenticated the peer is
        // the admission key the whole exchange ran under: without it the first
        // message would not have decrypted and nothing would reach here.
        match self.expected_peer_static {
            Some(pinned) if !self.admission => {
                if !constant_time_equal(&remote_static, &pinned) {
                    return Err(HandshakeError);
                }
            }
            _ if self.admission => {}
            // Neither pinned nor admitting: the constructor refuses this, and
            // reaching it would mean the peer was authenticated by nothing.
            _ => return Err(HandshakeError),
        }
        let session = finish(&self.profile, &state, remote_static, selection)?;
        self.state = state;
        if self.admission {
            self.promoted_static = Some(remote_static);
        }
        Ok(session)
    }
}
