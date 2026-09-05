// SPDX-License-Identifier: Apache-2.0
#![doc = "Minimal libsodium-backed primitives for the Trahens P1 prototype."]

pub mod c1;

use core::ffi::{c_int, c_uchar, c_ulonglong, c_void};
use protocol_registry::{DOMAIN_C1_LABEL_PREFIX, DOMAIN_C1_REPLY_COMMIT, SUITE_C1_V2};
use std::sync::OnceLock;

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;
pub const POINT_BYTES: usize = 32;
pub const SCALAR_BYTES: usize = 32;
pub const COMMITMENT_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    Initialization,
    InvalidLength,
    InvalidEncoding,
    Authentication,
    ResourceLimit,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Initialization => "cryptographic initialization failed",
            Self::InvalidLength | Self::InvalidEncoding => "invalid cryptographic input",
            Self::Authentication => "cryptographic authentication failed",
            Self::ResourceLimit => "cryptographic resource limit exceeded",
        })
    }
}

impl std::error::Error for CryptoError {}

#[link(name = "sodium")]
unsafe extern "C" {
    fn sodium_init() -> c_int;
    fn randombytes_buf(buf: *mut c_void, size: usize);
    fn sodium_memzero(buf: *mut c_void, size: usize);
    fn sodium_memcmp(left: *const c_void, right: *const c_void, size: usize) -> c_int;

    fn crypto_hash_sha256(
        out: *mut c_uchar,
        input: *const c_uchar,
        input_len: c_ulonglong,
    ) -> c_int;
    fn crypto_auth_hmacsha256(
        out: *mut c_uchar,
        input: *const c_uchar,
        input_len: c_ulonglong,
        key: *const c_uchar,
    ) -> c_int;

    fn crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext: *mut c_uchar,
        ciphertext_len: *mut c_ulonglong,
        message: *const c_uchar,
        message_len: c_ulonglong,
        aad: *const c_uchar,
        aad_len: c_ulonglong,
        secret_nonce: *const c_uchar,
        public_nonce: *const c_uchar,
        key: *const c_uchar,
    ) -> c_int;
    fn crypto_aead_chacha20poly1305_ietf_decrypt(
        message: *mut c_uchar,
        message_len: *mut c_ulonglong,
        secret_nonce: *mut c_uchar,
        ciphertext: *const c_uchar,
        ciphertext_len: c_ulonglong,
        aad: *const c_uchar,
        aad_len: c_ulonglong,
        public_nonce: *const c_uchar,
        key: *const c_uchar,
    ) -> c_int;

    fn crypto_core_ristretto255_is_valid_point(point: *const c_uchar) -> c_int;
    fn crypto_core_ristretto255_scalar_random(scalar: *mut c_uchar);
    fn crypto_core_ristretto255_scalar_mul(
        output: *mut c_uchar,
        left: *const c_uchar,
        right: *const c_uchar,
    );
    fn crypto_core_ristretto255_add(
        output: *mut c_uchar,
        left: *const c_uchar,
        right: *const c_uchar,
    ) -> c_int;
    fn crypto_core_ristretto255_sub(
        output: *mut c_uchar,
        left: *const c_uchar,
        right: *const c_uchar,
    ) -> c_int;
    fn crypto_core_ristretto255_from_hash(output: *mut c_uchar, hash: *const c_uchar) -> c_int;
    fn crypto_hash_sha512(
        output: *mut c_uchar,
        input: *const c_uchar,
        length: c_ulonglong,
    ) -> c_int;
    fn crypto_core_ristretto255_scalar_add(
        output: *mut c_uchar,
        left: *const c_uchar,
        right: *const c_uchar,
    );
    fn crypto_core_ristretto255_scalar_reduce(output: *mut c_uchar, wide: *const c_uchar);
    fn crypto_scalarmult_ristretto255_base(output: *mut c_uchar, scalar: *const c_uchar) -> c_int;
    fn crypto_scalarmult_ristretto255(
        output: *mut c_uchar,
        scalar: *const c_uchar,
        point: *const c_uchar,
    ) -> c_int;

    fn crypto_sign_seed_keypair(
        public: *mut c_uchar,
        secret: *mut c_uchar,
        seed: *const c_uchar,
    ) -> c_int;
    fn crypto_sign_detached(
        signature: *mut c_uchar,
        signature_len: *mut c_ulonglong,
        message: *const c_uchar,
        message_len: c_ulonglong,
        secret: *const c_uchar,
    ) -> c_int;
    fn crypto_sign_verify_detached(
        signature: *const c_uchar,
        message: *const c_uchar,
        message_len: c_ulonglong,
        public: *const c_uchar,
    ) -> c_int;
}

static SODIUM: OnceLock<Result<(), CryptoError>> = OnceLock::new();

pub fn initialize() -> Result<(), CryptoError> {
    *SODIUM.get_or_init(|| {
        // SAFETY: sodium_init is process-global and explicitly safe to call repeatedly.
        let result = unsafe { sodium_init() };
        if result < 0 {
            Err(CryptoError::Initialization)
        } else {
            Ok(())
        }
    })
}

pub fn zeroize_slice(value: &mut [u8]) {
    if initialize().is_ok() {
        // SAFETY: value is a valid writable slice for its full length.
        unsafe { sodium_memzero(value.as_mut_ptr().cast(), value.len()) };
    } else {
        value.fill(0);
    }
}

pub fn zeroize<const N: usize>(value: &mut [u8; N]) {
    zeroize_slice(value);
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    initialize()?;
    let mut output = [0_u8; N];
    // SAFETY: output is valid for N writable bytes.
    unsafe { randombytes_buf(output.as_mut_ptr().cast(), N) };
    Ok(output)
}

pub fn random_nonzero_16() -> Result<[u8; 16], CryptoError> {
    for _ in 0..32 {
        let value = random_bytes::<16>()?;
        if value != [0_u8; 16] {
            return Ok(value);
        }
    }
    Err(CryptoError::Initialization)
}

pub fn sha256(input: &[u8]) -> Result<[u8; 32], CryptoError> {
    initialize()?;
    let mut output = [0_u8; 32];
    // SAFETY: pointers are valid for their declared lengths and do not overlap mutably.
    let result = unsafe {
        crypto_hash_sha256(
            output.as_mut_ptr(),
            input.as_ptr(),
            input.len() as c_ulonglong,
        )
    };
    if result == 0 {
        Ok(output)
    } else {
        Err(CryptoError::Initialization)
    }
}

pub fn hmac_sha256(key: &[u8; 32], input: &[u8]) -> Result<[u8; 32], CryptoError> {
    initialize()?;
    let mut output = [0_u8; 32];
    // SAFETY: libsodium HMAC-SHA256 consumes a 32-byte key and bounded input.
    let result = unsafe {
        crypto_auth_hmacsha256(
            output.as_mut_ptr(),
            input.as_ptr(),
            input.len() as c_ulonglong,
            key.as_ptr(),
        )
    };
    if result == 0 {
        Ok(output)
    } else {
        Err(CryptoError::Initialization)
    }
}

pub fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    initialize().is_ok()
        && unsafe { sodium_memcmp(left.as_ptr().cast(), right.as_ptr().cast(), left.len()) } == 0
}

pub fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    initialize()?;
    let mut output = vec![
        0_u8;
        plaintext
            .len()
            .checked_add(TAG_BYTES)
            .ok_or(CryptoError::ResourceLimit)?
    ];
    let mut output_len = 0_u64;
    // SAFETY: all slices are valid; output has message length plus the documented tag capacity.
    let result = unsafe {
        crypto_aead_chacha20poly1305_ietf_encrypt(
            output.as_mut_ptr(),
            &mut output_len,
            plaintext.as_ptr(),
            plaintext.len() as c_ulonglong,
            aad.as_ptr(),
            aad.len() as c_ulonglong,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    if result != 0 || output_len as usize != output.len() {
        return Err(CryptoError::Authentication);
    }
    Ok(output)
}

pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    initialize()?;
    if ciphertext.len() < TAG_BYTES {
        return Err(CryptoError::Authentication);
    }
    let mut output = vec![0_u8; ciphertext.len() - TAG_BYTES];
    let mut output_len = 0_u64;
    // SAFETY: all pointers refer to valid, non-overlapping slices of sufficient capacity.
    let result = unsafe {
        crypto_aead_chacha20poly1305_ietf_decrypt(
            output.as_mut_ptr(),
            &mut output_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as c_ulonglong,
            aad.as_ptr(),
            aad.len() as c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    if result != 0 || output_len as usize != output.len() {
        output.fill(0);
        return Err(CryptoError::Authentication);
    }
    Ok(output)
}

pub(crate) fn encode_fields(label: &[u8], fields: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    let mut total = DOMAIN_C1_LABEL_PREFIX.len() + 2 + label.len();
    for field in fields {
        if field.len() > u16::MAX as usize {
            return Err(CryptoError::InvalidLength);
        }
        total = total
            .checked_add(2 + field.len())
            .ok_or(CryptoError::ResourceLimit)?;
    }
    if label.len() > u16::MAX as usize {
        return Err(CryptoError::InvalidLength);
    }
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(DOMAIN_C1_LABEL_PREFIX);
    output.extend_from_slice(&(label.len() as u16).to_be_bytes());
    output.extend_from_slice(label);
    for field in fields {
        output.extend_from_slice(&(field.len() as u16).to_be_bytes());
        output.extend_from_slice(field);
    }
    Ok(output)
}

fn hkdf_extract(ikm: &[u8]) -> Result<[u8; 32], CryptoError> {
    hmac_sha256(&[0_u8; 32], ikm)
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
    if length > 255 * 32 {
        return Err(CryptoError::InvalidLength);
    }
    let mut output = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let mut counter = 1_u8;
    while output.len() < length {
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);
        previous = hmac_sha256(prk, &input)?.to_vec();
        output.extend_from_slice(&previous);
        counter = counter.checked_add(1).ok_or(CryptoError::InvalidLength)?;
    }
    output.truncate(length);
    Ok(output)
}

fn valid_point(point: &[u8; 32]) -> Result<(), CryptoError> {
    initialize()?;
    // SAFETY: point points to exactly 32 readable bytes.
    if unsafe { crypto_core_ristretto255_is_valid_point(point.as_ptr()) } == 1
        && *point != [0_u8; 32]
    {
        Ok(())
    } else {
        Err(CryptoError::InvalidEncoding)
    }
}

pub fn require_point(point: &[u8; 32]) -> Result<(), CryptoError> {
    valid_point(point)
}

pub fn random_scalar() -> Result<[u8; 32], CryptoError> {
    initialize()?;
    let mut scalar = [0_u8; 32];
    // SAFETY: scalar is a writable 32-byte buffer.
    unsafe { crypto_core_ristretto255_scalar_random(scalar.as_mut_ptr()) };
    if scalar == [0_u8; 32] {
        Err(CryptoError::Initialization)
    } else {
        Ok(scalar)
    }
}

pub fn scalar_base(scalar: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    initialize()?;
    if *scalar == [0_u8; 32] {
        return Err(CryptoError::InvalidEncoding);
    }
    let mut output = [0_u8; 32];
    // SAFETY: input and output are fixed-size buffers required by libsodium.
    let result =
        unsafe { crypto_scalarmult_ristretto255_base(output.as_mut_ptr(), scalar.as_ptr()) };
    if result == 0 {
        valid_point(&output)?;
        Ok(output)
    } else {
        Err(CryptoError::InvalidEncoding)
    }
}

pub fn scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    initialize()?;
    if *scalar == [0_u8; 32] {
        return Err(CryptoError::InvalidEncoding);
    }
    valid_point(point)?;
    let mut output = [0_u8; 32];
    // SAFETY: fixed-size validated inputs and writable output satisfy libsodium's contract.
    let result = unsafe {
        crypto_scalarmult_ristretto255(output.as_mut_ptr(), scalar.as_ptr(), point.as_ptr())
    };
    if result == 0 {
        valid_point(&output)?;
        Ok(output)
    } else {
        Err(CryptoError::InvalidEncoding)
    }
}

/// Group addition on ristretto255.
pub fn point_add(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    initialize()?;
    valid_point(left)?;
    valid_point(right)?;
    let mut output = [0_u8; 32];
    // SAFETY: every buffer is exactly one 32-byte ristretto255 element.
    let result =
        unsafe { crypto_core_ristretto255_add(output.as_mut_ptr(), left.as_ptr(), right.as_ptr()) };
    if result == 0 {
        Ok(output)
    } else {
        Err(CryptoError::InvalidEncoding)
    }
}

/// Group subtraction on ristretto255.
pub fn point_sub(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    initialize()?;
    valid_point(left)?;
    valid_point(right)?;
    let mut output = [0_u8; 32];
    // SAFETY: every buffer is exactly one 32-byte ristretto255 element.
    let result =
        unsafe { crypto_core_ristretto255_sub(output.as_mut_ptr(), left.as_ptr(), right.as_ptr()) };
    if result == 0 {
        Ok(output)
    } else {
        Err(CryptoError::InvalidEncoding)
    }
}

/// SHA-512, used only for the wide inputs ristretto255 maps into the group.
pub fn sha512(input: &[u8]) -> Result<[u8; 64], CryptoError> {
    initialize()?;
    let mut output = [0_u8; 64];
    // SAFETY: the output buffer is exactly one SHA-512 digest.
    let result = unsafe {
        crypto_hash_sha512(
            output.as_mut_ptr(),
            input.as_ptr(),
            input.len() as c_ulonglong,
        )
    };
    if result == 0 {
        Ok(output)
    } else {
        Err(CryptoError::Initialization)
    }
}

/// Hash a label to a group element: `from_hash(SHA-512(dst || label))`.
///
/// Matches `ristretto.point_from_label` in the Python reference so both
/// implementations derive identical elements.
pub fn point_from_label(label: &[u8], domain: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut input = Vec::with_capacity(domain.len() + label.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(label);
    let wide = sha512(&input)?;
    let mut output = [0_u8; 32];
    // SAFETY: the input is exactly the 64 bytes from_hash consumes.
    let result = unsafe { crypto_core_ristretto255_from_hash(output.as_mut_ptr(), wide.as_ptr()) };
    if result == 0 {
        Ok(output)
    } else {
        Err(CryptoError::InvalidEncoding)
    }
}

/// Hash a label to a non-zero scalar.
///
/// Matches `ristretto.scalar_from_label`: SHA-512 over `dst || counter ||
/// label`, reduced into the group order, retrying while the result is zero.
pub fn scalar_from_label(label: &[u8], domain: &[u8]) -> Result<[u8; 32], CryptoError> {
    for counter in 0_u8..=255 {
        let mut input = Vec::with_capacity(domain.len() + 1 + label.len());
        input.extend_from_slice(domain);
        input.push(counter);
        input.extend_from_slice(label);
        let wide = sha512(&input)?;
        let mut output = [0_u8; 32];
        // SAFETY: scalar_reduce consumes exactly 64 bytes and writes 32.
        unsafe { crypto_core_ristretto255_scalar_reduce(output.as_mut_ptr(), wide.as_ptr()) };
        if output != [0_u8; 32] {
            return Ok(output);
        }
    }
    Err(CryptoError::InvalidEncoding)
}

/// Scalar addition modulo the group order.
pub fn scalar_sum(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    initialize()?;
    let mut output = [0_u8; 32];
    // SAFETY: all scalar buffers are exactly 32 bytes.
    unsafe {
        crypto_core_ristretto255_scalar_add(output.as_mut_ptr(), left.as_ptr(), right.as_ptr());
    }
    Ok(output)
}

/// Deterministic keypair derived from a label, for domain-separated keys.
pub fn keypair_from_label(
    label: &[u8],
    domain: &[u8],
) -> Result<([u8; 32], SecretBytes<32>), CryptoError> {
    let secret = scalar_from_label(label, domain)?;
    if secret == [0_u8; 32] {
        return Err(CryptoError::InvalidEncoding);
    }
    let public = scalar_base(&secret)?;
    Ok((public, SecretBytes(secret)))
}

pub fn scalar_product(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    initialize()?;
    if *left == [0_u8; 32] || *right == [0_u8; 32] {
        return Err(CryptoError::InvalidEncoding);
    }
    let mut output = [0_u8; 32];
    // SAFETY: all scalar buffers are exactly 32 bytes.
    unsafe {
        crypto_core_ristretto255_scalar_mul(output.as_mut_ptr(), left.as_ptr(), right.as_ptr())
    };
    if output == [0_u8; 32] {
        Err(CryptoError::InvalidEncoding)
    } else {
        Ok(output)
    }
}

pub fn blind_public(public: &[u8; 32], factor: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    scalar_mult(factor, public)
}

pub fn blind_secret(secret: &[u8; 32], factor: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    scalar_product(secret, factor)
}

fn derive_reply_context(
    dh_point: &[u8; 32],
    encapsulation: &[u8; 32],
    recipient_public: &[u8; 32],
    info: &[u8],
) -> Result<(SecretBytes<32>, [u8; 12], SecretBytes<32>), CryptoError> {
    let context = encode_fields(
        b"reply-kem-context",
        &[&SUITE_C1_V2, encapsulation, recipient_public, info],
    )?;
    let dh = encode_fields(b"reply-kem-dh", &[dh_point])?;
    let prk = hkdf_extract(&dh)?;
    let schedule = encode_fields(b"reply-kem-key-schedule", &[&context])?;
    let okm = hkdf_expand(&prk, &schedule, 76)?;
    let mut key = [0_u8; 32];
    let mut nonce = [0_u8; 12];
    let mut commitment_key = [0_u8; 32];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..44]);
    commitment_key.copy_from_slice(&okm[44..76]);
    Ok((SecretBytes(key), nonce, SecretBytes(commitment_key)))
}

fn reply_commitment(
    key: &[u8; 32],
    encapsulation: &[u8; 32],
    recipient_public: &[u8; 32],
    aad: &[u8],
    info: &[u8],
    ciphertext: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let transcript = encode_fields(
        b"reply-key-commitment",
        &[
            DOMAIN_C1_REPLY_COMMIT,
            encapsulation,
            recipient_public,
            aad,
            info,
            ciphertext,
        ],
    )?;
    hmac_sha256(key, &transcript)
}

/// Seal with a caller-supplied ephemeral scalar.
///
/// Exposed so tests can reproduce the published C1 vectors, whose
/// `reply_kem` case fixes the ephemeral secret. Production callers use
/// [`reply_seal`], which draws the scalar randomly.
#[doc(hidden)]
pub fn reply_seal_with_scalar(
    recipient_public: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    info: &[u8],
    ephemeral: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    valid_point(recipient_public)?;
    let encapsulation = scalar_base(ephemeral)?;
    let dh = SecretBytes(scalar_mult(ephemeral, recipient_public)?);
    let (key, nonce, commitment_key) =
        derive_reply_context(&dh.0, &encapsulation, recipient_public, info)?;
    let ciphertext = aead_seal(&key.0, &nonce, plaintext, aad)?;
    let commitment = reply_commitment(
        &commitment_key.0,
        &encapsulation,
        recipient_public,
        aad,
        info,
        &ciphertext,
    )?;
    let mut output = Vec::with_capacity(32 + ciphertext.len() + 32);
    output.extend_from_slice(&encapsulation);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&commitment);
    Ok(output)
}

pub fn reply_seal(
    recipient_public: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral = SecretBytes(random_scalar()?);
    reply_seal_with_scalar(recipient_public, plaintext, aad, info, &ephemeral.0)
}

pub fn reply_open(
    recipient_secret: &[u8; 32],
    sealed: &[u8],
    aad: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < POINT_BYTES + TAG_BYTES + COMMITMENT_BYTES {
        return Err(CryptoError::Authentication);
    }
    let mut encapsulation = [0_u8; 32];
    encapsulation.copy_from_slice(&sealed[..32]);
    let split = sealed.len() - COMMITMENT_BYTES;
    let ciphertext = &sealed[32..split];
    let commitment = &sealed[split..];
    let recipient_public = scalar_base(recipient_secret)?;
    let dh = SecretBytes(scalar_mult(recipient_secret, &encapsulation)?);
    let (key, nonce, commitment_key) =
        derive_reply_context(&dh.0, &encapsulation, &recipient_public, info)?;
    let expected = reply_commitment(
        &commitment_key.0,
        &encapsulation,
        &recipient_public,
        aad,
        info,
        ciphertext,
    )?;
    let commitment_ok = constant_time_equal(commitment, &expected);
    let opened = aead_open(&key.0, &nonce, ciphertext, aad);
    match (commitment_ok, opened) {
        (true, Ok(plaintext)) => Ok(plaintext),
        _ => Err(CryptoError::Authentication),
    }
}

/// Which way along a route a record travels.
///
/// The code is the leading quarter of the AEAD nonce and selects the key, so
/// the two directions can never collide under one key even if their sequence
/// spaces do, and a reflected record cannot open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDirection {
    EndpointToGateway,
    GatewayToEndpoint,
}

impl RouteDirection {
    pub fn code(self) -> u32 {
        match self {
            Self::EndpointToGateway => 0,
            Self::GatewayToEndpoint => 1,
        }
    }

    fn domain(self) -> &'static [u8] {
        match self {
            Self::EndpointToGateway => protocol_registry::DOMAIN_P1_ROUTE_KEY_E2G,
            Self::GatewayToEndpoint => protocol_registry::DOMAIN_P1_ROUTE_KEY_G2E,
        }
    }
}

/// The two directional keys of one route channel.
pub struct RouteKeys {
    pub endpoint_to_gateway: SecretBytes<32>,
    pub gateway_to_endpoint: SecretBytes<32>,
}

impl RouteKeys {
    pub fn direction(&self, direction: RouteDirection) -> &[u8; 32] {
        match direction {
            RouteDirection::EndpointToGateway => &self.endpoint_to_gateway.0,
            RouteDirection::GatewayToEndpoint => &self.gateway_to_endpoint.0,
        }
    }
}

/// Derive both directional route keys from the route secret.
///
/// The selected offer's transcript hash is bound into the expansion, so the
/// keys are valid only for the offer that was actually chosen: a route secret
/// presented under any other offer derives different keys and fails closed.
pub fn route_keys(
    route_secret: &[u8; 32],
    offer_transcript_hash: &[u8; 32],
) -> Result<RouteKeys, CryptoError> {
    if *route_secret == [0_u8; 32] {
        return Err(CryptoError::InvalidEncoding);
    }
    let mut ikm =
        Vec::with_capacity(protocol_registry::DOMAIN_P1_ROUTE_EXTRACT.len() + route_secret.len());
    ikm.extend_from_slice(protocol_registry::DOMAIN_P1_ROUTE_EXTRACT);
    ikm.extend_from_slice(route_secret);
    let prk = hkdf_extract(&ikm)?;
    Ok(RouteKeys {
        endpoint_to_gateway: SecretBytes(expand_route_key(
            &prk,
            RouteDirection::EndpointToGateway,
            offer_transcript_hash,
        )?),
        gateway_to_endpoint: SecretBytes(expand_route_key(
            &prk,
            RouteDirection::GatewayToEndpoint,
            offer_transcript_hash,
        )?),
    })
}

fn expand_route_key(
    prk: &[u8; 32],
    direction: RouteDirection,
    offer_transcript_hash: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let domain = direction.domain();
    let mut info = Vec::with_capacity(domain.len() + offer_transcript_hash.len());
    info.extend_from_slice(domain);
    info.extend_from_slice(offer_transcript_hash);
    let bytes = hkdf_expand(prk, &info, 32)?;
    let mut key = [0_u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Deterministic route nonce: direction then sequence, filling the AEAD nonce
/// exactly. A counter rather than randomness, so one key never repeats a nonce
/// and the receiver can bound what it has already accepted.
fn route_nonce(direction: RouteDirection, sequence: u64) -> [u8; NONCE_BYTES] {
    let mut nonce = [0_u8; NONCE_BYTES];
    nonce[..4].copy_from_slice(&direction.code().to_be_bytes());
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

pub fn route_seal(
    key: &[u8; 32],
    direction: RouteDirection,
    sequence: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = route_nonce(direction, sequence);
    let ciphertext = aead_seal(key, &nonce, plaintext, aad)?;
    let mut output = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Open a route record, returning its authenticated sequence number.
///
/// The caller supplies the key for the direction it expects to receive, so a
/// record travelling the other way cannot open. The sequence is returned rather
/// than trusted from the payload: it is the value the caller must check against
/// its replay window.
pub fn route_open(
    key: &[u8; 32],
    expected_direction: RouteDirection,
    sealed: &[u8],
    aad: &[u8],
) -> Result<(u64, Vec<u8>), CryptoError> {
    if sealed.len() < NONCE_BYTES + TAG_BYTES {
        return Err(CryptoError::Authentication);
    }
    let mut nonce = [0_u8; NONCE_BYTES];
    nonce.copy_from_slice(&sealed[..NONCE_BYTES]);
    let mut code = [0_u8; 4];
    code.copy_from_slice(&nonce[..4]);
    if u32::from_be_bytes(code) != expected_direction.code() {
        return Err(CryptoError::Authentication);
    }
    let mut sequence = [0_u8; 8];
    sequence.copy_from_slice(&nonce[4..]);
    let plaintext = aead_open(key, &nonce, &sealed[NONCE_BYTES..], aad)?;
    Ok((u64::from_be_bytes(sequence), plaintext))
}

pub fn keyed_proof(
    key: &[u8; 32],
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<[u8; 32], CryptoError> {
    let mut input = Vec::with_capacity(
        domain.len() + fields.iter().map(|field| 2 + field.len()).sum::<usize>(),
    );
    input.extend_from_slice(domain);
    for field in fields {
        if field.len() > u16::MAX as usize {
            return Err(CryptoError::InvalidLength);
        }
        input.extend_from_slice(&(field.len() as u16).to_be_bytes());
        input.extend_from_slice(field);
    }
    hmac_sha256(key, &input)
}

pub struct SecretBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

pub fn signing_keypair(seed: &[u8; 32]) -> Result<([u8; 32], SecretBytes<64>), CryptoError> {
    initialize()?;
    let mut public = [0_u8; 32];
    let mut secret = [0_u8; 64];
    // SAFETY: output buffers and seed are exact libsodium sizes.
    let result = unsafe {
        crypto_sign_seed_keypair(public.as_mut_ptr(), secret.as_mut_ptr(), seed.as_ptr())
    };
    if result == 0 {
        Ok((public, SecretBytes(secret)))
    } else {
        Err(CryptoError::Initialization)
    }
}

pub fn sign(secret: &SecretBytes<64>, message: &[u8]) -> Result<[u8; 64], CryptoError> {
    initialize()?;
    let mut signature = [0_u8; 64];
    let mut signature_len = 0_u64;
    // SAFETY: fixed-size key/signature buffers and bounded message satisfy libsodium's API.
    let result = unsafe {
        crypto_sign_detached(
            signature.as_mut_ptr(),
            &mut signature_len,
            message.as_ptr(),
            message.len() as c_ulonglong,
            secret.0.as_ptr(),
        )
    };
    if result == 0 && signature_len == 64 {
        Ok(signature)
    } else {
        Err(CryptoError::Initialization)
    }
}

pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
    initialize()?;
    // SAFETY: all slices point to the documented fixed-size values.
    let result = unsafe {
        crypto_sign_verify_detached(
            signature.as_ptr(),
            message.as_ptr(),
            message.len() as c_ulonglong,
            public.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(CryptoError::Authentication)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_registry::{DOMAIN_C1_ELEMENT, DOMAIN_C1_SCALAR, DOMAIN_C1_URE_R0};

    #[test]
    fn reply_round_trip_and_cross_recipient_rejection() -> Result<(), CryptoError> {
        let recipient = random_scalar()?;
        let other = random_scalar()?;
        let public = scalar_base(&recipient)?;
        let ephemeral = random_scalar()?;
        let sealed = reply_seal_with_scalar(&public, b"payload", b"aad", b"info", &ephemeral)?;
        assert_eq!(
            reply_open(&recipient, &sealed, b"aad", b"info")?,
            b"payload"
        );
        assert_eq!(
            reply_open(&other, &sealed, b"aad", b"info"),
            Err(CryptoError::Authentication)
        );
        Ok(())
    }

    #[test]
    fn public_and_secret_blinding_match() -> Result<(), CryptoError> {
        let secret = random_scalar()?;
        let factor = random_scalar()?;
        let public = scalar_base(&secret)?;
        let blinded_secret = blind_secret(&secret, &factor)?;
        assert_eq!(
            blind_public(&public, &factor)?,
            scalar_base(&blinded_secret)?
        );
        Ok(())
    }

    #[test]
    fn published_c1_reply_kem_vector_reproduces_exactly() -> Result<(), CryptoError> {
        // The reply_kem case fixes the ephemeral secret, so the sealed output
        // is fully determined and can be compared byte-for-byte against the
        // published vector rather than only round-tripped.
        let vectors = test_vectors::crypto_c1().map_err(|_| CryptoError::Initialization)?;
        let get = |path: &str| {
            test_vectors::hex_at(&vectors, path).map_err(|_| CryptoError::Initialization)
        };
        let get32 = |path: &str| {
            test_vectors::hex_array_at::<32>(&vectors, path)
                .map_err(|_| CryptoError::Initialization)
        };

        let root_secret = get32("reply_kem/root_secret")?;
        let root_public = get32("reply_kem/root_public")?;
        assert_eq!(scalar_base(&root_secret)?, root_public, "root public key");

        // Blinding: the blinded secret and blinded public must agree.
        let factor = get32("reply_kem/blinding_factor")?;
        let blinded_public = get32("reply_kem/blinded_public")?;
        let blinded_secret = get32("reply_kem/blinded_secret")?;
        assert_eq!(blind_public(&root_public, &factor)?, blinded_public);
        assert_eq!(blind_secret(&root_secret, &factor)?, blinded_secret);
        assert_eq!(
            scalar_base(&blinded_secret)?,
            get32("reply_kem/public_from_blinded_secret")?,
        );

        // Sealing with the vector's ephemeral scalar is deterministic.
        let ephemeral = get32("reply_kem/ephemeral_secret")?;
        let plaintext = get("reply_kem/plaintext")?;
        let aad = get("reply_kem/aad")?;
        let info = get("reply_kem/info")?;
        let sealed = reply_seal_with_scalar(&blinded_public, &plaintext, &aad, &info, &ephemeral)?;
        assert_eq!(sealed, get("reply_kem/sealed")?, "sealed ciphertext");

        // And the blinded secret opens it back to the published plaintext.
        let opened = reply_open(&blinded_secret, &sealed, &aad, &info)?;
        assert_eq!(opened, get("reply_kem/opened")?, "opened plaintext");
        Ok(())
    }

    #[test]
    fn ristretto_helpers_satisfy_group_laws() -> Result<(), CryptoError> {
        let a = scalar_base(&random_scalar()?)?;
        let b = scalar_base(&random_scalar()?)?;

        // Addition and subtraction are inverse.
        let sum = point_add(&a, &b)?;
        assert_eq!(point_sub(&sum, &b)?, a, "add then sub returns the operand");
        assert_ne!(sum, a);

        // Addition commutes.
        assert_eq!(point_add(&a, &b)?, point_add(&b, &a)?);

        // Hash-to-group is deterministic, domain separated, and valid.
        let first = point_from_label(b"input", DOMAIN_C1_ELEMENT)?;
        assert_eq!(first, point_from_label(b"input", DOMAIN_C1_ELEMENT)?);
        assert_ne!(first, point_from_label(b"input", DOMAIN_C1_SCALAR)?);
        assert_ne!(first, point_from_label(b"other", DOMAIN_C1_ELEMENT)?);
        require_point(&first)?;

        // Hash-to-scalar shares those properties and yields a usable key.
        let scalar = scalar_from_label(b"input", DOMAIN_C1_SCALAR)?;
        assert_eq!(scalar, scalar_from_label(b"input", DOMAIN_C1_SCALAR)?);
        assert_ne!(scalar, scalar_from_label(b"input", DOMAIN_C1_URE_R0)?);
        assert_ne!(scalar, scalar_from_label(b"other", DOMAIN_C1_SCALAR)?);
        let (public, secret) = keypair_from_label(b"input", DOMAIN_C1_SCALAR)?;
        assert_eq!(scalar_base(&secret.0)?, public);

        // Scalar addition is commutative and matches repeated base scaling:
        // (x + y) * B == x*B + y*B.
        let x = random_scalar()?;
        let y = random_scalar()?;
        assert_eq!(scalar_sum(&x, &y)?, scalar_sum(&y, &x)?);
        assert_eq!(
            scalar_base(&scalar_sum(&x, &y)?)?,
            point_add(&scalar_base(&x)?, &scalar_base(&y)?)?,
            "scalar addition is a group homomorphism"
        );
        Ok(())
    }
}
