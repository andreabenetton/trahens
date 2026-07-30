#![doc = "Minimal libsodium-backed primitives for the Trahens P1 prototype."]

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

fn encode_fields(label: &[u8], fields: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
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

fn reply_seal_with_scalar(
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

fn route_key(route_secret: &[u8; 32]) -> Result<SecretBytes<32>, CryptoError> {
    if *route_secret == [0_u8; 32] {
        return Err(CryptoError::InvalidEncoding);
    }
    let mut input =
        Vec::with_capacity(protocol_registry::DOMAIN_P1_ROUTE_KEY.len() + route_secret.len());
    input.extend_from_slice(protocol_registry::DOMAIN_P1_ROUTE_KEY);
    input.extend_from_slice(route_secret);
    Ok(SecretBytes(hmac_sha256(route_secret, &input)?))
}

pub fn route_seal(
    route_secret: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = route_key(route_secret)?;
    let nonce = random_bytes::<12>()?;
    let ciphertext = aead_seal(&key.0, &nonce, plaintext, aad)?;
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn route_open(
    route_secret: &[u8; 32],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE_BYTES + TAG_BYTES {
        return Err(CryptoError::Authentication);
    }
    let key = route_key(route_secret)?;
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&sealed[..12]);
    aead_open(&key.0, &nonce, &sealed[12..], aad)
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
}
