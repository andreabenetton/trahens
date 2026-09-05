// SPDX-License-Identifier: Apache-2.0
#![doc = "C1 research-suite constructions: URE eligibility capsules and endpoint keys."]

//! C1 is a selectable experimental eligibility profile. It is not part of the
//! mandatory P1 path, which uses R1, and it may not be cited as evidence for a
//! mandatory gate line; but a node started with `--eligibility-suite c1` does
//! emit these constructions on the wire under its own CI gate. ADR 0038
//! originally barred C1 from the wire by construction; ADR 0040 replaced that
//! with a profile restriction.

use crate::{
    encode_fields, point_add, point_from_label, point_sub, require_point, scalar_base,
    scalar_from_label, scalar_mult, sha256, signing_keypair, CryptoError, SecretBytes,
};
use protocol_registry::{DOMAIN_C1_ELEMENT, DOMAIN_C1_LABEL_PREFIX, DOMAIN_C1_SCALAR, SUITE_C1_V2};

/// C1 protocol version byte carried in an endpoint descriptor.
pub const C1_VERSION: u8 = 2;

/// The ristretto255 identity element encoding.
const IDENTITY: [u8; 32] = [0_u8; 32];

/// Encoded length of a URE ciphertext: four ristretto255 elements.
pub const URE_BYTES: usize = 4 * 32;

/// Golle-Jakobsson-Juels-Syverson universally rerandomizable ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UreCiphertext {
    pub u0: [u8; 32],
    pub v0: [u8; 32],
    pub u1: [u8; 32],
    pub v1: [u8; 32],
}

impl UreCiphertext {
    /// Encode as `u0 || v0 || u1 || v1`, rejecting invalid elements.
    pub fn encode(&self) -> Result<[u8; URE_BYTES], CryptoError> {
        for point in [&self.u0, &self.v0, &self.u1, &self.v1] {
            require_point(point)?;
        }
        let mut output = [0_u8; URE_BYTES];
        output[..32].copy_from_slice(&self.u0);
        output[32..64].copy_from_slice(&self.v0);
        output[64..96].copy_from_slice(&self.u1);
        output[96..].copy_from_slice(&self.v1);
        Ok(output)
    }

    /// Decode and validate all four elements.
    pub fn decode(encoded: &[u8]) -> Result<Self, CryptoError> {
        if encoded.len() != URE_BYTES {
            return Err(CryptoError::InvalidEncoding);
        }
        let part = |index: usize| -> Result<[u8; 32], CryptoError> {
            <[u8; 32]>::try_from(&encoded[index * 32..(index + 1) * 32])
                .map_err(|_| CryptoError::InvalidEncoding)
        };
        let value = Self {
            u0: part(0)?,
            v0: part(1)?,
            u1: part(2)?,
            v1: part(3)?,
        };
        for point in [&value.u0, &value.v0, &value.u1, &value.v1] {
            require_point(point)?;
        }
        Ok(value)
    }
}

/// The fixed group element that marks a capsule as eligible.
pub fn eligibility_marker() -> Result<[u8; 32], CryptoError> {
    point_from_label(b"eligibility-marker", DOMAIN_C1_ELEMENT)
}

/// Encrypt the eligibility marker under `recipient_public`.
pub fn ure_encrypt(
    recipient_public: &[u8; 32],
    plaintext: Option<&[u8; 32]>,
    r0: &[u8; 32],
    r1: &[u8; 32],
) -> Result<UreCiphertext, CryptoError> {
    require_point(recipient_public)?;
    let marker = eligibility_marker()?;
    let message = match plaintext {
        Some(value) => {
            require_point(value)?;
            *value
        }
        None => marker,
    };
    Ok(UreCiphertext {
        u0: point_add(&message, &scalar_mult(r0, recipient_public)?)?,
        v0: scalar_base(r0)?,
        u1: scalar_mult(r1, recipient_public)?,
        v1: scalar_base(r1)?,
    })
}

/// Rerandomize without knowing the recipient key.
///
/// `s1` must not be the identity scalar, and the result must differ from the
/// input; both would leave the capsule linkable.
pub fn ure_rerandomize(
    ciphertext: &UreCiphertext,
    s0: &[u8; 32],
    s1: &[u8; 32],
) -> Result<UreCiphertext, CryptoError> {
    let before = ciphertext.encode()?;
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    if *s1 == identity {
        return Err(CryptoError::InvalidEncoding);
    }
    let rerandomized = UreCiphertext {
        u0: point_add(&ciphertext.u0, &scalar_mult(s0, &ciphertext.u1)?)?,
        v0: point_add(&ciphertext.v0, &scalar_mult(s0, &ciphertext.v1)?)?,
        u1: scalar_mult(s1, &ciphertext.u1)?,
        v1: scalar_mult(s1, &ciphertext.v1)?,
    };
    if rerandomized.encode()? == before {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(rerandomized)
}

/// Decrypt to the underlying group element, checking the eligibility branch.
pub fn ure_decrypt(
    recipient_secret: &[u8; 32],
    ciphertext: &UreCiphertext,
) -> Result<[u8; 32], CryptoError> {
    // The second component must cancel exactly: u1 - x*v1 is the identity
    // only for the intended recipient. A capsule for anyone else leaves a
    // non-identity residue.
    let check = point_sub(
        &ciphertext.u1,
        &scalar_mult(recipient_secret, &ciphertext.v1)?,
    )?;
    if check != IDENTITY {
        return Err(CryptoError::InvalidEncoding);
    }
    point_sub(
        &ciphertext.u0,
        &scalar_mult(recipient_secret, &ciphertext.v0)?,
    )
}

/// True when the capsule decrypts to the eligibility marker.
pub fn ure_is_eligible(recipient_secret: &[u8; 32], ciphertext: &UreCiphertext) -> bool {
    match (
        ure_decrypt(recipient_secret, ciphertext),
        eligibility_marker(),
    ) {
        (Ok(message), Ok(marker)) => message == marker,
        _ => false,
    }
}

/// An endpoint's C1 identity: eligibility key, signing key, descriptor, address.
///
/// Deliberately not `Debug`: it holds secrets, and `SecretBytes` is not
/// printable for the same reason.
pub struct EndpointKeys {
    pub eligibility_secret: SecretBytes<32>,
    pub eligibility_public: [u8; 32],
    pub signing_seed: SecretBytes<32>,
    pub signing_public: [u8; 32],
    pub descriptor: Vec<u8>,
    pub address: [u8; 32],
}

/// Derive an endpoint's C1 keys, descriptor, and address from a label.
pub fn build_endpoint_keys(label: &[u8]) -> Result<EndpointKeys, CryptoError> {
    let mut eligibility_label = Vec::with_capacity(16 + label.len());
    eligibility_label.extend_from_slice(b"eligibility-key/");
    eligibility_label.extend_from_slice(label);
    let eligibility_secret = scalar_from_label(&eligibility_label, DOMAIN_C1_SCALAR)?;
    let eligibility_public = scalar_base(&eligibility_secret)?;

    let mut seed_input = Vec::with_capacity(DOMAIN_C1_LABEL_PREFIX.len() + 15 + label.len());
    seed_input.extend_from_slice(DOMAIN_C1_LABEL_PREFIX);
    seed_input.extend_from_slice(b"/signing-seed/");
    seed_input.extend_from_slice(label);
    let signing_seed = sha256(&seed_input)?;
    let (signing_public, _) = signing_keypair(&signing_seed)?;

    let mut descriptor = Vec::with_capacity(1 + 2 + 32 + 32);
    descriptor.push(C1_VERSION);
    descriptor.extend_from_slice(&SUITE_C1_V2);
    descriptor.extend_from_slice(&eligibility_public);
    descriptor.extend_from_slice(&signing_public);
    let address = sha256(&encode_fields(b"endpoint-address", &[&descriptor])?)?;

    Ok(EndpointKeys {
        eligibility_secret: SecretBytes(eligibility_secret),
        eligibility_public,
        signing_seed: SecretBytes(signing_seed),
        signing_public,
        descriptor,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify;

    #[test]
    fn published_c1_eligibility_vector_reproduces_exactly() -> Result<(), CryptoError> {
        let vectors = test_vectors::crypto_c1().map_err(|_| CryptoError::Initialization)?;
        let get = |path: &str| {
            test_vectors::hex_at(&vectors, path).map_err(|_| CryptoError::InvalidEncoding)
        };
        let get32 = |path: &str| {
            test_vectors::hex_array_at::<32>(&vectors, path)
                .map_err(|_| CryptoError::InvalidEncoding)
        };

        // Endpoint identity derived from the label the generator uses.
        let keys = build_endpoint_keys(b"endpoint-alice")?;
        assert_eq!(keys.eligibility_secret.0, get32("eligibility/secret")?);
        assert_eq!(keys.eligibility_public, get32("eligibility/public")?);
        assert_eq!(keys.signing_seed.0, get32("eligibility/signing_seed")?);
        assert_eq!(keys.signing_public, get32("eligibility/signing_public")?);
        assert_eq!(keys.descriptor, get("eligibility/descriptor")?);
        assert_eq!(keys.address, get32("eligibility/address")?);

        // The marker is a fixed group element.
        assert_eq!(eligibility_marker()?, get32("eligibility/marker")?);

        // Encryption with the vector's scalars is deterministic.
        let capsule = ure_encrypt(
            &keys.eligibility_public,
            None,
            &get32("eligibility/r0")?,
            &get32("eligibility/r1")?,
        )?;
        assert_eq!(
            capsule.encode()?.to_vec(),
            get("eligibility/ciphertext")?,
            "URE ciphertext"
        );

        // Rerandomization is likewise reproducible and stays eligible.
        let rerandomized = ure_rerandomize(
            &capsule,
            &get32("eligibility/s0")?,
            &get32("eligibility/s1")?,
        )?;
        assert_eq!(
            rerandomized.encode()?.to_vec(),
            get("eligibility/rerandomized_ciphertext")?,
            "rerandomized URE ciphertext"
        );

        assert_eq!(
            ure_decrypt(&keys.eligibility_secret.0, &rerandomized)?,
            get32("eligibility/decrypted_marker")?
        );
        assert_eq!(
            ure_is_eligible(&keys.eligibility_secret.0, &rerandomized),
            test_vectors::bool_at(&vectors, "eligibility/eligible")
                .map_err(|_| CryptoError::InvalidEncoding)?
        );

        // A different key must not be eligible.
        let other = build_endpoint_keys(b"endpoint-mallory")?;
        assert_eq!(
            ure_is_eligible(&other.eligibility_secret.0, &rerandomized),
            test_vectors::bool_at(&vectors, "eligibility/wrong_key_eligible")
                .map_err(|_| CryptoError::InvalidEncoding)?
        );

        // The published candidate signature verifies under the signing key.
        let transcript = get32("candidate_authentication/transcript_hash")?;
        let signature = get("candidate_authentication/signature")?;
        let signature =
            <[u8; 64]>::try_from(signature.as_slice()).map_err(|_| CryptoError::InvalidEncoding)?;
        assert!(verify(&keys.signing_public, &transcript, &signature).is_ok());
        Ok(())
    }

    #[test]
    fn rerandomization_rejects_the_identity_scalar() -> Result<(), CryptoError> {
        let keys = build_endpoint_keys(b"endpoint-alice")?;
        let capsule = ure_encrypt(
            &keys.eligibility_public,
            None,
            &crate::random_scalar()?,
            &crate::random_scalar()?,
        )?;
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        // s1 = 1 leaves the second component untouched, which would leave the
        // capsule linkable across hops.
        assert!(ure_rerandomize(&capsule, &crate::random_scalar()?, &identity).is_err());
        Ok(())
    }
}
