// SPDX-License-Identifier: Apache-2.0
//! The B1.2 signed seed manifest.
//!
//! Implements `spec/seed-manifest-b12.md` and ADR 0050. A joiner has to learn a
//! candidate from somewhere, and until this the only thing that could fill the
//! candidate cache was an advertisement from a peer the joiner was already
//! talking to.
//!
//! Entries carry an **advertisement key**, not a static admission key. That is
//! what makes a manifest checkable rather than merely followed: ADR 0049 binds
//! an advertisement key to whoever completes an admission exchange.
//!
//! A file, not a datagram: no first-byte discriminator and no padding. The
//! advertisement is one cell wide because its length would otherwise
//! distinguish it on the wire, and a file read from disk has no such observer.

use crate::CookieError;
use protocol_registry::{
    BYTES_B12_SEED_ADDRESS_V4, BYTES_B12_SEED_ADDRESS_V6, BYTES_B12_SEED_SIGNATURE,
    BYTES_X25519_PUBLIC, DOMAIN_B12_SEED_MANIFEST, LIMIT_MAX_SEED_ENTRIES,
    LIMIT_SEED_MANIFEST_TTL_MS, VERSION,
};
use trahens_crypto::{sign, verify, SecretBytes};

type Result<T> = std::result::Result<T, CookieError>;

pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;
/// version + issued + expiry + count.
const HEADER_BYTES: usize = 1 + 8 + 8 + 1;

fn address_bytes(family: u8) -> Option<usize> {
    match family {
        FAMILY_V4 => Some(BYTES_B12_SEED_ADDRESS_V4),
        FAMILY_V6 => Some(BYTES_B12_SEED_ADDRESS_V6),
        _ => None,
    }
}

/// One candidate: where to try, and whose advertisement key to expect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedEntry {
    pub advertisement_key: [u8; BYTES_X25519_PUBLIC],
    pub family: u8,
    pub address: Vec<u8>,
    pub port: u16,
}

impl SeedEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let width = address_bytes(self.family).ok_or(CookieError)?;
        if self.address.len() != width {
            return Err(CookieError);
        }
        out.extend_from_slice(&self.advertisement_key);
        out.push(self.family);
        out.extend_from_slice(&self.address);
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedManifest {
    pub version: u8,
    pub issued_ms: u64,
    pub expiry_ms: u64,
    pub entries: Vec<SeedEntry>,
}

impl SeedManifest {
    /// The signed region.
    ///
    /// # Errors
    ///
    /// [`CookieError`] on an entry count out of range, a lifetime that is
    /// inverted or longer than `seed_manifest_ttl_ms`, or a malformed entry.
    pub fn body(&self) -> Result<Vec<u8>> {
        if self.entries.is_empty() || self.entries.len() > LIMIT_MAX_SEED_ENTRIES {
            return Err(CookieError);
        }
        if self.expiry_ms <= self.issued_ms {
            return Err(CookieError);
        }
        // Bounded ahead of issue, or the expiry would be decoration: an issuer
        // could otherwise write one that never lapses.
        if self.expiry_ms - self.issued_ms > LIMIT_SEED_MANIFEST_TTL_MS as u64 {
            return Err(CookieError);
        }
        let mut out = Vec::with_capacity(HEADER_BYTES + self.entries.len() * 51);
        out.push(self.version);
        out.extend_from_slice(&self.issued_ms.to_be_bytes());
        out.extend_from_slice(&self.expiry_ms.to_be_bytes());
        out.push(u8::try_from(self.entries.len()).map_err(|_| CookieError)?);
        for entry in &self.entries {
            entry.encode(&mut out)?;
        }
        Ok(out)
    }
}

/// Sign the whole body, so no entry can be added, removed or reordered.
///
/// # Errors
///
/// [`CookieError`] if the manifest will not encode or the seed will not sign.
pub fn encode(manifest: &SeedManifest, signing: &SecretBytes<64>) -> Result<Vec<u8>> {
    let body = manifest.body()?;
    let mut signed = Vec::with_capacity(DOMAIN_B12_SEED_MANIFEST.len() + body.len());
    signed.extend_from_slice(DOMAIN_B12_SEED_MANIFEST);
    signed.extend_from_slice(&body);
    let signature = sign(signing, &signed)?;
    let mut document = body;
    document.extend_from_slice(&signature);
    Ok(document)
}

/// Parse and verify against the seed key a joiner holds out of band.
///
/// Every bound is checked before anything is allocated for it, and the expiry
/// after the signature: an expired manifest is a real one that has lapsed, and
/// answering before verifying would answer for documents nobody signed.
///
/// # Errors
///
/// [`CookieError`] for every refusal. A reader is never told which one applied.
pub fn decode(
    document: &[u8],
    seed_key: &[u8; BYTES_X25519_PUBLIC],
    now_ms: u64,
) -> Result<SeedManifest> {
    if document.len() < BYTES_B12_SEED_SIGNATURE + HEADER_BYTES {
        return Err(CookieError);
    }
    let split = document.len() - BYTES_B12_SEED_SIGNATURE;
    let body = document.get(..split).ok_or(CookieError)?;
    let signature: [u8; BYTES_B12_SEED_SIGNATURE] = document
        .get(split..)
        .ok_or(CookieError)?
        .try_into()
        .map_err(|_| CookieError)?;

    let mut signed = Vec::with_capacity(DOMAIN_B12_SEED_MANIFEST.len() + body.len());
    signed.extend_from_slice(DOMAIN_B12_SEED_MANIFEST);
    signed.extend_from_slice(body);
    verify(seed_key, &signed, &signature)?;

    let version = *body.first().ok_or(CookieError)?;
    if version != VERSION {
        return Err(CookieError);
    }
    let issued_ms = u64::from_be_bytes(
        body.get(1..9)
            .ok_or(CookieError)?
            .try_into()
            .map_err(|_| CookieError)?,
    );
    let expiry_ms = u64::from_be_bytes(
        body.get(9..17)
            .ok_or(CookieError)?
            .try_into()
            .map_err(|_| CookieError)?,
    );
    let count = usize::from(*body.get(17).ok_or(CookieError)?);
    // The count is attacker-chosen and is refused before any entry is read, so
    // a reader is not made to work for a number it was handed.
    if count == 0 || count > LIMIT_MAX_SEED_ENTRIES {
        return Err(CookieError);
    }
    if expiry_ms <= issued_ms || expiry_ms - issued_ms > LIMIT_SEED_MANIFEST_TTL_MS as u64 {
        return Err(CookieError);
    }
    if now_ms >= expiry_ms {
        return Err(CookieError);
    }

    let mut entries = Vec::with_capacity(count);
    let mut cursor = HEADER_BYTES;
    for _ in 0..count {
        let advertisement_key: [u8; BYTES_X25519_PUBLIC] = body
            .get(cursor..cursor + BYTES_X25519_PUBLIC)
            .ok_or(CookieError)?
            .try_into()
            .map_err(|_| CookieError)?;
        cursor += BYTES_X25519_PUBLIC;
        let family = *body.get(cursor).ok_or(CookieError)?;
        cursor += 1;
        let width = address_bytes(family).ok_or(CookieError)?;
        let address = body
            .get(cursor..cursor + width)
            .ok_or(CookieError)?
            .to_vec();
        cursor += width;
        let port = u16::from_be_bytes(
            body.get(cursor..cursor + 2)
                .ok_or(CookieError)?
                .try_into()
                .map_err(|_| CookieError)?,
        );
        cursor += 2;
        entries.push(SeedEntry {
            advertisement_key,
            family,
            address,
            port,
        });
    }
    // A reader that ignored a tail would accept a document whose signed region
    // it only partly read.
    if cursor != body.len() {
        return Err(CookieError);
    }
    Ok(SeedManifest {
        version,
        issued_ms,
        expiry_ms,
        entries,
    })
}
