// SPDX-License-Identifier: Apache-2.0
//! Reproduce the published seed manifests, and refuse what the spec refuses.
//!
//! Two implementations must parse the same file identically, which is why the
//! encoding is published rather than agreed. The refusals matter more than the
//! round trip: a manifest is a file an attacker may hand a joiner, and the
//! reader is the only thing between the two.

use admission_b12::seed::{decode, encode, FAMILY_V4, FAMILY_V6};
use admission_b12::{SeedEntry, SeedManifest};
use protocol_registry::{LIMIT_MAX_SEED_ENTRIES, LIMIT_SEED_MANIFEST_TTL_MS, VERSION};
use std::error::Error;
use test_vectors::Value;
use trahens_crypto::{signing_keypair, SecretBytes};

type Fallible<T> = Result<T, Box<dyn Error>>;

const SEED: [u8; 32] = [0x5a; 32];

fn published() -> Fallible<Value> {
    Ok(test_vectors::b12_seed_manifest()?)
}

fn field(value: &Value, name: &str) -> Fallible<String> {
    Ok(value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {name}"))?
        .to_owned())
}

fn number(value: &Value, name: &str) -> Fallible<u64> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing {name}").into())
}

fn entry(index: u8, family: u8) -> SeedEntry {
    SeedEntry {
        advertisement_key: [0xc0 + index; 32],
        family,
        address: if family == FAMILY_V4 {
            vec![10, 201, 0, index + 1]
        } else {
            vec![index; 16]
        },
        port: 45_301 + u16::from(index),
    }
}

fn manifest(entries: Vec<SeedEntry>) -> SeedManifest {
    SeedManifest {
        version: VERSION,
        issued_ms: 1_000,
        expiry_ms: 1_000 + 3_600_000,
        entries,
    }
}

fn signing() -> Fallible<SecretBytes<64>> {
    Ok(signing_keypair(&SEED)?.1)
}

fn seed_public() -> Fallible<[u8; 32]> {
    Ok(signing_keypair(&SEED)?.0)
}

/// The whole point of publishing: this implementation writes the same bytes.
#[test]
fn every_published_manifest_reproduces() -> Fallible<()> {
    let document = published()?;
    let signing_seed: [u8; 32] = hex::decode(field(&document, "seed_signing_seed")?)?
        .try_into()
        .map_err(|_| "seed is not 32 bytes")?;
    let (public, secret) = signing_keypair(&signing_seed)?;
    assert_eq!(hex::encode(public), field(&document, "seed_public_key")?);

    let vectors = document
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or("no vectors")?;
    assert!(!vectors.is_empty(), "the file publishes something");
    for vector in vectors {
        let label = field(vector, "label")?;
        let entries = vector
            .get("entries")
            .and_then(Value::as_array)
            .ok_or("no entries")?;
        let mut built = Vec::new();
        for published_entry in entries {
            built.push(SeedEntry {
                advertisement_key: hex::decode(field(published_entry, "advertisement_key")?)?
                    .try_into()
                    .map_err(|_| "advertisement key is not 32 bytes")?,
                family: u8::try_from(number(published_entry, "family")?)?,
                address: hex::decode(field(published_entry, "address")?)?,
                port: u16::try_from(number(published_entry, "port")?)?,
            });
        }
        let rebuilt = SeedManifest {
            version: VERSION,
            issued_ms: number(vector, "issued_ms")?,
            expiry_ms: number(vector, "expiry_ms")?,
            entries: built,
        };
        assert_eq!(
            hex::encode(encode(&rebuilt, &secret)?),
            field(vector, "document")?,
            "{label}"
        );

        // And it reads back what it wrote, at a moment inside the lifetime.
        let parsed = decode(
            &hex::decode(field(vector, "document")?)?,
            &public,
            rebuilt.issued_ms,
        )?;
        assert_eq!(parsed, rebuilt, "{label}");
    }
    Ok(())
}

#[test]
fn a_signature_by_another_key_is_refused() -> Fallible<()> {
    let document = encode(&manifest(vec![entry(0, FAMILY_V4)]), &signing()?)?;
    let (other, _) = signing_keypair(&[0xa5; 32])?;
    assert!(decode(&document, &other, 2_000).is_err());
    Ok(())
}

/// The signature covers the whole body, count included, so no field is
/// alterable and no entry can be dropped.
#[test]
fn tampering_with_any_byte_is_refused() -> Fallible<()> {
    let document = encode(
        &manifest(vec![entry(0, FAMILY_V4), entry(1, FAMILY_V6)]),
        &signing()?,
    )?;
    let public = seed_public()?;
    for position in (0..document.len()).step_by(7) {
        let mut mutated = document.clone();
        mutated[position] ^= 0x01;
        assert!(
            decode(&mutated, &public, 2_000).is_err(),
            "byte {position} was alterable"
        );
    }
    Ok(())
}

#[test]
fn an_expired_manifest_is_refused() -> Fallible<()> {
    let mut expiring = manifest(vec![entry(0, FAMILY_V4)]);
    expiring.expiry_ms = 2_000;
    let document = encode(&expiring, &signing()?)?;
    let public = seed_public()?;
    assert!(decode(&document, &public, 1_999).is_ok());
    assert!(decode(&document, &public, 2_000).is_err());
    Ok(())
}

/// Without this the expiry would be decoration: an issuer could write one that
/// never lapses.
#[test]
fn an_unbounded_lifetime_cannot_be_issued() -> Fallible<()> {
    let mut forever = manifest(vec![entry(0, FAMILY_V4)]);
    forever.issued_ms = 0;
    forever.expiry_ms = u64::try_from(LIMIT_SEED_MANIFEST_TTL_MS)? + 1;
    assert!(encode(&forever, &signing()?).is_err());
    Ok(())
}

#[test]
fn an_empty_or_oversized_manifest_cannot_be_issued() -> Fallible<()> {
    assert!(encode(&manifest(Vec::new()), &signing()?).is_err());
    let many: Vec<SeedEntry> = (0..=LIMIT_MAX_SEED_ENTRIES)
        .map(|index| entry(u8::try_from(index % 200).unwrap_or(0), FAMILY_V4))
        .collect();
    assert!(encode(&manifest(many), &signing()?).is_err());
    Ok(())
}

/// The count is attacker-chosen, so it is refused before any entry is read.
#[test]
fn a_declared_count_beyond_the_bound_is_refused() -> Fallible<()> {
    let mut body = manifest(vec![entry(0, FAMILY_V4)]).body()?;
    body[17] = u8::try_from(LIMIT_MAX_SEED_ENTRIES)? + 1;
    let mut signed = Vec::from(protocol_registry::DOMAIN_B12_SEED_MANIFEST);
    signed.extend_from_slice(&body);
    let signature = trahens_crypto::sign(&signing()?, &signed)?;
    body.extend_from_slice(&signature);
    assert!(decode(&body, &seed_public()?, 2_000).is_err());
    Ok(())
}

#[test]
fn an_unknown_address_family_is_refused() -> Fallible<()> {
    let mut body = manifest(vec![entry(0, FAMILY_V4)]).body()?;
    body[18 + 32] = 7;
    let mut signed = Vec::from(protocol_registry::DOMAIN_B12_SEED_MANIFEST);
    signed.extend_from_slice(&body);
    let signature = trahens_crypto::sign(&signing()?, &signed)?;
    body.extend_from_slice(&signature);
    assert!(decode(&body, &seed_public()?, 2_000).is_err());
    Ok(())
}

/// A reader that ignored a tail would accept a document whose signed region it
/// only partly read.
#[test]
fn trailing_bytes_are_refused() -> Fallible<()> {
    let mut body = manifest(vec![entry(0, FAMILY_V4)]).body()?;
    body.push(0);
    let mut signed = Vec::from(protocol_registry::DOMAIN_B12_SEED_MANIFEST);
    signed.extend_from_slice(&body);
    let signature = trahens_crypto::sign(&signing()?, &signed)?;
    body.extend_from_slice(&signature);
    assert!(decode(&body, &seed_public()?, 2_000).is_err());
    Ok(())
}

/// ADR 0050 D18: a file has no observer its length would inform, so the
/// advertisement's fixed width does not carry over.
#[test]
fn a_manifest_is_not_padded() -> Fallible<()> {
    let one = encode(&manifest(vec![entry(0, FAMILY_V4)]), &signing()?)?.len();
    let two = encode(
        &manifest(vec![entry(0, FAMILY_V4), entry(1, FAMILY_V4)]),
        &signing()?,
    )?
    .len();
    assert_ne!(one, two);
    Ok(())
}
