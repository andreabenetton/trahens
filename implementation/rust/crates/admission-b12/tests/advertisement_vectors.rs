// SPDX-License-Identifier: Apache-2.0
//! Check the advertisement encoding against the published vectors.

use admission_b12::advertisement::{decode, encode};
use admission_b12::Advertisement;
use protocol_registry::{B12_DATAGRAM_ADVERTISEMENT, BYTES_B12_ADVERTISEMENT, BYTES_B12_COOKIE};
use std::error::Error;
use test_vectors::Value;
use trahens_crypto::signing_keypair;

type Fallible<T> = Result<T, Box<dyn Error>>;

fn bytes(case: &Value, name: &str) -> Fallible<Vec<u8>> {
    Ok(hex::decode(
        case.get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("case is missing {name}"))?,
    )?)
}

fn number(case: &Value, name: &str) -> Fallible<u64> {
    case.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("case is missing {name}").into())
}

fn list(case: &Value, name: &str) -> Fallible<Vec<u64>> {
    Ok(case
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("case is missing {name}"))?
        .iter()
        .filter_map(Value::as_u64)
        .collect())
}

fn rebuild(case: &Value) -> Fallible<Advertisement> {
    let key: [u8; 32] = bytes(case, "key")?
        .try_into()
        .map_err(|_| "key is not 32 bytes")?;
    let cookie_hex = bytes(case, "cookie")?;
    let cookie = if cookie_hex.is_empty() {
        None
    } else {
        Some(
            <[u8; BYTES_B12_COOKIE]>::try_from(cookie_hex.as_slice())
                .map_err(|_| "cookie is not the registry width")?,
        )
    };
    Ok(Advertisement {
        version: u8::try_from(number(case, "version")?)?,
        key,
        expiry_ms: number(case, "expiry_ms")?,
        capacity_class: u8::try_from(number(case, "capacity_class")?)?,
        auth_modes: u8::try_from(number(case, "auth_modes")?)?,
        w2_profiles: list(case, "w2_profiles")?
            .into_iter()
            .map(u8::try_from)
            .collect::<Result<_, _>>()?,
        t1_profiles: list(case, "t1_profiles")?
            .into_iter()
            .map(u8::try_from)
            .collect::<Result<_, _>>()?,
        t2_profiles: list(case, "t2_profiles")?
            .into_iter()
            .map(u8::try_from)
            .collect::<Result<_, _>>()?,
        suites: list(case, "suites")?
            .into_iter()
            .map(u16::try_from)
            .collect::<Result<_, _>>()?,
        cookie,
    })
}

fn cases() -> Fallible<Vec<Value>> {
    Ok(test_vectors::b12_advertisement()?
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("no cases array")?
        .clone())
}

#[test]
fn every_published_datagram_reproduces() -> Fallible<()> {
    let cases = cases()?;
    assert!(!cases.is_empty(), "the vector publishes no cases");
    for case in &cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let seed: [u8; 32] = bytes(case, "signing_seed")?
            .try_into()
            .map_err(|_| "signing seed is not 32 bytes")?;
        let (public, secret) = signing_keypair(&seed)?;
        let advertisement = rebuild(case)?;
        assert_eq!(public, advertisement.key, "{name}: key follows the seed");
        assert_eq!(
            hex::encode(encode(&advertisement, &secret)?),
            case.get("datagram")
                .and_then(Value::as_str)
                .ok_or("case is missing datagram")?,
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn every_published_datagram_decodes_to_what_it_encoded() -> Fallible<()> {
    for case in &cases()? {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let datagram = bytes(case, "datagram")?;
        assert_eq!(datagram.len(), BYTES_B12_ADVERTISEMENT, "{name}: one cell");
        assert_eq!(datagram[0], B12_DATAGRAM_ADVERTISEMENT, "{name}");
        assert_eq!(decode(&datagram)?, rebuild(case)?, "{name}");
    }
    Ok(())
}

/// The signature covers the discriminator and the whole framed region, padding
/// included, so a change anywhere before it must be caught.
#[test]
fn tampering_anywhere_is_refused() -> Fallible<()> {
    let case = cases()?.into_iter().next().ok_or("no cases")?;
    let datagram = bytes(&case, "datagram")?;
    for offset in [0_usize, 1, 40, 300, 900, BYTES_B12_ADVERTISEMENT - 1] {
        let mut tampered = datagram.clone();
        tampered[offset] ^= 0x01;
        assert!(decode(&tampered).is_err(), "offset {offset} was accepted");
    }
    Ok(())
}

#[test]
fn a_wrong_width_or_discriminator_is_refused() -> Fallible<()> {
    let case = cases()?.into_iter().next().ok_or("no cases")?;
    let datagram = bytes(&case, "datagram")?;
    assert!(decode(&datagram[..datagram.len() - 1]).is_err());
    let mut wrong_type = datagram.clone();
    wrong_type[0] = 0;
    assert!(decode(&wrong_type).is_err());
    Ok(())
}

/// The key that signed must be the key the datagram carries, or an
/// advertisement could be replayed under someone else's identity.
#[test]
fn a_signature_by_another_key_is_refused() -> Fallible<()> {
    let case = cases()?.into_iter().next().ok_or("no cases")?;
    let (_, other) = signing_keypair(&[9_u8; 32])?;
    let forged = encode(&rebuild(&case)?, &other)?;
    assert!(decode(&forged).is_err());
    Ok(())
}

#[test]
fn an_empty_profile_list_is_refused() -> Fallible<()> {
    let case = cases()?.into_iter().next().ok_or("no cases")?;
    let (_, secret) = signing_keypair(&[1_u8; 32])?;
    let mut advertisement = rebuild(&case)?;
    advertisement.w2_profiles.clear();
    assert!(encode(&advertisement, &secret).is_err());
    Ok(())
}
