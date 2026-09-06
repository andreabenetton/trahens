// SPDX-License-Identifier: Apache-2.0
//! Check the cookie against the published vectors.
//!
//! The vectors come from the independent Python reference, so agreement here
//! is agreement between two implementations of the same written construction
//! rather than one implementation agreeing with itself.

use admission_b12::{issue, verify, window_id, Secrets, SECRET_BYTES};
use std::error::Error;
use test_vectors::Value;
use trahens_crypto::SecretBytes;

type Fallible<T> = Result<T, Box<dyn Error>>;

fn cases() -> Fallible<Vec<Value>> {
    Ok(test_vectors::b12_cookie()?
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("no cases array")?
        .clone())
}

fn bytes(case: &Value, name: &str) -> Fallible<Vec<u8>> {
    let text = case
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("case is missing {name}"))?;
    Ok(hex::decode(text)?)
}

fn secret(case: &Value) -> Fallible<[u8; SECRET_BYTES]> {
    Ok(bytes(case, "responder_secret")?
        .try_into()
        .map_err(|_| "responder secret is not 32 bytes")?)
}

fn number(case: &Value, name: &str) -> Fallible<u64> {
    case.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("case is missing {name}").into())
}

#[test]
fn every_published_cookie_reproduces() -> Fallible<()> {
    let cases = cases()?;
    assert!(!cases.is_empty(), "the vector publishes no cases");
    for case in &cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let cookie = issue(
            &secret(case)?,
            &bytes(case, "source")?,
            u16::try_from(number(case, "port")?)?,
            number(case, "window")?,
            &bytes(case, "offer")?,
        )?;
        assert_eq!(
            hex::encode(cookie),
            case.get("cookie")
                .and_then(Value::as_str)
                .ok_or("case is missing cookie")?,
            "{name}"
        );
    }
    Ok(())
}

/// The vectors differ in exactly one field each, so no two may collide. The
/// generator refuses to publish a collision; this is the same check on the
/// other side of the wire format.
#[test]
fn no_two_published_cookies_collide() -> Fallible<()> {
    let cases = cases()?;
    let mut seen: Vec<String> = Vec::new();
    for case in &cases {
        let cookie = case
            .get("cookie")
            .and_then(Value::as_str)
            .ok_or("case is missing cookie")?
            .to_owned();
        assert!(!seen.contains(&cookie), "two cases share a cookie");
        seen.push(cookie);
    }
    Ok(())
}

#[test]
fn a_cookie_verifies_in_its_window_and_not_beyond() -> Fallible<()> {
    let secret = [7_u8; SECRET_BYTES];
    let source = [10_u8, 200, 0, 1];
    let offer = b"offered-parameters";
    let window_ms = u64::from(u32::try_from(protocol_registry::LIMIT_COOKIE_WINDOW_MS)?);
    let now = 1_757_000_000_000_u64;

    let cookie = issue(&secret, &source, 41_000, window_id(now), offer)?;
    let secrets = vec![SecretBytes(secret), SecretBytes(secret)];
    assert!(verify(&secrets, &cookie, &source, 41_000, offer, now));
    // One rotation later it must still be accepted, or every boundary would
    // reject senders mid-exchange.
    assert!(verify(
        &secrets,
        &cookie,
        &source,
        41_000,
        offer,
        now + window_ms
    ));
    // Beyond the accepted windows it must not be.
    let beyond = now
        + window_ms
            * u64::from(u32::try_from(
                protocol_registry::LIMIT_COOKIE_WINDOWS_ACCEPTED,
            )?);
    assert!(!verify(&secrets, &cookie, &source, 41_000, offer, beyond));
    Ok(())
}

#[test]
fn a_cookie_is_bound_to_source_port_and_offer() -> Fallible<()> {
    let secret = [7_u8; SECRET_BYTES];
    let source = [10_u8, 200, 0, 1];
    let offer = b"offered-parameters";
    let now = 1_757_000_000_000_u64;
    let cookie = issue(&secret, &source, 41_000, window_id(now), offer)?;
    let secrets = vec![SecretBytes(secret)];

    assert!(!verify(
        &secrets,
        &cookie,
        &[10, 200, 0, 2],
        41_000,
        offer,
        now
    ));
    assert!(!verify(&secrets, &cookie, &source, 41_001, offer, now));
    assert!(!verify(
        &secrets,
        &cookie,
        &source,
        41_000,
        b"different",
        now
    ));
    Ok(())
}

/// Without length prefixes these two inputs would build the same message.
#[test]
fn the_length_prefix_separates_source_from_offer() -> Fallible<()> {
    let secret = [7_u8; SECRET_BYTES];
    assert_ne!(
        issue(&secret, b"AB", 41_000, 7, b"CD")?,
        issue(&secret, b"ABC", 41_000, 7, b"D")?
    );
    Ok(())
}

#[test]
fn rotation_retires_the_oldest_secret() -> Fallible<()> {
    let window_ms = u64::from(u32::try_from(protocol_registry::LIMIT_COOKIE_WINDOW_MS)?);
    let now = 1_757_000_000_000_u64;
    let source = [10_u8, 200, 0, 1];
    let offer = b"offered-parameters";

    let mut secrets = Secrets::new(now, [1_u8; SECRET_BYTES]);
    let cookie = issue(
        &[1_u8; SECRET_BYTES],
        &source,
        41_000,
        window_id(now),
        offer,
    )?;
    assert!(secrets.verify(&cookie, &source, 41_000, offer, now));

    // One rotation: the original secret is still retained.
    secrets.rotate(now + window_ms, [2_u8; SECRET_BYTES]);
    assert!(secrets.verify(&cookie, &source, 41_000, offer, now + window_ms));

    // A second rotation ages it out, so the cookie stops verifying even though
    // only two windows have passed.
    secrets.rotate(now + window_ms * 2, [3_u8; SECRET_BYTES]);
    assert!(!secrets.verify(&cookie, &source, 41_000, offer, now + window_ms * 2));
    Ok(())
}
