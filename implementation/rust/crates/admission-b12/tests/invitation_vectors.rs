// SPDX-License-Identifier: Apache-2.0
//! Check the invitation pre-shared key against the published vectors.

use admission_b12::{invitation_psk, Invitation};
use protocol_registry::{BYTES_B12_INVITATION_ID, BYTES_B12_INVITATION_SECRET};
use std::error::Error;
use test_vectors::Value;

type Fallible<T> = Result<T, Box<dyn Error>>;

fn field(case: &Value, name: &str) -> Fallible<Vec<u8>> {
    let text = case
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("case is missing {name}"))?;
    Ok(hex::decode(text)?)
}

#[test]
fn every_published_psk_reproduces() -> Fallible<()> {
    let document = test_vectors::b12_invitation()?;
    let cases = document
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("no cases array")?;
    assert!(!cases.is_empty(), "the vector publishes no cases");

    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let identifier: [u8; BYTES_B12_INVITATION_ID] = field(case, "identifier")?
            .try_into()
            .map_err(|_| "identifier is not 16 bytes")?;
        let secret: [u8; BYTES_B12_INVITATION_SECRET] = field(case, "secret")?
            .try_into()
            .map_err(|_| "secret is not 32 bytes")?;
        assert_eq!(
            hex::encode(invitation_psk(&identifier, &secret)?),
            case.get("psk")
                .and_then(Value::as_str)
                .ok_or("case is missing psk")?,
            "{name}"
        );
    }
    Ok(())
}

/// The vectors vary one field at a time, so no two may collide. The generator
/// refuses to publish a collision; this is the same check on the other side.
#[test]
fn no_two_published_psks_collide() -> Fallible<()> {
    let document = test_vectors::b12_invitation()?;
    let cases = document
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("no cases array")?;
    let mut seen: Vec<String> = Vec::new();
    for case in cases {
        let psk = case
            .get("psk")
            .and_then(Value::as_str)
            .ok_or("case is missing psk")?
            .to_owned();
        assert!(!seen.contains(&psk), "two cases share a pre-shared key");
        seen.push(psk);
    }
    Ok(())
}

#[test]
fn an_all_zero_secret_is_refused() -> Fallible<()> {
    assert!(Invitation::new(
        [1_u8; BYTES_B12_INVITATION_ID],
        [0_u8; BYTES_B12_INVITATION_SECRET],
        [2_u8; 32]
    )
    .is_err());
    Ok(())
}

#[test]
fn the_identifier_and_the_secret_are_both_bound() -> Fallible<()> {
    let identifier = [1_u8; BYTES_B12_INVITATION_ID];
    let secret = [2_u8; BYTES_B12_INVITATION_SECRET];
    let base = invitation_psk(&identifier, &secret)?;
    assert_ne!(
        base,
        invitation_psk(&[9_u8; BYTES_B12_INVITATION_ID], &secret)?
    );
    assert_ne!(
        base,
        invitation_psk(&identifier, &[9_u8; BYTES_B12_INVITATION_SECRET])?
    );
    Ok(())
}
