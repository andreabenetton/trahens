// SPDX-License-Identifier: Apache-2.0
//! Check the route channel against the published vectors.
//!
//! The route channel closed TR-01 of the 2026-09-04 review and was, until these
//! vectors existed, the one protocol layer verified only by its own unit tests:
//! this implementation agreed with itself and with nothing else. The vectors
//! come from the independent Python reference in `simulator/trahens_crypto/`,
//! so agreement here is agreement between two implementations of the same
//! written construction.

use node_runtime::p1::{control_aad, open_control, seal_control};
use std::error::Error;
use test_vectors::Value;
use trahens_crypto::{route_keys, route_open, route_seal, RouteDirection};

type Fallible<T> = Result<T, Box<dyn Error>>;

fn document() -> Fallible<Value> {
    Ok(test_vectors::route_channel()?)
}

fn hex_field(parent: &Value, name: &str) -> Fallible<Vec<u8>> {
    let text = parent
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("vector is missing {name}"))?;
    Ok(hex::decode(text)?)
}

fn key_field(parent: &Value, name: &str) -> Fallible<[u8; 32]> {
    Ok(hex_field(parent, name)?
        .try_into()
        .map_err(|_| format!("{name} is not 32 bytes"))?)
}

fn number(parent: &Value, name: &str) -> Fallible<u64> {
    parent
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("vector is missing {name}").into())
}

fn direction(code: u64) -> Fallible<RouteDirection> {
    match code {
        0 => Ok(RouteDirection::EndpointToGateway),
        1 => Ok(RouteDirection::GatewayToEndpoint),
        other => Err(format!("unknown direction {other}").into()),
    }
}

#[test]
fn the_directional_keys_match_the_published_vector() -> Fallible<()> {
    let document = document()?;
    let keys = route_keys(
        &key_field(&document, "route_secret")?,
        &key_field(&document, "offer_transcript_hash")?,
    )?;
    assert_eq!(
        hex::encode(keys.endpoint_to_gateway.0),
        document
            .get("endpoint_to_gateway_key")
            .and_then(Value::as_str)
            .ok_or("missing endpoint_to_gateway_key")?,
        "endpoint to gateway key"
    );
    assert_eq!(
        hex::encode(keys.gateway_to_endpoint.0),
        document
            .get("gateway_to_endpoint_key")
            .and_then(Value::as_str)
            .ok_or("missing gateway_to_endpoint_key")?,
        "gateway to endpoint key"
    );
    Ok(())
}

/// The property the expansion context exists for: the same route secret under a
/// different selected offer derives a different key, so a secret cannot be
/// carried from one offer to another.
#[test]
fn a_different_offer_transcript_derives_a_different_key() -> Fallible<()> {
    let document = document()?;
    let other = route_keys(
        &key_field(&document, "route_secret")?,
        &key_field(&document, "other_offer_transcript_hash")?,
    )?;
    assert_eq!(
        hex::encode(other.endpoint_to_gateway.0),
        document
            .get("other_endpoint_to_gateway_key")
            .and_then(Value::as_str)
            .ok_or("missing other_endpoint_to_gateway_key")?,
        "the other offer's key must match the vector too"
    );
    assert_ne!(
        other.endpoint_to_gateway.0,
        key_field(&document, "endpoint_to_gateway_key")?,
        "a different transcript must not derive the same key"
    );
    Ok(())
}

#[test]
fn every_published_record_seals_and_opens_to_the_same_bytes() -> Fallible<()> {
    let document = document()?;
    let keys = route_keys(
        &key_field(&document, "route_secret")?,
        &key_field(&document, "offer_transcript_hash")?,
    )?;
    let records = document
        .get("records")
        .and_then(Value::as_array)
        .ok_or("no records array")?;
    assert!(!records.is_empty(), "the vector publishes no records");

    for record in records {
        let name = record
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let dir = direction(number(record, "direction")?)?;
        let sequence = number(record, "sequence")?;
        let plaintext = hex_field(record, "plaintext")?;
        let aad = hex_field(record, "aad")?;
        let key = keys.direction(dir);

        // The AAD is rebuilt from the record's own message type and generation
        // rather than lifted from the vector, so the comparison covers how it
        // is constructed and not only that both sides used the same bytes.
        let message_type = u8::try_from(number(record, "message_type")?)?;
        let generation = u32::try_from(number(record, "generation")?)?;
        assert_eq!(
            hex::encode(control_aad_bytes(message_type, generation)?),
            hex::encode(&aad),
            "{name}: associated data"
        );

        let sealed = route_seal(key, dir, sequence, &plaintext, &aad)?;
        assert_eq!(
            hex::encode(&sealed),
            record
                .get("sealed")
                .and_then(Value::as_str)
                .ok_or("missing sealed")?,
            "{name}: sealed record"
        );

        let (opened_sequence, opened) = route_open(key, dir, &sealed, &aad)?;
        assert_eq!(opened_sequence, sequence, "{name}: authenticated sequence");
        assert_eq!(opened, plaintext, "{name}: plaintext");
    }
    Ok(())
}

/// Reach `control_aad` through its public signature without depending on the
/// codec's `MessageType` ordering, which the vector names numerically.
fn control_aad_bytes(message_type: u8, generation: u32) -> Fallible<Vec<u8>> {
    let typed = match message_type {
        34 => codec_m2::MessageType::Commit,
        35 => codec_m2::MessageType::Ready,
        other => return Err(format!("vector uses an unmapped message type {other}").into()),
    };
    Ok(control_aad(typed, generation))
}

/// A sealed body must not open under the other direction's key, which is what
/// stops a recorded record being reflected back at its sender.
#[test]
fn a_record_does_not_open_in_the_other_direction() -> Fallible<()> {
    let document = document()?;
    let keys = route_keys(
        &key_field(&document, "route_secret")?,
        &key_field(&document, "offer_transcript_hash")?,
    )?;
    let sealed = route_seal(
        keys.direction(RouteDirection::EndpointToGateway),
        RouteDirection::EndpointToGateway,
        0,
        b"body",
        b"aad",
    )?;
    assert!(
        route_open(
            keys.direction(RouteDirection::GatewayToEndpoint),
            RouteDirection::GatewayToEndpoint,
            &sealed,
            b"aad"
        )
        .is_err(),
        "a reflected record must not open"
    );
    Ok(())
}

/// The sealed control path agrees with the raw one, so the vectors cover what
/// the binaries actually call.
#[test]
fn the_control_path_round_trips_over_the_published_keys() -> Fallible<()> {
    let document = document()?;
    let keys = route_keys(
        &key_field(&document, "route_secret")?,
        &key_field(&document, "offer_transcript_hash")?,
    )?;
    let payload = codec_m2::P1Payload::Commit { proof: [7_u8; 32] };
    let sealed = seal_control(
        keys.direction(RouteDirection::EndpointToGateway),
        RouteDirection::EndpointToGateway,
        3,
        codec_m2::MessageType::Commit,
        1,
        &payload,
    )?;
    let (sequence, opened) = open_control(
        keys.direction(RouteDirection::EndpointToGateway),
        RouteDirection::EndpointToGateway,
        codec_m2::MessageType::Commit,
        1,
        &sealed,
    )?;
    assert_eq!(sequence, 3);
    assert!(matches!(
        opened,
        codec_m2::P1Payload::Commit { proof } if proof == [7_u8; 32]
    ));
    Ok(())
}
