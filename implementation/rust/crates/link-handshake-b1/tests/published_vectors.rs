// SPDX-License-Identifier: Apache-2.0
//! Check this implementation against the published B1.1 vectors.
//!
//! The vectors are normative for the encoding and are themselves cross-checked
//! against an independent Noise implementation in `cross_check_snow.rs`, so
//! agreement here means agreement with Noise and not merely with the Python
//! reference.

use link_handshake_b1::{Initiator, Offer, Profile, Responder, Selection};
use std::error::Error;
use test_vectors::Value;

type Fallible<T> = Result<T, Box<dyn Error>>;

fn registry() -> Fallible<Value> {
    Ok(test_vectors::protocol_registry_v18()?)
}

fn text(parent: &Value, section: &str, name: &str) -> Fallible<String> {
    Ok(parent
        .get(section)
        .and_then(|group| group.get(name))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("registry has no {section}.{name}"))?
        .to_owned())
}

fn number(parent: &Value, section: &str, name: &str) -> Fallible<usize> {
    let value = parent
        .get(section)
        .and_then(|group| group.get(name))
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("registry has no {section}.{name}"))?;
    Ok(usize::try_from(value)?)
}

fn record_type(registry: &Value, name: &str) -> Fallible<u8> {
    Ok(u8::try_from(number(registry, "b1_record_types", name)?)?)
}

fn suite(registry: &Value, name: &str) -> Fallible<[u8; 2]> {
    let value = number(registry, "suites", name)?;
    Ok([u8::try_from(value >> 8)?, u8::try_from(value & 0xff)?])
}

/// Build the profile from the draft registry, the way node-runtime will build
/// it from generated constants once v1.8 is active.
fn profile() -> Fallible<Profile> {
    let registry = registry()?;
    let version = registry
        .get("protocol")
        .and_then(|protocol| protocol.get("version"))
        .and_then(Value::as_u64)
        .ok_or("registry has no protocol.version")?;
    Ok(Profile {
        protocol_version: u8::try_from(version)?,
        noise_protocol: text(&registry, "domain_separators", "b1_noise_protocol")?.into_bytes(),
        noise_protocol_rekey: text(&registry, "domain_separators", "b1_noise_protocol_rekey")?
            .into_bytes(),
        prologue_domain: text(&registry, "domain_separators", "b1_prologue")?.into_bytes(),
        rekey_chain_domain: text(&registry, "domain_separators", "b1_rekey_chain")?.into_bytes(),
        epoch_domain: text(&registry, "domain_separators", "b1_epoch")?.into_bytes(),
        export_domain: text(&registry, "domain_separators", "b1_export")?.into_bytes(),
        record_bytes: number(&registry, "widths_bytes", "b1_record")?,
        record_prefix_bytes: number(&registry, "widths_bytes", "b1_record_prefix")?,
        initiate_payload_bytes: number(&registry, "widths_bytes", "b1_initiate_payload")?,
        initiate_payload_psk_bytes: number(&registry, "widths_bytes", "b1_initiate_payload_psk")?,
        respond_payload_bytes: number(&registry, "widths_bytes", "b1_respond_payload")?,
        finish_payload_bytes: number(&registry, "widths_bytes", "b1_finish_payload")?,
        handshake_record_types: [
            record_type(&registry, "handshake_initiate")?,
            record_type(&registry, "handshake_respond")?,
            record_type(&registry, "handshake_finish")?,
        ],
        rekey_record_types: [
            record_type(&registry, "rekey_initiate")?,
            record_type(&registry, "rekey_respond")?,
            record_type(&registry, "rekey_finish")?,
        ],
        max_offered_per_class: number(&registry, "limits", "max_offered_profiles_per_class")?,
        rejected_suites: vec![
            suite(&registry, "c1_v1_retired")?,
            suite(&registry, "c2_symbolic")?,
            suite(&registry, "c2_k2_disabled")?,
        ],
    })
}

fn vector(rekey: bool) -> Fallible<Value> {
    let document = test_vectors::b1()?;
    document
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or("no vectors array")?
        .iter()
        .find(|candidate| candidate.get("rekey").and_then(Value::as_bool) == Some(rekey))
        .cloned()
        .ok_or_else(|| format!("no vector with rekey={rekey}").into())
}

fn field(vector: &Value, name: &str) -> Fallible<String> {
    Ok(vector
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("vector is missing {name}"))?
        .to_owned())
}

fn key(vector: &Value, name: &str) -> Fallible<[u8; 32]> {
    Ok(hex::decode(field(vector, name)?)?
        .try_into()
        .map_err(|_| format!("{name} is not 32 bytes"))?)
}

fn replay(rekey: bool) -> Fallible<()> {
    let vector = vector(rekey)?;
    let profile = profile()?;
    let chained: Option<[u8; 32]> = if rekey {
        Some(key(&vector, "chained_export_key")?)
    } else {
        None
    };

    // Exactly the offer and selection the vector publishes.
    let offer = Offer {
        version: profile.protocol_version,
        w2_profiles: vec![2],
        t1_profiles: vec![3],
        t2_profiles: vec![4],
        suites: vec![[0x01, 0x01], [0x00, 0x03]],
        resource_class: 1,
    };
    let selection = Selection {
        version: profile.protocol_version,
        w2_profile: 2,
        t1_profile: 3,
        t2_profile: 4,
        suite: [0x01, 0x01],
        resource_class: 1,
    };

    let mut initiator = Initiator::new(
        profile.clone(),
        key(&vector, "initiator_static_secret")?,
        key(&vector, "initiator_ephemeral_secret")?,
        key(&vector, "responder_static_public")?,
        offer,
        chained.as_ref(),
    )?;
    let mut responder = Responder::new(
        profile,
        key(&vector, "responder_static_secret")?,
        key(&vector, "responder_ephemeral_secret")?,
        key(&vector, "initiator_static_public")?,
        chained.as_ref(),
    )?;

    let message_1 = initiator.write_initiate()?;
    assert_eq!(
        hex::encode(&message_1),
        field(&vector, "message_1")?,
        "message 1"
    );
    responder.read_initiate(&message_1)?;

    let message_2 = responder.write_respond(selection)?;
    assert_eq!(
        hex::encode(&message_2),
        field(&vector, "message_2")?,
        "message 2"
    );
    initiator.read_respond(&message_2)?;

    let (message_3, initiator_session) = initiator.write_finish()?;
    assert_eq!(
        hex::encode(&message_3),
        field(&vector, "message_3")?,
        "message 3"
    );
    let responder_session = responder.read_finish(&message_3)?;

    assert_eq!(
        hex::encode(initiator_session.handshake_hash),
        field(&vector, "handshake_hash")?,
        "handshake hash"
    );
    assert_eq!(
        hex::encode(initiator_session.initiator_to_responder.0),
        field(&vector, "initiator_to_responder_key")?,
        "initiator to responder key"
    );
    assert_eq!(
        hex::encode(initiator_session.responder_to_initiator.0),
        field(&vector, "responder_to_initiator_key")?,
        "responder to initiator key"
    );
    assert_eq!(
        hex::encode(initiator_session.export_key.0),
        field(&vector, "export_key")?,
        "export key"
    );
    assert_eq!(
        hex::encode(initiator_session.epoch.to_be_bytes()),
        field(&vector, "epoch")?,
        "epoch"
    );

    // Both ends must land on the same session or the link cannot carry a cell.
    assert_eq!(
        initiator_session.handshake_hash,
        responder_session.handshake_hash
    );
    assert_eq!(
        initiator_session.initiator_to_responder.0,
        responder_session.initiator_to_responder.0
    );
    assert_eq!(initiator_session.epoch, responder_session.epoch);
    assert_eq!(
        initiator_session.export_key.0,
        responder_session.export_key.0
    );
    Ok(())
}

#[test]
fn the_initial_handshake_matches_the_published_vector() -> Fallible<()> {
    replay(false)
}

#[test]
fn the_chained_rekey_matches_the_published_vector() -> Fallible<()> {
    replay(true)
}

#[test]
fn a_derived_epoch_never_begins_with_a_zero_byte() -> Fallible<()> {
    // A handshake record starts with a zero byte, so if a derived epoch could
    // too, a receiver could not tell a record from a W2 cell without trying to
    // decrypt it.
    for rekey in [false, true] {
        let vector = vector(rekey)?;
        let epoch = hex::decode(field(&vector, "epoch")?)?;
        assert_ne!(epoch.first().copied(), Some(0));
        assert_eq!(epoch.first().copied().map(|b| b & 0x80), Some(0x80));
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Refusals. Vectors fix what a correct exchange looks like; these fix what an
// incorrect one must not be allowed to become.
// --------------------------------------------------------------------------

fn parties(
    pin_responder: Option<[u8; 32]>,
    pin_initiator: Option<[u8; 32]>,
) -> Fallible<(Initiator, Responder, Selection)> {
    let vector = vector(false)?;
    let profile = profile()?;
    let offer = Offer {
        version: profile.protocol_version,
        w2_profiles: vec![2],
        t1_profiles: vec![3],
        t2_profiles: vec![4],
        suites: vec![[0x01, 0x01], [0x00, 0x03]],
        resource_class: 1,
    };
    let selection = Selection {
        version: profile.protocol_version,
        w2_profile: 2,
        t1_profile: 3,
        t2_profile: 4,
        suite: [0x01, 0x01],
        resource_class: 1,
    };
    let initiator = Initiator::new(
        profile.clone(),
        key(&vector, "initiator_static_secret")?,
        key(&vector, "initiator_ephemeral_secret")?,
        pin_responder.unwrap_or(key(&vector, "responder_static_public")?),
        offer,
        None,
    )?;
    let responder = Responder::new(
        profile,
        key(&vector, "responder_static_secret")?,
        key(&vector, "responder_ephemeral_secret")?,
        pin_initiator.unwrap_or(key(&vector, "initiator_static_public")?),
        None,
    )?;
    Ok((initiator, responder, selection))
}

#[test]
fn a_responder_static_outside_the_manifest_is_refused() -> Fallible<()> {
    let (mut initiator, mut responder, selection) = parties(Some([9_u8; 32]), None)?;
    responder.read_initiate(&initiator.write_initiate()?)?;
    let respond = responder.write_respond(selection)?;
    // The key authenticates; it is simply not the pinned one.
    assert!(initiator.read_respond(&respond).is_err());
    Ok(())
}

#[test]
fn an_initiator_static_outside_the_manifest_is_refused() -> Fallible<()> {
    let (mut initiator, mut responder, selection) = parties(None, Some([9_u8; 32]))?;
    responder.read_initiate(&initiator.write_initiate()?)?;
    initiator.read_respond(&responder.write_respond(selection)?)?;
    let (finish, _) = initiator.write_finish()?;
    assert!(responder.read_finish(&finish).is_err());
    Ok(())
}

/// A record that fails to open must leave the reader able to try again.
///
/// Section 4 has a peer keep waiting rather than tear the link down, because a
/// record that does not open is usually loss-induced garbage. That is only true
/// if the failed read committed nothing: a transcript that has already absorbed
/// the bad record can never agree with the peer's again, so every retry fails
/// and one datagram ends the exchange. An initial handshake's first message is
/// unencrypted, so producing one costs an attacker nothing.
#[test]
fn a_record_that_fails_to_open_leaves_the_exchange_usable() -> Fallible<()> {
    let (mut initiator, mut responder, selection) = parties(None, None)?;
    let initiate = initiator.write_initiate()?;

    // Well-framed enough to reach the transcript -- right length, right record
    // type -- and rubbish after that. This is what a probe or a corrupted
    // datagram looks like.
    let mut garbage = initiate.clone();
    for byte in garbage.iter_mut().skip(2) {
        *byte ^= 0xff;
    }
    assert!(
        responder.read_initiate(&garbage).is_err(),
        "the garbage record must be refused"
    );

    // The genuine record now has to work, and the whole exchange after it.
    responder.read_initiate(&initiate)?;
    let respond = responder.write_respond(selection)?;

    let mut garbage = respond.clone();
    for byte in garbage.iter_mut().skip(2) {
        *byte ^= 0xff;
    }
    assert!(initiator.read_respond(&garbage).is_err());
    initiator.read_respond(&respond)?;
    let (finish, initiator_session) = initiator.write_finish()?;

    let mut garbage = finish.clone();
    for byte in garbage.iter_mut().skip(2) {
        *byte ^= 0xff;
    }
    assert!(responder.read_finish(&garbage).is_err());
    let responder_session = responder.read_finish(&finish)?;

    assert_eq!(
        initiator_session.handshake_hash, responder_session.handshake_hash,
        "both ends must reach the same transcript despite the refused records"
    );
    Ok(())
}

#[test]
fn a_selection_outside_the_offer_is_refused() -> Fallible<()> {
    let (mut initiator, mut responder, selection) = parties(None, None)?;
    responder.read_initiate(&initiator.write_initiate()?)?;
    let outside = Selection {
        w2_profile: 7,
        ..selection
    };
    assert!(responder.write_respond(outside).is_err());
    Ok(())
}

#[test]
fn a_retired_suite_cannot_be_offered() -> Fallible<()> {
    let profile = profile()?;
    let vector = vector(false)?;
    let retired = Offer {
        version: profile.protocol_version,
        w2_profiles: vec![2],
        t1_profiles: vec![3],
        t2_profiles: vec![4],
        suites: vec![[0x00, 0x01]],
        resource_class: 1,
    };
    let mut initiator = Initiator::new(
        profile,
        key(&vector, "initiator_static_secret")?,
        key(&vector, "initiator_ephemeral_secret")?,
        key(&vector, "responder_static_public")?,
        retired,
        None,
    )?;
    assert!(initiator.write_initiate().is_err());
    Ok(())
}

#[test]
fn tampering_with_the_first_record_breaks_the_transcript() -> Fallible<()> {
    let (mut initiator, mut responder, selection) = parties(None, None)?;
    let mut initiate = initiator.write_initiate()?;
    // The offer is in the clear in an initial handshake, but it is hashed:
    // a modification the responder accepts must still break message 2.
    if let Some(byte) = initiate.get_mut(2) {
        *byte ^= 0x01;
    }
    responder.read_initiate(&initiate)?;
    let respond = responder.write_respond(selection)?;
    assert!(initiator.read_respond(&respond).is_err());
    Ok(())
}

#[test]
fn non_zero_payload_padding_is_refused() -> Fallible<()> {
    let (mut initiator, mut responder, _) = parties(None, None)?;
    let mut initiate = initiator.write_initiate()?;
    if let Some(byte) = initiate.last_mut() {
        *byte ^= 0x01;
    }
    assert!(responder.read_initiate(&initiate).is_err());
    Ok(())
}

#[test]
fn a_rekey_chained_to_another_session_is_refused_before_any_diffie_hellman() -> Fallible<()> {
    let vector = vector(true)?;
    let profile = profile()?;
    let offer = Offer {
        version: profile.protocol_version,
        w2_profiles: vec![2],
        t1_profiles: vec![3],
        t2_profiles: vec![4],
        suites: vec![[0x01, 0x01], [0x00, 0x03]],
        resource_class: 1,
    };
    let mut initiator = Initiator::new(
        profile.clone(),
        key(&vector, "initiator_static_secret")?,
        key(&vector, "initiator_ephemeral_secret")?,
        key(&vector, "responder_static_public")?,
        offer,
        Some(&key(&vector, "chained_export_key")?),
    )?;
    let mut responder = Responder::new(
        profile,
        key(&vector, "responder_static_secret")?,
        key(&vector, "responder_ephemeral_secret")?,
        key(&vector, "initiator_static_public")?,
        Some(&[7_u8; 32]),
    )?;
    // Under psk0 the first record is already encrypted, so the mismatch is
    // caught there rather than after the responder has spent a DH.
    assert!(responder
        .read_initiate(&initiator.write_initiate()?)
        .is_err());
    Ok(())
}
