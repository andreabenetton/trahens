// SPDX-License-Identifier: Apache-2.0
//! What the first message does **not** prove, asserted rather than described.
//!
//! `spec/link-handshake-b1.md` section 4.2 states three limits of the `psk0`
//! prefilter, and an external review
//! (`docs/external-review-2026-09-08.md`, B1-A) established the first of them by
//! argument. An argument in a specification is a claim about the code that
//! nothing checks: it can be right when written and wrong two commits later,
//! and the failure mode is a specification that describes a weakness the code no
//! longer has, or worse, misses one it has grown.
//!
//! The published-vector tests next door cannot cover this. They check that two
//! implementations agree on the bytes of a well-formed exchange, which is a
//! different question from what an attacker gets out of a malformed or replayed
//! one. The review said as much: byte-for-byte agreement is not what finds
//! these.
//!
//! A test here failing does not necessarily mean something broke. It may mean
//! the weakness was fixed and section 4.2 needs to stop claiming it.

use link_handshake_b1::{Initiator, Keying, Offer, Profile, Responder, Selection};
use protocol_registry::{
    B1_RECORD_HANDSHAKE_FINISH, B1_RECORD_HANDSHAKE_INITIATE, B1_RECORD_HANDSHAKE_RESPOND,
    B1_RECORD_REKEY_FINISH, B1_RECORD_REKEY_INITIATE, B1_RECORD_REKEY_RESPOND, BYTES_B12_COOKIE,
    BYTES_B12_INVITATION_ID, BYTES_B1_ADMISSION_HEADER, BYTES_B1_ADMISSION_PAYLOAD,
    BYTES_B1_FINISH_PAYLOAD, BYTES_B1_INITIATE_PAYLOAD_PSK, BYTES_B1_RECORD,
    BYTES_B1_RECORD_PREFIX, BYTES_B1_RESPOND_PAYLOAD, DOMAIN_B1_EPOCH, DOMAIN_B1_EXPORT,
    DOMAIN_B1_NOISE_PROTOCOL, DOMAIN_B1_PROLOGUE, DOMAIN_B1_REKEY_CHAIN, DOMAIN_B1_REKEY_PSK,
    DOMAIN_B1_STATIC_PSK, DOMAIN_B1_TRANSITION, LIMIT_MAX_OFFERED_PROFILES_PER_CLASS,
    SCHEDULE_PROFILE_T2, SUITE_C1_V1_RETIRED, SUITE_C1_V2, SUITE_C2_K2_DISABLED, SUITE_C2_SYMBOLIC,
    TRANSPORT_PROFILE_T1, VERSION, WIRE_PROFILE_W2,
};
use std::error::Error;
use trahens_crypto::x25519_base;

type Fallible<T> = Result<T, Box<dyn Error>>;

const B1_RECORD_ADMISSION_INITIATE: u8 = protocol_registry::B1_RECORD_ADMISSION_INITIATE;
const B1_RECORD_COOKIE_CHALLENGE: u8 = protocol_registry::B1_RECORD_COOKIE_CHALLENGE;

fn profile() -> Profile {
    Profile {
        protocol_version: VERSION,
        noise_protocol: DOMAIN_B1_NOISE_PROTOCOL.to_vec(),
        prologue_domain: DOMAIN_B1_PROLOGUE.to_vec(),
        rekey_chain_domain: DOMAIN_B1_REKEY_CHAIN.to_vec(),
        rekey_psk_domain: DOMAIN_B1_REKEY_PSK.to_vec(),
        static_psk_domain: DOMAIN_B1_STATIC_PSK.to_vec(),
        epoch_domain: DOMAIN_B1_EPOCH.to_vec(),
        export_domain: DOMAIN_B1_EXPORT.to_vec(),
        record_bytes: BYTES_B1_RECORD,
        record_prefix_bytes: BYTES_B1_RECORD_PREFIX,
        initiate_payload_psk_bytes: BYTES_B1_INITIATE_PAYLOAD_PSK,
        respond_payload_bytes: BYTES_B1_RESPOND_PAYLOAD,
        finish_payload_bytes: BYTES_B1_FINISH_PAYLOAD,
        admission_header_bytes: BYTES_B1_ADMISSION_HEADER,
        admission_payload_bytes: BYTES_B1_ADMISSION_PAYLOAD,
        invitation_id_bytes: BYTES_B12_INVITATION_ID,
        cookie_bytes: BYTES_B12_COOKIE,
        transition_domain: DOMAIN_B1_TRANSITION.to_vec(),
        admission_initiate_type: B1_RECORD_ADMISSION_INITIATE,
        cookie_challenge_type: B1_RECORD_COOKIE_CHALLENGE,
        handshake_record_types: [
            B1_RECORD_HANDSHAKE_INITIATE,
            B1_RECORD_HANDSHAKE_RESPOND,
            B1_RECORD_HANDSHAKE_FINISH,
        ],
        rekey_record_types: [
            B1_RECORD_REKEY_INITIATE,
            B1_RECORD_REKEY_RESPOND,
            B1_RECORD_REKEY_FINISH,
        ],
        max_offered_per_class: LIMIT_MAX_OFFERED_PROFILES_PER_CLASS,
        rejected_suites: vec![SUITE_C1_V1_RETIRED, SUITE_C2_SYMBOLIC, SUITE_C2_K2_DISABLED],
    }
}

fn offer() -> Offer {
    Offer {
        version: VERSION,
        w2_profiles: vec![WIRE_PROFILE_W2],
        t1_profiles: vec![TRANSPORT_PROFILE_T1],
        t2_profiles: vec![SCHEDULE_PROFILE_T2],
        suites: vec![SUITE_C1_V2],
        resource_class: 1,
    }
}

fn selection() -> Selection {
    Selection {
        version: VERSION,
        w2_profile: WIRE_PROFILE_W2,
        t1_profile: TRANSPORT_PROFILE_T1,
        t2_profile: SCHEDULE_PROFILE_T2,
        suite: SUITE_C1_V2,
        resource_class: 1,
    }
}

/// Distinct secrets that do not depend on the RNG, so a failure reproduces.
fn secret(tag: u8) -> [u8; 32] {
    let mut value = [tag; 32];
    value[0] = tag.wrapping_add(1);
    value
}

/// A responder as it exists after a restart: same static key, fresh ephemeral,
/// no memory of anything it saw before.
fn responder(static_secret: [u8; 32], peer_static: [u8; 32], ephemeral: u8) -> Fallible<Responder> {
    Ok(Responder::new(
        profile(),
        static_secret,
        secret(ephemeral),
        Keying::Manifest { peer_static },
    )?)
}

/// B1-A. A recorded first message stays valid, and a responder that never saw
/// it before answers it.
///
/// This is the property section 4.2 rests on. The first message carries no
/// responder freshness: its ephemeral is the initiator's own and every other
/// field is fixed by the pair, so nothing in it goes stale. The second
/// responder here is a restarted one -- same static key, fresh ephemeral, empty
/// state -- which is exactly the case a process-local replay cache would not
/// catch.
#[test]
fn a_recorded_first_message_is_answered_by_a_restarted_responder() -> Fallible<()> {
    let initiator_static = secret(0x11);
    let responder_static = secret(0x22);
    let initiator_public = x25519_base(&initiator_static)?;
    let responder_public = x25519_base(&responder_static)?;

    let mut initiator = Initiator::new(
        profile(),
        initiator_static,
        secret(0x33),
        offer(),
        Keying::Manifest {
            peer_static: responder_public,
        },
    )?;
    let recorded = initiator.write_initiate()?;

    // The genuine exchange, so the record is known to be one a responder acts
    // on. Without this the replay below could be answered by a responder that
    // answers anything, and the test would prove nothing.
    let mut first = responder(responder_static, initiator_public, 0x44)?;
    first.read_initiate(&recorded)?;
    first.write_respond(selection())?;

    // Now the attacker. It holds the recorded bytes and nothing else: no static
    // secret, no ephemeral secret, no session state.
    let mut restarted = responder(responder_static, initiator_public, 0x55)?;
    restarted.read_initiate(&recorded)?;
    let answer = restarted.write_respond(selection())?;

    assert_eq!(
        answer.len(),
        BYTES_B1_RECORD,
        "the restarted responder answered a replay with a full record"
    );
    assert_eq!(
        answer.get(1).copied(),
        Some(B1_RECORD_HANDSHAKE_RESPOND),
        "and the answer is a respond, so the attempt was spent"
    );
    Ok(())
}

/// The other half of B1-A, and the reason it is a starvation attack rather than
/// a disclosure one: the replayer cannot finish.
///
/// The responder is now committed to an initiator ephemeral whose private key
/// nobody present holds. A genuine initiator arriving afterwards cannot rescue
/// it either -- its own fresh exchange is a different transcript -- which is
/// what makes winning the race worth doing.
#[test]
fn the_replayer_cannot_finish_what_it_started() -> Fallible<()> {
    let initiator_static = secret(0x11);
    let responder_static = secret(0x22);
    let initiator_public = x25519_base(&initiator_static)?;
    let responder_public = x25519_base(&responder_static)?;

    let mut initiator = Initiator::new(
        profile(),
        initiator_static,
        secret(0x33),
        offer(),
        Keying::Manifest {
            peer_static: responder_public,
        },
    )?;
    let recorded = initiator.write_initiate()?;

    let mut restarted = responder(responder_static, initiator_public, 0x66)?;
    restarted.read_initiate(&recorded)?;
    let answer = restarted.write_respond(selection())?;

    // A second, genuine initiator: the real peer reconnecting after the race
    // was lost. It holds every secret, and it still cannot complete the
    // responder's state, because that state is bound to the recorded ephemeral
    // and not to this one.
    let mut genuine = Initiator::new(
        profile(),
        initiator_static,
        secret(0x77),
        offer(),
        Keying::Manifest {
            peer_static: responder_public,
        },
    )?;
    let fresh_initiate = genuine.write_initiate()?;
    assert!(
        genuine.read_respond(&answer).is_err(),
        "a fresh initiator must not be able to adopt the replayed exchange"
    );

    // Run the genuine peer's exchange to completion against a responder that
    // did receive its first message, and offer that third message to the
    // stranded one. It is a valid record from the pinned peer, and it still
    // does not release the state the replay committed: the transcripts differ.
    let mut healthy = responder(responder_static, initiator_public, 0x88)?;
    healthy.read_initiate(&fresh_initiate)?;
    let healthy_answer = healthy.write_respond(selection())?;
    let mut genuine = Initiator::new(
        profile(),
        initiator_static,
        secret(0x77),
        offer(),
        Keying::Manifest {
            peer_static: responder_public,
        },
    )?;
    genuine.write_initiate()?;
    genuine.read_respond(&healthy_answer)?;
    let (finish, _) = genuine.write_finish()?;
    assert!(
        restarted.read_finish(&finish).is_err(),
        "the stranded responder must not accept the genuine peer's finish"
    );
    healthy.read_finish(&finish)?;
    Ok(())
}
