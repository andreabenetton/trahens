// SPDX-License-Identifier: Apache-2.0
#![doc = "Running the B1.1 handshake on a UDP link before any W2 cell exists."]

//! `spec/link-handshake-b1.md` defines the exchange; this module carries it
//! over the wire and turns its output into the link's directional keys and
//! epoch. No W2 cell and no P1 route state may exist on a link until this
//! completes, so it runs to conclusion before the main loop starts.

use link_handshake_b1::{Initiator, Keying, Offer, Profile, Responder, Selection, Session, Stage};
use protocol_registry::{
    B1_RECORD_HANDSHAKE_FINISH, B1_RECORD_HANDSHAKE_INITIATE, B1_RECORD_HANDSHAKE_RESPOND,
    B1_RECORD_REKEY_FINISH, B1_RECORD_REKEY_INITIATE, B1_RECORD_REKEY_RESPOND,
    BYTES_B1_FINISH_PAYLOAD, BYTES_B1_INITIATE_PAYLOAD_PSK, BYTES_B1_RECORD,
    BYTES_B1_RECORD_PREFIX, BYTES_B1_RESPOND_PAYLOAD, DOMAIN_B1_EPOCH, DOMAIN_B1_EXPORT,
    DOMAIN_B1_NOISE_PROTOCOL, DOMAIN_B1_PROLOGUE, DOMAIN_B1_REKEY_CHAIN, DOMAIN_B1_STATIC_PSK,
    LIMIT_HANDSHAKE_TIMEOUT_MS, LIMIT_MAX_HANDSHAKE_RETRANSMITS,
    LIMIT_MAX_OFFERED_PROFILES_PER_CLASS, SCHEDULE_PROFILE_T2, SUITE_C1_V1_RETIRED,
    SUITE_C2_K2_DISABLED, SUITE_C2_SYMBOLIC, TRANSPORT_PROFILE_T1, VERSION, WIRE_PROFILE_W2,
};
use std::net::UdpSocket;
use std::time::{Duration, Instant};
use trahens_crypto::random_bytes;

/// The registry values the handshake needs, from the generated bindings.
///
/// The handshake crate is parameterised rather than hardcoded so that it could
/// be built while v1.8 was still a draft generating no bindings. Now that v1.8
/// is active this is the one place those constants are read.
pub fn profile(suite: [u8; 2]) -> Profile {
    Profile {
        protocol_version: VERSION,
        noise_protocol: DOMAIN_B1_NOISE_PROTOCOL.to_vec(),
        prologue_domain: DOMAIN_B1_PROLOGUE.to_vec(),
        rekey_chain_domain: DOMAIN_B1_REKEY_CHAIN.to_vec(),
        static_psk_domain: DOMAIN_B1_STATIC_PSK.to_vec(),
        epoch_domain: DOMAIN_B1_EPOCH.to_vec(),
        export_domain: DOMAIN_B1_EXPORT.to_vec(),
        record_bytes: BYTES_B1_RECORD,
        record_prefix_bytes: BYTES_B1_RECORD_PREFIX,
        initiate_payload_psk_bytes: BYTES_B1_INITIATE_PAYLOAD_PSK,
        respond_payload_bytes: BYTES_B1_RESPOND_PAYLOAD,
        finish_payload_bytes: BYTES_B1_FINISH_PAYLOAD,
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
    .with_suite(suite)
}

trait WithSuite {
    fn with_suite(self, suite: [u8; 2]) -> Self;
}

impl WithSuite for Profile {
    /// The link's own suite is always offerable even though the rejected list
    /// is fixed: a node configured for the experimental C1 profile must be able
    /// to offer C1.
    fn with_suite(mut self, suite: [u8; 2]) -> Self {
        self.rejected_suites.retain(|rejected| *rejected != suite);
        self
    }
}

/// What this node offers. One entry per class on the mandatory path; a node
/// that supported several would list them here and the transcript would bind
/// the whole set.
fn offer(suite: [u8; 2]) -> Offer {
    Offer {
        version: VERSION,
        w2_profiles: vec![WIRE_PROFILE_W2],
        t1_profiles: vec![TRANSPORT_PROFILE_T1],
        t2_profiles: vec![SCHEDULE_PROFILE_T2],
        suites: vec![suite],
        resource_class: 1,
    }
}

fn selection(suite: [u8; 2]) -> Selection {
    Selection {
        version: VERSION,
        w2_profile: WIRE_PROFILE_W2,
        t1_profile: TRANSPORT_PROFILE_T1,
        t2_profile: SCHEDULE_PROFILE_T2,
        suite,
        resource_class: 1,
    }
}

/// One session's link material, oriented for this node.
pub struct LinkSession {
    pub send: [u8; 32],
    pub receive: [u8; 32],
    pub epoch: u32,
    /// Chains the next rekey.
    pub export: [u8; 32],
}

/// Orient a completed session's two directional keys for this node.
pub fn directional(session: &Session, initiator: bool) -> LinkSession {
    let (send, receive) = if initiator {
        (
            session.initiator_to_responder.0,
            session.responder_to_initiator.0,
        )
    } else {
        (
            session.responder_to_initiator.0,
            session.initiator_to_responder.0,
        )
    };
    LinkSession {
        send,
        receive,
        epoch: session.epoch,
        export: session.export_key.0,
    }
}

/// Classify a datagram that begins with the handshake marker.
///
/// A derived epoch always has its top bit set, so a leading zero byte cannot be
/// a W2 cell. Returns which stage of which exchange the record claims to be;
/// the claim is not trusted beyond dispatch, since the record still has to
/// authenticate.
pub fn record_stage(record: &[u8]) -> Option<(bool, Stage)> {
    if record.len() != BYTES_B1_RECORD || record.first() != Some(&0) {
        return None;
    }
    let kind = *record.get(1)?;
    match kind {
        _ if kind == B1_RECORD_HANDSHAKE_INITIATE => Some((false, Stage::Initiate)),
        _ if kind == B1_RECORD_HANDSHAKE_RESPOND => Some((false, Stage::Respond)),
        _ if kind == B1_RECORD_HANDSHAKE_FINISH => Some((false, Stage::Finish)),
        _ if kind == B1_RECORD_REKEY_INITIATE => Some((true, Stage::Initiate)),
        _ if kind == B1_RECORD_REKEY_RESPOND => Some((true, Stage::Respond)),
        _ if kind == B1_RECORD_REKEY_FINISH => Some((true, Stage::Finish)),
        _ => None,
    }
}

/// Start a rekey as the initiator: the first record and the state to drive it.
pub fn begin_rekey(
    suite: [u8; 2],
    static_secret: [u8; 32],
    peer_static: [u8; 32],
    previous_export: &[u8; 32],
) -> Option<(Initiator, Vec<u8>)> {
    let ephemeral = random_bytes::<32>().ok()?;
    let mut initiator = Initiator::new(
        profile(suite),
        static_secret,
        ephemeral,
        offer(suite),
        Keying::Rekey {
            previous_export,
            peer_static,
        },
    )
    .ok()?;
    let record = initiator.write_initiate().ok()?;
    Some((initiator, record))
}

/// Answer a peer's rekey: the reply record and the state to finish it.
pub fn answer_rekey(
    suite: [u8; 2],
    static_secret: [u8; 32],
    peer_static: [u8; 32],
    previous_export: &[u8; 32],
    initiate: &[u8],
) -> Option<(Responder, Vec<u8>)> {
    let ephemeral = random_bytes::<32>().ok()?;
    let mut responder = Responder::new(
        profile(suite),
        static_secret,
        ephemeral,
        Keying::Rekey {
            previous_export,
            peer_static,
        },
    )
    .ok()?;
    responder.read_initiate(initiate).ok()?;
    let record = responder.write_respond(selection(suite)).ok()?;
    Some((responder, record))
}

/// Which side opens the exchange.
///
/// Both ends cannot initiate, so the lower node identifier does. It is stable,
/// both ends compute it identically, and it is the same rule the T2 rate
/// negotiation already uses for its leader.
pub fn is_initiator(local_id: u32, peer_id: u32) -> bool {
    local_id < peer_id
}

/// Read one handshake record, retransmitting `resend` until the deadline.
///
/// UDP loses records and the peer may not be listening yet, so a handshake that
/// simply blocked would fail on a cold start. Anything that is not a
/// well-formed record for this exchange is discarded without comment: a peer
/// learns nothing from being told why.
fn exchange(
    socket: &UdpSocket,
    resend: Option<&[u8]>,
    deadline: Instant,
    attempts: usize,
) -> Option<Vec<u8>> {
    let mut buffer = vec![0_u8; BYTES_B1_RECORD];
    let interval =
        Duration::from_millis((LIMIT_HANDSHAKE_TIMEOUT_MS / attempts.max(1)).max(1) as u64);
    let mut next_send = Instant::now();
    while Instant::now() < deadline {
        if let Some(record) = resend {
            if Instant::now() >= next_send {
                let _ = socket.send(record);
                next_send = Instant::now() + interval;
            }
        }
        match socket.recv(&mut buffer) {
            Ok(read) if read == BYTES_B1_RECORD => return Some(buffer[..read].to_vec()),
            // A short or oversized datagram is not a handshake record.
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(_) => return None,
        }
    }
    None
}

/// Run the handshake to completion, or fail closed.
///
/// `previous_export` chains a rekey to the session it replaces; `None` is an
/// initial handshake.
/// Returns the session and, for the initiator, the final record.
///
/// The final record has to be retained. It is sent once and nothing in the
/// exchange acknowledges it, so if that datagram is lost the responder waits
/// for a message the initiator believes it has already delivered. The caller
/// keeps it and resends it when the peer repeats its reply, which is the only
/// signal that it never arrived.
pub fn run(
    socket: &UdpSocket,
    local_id: u32,
    peer_id: u32,
    suite: [u8; 2],
    static_secret: [u8; 32],
    peer_static: [u8; 32],
    previous_export: Option<&[u8; 32]>,
) -> Option<(Session, Option<Vec<u8>>)> {
    let profile = profile(suite);
    let deadline = Instant::now() + Duration::from_millis(LIMIT_HANDSHAKE_TIMEOUT_MS as u64);
    let attempts = LIMIT_MAX_HANDSHAKE_RETRANSMITS;
    let ephemeral = random_bytes::<32>().ok()?;
    // P1 links are always manifest-pinned; B1.2 admission does not run here.
    let keying = match previous_export {
        Some(previous_export) => Keying::Rekey {
            previous_export,
            peer_static,
        },
        None => Keying::Manifest { peer_static },
    };

    if is_initiator(local_id, peer_id) {
        let mut initiator =
            Initiator::new(profile, static_secret, ephemeral, offer(suite), keying).ok()?;
        let initiate = initiator.write_initiate().ok()?;
        // Retransmitted until the responder answers: the peer's socket may not
        // be bound yet when a run starts every node at once.
        loop {
            let respond = exchange(socket, Some(&initiate), deadline, attempts)?;
            if initiator.read_respond(&respond).is_ok() {
                break;
            }
            // A record that does not open is either loss-induced garbage or a
            // probe. Keep waiting rather than tearing the link down.
        }
        let (finish, session) = initiator.write_finish().ok()?;
        let _ = socket.send(&finish);
        Some((session, Some(finish)))
    } else {
        let mut responder = Responder::new(profile, static_secret, ephemeral, keying).ok()?;
        let respond = loop {
            let initiate = exchange(socket, None, deadline, attempts)?;
            if responder.read_initiate(&initiate).is_ok() {
                break responder.write_respond(selection(suite)).ok()?;
            }
        };
        loop {
            let finish = exchange(socket, Some(&respond), deadline, attempts)?;
            if let Ok(session) = responder.read_finish(&finish) {
                return Some((session, None));
            }
        }
    }
}
