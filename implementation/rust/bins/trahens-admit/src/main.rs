// SPDX-License-Identifier: Apache-2.0
//! A node that admits joiners over a listening socket.
//!
//! The first process in this tree that accepts a handshake from a peer it was
//! never configured with. Everything it does is `node_runtime::listener`; this
//! binary is the arguments, the loop, and the events a harness asserts on.
//!
//! It is deliberately not `trahens-relay` or `trahens-endpoint` with a flag.
//! ADR 0045 D7 makes B1.2 additive: a node with discovery disabled speaks
//! exactly what a v1.8 node speaks, and the cleanest way to keep that true —
//! and to keep the P1 fixed-cadence claim untouched — is for the listening path
//! to be a different process rather than a branch inside one that already
//! carries a claim.

use node_runtime::listener::Listener;
use node_runtime::{parse_hex, structured_event, CliArgs};
use protocol_registry::SUITE_C1_V2;
use std::error::Error;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use admission_b12::{Admission, Advertisement, Invitation};
use protocol_registry::{
    LIMIT_CANDIDATE_TTL_MS, SCHEDULE_PROFILE_T2, TRANSPORT_PROFILE_T1, VERSION, WIRE_PROFILE_W2,
};
use std::net::UdpSocket;
use trahens_crypto::random_bytes;

/// One `id:secret` pair, both hex. The inviter's own static public key is not
/// carried here: it is what the joiner pins, and it holds it out of band.
fn invitation(value: &str, inviter_static: [u8; 32]) -> Result<Invitation, Box<dyn Error>> {
    let (identifier, secret) = value
        .split_once(':')
        .ok_or("an invitation is id:secret, both hex")?;
    Ok(Invitation::new(
        parse_hex::<16>(identifier)?,
        parse_hex::<32>(secret)?,
        inviter_static,
    )?)
}

/// One signed advertisement for this node.
///
/// It carries what section 6 permits and nothing else: the short-lived key, an
/// expiry, a capacity class and the profiles offered. Rebuilt each time rather
/// than cached, because the expiry moves with the clock and a stale one would
/// be refused by every receiver that checked it.
fn advertisement(
    secret: &[u8; 32],
    public: [u8; 32],
    now_ms: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let (_, signing) = trahens_crypto::signing_keypair(secret)?;
    let advertisement = Advertisement {
        version: VERSION,
        key: public,
        expiry_ms: now_ms.saturating_add(LIMIT_CANDIDATE_TTL_MS as u64),
        capacity_class: 1,
        auth_modes: 1,
        w2_profiles: vec![WIRE_PROFILE_W2],
        t1_profiles: vec![TRANSPORT_PROFILE_T1],
        t2_profiles: vec![SCHEDULE_PROFILE_T2],
        suites: vec![u16::from_be_bytes(SUITE_C1_V2)],
    };
    Ok(admission_b12::advertisement::encode(
        &advertisement,
        &signing,
    )?)
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = CliArgs::parse()?;
    let static_secret = parse_hex::<32>(args.required("static-secret")?)?;
    let inviter_static = trahens_crypto::x25519_base(&static_secret)?;
    let store = PathBuf::from(args.required("store")?);
    // Distinct from the static secret: a key is never reused across a signature
    // scheme and a Diffie-Hellman one. Short-lived by design, so a fresh one per
    // run is the shape; it is settable so that a seed manifest can name this
    // node, which is the only way a joiner can check it reached who it meant.
    let advertisement_secret = match args.optional("advertisement-secret", "") {
        "" => random_bytes::<32>()?,
        supplied => parse_hex::<32>(supplied)?,
    };
    let advertisement_public = trahens_crypto::signing_keypair(&advertisement_secret)?.0;

    // ADR 0047 D12: the store path is required for any node that can admit, so
    // there is no default and no in-memory fallback. A node that cannot record
    // what it spent does not admit.
    let mut admission = Admission::open(&store)?;
    // Comma-separated rather than a repeated flag: CliArgs is a map, so a
    // repeated --invitation would silently keep only the last one, and an
    // operator would find one joiner admitted out of three with nothing said.
    for value in args.required("invitations")?.split(',') {
        admission.offer(invitation(value, inviter_static)?);
    }
    let offered = admission.live_count();

    let started = Instant::now();
    let mut listener = Listener::bind(
        args.socket("bind")?,
        SUITE_C1_V2,
        static_secret,
        advertisement_secret,
        admission,
        args.u32("first-peer-id")?,
        0,
    )?;
    structured_event(
        "admit",
        "listening",
        &[
            (
                "bind",
                listener
                    .local_addr()
                    .map(|address| address.to_string())
                    .unwrap_or_default(),
            ),
            ("invitations_offered", offered.to_string()),
            // What a joiner pins. An invitation carries it out of band, and a
            // harness reads it here rather than deriving it a second time:
            // a second derivation is a second place to get it wrong.
            ("static_public", node_runtime::hex(&inviter_static)),
            // What a seed manifest would name for this node, and what a joiner
            // checks the transition of ADR 0049 against.
            (
                "advertisement_public",
                node_runtime::hex(&advertisement_public),
            ),
        ],
    );

    // Optional, and off unless asked for. ADR 0045 D7: a node that does not
    // advertise emits exactly what a v1.8 node emits.
    let advertise_to = match args.optional("advertise-to", "") {
        "" => None,
        target => Some(target.parse::<std::net::SocketAddr>()?),
    };
    let advertise_every = Duration::from_millis(args.u64_or("advertise-interval-ms", 200)?.max(1));
    let advertiser = UdpSocket::bind("0.0.0.0:0")?;
    let mut next_advertisement = Instant::now();
    let mut advertisements_sent = 0_u64;

    let deadline =
        Instant::now() + Duration::from_millis(args.u64_or("timeout-ms", 10_000)?.min(120_000));
    // Bounded per turn for the reason poll() is bounded: a flood must not hold
    // this loop past the point where it would do anything else.
    let budget = 32_usize;
    while Instant::now() < deadline {
        let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if let Some(target) = advertise_to {
            if Instant::now() >= next_advertisement {
                let datagram = advertisement(&advertisement_secret, advertisement_public, now_ms)?;
                if advertiser.send_to(&datagram, target).is_ok() {
                    advertisements_sent += 1;
                }
                next_advertisement = Instant::now() + advertise_every;
            }
        }
        for admitted in listener.poll(budget, now_ms)? {
            structured_event(
                "admit",
                "admitted",
                &[
                    ("peer_id", admitted.peer_id.to_string()),
                    ("address", admitted.address.to_string()),
                    ("static_public", node_runtime::hex(&admitted.static_public)),
                ],
            );
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    let metrics = listener.metrics();
    structured_event(
        "admit",
        "stopped",
        &[
            ("datagrams_received", metrics.datagrams_received.to_string()),
            ("challenges_sent", metrics.challenges_sent.to_string()),
            (
                "admissions_completed",
                metrics.admissions_completed.to_string(),
            ),
            ("dropped", metrics.dropped.to_string()),
            ("dropped_by_gate", metrics.dropped_by_gate.to_string()),
            (
                "handshake_contexts_open",
                listener.front().gate().contexts().to_string(),
            ),
            (
                "tracked_sources",
                listener.front().gate().tracked_sources().to_string(),
            ),
            ("advertisements_sent", advertisements_sent.to_string()),
            (
                "advertisements_cached",
                metrics.advertisements_cached.to_string(),
            ),
            // How many candidates this node holds, which is what discovery is
            // for and the only externally visible sign that it happened.
            ("candidates", listener.front().cache().len().to_string()),
        ],
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("trahens-admit: {error}");
        std::process::exit(1);
    }
}
