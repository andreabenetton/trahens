// SPDX-License-Identifier: Apache-2.0
//! A node joining under an invitation.
//!
//! The joiner half of ADR 0048's exchange: send an initiate with no cookie,
//! take the challenge, resend with the cookie, finish. It pins the inviter,
//! because an invitation is delivered out of band and can carry the inviter's
//! static key; only the inviter is left learning an identity it did not hold.

use link_handshake_b1::{decode_cookie_challenge, Initiator, Keying, Offer};
use node_runtime::handshake::profile;
use node_runtime::{parse_hex, structured_event, CliArgs};
use protocol_registry::{
    BYTES_B1_RECORD, LIMIT_HANDSHAKE_TIMEOUT_MS, SUITE_C1_V2, TRANSPORT_PROFILE_T1, VERSION,
    WIRE_PROFILE_W2,
};
use std::error::Error;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn offer() -> Offer {
    Offer {
        version: VERSION,
        w2_profiles: vec![WIRE_PROFILE_W2],
        t1_profiles: vec![TRANSPORT_PROFILE_T1],
        t2_profiles: vec![protocol_registry::SCHEDULE_PROFILE_T2],
        suites: vec![SUITE_C1_V2],
        resource_class: 1,
    }
}

/// Read one record, or nothing before the deadline.
fn read(socket: &UdpSocket, deadline: Instant) -> Option<Vec<u8>> {
    let mut buffer = vec![0_u8; BYTES_B1_RECORD + 1];
    while Instant::now() < deadline {
        match socket.recv(&mut buffer) {
            Ok(read) => return Some(buffer.get(..read)?.to_vec()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return None,
        }
    }
    None
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = CliArgs::parse()?;
    let static_secret = parse_hex::<32>(args.required("static-secret")?)?;
    let ephemeral = trahens_crypto::random_bytes::<32>()?;
    let identifier = parse_hex::<16>(args.required("invitation-id")?)?;
    let secret = parse_hex::<32>(args.required("invitation-secret")?)?;
    let inviter_static = parse_hex::<32>(args.required("inviter-static")?)?;
    let psk = admission_b12::invitation_psk(&identifier, &secret)?;

    let socket = UdpSocket::bind(args.socket("bind")?)?;
    socket.connect(args.socket("peer")?)?;
    socket.set_nonblocking(true)?;
    let deadline = Instant::now()
        + Duration::from_millis(
            args.u64_or("timeout-ms", (LIMIT_HANDSHAKE_TIMEOUT_MS as u64) * 4)?
                .min(60_000),
        );
    structured_event("join", "started", &[]);

    // A fresh initiator per attempt. The cookie is inside the transcript, so a
    // retry writes its first message again rather than editing the old one.
    let build = |cookie: &[u8]| -> Result<(Initiator, Vec<u8>), Box<dyn Error>> {
        let mut initiator = Initiator::new(
            profile(SUITE_C1_V2),
            static_secret,
            ephemeral,
            offer(),
            Keying::Admission {
                psk: &psk,
                peer_static: Some(inviter_static),
                invitation_id: &identifier,
                cookie,
            },
        )?;
        let record = initiator.write_initiate()?;
        Ok((initiator, record))
    };

    // First attempt: no cookie, because this node has none. It is not a special
    // case -- it is a cookie that will not verify, which is what provokes one.
    let (_, first) = build(&[0_u8; 32])?;
    let mut cookie = None;
    while Instant::now() < deadline && cookie.is_none() {
        socket.send(&first)?;
        let Some(record) = read(&socket, Instant::now() + Duration::from_millis(200)) else {
            continue;
        };
        if let Ok((echoed, fresh)) = decode_cookie_challenge(&profile(SUITE_C1_V2), &record) {
            if echoed == identifier {
                cookie = Some(fresh);
            }
        }
    }
    let Some(cookie) = cookie else {
        structured_event("join", "no_challenge", &[]);
        return Err("the inviter never challenged".into());
    };
    // Published so a harness can hand this cookie to a joiner at a different
    // address and check that it is refused there. A cookie is a correlation
    // handle for as long as it is valid, which is why it is short-lived; a test
    // that could not read one could not check that it is bound.
    structured_event(
        "join",
        "challenged",
        &[("cookie", node_runtime::hex(&cookie))],
    );

    // A cookie supplied on the command line overrides the one just issued, so a
    // scenario can present a cookie that was issued for somewhere else.
    let cookie = match args.optional("cookie", "") {
        "" => cookie,
        supplied => parse_hex::<32>(supplied)?.to_vec(),
    };

    let (mut initiator, second) = build(&cookie)?;

    // Open the exchange and walk away. This is the shape that costs a responder
    // a handshake context for nothing, and the reason handshake_timeout_ms and
    // the backoff exist; a scenario needs a peer that does it on purpose.
    if args.flag("abandon") {
        socket.send(&second)?;
        structured_event("join", "abandoned", &[]);
        return Ok(());
    }

    let session = loop {
        if Instant::now() >= deadline {
            structured_event("join", "no_respond", &[]);
            return Err("the inviter never answered the cookie".into());
        }
        socket.send(&second)?;
        let Some(record) = read(&socket, Instant::now() + Duration::from_millis(200)) else {
            continue;
        };
        if initiator.read_respond(&record).is_ok() {
            let (finish, session) = initiator.write_finish()?;
            socket.send(&finish)?;
            break session;
        }
    };

    structured_event(
        "join",
        "admitted",
        &[
            ("epoch", node_runtime::hex(&session.epoch.to_be_bytes())),
            ("handshake_hash", node_runtime::hex(&session.handshake_hash)),
        ],
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("trahens-join: {error}");
        std::process::exit(1);
    }
}
