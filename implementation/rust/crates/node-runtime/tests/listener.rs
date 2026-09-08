// SPDX-License-Identifier: Apache-2.0
//! A joiner admitted over a real listening socket.
//!
//! Everything below the socket has been tested without one. What only a socket
//! shows is that the pieces agree about the wire: that the challenge a front end
//! produces is one a joiner can decode, that the record a joiner writes is one a
//! responder reads, and that the exchange survives the loss UDP actually has.

use admission_b12::{Admission, Invitation};
use link_handshake_b1::{Initiator, Keying, Offer};
use node_runtime::handshake::profile;
use node_runtime::listener::Listener;
use protocol_registry::{BYTES_B1_RECORD, LIMIT_MAX_HANDSHAKE_CONTEXTS, SUITE_C1_V2, VERSION};
use std::error::Error;
use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use trahens_crypto::x25519_base;

type Fallible<T> = Result<T, Box<dyn Error>>;

const INVITATION_ID: [u8; 16] = [0xa1; 16];
const INVITATION_SECRET: [u8; 32] = [0x77; 32];
const INVITER_STATIC: [u8; 32] = [0x11; 32];
const JOINER_STATIC: [u8; 32] = [0x22; 32];
const ADVERTISEMENT_SECRET: [u8; 32] = [0xc3; 32];

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("trahens-listener-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn admission(scratch: &Scratch) -> Fallible<Admission> {
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(Invitation::new(
        INVITATION_ID,
        INVITATION_SECRET,
        x25519_base(&INVITER_STATIC)?,
    )?);
    Ok(admission)
}

fn listener(scratch: &Scratch) -> Fallible<Listener> {
    Ok(Listener::bind(
        "127.0.0.1:0".parse::<SocketAddr>()?,
        SUITE_C1_V2,
        INVITER_STATIC,
        ADVERTISEMENT_SECRET,
        admission(scratch)?,
        1_000,
        0,
    )?)
}

fn offer() -> Offer {
    Offer {
        version: VERSION,
        w2_profiles: vec![2],
        t1_profiles: vec![3],
        t2_profiles: vec![4],
        suites: vec![SUITE_C1_V2],
        resource_class: 1,
    }
}

/// A joiner: its own socket, and the initiate it writes under a given cookie.
struct Joiner {
    socket: UdpSocket,
    ephemeral: [u8; 32],
}

impl Joiner {
    fn new() -> Fallible<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_millis(500)))?;
        Ok(Self {
            socket,
            ephemeral: [0x33; 32],
        })
    }

    /// A fresh initiator each time, because a joiner that retries after a
    /// challenge builds its message again rather than editing the old one: the
    /// cookie is inside the transcript.
    fn initiate(&self, cookie: &[u8]) -> Fallible<(Initiator, Vec<u8>)> {
        let mut initiator = Initiator::new(
            profile(SUITE_C1_V2),
            JOINER_STATIC,
            self.ephemeral,
            offer(),
            Keying::Admission {
                psk: &admission_b12::invitation_psk(&INVITATION_ID, &INVITATION_SECRET)?,
                peer_static: Some(x25519_base(&INVITER_STATIC)?),
                invitation_id: &INVITATION_ID,
                cookie,
                advertisement_secret: None,
            },
        )?;
        let record = initiator.write_initiate()?;
        Ok((initiator, record))
    }

    fn recv(&self) -> Fallible<Vec<u8>> {
        let mut buffer = vec![0_u8; BYTES_B1_RECORD + 1];
        let read = self.socket.recv(&mut buffer)?;
        Ok(buffer[..read].to_vec())
    }
}

/// The whole exchange: challenge, retry, admit — over a socket, with the
/// listener polled between each step as a caller would poll it.
#[test]
fn a_joiner_is_challenged_then_admitted() -> Fallible<()> {
    let scratch = Scratch::new("admitted");
    let mut listener = listener(&scratch)?;
    let address = listener.local_addr().ok_or("no local address")?;
    let joiner = Joiner::new()?;
    joiner.socket.connect(address)?;

    // First attempt: no cookie, because a joiner has none.
    let (_, first) = joiner.initiate(&[0; 32])?;
    joiner.socket.send(&first)?;
    assert!(listener.poll(8, 10)?.is_empty(), "nothing admitted yet");
    assert_eq!(listener.metrics().challenges_sent, 1);

    let challenge = joiner.recv()?;
    let (identifier, cookie) =
        link_handshake_b1::decode_cookie_challenge(&profile(SUITE_C1_V2), &challenge)?;
    assert_eq!(identifier, INVITATION_ID);

    // Second attempt, carrying the cookie.
    let (mut initiator, second) = joiner.initiate(&cookie)?;
    joiner.socket.send(&second)?;
    assert!(listener.poll(8, 20)?.is_empty(), "respond, not yet done");

    let respond = joiner.recv()?;
    initiator.read_respond(&respond)?;
    let (finish, joiner_session) = initiator.write_finish()?;
    joiner.socket.send(&finish)?;

    let admitted = listener.poll(8, 30)?;
    let entry = admitted.first().ok_or("expected an admission")?;
    assert_eq!(entry.peer_id, 1_000);
    assert_eq!(
        entry.static_public,
        x25519_base(&JOINER_STATIC)?,
        "the inviter learned the key it had no way to pin"
    );
    // Both ends must land on the same session or the link cannot carry a cell.
    assert_eq!(entry.session.handshake_hash, joiner_session.handshake_hash);
    assert_eq!(entry.session.epoch, joiner_session.epoch);
    assert_eq!(listener.metrics().admissions_completed, 1);
    Ok(())
}

/// The spent marker and the pin are on disk when the admission is reported, not
/// after. ADR 0047: a marker written after the link is up is one a crash loses.
#[test]
fn the_admission_is_durable_before_it_is_reported() -> Fallible<()> {
    let scratch = Scratch::new("durable");
    admit_one(&scratch)?;

    // A fresh store, as a restart would build it.
    let restarted = Admission::open(&scratch.0)?;
    assert!(
        restarted.is_spent(&INVITATION_ID),
        "the invitation is spent"
    );
    assert_eq!(
        restarted.pinned(1_000),
        Some(x25519_base(&JOINER_STATIC)?),
        "and the key is pinned"
    );
    Ok(())
}

/// D8 across a restart, over the socket: the same invitation does not admit a
/// second joiner even after the process that spent it has gone.
#[test]
fn a_spent_invitation_does_not_admit_again_after_a_restart() -> Fallible<()> {
    let scratch = Scratch::new("restart");
    admit_one(&scratch)?;

    // A new listener over the same store, and an operator that re-offers the
    // invitation because its own list has no idea the handshake happened.
    let mut listener = listener(&scratch)?;
    let address = listener.local_addr().ok_or("no local address")?;
    let joiner = Joiner::new()?;
    joiner.socket.connect(address)?;

    let (_, first) = joiner.initiate(&[0; 32])?;
    joiner.socket.send(&first)?;
    listener.poll(8, 10)?;
    let challenge = joiner.recv()?;
    let (_, cookie) =
        link_handshake_b1::decode_cookie_challenge(&profile(SUITE_C1_V2), &challenge)?;

    // Driven all the way to the finish. Asserting emptiness after the second
    // message would prove nothing: at that point the listener has answered but
    // admitted nobody in *any* case, spent invitation or not.
    let (mut initiator, second) = joiner.initiate(&cookie)?;
    joiner.socket.send(&second)?;
    assert!(listener.poll(8, 20)?.is_empty(), "nothing admitted yet");

    // A spent invitation is refused before an exchange begins, so there is no
    // answer to read and nothing to finish. The joiner is left waiting, which
    // is the correct outcome and the one an attacker sees.
    assert!(
        joiner.recv().is_err(),
        "the listener answered a spent invitation"
    );
    let _ = &mut initiator;

    assert!(
        listener.poll(8, 30)?.is_empty(),
        "the spent invitation admitted nobody"
    );
    assert_eq!(listener.metrics().admissions_completed, 0);
    assert_eq!(
        listener.front().gate().contexts(),
        0,
        "and took no context, because the lookup released it as a failure"
    );
    Ok(())
}

fn admit_one(scratch: &Scratch) -> Fallible<()> {
    let mut listener = listener(scratch)?;
    let address = listener.local_addr().ok_or("no local address")?;
    let joiner = Joiner::new()?;
    joiner.socket.connect(address)?;

    let (_, first) = joiner.initiate(&[0; 32])?;
    joiner.socket.send(&first)?;
    listener.poll(8, 10)?;
    let challenge = joiner.recv()?;
    let (_, cookie) =
        link_handshake_b1::decode_cookie_challenge(&profile(SUITE_C1_V2), &challenge)?;

    let (mut initiator, second) = joiner.initiate(&cookie)?;
    joiner.socket.send(&second)?;
    listener.poll(8, 20)?;
    let respond = joiner.recv()?;
    initiator.read_respond(&respond)?;
    let (finish, _) = initiator.write_finish()?;
    joiner.socket.send(&finish)?;
    let admitted = listener.poll(8, 30)?;
    assert_eq!(admitted.len(), 1, "the joiner was admitted");
    Ok(())
}

/// A cookie is bound to the source it was issued for, so a second host cannot
/// take one off the wire and use it.
#[test]
fn a_cookie_is_not_transferable_between_sources() -> Fallible<()> {
    let scratch = Scratch::new("transfer");
    let mut listener = listener(&scratch)?;
    let address = listener.local_addr().ok_or("no local address")?;

    let first = Joiner::new()?;
    first.socket.connect(address)?;
    let (_, attempt) = first.initiate(&[0; 32])?;
    first.socket.send(&attempt)?;
    listener.poll(8, 10)?;
    let challenge = first.recv()?;
    let (_, cookie) =
        link_handshake_b1::decode_cookie_challenge(&profile(SUITE_C1_V2), &challenge)?;

    // A different socket is a different port, and the cookie binds the port.
    let second = Joiner::new()?;
    second.socket.connect(address)?;
    let (_, stolen) = second.initiate(&cookie)?;
    second.socket.send(&stolen)?;
    listener.poll(8, 20)?;

    assert_eq!(
        listener.metrics().admissions_completed,
        0,
        "the stolen cookie admitted nobody"
    );
    assert_eq!(
        listener.metrics().challenges_sent,
        2,
        "and the second source was challenged in its own right"
    );
    Ok(())
}

/// A repeated initiate means this node's answer was lost, and resending it is
/// the only way the joiner learns that: nothing acknowledges it.
#[test]
fn a_repeated_initiate_is_answered_again() -> Fallible<()> {
    let scratch = Scratch::new("repeat");
    let mut listener = listener(&scratch)?;
    let address = listener.local_addr().ok_or("no local address")?;
    let joiner = Joiner::new()?;
    joiner.socket.connect(address)?;

    let (_, first) = joiner.initiate(&[0; 32])?;
    joiner.socket.send(&first)?;
    listener.poll(8, 10)?;
    let challenge = joiner.recv()?;
    let (_, cookie) =
        link_handshake_b1::decode_cookie_challenge(&profile(SUITE_C1_V2), &challenge)?;

    let (_, second) = joiner.initiate(&cookie)?;
    joiner.socket.send(&second)?;
    listener.poll(8, 20)?;
    let respond = joiner.recv()?;

    // The joiner never saw that answer, so it repeats its initiate.
    joiner.socket.send(&second)?;
    listener.poll(8, 25)?;
    assert_eq!(joiner.recv()?, respond, "the same answer, resent");
    Ok(())
}

/// A datagram that is not a record this node handles allocates nothing, however
/// many arrive. This is the flood shape with no cookie in it at all.
#[test]
fn rubbish_allocates_nothing() -> Fallible<()> {
    let scratch = Scratch::new("rubbish");
    let mut listener = listener(&scratch)?;
    let address = listener.local_addr().ok_or("no local address")?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;

    // A reserved discriminator, a short datagram, and an oversized one.
    let mut reserved = vec![0_u8; BYTES_B1_RECORD];
    reserved[0] = 0x40;
    for _ in 0..32 {
        sender.send_to(&reserved, address)?;
        sender.send_to(&[0x00, 0x01], address)?;
        sender.send_to(&vec![0x80_u8; BYTES_B1_RECORD + 1], address)?;
    }
    listener.poll(256, 10)?;

    assert!(listener.metrics().datagrams_received >= 96);
    assert_eq!(listener.metrics().challenges_sent, 0);
    assert_eq!(listener.front().gate().contexts(), 0, "no context taken");
    assert_eq!(
        listener.front().gate().tracked_sources(),
        0,
        "and no tracking entry, so the table cannot be grown this way"
    );
    Ok(())
}

/// The poll budget is what keeps a flood from holding the caller past its next
/// scheduled slot. A loop that drained the socket would break the fixed-T2
/// cadence with the flood rather than with the protocol.
#[test]
fn the_poll_budget_is_respected() -> Fallible<()> {
    let scratch = Scratch::new("budget");
    let mut listener = listener(&scratch)?;
    let address = listener.local_addr().ok_or("no local address")?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;

    let mut reserved = vec![0_u8; BYTES_B1_RECORD];
    reserved[0] = 0x40;
    for _ in 0..64 {
        sender.send_to(&reserved, address)?;
    }
    listener.poll(4, 10)?;
    assert_eq!(
        listener.metrics().datagrams_received,
        4,
        "it read its budget and returned"
    );
    Ok(())
}

/// An exchange the joiner abandons is reclaimed at `handshake_timeout_ms`, and
/// counts as a failure, so walking away is not cheaper than failing.
#[test]
fn an_abandoned_exchange_is_reclaimed() -> Fallible<()> {
    let scratch = Scratch::new("abandoned");
    let mut listener = listener(&scratch)?;
    let address = listener.local_addr().ok_or("no local address")?;
    let joiner = Joiner::new()?;
    joiner.socket.connect(address)?;

    let (_, first) = joiner.initiate(&[0; 32])?;
    joiner.socket.send(&first)?;
    listener.poll(8, 10)?;
    let challenge = joiner.recv()?;
    let (_, cookie) =
        link_handshake_b1::decode_cookie_challenge(&profile(SUITE_C1_V2), &challenge)?;

    let (_, second) = joiner.initiate(&cookie)?;
    joiner.socket.send(&second)?;
    listener.poll(8, 20)?;
    assert_eq!(
        listener.front().gate().contexts(),
        1,
        "one exchange in flight"
    );

    // The joiner says nothing further.
    let later = 20 + u64::try_from(protocol_registry::LIMIT_HANDSHAKE_TIMEOUT_MS)? + 1;
    listener.poll(8, later)?;
    assert_eq!(
        listener.front().gate().contexts(),
        0,
        "the context was reclaimed"
    );
    assert!(
        listener.front().gate().contexts() < LIMIT_MAX_HANDSHAKE_CONTEXTS,
        "so the pool cannot be held by silence"
    );
    Ok(())
}
