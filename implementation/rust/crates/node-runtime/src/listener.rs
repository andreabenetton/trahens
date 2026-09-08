// SPDX-License-Identifier: Apache-2.0
//! The listening socket.
//!
//! Every node until now bound one socket per configured link and connected it to
//! that peer, so the kernel dropped everything else before the process saw it.
//! This binds one socket and accepts from anyone, which is what B1.2 is for and
//! what makes `link-handshake-b1.md` section 8's bounds live rather than
//! structural.
//!
//! The decision about an arriving datagram is not made here. `admission_b12`'s
//! front end owns it, testable against adversarial input without a network, and
//! this module is the part that could not be: a socket, a clock, and the
//! exchanges currently in flight.
//!
//! **Exchanges are kept per source rather than run inline.** Driving a handshake
//! to completion inside the receive loop would serialise admission: one joiner
//! that fell silent would hold every other joiner out for `handshake_timeout_ms`,
//! and `max_handshake_contexts` would never be the binding constraint because
//! the socket would be. Holding a responder per source is what makes that bound
//! mean what it says.

use crate::handshake::{profile, selection};
use admission_b12::{
    Admission, Datagram, Disposition, DropReason, FrontEnd, Grant, Lease, Secrets, SECRET_BYTES,
};
use link_handshake_b1::{Keying, Profile, Responder, Session};
use protocol_registry::{
    BYTES_B1_RECORD, LIMIT_COOKIE_WINDOW_MS, LIMIT_HANDSHAKE_TIMEOUT_MS, VERSION,
};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use trahens_crypto::random_bytes;

/// Why a listener could not start or could not continue.
#[derive(Debug)]
pub enum ListenError {
    Io(std::io::Error),
    /// The admission store would not load. ADR 0047 D11: a node that cannot
    /// read what it already spent does not start.
    Store,
    /// Randomness failed, so no cookie secret could be produced.
    Entropy,
}

impl std::fmt::Display for ListenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "listener io: {error}"),
            Self::Store => formatter.write_str("admission store would not load"),
            Self::Entropy => formatter.write_str("no randomness for a cookie secret"),
        }
    }
}

impl std::error::Error for ListenError {}

impl From<std::io::Error> for ListenError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// A joiner that completed an admission handshake.
///
/// No `Debug`: it carries a [`Session`], and the registry classes keys as
/// never-logged. A type that could be formatted is one a diagnostic print will
/// eventually format.
pub struct Admitted {
    pub peer_id: u32,
    pub address: SocketAddr,
    pub session: Session,
    /// The static key the joiner presented, now pinned and on disk.
    pub static_public: [u8; 32],
}

/// What one turn of the loop did. Counted rather than logged per datagram: a
/// listener under flood would otherwise spend its time writing about it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ListenerMetrics {
    pub datagrams_received: u64,
    pub challenges_sent: u64,
    pub admissions_completed: u64,
    pub cells_forwarded: u64,
    pub advertisements_cached: u64,
    /// Refused for any reason. The front end distinguishes them; this is the
    /// total, and `dropped_by_gate` is the one an operator watches.
    pub dropped: u64,
    pub dropped_by_gate: u64,
}

/// An admission exchange this node has answered and is waiting on.
struct Pending {
    responder: Responder,
    lease: Lease,
    invitation_id: Vec<u8>,
    /// Retained because nothing acknowledges it: if the joiner's finish is lost
    /// it repeats its initiate, and this is what answers that repeat.
    respond: Vec<u8>,
    deadline_ms: u64,
}

pub struct Listener {
    socket: UdpSocket,
    front: FrontEnd,
    secrets: Secrets,
    suite: [u8; 2],
    /// Built once. It holds several owned domain strings, and rebuilding it per
    /// datagram would let a flood set the allocation rate.
    profile: Profile,
    static_secret: [u8; 32],
    /// ADR 0049 D16: an admitting node holds one whether or not it has
    /// advertised, because a responder that could decline to bind itself would
    /// present a joiner with the case it cannot tell apart from an attack.
    advertisement_secret: [u8; 32],
    pending: HashMap<SocketAddr, Pending>,
    next_peer_id: u32,
    metrics: ListenerMetrics,
    /// When the cookie secret was last rotated, in the caller's clock.
    rotated_ms: u64,
}

impl Listener {
    /// Bind, load the admission store, and start with a fresh cookie secret.
    ///
    /// # Errors
    ///
    /// [`ListenError::Store`] if the store exists and does not parse, which is
    /// ADR 0047 D11 refusing to start rather than admitting on a store it could
    /// not read; [`ListenError::Io`] on a bind failure.
    pub fn bind(
        bind: SocketAddr,
        suite: [u8; 2],
        static_secret: [u8; 32],
        advertisement_secret: [u8; 32],
        admission: Admission,
        first_peer_id: u32,
        now_ms: u64,
    ) -> Result<Self, ListenError> {
        let socket = UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        let secret = random_bytes::<SECRET_BYTES>().map_err(|_| ListenError::Entropy)?;
        Ok(Self {
            socket,
            front: FrontEnd::new().with_admission(admission),
            secrets: Secrets::new(now_ms, secret),
            suite,
            profile: profile(suite),
            static_secret,
            advertisement_secret,
            pending: HashMap::new(),
            next_peer_id: first_peer_id,
            metrics: ListenerMetrics::default(),
            rotated_ms: now_ms,
        })
    }

    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok()
    }

    #[must_use]
    pub fn metrics(&self) -> ListenerMetrics {
        self.metrics
    }

    #[must_use]
    pub fn front(&self) -> &FrontEnd {
        &self.front
    }

    /// Read and act on at most `budget` datagrams, returning what was admitted.
    ///
    /// Bounded rather than draining, so a flood cannot keep the caller inside
    /// this function past its next scheduled slot. The fixed-T2 cadence is a
    /// claim about a constant rate, and a receive loop that ran until the socket
    /// was empty would break it with the flood rather than with the protocol.
    ///
    /// # Errors
    ///
    /// [`ListenError::Io`] on a socket error other than would-block.
    pub fn poll(&mut self, budget: usize, now_ms: u64) -> Result<Vec<Admitted>, ListenError> {
        self.rotate(now_ms)?;
        self.expire(now_ms);

        let mut admitted = Vec::new();
        // One byte more than a record, so an oversized datagram is visibly
        // oversized rather than silently truncated to the right width.
        let mut buffer = vec![0_u8; BYTES_B1_RECORD + 1];
        for _ in 0..budget {
            let (read, from) = match self.socket.recv_from(&mut buffer) {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(ListenError::Io(error)),
            };
            self.metrics.datagrams_received += 1;
            let bytes = buffer.get(..read).unwrap_or_default().to_vec();
            if let Some(entry) = self.act(&bytes, from, now_ms) {
                admitted.push(entry);
            }
        }
        Ok(admitted)
    }

    /// Act on one datagram. Infallible for the same reason
    /// [`Self::continue_exchange`] is: every outcome but completion is a
    /// datagram this node declines to act on.
    fn act(&mut self, bytes: &[u8], from: SocketAddr, now_ms: u64) -> Option<Admitted> {
        // An exchange already in flight is answered before the front end sees
        // the datagram: this source holds a lease, so the front end's job of
        // deciding whether to allocate one is already done.
        if self.pending.contains_key(&from) {
            return self.continue_exchange(bytes, from, now_ms);
        }

        let source = address_bytes(from);
        let datagram = Datagram {
            source: &source,
            port: from.port(),
            bytes,
            now_ms,
        };
        match self.front.receive(&datagram, &self.secrets, &self.profile) {
            Disposition::Challenge(record) => {
                self.metrics.challenges_sent += 1;
                let _ = self.socket.send_to(&record, from);
                None
            }
            Disposition::Admit(grant) => {
                self.begin_exchange(*grant, bytes, from, now_ms);
                None
            }
            Disposition::Cached(_) => {
                self.metrics.advertisements_cached += 1;
                None
            }
            Disposition::ToLink => {
                self.metrics.cells_forwarded += 1;
                None
            }
            // A configured peer's manifest handshake does not run here: those
            // links own their own connected sockets, and mixing the two would
            // give a peer two paths to the same state.
            Disposition::Handshake(lease) => {
                self.front.gate_mut().failed(lease, now_ms);
                self.metrics.dropped += 1;
                None
            }
            Disposition::Drop(reason) => {
                self.metrics.dropped += 1;
                if matches!(reason, DropReason::Gate(_)) {
                    self.metrics.dropped_by_gate += 1;
                }
                None
            }
        }
    }

    fn begin_exchange(&mut self, grant: Grant, initiate: &[u8], from: SocketAddr, now_ms: u64) {
        let Ok(ephemeral) = random_bytes::<32>() else {
            self.front.gate_mut().failed(grant.lease, now_ms);
            return;
        };
        let keying = Keying::Admission {
            psk: &grant.psk,
            // The inviter has no manifest entry for a joiner, so it records the
            // presented key rather than checking it.
            peer_static: None,
            invitation_id: &grant.invitation_id,
            cookie: &grant.cookie,
            advertisement_secret: Some(&self.advertisement_secret),
        };
        let Ok(mut responder) =
            Responder::new(self.profile.clone(), self.static_secret, ephemeral, keying)
        else {
            self.front.gate_mut().failed(grant.lease, now_ms);
            return;
        };
        if responder.read_initiate(initiate).is_err() {
            self.front.gate_mut().failed(grant.lease, now_ms);
            return;
        }
        let Ok(respond) = responder.write_respond(selection(self.suite)) else {
            self.front.gate_mut().failed(grant.lease, now_ms);
            return;
        };
        let _ = self.socket.send_to(&respond, from);
        self.pending.insert(
            from,
            Pending {
                responder,
                lease: grant.lease,
                invitation_id: grant.invitation_id,
                respond,
                deadline_ms: now_ms.saturating_add(LIMIT_HANDSHAKE_TIMEOUT_MS as u64),
            },
        );
    }

    /// Feed a record to an exchange already in flight.
    ///
    /// Infallible by construction: every outcome other than completion is a
    /// datagram this node declines to act on, and a peer is never told which.
    /// Nothing here can fail in a way the caller could do something about.
    fn continue_exchange(
        &mut self,
        bytes: &[u8],
        from: SocketAddr,
        now_ms: u64,
    ) -> Option<Admitted> {
        let pending = self.pending.get_mut(&from)?;
        if bytes.len() != BYTES_B1_RECORD {
            self.metrics.dropped += 1;
            return None;
        }
        // Read once. A reader that tried twice would advance the transcript on
        // the first attempt and could not agree with the peer on the second.
        let Ok(session) = pending.responder.read_finish(bytes) else {
            // Anything else from this source is a repeated initiate, meaning
            // this node's answer was lost. Resending it is the only way the
            // joiner learns that, since nothing acknowledges it.
            let respond = pending.respond.clone();
            let _ = self.socket.send_to(&respond, from);
            self.metrics.dropped += 1;
            return None;
        };
        let static_public = pending.responder.promoted_static()?;
        let invitation_id = pending.invitation_id.clone();

        let pending = self.pending.remove(&from)?;
        let peer_id = self.next_peer_id;

        // Durable before complete, per ADR 0047. A spent marker written after
        // the link is up is one a crash can lose, and losing it re-opens the
        // invitation this exchange just consumed.
        let Ok(identifier) = <[u8; 16]>::try_from(invitation_id.as_slice()) else {
            self.front.gate_mut().failed(pending.lease, now_ms);
            return None;
        };
        let recorded = self
            .front
            .admission_mut()
            .map(|admission| admission.admit(&identifier, peer_id, static_public));
        if !matches!(recorded, Some(Ok(()))) {
            // The record did not reach disk, so the admission did not happen.
            // Failing here rather than proceeding is what keeps the marker and
            // the link from disagreeing after a crash.
            self.front.gate_mut().failed(pending.lease, now_ms);
            return None;
        }

        self.front.gate_mut().succeeded(pending.lease);
        self.front.link_established(&address_bytes(from), peer_id);
        self.next_peer_id = self.next_peer_id.saturating_add(1);
        self.metrics.admissions_completed += 1;
        Some(Admitted {
            peer_id,
            address: from,
            session,
            static_public,
        })
    }

    /// Drop exchanges past `handshake_timeout_ms`, returning their contexts.
    fn expire(&mut self, now_ms: u64) {
        let stale: Vec<SocketAddr> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline_ms <= now_ms)
            .map(|(address, _)| *address)
            .collect();
        for address in stale {
            if let Some(pending) = self.pending.remove(&address) {
                self.front.gate_mut().failed(pending.lease, now_ms);
            }
        }
        self.front.gate_mut().sweep(now_ms);
    }

    /// Install a fresh cookie secret once the window has moved on.
    fn rotate(&mut self, now_ms: u64) -> Result<(), ListenError> {
        let window = LIMIT_COOKIE_WINDOW_MS as u64;
        if now_ms.saturating_sub(self.rotated_ms) < window.max(1) {
            return Ok(());
        }
        let fresh = random_bytes::<SECRET_BYTES>().map_err(|_| ListenError::Entropy)?;
        self.secrets.rotate(now_ms, fresh);
        self.rotated_ms = now_ms;
        Ok(())
    }
}

/// The observed source as the cookie binds it: the address bytes, with the port
/// carried separately.
fn address_bytes(address: SocketAddr) -> Vec<u8> {
    match address {
        SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
        SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
    }
}

/// The protocol version a listener speaks, for a caller that offers it.
#[must_use]
pub fn version() -> u8 {
    VERSION
}
