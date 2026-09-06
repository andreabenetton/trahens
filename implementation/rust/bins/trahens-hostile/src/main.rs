// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! A peer that never completes a handshake and sends adversarial input instead.
//!
//! The harness has never had one. `link-handshake-b1.md` section 8 records the
//! registry bounds on handshake contexts and public-key operations as satisfied
//! by P1's topology rather than enforced, and the reason those have stayed
//! untested is that nothing could misbehave on purpose.
//!
//! What this exercises today is narrower than those bounds and still worth
//! having: a node under adversarial volume on one link must keep its cadence on
//! the others. A link's worker parses every datagram of the right size before
//! it can reject it, and the fixed-T2 claim the P1 gate rests on is a claim
//! about *every* link, not the healthy ones.
//!
//! It substitutes for the initiator through the harness's existing
//! `ENDPOINT_CMD` hook, so it receives the endpoint's whole argument set and
//! uses the three values it needs.

use node_runtime::{structured_event, CliArgs};
use protocol_registry::{B1_RECORD_HANDSHAKE_INITIATE, B1_RECORD_REKEY_INITIATE, BYTES_B1_RECORD};
use std::error::Error;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

/// Datagrams per burst, then a pause. Enough to keep a receiver busy without
/// saturating the host, which would make the victim's schedule prove nothing
/// about the protocol and everything about the load generator.
const BURST: usize = 20;
const PAUSE_MS: u64 = 10;

/// Deterministic filler, so a failing run can be repeated exactly.
fn filler(seed: usize) -> u8 {
    ((seed.wrapping_mul(31).wrapping_add(7)) % 251) as u8
}

/// The shapes worth sending, each reaching a different depth of the receiver.
///
/// A receiver separates a handshake record from a W2 cell by its first byte: a
/// derived epoch never begins with zero. So shape 0 is refused as a cell with
/// an unopenable epoch, and shapes 1 and 2 are routed into the handshake
/// readers, reaching the record prefix, the point decode and the AEAD.
///
/// Every shape is a full cell. Under-length datagrams are deliberately not
/// sent: the harness asserts that every captured UDP payload is exactly one
/// cell, which is a claim about what Trahens emits and worth keeping intact,
/// and the short-input path is already covered by the `b1` fuzz target and by
/// `malformed_records_are_refused_without_panicking`. What this peer adds is
/// volume against a live receiver, not shape coverage.
fn shape(index: usize, round: usize) -> Vec<u8> {
    let mut record = vec![0_u8; BYTES_B1_RECORD];
    for (offset, byte) in record.iter_mut().enumerate() {
        *byte = filler(offset.wrapping_add(round));
    }
    match index % 3 {
        // Looks like a cell: leading byte non-zero, so it is tried as W2.
        0 => {
            record[0] |= 0x80;
            record
        }
        // Well-framed initial handshake record, rubbish after the prefix.
        1 => {
            record[0] = 0;
            record[1] = B1_RECORD_HANDSHAKE_INITIATE;
            record
        }
        // Well-framed rekey record, which an established link routes into the
        // chained reader rather than the initial one.
        _ => {
            record[0] = 0;
            record[1] = B1_RECORD_REKEY_INITIATE;
            record
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = CliArgs::parse()?;
    let socket = UdpSocket::bind(args.socket("bind")?)?;
    socket.connect(args.socket("peer")?)?;
    let deadline =
        Instant::now() + Duration::from_millis(args.u64_or("timeout-ms", 10_000)?.min(60_000));

    structured_event("hostile", "started", &[]);
    let mut sent = 0_u64;
    let mut round = 0_usize;
    while Instant::now() < deadline {
        for index in 0..BURST {
            if socket
                .send(&shape(index.wrapping_add(round), round))
                .is_ok()
            {
                sent = sent.saturating_add(1);
            }
        }
        round = round.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(PAUSE_MS));
    }

    // Reported so the scenario can assert the run was actually hostile. A
    // generator that sent nothing would leave every victim trivially intact,
    // which is the shape of assertion this exists to avoid.
    structured_event(
        "hostile",
        "stopped",
        &[("datagrams_sent", sent.to_string())],
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("trahens-hostile: {error}");
        std::process::exit(1);
    }
}
