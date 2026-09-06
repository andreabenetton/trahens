// SPDX-License-Identifier: Apache-2.0
//! Fuzz the B1.1 handshake record readers.
//!
//! These parse the first bytes a link ever receives, from a peer that has not
//! authenticated yet, so they are the most exposed decoder in the system after
//! M2 and W2. Each reader walks a record prefix, a raw X25519 point, an AEAD
//! open and a length-prefixed payload before anything is trusted.
//!
//! The profile comes from `node_runtime`, which is where the registry constants
//! are read; building one here would be the second copy the generated-bindings
//! rule exists to prevent.

#![no_main]

use libfuzzer_sys::fuzz_target;
use link_handshake_b1::{Initiator, Offer, Responder};
use protocol_registry::{SUITE_C1_V2, SUITE_R1, VERSION};

fn offer() -> Offer {
    Offer {
        version: VERSION,
        w2_profiles: vec![2],
        t1_profiles: vec![3],
        t2_profiles: vec![4],
        suites: vec![SUITE_R1, SUITE_C1_V2],
        resource_class: 1,
    }
}

fuzz_target!(|data: &[u8]| {
    // The first byte selects the exchange, so one corpus covers both the
    // initial handshake and the rekey chain rather than only whichever the
    // target happened to hardcode.
    let (selector, record) = match data.split_first() {
        Some(parts) => parts,
        None => return,
    };
    let chained = [0x5a_u8; 32];
    let previous = if selector & 1 == 0 {
        None
    } else {
        Some(&chained)
    };

    let profile = node_runtime::handshake::profile(SUITE_R1);
    let static_secret = [0x11_u8; 32];
    let peer_static = match trahens_crypto::x25519_base(&[0x22_u8; 32]) {
        Ok(value) => value,
        Err(_) => return,
    };

    // A responder reads an initiate, then a finish. Both are reached before the
    // peer has authenticated.
    if let Ok(mut responder) = Responder::new(
        profile.clone(),
        static_secret,
        [0x33_u8; 32],
        peer_static,
        previous,
    ) {
        let _ = responder.read_initiate(record);
        let _ = responder.read_finish(record);
    }

    // An initiator reads a respond. Its state is further along, so this covers
    // the paths a responder's never reaches.
    if let Ok(mut initiator) = Initiator::new(
        profile,
        static_secret,
        [0x44_u8; 32],
        peer_static,
        offer(),
        previous,
    ) {
        let _ = initiator.read_respond(record);
    }
});
