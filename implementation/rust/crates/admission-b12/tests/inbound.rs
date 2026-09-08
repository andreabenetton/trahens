// SPDX-License-Identifier: Apache-2.0
//! What a listening socket does with datagrams it did not ask for.
//!
//! The classification tests matter more than they look. Section 3's reserved
//! range is only a reservation if a receiver refuses it; a receiver that lets it
//! fall through to the cell path drops it too, for the wrong reason, and every
//! datagram type added later disappears into that path with no way to tell.

use admission_b12::{
    classify, Advertisement, Disposition, DropReason, FrontEnd, Kind, Secrets, SECRET_BYTES,
};
use protocol_registry::{
    BYTES_B12_ADVERTISEMENT, BYTES_B1_RECORD, LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF, VERSION,
};
use std::error::Error;
use trahens_crypto::signing_keypair;

type Fallible<T> = Result<T, Box<dyn Error>>;

fn secrets() -> Secrets {
    Secrets::new(0, [7_u8; SECRET_BYTES])
}

fn handshake_record() -> Vec<u8> {
    let mut datagram = vec![0_u8; BYTES_B1_RECORD];
    datagram[1] = 1; // handshake_initiate
    datagram
}

fn signed_advertisement(expiry_ms: u64) -> Fallible<Vec<u8>> {
    let (verifying, signing) = signing_keypair(&[0x5a_u8; 32])?;
    let advertisement = Advertisement {
        version: VERSION,
        key: verifying,
        expiry_ms,
        capacity_class: 1,
        auth_modes: 1,
        w2_profiles: vec![2],
        t1_profiles: vec![3],
        t2_profiles: vec![4],
        suites: vec![3],
        cookie: None,
    };
    Ok(admission_b12::advertisement::encode(
        &advertisement,
        &signing,
    )?)
}

#[test]
fn the_first_byte_allocation_matches_section_three() {
    assert_eq!(classify(&[]), None);
    assert_eq!(classify(&[0x00]), Some(Kind::Handshake));
    assert_eq!(classify(&[0x01]), Some(Kind::Advertisement));
    for byte in 0x02_u8..=0x7f {
        assert_eq!(classify(&[byte]), Some(Kind::Reserved), "byte {byte:#04x}");
    }
    for byte in [0x80_u8, 0xc0, 0xff] {
        assert_eq!(classify(&[byte]), Some(Kind::Cell), "byte {byte:#04x}");
    }
}

/// The reservation is only real if it is refused as a reservation. A receiver
/// that let this fall through to the cell path would also drop it — and would
/// swallow every type added later, indistinguishably.
#[test]
fn a_reserved_discriminator_is_refused_as_reserved() {
    let mut front = FrontEnd::new();
    let secrets = secrets();
    for byte in [0x02_u8, 0x40, 0x7f] {
        let mut datagram = vec![0_u8; BYTES_B1_RECORD];
        datagram[0] = byte;
        assert_eq!(
            front.receive(b"source", &datagram, &secrets, 1_000),
            Disposition::Drop(DropReason::ReservedDiscriminator),
            "byte {byte:#04x}"
        );
    }
}

#[test]
fn an_empty_datagram_is_malformed() {
    let mut front = FrontEnd::new();
    assert_eq!(
        front.receive(b"source", &[], &secrets(), 1_000),
        Disposition::Drop(DropReason::Malformed)
    );
}

/// A cell from a stranger has nothing to open it with. Allocating on one is
/// precisely what the connected-socket topology made impossible for free.
#[test]
fn a_cell_from_an_unknown_source_allocates_nothing() {
    let mut front = FrontEnd::new();
    let cell = vec![0x80_u8; BYTES_B1_RECORD];
    assert_eq!(
        front.receive(b"stranger", &cell, &secrets(), 1_000),
        Disposition::Drop(DropReason::NoSuchLink)
    );
    assert_eq!(front.gate().contexts(), 0);
    assert_eq!(front.gate().tracked_sources(), 0);
}

#[test]
fn a_cell_from_an_established_source_goes_to_its_link() {
    let mut front = FrontEnd::new();
    front.link_established(b"peer", 7);
    let cell = vec![0x80_u8; BYTES_B1_RECORD];
    assert_eq!(
        front.receive(b"peer", &cell, &secrets(), 1_000),
        Disposition::ToLink
    );
    assert_eq!(front.peer_at(b"peer"), Some(7));

    front.link_lost(b"peer");
    assert_eq!(
        front.receive(b"peer", &cell, &secrets(), 1_000),
        Disposition::Drop(DropReason::NoSuchLink)
    );
}

/// Until the admission datagram's framing is specified there is no path for a
/// stranger's handshake, and the honest behaviour is to refuse before any state
/// rather than to allocate and fail later.
#[test]
fn a_handshake_from_a_stranger_allocates_nothing() {
    let mut front = FrontEnd::new();
    assert_eq!(
        front.receive(b"stranger", &handshake_record(), &secrets(), 1_000),
        Disposition::Drop(DropReason::NoAdmissionPath)
    );
    assert_eq!(front.gate().contexts(), 0);
    assert_eq!(
        front.gate().tracked_sources(),
        0,
        "and leaves no tracking entry either"
    );
}

/// A configured peer is vouched for by the manifest and still passes the gate:
/// section 8's bounds are the answer to an authenticated peer misbehaving,
/// which is the case a manifest cannot rule out.
#[test]
fn a_handshake_from_a_configured_peer_takes_a_context() -> Fallible<()> {
    let mut front = FrontEnd::new();
    front.link_established(b"peer", 7);
    let Disposition::Handshake(lease) =
        front.receive(b"peer", &handshake_record(), &secrets(), 1_000)
    else {
        return Err("expected a handshake lease".into());
    };
    assert_eq!(front.gate().contexts(), 1);
    front.gate_mut().succeeded(lease);
    assert_eq!(front.gate().contexts(), 0);
    Ok(())
}

/// The gate is reachable through the receive path, not only when called
/// directly: a configured peer that fails repeatedly is backed off here too.
#[test]
fn a_misbehaving_peer_is_backed_off_through_the_receive_path() -> Fallible<()> {
    let mut front = FrontEnd::new();
    front.link_established(b"peer", 7);
    for _ in 0..LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF {
        let Disposition::Handshake(lease) =
            front.receive(b"peer", &handshake_record(), &secrets(), 1_000)
        else {
            return Err("expected a handshake lease".into());
        };
        front.gate_mut().failed(lease, 1_000);
    }
    assert!(matches!(
        front.receive(b"peer", &handshake_record(), &secrets(), 1_000),
        Disposition::Drop(DropReason::Gate(_))
    ));
    Ok(())
}

#[test]
fn a_handshake_record_of_the_wrong_width_is_malformed() {
    let mut front = FrontEnd::new();
    front.link_established(b"peer", 7);
    let mut short = handshake_record();
    short.truncate(BYTES_B1_RECORD - 1);
    assert_eq!(
        front.receive(b"peer", &short, &secrets(), 1_000),
        Disposition::Drop(DropReason::Malformed)
    );
    assert_eq!(
        front.gate().contexts(),
        0,
        "width is checked before the gate"
    );
}

#[test]
fn a_verified_advertisement_is_cached_and_nothing_else() -> Fallible<()> {
    let mut front = FrontEnd::new();
    let datagram = signed_advertisement(60_000)?;
    assert!(matches!(
        front.receive(b"advertiser", &datagram, &secrets(), 1_000),
        Disposition::Cached(_)
    ));
    assert_eq!(front.cache().len(), 1);
    // D6: discovery allocated no handshake context and no tracking entry.
    assert_eq!(front.gate().contexts(), 0);
    assert_eq!(front.gate().tracked_sources(), 0);
    Ok(())
}

#[test]
fn a_tampered_advertisement_is_not_cached() -> Fallible<()> {
    let mut front = FrontEnd::new();
    let mut datagram = signed_advertisement(60_000)?;
    let last = datagram.len() - 1;
    datagram[last] ^= 0x01;
    assert_eq!(
        front.receive(b"advertiser", &datagram, &secrets(), 1_000),
        Disposition::Drop(DropReason::Unverified)
    );
    assert!(front.cache().is_empty());
    Ok(())
}

#[test]
fn an_advertisement_of_the_wrong_width_is_malformed() -> Fallible<()> {
    let mut front = FrontEnd::new();
    let mut datagram = signed_advertisement(60_000)?;
    datagram.truncate(BYTES_B12_ADVERTISEMENT - 1);
    assert_eq!(
        front.receive(b"advertiser", &datagram, &secrets(), 1_000),
        Disposition::Drop(DropReason::Malformed)
    );
    Ok(())
}

/// An expired advertisement verifies and is still refused: the signature says
/// who wrote it, not that it is worth keeping.
#[test]
fn an_expired_advertisement_verifies_and_is_still_refused() -> Fallible<()> {
    let mut front = FrontEnd::new();
    let datagram = signed_advertisement(1_000)?;
    assert!(matches!(
        front.receive(b"advertiser", &datagram, &secrets(), 1_000),
        Disposition::Drop(DropReason::Cache(_))
    ));
    assert!(front.cache().is_empty());
    Ok(())
}
