// SPDX-License-Identifier: Apache-2.0
//! The admission store's failure behaviour, which is the part that matters.
//!
//! A store that round-trips is easy. What ADR 0047 turns on is which damaged
//! states are survivable and which are not, so most of these tests corrupt a
//! file on purpose.

use admission_b12::{Record, Store, StoreError};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

type Fallible<T> = Result<T, Box<dyn Error>>;

/// A scratch path that removes itself, so a failing test does not leave state
/// behind that a later run would load.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("trahens-store-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn spent(byte: u8) -> Record {
    Record::InvitationSpent {
        identifier: [byte; 16],
    }
}

/// ADR 0047 D11: absence is a first run, not an error.
#[test]
fn an_absent_store_starts_empty() -> Fallible<()> {
    let scratch = Scratch::new("absent");
    let store = Store::open(&scratch.0)?;
    assert!(!store.is_spent(&[1_u8; 16]));
    assert_eq!(store.pinned_count(), 0);
    Ok(())
}

#[test]
fn what_was_appended_survives_a_reopen() -> Fallible<()> {
    let scratch = Scratch::new("reopen");
    let mut store = Store::open(&scratch.0)?;
    store.append(&spent(1))?;
    store.append(&Record::PeerPinned {
        peer_id: 7,
        static_public: [9_u8; 32],
    })?;
    drop(store);

    let reloaded = Store::open(&scratch.0)?;
    assert!(reloaded.is_spent(&[1_u8; 16]), "the spent marker survived");
    assert_eq!(reloaded.pinned(7), Some([9_u8; 32]));
    Ok(())
}

/// D9's removal is a withdrawal at this node, and it has to survive too, or a
/// restart would restore a peer that was removed.
#[test]
fn a_removal_survives_a_reopen() -> Fallible<()> {
    let scratch = Scratch::new("removal");
    let mut store = Store::open(&scratch.0)?;
    store.append(&Record::PeerPinned {
        peer_id: 7,
        static_public: [9_u8; 32],
    })?;
    store.append(&Record::PeerRemoved { peer_id: 7 })?;
    drop(store);

    assert_eq!(Store::open(&scratch.0)?.pinned(7), None);
    Ok(())
}

/// A crash during append truncates. The change never took effect, because the
/// flush had not returned, so discarding the partial record is correct and the
/// records before it must still load.
#[test]
fn a_torn_tail_is_discarded_and_the_rest_loads() -> Fallible<()> {
    let scratch = Scratch::new("torn");
    let mut store = Store::open(&scratch.0)?;
    store.append(&spent(1))?;
    store.append(&spent(2))?;
    drop(store);

    let full = fs::read(&scratch.0)?;
    // Every truncation inside the second record is a crash that could have
    // happened, and each must leave the first record intact.
    let first_record = 4 + 17 + 8;
    for cut in first_record + 1..full.len() {
        fs::write(&scratch.0, &full[..cut])?;
        let store = Store::open(&scratch.0)?;
        assert!(store.is_spent(&[1_u8; 16]), "truncated at {cut}");
        assert!(!store.is_spent(&[2_u8; 16]), "truncated at {cut}");
    }
    Ok(())
}

/// D11's distinction. A full record that does not check out is not something a
/// crash produces, so the node refuses rather than admitting on a store it
/// could not read.
#[test]
fn a_damaged_record_fails_closed() -> Fallible<()> {
    let scratch = Scratch::new("damaged");
    let mut store = Store::open(&scratch.0)?;
    store.append(&spent(1))?;
    store.append(&spent(2))?;
    drop(store);

    let mut bytes = fs::read(&scratch.0)?;
    // Flip a byte inside the first record's payload, leaving its checksum and
    // everything after it in place.
    bytes[6] ^= 0x01;
    fs::write(&scratch.0, &bytes)?;
    assert!(matches!(Store::open(&scratch.0), Err(StoreError::Damaged)));
    Ok(())
}

/// Damage in the final record is refused too. Only a *short* tail is a crash
/// artifact; a complete record that fails its checksum is not, wherever it sits.
#[test]
fn a_damaged_last_record_also_fails_closed() -> Fallible<()> {
    let scratch = Scratch::new("damaged-last");
    let mut store = Store::open(&scratch.0)?;
    store.append(&spent(1))?;
    drop(store);

    let mut bytes = fs::read(&scratch.0)?;
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&scratch.0, &bytes)?;
    assert!(matches!(Store::open(&scratch.0), Err(StoreError::Damaged)));
    Ok(())
}

/// A store written by a future version holds records this node cannot reason
/// about, so it refuses rather than silently ignoring what it does not
/// understand — which would be admitting on a store it only partly read.
///
/// The frame is built by hand with a correct checksum, because a tampered type
/// inside an existing frame would fail the checksum first and prove nothing
/// about the unknown-type path.
#[test]
fn an_unknown_record_type_fails_closed() -> Fallible<()> {
    let scratch = Scratch::new("unknown");
    let payload = vec![0x7f_u8, 1, 2, 3];
    let mut input = Vec::from(protocol_registry::DOMAIN_B12_STORE_RECORD);
    input.extend_from_slice(&payload);
    let digest = trahens_crypto::sha256(&input)?;

    let mut framed = Vec::new();
    framed.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
    framed.extend_from_slice(&payload);
    framed.extend_from_slice(&digest[..protocol_registry::BYTES_B12_STORE_CHECKSUM]);
    fs::write(&scratch.0, &framed)?;

    assert!(matches!(Store::open(&scratch.0), Err(StoreError::Damaged)));
    Ok(())
}
