// SPDX-License-Identifier: Apache-2.0
//! What ADR 0046 D8 and D9 claim, checked across a restart.
//!
//! The single-use property is only worth anything if it survives one, so every
//! test that matters here reopens the store rather than asserting against the
//! in-memory copy that just wrote it.

use admission_b12::{Admission, AdmissionError, Invitation};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

type Fallible<T> = Result<T, Box<dyn Error>>;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("trahens-admission-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

const ALICE: [u8; 16] = [0xa1; 16];
const BOB: [u8; 16] = [0xb0; 16];

fn invitation(identifier: [u8; 16], secret: u8) -> Result<Invitation, AdmissionError> {
    Invitation::new(identifier, [secret; 32], [0x11; 32]).map_err(|_| AdmissionError::Derivation)
}

#[test]
fn an_offered_invitation_keys_a_handshake() -> Fallible<()> {
    let scratch = Scratch::new("offered");
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(invitation(ALICE, 7)?);

    // The derivation is the published one, not a second copy of it.
    let expected = admission_b12::invitation_psk(&ALICE, &[7_u8; 32])?;
    assert_eq!(admission.psk_for(&ALICE)?, expected);
    Ok(())
}

#[test]
fn an_identifier_that_was_never_issued_is_refused() -> Fallible<()> {
    let scratch = Scratch::new("unknown");
    let admission = Admission::open(&scratch.0)?;
    assert_eq!(
        admission.psk_for(&ALICE),
        Err(AdmissionError::UnknownInvitation)
    );
    Ok(())
}

/// D8's whole point, and the reason ADR 0047 exists: a restart must not re-open
/// an invitation that has already admitted someone.
#[test]
fn a_spent_invitation_stays_spent_across_a_restart() -> Fallible<()> {
    let scratch = Scratch::new("spent");
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(invitation(ALICE, 7)?);
    admission.admit(&ALICE, 1, [0x22; 32])?;
    drop(admission);

    // A fresh process, and the operator re-offers the same invitation because
    // its list of what it handed out has no idea the handshake happened.
    let mut restarted = Admission::open(&scratch.0)?;
    restarted.offer(invitation(ALICE, 7)?);
    assert_eq!(restarted.psk_for(&ALICE), Err(AdmissionError::AlreadySpent));
    assert_eq!(
        restarted.admit(&ALICE, 2, [0x33; 32]),
        Err(AdmissionError::AlreadySpent)
    );
    assert_eq!(restarted.pinned(2), None, "no second peer was admitted");
    Ok(())
}

#[test]
fn a_promoted_key_survives_a_restart() -> Fallible<()> {
    let scratch = Scratch::new("promoted");
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(invitation(ALICE, 7)?);
    admission.admit(&ALICE, 1, [0x22; 32])?;
    drop(admission);

    assert_eq!(Admission::open(&scratch.0)?.pinned(1), Some([0x22; 32]));
    Ok(())
}

/// Two joiners, two secrets. Spending one must leave the other usable, or a
/// single admission would close the whole invitation list.
#[test]
fn spending_one_invitation_leaves_the_others_live() -> Fallible<()> {
    let scratch = Scratch::new("others");
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(invitation(ALICE, 7)?);
    admission.offer(invitation(BOB, 8)?);
    admission.admit(&ALICE, 1, [0x22; 32])?;

    assert!(admission.psk_for(&BOB).is_ok());
    assert_eq!(admission.live_count(), 1, "the spent one is no longer live");
    Ok(())
}

/// Two joiners must not derive the same key, which is what makes "one cannot
/// impersonate another" true rather than asserted.
#[test]
fn two_invitations_key_different_handshakes() -> Fallible<()> {
    let scratch = Scratch::new("distinct");
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(invitation(ALICE, 7)?);
    admission.offer(invitation(BOB, 8)?);
    assert_ne!(admission.psk_for(&ALICE)?, admission.psk_for(&BOB)?);
    Ok(())
}

/// Re-pinning an identifier to a different key would let a second joiner take
/// the place of the first, so it has to be withdrawn deliberately.
#[test]
fn a_pinned_peer_id_is_not_silently_overwritten() -> Fallible<()> {
    let scratch = Scratch::new("collision");
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(invitation(ALICE, 7)?);
    admission.admit(&ALICE, 1, [0x22; 32])?;
    admission.offer(invitation(BOB, 8)?);

    assert_eq!(
        admission.admit(&BOB, 1, [0x33; 32]),
        Err(AdmissionError::PeerIdInUse)
    );
    assert_eq!(
        admission.pinned(1),
        Some([0x22; 32]),
        "the first pin stands"
    );
    assert!(
        !admission.is_spent(&BOB),
        "a refused admission does not spend the invitation"
    );
    Ok(())
}

/// D9's removal, and the reason it is on the store rather than in memory.
#[test]
fn a_removed_peer_stays_removed_across_a_restart() -> Fallible<()> {
    let scratch = Scratch::new("removed");
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(invitation(ALICE, 7)?);
    admission.admit(&ALICE, 1, [0x22; 32])?;
    admission.remove(1)?;
    drop(admission);

    let restarted = Admission::open(&scratch.0)?;
    assert_eq!(restarted.pinned(1), None);
    assert!(
        restarted.is_spent(&ALICE),
        "removal withdraws the pin, not the spent marker"
    );
    Ok(())
}

/// The invitation is not re-opened by removal. Un-admitting a peer and letting
/// its invitation work again would make a leaked invitation permanently useful,
/// which is exactly what D8 rejected reusable invitations to avoid.
#[test]
fn removal_does_not_re_open_the_invitation() -> Fallible<()> {
    let scratch = Scratch::new("reopen");
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(invitation(ALICE, 7)?);
    admission.admit(&ALICE, 1, [0x22; 32])?;
    admission.remove(1)?;

    admission.offer(invitation(ALICE, 7)?);
    assert_eq!(admission.psk_for(&ALICE), Err(AdmissionError::AlreadySpent));
    Ok(())
}

/// Withdrawing before use leaves nothing behind: the invitation never completed
/// a handshake, so a restart simply does not re-offer it.
#[test]
fn withdrawing_an_unused_invitation_does_not_mark_it_spent() -> Fallible<()> {
    let scratch = Scratch::new("withdrawn");
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(invitation(ALICE, 7)?);
    admission.withdraw(&ALICE);

    assert_eq!(
        admission.psk_for(&ALICE),
        Err(AdmissionError::UnknownInvitation)
    );
    assert!(!admission.is_spent(&ALICE));
    Ok(())
}

/// ADR 0047 D11 reaches this layer too: a node that cannot read what it already
/// spent does not start, rather than starting with an empty spent list.
#[test]
fn a_damaged_store_stops_the_node_from_admitting() -> Fallible<()> {
    let scratch = Scratch::new("damaged");
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(invitation(ALICE, 7)?);
    admission.admit(&ALICE, 1, [0x22; 32])?;
    drop(admission);

    let mut bytes = fs::read(&scratch.0)?;
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&scratch.0, &bytes)?;

    assert!(Admission::open(&scratch.0).is_err());
    Ok(())
}
