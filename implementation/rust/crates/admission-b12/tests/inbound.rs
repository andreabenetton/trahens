// SPDX-License-Identifier: Apache-2.0
//! What a listening socket does with datagrams it did not ask for.
//!
//! The classification tests matter more than they look. Section 3's reserved
//! range is only a reservation if a receiver refuses it; a receiver that lets it
//! fall through to the cell path drops it too, for the wrong reason, and every
//! datagram type added later disappears into that path with no way to tell.

use admission_b12::{
    classify, Admission, Advertisement, Datagram, Disposition, DropReason, FrontEnd, Invitation,
    Kind, Secrets, SECRET_BYTES,
};
use link_handshake_b1::Profile;
use protocol_registry::{
    BYTES_B12_ADVERTISEMENT, BYTES_B1_RECORD, LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF, VERSION,
};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use test_vectors::Value;
use trahens_crypto::signing_keypair;

type Fallible<T> = Result<T, Box<dyn Error>>;

const PORT: u16 = 4242;
const INVITATION_ID: [u8; 16] = [0xa1; 16];
const INVITATION_SECRET: [u8; 32] = [0x77; 32];

fn number(registry: &Value, section: &str, name: &str) -> Fallible<usize> {
    let value = registry
        .get(section)
        .and_then(|group| group.get(name))
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("registry has no {section}.{name}"))?;
    Ok(usize::try_from(value)?)
}

fn text(registry: &Value, name: &str) -> Fallible<Vec<u8>> {
    Ok(registry
        .get("domain_separators")
        .and_then(|group| group.get(name))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("registry has no domain_separators.{name}"))?
        .as_bytes()
        .to_vec())
}

fn record_type(registry: &Value, name: &str) -> Fallible<u8> {
    Ok(u8::try_from(number(registry, "b1_record_types", name)?)?)
}

/// Built from the registry rather than from node-runtime's constants, which is
/// the second path to the same values the handshake crate's own tests use.
fn profile() -> Fallible<Profile> {
    let registry = test_vectors::protocol_registry_v18()?;
    Ok(Profile {
        protocol_version: VERSION,
        noise_protocol: text(&registry, "b1_noise_protocol")?,
        prologue_domain: text(&registry, "b1_prologue")?,
        rekey_chain_domain: text(&registry, "b1_rekey_chain")?,
        static_psk_domain: text(&registry, "b1_static_psk")?,
        epoch_domain: text(&registry, "b1_epoch")?,
        export_domain: text(&registry, "b1_export")?,
        record_bytes: number(&registry, "widths_bytes", "b1_record")?,
        record_prefix_bytes: number(&registry, "widths_bytes", "b1_record_prefix")?,
        initiate_payload_psk_bytes: number(&registry, "widths_bytes", "b1_initiate_payload_psk")?,
        respond_payload_bytes: number(&registry, "widths_bytes", "b1_respond_payload")?,
        finish_payload_bytes: number(&registry, "widths_bytes", "b1_finish_payload")?,
        admission_header_bytes: number(&registry, "widths_bytes", "b1_admission_header")?,
        admission_payload_bytes: number(&registry, "widths_bytes", "b1_admission_payload")?,
        invitation_id_bytes: number(&registry, "widths_bytes", "b12_invitation_id")?,
        cookie_bytes: number(&registry, "widths_bytes", "b12_cookie")?,
        transition_domain: text(&registry, "b1_transition")?,
        admission_initiate_type: record_type(&registry, "admission_initiate")?,
        cookie_challenge_type: record_type(&registry, "cookie_challenge")?,
        handshake_record_types: [
            record_type(&registry, "handshake_initiate")?,
            record_type(&registry, "handshake_respond")?,
            record_type(&registry, "handshake_finish")?,
        ],
        rekey_record_types: [
            record_type(&registry, "rekey_initiate")?,
            record_type(&registry, "rekey_respond")?,
            record_type(&registry, "rekey_finish")?,
        ],
        max_offered_per_class: number(&registry, "limits", "max_offered_profiles_per_class")?,
        rejected_suites: vec![],
    })
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("trahens-inbound-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn secrets() -> Secrets {
    Secrets::new(0, [7_u8; SECRET_BYTES])
}

fn at<'a>(source: &'a [u8], bytes: &'a [u8], now_ms: u64) -> Datagram<'a> {
    Datagram {
        source,
        port: PORT,
        bytes,
        now_ms,
    }
}

fn handshake_record() -> Vec<u8> {
    let mut datagram = vec![0_u8; BYTES_B1_RECORD];
    datagram[1] = 1; // handshake_initiate
    datagram
}

/// An admission initiate carrying `cookie`, framed by hand: these tests are
/// about the receive decision, not about the exchange, and building one through
/// the handshake would tie them to keys they do not care about.
fn admission_record(profile: &Profile, cookie: &[u8]) -> Vec<u8> {
    let mut record = vec![0_u8; BYTES_B1_RECORD];
    record[1] = profile.admission_initiate_type;
    record[2..2 + INVITATION_ID.len()].copy_from_slice(&INVITATION_ID);
    let start = 2 + INVITATION_ID.len();
    record[start..start + cookie.len()].copy_from_slice(cookie);
    record
}

fn admitting(scratch: &Scratch) -> Fallible<FrontEnd> {
    let mut admission = Admission::open(&scratch.0)?;
    admission.offer(Invitation::new(
        INVITATION_ID,
        INVITATION_SECRET,
        [0x11; 32],
    )?);
    Ok(FrontEnd::new().with_admission(admission))
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
fn a_reserved_discriminator_is_refused_as_reserved() -> Fallible<()> {
    let mut front = FrontEnd::new();
    let profile = profile()?;
    for byte in [0x02_u8, 0x40, 0x7f] {
        let mut datagram = vec![0_u8; BYTES_B1_RECORD];
        datagram[0] = byte;
        assert_eq!(
            front.receive(&at(b"source", &datagram, 1_000), &secrets(), &profile),
            Disposition::Drop(DropReason::ReservedDiscriminator),
            "byte {byte:#04x}"
        );
    }
    Ok(())
}

#[test]
fn an_empty_datagram_is_malformed() -> Fallible<()> {
    let mut front = FrontEnd::new();
    assert_eq!(
        front.receive(&at(b"source", &[], 1_000), &secrets(), &profile()?),
        Disposition::Drop(DropReason::Malformed)
    );
    Ok(())
}

/// A cell from a stranger has nothing to open it with. Allocating on one is
/// precisely what the connected-socket topology made impossible for free.
#[test]
fn a_cell_from_an_unknown_source_allocates_nothing() -> Fallible<()> {
    let mut front = FrontEnd::new();
    let cell = vec![0x80_u8; BYTES_B1_RECORD];
    assert_eq!(
        front.receive(&at(b"stranger", &cell, 1_000), &secrets(), &profile()?),
        Disposition::Drop(DropReason::NoSuchLink)
    );
    assert_eq!(front.gate().contexts(), 0);
    assert_eq!(front.gate().tracked_sources(), 0);
    Ok(())
}

#[test]
fn a_cell_from_an_established_source_goes_to_its_link() -> Fallible<()> {
    let mut front = FrontEnd::new();
    let profile = profile()?;
    front.link_established(b"peer", 7);
    let cell = vec![0x80_u8; BYTES_B1_RECORD];
    assert_eq!(
        front.receive(&at(b"peer", &cell, 1_000), &secrets(), &profile),
        Disposition::ToLink
    );
    assert_eq!(front.peer_at(b"peer"), Some(7));

    front.link_lost(b"peer");
    assert_eq!(
        front.receive(&at(b"peer", &cell, 1_000), &secrets(), &profile),
        Disposition::Drop(DropReason::NoSuchLink)
    );
    Ok(())
}

/// A manifest-path handshake from someone the manifest does not name has no
/// path, and is refused before any state rather than allocating and failing.
#[test]
fn a_manifest_handshake_from_a_stranger_allocates_nothing() -> Fallible<()> {
    let mut front = FrontEnd::new();
    assert_eq!(
        front.receive(
            &at(b"stranger", &handshake_record(), 1_000),
            &secrets(),
            &profile()?
        ),
        Disposition::Drop(DropReason::NoAdmissionPath)
    );
    assert_eq!(front.gate().contexts(), 0);
    assert_eq!(
        front.gate().tracked_sources(),
        0,
        "and leaves no tracking entry either"
    );
    Ok(())
}

/// A configured peer is vouched for by the manifest and still passes the gate:
/// section 8's bounds are the answer to an authenticated peer misbehaving,
/// which is the case a manifest cannot rule out.
#[test]
fn a_handshake_from_a_configured_peer_takes_a_context() -> Fallible<()> {
    let mut front = FrontEnd::new();
    front.link_established(b"peer", 7);
    let Disposition::Handshake(lease) = front.receive(
        &at(b"peer", &handshake_record(), 1_000),
        &secrets(),
        &profile()?,
    ) else {
        return Err("expected a handshake lease".into());
    };
    assert_eq!(front.gate().contexts(), 1);
    front.gate_mut().succeeded(lease);
    assert_eq!(front.gate().contexts(), 0);
    Ok(())
}

#[test]
fn a_misbehaving_peer_is_backed_off_through_the_receive_path() -> Fallible<()> {
    let mut front = FrontEnd::new();
    let profile = profile()?;
    front.link_established(b"peer", 7);
    for _ in 0..LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF {
        let Disposition::Handshake(lease) = front.receive(
            &at(b"peer", &handshake_record(), 1_000),
            &secrets(),
            &profile,
        ) else {
            return Err("expected a handshake lease".into());
        };
        front.gate_mut().failed(lease, 1_000);
    }
    assert!(matches!(
        front.receive(
            &at(b"peer", &handshake_record(), 1_000),
            &secrets(),
            &profile
        ),
        Disposition::Drop(DropReason::Gate(_))
    ));
    Ok(())
}

#[test]
fn a_handshake_record_of_the_wrong_width_is_malformed() -> Fallible<()> {
    let mut front = FrontEnd::new();
    front.link_established(b"peer", 7);
    let mut short = handshake_record();
    short.truncate(BYTES_B1_RECORD - 1);
    assert_eq!(
        front.receive(&at(b"peer", &short, 1_000), &secrets(), &profile()?),
        Disposition::Drop(DropReason::Malformed)
    );
    assert_eq!(
        front.gate().contexts(),
        0,
        "width is checked before the gate"
    );
    Ok(())
}

// --------------------------------------------------------------------------
// The admission path, ADR 0048.
// --------------------------------------------------------------------------

/// A joiner has no cookie, so its first attempt is challenged. Nothing is
/// allocated for it: that is the whole point of challenging.
#[test]
fn a_first_attempt_is_challenged_and_allocates_nothing() -> Fallible<()> {
    let scratch = Scratch::new("challenged");
    let mut front = admitting(&scratch)?;
    let profile = profile()?;
    let record = admission_record(&profile, &[0; 32]);

    let Disposition::Challenge(challenge) =
        front.receive(&at(b"joiner", &record, 1_000), &secrets(), &profile)
    else {
        return Err("expected a challenge".into());
    };
    assert_eq!(front.gate().contexts(), 0, "no context");
    assert_eq!(front.gate().tracked_sources(), 0, "no tracking entry");

    let (identifier, _) = link_handshake_b1::decode_cookie_challenge(&profile, &challenge)?;
    assert_eq!(identifier, INVITATION_ID, "the joiner can match the reply");
    Ok(())
}

/// The reply is the same width as the message that provoked it, which is the
/// whole of ADR 0048 D13's amplification argument.
#[test]
fn a_challenge_is_no_larger_than_what_provoked_it() -> Fallible<()> {
    let scratch = Scratch::new("amplification");
    let mut front = admitting(&scratch)?;
    let profile = profile()?;
    let record = admission_record(&profile, &[0; 32]);
    let Disposition::Challenge(challenge) =
        front.receive(&at(b"joiner", &record, 1_000), &secrets(), &profile)
    else {
        return Err("expected a challenge".into());
    };
    assert_eq!(challenge.len(), record.len());
    Ok(())
}

/// Echoing the challenged cookie is what gets a context allocated.
#[test]
fn the_challenged_cookie_is_accepted_and_admits() -> Fallible<()> {
    let scratch = Scratch::new("accepted");
    let mut front = admitting(&scratch)?;
    let profile = profile()?;
    let secrets = secrets();

    let first = admission_record(&profile, &[0; 32]);
    let Disposition::Challenge(challenge) =
        front.receive(&at(b"joiner", &first, 1_000), &secrets, &profile)
    else {
        return Err("expected a challenge".into());
    };
    let (_, cookie) = link_handshake_b1::decode_cookie_challenge(&profile, &challenge)?;

    let second = admission_record(&profile, &cookie);
    let Disposition::Admit(grant) =
        front.receive(&at(b"joiner", &second, 1_000), &secrets, &profile)
    else {
        return Err("expected an admission".into());
    };
    assert_eq!(grant.invitation_id, INVITATION_ID);
    assert_eq!(
        grant.psk,
        admission_b12::invitation_psk(&INVITATION_ID, &INVITATION_SECRET)?,
        "the key comes from the invitation the identifier named"
    );
    assert_eq!(front.gate().contexts(), 1);
    Ok(())
}

/// A cookie is bound to the source it was issued for, so it cannot be lifted
/// off the wire and replayed from somewhere else.
#[test]
fn a_cookie_issued_for_one_source_does_not_work_from_another() -> Fallible<()> {
    let scratch = Scratch::new("elsewhere");
    let mut front = admitting(&scratch)?;
    let profile = profile()?;
    let secrets = secrets();

    let first = admission_record(&profile, &[0; 32]);
    let Disposition::Challenge(challenge) =
        front.receive(&at(b"joiner", &first, 1_000), &secrets, &profile)
    else {
        return Err("expected a challenge".into());
    };
    let (_, cookie) = link_handshake_b1::decode_cookie_challenge(&profile, &challenge)?;

    let second = admission_record(&profile, &cookie);
    assert!(
        matches!(
            front.receive(&at(b"elsewhere", &second, 1_000), &secrets, &profile),
            Disposition::Challenge(_)
        ),
        "challenged again rather than admitted"
    );
    assert_eq!(front.gate().contexts(), 0);
    Ok(())
}

/// An identifier this node never issued is challenged exactly as a known one
/// is. Challenging only for invitations a node holds would turn the reply into
/// an oracle for which ones it is holding.
#[test]
fn an_unknown_invitation_is_challenged_the_same_as_a_known_one() -> Fallible<()> {
    let scratch = Scratch::new("oracle");
    let mut front = admitting(&scratch)?;
    let profile = profile()?;

    let mut record = admission_record(&profile, &[0; 32]);
    record[2..18].copy_from_slice(&[0xff; 16]);
    assert!(matches!(
        front.receive(&at(b"joiner", &record, 1_000), &secrets(), &profile),
        Disposition::Challenge(_)
    ));
    Ok(())
}

/// The lookup happens after the gate, so probing for valid identifiers spends
/// the prober's own budget rather than costing it a hash lookup.
#[test]
fn probing_for_identifiers_costs_the_prober_its_backoff() -> Fallible<()> {
    let scratch = Scratch::new("probing");
    let mut front = admitting(&scratch)?;
    let profile = profile()?;
    let secrets = secrets();

    // Get a cookie, then spend attempts on identifiers that do not exist.
    let mut unknown = admission_record(&profile, &[0; 32]);
    unknown[2..18].copy_from_slice(&[0xff; 16]);
    let Disposition::Challenge(challenge) =
        front.receive(&at(b"prober", &unknown, 1_000), &secrets, &profile)
    else {
        return Err("expected a challenge".into());
    };
    let (_, cookie) = link_handshake_b1::decode_cookie_challenge(&profile, &challenge)?;
    let mut probe = admission_record(&profile, &cookie);
    probe[2..18].copy_from_slice(&[0xff; 16]);

    for _ in 0..LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF {
        assert!(matches!(
            front.receive(&at(b"prober", &probe, 1_000), &secrets, &profile),
            Disposition::Drop(DropReason::Admission(_))
        ));
    }
    assert!(
        front.gate().is_backing_off(b"prober", 1_000),
        "the probes counted as failures"
    );
    assert_eq!(front.gate().contexts(), 0, "and released every context");
    Ok(())
}

/// ADR 0047 D12: a node with no store cannot admit, so it does not challenge
/// either — a challenge it could not follow through on is a reply it should not
/// have sent.
#[test]
fn a_node_without_admission_state_refuses_rather_than_challenging() -> Fallible<()> {
    let mut front = FrontEnd::new();
    let profile = profile()?;
    let record = admission_record(&profile, &[0; 32]);
    assert_eq!(
        front.receive(&at(b"joiner", &record, 1_000), &secrets(), &profile),
        Disposition::Drop(DropReason::NoAdmissionPath)
    );
    Ok(())
}

/// A spent invitation is refused after the cookie, so D8's single use holds on
/// the receive path and not only in the state layer.
#[test]
fn a_spent_invitation_is_refused_on_the_receive_path() -> Fallible<()> {
    let scratch = Scratch::new("spent");
    let mut front = admitting(&scratch)?;
    let profile = profile()?;
    let secrets = secrets();
    front
        .admission_mut()
        .ok_or("expected admission state")?
        .admit(&INVITATION_ID, 1, [0x22; 32])?;

    let first = admission_record(&profile, &[0; 32]);
    let Disposition::Challenge(challenge) =
        front.receive(&at(b"joiner", &first, 1_000), &secrets, &profile)
    else {
        return Err("expected a challenge".into());
    };
    let (_, cookie) = link_handshake_b1::decode_cookie_challenge(&profile, &challenge)?;
    let second = admission_record(&profile, &cookie);
    assert!(matches!(
        front.receive(&at(b"joiner", &second, 1_000), &secrets, &profile),
        Disposition::Drop(DropReason::Admission(_))
    ));
    Ok(())
}

// --------------------------------------------------------------------------
// Advertisements.
// --------------------------------------------------------------------------

#[test]
fn a_verified_advertisement_is_cached_and_nothing_else() -> Fallible<()> {
    let mut front = FrontEnd::new();
    let datagram = signed_advertisement(60_000)?;
    assert!(matches!(
        front.receive(
            &at(b"advertiser", &datagram, 1_000),
            &secrets(),
            &profile()?
        ),
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
        front.receive(
            &at(b"advertiser", &datagram, 1_000),
            &secrets(),
            &profile()?
        ),
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
        front.receive(
            &at(b"advertiser", &datagram, 1_000),
            &secrets(),
            &profile()?
        ),
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
        front.receive(
            &at(b"advertiser", &datagram, 1_000),
            &secrets(),
            &profile()?
        ),
        Disposition::Drop(DropReason::Cache(_))
    ));
    assert!(front.cache().is_empty());
    Ok(())
}
