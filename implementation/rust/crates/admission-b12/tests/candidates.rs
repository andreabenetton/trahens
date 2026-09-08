// SPDX-License-Identifier: Apache-2.0
//! The candidate cache's bounds, which are the reason it exists.
//!
//! ADR 0045 D6 keeps discovery from allocating handshake state; what these
//! tests check is the other half — that the thing discovery *can* allocate is
//! bounded, and bounded per source rather than only globally, because
//! advertisement keys are free to generate.

use admission_b12::candidates::Learned;
use admission_b12::{Advertisement, CacheError, CandidateCache, SeedEntry, SeedManifest};
use protocol_registry::{
    LIMIT_CANDIDATE_TTL_MS, LIMIT_MAX_CANDIDATE_PEERS, LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE,
    LIMIT_MAX_SEED_ENTRIES, VERSION,
};
use std::error::Error;

type Fallible<T> = Result<T, Box<dyn Error>>;

/// A distinct advertisement per index. Only the key has to differ: it is what
/// the cache is keyed by, and an attacker generating keys is the threat.
fn advertisement(index: usize, expiry_ms: u64) -> Advertisement {
    let mut key = [0_u8; 32];
    key[..8].copy_from_slice(&index.to_be_bytes());
    Advertisement {
        version: 3,
        key,
        expiry_ms,
        capacity_class: 1,
        auth_modes: 1,
        w2_profiles: vec![2],
        t1_profiles: vec![3],
        t2_profiles: vec![4],
        suites: vec![3],
    }
}

fn source(index: usize) -> Vec<u8> {
    index.to_be_bytes().to_vec()
}

#[test]
fn an_expired_advertisement_is_not_cached() {
    let mut cache = CandidateCache::new();
    assert_eq!(
        cache.observe(&source(0), &advertisement(0, 1_000), 1_000),
        Err(CacheError::Expired)
    );
    assert!(cache.is_empty());
}

/// The advertiser does not choose how long it is remembered. An expiry far in
/// the future is clamped to `candidate_ttl_ms` from when it was observed.
#[test]
fn an_advertisers_expiry_cannot_outrun_the_cache_ttl() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    cache.observe(&source(0), &advertisement(0, u64::MAX), 1_000)?;
    assert_eq!(cache.len(), 1);

    cache.expire(1_000 + u64::try_from(LIMIT_CANDIDATE_TTL_MS)? + 1);
    assert!(
        cache.is_empty(),
        "the TTL, not the advertised expiry, ended it"
    );
    Ok(())
}

/// An expiry sooner than the TTL is honoured as it stands.
#[test]
fn a_short_advertised_expiry_is_honoured() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    cache.observe(&source(0), &advertisement(0, 2_000), 1_000)?;
    cache.expire(2_001);
    assert!(cache.is_empty());
    Ok(())
}

/// The Sybil bound of section 12. One source cannot occupy the cache however
/// many keys it invents.
#[test]
fn one_source_cannot_fill_the_cache() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    for index in 0..LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE {
        cache.observe(&source(0), &advertisement(index, 60_000), 1_000)?;
    }
    assert_eq!(
        cache.held_by(&source(0)),
        LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE
    );

    let overflow = LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE;
    assert_eq!(
        cache.observe(&source(0), &advertisement(overflow, 60_000), 1_000),
        Err(CacheError::SourceFull)
    );
    assert!(
        cache.len() < LIMIT_MAX_CANDIDATE_PEERS,
        "the global bound was nowhere near reached"
    );
    Ok(())
}

/// A saturated source does not shut out anyone else, which is what makes the
/// per-source bound a defence rather than a denial of service in itself.
#[test]
fn a_saturated_source_does_not_block_another() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    for index in 0..LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE {
        cache.observe(&source(0), &advertisement(index, 60_000), 1_000)?;
    }
    cache.observe(&source(1), &advertisement(9_000, 60_000), 1_000)?;
    assert_eq!(cache.held_by(&source(1)), 1);
    Ok(())
}

/// Reaching the global bound costs as many distinct sources as the two limits
/// divide into, and the cache refuses rather than evicting what it already has.
#[test]
fn a_full_cache_refuses_rather_than_evicting() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    let sources = LIMIT_MAX_CANDIDATE_PEERS / LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE;
    let mut index = 0_usize;
    for which in 0..sources {
        for _ in 0..LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE {
            cache.observe(&source(which), &advertisement(index, 60_000), 1_000)?;
            index += 1;
        }
    }
    assert_eq!(cache.len(), LIMIT_MAX_CANDIDATE_PEERS);

    let first = advertisement(0, 60_000);
    assert_eq!(
        cache.observe(&source(sources), &advertisement(index, 60_000), 1_000),
        Err(CacheError::CacheFull)
    );
    assert_eq!(
        cache.len(),
        LIMIT_MAX_CANDIDATE_PEERS,
        "nothing was evicted"
    );
    // The entry that arrived first is still the one held, which is the
    // difference between refusing and evicting.
    cache.observe(&source(0), &first, 1_000)?;
    Ok(())
}

/// Expiry frees the space, so a flood stalls learning for a TTL rather than
/// permanently.
#[test]
fn expiry_reopens_a_full_cache() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    let sources = LIMIT_MAX_CANDIDATE_PEERS / LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE;
    let mut index = 0_usize;
    for which in 0..sources {
        for _ in 0..LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE {
            cache.observe(&source(which), &advertisement(index, 2_000), 1_000)?;
            index += 1;
        }
    }
    assert_eq!(
        cache.observe(&source(sources), &advertisement(index, 60_000), 1_000),
        Err(CacheError::CacheFull)
    );

    cache.observe(&source(sources), &advertisement(index, 60_000), 2_001)?;
    assert_eq!(cache.len(), 1, "the flood aged out");
    Ok(())
}

/// A refresh is not a second entry, or an advertiser could occupy its whole
/// per-source budget by repeating one advertisement.
#[test]
fn re_advertising_the_same_key_refreshes_one_entry() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    cache.observe(&source(0), &advertisement(0, 60_000), 1_000)?;
    cache.observe(&source(0), &advertisement(0, 60_000), 2_000)?;
    assert_eq!(cache.held_by(&source(0)), 1);
    Ok(())
}

/// A third party replaying a valid advertisement refreshes it but does not move
/// it onto its own budget — nor off the budget of the source that first held it.
#[test]
fn a_replay_from_elsewhere_does_not_move_the_accounting() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    cache.observe(&source(0), &advertisement(0, 60_000), 1_000)?;
    cache.observe(&source(1), &advertisement(0, 60_000), 1_500)?;

    assert_eq!(cache.held_by(&source(0)), 1);
    assert_eq!(cache.held_by(&source(1)), 0);
    Ok(())
}

/// D6's separate step: taking is what consumes a candidate, and a taken one is
/// gone until a fresh advertisement puts it back.
#[test]
fn taking_a_candidate_removes_it() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    cache.observe(&source(0), &advertisement(0, 60_000), 1_000)?;

    let taken = cache.take(1_000).ok_or("expected a candidate")?;
    assert_eq!(
        taken.learned.advertisement_key(),
        advertisement(0, 60_000).key
    );
    assert_eq!(taken.source, source(0));
    assert!(cache.is_empty());
    assert!(cache.take(1_000).is_none());
    Ok(())
}

// --------------------------------------------------------------------------
// Seeding from a signed manifest, ADR 0050.
// --------------------------------------------------------------------------

const SEED_KEY: [u8; 32] = [0x5e; 32];

fn seed_manifest(count: usize, expiry_ms: u64) -> SeedManifest {
    SeedManifest {
        version: VERSION,
        issued_ms: 0,
        expiry_ms,
        entries: (0..count)
            .map(|index| SeedEntry {
                advertisement_key: {
                    // Offset out of the advertisement helper's key space, so a
                    // test about the global bound is not quietly testing the
                    // refresh path instead.
                    let mut key = [0xee_u8; 32];
                    key[..8].copy_from_slice(&index.to_be_bytes());
                    key
                },
                family: 4,
                address: vec![10, 0, 0, 1],
                port: 45_301,
            })
            .collect(),
    }
}

/// The amendment to D19, and the arithmetic that forced it: a full manifest is
/// 32 entries and the per-source cap is 8, so applying that cap here would have
/// dropped three quarters of it. A manifest is not a network source.
#[test]
fn a_full_manifest_is_kept_whole() {
    let mut cache = CandidateCache::new();
    let manifest = seed_manifest(LIMIT_MAX_SEED_ENTRIES, 60_000);
    let kept = cache.seed(&SEED_KEY, &manifest, 1_000);
    assert_eq!(kept, LIMIT_MAX_SEED_ENTRIES);
    assert_eq!(cache.len(), LIMIT_MAX_SEED_ENTRIES);
}

/// The premise the test above rests on, checked at compile time: a manifest
/// must hold more than a source may, or "kept whole" would be indistinguishable
/// from "capped" and the test would pass without meaning anything.
const _: () = assert!(LIMIT_MAX_SEED_ENTRIES > LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE);

/// What still applies, and is the protection that matters.
#[test]
fn a_manifest_cannot_exceed_the_global_bound() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    // Fill the cache from network sources first.
    let sources = LIMIT_MAX_CANDIDATE_PEERS / LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE;
    let mut index = 0_usize;
    for which in 0..sources {
        for _ in 0..LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE {
            cache.observe(&source(which), &advertisement(index, 60_000), 1_000)?;
            index += 1;
        }
    }
    assert_eq!(cache.len(), LIMIT_MAX_CANDIDATE_PEERS);

    let kept = cache.seed(&SEED_KEY, &seed_manifest(4, 60_000), 1_000);
    assert_eq!(kept, 0, "a full cache takes nothing from a manifest");
    assert_eq!(
        cache.len(),
        LIMIT_MAX_CANDIDATE_PEERS,
        "and displaces nothing, because a full cache refuses rather than evicting"
    );
    Ok(())
}

/// A seeded entry says less than an advertisement, and says so rather than
/// pretending to carry a capacity class nobody signed.
#[test]
fn a_seeded_entry_is_distinguishable_from_an_advertised_one() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    cache.seed(&SEED_KEY, &seed_manifest(1, 60_000), 1_000);
    let taken = cache.take(1_000).ok_or("expected a candidate")?;
    assert!(matches!(taken.learned, Learned::Seeded { .. }));
    assert_eq!(taken.source, SEED_KEY, "accounted against the seed key");
    Ok(())
}

/// An advertisement is the peer's own word about itself; a manifest is someone
/// else's. A manifest refreshes what is held and does not replace it with less.
#[test]
fn a_manifest_does_not_overwrite_an_advertisement() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    let advertised = advertisement(0, 60_000);
    cache.observe(&source(0), &advertised, 1_000)?;

    let mut manifest = seed_manifest(1, 60_000);
    // Deliberately the same key, which is the case this test is about.
    manifest.entries[0].advertisement_key = advertised.key;
    assert_eq!(cache.seed(&SEED_KEY, &manifest, 1_000), 1);

    let taken = cache.take(1_000).ok_or("expected a candidate")?;
    assert!(
        matches!(taken.learned, Learned::Advertised(_)),
        "the peer's own advertisement survived"
    );
    assert_eq!(taken.source, source(0), "and its accounting did not move");
    Ok(())
}

/// An issuer does not choose how long its entries are remembered, for the same
/// reason an advertiser does not.
#[test]
fn a_manifests_expiry_cannot_outrun_the_cache_ttl() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    cache.seed(&SEED_KEY, &seed_manifest(1, u64::MAX), 1_000);
    assert_eq!(cache.len(), 1);
    cache.expire(1_000 + u64::try_from(LIMIT_CANDIDATE_TTL_MS)? + 1);
    assert!(cache.is_empty());
    Ok(())
}

#[test]
fn an_expired_manifest_seeds_nothing() {
    let mut cache = CandidateCache::new();
    assert_eq!(cache.seed(&SEED_KEY, &seed_manifest(4, 1_000), 1_000), 0);
    assert!(cache.is_empty());
}

/// An expired entry is never handed out, whether or not anything has swept.
#[test]
fn an_expired_candidate_is_never_taken() -> Fallible<()> {
    let mut cache = CandidateCache::new();
    cache.observe(&source(0), &advertisement(0, 2_000), 1_000)?;
    assert!(cache.take(2_001).is_none());
    Ok(())
}
