// SPDX-License-Identifier: Apache-2.0
//! The bounded candidate-peer cache.
//!
//! ADR 0045 D6 makes this the *only* thing the discovery path writes into.
//! Observing an advertisement never allocates a handshake context, never
//! performs a public-key operation beyond verifying the advertisement itself,
//! and never opens a socket. A separate step — [`CandidateCache::take`] — is
//! what turns a cached hint into an admission attempt, and it is bounded
//! independently. If discovery could allocate, `max_handshake_contexts` and
//! this cache would be the same bound and filling one would fill the other.
//!
//! `network-bootstrap-b1.md` section 13 requires a registry bound on candidate
//! peers retained, and section 12 names Sybil saturation of candidate lists as a
//! threat. One global bound does not answer that threat on its own, because
//! advertisement keys are free to generate; the per-source bound is what makes
//! filling the cache cost something.

use crate::advertisement::Advertisement;
use crate::seed::SeedManifest;
use protocol_registry::{
    LIMIT_CANDIDATE_TTL_MS, LIMIT_MAX_CANDIDATE_PEERS, LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE,
};
use std::collections::HashMap;

/// Why an advertisement was not cached.
///
/// Nothing is sent back to the advertiser; these exist so a node can count its
/// own refusals and tell an expired advertisement from a saturated cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    /// The advertisement's own expiry has passed, or it is not yet valid.
    Expired,
    /// This source already holds `max_candidate_peers_per_source` entries.
    SourceFull,
    /// The cache holds `max_candidate_peers` unexpired entries.
    CacheFull,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Expired => "advertisement has expired",
            Self::SourceFull => "source holds its share of the candidate cache",
            Self::CacheFull => "candidate cache is full",
        })
    }
}

impl std::error::Error for CacheError {}

/// Where a candidate came from, and what it therefore carries.
///
/// A seed entry is not an advertisement and is deliberately not converted into
/// one: it names a key, an address and a port, and nothing signed a capacity
/// class or a profile list for it. Fabricating those to make the two shapes
/// match would put values in the cache that no one asserted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Learned {
    /// A verified advertisement, from the source that sent it.
    Advertised(Box<Advertisement>),
    /// A signed seed manifest entry (ADR 0050).
    Seeded {
        advertisement_key: [u8; 32],
        address: Vec<u8>,
        port: u16,
    },
}

impl Learned {
    /// The advertisement key this candidate is keyed by, and the one a
    /// completed exchange's transition is checked against (ADR 0049).
    #[must_use]
    pub fn advertisement_key(&self) -> [u8; 32] {
        match self {
            Self::Advertised(advertisement) => advertisement.key,
            Self::Seeded {
                advertisement_key, ..
            } => *advertisement_key,
        }
    }
}

/// One retained hint about where admission might be attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// What this entry is accounted against. For an advertisement, the observed
    /// source it arrived from; for a seed entry, the key that signed the
    /// manifest. ADR 0050 D19 as amended: a manifest is not a network source
    /// and the per-source cap does not answer a threat it presents.
    pub source: Vec<u8>,
    pub learned: Learned,
    /// When this entry stops being usable: the earlier of what its origin says
    /// and `candidate_ttl_ms` from when it was learned. A node does not let an
    /// advertiser or an issuer choose how long it is remembered.
    pub expires_ms: u64,
}

/// Candidates keyed by advertisement key, bounded globally and per source.
pub struct CandidateCache {
    entries: HashMap<[u8; 32], Candidate>,
}

impl Default for CandidateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CandidateCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Record a verified advertisement.
    ///
    /// The caller has already verified the signature; this decides only whether
    /// to keep it. An advertisement for a key already held refreshes that entry
    /// and stays attributed to the source that first inserted it, so a third
    /// party replaying a valid advertisement cannot move the accounting onto
    /// someone else's budget.
    ///
    /// # Errors
    ///
    /// [`CacheError::Expired`], [`CacheError::SourceFull`] or
    /// [`CacheError::CacheFull`].
    pub fn observe(
        &mut self,
        source: &[u8],
        advertisement: &Advertisement,
        now_ms: u64,
    ) -> Result<(), CacheError> {
        if advertisement.expiry_ms <= now_ms {
            return Err(CacheError::Expired);
        }
        self.expire(now_ms);

        let expires_ms = advertisement
            .expiry_ms
            .min(now_ms.saturating_add(LIMIT_CANDIDATE_TTL_MS as u64));

        if let Some(existing) = self.entries.get_mut(&advertisement.key) {
            existing.learned = Learned::Advertised(Box::new(advertisement.clone()));
            existing.expires_ms = expires_ms;
            return Ok(());
        }

        if self
            .entries
            .values()
            .filter(|entry| entry.source == source)
            .count()
            >= LIMIT_MAX_CANDIDATE_PEERS_PER_SOURCE
        {
            return Err(CacheError::SourceFull);
        }
        // A full cache refuses rather than evicting. Evicting the oldest would
        // let a flood displace every honest entry, so an attacker could
        // guarantee the cache never holds a real candidate; refusing means an
        // early flood merely stalls new learning until the TTL drains it, and
        // what was learned first is kept. The per-source bound is what makes
        // reaching this expensive: filling the cache costs
        // max_candidate_peers / max_candidate_peers_per_source distinct
        // sources, not one.
        if self.entries.len() >= LIMIT_MAX_CANDIDATE_PEERS {
            return Err(CacheError::CacheFull);
        }

        self.entries.insert(
            advertisement.key,
            Candidate {
                source: source.to_vec(),
                learned: Learned::Advertised(Box::new(advertisement.clone())),
                expires_ms,
            },
        );
        Ok(())
    }

    /// Take every entry of a verified seed manifest.
    ///
    /// ADR 0050 D19 as amended. Entries are accounted against the key that
    /// signed the manifest rather than a network source, and the per-source cap
    /// does not apply: it exists because advertisement keys are free to generate
    /// and an unauthenticated source can invent as many as it likes, while a
    /// manifest is signed by a key the operator chose and is capped by its own
    /// parser before anything is allocated. Applying it would also drop three
    /// quarters of a full manifest.
    ///
    /// `max_candidate_peers` still applies and is the protection that matters:
    /// a manifest contributes at most its own bound and displaces nothing.
    ///
    /// Returns how many entries were kept, which is fewer than the manifest
    /// holds only when the global cache is full — the caller is told rather
    /// than left to assume.
    ///
    /// The caller has already verified the manifest; this decides only whether
    /// to keep what it names.
    pub fn seed(&mut self, seed_key: &[u8; 32], manifest: &SeedManifest, now_ms: u64) -> usize {
        self.expire(now_ms);
        let expires_ms = manifest
            .expiry_ms
            .min(now_ms.saturating_add(LIMIT_CANDIDATE_TTL_MS as u64));
        if manifest.expiry_ms <= now_ms {
            return 0;
        }

        let mut kept = 0_usize;
        for entry in &manifest.entries {
            if let Some(existing) = self.entries.get_mut(&entry.advertisement_key) {
                // An advertisement already held is better information than a
                // seed entry: it was signed by the peer itself and carries what
                // that peer offers. A manifest refreshes the lifetime and does
                // not overwrite it with less.
                existing.expires_ms = existing.expires_ms.max(expires_ms);
                kept += 1;
                continue;
            }
            if self.entries.len() >= LIMIT_MAX_CANDIDATE_PEERS {
                break;
            }
            self.entries.insert(
                entry.advertisement_key,
                Candidate {
                    source: seed_key.to_vec(),
                    learned: Learned::Seeded {
                        advertisement_key: entry.advertisement_key,
                        address: entry.address.clone(),
                        port: entry.port,
                    },
                    expires_ms,
                },
            );
            kept += 1;
        }
        kept
    }

    /// Consume one unexpired candidate, removing it from the cache.
    ///
    /// D6's separate step. Taking is what a caller does before deciding whether
    /// to attempt admission, and removing on take means a candidate that fails
    /// is not retried out of the cache forever — a fresh advertisement is what
    /// puts it back.
    pub fn take(&mut self, now_ms: u64) -> Option<Candidate> {
        self.expire(now_ms);
        let key = *self.entries.keys().next()?;
        self.entries.remove(&key)
    }

    /// Drop everything past its expiry.
    pub fn expire(&mut self, now_ms: u64) {
        self.entries.retain(|_, entry| entry.expires_ms > now_ms);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many entries a source currently holds, against its per-source bound.
    #[must_use]
    pub fn held_by(&self, source: &[u8]) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.source == source)
            .count()
    }
}
