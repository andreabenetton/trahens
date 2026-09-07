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

/// One retained hint about where admission might be attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The observed source the advertisement arrived from. Opaque here: an
    /// address on an IP underlay, whatever identifies a sender elsewhere.
    pub source: Vec<u8>,
    pub advertisement: Advertisement,
    /// When this entry stops being usable: the earlier of the advertisement's
    /// own expiry and `candidate_ttl_ms` from when it was observed. A node does
    /// not let an advertiser choose how long it is remembered.
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
            existing.advertisement = advertisement.clone();
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
                advertisement: advertisement.clone(),
                expires_ms,
            },
        );
        Ok(())
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
