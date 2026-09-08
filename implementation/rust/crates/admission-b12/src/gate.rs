// SPDX-License-Identifier: Apache-2.0
//! The bounded step between discovery and a handshake context.
//!
//! `link-handshake-b1.md` section 8 states plainly that three of its five
//! required bounds have nothing to count in P1, because a node opens one context
//! per configured link at startup and the kernel drops anything from another
//! address. A listening socket removes that argument. This is what replaces it.
//!
//! **The order of the checks is the whole design.** Each one is cheaper than the
//! one after it, and each is reached only by a sender that passed the one
//! before:
//!
//! 1. the cookie, which costs one HMAC and proves the sender receives datagrams
//!    at the address it claims;
//! 2. backoff, one lookup, which refuses a source that has just failed
//!    `max_failed_handshakes_before_backoff` times;
//! 3. the per-source public-key rate, one lookup and an increment;
//! 4. the global context pool, which is the only thing that allocates.
//!
//! Reversing any pair would let a cheaper attack reach a more expensive
//! resource. That the cookie comes first is what makes the tracking tables
//! themselves safe: an entry appears only for an address that answered, so a
//! sender cannot grow them from addresses it does not hold, which is why the
//! type system refuses to let the gate be entered without one.

use crate::Secrets;
use protocol_registry::{
    LIMIT_HANDSHAKE_BACKOFF_MS, LIMIT_HANDSHAKE_INTERVAL_MS,
    LIMIT_HANDSHAKE_PUBKEY_OPS_PER_INTERVAL, LIMIT_HANDSHAKE_TIMEOUT_MS,
    LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF, LIMIT_MAX_HANDSHAKE_CONTEXTS,
    LIMIT_MAX_TRACKED_SOURCES,
};
use std::collections::HashMap;

/// Proof that a source answered at the address it claims.
///
/// [`Gate`] takes one of these rather than a bare address, so the cookie check
/// cannot be forgotten or reordered behind something more expensive. The only
/// way to obtain one is [`ReturnRoutable::confirm`], which verifies a cookie.
pub struct ReturnRoutable<'a> {
    source: &'a [u8],
}

impl<'a> ReturnRoutable<'a> {
    /// Verify a cookie and, if it holds, vouch for the source.
    ///
    /// Returns `None` on any failure: a sender is never told which check
    /// refused it.
    #[must_use]
    pub fn confirm(
        secrets: &Secrets,
        cookie: &[u8],
        source: &'a [u8],
        port: u16,
        offer: &[u8],
        now_ms: u64,
    ) -> Option<Self> {
        if secrets.verify(cookie, source, port, offer, now_ms) {
            Some(Self { source })
        } else {
            None
        }
    }

    /// For a source already vouched for by something other than a cookie — an
    /// established link, or a configured peer on the manifest path, neither of
    /// which needs return routability proved again.
    #[must_use]
    pub fn established(source: &'a [u8]) -> Self {
        Self { source }
    }

    #[must_use]
    pub fn source(&self) -> &[u8] {
        self.source
    }
}

/// Why a handshake context was not allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    /// The source failed `max_failed_handshakes_before_backoff` times and is
    /// held off for `handshake_backoff_ms`.
    BackingOff,
    /// The source has spent `handshake_pubkey_ops_per_interval` this interval.
    RateLimited,
    /// `max_handshake_contexts` are outstanding.
    ContextsFull,
    /// `max_tracked_sources` are tracked. Refusing here rather than evicting is
    /// what keeps a backoff from being flushed by a flood.
    TrackingFull,
}

impl std::fmt::Display for GateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::BackingOff => "source is backing off after repeated failures",
            Self::RateLimited => "source has spent its public-key budget this interval",
            Self::ContextsFull => "no handshake context is available",
            Self::TrackingFull => "no source tracking slot is available",
        })
    }
}

impl std::error::Error for GateError {}

/// A handshake context this gate has allocated.
///
/// Not `Clone` or `Copy`: it names one allocation, and returning it twice would
/// release a context that is still in use.
#[derive(Debug, PartialEq, Eq)]
pub struct Lease {
    id: u64,
}

impl Lease {
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }
}

struct Context {
    source: Vec<u8>,
    deadline_ms: u64,
}

#[derive(Default)]
struct Tracked {
    /// The interval this count belongs to, absolute rather than relative to any
    /// node's start, as the cookie's windows are.
    window: u64,
    ops: usize,
    failures: usize,
    backoff_until_ms: u64,
    /// When this entry may be dropped if nothing else keeps it: a source with no
    /// live context, no backoff, and no recent activity is not worth a slot.
    idle_after_ms: u64,
}

/// Outstanding handshake contexts and per-source accounting.
pub struct Gate {
    contexts: HashMap<u64, Context>,
    tracked: HashMap<Vec<u8>, Tracked>,
    next_id: u64,
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate {
    #[must_use]
    pub fn new() -> Self {
        Self {
            contexts: HashMap::new(),
            tracked: HashMap::new(),
            next_id: 1,
        }
    }

    /// Allocate a handshake context for a source that has proved return
    /// routability.
    ///
    /// One call is one public-key operation's worth of budget, because a
    /// responder does its Diffie-Hellman work once per attempt and an attempt is
    /// what a context represents. The budget is charged only when the context is
    /// actually allocated, so a refusal at the pool costs the source nothing it
    /// did not spend.
    ///
    /// # Errors
    ///
    /// The four [`GateError`] refusals, in the order this module documents.
    pub fn allocate(
        &mut self,
        routable: &ReturnRoutable<'_>,
        now_ms: u64,
    ) -> Result<Lease, GateError> {
        self.sweep(now_ms);
        let source = routable.source();

        let window = window_of(now_ms);
        let known = self.tracked.contains_key(source);
        if !known && self.tracked.len() >= LIMIT_MAX_TRACKED_SOURCES {
            return Err(GateError::TrackingFull);
        }
        let entry = self.tracked.entry(source.to_vec()).or_default();

        if entry.backoff_until_ms > now_ms {
            return Err(GateError::BackingOff);
        }
        if entry.window != window {
            entry.window = window;
            entry.ops = 0;
        }
        if entry.ops >= LIMIT_HANDSHAKE_PUBKEY_OPS_PER_INTERVAL {
            return Err(GateError::RateLimited);
        }
        if self.contexts.len() >= LIMIT_MAX_HANDSHAKE_CONTEXTS {
            // Checked after the per-source limits on purpose: the global pool is
            // the shared resource, and a source must have spent its own budget
            // before it can compete for it.
            return Err(GateError::ContextsFull);
        }

        entry.ops += 1;
        entry.idle_after_ms = now_ms.saturating_add(LIMIT_HANDSHAKE_BACKOFF_MS as u64);

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.contexts.insert(
            id,
            Context {
                source: source.to_vec(),
                deadline_ms: now_ms.saturating_add(LIMIT_HANDSHAKE_TIMEOUT_MS as u64),
            },
        );
        Ok(Lease { id })
    }

    /// Release a context whose handshake completed. Clears the source's failure
    /// run: backoff is for consecutive failures, and a success is what ends one.
    // The lease is consumed rather than borrowed on purpose: it names one
    // allocation, and returning it twice would release a context still in use.
    #[allow(clippy::needless_pass_by_value)]
    pub fn succeeded(&mut self, lease: Lease) {
        if let Some(context) = self.contexts.remove(&lease.id) {
            if let Some(entry) = self.tracked.get_mut(&context.source) {
                entry.failures = 0;
                entry.backoff_until_ms = 0;
            }
        }
    }

    /// Release a context whose handshake failed, and back the source off once it
    /// has failed `max_failed_handshakes_before_backoff` times in a row.
    #[allow(clippy::needless_pass_by_value)]
    pub fn failed(&mut self, lease: Lease, now_ms: u64) {
        if let Some(context) = self.contexts.remove(&lease.id) {
            let entry = self.tracked.entry(context.source).or_default();
            entry.failures += 1;
            entry.idle_after_ms = now_ms.saturating_add(LIMIT_HANDSHAKE_BACKOFF_MS as u64);
            if entry.failures >= LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF {
                entry.backoff_until_ms = now_ms.saturating_add(LIMIT_HANDSHAKE_BACKOFF_MS as u64);
                entry.failures = 0;
            }
        }
    }

    /// Reclaim contexts past `handshake_timeout_ms` and tracking slots that are
    /// holding nothing.
    ///
    /// A timed-out context counts as a failure: a peer that opens exchanges and
    /// abandons them is exactly what the backoff is for, and a context released
    /// without one would make abandonment free.
    pub fn sweep(&mut self, now_ms: u64) {
        let expired: Vec<u64> = self
            .contexts
            .iter()
            .filter(|(_, context)| context.deadline_ms <= now_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.failed(Lease { id }, now_ms);
        }

        let live: Vec<&[u8]> = self
            .contexts
            .values()
            .map(|context| context.source.as_slice())
            .collect();
        self.tracked.retain(|source, entry| {
            entry.backoff_until_ms > now_ms
                || entry.idle_after_ms > now_ms
                || live.contains(&source.as_slice())
        });
    }

    #[must_use]
    pub fn contexts(&self) -> usize {
        self.contexts.len()
    }

    #[must_use]
    pub fn tracked_sources(&self) -> usize {
        self.tracked.len()
    }

    /// Whether a source is currently held off. For a caller that wants to drop a
    /// datagram before the cookie check, which is allowed but not relied on.
    #[must_use]
    pub fn is_backing_off(&self, source: &[u8], now_ms: u64) -> bool {
        self.tracked
            .get(source)
            .is_some_and(|entry| entry.backoff_until_ms > now_ms)
    }
}

/// Which public-key rate interval a moment falls in.
fn window_of(now_ms: u64) -> u64 {
    now_ms / (LIMIT_HANDSHAKE_INTERVAL_MS as u64).max(1)
}
