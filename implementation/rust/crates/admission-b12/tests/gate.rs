// SPDX-License-Identifier: Apache-2.0
//! The four bounds `link-handshake-b1.md` section 8 says have nothing to count.
//!
//! They have something to count now, and these tests are what say so. Each one
//! drives a bound to its registry value and one past it, so a change to the
//! registry moves the test with it rather than leaving a literal behind.

use admission_b12::{Gate, GateError, ReturnRoutable, Secrets, SECRET_BYTES};
use protocol_registry::{
    LIMIT_COOKIE_WINDOW_MS, LIMIT_HANDSHAKE_BACKOFF_MS, LIMIT_HANDSHAKE_INTERVAL_MS,
    LIMIT_HANDSHAKE_PUBKEY_OPS_PER_INTERVAL, LIMIT_HANDSHAKE_TIMEOUT_MS,
    LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF, LIMIT_MAX_HANDSHAKE_CONTEXTS,
    LIMIT_MAX_TRACKED_SOURCES,
};
use std::error::Error;

type Fallible<T> = Result<T, Box<dyn Error>>;

fn source(index: usize) -> Vec<u8> {
    index.to_be_bytes().to_vec()
}

/// Exhaust one source's public-key budget for the interval `now_ms` is in.
fn spend_budget(gate: &mut Gate, source: &[u8], now_ms: u64) {
    for _ in 0..LIMIT_HANDSHAKE_PUBKEY_OPS_PER_INTERVAL {
        if let Ok(lease) = gate.allocate(&ReturnRoutable::established(source), now_ms) {
            gate.succeeded(lease);
        }
    }
}

/// The cookie gates everything else, so a wrong one yields no witness and the
/// gate cannot be entered at all.
#[test]
fn a_bad_cookie_yields_no_witness() -> Fallible<()> {
    let secrets = Secrets::new(0, [7_u8; SECRET_BYTES]);
    let current = secrets.current().ok_or("expected a secret")?;
    let offer = b"offer";
    let cookie = admission_b12::issue(current, &source(0), 4242, 0, offer)?;

    assert!(ReturnRoutable::confirm(&secrets, &cookie, &source(0), 4242, offer, 0).is_some());
    // The same cookie under a different source is not this source's cookie.
    assert!(ReturnRoutable::confirm(&secrets, &cookie, &source(1), 4242, offer, 0).is_none());
    // Nor does it survive past the windows the responder still accepts.
    let beyond = LIMIT_COOKIE_WINDOW_MS as u64 * 8;
    assert!(ReturnRoutable::confirm(&secrets, &cookie, &source(0), 4242, offer, beyond).is_none());
    Ok(())
}

/// `max_handshake_contexts`, which had nothing to count when every context came
/// from a configured link at startup.
#[test]
fn the_context_pool_is_bounded() -> Fallible<()> {
    let mut gate = Gate::new();
    let mut leases = Vec::new();
    // One source per context, so the per-source rate limit is not what refuses.
    for index in 0..LIMIT_MAX_HANDSHAKE_CONTEXTS {
        let held = source(index);
        leases.push(gate.allocate(&ReturnRoutable::established(&held), 1_000)?);
    }
    assert_eq!(gate.contexts(), LIMIT_MAX_HANDSHAKE_CONTEXTS);

    let overflow = source(LIMIT_MAX_HANDSHAKE_CONTEXTS);
    assert_eq!(
        gate.allocate(&ReturnRoutable::established(&overflow), 1_000),
        Err(GateError::ContextsFull)
    );

    // Completing one frees exactly one.
    let released = leases.pop().ok_or("expected a lease")?;
    gate.succeeded(released);
    gate.allocate(&ReturnRoutable::established(&overflow), 1_000)?;
    Ok(())
}

/// `handshake_pubkey_ops_per_interval` per source. One source cannot spend the
/// whole context pool, whatever the pool has left.
#[test]
fn one_source_cannot_spend_the_whole_pool() -> Fallible<()> {
    let mut gate = Gate::new();
    let held = source(0);
    for _ in 0..LIMIT_HANDSHAKE_PUBKEY_OPS_PER_INTERVAL {
        let lease = gate.allocate(&ReturnRoutable::established(&held), 1_000)?;
        gate.succeeded(lease);
    }
    assert_eq!(
        gate.allocate(&ReturnRoutable::established(&held), 1_000),
        Err(GateError::RateLimited)
    );
    assert_eq!(gate.contexts(), 0, "and it holds no context while refused");

    // Another source is unaffected: the budget is per source, not global.
    let other = source(1);
    gate.allocate(&ReturnRoutable::established(&other), 1_000)?;
    Ok(())
}

/// The budget refills. A rate limit that never refilled would be a permanent
/// ban after `handshake_pubkey_ops_per_interval` attempts.
#[test]
fn the_public_key_budget_refills_next_interval() -> Fallible<()> {
    let mut gate = Gate::new();
    let held = source(0);
    spend_budget(&mut gate, &held, 1_000);
    assert_eq!(
        gate.allocate(&ReturnRoutable::established(&held), 1_000),
        Err(GateError::RateLimited)
    );

    let next = 1_000 + u64::try_from(LIMIT_HANDSHAKE_INTERVAL_MS)?;
    gate.allocate(&ReturnRoutable::established(&held), next)?;
    Ok(())
}

/// `max_failed_handshakes_before_backoff` and `handshake_backoff_ms`, which
/// section 8 records as not implemented.
#[test]
fn consecutive_failures_back_a_source_off() -> Fallible<()> {
    let mut gate = Gate::new();
    let held = source(0);
    for _ in 0..LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF {
        let lease = gate.allocate(&ReturnRoutable::established(&held), 1_000)?;
        gate.failed(lease, 1_000);
    }
    assert!(gate.is_backing_off(&held, 1_000));
    assert_eq!(
        gate.allocate(&ReturnRoutable::established(&held), 1_000),
        Err(GateError::BackingOff)
    );

    let after = 1_000 + u64::try_from(LIMIT_HANDSHAKE_BACKOFF_MS)? + 1;
    assert!(!gate.is_backing_off(&held, after));
    gate.allocate(&ReturnRoutable::established(&held), after)?;
    Ok(())
}

/// Backoff is for *consecutive* failures. A run broken by a success must not
/// eventually back off a peer on a lossy link that mostly works.
#[test]
fn a_success_clears_the_failure_run() -> Fallible<()> {
    let mut gate = Gate::new();
    let held = source(0);
    for _ in 0..LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF - 1 {
        let lease = gate.allocate(&ReturnRoutable::established(&held), 1_000)?;
        gate.failed(lease, 1_000);
    }
    let lease = gate.allocate(&ReturnRoutable::established(&held), 1_000)?;
    gate.succeeded(lease);

    // The run restarts, so one more failure is nowhere near the threshold.
    let lease = gate.allocate(&ReturnRoutable::established(&held), 1_000)?;
    gate.failed(lease, 1_000);
    assert!(!gate.is_backing_off(&held, 1_000));
    Ok(())
}

/// `handshake_timeout_ms`. A peer that opens exchanges and abandons them must
/// not hold the pool, and abandonment must not be cheaper than failing.
#[test]
fn an_abandoned_context_times_out_and_counts_as_a_failure() -> Fallible<()> {
    let mut gate = Gate::new();
    let held = source(0);
    for _ in 0..LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF {
        // The lease falls out of scope without succeeded() or failed(): the
        // peer simply stopped answering.
        gate.allocate(&ReturnRoutable::established(&held), 1_000)?;
    }
    assert_eq!(gate.contexts(), LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF);

    let after = 1_000 + u64::try_from(LIMIT_HANDSHAKE_TIMEOUT_MS)?;
    gate.sweep(after);
    assert_eq!(gate.contexts(), 0, "the pool was reclaimed");
    assert!(
        gate.is_backing_off(&held, after),
        "abandoning is not cheaper than failing"
    );
    Ok(())
}

/// The tracking table is state an attacker would otherwise grow for free. It is
/// bounded, and refuses rather than evicting, so a flood cannot flush a backoff.
#[test]
fn the_tracking_table_is_bounded_and_refuses_rather_than_evicting() -> Fallible<()> {
    let mut gate = Gate::new();
    // The first source fails into a backoff, then the table is filled by others.
    let victim = source(0);
    for _ in 0..LIMIT_MAX_FAILED_HANDSHAKES_BEFORE_BACKOFF {
        let lease = gate.allocate(&ReturnRoutable::established(&victim), 1_000)?;
        gate.failed(lease, 1_000);
    }
    assert!(gate.is_backing_off(&victim, 1_000));

    for index in 1..LIMIT_MAX_TRACKED_SOURCES {
        let held = source(index);
        if let Ok(lease) = gate.allocate(&ReturnRoutable::established(&held), 1_000) {
            gate.succeeded(lease);
        }
    }
    assert_eq!(gate.tracked_sources(), LIMIT_MAX_TRACKED_SOURCES);

    let overflow = source(LIMIT_MAX_TRACKED_SOURCES);
    assert_eq!(
        gate.allocate(&ReturnRoutable::established(&overflow), 1_000),
        Err(GateError::TrackingFull)
    );
    assert!(
        gate.is_backing_off(&victim, 1_000),
        "the backoff was not flushed to make room"
    );
    Ok(())
}

/// Tracking slots are reclaimed once they hold nothing, or the table would fill
/// permanently with sources that behaved.
#[test]
fn an_idle_source_releases_its_tracking_slot() -> Fallible<()> {
    let mut gate = Gate::new();
    let held = source(0);
    let lease = gate.allocate(&ReturnRoutable::established(&held), 1_000)?;
    gate.succeeded(lease);
    assert_eq!(gate.tracked_sources(), 1);

    gate.sweep(1_000 + u64::try_from(LIMIT_HANDSHAKE_BACKOFF_MS)? + 1);
    assert_eq!(gate.tracked_sources(), 0);
    Ok(())
}

/// A source holding a live context keeps its slot, even past the idle horizon:
/// releasing it would lose the accounting for a handshake still in flight.
#[test]
fn a_live_context_holds_its_tracking_slot() -> Fallible<()> {
    let mut gate = Gate::new();
    let held = source(0);
    let _lease = gate.allocate(&ReturnRoutable::established(&held), 1_000)?;

    // Short of the handshake timeout, so the context is still live.
    let later = 1_000 + u64::try_from(LIMIT_HANDSHAKE_TIMEOUT_MS)? - 1;
    gate.sweep(later);
    assert_eq!(gate.contexts(), 1);
    assert_eq!(gate.tracked_sources(), 1);
    Ok(())
}
