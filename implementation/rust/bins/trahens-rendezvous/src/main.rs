// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use codec_m2::{Candidate, Control, Envelope, Message, MessageType, P1Payload};
use node_runtime::p1::{
    commit_proof, offer_label, open_control, ready_proof, seal_control, seal_gateway_offer,
    verify_proof,
};
use node_runtime::{
    drain_links, event_channel, parse_hex, spawn_link, structured_event, unix_time_ms,
    write_link_metrics, CliArgs, Clock, LinkConfig, LinkEvent, LinkMetrics, NodeQueueBudget,
    RemoteInputDrops,
};
use protocol_registry::{
    ERROR_AUTHENTICATION_FAILED, ERROR_CAPABILITY_INVALID, ERROR_INTERNAL, ERROR_MALFORMED,
    ERROR_RESOURCE_EXHAUSTED, ERROR_STATE_VIOLATION, ERROR_TIMEOUT, LIMIT_CAPABILITY_TTL_MS,
    LIMIT_MAX_FAILED_REDEMPTIONS_PER_ROUTE, SUITE_R1,
};
use rendezvous_r1::Registry;
use state_machine::{Event, Phase, RouteTable};
use std::collections::HashMap;
use std::error::Error;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};
use trahens_crypto::{initialize, random_bytes, random_nonzero_16, signing_keypair, SecretBytes};

struct GatewayRoute {
    label: [u8; 16],
    /// Label this route was published under and is addressed by. Control
    /// travels upstream under it too, so the initiator recognises the chain it
    /// committed to rather than a branch token that names several.
    selector: [u8; 16],
    generation: u32,
    route_secret: SecretBytes<32>,
    // Wiped on drop for the same reason as the endpoint's copy.
    challenge: SecretBytes<32>,
    pseudonym: [u8; 16],
    failed_redemptions: usize,
}

fn control(
    message_type: MessageType,
    label: [u8; 16],
    generation: u32,
    protected_body: Vec<u8>,
) -> Envelope {
    Envelope {
        suite_id: SUITE_R1,
        message: Message::Control(Control {
            message_type,
            local_label: label,
            generation,
            expiry_class: 1,
            protected_body,
        }),
    }
}

fn send_control(
    link: &node_runtime::LinkHandle,
    route: &GatewayRoute,
    message_type: MessageType,
    payload: &P1Payload,
) -> Result<(), Box<dyn Error>> {
    let protected = seal_control(
        &route.route_secret.0,
        message_type,
        route.generation,
        payload,
    )?;
    link.send(control(
        message_type,
        route.selector,
        route.generation,
        protected,
    ))?;
    Ok(())
}

/// Reclaim every gateway route whose deadline has passed.
///
/// `event-lifecycle-profile-e1.md` section 9 requires expiry to be local and
/// non-blocking, and section 2 ranks it above every message sharing the same
/// timestamp, so it runs once per loop iteration rather than only when the
/// event channel falls idle.
fn reclaim_expired(
    now_ms: u64,
    routes: &mut HashMap<[u8; 16], GatewayRoute>,
    selectors: &mut HashMap<[u8; 16], [u8; 16]>,
    states: &mut RouteTable,
) -> usize {
    let expired: Vec<[u8; 16]> = routes
        .keys()
        .filter(|label| {
            states
                .get(label)
                .is_none_or(|state| state.expires_at_ms <= now_ms)
        })
        .copied()
        .collect();
    let count = expired.len();
    for label in expired {
        routes.remove(&label);
        selectors.retain(|_, branch| *branch != label);
        let _ = states.apply(label, Event::Timeout, now_ms);
    }
    states.expire(now_ms);
    count
}

fn collect_stopped(
    receiver: &std::sync::mpsc::Receiver<LinkEvent>,
    expected_peer: u32,
) -> Vec<(u32, LinkMetrics)> {
    let mut output = Vec::new();
    while let Ok(event) = receiver.recv_timeout(Duration::from_millis(100)) {
        if let LinkEvent::Stopped { peer_id, metrics } = event {
            output.push((peer_id, metrics));
            if peer_id == expected_peer {
                break;
            }
        }
    }
    output
}

fn run() -> Result<(), Box<dyn Error>> {
    initialize()?;
    let args = CliArgs::parse()?;
    let node_id = args.u32("id")?;
    let peer_id = args.u32("peer-id")?;
    let gateway_id = args.u32("gateway-id")?;
    let epoch = args.u32("epoch")?;
    let timeout_ms = args.u64_or("timeout-ms", 30_000)?;
    let metrics_path = args
        .optional("metrics", "rendezvous-metrics.json")
        .to_owned();
    let endpoint_handle = args
        .optional("endpoint-handle", "p1-endpoint")
        .as_bytes()
        .to_vec();

    let signing_seed = SecretBytes(parse_hex::<32>(args.required("signing-seed")?)?);
    let (signing_public, signing_secret) = signing_keypair(&signing_seed.0)?;
    let capability = SecretBytes(parse_hex::<32>(args.required("capability")?)?);
    // rendezvous-capability-r1.md section 3: the gateway registers its
    // short-lived pseudonym together with the capability, and advertises that
    // same pseudonym in every candidate. It is a property of the
    // registration, not of an individual route.
    let gateway_pseudonym = random_nonzero_16()?;
    let mut registry = Registry::default();
    registry.register(
        gateway_id,
        gateway_pseudonym,
        &capability,
        endpoint_handle,
        unix_time_ms(),
        args.u64_or("capability-ttl-ms", LIMIT_CAPABILITY_TTL_MS as u64)?,
    )?;
    drop(capability);

    let (event_sender, event_receiver) = event_channel();
    let budget = NodeQueueBudget::new();
    let link = spawn_link(
        LinkConfig {
            local_id: node_id,
            peer_id,
            bind: args.socket("bind")?,
            peer: args.socket("peer")?,
            base_key: parse_hex::<32>(args.required("key")?)?,
            epoch,
        },
        event_sender,
        budget.clone(),
    )?;

    let mut states = RouteTable::default();
    let mut routes: HashMap<[u8; 16], GatewayRoute> = HashMap::new();
    // Published offer label -> branch it answered.
    let mut selectors: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
    let mut drops = RemoteInputDrops::new();
    let clock = Clock::start();
    let deadline = clock.now_ms().saturating_add(timeout_ms);
    // Set by any terminal control: CLOSE for a completed route, CANCEL or
    // ABORT for one the initiator stood down.
    let mut observed_terminal = false;
    let mut transport_failed = false;
    let mut cleanup_started: Option<Instant> = None;
    let mut redemption_latency_ms = 0_u64;

    while clock.now_ms() < deadline {
        // Expiry runs before every event, not only when the channel is idle.
        // Registrations carry a wall-clock TTL because the client asserts its
        // validity interval on the wire; route state is purely local.
        registry.expire(unix_time_ms());
        reclaim_expired(clock.now_ms(), &mut routes, &mut selectors, &mut states);
        let event = match event_receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(value) => value,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        match event {
            LinkEvent::Message {
                peer_id: received_peer,
                envelope,
                ..
            } if received_peer == peer_id => match envelope.message {
                Message::Discover(discover) => {
                    if routes.contains_key(&discover.branch_token) {
                        drops.record("rendezvous", ERROR_STATE_VIOLATION, "discover_duplicate");
                        continue;
                    }
                    // A malformed discovery field is remote input: it costs
                    // this DISCOVER, never the gateway.
                    let Ok(discovery_nonce) =
                        <[u8; 32]>::try_from(discover.discovery_field.as_slice())
                    else {
                        drops.record("rendezvous", ERROR_MALFORMED, "discover_nonce_length");
                        continue;
                    };
                    // Randomness is a local subsystem: if it fails the process
                    // cannot serve anyone and stopping is correct.
                    let route_secret = random_bytes::<32>()?;
                    let challenge = random_bytes::<32>()?;
                    let pseudonym = gateway_pseudonym;
                    if route_secret == [0_u8; 32] || challenge == [0_u8; 32] {
                        return Err("gateway generated an invalid route secret".into());
                    }
                    // The offer expiry crosses the wire and is compared by the
                    // initiator, so it is wall clock. The route table's copy is
                    // a local deadline and uses the monotonic clock.
                    let expires_at_ms =
                        unix_time_ms().saturating_add(Phase::Discovering.lifetime_ms());
                    let state_expires_at_ms = clock
                        .now_ms()
                        .saturating_add(Phase::Discovering.lifetime_ms());
                    // The reply key is remote input, so an invalid point is
                    // this peer's problem rather than the gateway's.
                    let Ok(blob) = seal_gateway_offer(
                        &discover.reply_public_key,
                        gateway_id,
                        expires_at_ms,
                        pseudonym,
                        route_secret,
                        challenge,
                        discovery_nonce,
                        signing_public,
                        &signing_secret,
                    ) else {
                        drops.record("rendezvous", ERROR_MALFORMED, "discover_reply_public_key");
                        continue;
                    };
                    // The offer travels upstream under a label derived from
                    // the discovery nonce this gateway was given, so the
                    // adjacent relay can resolve it to the branch it belongs
                    // to while telling it apart from any sibling's offer.
                    let Ok(selector) = offer_label(&discovery_nonce, 0) else {
                        drops.record("rendezvous", ERROR_INTERNAL, "offer_label_derivation");
                        continue;
                    };
                    // A peer filling the route table is admission pressure, not
                    // a gateway fault. Propagating PeerLimit or GlobalLimit out
                    // of run() let a flood of perfectly valid discoveries
                    // terminate the process.
                    if states
                        .begin(discover.branch_token, peer_id, 0, state_expires_at_ms)
                        .is_err()
                    {
                        drops.record("rendezvous", ERROR_RESOURCE_EXHAUSTED, "route_table_limit");
                        continue;
                    }
                    if states
                        .apply(
                            discover.branch_token,
                            Event::CandidateAccepted,
                            clock.now_ms(),
                        )
                        .is_err()
                    {
                        drops.record("rendezvous", ERROR_STATE_VIOLATION, "candidate_transition");
                        let _ = states.apply(
                            discover.branch_token,
                            Event::CancelAccepted,
                            clock.now_ms(),
                        );
                        continue;
                    }
                    selectors.insert(selector, discover.branch_token);
                    routes.insert(
                        discover.branch_token,
                        GatewayRoute {
                            label: discover.branch_token,
                            selector,
                            generation: 0,
                            route_secret: SecretBytes(route_secret),
                            challenge: SecretBytes(challenge),
                            pseudonym,
                            failed_redemptions: 0,
                        },
                    );
                    if link
                        .send(Envelope {
                            suite_id: SUITE_R1,
                            message: Message::Candidate(Candidate {
                                candidate_token: selector,
                                expiry_class: discover.expiry_class,
                                layer_count: 1,
                                candidate_blob: blob,
                            }),
                        })
                        .is_err()
                    {
                        // A full outbound queue is back pressure produced by
                        // remote volume, so it drops this answer rather than
                        // the gateway.
                        drops.record(
                            "rendezvous",
                            ERROR_RESOURCE_EXHAUSTED,
                            "outbound_queue_full",
                        );
                    }
                }
                Message::Control(control_message) => {
                    // Control arrives addressed to the offer label the gateway
                    // published, which resolves back to its branch.
                    let route_label = selectors
                        .get(&control_message.local_label)
                        .copied()
                        .unwrap_or(control_message.local_label);
                    let mut cleanup_event = None;
                    {
                        let Some(route) = routes.get_mut(&route_label) else {
                            continue;
                        };
                        if control_message.generation != route.generation {
                            continue;
                        }
                        // CANCEL and ABORT are hop-local lifecycle signals
                        // with no end-to-end payload: the relay that sends one
                        // does not hold this route's secret, so there is no
                        // sealed body to open. Their authority comes from the
                        // authenticated link they arrived on and from the
                        // label resolving to a live route.
                        if matches!(
                            control_message.message_type,
                            MessageType::Cancel | MessageType::Abort
                        ) {
                            structured_event("rendezvous", "route_cancelled", &[]);
                            cleanup_started = Some(Instant::now());
                            observed_terminal = true;
                            cleanup_event = Some(Event::CancelAccepted);
                        } else {
                            let Ok(payload) = open_control(
                                &route.route_secret.0,
                                control_message.message_type,
                                route.generation,
                                &control_message.protected_body,
                            ) else {
                                drops.record(
                                    "rendezvous",
                                    ERROR_AUTHENTICATION_FAILED,
                                    "control_body",
                                );
                                continue;
                            };
                            match (control_message.message_type, payload) {
                                (MessageType::Commit, P1Payload::Commit { proof }) => {
                                    let expected = commit_proof(
                                        &route.route_secret.0,
                                        &route.challenge.0,
                                        &route.pseudonym,
                                    )?;
                                    // The proof is remote input: a mismatch or a
                                    // duplicate COMMIT is dropped, never fatal.
                                    if verify_proof(&expected, &proof).is_err() {
                                        drops.record(
                                            "rendezvous",
                                            ERROR_AUTHENTICATION_FAILED,
                                            "commit_proof",
                                        );
                                        continue;
                                    }
                                    if states
                                        .apply(route.label, Event::CommitAccepted, clock.now_ms())
                                        .is_err()
                                    {
                                        drops.record(
                                            "rendezvous",
                                            ERROR_STATE_VIOLATION,
                                            "commit_transition",
                                        );
                                        continue;
                                    }
                                    let ready = ready_proof(
                                        &route.route_secret.0,
                                        &route.challenge.0,
                                        &route.pseudonym,
                                    )?;
                                    send_control(
                                        &link,
                                        route,
                                        MessageType::Ready,
                                        &P1Payload::Ready { proof: ready },
                                    )?;
                                    if states
                                        .apply(route.label, Event::ReadyAccepted, clock.now_ms())
                                        .is_err()
                                    {
                                        drops.record(
                                            "rendezvous",
                                            ERROR_STATE_VIOLATION,
                                            "ready_transition",
                                        );
                                        continue;
                                    }
                                }
                                (
                                    MessageType::RendezvousOpen,
                                    P1Payload::RendezvousOpen {
                                        capability,
                                        client_nonce,
                                        expiration_ms,
                                        endpoint_handshake,
                                    },
                                ) => {
                                    let started = Instant::now();
                                    let phase = states.get(&route.label).map(|state| state.phase);
                                    let mut status = ERROR_STATE_VIOLATION;
                                    let now = unix_time_ms();
                                    // section 5: verify the half-open validity
                                    // interval the client asserts before touching
                                    // the registration.
                                    let interval_valid =
                                        expiration_ms > now && client_nonce != [0_u8; 16];
                                    if phase == Some(Phase::Ready) && interval_valid {
                                        let presented = SecretBytes(capability);
                                        status = match registry.redeem_for_pseudonym(
                                            gateway_id,
                                            &route.pseudonym,
                                            &presented,
                                            now,
                                        )? {
                                            Some(handle) => {
                                                // The handshake the client supplied
                                                // is the local rendezvous policy
                                                // input; the handle is what the
                                                // gateway hands to it.
                                                structured_event(
                                                    "rendezvous",
                                                    "capability_redeemed",
                                                    &[
                                                        (
                                                            "handshake_bytes",
                                                            endpoint_handshake.len().to_string(),
                                                        ),
                                                        ("handle_bytes", handle.len().to_string()),
                                                    ],
                                                );
                                                states.apply(
                                                    route.label,
                                                    Event::CapabilityAccepted,
                                                    clock.now_ms(),
                                                )?;
                                                0
                                            }
                                            None => {
                                                route.failed_redemptions =
                                                    route.failed_redemptions.saturating_add(1);
                                                ERROR_CAPABILITY_INVALID
                                            }
                                        };
                                    }
                                    redemption_latency_ms = started
                                        .elapsed()
                                        .as_micros()
                                        .try_into()
                                        .unwrap_or(u64::MAX);
                                    send_control(
                                        &link,
                                        route,
                                        MessageType::RendezvousResult,
                                        &P1Payload::RendezvousResult { status },
                                    )?;
                                    if route.failed_redemptions
                                        >= LIMIT_MAX_FAILED_REDEMPTIONS_PER_ROUTE
                                    {
                                        cleanup_started = Some(Instant::now());
                                        cleanup_event = Some(Event::CancelAccepted);
                                    }
                                }
                                (
                                    MessageType::Data,
                                    P1Payload::Data {
                                        direction: 0,
                                        sequence,
                                        payload,
                                    },
                                ) => {
                                    if states.get(&route.label).map(|state| state.phase)
                                        != Some(Phase::Open)
                                    {
                                        continue;
                                    }
                                    states.apply(
                                        route.label,
                                        Event::DataAccepted,
                                        clock.now_ms(),
                                    )?;
                                    send_control(
                                        &link,
                                        route,
                                        MessageType::Data,
                                        &P1Payload::Data {
                                            direction: 1,
                                            sequence,
                                            payload,
                                        },
                                    )?;
                                }
                                (MessageType::Close, P1Payload::Close { .. }) => {
                                    cleanup_started = Some(Instant::now());
                                    observed_terminal = true;
                                    cleanup_event = Some(Event::CloseAccepted);
                                }
                                _ => {}
                            }
                        }
                    }
                    if let Some(event) = cleanup_event {
                        routes.remove(&route_label);
                        selectors.retain(|_, branch| *branch != route_label);
                        let _ = states.apply(route_label, event, clock.now_ms());
                    }
                }
                _ => {}
            },
            LinkEvent::TransmissionFailed { .. } => {
                structured_event(
                    "rendezvous",
                    "transport_failure",
                    &[("error_id", ERROR_TIMEOUT.to_string())],
                );
                transport_failed = true;
                cleanup_started.get_or_insert_with(Instant::now);
                break;
            }
            LinkEvent::SecurityEvent {
                peer_id: source,
                error_id,
                detail,
            } => {
                structured_event(
                    "rendezvous",
                    "security_event",
                    &[
                        ("peer", source.to_string()),
                        ("error_id", error_id.to_string()),
                        ("detail", detail.to_owned()),
                    ],
                );
            }
            _ => {}
        }
        if observed_terminal && routes.is_empty() {
            drain_links(&[&link], &event_receiver);
            break;
        }
    }

    // One cleanup funnel for every exit, planned or not.
    routes.clear();
    selectors.clear();
    states.reclaim_all(Event::Timeout, clock.now_ms());
    let lifecycle_lost = link.lifecycle_lost();
    link.shutdown()?;
    let metrics = collect_stopped(&event_receiver, peer_id);
    let cleanup_ms = cleanup_started
        .map(|value| value.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0);
    write_link_metrics(
        &metrics_path,
        "rendezvous",
        states.live_routes(),
        cleanup_ms,
        &drops,
        states.peaks(),
        &metrics,
    )?;
    structured_event(
        "rendezvous",
        "stopped",
        &[
            ("live_routes", states.live_routes().to_string()),
            ("capabilities", registry.live_records().to_string()),
            ("redemption_latency_us", redemption_latency_ms.to_string()),
        ],
    );
    if lifecycle_lost {
        return Err("a link event was lost; this gateway's view of the link is incomplete".into());
    }
    if transport_failed {
        return Err(format!("T1 retry budget exhausted; status={ERROR_TIMEOUT}").into());
    }
    if !observed_terminal {
        return Err("rendezvous timed out before route cleanup".into());
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("trahens-rendezvous: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_envelopes_carry_the_r1_suite() {
        let envelope = control(MessageType::RendezvousResult, [0x07; 16], 2, vec![1]);
        assert_eq!(envelope.suite_id, SUITE_R1);
    }

    #[test]
    fn reclaim_expired_releases_lapsed_routes_and_spares_live_ones() -> Result<(), Box<dyn Error>> {
        let lapsed = [0x41; 16];
        let live = [0x42; 16];
        let mut routes = HashMap::new();
        let mut selectors = HashMap::new();
        let mut states = RouteTable::default();
        for (label, deadline) in [(lapsed, 100_u64), (live, 900)] {
            states.begin(label, 1, 0, deadline)?;
            routes.insert(
                label,
                GatewayRoute {
                    label,
                    selector: label,
                    generation: 0,
                    route_secret: SecretBytes([1; 32]),
                    challenge: SecretBytes([2; 32]),
                    pseudonym: [3; 16],
                    failed_redemptions: 0,
                },
            );
        }

        assert_eq!(
            reclaim_expired(500, &mut routes, &mut selectors, &mut states),
            1
        );
        assert!(!routes.contains_key(&lapsed));
        assert!(routes.contains_key(&live));
        assert_eq!(states.live_routes(), 1);
        assert_eq!(
            reclaim_expired(500, &mut routes, &mut selectors, &mut states),
            0
        );
        Ok(())
    }

    #[test]
    fn control_preserves_its_arguments() {
        let body = vec![8, 8, 8];
        let envelope = control(MessageType::RendezvousOpen, [0x0c; 16], 11, body.clone());

        let Message::Control(built) = envelope.message else {
            panic!("control must produce a control message");
        };
        assert_eq!(built.message_type, MessageType::RendezvousOpen);
        assert_eq!(built.local_label, [0x0c; 16]);
        assert_eq!(built.generation, 11);
        assert_eq!(built.protected_body, body);
        assert_eq!(built.expiry_class, 1);
    }
}
