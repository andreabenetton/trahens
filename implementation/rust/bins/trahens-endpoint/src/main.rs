// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use codec_m2::{Candidate, Control, Discover, Envelope, Message, MessageType, P1Payload};
use node_runtime::p1::{
    commit_proof, open_candidate_chain, open_control, ready_proof, seal_control, verify_proof,
};
use node_runtime::{
    drain_links, event_channel, parse_hex, spawn_link, structured_event, unix_time_ms,
    write_link_metrics, CliArgs, Clock, LinkConfig, LinkEvent, LinkMetrics, NodeQueueBudget,
    RemoteInputDrops,
};
use protocol_registry::{
    ERROR_AUTHENTICATION_FAILED, ERROR_CAPABILITY_INVALID, ERROR_INTERNAL, ERROR_STATE_VIOLATION,
    ERROR_TIMEOUT, LIMIT_CAPABILITY_TTL_MS, LIMIT_ROUTE_TTL_MS, SUITE_R1,
};
use state_machine::{Event, RouteTable};
use std::error::Error;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};
use trahens_crypto::{
    initialize, random_bytes, random_nonzero_16, random_scalar, scalar_base, SecretBytes,
};

struct ActiveRoute {
    /// Wire address for this route: the selector the initiator committed to.
    local_label: [u8; 16],
    /// Branch this route came from, which keys the local route state.
    state_label: [u8; 16],
    generation: u32,
    route_secret: SecretBytes<32>,
    // The commit challenge is a keyed-proof input shared with the gateway;
    // Core v1.5 section 8.4 requires it to be wiped when the route ends.
    challenge: SecretBytes<32>,
    pseudonym: [u8; 16],
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
    route: &ActiveRoute,
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
        route.local_label,
        route.generation,
        protected,
    ))?;
    Ok(())
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

/// One entry of the initiator-local ring schedule.
///
/// `event-lifecycle-profile-e1.md` section 3: the schedule is local policy and
/// MUST NOT appear in a wire message, so it is configured on the command line
/// and only its depth and fan-out class reach a DISCOVER.
#[derive(Debug, Clone, Copy)]
struct Ring {
    depth: u8,
    fanout_class: u8,
    window_ms: u64,
}

/// Per-ring discovery context. Each ring uses a fresh branch token and
/// discovery nonce, and the context is retained after the ring closes so a
/// candidate from an earlier ring stays eligible (section 3).
struct RingContext {
    ring: usize,
    branch_token: [u8; 16],
    discovery_nonce: [u8; 32],
}

/// A candidate offer held until its ring window closes.
struct HeldCandidate {
    ring: usize,
    /// Branch this offer answered. Keys the local route state.
    branch_token: [u8; 16],
    /// Tentative selector the adjacent relay minted for this one offer. A
    /// COMMIT addressed to it names this chain out of the several a fanned-out
    /// branch may return; the branch token alone would not.
    selector: [u8; 16],
    hop_count: u8,
    arrived_ms: u64,
    opened: node_runtime::p1::OpenedOffer,
}

/// Parse `depth:window_ms[,depth:window_ms...]`, e.g. "4:400,16:1200".
fn parse_rings(text: &str, fanout_class: u8) -> Result<Vec<Ring>, Box<dyn Error>> {
    let mut rings = Vec::new();
    for entry in text.split(',').filter(|item| !item.is_empty()) {
        let (depth, window) = entry
            .split_once(':')
            .ok_or("ring schedule entries are depth:window_ms")?;
        rings.push(Ring {
            depth: depth.parse()?,
            fanout_class,
            window_ms: window.parse()?,
        });
    }
    if rings.is_empty() {
        return Err("ring schedule must define at least one ring".into());
    }
    Ok(rings)
}

/// Deterministic selection order from section 5: minimum hop count, then
/// earliest arrival. Later tie-breakers are simulator-only and deliberately
/// omitted, since a production profile must not expose stable identity.
fn best_candidate(candidates: &[HeldCandidate]) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .min_by_key(|(index, candidate)| (candidate.hop_count, candidate.arrived_ms, *index))
        .map(|(index, _)| index)
}

fn run() -> Result<(), Box<dyn Error>> {
    initialize()?;
    let args = CliArgs::parse()?;
    let node_id = args.u32("id")?;
    let peer_id = args.u32("peer-id")?;
    let base_key = parse_hex::<32>(args.required("key")?)?;
    let expected_gateway_public = parse_hex::<32>(args.required("gateway-public")?)?;
    let capability = SecretBytes(parse_hex::<32>(args.required("capability")?)?);
    let message = args.optional("message", "trahens-p1").as_bytes().to_vec();
    let timeout_ms = args.u64_or("timeout-ms", 20_000)?;
    let metrics_path = args.optional("metrics", "endpoint-metrics.json").to_owned();
    let epoch = args.u32("epoch")?;

    let (event_sender, event_receiver) = event_channel();
    let budget = NodeQueueBudget::new();
    let link = spawn_link(
        LinkConfig {
            local_id: node_id,
            peer_id,
            bind: args.socket("bind")?,
            peer: args.socket("peer")?,
            base_key,
            epoch,
        },
        event_sender,
        budget.clone(),
    )?;

    let root_secret = SecretBytes(random_scalar()?);
    let reply_public_key = scalar_base(&root_secret.0)?;
    let rings = parse_rings(
        args.optional("rings", "16:1500"),
        u8::try_from(args.u64_or("fanout-class", 1)?).unwrap_or(1),
    )?;
    let endpoint_handshake = args
        .optional("endpoint-handle", "p1-endpoint")
        .as_bytes()
        .to_vec();
    let generation = 0_u32;
    let setup_started = Instant::now();
    let clock = Clock::start();
    let absolute_deadline = clock.now_ms().saturating_add(timeout_ms);
    let mut state = RouteTable::default();
    let mut drops = RemoteInputDrops::new();
    // Ring 0 opens immediately; later rings open only if the window closes
    // with nothing selectable.
    let mut contexts: Vec<RingContext> = Vec::new();
    let mut held: Vec<HeldCandidate> = Vec::new();
    let mut ring_index = 0_usize;
    let mut candidates_seen = 0_u64;
    let mut late_candidates = 0_u64;
    let mut candidates_dropped = 0_u64;
    let mut selected_branch: Option<[u8; 16]> = None;
    let candidate_threshold = usize::try_from(args.u64_or("candidate-threshold", 1)?).unwrap_or(1);
    let mut cancelled_branches = 0_u64;
    let mut no_candidate = false;

    let open_ring = |index: usize,
                     contexts: &mut Vec<RingContext>,
                     state: &mut RouteTable|
     -> Result<u64, Box<dyn Error>> {
        let now_ms = clock.now_ms();
        let ring = rings[index];
        let branch_token = random_nonzero_16()?;
        let discovery_nonce = random_bytes::<32>()?;
        if discovery_nonce == [0_u8; 32] {
            return Err("random discovery nonce was zero".into());
        }
        state.begin(
            branch_token,
            peer_id,
            generation,
            now_ms.saturating_add(LIMIT_ROUTE_TTL_MS as u64),
        )?;
        link.send(Envelope {
            suite_id: SUITE_R1,
            message: Message::Discover(Discover {
                branch_token,
                hop_remaining: ring.depth,
                fanout_class: ring.fanout_class,
                expiry_class: 1,
                options: 0,
                reply_public_key,
                discovery_field: discovery_nonce.to_vec(),
            }),
        })?;
        contexts.push(RingContext {
            ring: index,
            branch_token,
            discovery_nonce,
        });
        structured_event(
            "endpoint",
            "discovery_sent",
            &[
                ("ring", index.to_string()),
                ("depth", ring.depth.to_string()),
                ("fanout_class", ring.fanout_class.to_string()),
            ],
        );
        Ok(now_ms.saturating_add(ring.window_ms))
    };

    let mut window_closes_ms = open_ring(0, &mut contexts, &mut state)?;

    let mut active: Option<ActiveRoute> = None;
    let mut success = false;
    let mut setup_latency_ms = 0_u64;
    let mut cleanup_started = None;
    let mut transport_failed = false;
    let mut redemption_refused = false;
    let redeem_twice = args.flag("redeem-twice");
    let mut redemptions = 0_u32;

    while clock.now_ms() < absolute_deadline {
        // Expiry runs before every event, not only when the channel is idle:
        // continuous candidate traffic must not keep a lapsed branch usable.
        state.expire(clock.now_ms());
        // Wake no later than the pending window boundary, so a met threshold
        // is acted on immediately instead of waiting out a fixed tick.
        let wait = if selected_branch.is_some() {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(window_closes_ms.saturating_sub(clock.now_ms()).min(100))
        };
        let event = match event_receiver.recv_timeout(wait) {
            Ok(value) => value,
            Err(RecvTimeoutError::Timeout) => {
                let now = clock.now_ms();
                if selected_branch.is_some() || now < window_closes_ms {
                    continue;
                }

                // Section 3, window boundary: drop expired offers, select if
                // anything remains, otherwise open the next ring, and on the
                // final ring terminate with NO_CANDIDATE.
                // The offer expiry was minted by the gateway and travels on
                // the wire, so it is compared against wall clock.
                let before = held.len();
                let wall_now = unix_time_ms();
                held.retain(|candidate| candidate.opened.expires_at_ms > wall_now);
                candidates_dropped += (before - held.len()) as u64;

                if let Some(index) = best_candidate(&held) {
                    let chosen = held.swap_remove(index);
                    structured_event(
                        "endpoint",
                        "candidate_selected",
                        &[
                            ("ring", chosen.ring.to_string()),
                            ("hops", chosen.hop_count.to_string()),
                            ("candidates", candidates_seen.to_string()),
                        ],
                    );
                    selected_branch = Some(chosen.branch_token);

                    // Section 5: cancel every other live branch of this
                    // logical discovery so no off-route state is stranded.
                    for context in &contexts {
                        if context.branch_token == chosen.branch_token {
                            continue;
                        }
                        link.send(Envelope {
                            suite_id: SUITE_R1,
                            message: Message::Control(Control {
                                message_type: MessageType::Cancel,
                                local_label: context.branch_token,
                                generation,
                                expiry_class: 1,
                                protected_body: vec![0_u8],
                            }),
                        })?;
                        let _ = state.apply(
                            context.branch_token,
                            Event::CancelAccepted,
                            clock.now_ms(),
                        );
                        cancelled_branches += 1;
                        structured_event("endpoint", "branch_cancelled", &[]);
                    }
                    candidates_dropped += held.len() as u64;
                    held.clear();

                    let route = ActiveRoute {
                        local_label: chosen.selector,
                        state_label: chosen.branch_token,
                        generation,
                        route_secret: SecretBytes(chosen.opened.route_secret),
                        challenge: SecretBytes(chosen.opened.commit_challenge),
                        pseudonym: chosen.opened.gateway_pseudonym,
                    };
                    let proof =
                        commit_proof(&route.route_secret.0, &route.challenge.0, &route.pseudonym)?;
                    send_control(
                        &link,
                        &route,
                        MessageType::Commit,
                        &P1Payload::Commit { proof },
                    )?;
                    state.apply(route.state_label, Event::CommitAccepted, clock.now_ms())?;
                    active = Some(route);
                    continue;
                }

                if ring_index + 1 < rings.len() {
                    ring_index += 1;
                    window_closes_ms = open_ring(ring_index, &mut contexts, &mut state)?;
                    continue;
                }

                // Section 3 step 5: terminating with NO_CANDIDATE still has to
                // release every branch this discovery opened, exactly as
                // selection does for the branches it does not choose.
                for context in &contexts {
                    link.send(Envelope {
                        suite_id: SUITE_R1,
                        message: Message::Control(Control {
                            message_type: MessageType::Cancel,
                            local_label: context.branch_token,
                            generation,
                            expiry_class: 1,
                            protected_body: vec![0_u8],
                        }),
                    })?;
                    let _ =
                        state.apply(context.branch_token, Event::CancelAccepted, clock.now_ms());
                    cancelled_branches += 1;
                }
                structured_event(
                    "endpoint",
                    "no_candidate",
                    &[
                        ("rings", rings.len().to_string()),
                        ("candidates", candidates_seen.to_string()),
                        ("branches_cancelled", cancelled_branches.to_string()),
                    ],
                );
                no_candidate = true;
                // Let the cancellations reach the path before shutting down.
                drain_links(&[&link], &event_receiver);
                break;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        match event {
            LinkEvent::Message {
                peer_id: received_peer,
                envelope,
                ..
            } if received_peer == peer_id => match envelope.message {
                Message::Candidate(Candidate {
                    candidate_token,
                    layer_count,
                    candidate_blob,
                    ..
                }) => {
                    // Hold the offer until its ring window closes: section 5
                    // makes selection a window-boundary decision, so accepting
                    // the first arrival would defeat the ordering rule.
                    if selected_branch.is_some() {
                        // Section 5: after selection no further branches are
                        // admitted for this logical discovery.
                        late_candidates += 1;
                        candidates_dropped += 1;
                        structured_event("endpoint", "late_candidate_dropped", &[]);
                        continue;
                    }
                    // Each returned offer now carries its own tentative
                    // selector, minted by the first relay, so the token is not
                    // a branch token this node has seen. The ring is
                    // identified instead by the discovery-nonce chain the
                    // candidate is bound to, which is the binding that
                    // actually authenticates the offer.
                    let Some((ring, branch_token, opened)) = contexts.iter().find_map(|context| {
                        open_candidate_chain(
                            &root_secret.0,
                            &candidate_blob,
                            layer_count,
                            &expected_gateway_public,
                            &context.discovery_nonce,
                            unix_time_ms(),
                        )
                        .ok()
                        .map(|opened| (context.ring, context.branch_token, opened))
                    }) else {
                        drops.record("endpoint", ERROR_AUTHENTICATION_FAILED, "candidate_chain");
                        continue;
                    };
                    if state
                        .apply(branch_token, Event::CandidateAccepted, clock.now_ms())
                        .is_err()
                    {
                        drops.record("endpoint", ERROR_STATE_VIOLATION, "candidate_transition");
                        continue;
                    }
                    candidates_seen += 1;
                    if ring != ring_index {
                        // Eligible but from a ring that has already closed.
                        late_candidates += 1;
                    }
                    held.push(HeldCandidate {
                        ring,
                        branch_token,
                        selector: candidate_token,
                        hop_count: layer_count,
                        arrived_ms: clock.now_ms(),
                        opened,
                    });
                    structured_event(
                        "endpoint",
                        "candidate_held",
                        &[
                            ("ring", ring.to_string()),
                            ("layers", layer_count.to_string()),
                        ],
                    );
                    // Section 3 step 2 closes the window as soon as the
                    // configured threshold is met. Selection still happens at
                    // a window boundary; the threshold decides when that
                    // boundary arrives, so a single-candidate path does not
                    // wait out a window it cannot improve on.
                    if held.len() >= candidate_threshold {
                        window_closes_ms = clock.now_ms();
                    }
                }
                Message::Control(control_message) => {
                    let Some(route) = active.as_ref() else {
                        continue;
                    };
                    if control_message.local_label != route.local_label
                        || control_message.generation != route.generation
                    {
                        continue;
                    }
                    // Sealed control bodies are remote input: authentication
                    // failure drops the message, never the process.
                    let Ok(payload) = open_control(
                        &route.route_secret.0,
                        control_message.message_type,
                        route.generation,
                        &control_message.protected_body,
                    ) else {
                        drops.record("endpoint", ERROR_AUTHENTICATION_FAILED, "control_body");
                        continue;
                    };
                    match (control_message.message_type, payload) {
                        (MessageType::Ready, P1Payload::Ready { proof }) => {
                            let expected = ready_proof(
                                &route.route_secret.0,
                                &route.challenge.0,
                                &route.pseudonym,
                            )?;
                            if verify_proof(&expected, &proof).is_err() {
                                drops.record(
                                    "endpoint",
                                    ERROR_AUTHENTICATION_FAILED,
                                    "ready_proof",
                                );
                                continue;
                            }
                            if state
                                .apply(route.state_label, Event::ReadyAccepted, clock.now_ms())
                                .is_err()
                            {
                                drops.record("endpoint", ERROR_STATE_VIOLATION, "ready_transition");
                                continue;
                            }
                            setup_latency_ms = setup_started
                                .elapsed()
                                .as_millis()
                                .try_into()
                                .unwrap_or(u64::MAX);
                            send_control(
                                &link,
                                route,
                                MessageType::RendezvousOpen,
                                &P1Payload::RendezvousOpen {
                                    capability: capability.0,
                                    // Fresh per redemption: binds this
                                    // presentation to this attempt.
                                    client_nonce: random_nonzero_16()?,
                                    expiration_ms: unix_time_ms()
                                        .saturating_add(LIMIT_CAPABILITY_TTL_MS as u64),
                                    endpoint_handshake: endpoint_handshake.clone(),
                                },
                            )?;
                        }
                        (MessageType::RendezvousResult, P1Payload::RendezvousResult { status }) => {
                            if redeem_twice && status == 0 && redemptions == 0 {
                                // Replay arm: present the same capability a
                                // second time. R1 section 5 makes redemption
                                // one-time, so the gateway must answer with a
                                // generic failure.
                                redemptions += 1;
                                structured_event("endpoint", "replaying_capability", &[]);
                                send_control(
                                    &link,
                                    route,
                                    MessageType::RendezvousOpen,
                                    &P1Payload::RendezvousOpen {
                                        capability: capability.0,
                                        client_nonce: random_nonzero_16()?,
                                        expiration_ms: unix_time_ms()
                                            .saturating_add(LIMIT_CAPABILITY_TTL_MS as u64),
                                        endpoint_handshake: endpoint_handshake.clone(),
                                    },
                                )?;
                                continue;
                            }
                            if redeem_twice && redemptions == 1 {
                                if status == 0 {
                                    return Err("replayed capability was accepted".into());
                                }
                                structured_event(
                                    "endpoint",
                                    "replay_rejected",
                                    &[("status", status.to_string())],
                                );
                                // Rejection is the expected outcome: close the
                                // route so every node still reclaims state.
                                send_control(
                                    &link,
                                    route,
                                    MessageType::Close,
                                    &P1Payload::Close { reason: 0 },
                                )?;
                                cleanup_started = Some(Instant::now());
                                state.apply(
                                    route.state_label,
                                    Event::CloseAccepted,
                                    clock.now_ms(),
                                )?;
                                success = true;
                                break;
                            }
                            if status != 0 {
                                // The gateway's answer is remote input. A
                                // refusal ends this route, so it is recorded
                                // and closed through the normal path rather
                                // than raised from inside the event loop.
                                drops.record(
                                    "endpoint",
                                    ERROR_CAPABILITY_INVALID,
                                    "rendezvous_refused",
                                );
                                send_control(
                                    &link,
                                    route,
                                    MessageType::Close,
                                    &P1Payload::Close { reason: 0 },
                                )?;
                                cleanup_started = Some(Instant::now());
                                redemption_refused = true;
                                break;
                            }
                            state.apply(
                                route.state_label,
                                Event::CapabilityAccepted,
                                clock.now_ms(),
                            )?;
                            send_control(
                                &link,
                                route,
                                MessageType::Data,
                                &P1Payload::Data {
                                    direction: 0,
                                    sequence: 0,
                                    payload: message.clone(),
                                },
                            )?;
                        }
                        (
                            MessageType::Data,
                            P1Payload::Data {
                                direction: 1,
                                sequence: 0,
                                payload,
                            },
                        ) => {
                            if payload != message {
                                // The echoed body is remote input: a mismatch
                                // is this peer misbehaving, so it is counted
                                // and the route closed, not raised as a local
                                // fault.
                                drops.record("endpoint", ERROR_STATE_VIOLATION, "echo_mismatch");
                                continue;
                            }
                            state.apply(route.state_label, Event::DataAccepted, clock.now_ms())?;
                            send_control(
                                &link,
                                route,
                                MessageType::Close,
                                &P1Payload::Close { reason: 0 },
                            )?;
                            cleanup_started = Some(Instant::now());
                            state.apply(route.state_label, Event::CloseAccepted, clock.now_ms())?;
                            success = true;
                            break;
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            LinkEvent::TransmissionFailed { .. } => {
                // Break rather than return: the shared path below reclaims
                // route state and writes metrics before the process exits.
                structured_event(
                    "endpoint",
                    "transport_failure",
                    &[("error_id", ERROR_TIMEOUT.to_string())],
                );
                transport_failed = true;
                cleanup_started.get_or_insert_with(Instant::now);
                break;
            }
            LinkEvent::SecurityEvent {
                error_id, detail, ..
            } => {
                structured_event(
                    "endpoint",
                    "security_event",
                    &[
                        ("error_id", error_id.to_string()),
                        ("detail", detail.to_owned()),
                    ],
                );
            }
            _ => {}
        }
    }

    if success {
        drain_links(&[&link], &event_receiver);
    }
    // Every exit funnels through here: success, NO_CANDIDATE, transport
    // failure, channel disconnection, a terminal authentication failure, and
    // the absolute deadline. Releasing only the selected branch stranded every
    // ring context whenever the run ended before anything was selected, which
    // is exactly when the failure paths end.
    let reclaimed = state.reclaim_all(Event::Timeout, clock.now_ms());
    drop(active.take());
    let cleanup_ms = cleanup_started
        .map(|started| started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0);
    link.shutdown()?;
    let metrics = collect_stopped(&event_receiver, peer_id);
    write_link_metrics(
        &metrics_path,
        "endpoint",
        state.live_routes(),
        cleanup_ms,
        &drops,
        state.peaks(),
        &metrics,
    )?;

    structured_event(
        "endpoint",
        "discovery_measurements",
        &[
            ("candidates", candidates_seen.to_string()),
            ("late_candidates", late_candidates.to_string()),
            ("candidates_dropped", candidates_dropped.to_string()),
            ("branches_cancelled", cancelled_branches.to_string()),
            ("rings_opened", contexts.len().to_string()),
            ("selected", u8::from(selected_branch.is_some()).to_string()),
            ("routes_reclaimed_at_exit", reclaimed.to_string()),
        ],
    );
    if no_candidate {
        // A terminal NO_CANDIDATE is an ordinary outcome, not a fault: every
        // branch has been cancelled or expired and state is reclaimed.
        return Err("discovery terminated with NO_CANDIDATE".into());
    }
    if transport_failed {
        return Err(format!("T1 retry budget exhausted; status={ERROR_TIMEOUT}").into());
    }
    if redemption_refused {
        return Err(
            format!("rendezvous redemption refused; status={ERROR_CAPABILITY_INVALID}").into(),
        );
    }
    if !success {
        return Err(format!("endpoint timed out; status={ERROR_INTERNAL}").into());
    }
    structured_event(
        "endpoint",
        "p1_complete",
        &[
            ("setup_latency_ms", setup_latency_ms.to_string()),
            ("live_routes", state.live_routes().to_string()),
        ],
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("trahens-endpoint: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_envelopes_carry_the_r1_suite() {
        let envelope = control(MessageType::Discover, [0x05; 16], 3, vec![9, 9]);
        assert_eq!(envelope.suite_id, SUITE_R1);
    }

    #[test]
    fn control_preserves_its_arguments() {
        let body = vec![4, 5, 6, 7];
        let envelope = control(MessageType::Commit, [0x0a; 16], 42, body.clone());

        let Message::Control(built) = envelope.message else {
            panic!("control must produce a control message");
        };
        assert_eq!(built.message_type, MessageType::Commit);
        assert_eq!(built.local_label, [0x0a; 16]);
        assert_eq!(built.generation, 42);
        assert_eq!(built.protected_body, body);
    }

    #[test]
    fn control_uses_the_single_p1_expiry_class() {
        // P1 pins every control message to expiry class 1; a second class
        // would be an observable distinguisher between messages.
        for message_type in [
            MessageType::Discover,
            MessageType::Commit,
            MessageType::Close,
        ] {
            let envelope = control(message_type, [0; 16], 0, Vec::new());
            let Message::Control(built) = envelope.message else {
                panic!("control must produce a control message");
            };
            assert_eq!(built.expiry_class, 1);
        }
    }
}
