// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use codec_m2::{Candidate, Control, Discover, Envelope, Message, MessageType};
use node_runtime::p1::wrap_candidate;
use node_runtime::{
    drain_in_precedence_order, drain_links, event_channel, parse_hex, spawn_link, structured_event,
    write_link_metrics, CliArgs, Clock, LinkConfig, LinkEvent, LinkMetrics, NodeQueueBudget,
    RemoteInputDrops,
};
use protocol_registry::{
    ERROR_INTERNAL, ERROR_MALFORMED, ERROR_RESOURCE_EXHAUSTED, ERROR_STATE_VIOLATION,
    ERROR_TIMEOUT, LIMIT_MAX_CANDIDATE_LAYERS, LIMIT_MAX_FANOUT_CLASS, SUITE_R1,
};
use rendezvous_r1::suite::{EligibilitySuite, R1Suite};
use state_machine::{Event, IngressAdmission, Phase, RouteTable};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};
use trahens_crypto::{blind_public, initialize, random_nonzero_16, random_scalar, zeroize};

/// One forwarded child of a branch. Core v1.5 section 5 requires every child
/// to receive independently replaced context, so each carries its own label,
/// blinding factor, and discovery nonce.
#[derive(Clone)]
struct RelayChild {
    link_index: usize,
    child_label: [u8; 16],
    blinding_factor: [u8; 32],
    child_discovery_nonce: [u8; 32],
}

impl Drop for RelayChild {
    fn drop(&mut self) {
        zeroize(&mut self.blinding_factor);
    }
}

#[derive(Clone)]
struct RelayRoute {
    parent_label: [u8; 16],
    children: Vec<RelayChild>,
    /// Index of the child whose CANDIDATE was forwarded upstream. Control
    /// traffic follows that child; until one exists there is nothing to
    /// forward control to.
    committed_child: Option<usize>,
    incoming_reply_public: [u8; 32],
    depth: u8,
    parent_discovery_nonce: [u8; 32],
    generation: u32,
}

fn forward_control(message: Control, label: [u8; 16]) -> Envelope {
    Envelope {
        suite_id: SUITE_R1,
        message: Message::Control(Control {
            local_label: label,
            ..message
        }),
    }
}

fn cleanup_route(
    parent: [u8; 16],
    routes: &mut HashMap<[u8; 16], RelayRoute>,
    reverse: &mut HashMap<[u8; 16], [u8; 16]>,
    states: &mut RouteTable,
    event: Event,
    now_ms: u64,
) {
    if let Some(route) = routes.remove(&parent) {
        for child in &route.children {
            reverse.remove(&child.child_label);
        }
        let _ = states.apply(parent, event, now_ms);
    }
}

/// Reclaim every branch whose deadline has passed.
///
/// `event-lifecycle-profile-e1.md` section 9 requires expiry to be local and
/// non-blocking, and section 2 ranks it above every message sharing the same
/// timestamp. It therefore runs once per loop iteration, before any event is
/// processed: driving it only from an idle channel lets continuous traffic
/// keep expired state usable indefinitely.
fn reclaim_expired(
    now_ms: u64,
    routes: &mut HashMap<[u8; 16], RelayRoute>,
    reverse: &mut HashMap<[u8; 16], [u8; 16]>,
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
        cleanup_route(label, routes, reverse, states, Event::Timeout, now_ms);
    }
    // A state entry can outlive its route map entry, so sweep the table too.
    states.expire(now_ms);
    count
}

fn collect_stopped(
    receiver: &std::sync::mpsc::Receiver<LinkEvent>,
    expected: usize,
) -> Vec<(u32, LinkMetrics)> {
    let mut output = Vec::new();
    while output.len() < expected {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(LinkEvent::Stopped { peer_id, metrics }) => output.push((peer_id, metrics)),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    output
}

fn run() -> Result<(), Box<dyn Error>> {
    initialize()?;
    let args = CliArgs::parse()?;
    let node_id = args.u32("id")?;
    let upstream_id = args.u32("upstream-id")?;
    let epoch = args.u32("epoch")?;
    let timeout_ms = args.u64_or("timeout-ms", 30_000)?;
    let metrics_path = args.optional("metrics", "relay-metrics.json").to_owned();

    let (event_sender, event_receiver) = event_channel();
    // One budget shared by the upstream link and every child: the node-global
    // cell ceiling is a property of the process, not of any one link.
    let budget = NodeQueueBudget::new();
    let upstream = spawn_link(
        LinkConfig {
            local_id: node_id,
            peer_id: upstream_id,
            bind: args.socket("upstream-bind")?,
            peer: args.socket("upstream-peer")?,
            base_key: parse_hex::<32>(args.required("upstream-key")?)?,
            epoch,
        },
        event_sender.clone(),
        budget.clone(),
    )?;
    // Children are numbered: --downstream-id / -bind / -peer / -key describe
    // child 0, and --downstream-id-N and friends describe child N. Core v1.5
    // section 5 requires every forwarded child to get independently replaced
    // context, so each child has its own link, label, and blinding factor.
    let mut downstream: Vec<(u32, node_runtime::LinkHandle)> = Vec::new();
    for child in 0..LIMIT_MAX_FANOUT_CLASS {
        let suffix = if child == 0 {
            String::new()
        } else {
            format!("-{child}")
        };
        if !args.flag(&format!("downstream-id{suffix}")) {
            continue;
        }
        let peer_id = args.u32(&format!("downstream-id{suffix}"))?;
        downstream.push((
            peer_id,
            spawn_link(
                LinkConfig {
                    local_id: node_id,
                    peer_id,
                    bind: args.socket(&format!("downstream-bind{suffix}"))?,
                    peer: args.socket(&format!("downstream-peer{suffix}"))?,
                    base_key: parse_hex::<32>(args.required(&format!("downstream-key{suffix}"))?)?,
                    epoch,
                },
                event_sender.clone(),
                budget.clone(),
            )?,
        ));
    }
    drop(event_sender);
    if downstream.is_empty() {
        return Err("a relay needs at least one downstream child".into());
    }

    let mut states = RouteTable::default();
    let mut routes: HashMap<[u8; 16], RelayRoute> = HashMap::new();
    let mut reverse: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
    let mut drops = RemoteInputDrops::new();
    let eligibility = R1Suite;
    let mut admission = IngressAdmission::new();
    let clock = Clock::start();
    let deadline = clock.now_ms().saturating_add(timeout_ms);
    let mut cleanup_started: Option<Instant> = None;
    let mut observed_close = false;
    let mut transport_failed: Option<u32> = None;

    // Events that arrive together share a local timestamp, so they are drained
    // as a batch, ordered by E1 section 2 precedence, and then consumed one at
    // a time. Processing straight from the channel would let scheduling decide
    // whether a cancellation or a delayed candidate wins.
    let mut ordered: VecDeque<LinkEvent> = VecDeque::new();
    while clock.now_ms() < deadline {
        // Expiry runs before every event, not only when the channel is idle.
        reclaim_expired(clock.now_ms(), &mut routes, &mut reverse, &mut states);
        let next = match ordered.pop_front() {
            Some(event) => Ok(event),
            None => event_receiver.recv_timeout(Duration::from_millis(100)),
        };
        let event = match next {
            Ok(value) => {
                if ordered.is_empty() {
                    let batch = drain_in_precedence_order(&event_receiver, value);
                    ordered.extend(batch);
                    match ordered.pop_front() {
                        Some(first) => first,
                        None => continue,
                    }
                } else {
                    value
                }
            }
            // Expiry already ran at the top of the iteration; an idle channel
            // just means there is nothing else to do this tick.
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        match event {
            LinkEvent::Message {
                peer_id, envelope, ..
            } if peer_id == upstream_id => match envelope.message {
                Message::Discover(discover) => {
                    if routes.contains_key(&discover.branch_token) {
                        drops.record("relay", ERROR_STATE_VIOLATION, "discover_duplicate_token");
                        continue;
                    }
                    if discover.hop_remaining == 0
                        || usize::from(discover.options) >= LIMIT_MAX_CANDIDATE_LAYERS
                    {
                        drops.record(
                            "relay",
                            ERROR_RESOURCE_EXHAUSTED,
                            "discover_propagation_limit",
                        );
                        continue;
                    }
                    // E1 section 10: the per-ingress-peer bucket is charged
                    // before any cryptographic work or branch allocation, so a
                    // fresh-branch flood costs the relay a table lookup rather
                    // than a scalar multiplication.
                    if !admission.admit(epoch, upstream_id, clock.now_ms()) {
                        drops.record("relay", ERROR_RESOURCE_EXHAUSTED, "ingress_token_bucket");
                        continue;
                    }
                    let fanout = usize::from(discover.fanout_class)
                        .clamp(1, downstream.len().min(LIMIT_MAX_FANOUT_CLASS));
                    let Ok(parent_discovery_nonce) =
                        <[u8; 32]>::try_from(discover.discovery_field.as_slice())
                    else {
                        drops.record("relay", ERROR_MALFORMED, "discover_nonce_length");
                        continue;
                    };
                    let depth = discover.options.saturating_add(1);
                    let expires_at_ms = clock
                        .now_ms()
                        .saturating_add(Phase::Discovering.lifetime_ms());
                    // A peer exhausting the route table is admission
                    // pressure, not a relay fault: drop this DISCOVER.
                    if states
                        .begin(discover.branch_token, upstream_id, 0, expires_at_ms)
                        .is_err()
                    {
                        drops.record("relay", ERROR_RESOURCE_EXHAUSTED, "route_table_limit");
                        continue;
                    }

                    let mut children = Vec::with_capacity(fanout);
                    for link_index in 0..fanout {
                        let factor = random_scalar()?;
                        // The reply public key is remote input: an invalid
                        // point drops the DISCOVER rather than killing us.
                        let Ok(child_public) = blind_public(&discover.reply_public_key, &factor)
                        else {
                            drops.record("relay", ERROR_MALFORMED, "discover_reply_public_key");
                            break;
                        };
                        let child_label = random_nonzero_16()?;
                        // eligibility-suite-interface-v1.md: lifecycle code
                        // depends on the suite interface, not a concrete
                        // scheme, and each child gets its own fresh field.
                        let Ok(child_field) = eligibility.transform(&discover.discovery_field)
                        else {
                            drops.record("relay", ERROR_MALFORMED, "discovery_field_transform");
                            break;
                        };
                        let Ok(child_discovery_nonce) =
                            <[u8; 32]>::try_from(child_field.as_slice())
                        else {
                            drops.record("relay", ERROR_INTERNAL, "discovery_field_width");
                            break;
                        };
                        reverse.insert(child_label, discover.branch_token);
                        downstream[link_index].1.send(Envelope {
                            suite_id: SUITE_R1,
                            message: Message::Discover(Discover {
                                branch_token: child_label,
                                hop_remaining: discover.hop_remaining.saturating_sub(1),
                                fanout_class: discover.fanout_class,
                                expiry_class: discover.expiry_class,
                                options: depth,
                                reply_public_key: child_public,
                                discovery_field: child_discovery_nonce.to_vec(),
                            }),
                        })?;
                        children.push(RelayChild {
                            link_index,
                            child_label,
                            blinding_factor: factor,
                            child_discovery_nonce,
                        });
                    }
                    if children.is_empty() {
                        cleanup_route(
                            discover.branch_token,
                            &mut routes,
                            &mut reverse,
                            &mut states,
                            Event::CancelAccepted,
                            clock.now_ms(),
                        );
                        continue;
                    }
                    routes.insert(
                        discover.branch_token,
                        RelayRoute {
                            parent_label: discover.branch_token,
                            children,
                            committed_child: None,
                            incoming_reply_public: discover.reply_public_key,
                            depth,
                            parent_discovery_nonce,
                            generation: 0,
                        },
                    );
                }
                Message::Control(control) => {
                    let Some(route) = routes.get(&control.local_label).cloned() else {
                        continue;
                    };
                    if control.generation != route.generation {
                        continue;
                    }
                    match control.message_type {
                        MessageType::Commit => {
                            // event-lifecycle-profile-e1.md:142 — an exact
                            // duplicate COMMIT MUST be discarded or processed
                            // idempotently, never treated as fatal.
                            if states
                                .apply(route.parent_label, Event::CommitAccepted, clock.now_ms())
                                .is_err()
                            {
                                drops.record("relay", ERROR_STATE_VIOLATION, "commit_transition");
                                continue;
                            }
                            if let Some(child) = route
                                .committed_child
                                .and_then(|index| route.children.get(index))
                            {
                                downstream[child.link_index]
                                    .1
                                    .send(forward_control(control, child.child_label))?;
                            }
                        }
                        MessageType::RendezvousOpen => {
                            if states.get(&route.parent_label).map(|state| state.phase)
                                == Some(Phase::Ready)
                            {
                                if let Some(child) = route
                                    .committed_child
                                    .and_then(|index| route.children.get(index))
                                {
                                    downstream[child.link_index]
                                        .1
                                        .send(forward_control(control, child.child_label))?;
                                }
                            }
                        }
                        MessageType::Data => {
                            if states.get(&route.parent_label).map(|state| state.phase)
                                == Some(Phase::Open)
                            {
                                states.apply(
                                    route.parent_label,
                                    Event::DataAccepted,
                                    clock.now_ms(),
                                )?;
                                if let Some(child) = route
                                    .committed_child
                                    .and_then(|index| route.children.get(index))
                                {
                                    downstream[child.link_index]
                                        .1
                                        .send(forward_control(control, child.child_label))?;
                                }
                            }
                        }
                        MessageType::Close | MessageType::Cancel | MessageType::Abort => {
                            if let Some(child) = route
                                .committed_child
                                .and_then(|index| route.children.get(index))
                            {
                                downstream[child.link_index]
                                    .1
                                    .send(forward_control(control.clone(), child.child_label))?;
                            }
                            cleanup_started = Some(Instant::now());
                            observed_close = true;
                            let event = if control.message_type == MessageType::Close {
                                Event::CloseAccepted
                            } else {
                                Event::CancelAccepted
                            };
                            cleanup_route(
                                route.parent_label,
                                &mut routes,
                                &mut reverse,
                                &mut states,
                                event,
                                clock.now_ms(),
                            );
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            LinkEvent::Message {
                peer_id, envelope, ..
            } if downstream.iter().any(|(id, _)| *id == peer_id) => match envelope.message {
                Message::Candidate(candidate) => {
                    let Some(parent_label) = reverse.get(&candidate.candidate_token).copied()
                    else {
                        continue;
                    };
                    let Some(route) = routes.get(&parent_label).cloned() else {
                        continue;
                    };
                    if usize::from(candidate.layer_count) > LIMIT_MAX_CANDIDATE_LAYERS {
                        cleanup_route(
                            parent_label,
                            &mut routes,
                            &mut reverse,
                            &mut states,
                            Event::CancelAccepted,
                            clock.now_ms(),
                        );
                        continue;
                    }
                    // The candidate arrived on one specific child, so it must
                    // be unwrapped with that child's blinding factor and nonce.
                    let Some(child_index) = route
                        .children
                        .iter()
                        .position(|child| child.child_label == candidate.candidate_token)
                    else {
                        drops.record("relay", ERROR_STATE_VIOLATION, "candidate_unknown_child");
                        continue;
                    };
                    let child = &route.children[child_index];
                    // The candidate blob is remote input; a wrap failure
                    // drops the candidate rather than terminating the relay.
                    let Ok(wrapped) = wrap_candidate(
                        &route.incoming_reply_public,
                        route.depth,
                        child.blinding_factor,
                        child.child_label,
                        route.parent_label,
                        route.parent_discovery_nonce,
                        child.child_discovery_nonce,
                        candidate.candidate_blob,
                    ) else {
                        drops.record("relay", ERROR_MALFORMED, "candidate_blob_wrap");
                        continue;
                    };
                    // Control traffic for this route now follows that child.
                    if let Some(entry) = routes.get_mut(&parent_label) {
                        entry.committed_child.get_or_insert(child_index);
                    }
                    if states
                        .apply(parent_label, Event::CandidateAccepted, clock.now_ms())
                        .is_err()
                    {
                        drops.record("relay", ERROR_STATE_VIOLATION, "candidate_transition");
                        continue;
                    }
                    upstream.send(Envelope {
                        suite_id: SUITE_R1,
                        message: Message::Candidate(Candidate {
                            candidate_token: parent_label,
                            expiry_class: candidate.expiry_class,
                            layer_count: candidate.layer_count.saturating_add(1),
                            candidate_blob: wrapped,
                        }),
                    })?;
                }
                Message::Control(control) => {
                    let Some(parent_label) = reverse.get(&control.local_label).copied() else {
                        continue;
                    };
                    let Some(route) = routes.get(&parent_label).cloned() else {
                        continue;
                    };
                    if control.generation != route.generation {
                        continue;
                    }
                    match control.message_type {
                        MessageType::Ready => {
                            if states
                                .apply(parent_label, Event::ReadyAccepted, clock.now_ms())
                                .is_err()
                            {
                                drops.record("relay", ERROR_STATE_VIOLATION, "ready_transition");
                                continue;
                            }
                            upstream.send(forward_control(control, parent_label))?;
                        }
                        MessageType::RendezvousResult => {
                            if states
                                .apply(parent_label, Event::CapabilityAccepted, clock.now_ms())
                                .is_err()
                            {
                                drops.record(
                                    "relay",
                                    ERROR_STATE_VIOLATION,
                                    "rendezvous_result_transition",
                                );
                                continue;
                            }
                            upstream.send(forward_control(control, parent_label))?;
                        }
                        MessageType::Data => {
                            if states.get(&parent_label).map(|state| state.phase)
                                == Some(Phase::Open)
                            {
                                states.apply(parent_label, Event::DataAccepted, clock.now_ms())?;
                                upstream.send(forward_control(control, parent_label))?;
                            }
                        }
                        MessageType::Close | MessageType::Cancel | MessageType::Abort => {
                            upstream.send(forward_control(control.clone(), parent_label))?;
                            cleanup_started = Some(Instant::now());
                            observed_close = true;
                            cleanup_route(
                                parent_label,
                                &mut routes,
                                &mut reverse,
                                &mut states,
                                Event::CloseAccepted,
                                clock.now_ms(),
                            );
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            LinkEvent::TransmissionFailed { peer_id } => {
                // Retry exhaustion must terminate the run cleanly: reclaim
                // every route, then fall through to the shared cleanup and
                // metrics path so the harness can observe live_routes == 0.
                structured_event(
                    "relay",
                    "transport_failure",
                    &[
                        ("peer", peer_id.to_string()),
                        ("error_id", ERROR_TIMEOUT.to_string()),
                    ],
                );
                transport_failed = Some(peer_id);
                cleanup_started.get_or_insert_with(Instant::now);
                break;
            }
            LinkEvent::SecurityEvent {
                peer_id,
                error_id,
                detail,
            } => {
                structured_event(
                    "relay",
                    "security_event",
                    &[
                        ("peer", peer_id.to_string()),
                        ("error_id", error_id.to_string()),
                        ("detail", detail.to_owned()),
                    ],
                );
            }
            _ => {}
        }
        if observed_close && routes.is_empty() {
            // Drain in-flight T1 state instead of sleeping a fixed interval.
            let mut handles: Vec<&node_runtime::LinkHandle> = vec![&upstream];
            handles.extend(downstream.iter().map(|(_, link)| link));
            drain_links(&handles, &event_receiver);
            break;
        }
    }

    let remaining: Vec<[u8; 16]> = routes.keys().copied().collect();
    for label in remaining {
        cleanup_route(
            label,
            &mut routes,
            &mut reverse,
            &mut states,
            Event::Timeout,
            clock.now_ms(),
        );
    }
    let link_count = downstream.len() + 1;
    upstream.shutdown()?;
    for (_, link) in downstream {
        link.shutdown()?;
    }
    let metrics = collect_stopped(&event_receiver, link_count);
    let cleanup_ms = cleanup_started
        .map(|value| value.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0);
    write_link_metrics(
        &metrics_path,
        "relay",
        states.live_routes(),
        cleanup_ms,
        &drops,
        states.peaks(),
        &metrics,
    )?;
    structured_event(
        "relay",
        "stopped",
        &[
            ("live_routes", states.live_routes().to_string()),
            ("route_map", routes.len().to_string()),
            ("token_bucket_drops", admission.rejected().to_string()),
            ("id", node_id.to_string()),
        ],
    );
    if let Some(peer_id) = transport_failed {
        // State is already reclaimed and metrics are written; the non-zero
        // exit reports the outcome without stranding remote state.
        return Err(format!("T1 retry budget exhausted for peer {peer_id}").into());
    }
    if !observed_close {
        return Err(format!("relay {node_id} timed out before cleanup").into());
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("trahens-relay: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_control_rewrites_the_label_and_nothing_else() {
        let incoming = Control {
            message_type: MessageType::Commit,
            local_label: [0xaa; 16],
            generation: 9,
            expiry_class: 3,
            protected_body: vec![1, 2, 3],
        };

        let envelope = forward_control(incoming.clone(), [0xbb; 16]);

        assert_eq!(envelope.suite_id, SUITE_R1);
        let Message::Control(forwarded) = envelope.message else {
            panic!("forward_control must produce a control message");
        };
        // The child label is branch-local: rewriting it is the whole point of
        // the hop, and every other field must survive untouched.
        assert_eq!(forwarded.local_label, [0xbb; 16]);
        assert_eq!(forwarded.message_type, incoming.message_type);
        assert_eq!(forwarded.generation, incoming.generation);
        assert_eq!(forwarded.expiry_class, incoming.expiry_class);
        assert_eq!(forwarded.protected_body, incoming.protected_body);
    }

    #[test]
    fn forward_control_does_not_reuse_the_incoming_label() {
        let incoming = Control {
            message_type: MessageType::Ready,
            local_label: [0x11; 16],
            generation: 1,
            expiry_class: 1,
            protected_body: Vec::new(),
        };

        let envelope = forward_control(incoming, [0x22; 16]);

        let Message::Control(forwarded) = envelope.message else {
            panic!("forward_control must produce a control message");
        };
        assert_ne!(forwarded.local_label, [0x11; 16]);
    }

    #[test]
    fn cleanup_route_drops_both_directions() {
        let parent = [0x01; 16];
        let child = [0x02; 16];
        let mut routes = HashMap::new();
        let mut reverse = HashMap::new();
        routes.insert(
            parent,
            RelayRoute {
                parent_label: parent,
                children: vec![RelayChild {
                    link_index: 0,
                    child_label: child,
                    blinding_factor: [7; 32],
                    child_discovery_nonce: [0; 32],
                }],
                committed_child: None,
                incoming_reply_public: [0; 32],
                depth: 1,
                parent_discovery_nonce: [0; 32],
                generation: 1,
            },
        );
        reverse.insert(child, parent);
        let mut states = RouteTable::default();

        cleanup_route(
            parent,
            &mut routes,
            &mut reverse,
            &mut states,
            Event::CloseAccepted,
            0,
        );

        assert!(routes.is_empty(), "parent mapping must be removed");
        assert!(reverse.is_empty(), "child reverse mapping must be removed");
    }

    #[test]
    fn cleanup_releases_every_child_of_a_fanned_out_branch() {
        // With fan-out the branch has several reverse mappings, and cancelling
        // it must release all of them or a later candidate would resolve to a
        // route that no longer exists.
        let parent = [0x11; 16];
        let mut routes = HashMap::new();
        let mut reverse = HashMap::new();
        let children: Vec<RelayChild> = (0..3)
            .map(|index| RelayChild {
                link_index: index,
                child_label: [index as u8 + 1; 16],
                blinding_factor: [7; 32],
                child_discovery_nonce: [0; 32],
            })
            .collect();
        for child in &children {
            reverse.insert(child.child_label, parent);
        }
        routes.insert(
            parent,
            RelayRoute {
                parent_label: parent,
                children,
                committed_child: Some(1),
                incoming_reply_public: [0; 32],
                depth: 1,
                parent_discovery_nonce: [0; 32],
                generation: 1,
            },
        );
        let mut states = RouteTable::default();

        cleanup_route(
            parent,
            &mut routes,
            &mut reverse,
            &mut states,
            Event::CancelAccepted,
            0,
        );

        assert!(routes.is_empty());
        assert!(reverse.is_empty(), "every child mapping is released");
    }

    #[test]
    fn reclaim_expired_releases_lapsed_branches_and_spares_live_ones() -> Result<(), Box<dyn Error>>
    {
        // The relay now sweeps before every event rather than only when the
        // channel falls idle, so this is the sweep a busy relay depends on.
        let lapsed = [0x21; 16];
        let live = [0x22; 16];
        let mut routes = HashMap::new();
        let mut reverse = HashMap::new();
        let mut states = RouteTable::default();

        for (label, child, deadline) in [(lapsed, [0x31_u8; 16], 100_u64), (live, [0x32; 16], 900)]
        {
            states.begin(label, 1, 0, deadline)?;
            reverse.insert(child, label);
            routes.insert(
                label,
                RelayRoute {
                    parent_label: label,
                    children: vec![RelayChild {
                        link_index: 0,
                        child_label: child,
                        blinding_factor: [7; 32],
                        child_discovery_nonce: [0; 32],
                    }],
                    committed_child: None,
                    incoming_reply_public: [0; 32],
                    depth: 1,
                    parent_discovery_nonce: [0; 32],
                    generation: 0,
                },
            );
        }

        assert_eq!(
            reclaim_expired(500, &mut routes, &mut reverse, &mut states),
            1
        );
        assert!(!routes.contains_key(&lapsed), "the lapsed branch is gone");
        assert!(routes.contains_key(&live), "the live branch is untouched");
        assert!(
            !reverse.contains_key(&[0x31; 16]),
            "its child mapping goes with it"
        );
        assert_eq!(states.live_routes(), 1);

        // A second sweep at the same instant is a no-op, so running it every
        // iteration costs nothing.
        assert_eq!(
            reclaim_expired(500, &mut routes, &mut reverse, &mut states),
            0
        );
        Ok(())
    }

    #[test]
    fn cleanup_route_is_idempotent_for_unknown_labels() {
        let mut routes: HashMap<[u8; 16], RelayRoute> = HashMap::new();
        let mut reverse: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
        let mut states = RouteTable::default();

        cleanup_route(
            [0xff; 16],
            &mut routes,
            &mut reverse,
            &mut states,
            Event::CloseAccepted,
            0,
        );

        assert!(routes.is_empty());
        assert!(reverse.is_empty());
    }
}
