#![forbid(unsafe_code)]

use codec_m2::{Candidate, Control, Discover, Envelope, Message, MessageType};
use node_runtime::p1::wrap_candidate;
use node_runtime::{
    event_channel, parse_hex, spawn_link, structured_event, unix_time_ms, write_link_metrics,
    CliArgs, LinkConfig, LinkEvent, LinkHandle, LinkMetrics,
};
use protocol_registry::{LIMIT_MAX_CANDIDATE_LAYERS, LIMIT_ROUTE_TTL_MS, SUITE_R1};
use state_machine::{Event, Phase, RouteTable};
use std::collections::HashMap;
use std::error::Error;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};
use trahens_crypto::{blind_public, initialize, random_nonzero_16, random_scalar, zeroize};

#[derive(Clone)]
struct RelayRoute {
    parent_label: [u8; 16],
    child_label: [u8; 16],
    incoming_reply_public: [u8; 32],
    blinding_factor: [u8; 32],
    depth: u8,
    parent_discovery_nonce: [u8; 32],
    child_discovery_nonce: [u8; 32],
    generation: u32,
    expires_at_ms: u64,
}

impl Drop for RelayRoute {
    fn drop(&mut self) {
        zeroize(&mut self.blinding_factor);
    }
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
) {
    if let Some(route) = routes.remove(&parent) {
        reverse.remove(&route.child_label);
        let _ = states.apply(parent, event);
    }
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
    let downstream_id = args.u32("downstream-id")?;
    let epoch = args.u32("epoch")?;
    let timeout_ms = args.u64_or("timeout-ms", 30_000)?;
    let metrics_path = args.optional("metrics", "relay-metrics.json").to_owned();

    let (event_sender, event_receiver) = event_channel();
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
    )?;
    let downstream = spawn_link(
        LinkConfig {
            local_id: node_id,
            peer_id: downstream_id,
            bind: args.socket("downstream-bind")?,
            peer: args.socket("downstream-peer")?,
            base_key: parse_hex::<32>(args.required("downstream-key")?)?,
            epoch,
        },
        event_sender,
    )?;

    let mut states = RouteTable::default();
    let mut routes: HashMap<[u8; 16], RelayRoute> = HashMap::new();
    let mut reverse: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
    let deadline = unix_time_ms().saturating_add(timeout_ms);
    let mut cleanup_started: Option<Instant> = None;
    let mut observed_close = false;

    while unix_time_ms() < deadline {
        let event = match event_receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(value) => value,
            Err(RecvTimeoutError::Timeout) => {
                let now = unix_time_ms();
                let expired: Vec<[u8; 16]> = routes
                    .iter()
                    .filter_map(|(label, route)| (route.expires_at_ms <= now).then_some(*label))
                    .collect();
                for label in expired {
                    cleanup_route(
                        label,
                        &mut routes,
                        &mut reverse,
                        &mut states,
                        Event::Timeout,
                    );
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        match event {
            LinkEvent::Message {
                peer_id, envelope, ..
            } if peer_id == upstream_id => match envelope.message {
                Message::Discover(discover) => {
                    if discover.hop_remaining == 0
                        || usize::from(discover.options) >= LIMIT_MAX_CANDIDATE_LAYERS
                        || routes.contains_key(&discover.branch_token)
                    {
                        structured_event(
                            "relay",
                            "discover_rejected",
                            &[("reason", "limit_or_duplicate".to_owned())],
                        );
                        continue;
                    }
                    let factor = random_scalar()?;
                    let child_public = blind_public(&discover.reply_public_key, &factor)?;
                    let child_label = random_nonzero_16()?;
                    let parent_discovery_nonce: [u8; 32] = discover
                        .discovery_field
                        .as_slice()
                        .try_into()
                        .map_err(|_| "invalid R1 discovery nonce")?;
                    let child_discovery_nonce = loop {
                        let value = trahens_crypto::random_bytes::<32>()?;
                        if value != [0_u8; 32] {
                            break value;
                        }
                    };
                    let depth = discover.options.saturating_add(1);
                    let expires_at_ms = unix_time_ms().saturating_add(LIMIT_ROUTE_TTL_MS as u64);
                    states.begin(discover.branch_token, upstream_id, 0, expires_at_ms)?;
                    let route = RelayRoute {
                        parent_label: discover.branch_token,
                        child_label,
                        incoming_reply_public: discover.reply_public_key,
                        blinding_factor: factor,
                        depth,
                        parent_discovery_nonce,
                        child_discovery_nonce,
                        generation: 0,
                        expires_at_ms,
                    };
                    reverse.insert(child_label, discover.branch_token);
                    routes.insert(discover.branch_token, route);
                    downstream.send(Envelope {
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
                            states.apply(route.parent_label, Event::CommitAccepted)?;
                            downstream.send(forward_control(control, route.child_label))?;
                        }
                        MessageType::RendezvousOpen => {
                            if states.get(&route.parent_label).map(|state| state.phase)
                                == Some(Phase::Ready)
                            {
                                downstream.send(forward_control(control, route.child_label))?;
                            }
                        }
                        MessageType::Data => {
                            if states.get(&route.parent_label).map(|state| state.phase)
                                == Some(Phase::Open)
                            {
                                states.apply(route.parent_label, Event::DataAccepted)?;
                                downstream.send(forward_control(control, route.child_label))?;
                            }
                        }
                        MessageType::Close | MessageType::Cancel | MessageType::Abort => {
                            downstream.send(forward_control(control.clone(), route.child_label))?;
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
                            );
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            LinkEvent::Message {
                peer_id, envelope, ..
            } if peer_id == downstream_id => match envelope.message {
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
                        );
                        continue;
                    }
                    let wrapped = wrap_candidate(
                        &route.incoming_reply_public,
                        route.depth,
                        route.blinding_factor,
                        route.child_label,
                        route.parent_label,
                        route.parent_discovery_nonce,
                        route.child_discovery_nonce,
                        candidate.candidate_blob,
                    )?;
                    states.apply(parent_label, Event::CandidateAccepted)?;
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
                            states.apply(parent_label, Event::ReadyAccepted)?;
                            upstream.send(forward_control(control, parent_label))?;
                        }
                        MessageType::RendezvousResult => {
                            states.apply(parent_label, Event::CapabilityAccepted)?;
                            upstream.send(forward_control(control, parent_label))?;
                        }
                        MessageType::Data => {
                            if states.get(&parent_label).map(|state| state.phase)
                                == Some(Phase::Open)
                            {
                                states.apply(parent_label, Event::DataAccepted)?;
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
                            );
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            LinkEvent::TransmissionFailed { peer_id } => {
                return Err(format!("T1 retry budget exhausted for peer {peer_id}").into());
            }
            LinkEvent::SecurityEvent { peer_id, code } => {
                structured_event(
                    "relay",
                    "security_event",
                    &[("peer", peer_id.to_string()), ("code", code.to_owned())],
                );
            }
            _ => {}
        }
        if observed_close && routes.is_empty() {
            std::thread::sleep(Duration::from_millis(1_500));
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
        );
    }
    upstream.shutdown()?;
    downstream.shutdown()?;
    let metrics = collect_stopped(&event_receiver, 2);
    let cleanup_ms = cleanup_started
        .map(|value| value.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0);
    write_link_metrics(
        &metrics_path,
        "relay",
        states.live_routes(),
        cleanup_ms,
        &metrics,
    )?;
    structured_event(
        "relay",
        "stopped",
        &[
            ("live_routes", states.live_routes().to_string()),
            ("route_map", routes.len().to_string()),
            ("id", node_id.to_string()),
        ],
    );
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
                child_label: child,
                incoming_reply_public: [0; 32],
                blinding_factor: [7; 32],
                depth: 1,
                parent_discovery_nonce: [0; 32],
                child_discovery_nonce: [0; 32],
                generation: 1,
                expires_at_ms: 0,
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
        );

        assert!(routes.is_empty(), "parent mapping must be removed");
        assert!(reverse.is_empty(), "child reverse mapping must be removed");
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
        );

        assert!(routes.is_empty());
        assert!(reverse.is_empty());
    }
}
