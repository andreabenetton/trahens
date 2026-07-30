#![forbid(unsafe_code)]

use codec_m2::{Candidate, Control, Discover, Envelope, Message, MessageType, P1Payload};
use node_runtime::p1::{
    commit_proof, open_candidate_chain, open_control, ready_proof, seal_control, verify_proof,
};
use node_runtime::{
    event_channel, parse_hex, spawn_link, structured_event, unix_time_ms, write_link_metrics,
    CliArgs, LinkConfig, LinkEvent, LinkMetrics,
};
use protocol_registry::{
    ERROR_INTERNAL, LIMIT_ROUTE_TTL_MS, SUITE_R1,
};
use state_machine::{Event, RouteTable};
use std::error::Error;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};
use trahens_crypto::{
    initialize, random_bytes, random_nonzero_16, random_scalar, scalar_base, SecretBytes,
};

struct ActiveRoute {
    local_label: [u8; 16],
    generation: u32,
    route_secret: SecretBytes<32>,
    challenge: [u8; 32],
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
    let protected = seal_control(&route.route_secret.0, message_type, route.generation, payload)?;
    link.send(control(message_type, route.local_label, route.generation, protected))?;
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
    )?;

    let root_secret = SecretBytes(random_scalar()?);
    let reply_public_key = scalar_base(&root_secret.0)?;
    let branch_token = random_nonzero_16()?;
    let discovery_nonce = random_bytes::<32>()?;
    if discovery_nonce == [0_u8; 32] {
        return Err("random discovery nonce was zero".into());
    }
    let generation = 0_u32;
    let setup_started = Instant::now();
    let absolute_deadline = unix_time_ms().saturating_add(timeout_ms);
    let mut state = RouteTable::default();
    state.begin(
        branch_token,
        peer_id,
        generation,
        unix_time_ms().saturating_add(LIMIT_ROUTE_TTL_MS as u64),
    )?;

    link.send(Envelope {
        suite_id: SUITE_R1,
        message: Message::Discover(Discover {
            branch_token,
            hop_remaining: 16,
            fanout_class: 1,
            expiry_class: 1,
            options: 0,
            reply_public_key,
            discovery_field: discovery_nonce.to_vec(),
        }),
    })?;
    structured_event("endpoint", "discovery_sent", &[]);

    let mut active: Option<ActiveRoute> = None;
    let mut success = false;
    let mut setup_latency_ms = 0_u64;
    let mut cleanup_started = None;

    while unix_time_ms() < absolute_deadline {
        let event = match event_receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(value) => value,
            Err(RecvTimeoutError::Timeout) => {
                state.expire(unix_time_ms());
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        match event {
            LinkEvent::Message { peer_id: received_peer, envelope, .. } if received_peer == peer_id => {
                match envelope.message {
                    Message::Candidate(Candidate {
                        candidate_token,
                        layer_count,
                        candidate_blob,
                        ..
                    }) if candidate_token == branch_token && active.is_none() => {
                        let opened = open_candidate_chain(
                            &root_secret.0,
                            &candidate_blob,
                            layer_count,
                            &expected_gateway_public,
                            &discovery_nonce,
                            unix_time_ms(),
                        )?;
                        state.apply(branch_token, Event::CandidateAccepted)?;
                        let route = ActiveRoute {
                            local_label: branch_token,
                            generation,
                            route_secret: SecretBytes(opened.route_secret),
                            challenge: opened.commit_challenge,
                            pseudonym: opened.gateway_pseudonym,
                        };
                        let proof = commit_proof(&route.route_secret.0, &route.challenge, &route.pseudonym)?;
                        send_control(&link, &route, MessageType::Commit, &P1Payload::Commit { proof })?;
                        state.apply(branch_token, Event::CommitAccepted)?;
                        active = Some(route);
                        structured_event(
                            "endpoint",
                            "candidate_authenticated",
                            &[("layers", layer_count.to_string())],
                        );
                    }
                    Message::Control(control_message) => {
                        let Some(route) = active.as_ref() else { continue };
                        if control_message.local_label != route.local_label
                            || control_message.generation != route.generation
                        {
                            continue;
                        }
                        let payload = open_control(
                            &route.route_secret.0,
                            control_message.message_type,
                            route.generation,
                            &control_message.protected_body,
                        )?;
                        match (control_message.message_type, payload) {
                            (MessageType::Ready, P1Payload::Ready { proof }) => {
                                let expected = ready_proof(
                                    &route.route_secret.0,
                                    &route.challenge,
                                    &route.pseudonym,
                                )?;
                                verify_proof(&expected, &proof)?;
                                state.apply(branch_token, Event::ReadyAccepted)?;
                                setup_latency_ms = setup_started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                                send_control(
                                    &link,
                                    route,
                                    MessageType::RendezvousOpen,
                                    &P1Payload::RendezvousOpen {
                                        gateway_pseudonym: route.pseudonym,
                                        capability: capability.0,
                                    },
                                )?;
                            }
                            (MessageType::RendezvousResult, P1Payload::RendezvousResult { status }) => {
                                if status != 0 {
                                    return Err(format!("rendezvous redemption failed with status {status}").into());
                                }
                                state.apply(branch_token, Event::CapabilityAccepted)?;
                                send_control(
                                    &link,
                                    route,
                                    MessageType::Data,
                                    &P1Payload::Data { direction: 0, sequence: 0, payload: message.clone() },
                                )?;
                            }
                            (MessageType::Data, P1Payload::Data { direction: 1, sequence: 0, payload }) => {
                                if payload != message {
                                    return Err("echo payload mismatch".into());
                                }
                                state.apply(branch_token, Event::DataAccepted)?;
                                send_control(
                                    &link,
                                    route,
                                    MessageType::Close,
                                    &P1Payload::Close { reason: 0 },
                                )?;
                                cleanup_started = Some(Instant::now());
                                state.apply(branch_token, Event::CloseAccepted)?;
                                success = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            LinkEvent::TransmissionFailed { .. } => {
                return Err("T1 retry budget exhausted".into());
            }
            LinkEvent::SecurityEvent { code, .. } => {
                structured_event("endpoint", "security_event", &[("code", code.to_owned())]);
            }
            _ => {}
        }
    }

    if success {
        std::thread::sleep(Duration::from_millis(1_500));
    }
    if state.live_routes() != 0 {
        let _ = state.apply(branch_token, Event::Timeout);
    }
    drop(active.take());
    let cleanup_ms = cleanup_started
        .map(|started| started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0);
    link.shutdown()?;
    let metrics = collect_stopped(&event_receiver, peer_id);
    write_link_metrics(&metrics_path, "endpoint", state.live_routes(), cleanup_ms, &metrics)?;

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
