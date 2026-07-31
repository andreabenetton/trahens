// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use codec_m2::{Candidate, Control, Discover, Envelope, Message, MessageType, P1Payload};
use node_runtime::p1::{
    commit_proof, open_candidate_chain, open_control, ready_proof, seal_control, verify_proof,
};
use node_runtime::{
    drain_links, event_channel, parse_hex, spawn_link, structured_event, unix_time_ms,
    write_link_metrics, CliArgs, LinkConfig, LinkEvent, LinkMetrics, RemoteInputDrops,
};
use protocol_registry::{
    ERROR_AUTHENTICATION_FAILED, ERROR_INTERNAL, ERROR_STATE_VIOLATION, ERROR_TIMEOUT,
    LIMIT_CAPABILITY_TTL_MS, LIMIT_ROUTE_TTL_MS, SUITE_R1,
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
    let endpoint_handshake = args
        .optional("endpoint-handle", "p1-endpoint")
        .as_bytes()
        .to_vec();
    let generation = 0_u32;
    let setup_started = Instant::now();
    let absolute_deadline = unix_time_ms().saturating_add(timeout_ms);
    let mut state = RouteTable::default();
    let mut drops = RemoteInputDrops::new();
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
    let mut transport_failed = false;
    let redeem_twice = args.flag("redeem-twice");
    let mut redemptions = 0_u32;

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
                }) if candidate_token == branch_token && active.is_none() => {
                    // The candidate chain is remote input: an unauthentic or
                    // malformed blob is dropped and the endpoint keeps
                    // waiting for a valid candidate until its deadline.
                    let Ok(opened) = open_candidate_chain(
                        &root_secret.0,
                        &candidate_blob,
                        layer_count,
                        &expected_gateway_public,
                        &discovery_nonce,
                        unix_time_ms(),
                    ) else {
                        drops.record("endpoint", ERROR_AUTHENTICATION_FAILED, "candidate_chain");
                        continue;
                    };
                    if state
                        .apply(branch_token, Event::CandidateAccepted, unix_time_ms())
                        .is_err()
                    {
                        drops.record("endpoint", ERROR_STATE_VIOLATION, "candidate_transition");
                        continue;
                    }
                    let route = ActiveRoute {
                        local_label: branch_token,
                        generation,
                        route_secret: SecretBytes(opened.route_secret),
                        challenge: SecretBytes(opened.commit_challenge),
                        pseudonym: opened.gateway_pseudonym,
                    };
                    let proof =
                        commit_proof(&route.route_secret.0, &route.challenge.0, &route.pseudonym)?;
                    send_control(
                        &link,
                        &route,
                        MessageType::Commit,
                        &P1Payload::Commit { proof },
                    )?;
                    state.apply(branch_token, Event::CommitAccepted, unix_time_ms())?;
                    active = Some(route);
                    structured_event(
                        "endpoint",
                        "candidate_authenticated",
                        &[("layers", layer_count.to_string())],
                    );
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
                                .apply(branch_token, Event::ReadyAccepted, unix_time_ms())
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
                                state.apply(branch_token, Event::CloseAccepted, unix_time_ms())?;
                                success = true;
                                break;
                            }
                            if status != 0 {
                                return Err(format!(
                                    "rendezvous redemption failed with status {status}"
                                )
                                .into());
                            }
                            state.apply(branch_token, Event::CapabilityAccepted, unix_time_ms())?;
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
                                return Err("echo payload mismatch".into());
                            }
                            state.apply(branch_token, Event::DataAccepted, unix_time_ms())?;
                            send_control(
                                &link,
                                route,
                                MessageType::Close,
                                &P1Payload::Close { reason: 0 },
                            )?;
                            cleanup_started = Some(Instant::now());
                            state.apply(branch_token, Event::CloseAccepted, unix_time_ms())?;
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
    if state.live_routes() != 0 {
        let _ = state.apply(branch_token, Event::Timeout, unix_time_ms());
    }
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

    if transport_failed {
        return Err(format!("T1 retry budget exhausted; status={ERROR_TIMEOUT}").into());
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
