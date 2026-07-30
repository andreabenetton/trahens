#![forbid(unsafe_code)]

use codec_m2::{Candidate, Control, Envelope, Message, MessageType, P1Payload};
use node_runtime::p1::{
    commit_proof, open_control, ready_proof, seal_control, seal_gateway_offer, verify_proof,
};
use node_runtime::{
    event_channel, parse_hex, spawn_link, structured_event, unix_time_ms, write_link_metrics,
    CliArgs, LinkConfig, LinkEvent, LinkMetrics,
};
use protocol_registry::{
    ERROR_CAPABILITY_INVALID, ERROR_STATE_VIOLATION, LIMIT_CAPABILITY_TTL_MS,
    LIMIT_MAX_FAILED_REDEMPTIONS_PER_ROUTE, LIMIT_ROUTE_TTL_MS, SUITE_R1,
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
    generation: u32,
    route_secret: SecretBytes<32>,
    challenge: [u8; 32],
    pseudonym: [u8; 16],
    expires_at_ms: u64,
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
        route.label,
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
    let mut registry = Registry::default();
    registry.register(
        gateway_id,
        &capability,
        endpoint_handle,
        unix_time_ms(),
        args.u64_or("capability-ttl-ms", LIMIT_CAPABILITY_TTL_MS as u64)?,
    )?;
    drop(capability);

    let (event_sender, event_receiver) = event_channel();
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
    )?;

    let mut states = RouteTable::default();
    let mut routes: HashMap<[u8; 16], GatewayRoute> = HashMap::new();
    let deadline = unix_time_ms().saturating_add(timeout_ms);
    let mut observed_close = false;
    let mut cleanup_started: Option<Instant> = None;
    let mut redemption_latency_ms = 0_u64;

    while unix_time_ms() < deadline {
        let event = match event_receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(value) => value,
            Err(RecvTimeoutError::Timeout) => {
                let now = unix_time_ms();
                registry.expire(now);
                let expired: Vec<[u8; 16]> = routes
                    .iter()
                    .filter_map(|(label, route)| (route.expires_at_ms <= now).then_some(*label))
                    .collect();
                for label in expired {
                    routes.remove(&label);
                    let _ = states.apply(label, Event::Timeout);
                }
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
                Message::Discover(discover) => {
                    if routes.contains_key(&discover.branch_token) {
                        continue;
                    }
                    let discovery_nonce: [u8; 32] = discover
                        .discovery_field
                        .as_slice()
                        .try_into()
                        .map_err(|_| "invalid R1 discovery nonce")?;
                    let route_secret = random_bytes::<32>()?;
                    let challenge = random_bytes::<32>()?;
                    let pseudonym = random_nonzero_16()?;
                    if route_secret == [0_u8; 32] || challenge == [0_u8; 32] {
                        return Err("gateway generated an invalid route secret".into());
                    }
                    let expires_at_ms = unix_time_ms().saturating_add(LIMIT_ROUTE_TTL_MS as u64);
                    let blob = seal_gateway_offer(
                        &discover.reply_public_key,
                        gateway_id,
                        expires_at_ms,
                        pseudonym,
                        route_secret,
                        challenge,
                        discovery_nonce,
                        signing_public,
                        &signing_secret,
                    )?;
                    states.begin(discover.branch_token, peer_id, 0, expires_at_ms)?;
                    states.apply(discover.branch_token, Event::CandidateAccepted)?;
                    routes.insert(
                        discover.branch_token,
                        GatewayRoute {
                            label: discover.branch_token,
                            generation: 0,
                            route_secret: SecretBytes(route_secret),
                            challenge,
                            pseudonym,
                            expires_at_ms,
                            failed_redemptions: 0,
                        },
                    );
                    link.send(Envelope {
                        suite_id: SUITE_R1,
                        message: Message::Candidate(Candidate {
                            candidate_token: discover.branch_token,
                            expiry_class: discover.expiry_class,
                            layer_count: 1,
                            candidate_blob: blob,
                        }),
                    })?;
                }
                Message::Control(control_message) => {
                    let route_label = control_message.local_label;
                    let mut cleanup_event = None;
                    {
                        let Some(route) = routes.get_mut(&route_label) else {
                            continue;
                        };
                        if control_message.generation != route.generation {
                            continue;
                        }
                        let payload = match open_control(
                            &route.route_secret.0,
                            control_message.message_type,
                            route.generation,
                            &control_message.protected_body,
                        ) {
                            Ok(value) => value,
                            Err(_) => {
                                structured_event(
                                    "rendezvous",
                                    "security_event",
                                    &[("code", "e2e_authentication_failed".to_owned())],
                                );
                                continue;
                            }
                        };
                        match (control_message.message_type, payload) {
                            (MessageType::Commit, P1Payload::Commit { proof }) => {
                                let expected = commit_proof(
                                    &route.route_secret.0,
                                    &route.challenge,
                                    &route.pseudonym,
                                )?;
                                verify_proof(&expected, &proof)?;
                                states.apply(route.label, Event::CommitAccepted)?;
                                let ready = ready_proof(
                                    &route.route_secret.0,
                                    &route.challenge,
                                    &route.pseudonym,
                                )?;
                                send_control(
                                    &link,
                                    route,
                                    MessageType::Ready,
                                    &P1Payload::Ready { proof: ready },
                                )?;
                                states.apply(route.label, Event::ReadyAccepted)?;
                            }
                            (
                                MessageType::RendezvousOpen,
                                P1Payload::RendezvousOpen {
                                    gateway_pseudonym,
                                    capability,
                                },
                            ) => {
                                let started = Instant::now();
                                let phase = states.get(&route.label).map(|state| state.phase);
                                let mut status = ERROR_STATE_VIOLATION;
                                if phase == Some(Phase::Ready)
                                    && gateway_pseudonym == route.pseudonym
                                {
                                    let presented = SecretBytes(capability);
                                    status = match registry.redeem(
                                        gateway_id,
                                        &presented,
                                        unix_time_ms(),
                                    )? {
                                        Some(_handle) => {
                                            states.apply(route.label, Event::CapabilityAccepted)?;
                                            0
                                        }
                                        None => {
                                            route.failed_redemptions =
                                                route.failed_redemptions.saturating_add(1);
                                            ERROR_CAPABILITY_INVALID
                                        }
                                    };
                                }
                                redemption_latency_ms =
                                    started.elapsed().as_micros().try_into().unwrap_or(u64::MAX);
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
                                states.apply(route.label, Event::DataAccepted)?;
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
                                observed_close = true;
                                cleanup_event = Some(Event::CloseAccepted);
                            }
                            (MessageType::Cancel | MessageType::Abort, _) => {
                                cleanup_started = Some(Instant::now());
                                cleanup_event = Some(Event::CancelAccepted);
                            }
                            _ => {}
                        }
                    }
                    if let Some(event) = cleanup_event {
                        routes.remove(&route_label);
                        states.apply(route_label, event)?;
                    }
                }
                _ => {}
            },
            LinkEvent::TransmissionFailed { .. } => {
                return Err("T1 retry budget exhausted".into());
            }
            LinkEvent::SecurityEvent {
                peer_id: source,
                code,
            } => {
                structured_event(
                    "rendezvous",
                    "security_event",
                    &[("peer", source.to_string()), ("code", code.to_owned())],
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
        routes.remove(&label);
        let _ = states.apply(label, Event::Timeout);
    }
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
    if !observed_close {
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
