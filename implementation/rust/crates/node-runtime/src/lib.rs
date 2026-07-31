// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "UDP link runtime shared by Trahens P1 executables."]

pub mod p1;

use codec_m2::{decode, encode, Envelope};
use protocol_registry::{
    ERROR_INTERNAL, ERROR_MALFORMED, ERROR_RESOURCE_EXHAUSTED, ERROR_UNSUPPORTED_SUITE,
    FIXED_T2_EPOCH_MS, FIXED_T2_QUEUE_CELLS_PER_PEER, LIMIT_MAX_T1_RETRIES,
    LIMIT_T1_MAX_PENDING_ACKS, LIMIT_T1_RTO_MS, SUITE_R1,
};
use scheduling_t2::{FixedSchedule, ScheduleMetrics, SlotClass};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver as ChannelReceiver, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use trahens_crypto::{hmac_sha256, random_bytes, zeroize};
use transport_t1::{decode_frame, encode_frame, fresh_chaff, Frame, Receiver, Sender};
use wire_w2::{open_record, seal_record, ReplayWindow};

#[derive(Debug, Clone)]
pub struct LinkConfig {
    pub local_id: u32,
    pub peer_id: u32,
    pub bind: SocketAddr,
    pub peer: SocketAddr,
    pub base_key: [u8; 32],
    pub epoch: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkMetrics {
    pub sent_cells: u64,
    pub received_cells: u64,
    pub malformed_cells: u64,
    pub replay_rejections: u64,
    pub logical_messages_sent: u64,
    pub logical_messages_received: u64,
    pub transmission_failures: u64,
    pub ack_drops: u64,
    pub peak_queue_cells: usize,
    pub schedule: ScheduleMetrics,
}

#[derive(Debug)]
pub enum LinkEvent {
    Message {
        peer_id: u32,
        envelope: Envelope,
        received_at_ms: u64,
    },
    TransmissionFailed {
        peer_id: u32,
    },
    SecurityEvent {
        peer_id: u32,
        /// Stable registry `ERROR_*` identifier (Core v1.5 section 8.7).
        error_id: u16,
        /// Human-readable detail; never a substitute for `error_id`.
        detail: &'static str,
    },
    Stopped {
        peer_id: u32,
        metrics: LinkMetrics,
    },
    /// Emitted once after `request_drain` when the sender has no pending
    /// transmissions and no queued ACKs, so shutdown loses nothing in flight.
    Drained {
        peer_id: u32,
    },
}

#[derive(Debug)]
enum LinkCommand {
    Send(Envelope),
    Drain,
    Shutdown,
}

pub struct LinkHandle {
    peer_id: u32,
    commands: SyncSender<LinkCommand>,
    worker: Option<JoinHandle<()>>,
}

impl LinkHandle {
    pub fn send(&self, envelope: Envelope) -> Result<(), RuntimeError> {
        self.commands
            .try_send(LinkCommand::Send(envelope))
            .map_err(|_| RuntimeError::QueueFull)
    }

    /// Ask the worker to report `LinkEvent::Drained` once it is idle.
    pub fn request_drain(&self) -> Result<(), RuntimeError> {
        self.commands
            .try_send(LinkCommand::Drain)
            .map_err(|_| RuntimeError::QueueFull)
    }

    pub fn shutdown(mut self) -> Result<(), RuntimeError> {
        let _ = self.commands.send(LinkCommand::Shutdown);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| RuntimeError::Thread)?;
        }
        Ok(())
    }

    pub fn peer_id(&self) -> u32 {
        self.peer_id
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Io(std::io::Error),
    QueueFull,
    Thread,
    KeyDerivation,
    Arguments(String),
}

impl From<std::io::Error> for RuntimeError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "runtime I/O error: {error}"),
            Self::QueueFull => formatter.write_str("runtime queue is full"),
            Self::Thread => formatter.write_str("runtime worker failed"),
            Self::KeyDerivation => formatter.write_str("runtime key derivation failed"),
            Self::Arguments(message) => write!(formatter, "invalid arguments: {message}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

fn directional_key(base: &[u8; 32], sender: u32, receiver: u32) -> Result<[u8; 32], RuntimeError> {
    let mut input = Vec::with_capacity(8 + 22);
    input.extend_from_slice(b"Trahens-W2-direction-v1");
    input.extend_from_slice(&sender.to_be_bytes());
    input.extend_from_slice(&receiver.to_be_bytes());
    hmac_sha256(base, &input).map_err(|_| RuntimeError::KeyDerivation)
}

fn elapsed_ms(origin: Instant) -> u64 {
    origin.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn next_transmission_id() -> Option<[u8; 16]> {
    for _ in 0..32 {
        if let Ok(value) = random_bytes::<16>() {
            if value != [0_u8; 16] {
                return Some(value);
            }
        }
    }
    None
}

pub fn unix_time_ms() -> u64 {
    let base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0);
    let offset = std::env::var("TRAHENS_CLOCK_OFFSET_MS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    if offset >= 0 {
        base.saturating_add(offset as u64)
    } else {
        base.saturating_sub(offset.unsigned_abs())
    }
}

pub fn spawn_link(
    config: LinkConfig,
    events: SyncSender<LinkEvent>,
) -> Result<LinkHandle, RuntimeError> {
    let socket = UdpSocket::bind(config.bind)?;
    socket.connect(config.peer)?;
    socket.set_nonblocking(true)?;
    let send_key = directional_key(&config.base_key, config.local_id, config.peer_id)?;
    let receive_key = directional_key(&config.base_key, config.peer_id, config.local_id)?;
    let (command_sender, command_receiver) = mpsc::sync_channel(FIXED_T2_QUEUE_CELLS_PER_PEER);
    let peer_id = config.peer_id;
    let worker = thread::Builder::new()
        .name(format!(
            "trahens-link-{}-{}",
            config.local_id, config.peer_id
        ))
        .spawn(move || {
            run_link(
                config,
                socket,
                send_key,
                receive_key,
                command_receiver,
                events,
            )
        })?;
    Ok(LinkHandle {
        peer_id,
        commands: command_sender,
        worker: Some(worker),
    })
}

fn run_link(
    mut config: LinkConfig,
    socket: UdpSocket,
    mut send_key: [u8; 32],
    mut receive_key: [u8; 32],
    commands: ChannelReceiver<LinkCommand>,
    events: SyncSender<LinkEvent>,
) {
    let origin = Instant::now();
    let mut schedule = FixedSchedule::new(origin);
    // Randomized but bounded to the low 32 bits: the start stays
    // unpredictable while leaving 2^64 - 2^32 sequence numbers of headroom, so
    // the wrap guard below is unreachable in any real run. An unbounded random
    // start could sit near u64::MAX and fail the link within a few cells.
    let mut sequence = u64::from(u32::from_be_bytes(random_bytes::<4>().unwrap_or([0_u8; 4])));
    let mut replay = ReplayWindow::new(config.epoch);
    let mut sender = Sender::new();
    let mut receiver = Receiver::new();
    let mut ack_queue: VecDeque<Frame> = VecDeque::new();
    let mut metrics = LinkMetrics::default();
    let mut buffer = [0_u8; 2_048];
    let mut running = true;
    let mut draining = false;

    while running {
        loop {
            match commands.try_recv() {
                Ok(LinkCommand::Send(envelope)) => {
                    let encoded = match encode(&envelope) {
                        Ok(value) => value,
                        Err(_) => {
                            let _ = events.try_send(LinkEvent::SecurityEvent {
                                peer_id: config.peer_id,
                                error_id: ERROR_INTERNAL,
                                detail: "local_noncanonical_message",
                            });
                            continue;
                        }
                    };
                    let Some(id) = next_transmission_id() else {
                        let _ = events.try_send(LinkEvent::TransmissionFailed {
                            peer_id: config.peer_id,
                        });
                        continue;
                    };
                    if sender.enqueue(envelope.suite_id, id, &encoded).is_err() {
                        let _ = events.try_send(LinkEvent::TransmissionFailed {
                            peer_id: config.peer_id,
                        });
                    } else {
                        metrics.logical_messages_sent =
                            metrics.logical_messages_sent.saturating_add(1);
                    }
                }
                Ok(LinkCommand::Drain) => {
                    draining = true;
                }
                Ok(LinkCommand::Shutdown) => {
                    running = false;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    running = false;
                    break;
                }
            }
        }

        loop {
            match socket.recv(&mut buffer) {
                Ok(length) => {
                    match open_record(&receive_key, config.epoch, &buffer[..length], &mut replay) {
                        Ok((_received_sequence, body)) => {
                            metrics.received_cells = metrics.received_cells.saturating_add(1);
                            match decode_frame(&body) {
                                Ok(Frame::Ack {
                                    transmission_id,
                                    fragment_count,
                                    bitmap,
                                    ..
                                }) => {
                                    if sender
                                        .on_ack(
                                            transmission_id,
                                            fragment_count,
                                            bitmap,
                                            elapsed_ms(origin),
                                        )
                                        .is_err()
                                    {
                                        metrics.malformed_cells =
                                            metrics.malformed_cells.saturating_add(1);
                                    }
                                }
                                Ok(frame @ Frame::Data { .. }) => match receiver
                                    .accept(frame, elapsed_ms(origin))
                                {
                                    Ok(Some(result)) => {
                                        if ack_queue.len() < LIMIT_T1_MAX_PENDING_ACKS {
                                            ack_queue.push_back(result.ack);
                                        } else {
                                            // Dropping an ACK silently forces
                                            // the peer into an avoidable
                                            // recovery round; count it and
                                            // report the resource limit.
                                            metrics.ack_drops = metrics.ack_drops.saturating_add(1);
                                            let _ = events.try_send(LinkEvent::SecurityEvent {
                                                peer_id: config.peer_id,
                                                error_id: ERROR_RESOURCE_EXHAUSTED,
                                                detail: "ack_queue_full",
                                            });
                                        }
                                        if let Some((suite, message)) = result.complete {
                                            match decode(&message) {
                                                Ok(envelope) if envelope.suite_id == suite => {
                                                    metrics.logical_messages_received = metrics
                                                        .logical_messages_received
                                                        .saturating_add(1);
                                                    let _ = events.try_send(LinkEvent::Message {
                                                        peer_id: config.peer_id,
                                                        envelope,
                                                        received_at_ms: elapsed_ms(origin),
                                                    });
                                                }
                                                Ok(_) => {
                                                    let _ =
                                                        events.try_send(LinkEvent::SecurityEvent {
                                                            peer_id: config.peer_id,
                                                            error_id: ERROR_UNSUPPORTED_SUITE,
                                                            detail: "m2_suite_mismatch",
                                                        });
                                                }
                                                Err(_) => {
                                                    let _ =
                                                        events.try_send(LinkEvent::SecurityEvent {
                                                            peer_id: config.peer_id,
                                                            error_id: ERROR_MALFORMED,
                                                            detail: "m2_decode",
                                                        });
                                                }
                                            }
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(_) => {
                                        metrics.malformed_cells =
                                            metrics.malformed_cells.saturating_add(1);
                                    }
                                },
                                Ok(Frame::Chaff { .. }) => {}
                                Err(_) => {
                                    metrics.malformed_cells =
                                        metrics.malformed_cells.saturating_add(1);
                                }
                            }
                        }
                        Err(wire_w2::WireError::Replay) => {
                            metrics.replay_rejections = metrics.replay_rejections.saturating_add(1);
                        }
                        Err(_) => {
                            metrics.malformed_cells = metrics.malformed_cells.saturating_add(1);
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    let _ = events.try_send(LinkEvent::SecurityEvent {
                        peer_id: config.peer_id,
                        error_id: ERROR_INTERNAL,
                        detail: "udp_receive_failure",
                    });
                    break;
                }
            }
        }

        let now_ms = elapsed_ms(origin);
        if sender.poll_timeouts(now_ms).is_err() {
            let failed = sender.abort_all();
            metrics.transmission_failures =
                metrics.transmission_failures.saturating_add(failed as u64);
            let _ = events.try_send(LinkEvent::TransmissionFailed {
                peer_id: config.peer_id,
            });
        }
        receiver.expire(now_ms);
        metrics.peak_queue_cells = metrics
            .peak_queue_cells
            .max(sender.queue_depth().saturating_add(ack_queue.len()));

        let now = Instant::now();
        if now >= schedule.next_deadline() {
            let (class, frame) = if let Some(frame) = ack_queue.pop_front() {
                (SlotClass::Ack, frame)
            } else if let Some(frame) = sender.next_retry(now_ms) {
                (SlotClass::Retransmission, frame)
            } else if let Some(frame) = sender.next_new(now_ms) {
                (SlotClass::NewData, frame)
            } else {
                match fresh_chaff(SUITE_R1) {
                    Ok(frame) => (SlotClass::Chaff, frame),
                    Err(_) => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                }
            };
            match encode_frame(&frame).and_then(|body| {
                seal_record(&send_key, config.epoch, sequence, &body)
                    .map_err(|_| transport_t1::TransportError::Malformed)
            }) {
                Ok(record) => {
                    if socket.send(&record).is_ok() {
                        metrics.sent_cells = metrics.sent_cells.saturating_add(1);
                    } else {
                        let _ = events.try_send(LinkEvent::SecurityEvent {
                            peer_id: config.peer_id,
                            error_id: ERROR_INTERNAL,
                            detail: "udp_send_failure",
                        });
                    }
                    // wire-cell-w2.md section 3 forbids key and nonce reuse.
                    // The nonce is (epoch, sequence), so a wrap would silently
                    // repeat a triple and break the replay window's saturating
                    // comparisons. Fail the link cleanly at the horizon
                    // instead; the peer observes a transport failure and
                    // reclaims state through the normal path.
                    let Some(next_sequence) = sequence.checked_add(1) else {
                        let _ = events.try_send(LinkEvent::SecurityEvent {
                            peer_id: config.peer_id,
                            error_id: ERROR_RESOURCE_EXHAUSTED,
                            detail: "sequence_horizon",
                        });
                        let _ = events.try_send(LinkEvent::TransmissionFailed {
                            peer_id: config.peer_id,
                        });
                        running = false;
                        continue;
                    };
                    sequence = next_sequence;
                    schedule.advance(class);
                }
                Err(_) => {
                    let _ = events.try_send(LinkEvent::SecurityEvent {
                        peer_id: config.peer_id,
                        error_id: ERROR_INTERNAL,
                        detail: "cell_encode_failure",
                    });
                }
            }
        } else {
            let wait = schedule
                .next_deadline()
                .saturating_duration_since(now)
                .min(Duration::from_millis(1));
            thread::sleep(wait);
        }

        if draining && sender.pending_count() == 0 && ack_queue.is_empty() {
            draining = false;
            let _ = events.try_send(LinkEvent::Drained {
                peer_id: config.peer_id,
            });
        }
    }

    metrics.schedule = schedule.metrics();
    zeroize(&mut send_key);
    zeroize(&mut receive_key);
    zeroize(&mut config.base_key);
    let _ = events.send(LinkEvent::Stopped {
        peer_id: config.peer_id,
        metrics,
    });
}

pub fn event_channel() -> (SyncSender<LinkEvent>, ChannelReceiver<LinkEvent>) {
    mpsc::sync_channel(4_096)
}

pub fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], RuntimeError> {
    if value.len() != N * 2 {
        return Err(RuntimeError::KeyDerivation);
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| RuntimeError::KeyDerivation)?;
    }
    Ok(output)
}

pub fn hex(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        output.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    output
}

/// Counters for remote-supplied input that was dropped instead of processed.
///
/// Core v1.5 section 8 requires malformed, unauthenticated, or over-limit
/// remote input to be rejected without terminating the process and without
/// distinguishable failure behavior. Every drop is counted under its stable
/// registry error identifier and logged as one uniform structured event.
#[derive(Debug, Default)]
pub struct RemoteInputDrops {
    counts: std::collections::BTreeMap<u16, u64>,
}

impl RemoteInputDrops {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one dropped remote input under a registry `ERROR_*` identifier.
    pub fn record(&mut self, node: &str, error_id: u16, detail: &str) {
        *self.counts.entry(error_id).or_insert(0) += 1;
        structured_event(
            node,
            "remote_input_dropped",
            &[
                ("error_id", error_id.to_string()),
                ("detail", detail.to_owned()),
            ],
        );
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }

    /// JSON object fragment keyed by error id, e.g. `{"1":2,"9":1}`.
    #[must_use]
    pub fn to_json(&self) -> String {
        let body = self
            .counts
            .iter()
            .map(|(id, count)| format!("\"{id}\":{count}"))
            .collect::<Vec<_>>()
            .join(",");
        format!("{{{body}}}")
    }
}

/// Upper bound on the post-CLOSE drain.
///
/// A transmission that has not completed within its full T1 retry budget never
/// will: the sender raises `TransmissionFailed` instead. One extra fixed-T2
/// epoch covers the slot on which the final ACK is emitted.
#[must_use]
pub fn drain_budget() -> Duration {
    Duration::from_millis((LIMIT_MAX_T1_RETRIES * LIMIT_T1_RTO_MS + FIXED_T2_EPOCH_MS) as u64)
}

/// Wait for every link to report `Drained`, bounded by [`drain_budget`].
///
/// Replaces a fixed sleep: returns as soon as the senders are idle, and caps
/// the wait when a peer has stopped responding.
pub fn drain_links(links: &[&LinkHandle], events: &ChannelReceiver<LinkEvent>) -> usize {
    for link in links {
        let _ = link.request_drain();
    }
    let deadline = Instant::now() + drain_budget();
    let mut drained = 0;
    while drained < links.len() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match events.recv_timeout(remaining.min(Duration::from_millis(50))) {
            Ok(LinkEvent::Drained { .. }) => drained += 1,
            Ok(_) => {}
            Err(_) if Instant::now() >= deadline => break,
            Err(_) => {}
        }
    }
    drained
}

pub fn structured_event(node: &str, event: &str, fields: &[(&str, String)]) {
    let mut line = format!("{{\"node\":\"{node}\",\"event\":\"{event}\"");
    for (key, value) in fields {
        line.push_str(&format!(",\"{key}\":\"{}\"", value.replace('"', "'")));
    }
    line.push('}');
    println!("{line}");
}

pub fn default_rto() -> Duration {
    Duration::from_millis(LIMIT_T1_RTO_MS as u64)
}

#[derive(Debug, Default)]
pub struct CliArgs {
    values: std::collections::HashMap<String, String>,
}

impl CliArgs {
    pub fn parse() -> Result<Self, RuntimeError> {
        let mut values = std::collections::HashMap::new();
        let mut arguments = std::env::args().skip(1);
        while let Some(name) = arguments.next() {
            if !name.starts_with("--") {
                return Err(RuntimeError::Arguments(format!(
                    "unexpected argument: {name}"
                )));
            }
            let value = arguments
                .next()
                .ok_or_else(|| RuntimeError::Arguments(format!("missing value for {name}")))?;
            values.insert(name.trim_start_matches("--").to_owned(), value);
        }
        Ok(Self { values })
    }

    pub fn required(&self, name: &str) -> Result<&str, RuntimeError> {
        self.values
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| RuntimeError::Arguments(format!("missing --{name}")))
    }

    pub fn optional<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        self.values.get(name).map_or(default, String::as_str)
    }

    pub fn u32(&self, name: &str) -> Result<u32, RuntimeError> {
        self.required(name)?
            .parse::<u32>()
            .map_err(|_| RuntimeError::Arguments(format!("invalid --{name}")))
    }

    pub fn u64_or(&self, name: &str, default: u64) -> Result<u64, RuntimeError> {
        match self.values.get(name) {
            Some(value) => value
                .parse::<u64>()
                .map_err(|_| RuntimeError::Arguments(format!("invalid --{name}"))),
            None => Ok(default),
        }
    }

    pub fn socket(&self, name: &str) -> Result<SocketAddr, RuntimeError> {
        self.required(name)?
            .parse::<SocketAddr>()
            .map_err(|_| RuntimeError::Arguments(format!("invalid --{name}")))
    }
}

pub fn write_link_metrics(
    path: &str,
    node: &str,
    live_routes: usize,
    cleanup_ms: u64,
    drops: &RemoteInputDrops,
    links: &[(u32, LinkMetrics)],
) -> Result<(), RuntimeError> {
    let mut output = format!(
        "{{\n  \"node\": \"{}\",\n  \"live_routes\": {},\n  \"cleanup_ms\": {},\n  \"remote_input_drops\": {},\n  \"links\": [\n",
        node.replace('"', "'"),
        live_routes,
        cleanup_ms,
        drops.to_json()
    );
    for (index, (peer, metrics)) in links.iter().enumerate() {
        if index != 0 {
            output.push_str(",\n");
        }
        output.push_str(&format!(
            "    {{\"peer_id\":{peer},\"sent_cells\":{},\"received_cells\":{},\"malformed_cells\":{},\"replay_rejections\":{},\"logical_messages_sent\":{},\"logical_messages_received\":{},\"transmission_failures\":{},\"ack_drops\":{},\"peak_queue_cells\":{},\"slots\":{},\"ack_cells\":{},\"retransmission_cells\":{},\"new_data_cells\":{},\"chaff_cells\":{}}}",
            metrics.sent_cells,
            metrics.received_cells,
            metrics.malformed_cells,
            metrics.replay_rejections,
            metrics.logical_messages_sent,
            metrics.logical_messages_received,
            metrics.transmission_failures,
            metrics.ack_drops,
            metrics.peak_queue_cells,
            metrics.schedule.slots,
            metrics.schedule.ack_cells,
            metrics.schedule.retransmission_cells,
            metrics.schedule.new_data_cells,
            metrics.schedule.chaff_cells,
        ));
    }
    output.push_str("\n  ]\n}\n");
    std::fs::write(path, output).map_err(RuntimeError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_registry::{ERROR_AUTHENTICATION_FAILED, ERROR_MALFORMED};

    #[test]
    fn remote_input_drops_count_by_error_id() {
        let mut drops = RemoteInputDrops::new();
        assert_eq!(drops.total(), 0);
        assert_eq!(drops.to_json(), "{}");
        drops.record("test", ERROR_MALFORMED, "a");
        drops.record("test", ERROR_MALFORMED, "b");
        drops.record("test", ERROR_AUTHENTICATION_FAILED, "c");
        assert_eq!(drops.total(), 3);
        assert_eq!(drops.to_json(), "{\"1\":2,\"5\":1}");
    }
}
