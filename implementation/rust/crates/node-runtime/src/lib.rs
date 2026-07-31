// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "UDP link runtime shared by Trahens P1 executables."]

pub mod p1;

use codec_m2::{decode, encode, Envelope};
use protocol_registry::{
    ERROR_INTERNAL, ERROR_MALFORMED, ERROR_RESOURCE_EXHAUSTED, ERROR_UNSUPPORTED_SUITE,
    FIXED_T2_ACK_RESERVE_PER_EPOCH, FIXED_T2_CELLS_PER_EPOCH, FIXED_T2_EPOCH_MS,
    FIXED_T2_QUEUE_CELLS_PER_PEER, FIXED_T2_RETRANSMIT_RESERVE_PER_EPOCH, LIMIT_MAX_T1_RETRIES,
    LIMIT_T1_ACK_DELAY_MAX_MS, LIMIT_T1_MAX_PENDING_ACKS, LIMIT_T1_RTO_MS, SUITE_R1,
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
    pub ack_coalesced: u64,
    pub reassembly: transport_t1::ReceiverMetrics,
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

/// Monotonic local clock.
///
/// `event-lifecycle-profile-e1.md` section 1 models time as a monotonically
/// increasing local clock, and every E1 deadline is expressed against it. Wall
/// clock is unusable for that: a backward adjustment prolongs route state past
/// its deadline, and a forward one expires a live route early. Reserve
/// [`unix_time_ms`] for values two processes compare with each other.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    origin: Instant,
}

impl Clock {
    #[must_use]
    pub fn start() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    /// Milliseconds since this clock started. Never decreases.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        elapsed_ms(self.origin)
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::start()
    }
}

/// Wall-clock milliseconds since the Unix epoch.
///
/// Only for values that cross a trust boundary and are compared by another
/// process: the sealed gateway offer's expiry, the capability validity
/// interval a client asserts, and the R1 registration TTLs. Local deadlines
/// MUST use [`Clock`].
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

/// Transmission identifier of any frame, used to coalesce queued ACKs.
fn ack_transmission_id(frame: &Frame) -> [u8; 16] {
    match frame {
        Frame::Data {
            transmission_id, ..
        }
        | Frame::Ack {
            transmission_id, ..
        }
        | Frame::Chaff {
            transmission_id, ..
        } => *transmission_id,
    }
}

/// Stamp the measured hold time onto an ACK, bounded by the registry limit.
fn with_ack_delay(frame: Frame, held_ms: u64) -> Frame {
    if let Frame::Ack {
        suite,
        transmission_id,
        fragment_count,
        bitmap,
        ..
    } = frame
    {
        let bounded = held_ms.min(LIMIT_T1_ACK_DELAY_MAX_MS as u64);
        return Frame::Ack {
            suite,
            transmission_id,
            fragment_count,
            ack_delay_ms: u16::try_from(bounded).unwrap_or(u16::MAX),
            bitmap,
        };
    }
    frame
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
    // Queued ACKs with the time each was first queued, so the emitted
    // ack_delay_ms reports the real hold rather than a constant zero.
    let mut ack_queue: VecDeque<(Frame, u64)> = VecDeque::new();
    let mut metrics = LinkMetrics::default();
    let mut buffer = [0_u8; 2_048];
    let mut running = true;
    let mut draining = false;
    // Per-epoch slot accounting. transport-profile-t2.md section 6 requires
    // the ACK and retransmit reserves to be finite and never to starve DATA,
    // so each is capped per epoch; DATA is guaranteed the remaining slots.
    let mut slot_in_epoch = 0_usize;
    let mut ack_slots = 0_usize;
    let mut retransmit_slots = 0_usize;

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
                                        // transport-profile-t1.md section 9:
                                        // an ACK is cumulative for its
                                        // transmission, so a newer one
                                        // supersedes any still queued. Replace
                                        // in place to coalesce a burst of
                                        // fragment arrivals into one cell.
                                        let queued_id = ack_transmission_id(&result.ack);
                                        let existing = ack_queue.iter_mut().find(|(frame, _)| {
                                            ack_transmission_id(frame) == queued_id
                                        });
                                        if let Some((frame, _)) = existing {
                                            *frame = result.ack;
                                            metrics.ack_coalesced =
                                                metrics.ack_coalesced.saturating_add(1);
                                        } else if ack_queue.len() < LIMIT_T1_MAX_PENDING_ACKS {
                                            ack_queue.push_back((result.ack, elapsed_ms(origin)));
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
        // Retry exhaustion is scoped to the transmission that ran out of
        // budget. Tearing down every transmission on the link would let one
        // stalled message fail unrelated routes that were making progress.
        for transmission_id in sender.poll_timeouts(now_ms).exhausted {
            if sender.abort(transmission_id) {
                metrics.transmission_failures = metrics.transmission_failures.saturating_add(1);
                let _ = events.try_send(LinkEvent::TransmissionFailed {
                    peer_id: config.peer_id,
                });
            }
        }
        receiver.expire(now_ms);
        metrics.peak_queue_cells = metrics
            .peak_queue_cells
            .max(sender.queue_depth().saturating_add(ack_queue.len()));

        let now = Instant::now();
        if now >= schedule.next_deadline() {
            let ack_available = !ack_queue.is_empty();
            let take_ack = ack_available && ack_slots < FIXED_T2_ACK_RESERVE_PER_EPOCH;
            let take_retransmit =
                !take_ack && retransmit_slots < FIXED_T2_RETRANSMIT_RESERVE_PER_EPOCH;

            let mut pop_ack = || {
                ack_queue.pop_front().map(|(frame, queued_at)| {
                    with_ack_delay(frame, elapsed_ms(origin).saturating_sub(queued_at))
                })
            };

            let (class, frame) = if take_ack {
                match pop_ack() {
                    Some(frame) => {
                        ack_slots += 1;
                        (SlotClass::Ack, frame)
                    }
                    None => continue,
                }
            } else if take_retransmit && sender.has_retry() {
                match sender.next_retry(now_ms) {
                    Some(frame) => {
                        retransmit_slots += 1;
                        (SlotClass::Retransmission, frame)
                    }
                    None => continue,
                }
            } else if let Some(frame) = sender.next_new(now_ms) {
                (SlotClass::NewData, frame)
            } else if let Some(frame) = pop_ack() {
                // Beyond the reserve, but DATA has nothing queued: emitting a
                // held ACK beats emitting chaff.
                ack_slots += 1;
                (SlotClass::Ack, frame)
            } else if let Some(frame) = sender.next_retry(now_ms) {
                retransmit_slots += 1;
                (SlotClass::Retransmission, frame)
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
                    slot_in_epoch += 1;
                    if slot_in_epoch >= FIXED_T2_CELLS_PER_EPOCH {
                        slot_in_epoch = 0;
                        ack_slots = 0;
                        retransmit_slots = 0;
                    }
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
    metrics.reassembly = receiver.metrics();
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

/// Chaff cells per real cell, one of the P1 measurements.
///
/// "Real" is every non-chaff emission: ACK, retransmission, and new DATA.
#[must_use]
pub fn chaff_to_real_ratio(metrics: &LinkMetrics) -> f64 {
    let real = metrics
        .schedule
        .ack_cells
        .saturating_add(metrics.schedule.retransmission_cells)
        .saturating_add(metrics.schedule.new_data_cells);
    if real == 0 {
        return 0.0;
    }
    metrics.schedule.chaff_cells as f64 / real as f64
}

/// Deterministic precedence for events sharing a local timestamp.
///
/// `event-lifecycle-profile-e1.md` section 2 fixes the order as: state expiry,
/// cancellation and abort, route control, candidate, discover, window closure,
/// local generation. State expiry is driven by each node's timer branch rather
/// than by a link event, so rank 0 is reserved for it and link events occupy
/// the remaining ranks in the same relative order.
#[must_use]
pub fn event_precedence(event: &LinkEvent) -> u8 {
    match event {
        // A transport failure reclaims state, so it ranks with expiry.
        LinkEvent::TransmissionFailed { .. } => 1,
        LinkEvent::Message { envelope, .. } => match &envelope.message {
            codec_m2::Message::Control(control) => match control.message_type {
                codec_m2::MessageType::Cancel
                | codec_m2::MessageType::Abort
                | codec_m2::MessageType::Close => 2,
                _ => 3,
            },
            codec_m2::Message::Candidate(_) => 4,
            codec_m2::Message::Discover(_) => 5,
            codec_m2::Message::Chaff => 7,
        },
        LinkEvent::SecurityEvent { .. } => 6,
        LinkEvent::Stopped { .. } | LinkEvent::Drained { .. } => 7,
    }
}

/// Collect every immediately available event and order it by precedence.
///
/// Events that arrive together carry the same local timestamp, so processing
/// them in arrival order would make the outcome depend on channel scheduling.
/// The sort is stable, so equal-precedence events keep arrival order.
pub fn drain_in_precedence_order(
    events: &ChannelReceiver<LinkEvent>,
    first: LinkEvent,
) -> Vec<LinkEvent> {
    let mut batch = vec![first];
    while let Ok(event) = events.try_recv() {
        batch.push(event);
        if batch.len() >= FIXED_T2_QUEUE_CELLS_PER_PEER {
            break;
        }
    }
    batch.sort_by_key(event_precedence);
    batch
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

    /// True when `--name` was supplied with any value.
    #[must_use]
    pub fn flag(&self, name: &str) -> bool {
        self.values.contains_key(name)
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
    peaks: state_machine::StatePeaks,
    links: &[(u32, LinkMetrics)],
) -> Result<(), RuntimeError> {
    let mut output = format!(
        "{{\n  \"node\": \"{}\",\n  \"live_routes\": {},\n  \"cleanup_ms\": {},\n  \"remote_input_drops\": {},\n  \"peak_routes\": {},\n  \"peak_routes_per_peer\": {},\n  \"peak_branches\": {},\n  \"peak_pending_ready\": {},\n  \"peak_active\": {},\n  \"links\": [\n",
        node.replace('"', "'"),
        live_routes,
        cleanup_ms,
        drops.to_json(),
        peaks.peak_routes,
        peaks.peak_routes_per_peer,
        peaks.peak_branches,
        peaks.peak_pending_ready,
        peaks.peak_active
    );
    for (index, (peer, metrics)) in links.iter().enumerate() {
        if index != 0 {
            output.push_str(",\n");
        }
        output.push_str(&format!(
            "    {{\"peer_id\":{peer},\"sent_cells\":{},\"received_cells\":{},\"malformed_cells\":{},\"replay_rejections\":{},\"logical_messages_sent\":{},\"logical_messages_received\":{},\"transmission_failures\":{},\"ack_drops\":{},\"ack_coalesced\":{},\"duplicate_fragments\":{},\"capacity_drops\":{},\"metadata_failures\":{},\"peak_reassembly_messages\":{},\"peak_reassembly_bytes\":{},\"chaff_to_real_cell_ratio\":{:.4},\"peak_queue_cells\":{},\"slots\":{},\"ack_cells\":{},\"retransmission_cells\":{},\"new_data_cells\":{},\"chaff_cells\":{}}}",
            metrics.sent_cells,
            metrics.received_cells,
            metrics.malformed_cells,
            metrics.replay_rejections,
            metrics.logical_messages_sent,
            metrics.logical_messages_received,
            metrics.transmission_failures,
            metrics.ack_drops,
            metrics.ack_coalesced,
            metrics.reassembly.duplicate_fragments,
            metrics.reassembly.capacity_drops,
            metrics.reassembly.metadata_failures,
            metrics.reassembly.peak_messages,
            metrics.reassembly.peak_reserved_bytes,
            chaff_to_real_ratio(metrics),
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
    fn equal_time_events_follow_the_specified_precedence() {
        // E1 section 2: cancellation outranks route control, which outranks
        // candidate, which outranks discover.
        let control = |message_type| LinkEvent::Message {
            peer_id: 1,
            envelope: Envelope {
                suite_id: SUITE_R1,
                message: codec_m2::Message::Control(codec_m2::Control {
                    message_type,
                    local_label: [1_u8; 16],
                    generation: 0,
                    expiry_class: 1,
                    protected_body: vec![1],
                }),
            },
            received_at_ms: 0,
        };
        assert!(
            event_precedence(&control(codec_m2::MessageType::Cancel))
                < event_precedence(&control(codec_m2::MessageType::Commit)),
            "cancellation can overtake a delayed route-control message"
        );
        assert!(
            event_precedence(&LinkEvent::TransmissionFailed { peer_id: 1 })
                < event_precedence(&control(codec_m2::MessageType::Cancel)),
            "state reclamation ranks first"
        );

        let candidate = LinkEvent::Message {
            peer_id: 1,
            envelope: Envelope {
                suite_id: SUITE_R1,
                message: codec_m2::Message::Candidate(codec_m2::Candidate {
                    candidate_token: [2_u8; 16],
                    expiry_class: 1,
                    layer_count: 1,
                    candidate_blob: vec![7],
                }),
            },
            received_at_ms: 0,
        };
        let discover = LinkEvent::Message {
            peer_id: 1,
            envelope: Envelope {
                suite_id: SUITE_R1,
                message: codec_m2::Message::Discover(codec_m2::Discover {
                    branch_token: [3_u8; 16],
                    hop_remaining: 4,
                    fanout_class: 1,
                    expiry_class: 1,
                    options: 0,
                    reply_public_key: [4_u8; 32],
                    discovery_field: vec![5_u8; 32],
                }),
            },
            received_at_ms: 0,
        };
        assert!(
            event_precedence(&control(codec_m2::MessageType::Commit))
                < event_precedence(&candidate)
        );
        assert!(event_precedence(&candidate) < event_precedence(&discover));

        // A batch arriving together is reordered, and the sort is stable.
        let (sender, receiver) = event_channel();
        sender.try_send(candidate).ok();
        sender.try_send(control(codec_m2::MessageType::Cancel)).ok();
        let ordered = drain_in_precedence_order(&receiver, discover);
        let ranks: Vec<u8> = ordered.iter().map(event_precedence).collect();
        assert_eq!(ranks, vec![2, 4, 5], "cancel, candidate, discover");
    }

    #[test]
    fn ack_delay_reports_the_measured_hold_bounded_by_the_registry() {
        let ack = Frame::Ack {
            suite: SUITE_R1,
            transmission_id: [3_u8; 16],
            fragment_count: 2,
            ack_delay_ms: 0,
            bitmap: 0b11,
        };
        let Frame::Ack { ack_delay_ms, .. } = with_ack_delay(ack.clone(), 7) else {
            panic!("expected an ACK");
        };
        assert_eq!(
            ack_delay_ms, 7,
            "reports the real hold, not a constant zero"
        );

        let Frame::Ack { ack_delay_ms, .. } = with_ack_delay(ack, 10_000) else {
            panic!("expected an ACK");
        };
        assert_eq!(
            u64::from(ack_delay_ms),
            LIMIT_T1_ACK_DELAY_MAX_MS as u64,
            "bounded by the registry limit"
        );
    }

    #[test]
    fn ack_coalescing_keys_on_the_transmission_identifier() {
        let data = Frame::Data {
            suite: SUITE_R1,
            transmission_id: [1_u8; 16],
            fragment_index: 0,
            fragment_count: 1,
            total_length: 3,
            fragment: b"abc".to_vec(),
        };
        let ack = Frame::Ack {
            suite: SUITE_R1,
            transmission_id: [1_u8; 16],
            fragment_count: 1,
            ack_delay_ms: 0,
            bitmap: 0b1,
        };
        let chaff = Frame::Chaff {
            suite: SUITE_R1,
            transmission_id: [2_u8; 16],
        };
        assert_eq!(ack_transmission_id(&data), ack_transmission_id(&ack));
        assert_ne!(ack_transmission_id(&chaff), ack_transmission_id(&ack));
    }

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
