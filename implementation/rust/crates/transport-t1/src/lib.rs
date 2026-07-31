// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "Bounded hop-local T1 framing, selective ACK, and reassembly."]

use protocol_registry::*;
use std::collections::{HashMap, VecDeque};
use trahens_crypto::{random_bytes, CryptoError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Malformed,
    UnsupportedSuite,
    ResourceLimit,
    RetryExhausted,
    Randomness,
}

impl From<CryptoError> for TransportError {
    fn from(_value: CryptoError) -> Self {
        Self::Randomness
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed T1 frame",
            Self::UnsupportedSuite => "unsupported T1 suite",
            Self::ResourceLimit => "T1 resource limit exceeded",
            Self::RetryExhausted => "T1 retry budget exhausted",
            Self::Randomness => "T1 randomness failed",
        })
    }
}

impl std::error::Error for TransportError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data {
        suite: [u8; 2],
        transmission_id: [u8; 16],
        fragment_index: u16,
        fragment_count: u16,
        total_length: u16,
        fragment: Vec<u8>,
    },
    Ack {
        suite: [u8; 2],
        transmission_id: [u8; 16],
        fragment_count: u16,
        ack_delay_ms: u16,
        bitmap: u32,
    },
    Chaff {
        suite: [u8; 2],
        transmission_id: [u8; 16],
    },
}

fn suite_valid(suite: [u8; 2]) -> bool {
    suite_is_network_valid(suite)
}

fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn canonical_fragment_length(index: u16, count: u16, total: u16) -> Option<usize> {
    if count == 0 || usize::from(count) > LIMIT_MAX_FRAGMENTS || index >= count || total == 0 {
        return None;
    }
    let total = usize::from(total);
    let count = usize::from(count);
    if count != total.div_ceil(BYTES_CELL_PAYLOAD) {
        return None;
    }
    if usize::from(index) + 1 < count {
        Some(BYTES_CELL_PAYLOAD)
    } else {
        Some(total - BYTES_CELL_PAYLOAD * (count - 1))
    }
}

pub fn encode_frame(frame: &Frame) -> Result<[u8; BYTES_CELL_BODY], TransportError> {
    let (suite, frame_type, transmission_id) = match frame {
        Frame::Data {
            suite,
            transmission_id,
            ..
        } => (*suite, T1_FRAME_DATA, *transmission_id),
        Frame::Ack {
            suite,
            transmission_id,
            ..
        } => (*suite, T1_FRAME_ACK, *transmission_id),
        Frame::Chaff {
            suite,
            transmission_id,
        } => (*suite, T1_FRAME_CHAFF, *transmission_id),
    };
    if !suite_valid(suite) {
        return Err(TransportError::UnsupportedSuite);
    }
    if !nonzero(&transmission_id) {
        return Err(TransportError::Malformed);
    }
    let mut output = random_bytes::<BYTES_CELL_BODY>()?;
    output[..4].copy_from_slice(&[
        TRANSPORT_PROFILE_T1,
        VERSION,
        PRIVACY_PROFILE_U1,
        LIFECYCLE_PROFILE_E1,
    ]);
    output[4..6].copy_from_slice(&suite);
    output[6] = frame_type;
    output[7] = 0;
    output[8..24].copy_from_slice(&transmission_id);
    match frame {
        Frame::Data {
            fragment_index,
            fragment_count,
            total_length,
            fragment,
            ..
        } => {
            let expected =
                canonical_fragment_length(*fragment_index, *fragment_count, *total_length)
                    .ok_or(TransportError::Malformed)?;
            if fragment.len() != expected {
                return Err(TransportError::Malformed);
            }
            output[24..26].copy_from_slice(&fragment_index.to_be_bytes());
            output[26..28].copy_from_slice(&fragment_count.to_be_bytes());
            output[28..30].copy_from_slice(&(fragment.len() as u16).to_be_bytes());
            output[30..32].copy_from_slice(&total_length.to_be_bytes());
            output[32..32 + fragment.len()].copy_from_slice(fragment);
        }
        Frame::Ack {
            fragment_count,
            ack_delay_ms,
            bitmap,
            ..
        } => {
            if *fragment_count == 0 || usize::from(*fragment_count) > LIMIT_MAX_FRAGMENTS {
                return Err(TransportError::Malformed);
            }
            let valid_mask = (1_u32 << u32::from(*fragment_count)) - 1;
            if bitmap & !valid_mask != 0 {
                return Err(TransportError::Malformed);
            }
            output[24..26].copy_from_slice(&fragment_count.to_be_bytes());
            output[26..28].copy_from_slice(&ack_delay_ms.to_be_bytes());
            output[28..32].copy_from_slice(&bitmap.to_be_bytes());
        }
        Frame::Chaff { .. } => output[24..32].fill(0),
    }
    Ok(output)
}

pub fn decode_frame(input: &[u8; BYTES_CELL_BODY]) -> Result<Frame, TransportError> {
    if input[0] != TRANSPORT_PROFILE_T1
        || input[1] != VERSION
        || input[2] != PRIVACY_PROFILE_U1
        || input[3] != LIFECYCLE_PROFILE_E1
        || input[7] != 0
    {
        return Err(TransportError::Malformed);
    }
    let suite = [input[4], input[5]];
    if !suite_valid(suite) {
        return Err(TransportError::UnsupportedSuite);
    }
    let mut transmission_id = [0_u8; 16];
    transmission_id.copy_from_slice(&input[8..24]);
    if !nonzero(&transmission_id) {
        return Err(TransportError::Malformed);
    }
    match input[6] {
        T1_FRAME_DATA => {
            let fragment_index = u16::from_be_bytes([input[24], input[25]]);
            let fragment_count = u16::from_be_bytes([input[26], input[27]]);
            let fragment_length = u16::from_be_bytes([input[28], input[29]]);
            let total_length = u16::from_be_bytes([input[30], input[31]]);
            let expected = canonical_fragment_length(fragment_index, fragment_count, total_length)
                .ok_or(TransportError::Malformed)?;
            if usize::from(fragment_length) != expected {
                return Err(TransportError::Malformed);
            }
            Ok(Frame::Data {
                suite,
                transmission_id,
                fragment_index,
                fragment_count,
                total_length,
                fragment: input[32..32 + expected].to_vec(),
            })
        }
        T1_FRAME_ACK => {
            let fragment_count = u16::from_be_bytes([input[24], input[25]]);
            let ack_delay_ms = u16::from_be_bytes([input[26], input[27]]);
            let bitmap = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
            if fragment_count == 0 || usize::from(fragment_count) > LIMIT_MAX_FRAGMENTS {
                return Err(TransportError::Malformed);
            }
            let valid_mask = (1_u32 << u32::from(fragment_count)) - 1;
            if bitmap & !valid_mask != 0 {
                return Err(TransportError::Malformed);
            }
            Ok(Frame::Ack {
                suite,
                transmission_id,
                fragment_count,
                ack_delay_ms,
                bitmap,
            })
        }
        T1_FRAME_CHAFF => {
            if input[24..32] != [0_u8; 8] {
                return Err(TransportError::Malformed);
            }
            Ok(Frame::Chaff {
                suite,
                transmission_id,
            })
        }
        _ => Err(TransportError::Malformed),
    }
}

/// Where one fragment of a transmission stands.
///
/// Making this explicit is what keeps a recovery round tied to a real
/// retransmission. With only a "last sent at" timestamp, a fragment queued for
/// retry but not yet released by the schedule still looked overdue on the next
/// poll, so a congested link could consume the whole retry budget without
/// putting a single cell on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FragmentState {
    /// Queued for its first emission and waiting on a slot.
    NeverSent,
    /// On the wire; the retransmission timer runs from `sent_at_ms`.
    InFlight {
        sent_at_ms: u64,
    },
    /// Waiting in the retry queue. No timer runs: it restarts on emission.
    RetryQueued,
    Acknowledged,
}

#[derive(Debug, Clone)]
struct Outbound {
    suite: [u8; 2],
    fragments: Vec<Vec<u8>>,
    acknowledged: u32,
    states: Vec<FragmentState>,
    send_count: Vec<u8>,
    recovery_rounds: u8,
}

/// Outcome of one [`Sender::poll_timeouts`] pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimeoutReport {
    /// Fragments moved into the retry queue by this pass.
    pub queued: usize,
    /// Transmissions that have spent their whole retry budget. Each is the
    /// caller's to abandon; the rest of the link is unaffected.
    pub exhausted: Vec<[u8; 16]>,
}

impl TimeoutReport {
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        self.queued == 0 && self.exhausted.is_empty()
    }
}

/// RFC 6298-style RTO estimator, per `transport-profile-t1.md` section 10.
///
/// Samples come only from fragments that were never retransmitted (Karn's
/// rule), the timer doubles on timeout, and the result is always clamped to
/// the registry's `[t1_rto_min_ms, t1_rto_max_ms]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtoEstimator {
    smoothed_ms: Option<u64>,
    variation_ms: u64,
    current_ms: u64,
}

impl Default for RtoEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RtoEstimator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            smoothed_ms: None,
            variation_ms: 0,
            current_ms: LIMIT_T1_RTO_MS as u64,
        }
    }

    /// Clock granularity `G`: one fixed-T2 slot, rounded up to a millisecond.
    const fn granularity_ms() -> u64 {
        (FIXED_T2_SLOT_INTERVAL_US as u64).div_ceil(1_000)
    }

    fn clamp(value: u64) -> u64 {
        value.clamp(LIMIT_T1_RTO_MIN_MS as u64, LIMIT_T1_RTO_MAX_MS as u64)
    }

    /// Fold in one round-trip sample from a fragment sent exactly once.
    pub fn on_sample(&mut self, sample_ms: u64) {
        match self.smoothed_ms {
            None => {
                self.smoothed_ms = Some(sample_ms);
                self.variation_ms = sample_ms / 2;
            }
            Some(smoothed) => {
                let difference = smoothed.abs_diff(sample_ms);
                self.variation_ms = (3 * self.variation_ms + difference) / 4;
                self.smoothed_ms = Some((7 * smoothed + sample_ms) / 8);
            }
        }
        let smoothed = self.smoothed_ms.unwrap_or(sample_ms);
        let margin = Self::granularity_ms().max(4 * self.variation_ms);
        self.current_ms = Self::clamp(smoothed.saturating_add(margin));
    }

    /// Double the timer on expiry, still bounded by `RTO_max`.
    pub fn on_timeout(&mut self) {
        self.current_ms = Self::clamp(self.current_ms.saturating_mul(2));
    }

    #[must_use]
    pub fn current_ms(&self) -> u64 {
        self.current_ms
    }
}

#[derive(Debug, Clone)]
pub struct Sender {
    pending: HashMap<[u8; 16], Outbound>,
    /// First-send fragments, one queue per live transmission.
    ///
    /// `transport-profile-t1.md` section 12 selects a new fragment by
    /// round-robin across live transmissions, so that one large candidate
    /// cannot occupy every DATA slot ahead of a small control message. A
    /// single flat queue made that FIFO instead, and a COMMIT or READY behind
    /// a 17-fragment message could miss its route deadline.
    new_fragments: HashMap<[u8; 16], VecDeque<u16>>,
    /// Whose turn it is. Front is next; a transmission with fragments left
    /// goes to the back after each turn.
    new_order: VecDeque<[u8; 16]>,
    retry_queue: VecDeque<([u8; 16], u16)>,
    rto: RtoEstimator,
}

impl Sender {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            new_fragments: HashMap::new(),
            new_order: VecDeque::new(),
            retry_queue: VecDeque::new(),
            rto: RtoEstimator::new(),
        }
    }

    pub fn enqueue(
        &mut self,
        suite: [u8; 2],
        transmission_id: [u8; 16],
        message: &[u8],
    ) -> Result<(), TransportError> {
        if !suite_valid(suite)
            || !nonzero(&transmission_id)
            || message.is_empty()
            || message.len() > LIMIT_MAX_LOGICAL_MESSAGE_BYTES
            || self.pending.len() >= LIMIT_MAX_SENDER_TRANSMISSIONS_PER_PEER
            || self.pending.contains_key(&transmission_id)
        {
            return Err(TransportError::ResourceLimit);
        }
        let fragments: Vec<Vec<u8>> = message
            .chunks(BYTES_CELL_PAYLOAD)
            .map(<[u8]>::to_vec)
            .collect();
        if fragments.is_empty() || fragments.len() > LIMIT_MAX_FRAGMENTS {
            return Err(TransportError::ResourceLimit);
        }
        self.new_fragments.insert(
            transmission_id,
            (0..fragments.len() as u16).collect::<VecDeque<u16>>(),
        );
        self.new_order.push_back(transmission_id);
        self.pending.insert(
            transmission_id,
            Outbound {
                suite,
                states: vec![FragmentState::NeverSent; fragments.len()],
                send_count: vec![0; fragments.len()],
                fragments,
                acknowledged: 0,
                recovery_rounds: 0,
            },
        );
        Ok(())
    }

    fn frame_for(&mut self, transmission_id: [u8; 16], index: u16, now_ms: u64) -> Option<Frame> {
        let outbound = self.pending.get_mut(&transmission_id)?;
        let position = usize::from(index);
        if position >= outbound.fragments.len() || outbound.acknowledged & (1_u32 << index) != 0 {
            return None;
        }
        // The timer starts here, on the actual emission, not when the fragment
        // entered a queue it may sit in for several slots.
        outbound.states[position] = FragmentState::InFlight { sent_at_ms: now_ms };
        outbound.send_count[position] = outbound.send_count[position].saturating_add(1);
        Some(Frame::Data {
            suite: outbound.suite,
            transmission_id,
            fragment_index: index,
            fragment_count: outbound.fragments.len() as u16,
            total_length: outbound.fragments.iter().map(Vec::len).sum::<usize>() as u16,
            fragment: outbound.fragments[position].clone(),
        })
    }

    /// True when a retransmission is queued.
    #[must_use]
    pub fn has_retry(&self) -> bool {
        !self.retry_queue.is_empty()
    }

    pub fn next_retry(&mut self, now_ms: u64) -> Option<Frame> {
        while let Some((id, index)) = self.retry_queue.pop_front() {
            if let Some(frame) = self.frame_for(id, index, now_ms) {
                return Some(frame);
            }
        }
        None
    }

    /// One first-send fragment, taking each live transmission in turn.
    pub fn next_new(&mut self, now_ms: u64) -> Option<Frame> {
        // Bounded by the number of live transmissions: every iteration either
        // returns a frame or discards one exhausted or abandoned entry.
        for _ in 0..=self.new_order.len() {
            let id = self.new_order.pop_front()?;
            let Some(queue) = self.new_fragments.get_mut(&id) else {
                continue;
            };
            let Some(index) = queue.pop_front() else {
                self.new_fragments.remove(&id);
                continue;
            };
            let remaining = !queue.is_empty();
            let frame = self.frame_for(id, index, now_ms);
            if remaining {
                // Its turn is spent; the next transmission goes first.
                self.new_order.push_back(id);
            } else {
                self.new_fragments.remove(&id);
            }
            if frame.is_some() {
                return frame;
            }
        }
        None
    }

    /// Apply a cumulative ACK bitmap.
    ///
    /// `now_ms` supplies round-trip samples: a fragment acknowledged for the
    /// first time contributes a sample only if it was never retransmitted,
    /// which is Karn's rule as required by section 10.
    pub fn on_ack(
        &mut self,
        transmission_id: [u8; 16],
        fragment_count: u16,
        bitmap: u32,
        now_ms: u64,
    ) -> Result<bool, TransportError> {
        let Some(outbound) = self.pending.get_mut(&transmission_id) else {
            return Ok(false);
        };
        if usize::from(fragment_count) != outbound.fragments.len() {
            return Err(TransportError::Malformed);
        }
        let mask = (1_u32 << u32::from(fragment_count)) - 1;
        if bitmap & !mask != 0 {
            return Err(TransportError::Malformed);
        }
        let newly = bitmap & !outbound.acknowledged;
        let mut samples = Vec::new();
        for index in 0..outbound.fragments.len() {
            if newly & (1_u32 << index) == 0 {
                continue;
            }
            if outbound.send_count[index] == 1 {
                if let FragmentState::InFlight { sent_at_ms } = outbound.states[index] {
                    samples.push(now_ms.saturating_sub(sent_at_ms));
                }
            }
            outbound.states[index] = FragmentState::Acknowledged;
        }
        outbound.acknowledged |= bitmap;
        let complete = outbound.acknowledged == mask;
        for sample in samples {
            self.rto.on_sample(sample);
        }
        if complete {
            self.pending.remove(&transmission_id);
            return Ok(true);
        }
        Ok(false)
    }

    /// Current retransmission timeout in milliseconds.
    #[must_use]
    pub fn rto_ms(&self) -> u64 {
        self.rto.current_ms()
    }

    /// Open one recovery round for every transmission whose timer has expired.
    ///
    /// A transmission is due only when a fragment is still `InFlight` past the
    /// RTO. Fragments already sitting in the retry queue are not due — their
    /// timer restarts when they are actually emitted — so polling faster than
    /// the schedule can drain cannot consume extra rounds.
    ///
    /// Retry exhaustion is reported per transmission rather than raised as one
    /// link-wide error: one stalled message must not tear down every unrelated
    /// transmission sharing the link.
    pub fn poll_timeouts(&mut self, now_ms: u64) -> TimeoutReport {
        let mut report = TimeoutReport::default();
        let mut expired = false;
        let rto_ms = self.rto.current_ms();
        for (id, outbound) in &mut self.pending {
            let due = outbound.states.iter().enumerate().any(|(index, state)| {
                outbound.acknowledged & (1_u32 << index) == 0
                    && matches!(state, FragmentState::InFlight { sent_at_ms }
                        if now_ms.saturating_sub(*sent_at_ms) >= rto_ms)
            });
            if !due {
                continue;
            }
            if usize::from(outbound.recovery_rounds) >= LIMIT_MAX_T1_RETRIES {
                report.exhausted.push(*id);
                continue;
            }
            outbound.recovery_rounds = outbound.recovery_rounds.saturating_add(1);
            expired = true;
            // Selective recovery retransmits exactly the fragments the peer has
            // not acknowledged. A fragment never sent stays in the new queue,
            // and one already queued for retry is left alone.
            for index in 0..outbound.fragments.len() {
                if outbound.acknowledged & (1_u32 << index) != 0
                    || !matches!(outbound.states[index], FragmentState::InFlight { .. })
                {
                    continue;
                }
                outbound.states[index] = FragmentState::RetryQueued;
                self.retry_queue.push_back((*id, index as u16));
                report.queued += 1;
            }
        }
        if expired {
            // section 10: on timeout the sender doubles the current RTO.
            self.rto.on_timeout();
        }
        report
    }

    /// Abandon one transmission, leaving every other one on the link intact.
    ///
    /// Returns false when the identifier is unknown, so a double abandon is
    /// visible rather than silent.
    pub fn abort(&mut self, transmission_id: [u8; 16]) -> bool {
        if self.pending.remove(&transmission_id).is_none() {
            return false;
        }
        self.new_fragments.remove(&transmission_id);
        self.new_order.retain(|id| *id != transmission_id);
        self.retry_queue.retain(|(id, _)| *id != transmission_id);
        true
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn queue_depth(&self) -> usize {
        let new_cells: usize = self.new_fragments.values().map(VecDeque::len).sum();
        new_cells + self.retry_queue.len()
    }

    pub fn abort_all(&mut self) -> usize {
        let count = self.pending.len();
        self.pending.clear();
        self.new_fragments.clear();
        self.new_order.clear();
        self.retry_queue.clear();
        count
    }
}

impl Default for Sender {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct Inbound {
    suite: [u8; 2],
    fragment_count: u16,
    total_length: u16,
    created_ms: u64,
    fragments: Vec<Option<Vec<u8>>>,
    // Set on first completion. The entry then lingers as a completion cache
    // for LIMIT_COMPLETION_CACHE_MS so that a retransmission whose ACK was
    // lost is re-acknowledged without delivering the message a second time.
    delivered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveResult {
    pub ack: Frame,
    pub complete: Option<([u8; 2], Vec<u8>)>,
}

/// Bounded-reassembly observability counters required by ADR 0020 and the
/// P1 measurement list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiverMetrics {
    pub duplicate_fragments: u64,
    pub capacity_drops: u64,
    pub metadata_failures: u64,
    pub peak_messages: usize,
    pub peak_reserved_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct Receiver {
    inbound: HashMap<[u8; 16], Inbound>,
    reserved_bytes: usize,
    metrics: ReceiverMetrics,
}

impl Receiver {
    pub fn new() -> Self {
        Self {
            inbound: HashMap::new(),
            reserved_bytes: 0,
            metrics: ReceiverMetrics::default(),
        }
    }

    /// Snapshot of the bounded-reassembly counters.
    #[must_use]
    pub fn metrics(&self) -> ReceiverMetrics {
        self.metrics
    }

    pub fn expire(&mut self, now_ms: u64) -> usize {
        let expired: Vec<[u8; 16]> = self
            .inbound
            .iter()
            .filter_map(|(id, value)| {
                let lifetime_ms = if value.delivered {
                    LIMIT_COMPLETION_CACHE_MS
                } else {
                    LIMIT_REASSEMBLY_TIMEOUT_MS
                };
                (now_ms.saturating_sub(value.created_ms) >= lifetime_ms as u64).then_some(*id)
            })
            .collect();
        for id in &expired {
            if let Some(value) = self.inbound.remove(id) {
                self.reserved_bytes = self
                    .reserved_bytes
                    .saturating_sub(usize::from(value.total_length));
            }
        }
        expired.len()
    }

    pub fn accept(
        &mut self,
        frame: Frame,
        now_ms: u64,
    ) -> Result<Option<ReceiveResult>, TransportError> {
        let Frame::Data {
            suite,
            transmission_id,
            fragment_index,
            fragment_count,
            total_length,
            fragment,
        } = frame
        else {
            return Ok(None);
        };
        self.expire(now_ms);
        if !self.inbound.contains_key(&transmission_id) {
            if self.inbound.len() >= LIMIT_MAX_REASSEMBLY_MESSAGES_PER_PEER
                || self.reserved_bytes + usize::from(total_length)
                    > LIMIT_MAX_REASSEMBLY_BYTES_GLOBAL
            {
                self.metrics.capacity_drops = self.metrics.capacity_drops.saturating_add(1);
                return Err(TransportError::ResourceLimit);
            }
            self.reserved_bytes += usize::from(total_length);
            self.inbound.insert(
                transmission_id,
                Inbound {
                    suite,
                    fragment_count,
                    total_length,
                    created_ms: now_ms,
                    fragments: vec![None; usize::from(fragment_count)],
                    delivered: false,
                },
            );
        }

        let metadata_mismatch = self.inbound.get(&transmission_id).is_none_or(|entry| {
            entry.suite != suite
                || entry.fragment_count != fragment_count
                || entry.total_length != total_length
        });
        if metadata_mismatch {
            self.metrics.metadata_failures = self.metrics.metadata_failures.saturating_add(1);
            self.remove_inbound(transmission_id);
            return Err(TransportError::Malformed);
        }

        let position = usize::from(fragment_index);
        let conflicting_fragment = self
            .inbound
            .get(&transmission_id)
            .and_then(|entry| entry.fragments.get(position))
            .is_none_or(|slot| slot.as_ref().is_some_and(|existing| existing != &fragment));
        if conflicting_fragment {
            self.metrics.metadata_failures = self.metrics.metadata_failures.saturating_add(1);
            self.remove_inbound(transmission_id);
            return Err(TransportError::Malformed);
        }
        let mut duplicate = false;
        let (bitmap, deliver_now) = {
            let entry = self
                .inbound
                .get_mut(&transmission_id)
                .ok_or(TransportError::Malformed)?;
            if entry.fragments[position].is_none() {
                entry.fragments[position] = Some(fragment);
            } else {
                duplicate = true;
            }
            let mut bitmap = 0_u32;
            for (index, value) in entry.fragments.iter().enumerate() {
                if value.is_some() {
                    bitmap |= 1_u32 << index;
                }
            }
            // Deliver exactly once. The entry stays behind as a completion
            // cache so later duplicates are re-acknowledged above without a
            // second delivery; expire() reclaims it after
            // LIMIT_COMPLETION_CACHE_MS counted from delivery.
            let deliver_now = entry.fragments.iter().all(Option::is_some) && !entry.delivered;
            if deliver_now {
                entry.delivered = true;
                entry.created_ms = now_ms;
            }
            (bitmap, deliver_now)
        };

        if duplicate {
            self.metrics.duplicate_fragments = self.metrics.duplicate_fragments.saturating_add(1);
        }
        self.metrics.peak_messages = self.metrics.peak_messages.max(self.inbound.len());
        self.metrics.peak_reserved_bytes =
            self.metrics.peak_reserved_bytes.max(self.reserved_bytes);

        let ack = Frame::Ack {
            suite,
            transmission_id,
            fragment_count,
            ack_delay_ms: 0,
            bitmap,
        };
        let complete = if deliver_now {
            let entry = self
                .inbound
                .get(&transmission_id)
                .ok_or(TransportError::Malformed)?;
            let mut message = Vec::with_capacity(usize::from(entry.total_length));
            for fragment in &entry.fragments {
                message.extend_from_slice(fragment.as_deref().ok_or(TransportError::Malformed)?);
            }
            if message.len() != usize::from(entry.total_length) {
                return Err(TransportError::Malformed);
            }
            Some((suite, message))
        } else {
            None
        };
        Ok(Some(ReceiveResult { ack, complete }))
    }

    fn remove_inbound(&mut self, transmission_id: [u8; 16]) {
        if let Some(removed) = self.inbound.remove(&transmission_id) {
            self.reserved_bytes = self
                .reserved_bytes
                .saturating_sub(usize::from(removed.total_length));
        }
    }

    pub fn live_messages(&self) -> usize {
        self.inbound.len()
    }

    pub fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}

pub fn fresh_chaff(suite: [u8; 2]) -> Result<Frame, TransportError> {
    for _ in 0..32 {
        let transmission_id = random_bytes::<16>()?;
        if nonzero(&transmission_id) {
            return Ok(Frame::Chaff {
                suite,
                transmission_id,
            });
        }
    }
    Err(TransportError::Randomness)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_fragment_selective_recovery() -> Result<(), TransportError> {
        let mut sender = Sender::new();
        let id = [9_u8; 16];
        let message = vec![7_u8; 2_200];
        sender.enqueue(SUITE_R1, id, &message)?;
        let mut frames = Vec::new();
        while let Some(frame) = sender.next_new(0) {
            frames.push(frame);
        }
        assert_eq!(frames.len(), 3);
        let mut receiver = Receiver::new();
        let first = receiver
            .accept(frames[0].clone(), 0)?
            .ok_or(TransportError::Malformed)?;
        let third = receiver
            .accept(frames[2].clone(), 0)?
            .ok_or(TransportError::Malformed)?;
        let Frame::Ack {
            fragment_count,
            bitmap,
            ..
        } = third.ack
        else {
            return Err(TransportError::Malformed);
        };
        sender.on_ack(id, fragment_count, bitmap, LIMIT_T1_RTO_MS as u64)?;
        let deadline = sender.rto_ms();
        assert_eq!(sender.poll_timeouts(deadline).queued, 1);
        let retry = sender
            .next_retry(deadline)
            .ok_or(TransportError::Malformed)?;
        let completed = receiver
            .accept(retry, deadline)?
            .ok_or(TransportError::Malformed)?;
        assert_eq!(completed.complete, Some((SUITE_R1, message)));
        let Frame::Ack {
            fragment_count,
            bitmap,
            ..
        } = completed.ack
        else {
            return Err(TransportError::Malformed);
        };
        assert!(sender.on_ack(id, fragment_count, bitmap, LIMIT_T1_RTO_MS as u64)?);
        assert_eq!(sender.pending_count(), 0);
        let _ = first;
        Ok(())
    }

    #[test]
    fn lost_ack_retransmission_is_reacked_but_not_redelivered() -> Result<(), TransportError> {
        // transport-profile-t1.md:99 — a duplicate DATA fragment MUST NOT
        // allocate a second fragment and SHOULD be acknowledged again. When
        // the duplicate arrives after completion (the ACK was lost), the
        // message must not be delivered a second time: an upstream duplicate
        // COMMIT is an invalid E1 transition and killed relays in the
        // netns-p1 harness under 5 percent loss.
        let mut sender = Sender::new();
        let id = [8_u8; 16];
        let message = b"commit-equivalent".to_vec();
        sender.enqueue(SUITE_R1, id, &message)?;
        let frame = sender.next_new(0).ok_or(TransportError::Malformed)?;

        let mut receiver = Receiver::new();
        let first = receiver
            .accept(frame, 0)?
            .ok_or(TransportError::Malformed)?;
        assert_eq!(first.complete, Some((SUITE_R1, message)));

        // The ACK never reaches the sender; it retransmits after one RTO.
        sender.poll_timeouts(LIMIT_T1_RTO_MS as u64);
        let retry = sender
            .next_retry(LIMIT_T1_RTO_MS as u64)
            .ok_or(TransportError::Malformed)?;
        let duplicate = receiver
            .accept(retry, LIMIT_T1_RTO_MS as u64)?
            .ok_or(TransportError::Malformed)?;
        assert_eq!(duplicate.complete, None, "duplicate must not redeliver");
        let Frame::Ack {
            fragment_count,
            bitmap,
            ..
        } = duplicate.ack
        else {
            return Err(TransportError::Malformed);
        };
        assert!(
            sender.on_ack(id, fragment_count, bitmap, LIMIT_T1_RTO_MS as u64)?,
            "duplicate must still produce a full cumulative ACK"
        );

        // The completion cache holds the transmission id for
        // LIMIT_COMPLETION_CACHE_MS and reclaims it afterwards.
        let now = (LIMIT_T1_RTO_MS + LIMIT_COMPLETION_CACHE_MS) as u64;
        assert_eq!(receiver.expire(now), 1);
        Ok(())
    }

    #[test]
    fn rapid_polling_within_one_rto_consumes_at_most_one_recovery_round(
    ) -> Result<(), TransportError> {
        // The link worker polls timeouts roughly every millisecond while the
        // fixed T2 schedule grants an emission slot only every 12.5 ms. A
        // recovery round is one RTO period, not one poll: before this held,
        // a single lost cell could burn the whole retry budget between two
        // slots and kill the process with zero retransmissions on the wire.
        let mut sender = Sender::new();
        let id = [6_u8; 16];
        sender.enqueue(SUITE_R1, id, b"lost-once")?;
        let _initial = sender.next_new(0).ok_or(TransportError::Malformed)?;

        // The cell is lost; the RTO expires; the worker then polls every
        // millisecond for far more ticks than the retry budget holds rounds.
        let rto = LIMIT_T1_RTO_MS as u64;
        for tick in 0..(3 * LIMIT_MAX_T1_RETRIES as u64) {
            let report = sender.poll_timeouts(rto + tick);
            assert!(
                report.exhausted.is_empty(),
                "a queued retry is not overdue, so no round is charged for it"
            );
        }

        // One retry was queued and, once emitted and acknowledged, the
        // transmission completes normally.
        let retry = sender.next_retry(rto).ok_or(TransportError::Malformed)?;
        let Frame::Data { fragment_count, .. } = retry else {
            return Err(TransportError::Malformed);
        };
        assert!(sender.next_retry(rto).is_none(), "exactly one retry queued");
        assert!(sender.on_ack(id, fragment_count, 0b1, rto)?);
        assert_eq!(sender.pending_count(), 0);
        Ok(())
    }

    #[test]
    fn burst_loss_retry_exhaustion_is_bounded_and_reclaimable() -> Result<(), TransportError> {
        let mut sender = Sender::new();
        let id = [4_u8; 16];
        sender.enqueue(SUITE_R1, id, b"burst-loss")?;
        let _initial = sender.next_new(0).ok_or(TransportError::Malformed)?;
        // The timer doubles each round, so step by the live RTO rather than a
        // fixed interval.
        let mut now = 0_u64;
        for _ in 1..=LIMIT_MAX_T1_RETRIES {
            now += sender.rto_ms();
            sender.poll_timeouts(now);
            let _retry = sender.next_retry(now).ok_or(TransportError::Malformed)?;
        }
        now += sender.rto_ms();
        assert_eq!(sender.poll_timeouts(now).exhausted, vec![id]);
        assert!(sender.abort(id));
        assert!(!sender.abort(id), "a second abandon is visible");
        assert_eq!(sender.pending_count(), 0);
        assert_eq!(sender.queue_depth(), 0);
        Ok(())
    }

    #[test]
    fn a_small_control_message_is_not_stuck_behind_a_large_one() -> Result<(), TransportError> {
        // Section 12: new fragments are chosen by round-robin across live
        // transmissions. With one flat queue a COMMIT enqueued behind a
        // full-size candidate waited out all 17 of its fragments, long enough
        // on a fixed 12.5 ms slot to threaten the route deadline.
        let large = [1_u8; 16];
        let control = [2_u8; 16];
        let mut sender = Sender::new();
        // The largest logical message is 17 fragments, the fragment ceiling.
        let widest = vec![9_u8; LIMIT_MAX_LOGICAL_MESSAGE_BYTES];
        assert_eq!(
            widest.len().div_ceil(BYTES_CELL_PAYLOAD),
            LIMIT_MAX_FRAGMENTS
        );
        sender.enqueue(SUITE_R1, large, &widest)?;
        sender.enqueue(SUITE_R1, control, b"commit")?;

        let mut emitted = Vec::new();
        while let Some(Frame::Data {
            transmission_id, ..
        }) = sender.next_new(0)
        {
            emitted.push(transmission_id);
        }
        assert_eq!(emitted.len(), LIMIT_MAX_FRAGMENTS + 1);
        let position = emitted
            .iter()
            .position(|id| *id == control)
            .ok_or(TransportError::Malformed)?;
        assert_eq!(position, 1, "the control message takes the second slot");

        // The large message still gets every one of its fragments.
        assert_eq!(
            emitted.iter().filter(|id| **id == large).count(),
            LIMIT_MAX_FRAGMENTS
        );
        assert_eq!(sender.queue_depth(), 0);
        Ok(())
    }

    #[test]
    fn a_saturated_queue_charges_one_round_per_retransmission() -> Result<(), TransportError> {
        // The link is full: every sender slot holds a multi-fragment message
        // and the schedule releases far fewer cells per poll than are queued.
        // A recovery round must correspond to a fragment that actually went
        // back on the wire, otherwise a congested link exhausts the budget
        // without retransmitting anything.
        let mut sender = Sender::new();
        let message = vec![3_u8; BYTES_CELL_PAYLOAD * 3];
        let mut ids = Vec::new();
        for index in 0..LIMIT_MAX_SENDER_TRANSMISSIONS_PER_PEER {
            let mut id = [0_u8; 16];
            id[0] = (index % 251) as u8;
            id[1] = (index / 251) as u8 + 1;
            sender.enqueue(SUITE_R1, id, &message)?;
            ids.push(id);
        }

        // Emit every first send, then let all of them time out.
        let mut emitted = 0;
        while sender.next_new(0).is_some() {
            emitted += 1;
        }
        assert_eq!(emitted, ids.len() * 3, "three fragments per transmission");

        let rto = sender.rto_ms();
        let first = sender.poll_timeouts(rto);
        assert!(first.exhausted.is_empty());
        assert_eq!(first.queued, emitted, "every unacknowledged fragment");

        // Polling again before the schedule has drained anything charges no
        // further rounds: the queued fragments are not in flight.
        for tick in 1..(4 * LIMIT_MAX_T1_RETRIES as u64) {
            let report = sender.poll_timeouts(rto + tick * rto);
            assert!(report.is_quiet(), "no round without a retransmission");
        }
        assert_eq!(sender.queue_depth(), emitted);
        Ok(())
    }

    #[test]
    fn one_exhausted_transmission_does_not_abandon_the_others() -> Result<(), TransportError> {
        // Before this held, retry exhaustion called abort_all and killed every
        // unrelated transmission sharing the link.
        let stalled = [1_u8; 16];
        let healthy = [2_u8; 16];
        let mut sender = Sender::new();
        sender.enqueue(SUITE_R1, stalled, b"never-acknowledged")?;
        sender.enqueue(SUITE_R1, healthy, b"making-progress")?;
        let _ = sender.next_new(0).ok_or(TransportError::Malformed)?;
        let _ = sender.next_new(0).ok_or(TransportError::Malformed)?;

        // Only the stalled transmission keeps timing out; the healthy one is
        // acknowledged on its first send and leaves the table cleanly.
        assert!(sender.on_ack(healthy, 1, 0b1, 1)?);

        let mut now = 0_u64;
        for _ in 0..LIMIT_MAX_T1_RETRIES {
            now += sender.rto_ms();
            sender.poll_timeouts(now);
            let _ = sender.next_retry(now).ok_or(TransportError::Malformed)?;
        }
        now += sender.rto_ms();
        let report = sender.poll_timeouts(now);
        assert_eq!(report.exhausted, vec![stalled]);

        // A third transmission enqueued after the failure is unaffected.
        let fresh = [3_u8; 16];
        sender.abort(stalled);
        sender.enqueue(SUITE_R1, fresh, b"unaffected")?;
        assert_eq!(sender.pending_count(), 1);
        assert!(sender.next_new(now).is_some());
        Ok(())
    }

    // The published T1 vectors pin the 32-byte frame header, which is fully
    // determined by the protocol. They also record body and record digests,
    // but those cover the random privacy padding, which the Python generator
    // draws from a seeded Mersenne Twister; reproducing that stream in Rust
    // would test Python's PRNG rather than any protocol property, so the
    // digests are deliberately not asserted here.
    fn header_of(frame: &Frame) -> Result<[u8; 32], TransportError> {
        let encoded = encode_frame(frame)?;
        <[u8; 32]>::try_from(&encoded[..32]).map_err(|_| TransportError::Malformed)
    }

    #[test]
    fn rto_estimator_follows_the_specified_recurrence() {
        let mut rto = RtoEstimator::new();
        assert_eq!(rto.current_ms(), LIMIT_T1_RTO_MS as u64, "initial RTO");

        // First sample: SRTT = R, RTTVAR = R/2, so RTO = R + 4*(R/2) = 3R,
        // clamped into [RTO_min, RTO_max].
        rto.on_sample(40);
        assert_eq!(rto.current_ms(), 120);

        // Later samples follow the 7/8 and 3/4 recurrences.
        // RTTVAR = (3*20 + |40-40|)/4 = 15; SRTT = (7*40 + 40)/8 = 40.
        rto.on_sample(40);
        assert_eq!(rto.current_ms(), 40 + 4 * 15);

        // Timeout doubles the current value.
        let before = rto.current_ms();
        rto.on_timeout();
        assert_eq!(rto.current_ms(), before * 2);

        // Both bounds are enforced.
        let mut low = RtoEstimator::new();
        low.on_sample(0);
        assert_eq!(
            low.current_ms(),
            LIMIT_T1_RTO_MIN_MS as u64,
            "clamped to min"
        );
        let mut high = RtoEstimator::new();
        for _ in 0..20 {
            high.on_timeout();
        }
        assert_eq!(
            high.current_ms(),
            LIMIT_T1_RTO_MAX_MS as u64,
            "clamped to max"
        );
    }

    #[test]
    fn retransmitted_fragments_do_not_contribute_rtt_samples() -> Result<(), TransportError> {
        // Karn's rule: a fragment that was retransmitted has an ambiguous
        // round trip, so acknowledging it must leave the estimator untouched.
        let mut sender = Sender::new();
        let id = [5_u8; 16];
        sender.enqueue(SUITE_R1, id, b"karn")?;
        let _first = sender.next_new(0).ok_or(TransportError::Malformed)?;
        let baseline = sender.rto_ms();

        sender.poll_timeouts(baseline);
        let _retry = sender
            .next_retry(baseline)
            .ok_or(TransportError::Malformed)?;
        let after_timeout = sender.rto_ms();
        assert_eq!(after_timeout, baseline * 2, "timeout doubled the timer");

        // Acknowledging the twice-sent fragment must not fold in a sample.
        assert!(sender.on_ack(id, 1, 0b1, baseline + 5)?);
        assert_eq!(sender.rto_ms(), after_timeout, "no sample from a retry");
        Ok(())
    }

    #[test]
    fn published_t1_vectors_pin_the_frame_headers() -> Result<(), TransportError> {
        let vectors = test_vectors::t1().map_err(|_| TransportError::Malformed)?;
        let suite = test_vectors::hex_array_at::<2>(&vectors, "crypto_suite")
            .map_err(|_| TransportError::Malformed)?;
        assert_eq!(suite, SUITE_R1);
        assert_eq!(
            test_vectors::u64_at(&vectors, "record_bytes")
                .map_err(|_| TransportError::Malformed)?,
            BYTES_CELL_RECORD as u64
        );

        let transmission_id =
            test_vectors::hex_array_at::<16>(&vectors, "data_first_emission/transmission_id")
                .map_err(|_| TransportError::Malformed)?;
        let fragment_count = test_vectors::u64_at(&vectors, "logical_message/fragment_count")
            .map_err(|_| TransportError::Malformed)?;
        let lengths = test_vectors::u64_list_at(&vectors, "logical_message/fragment_lengths")
            .map_err(|_| TransportError::Malformed)?;
        let total = test_vectors::u64_at(&vectors, "logical_message/length")
            .map_err(|_| TransportError::Malformed)?;
        assert_eq!(lengths.len(), fragment_count as usize);
        assert_eq!(lengths.iter().sum::<u64>(), total);
        assert_eq!(lengths[0] as usize, BYTES_CELL_PAYLOAD);

        // The vector encodes the generator's frames[-1]: the final fragment.
        let last = fragment_count as usize - 1;
        let data = Frame::Data {
            suite,
            transmission_id,
            fragment_index: last as u16,
            fragment_count: fragment_count as u16,
            total_length: total as u16,
            fragment: vec![0_u8; lengths[last] as usize],
        };
        let expected = test_vectors::hex_array_at::<32>(
            &vectors,
            "data_first_emission/encrypted_header_plaintext",
        )
        .map_err(|_| TransportError::Malformed)?;
        assert_eq!(header_of(&data)?, expected, "DATA header");

        // Selective ACK over both fragments.
        let bitmap = test_vectors::u64_at(&vectors, "selective_ack/bitmap")
            .map_err(|_| TransportError::Malformed)?;
        let acknowledged =
            test_vectors::u64_list_at(&vectors, "selective_ack/acknowledged_indexes")
                .map_err(|_| TransportError::Malformed)?;
        let rebuilt = acknowledged
            .iter()
            .fold(0_u32, |mask, index| mask | (1 << index));
        assert_eq!(u64::from(rebuilt), bitmap, "bitmap matches indexes");
        let ack = Frame::Ack {
            suite,
            transmission_id,
            fragment_count: fragment_count as u16,
            ack_delay_ms: test_vectors::u64_at(&vectors, "selective_ack/ack_delay_ms")
                .map_err(|_| TransportError::Malformed)? as u16,
            bitmap: rebuilt,
        };
        let expected =
            test_vectors::hex_array_at::<32>(&vectors, "selective_ack/encrypted_header_plaintext")
                .map_err(|_| TransportError::Malformed)?;
        assert_eq!(header_of(&ack)?, expected, "ACK header");

        // Chaff carries its own transmission identifier and no metadata.
        let chaff_id = test_vectors::hex_array_at::<16>(&vectors, "chaff/transmission_id")
            .map_err(|_| TransportError::Malformed)?;
        let chaff = Frame::Chaff {
            suite,
            transmission_id: chaff_id,
        };
        let expected =
            test_vectors::hex_array_at::<32>(&vectors, "chaff/encrypted_header_plaintext")
                .map_err(|_| TransportError::Malformed)?;
        assert_eq!(header_of(&chaff)?, expected, "CHAFF header");
        Ok(())
    }

    #[test]
    fn frame_has_fixed_size_and_randomized_padding() -> Result<(), TransportError> {
        let frame = Frame::Data {
            suite: SUITE_R1,
            transmission_id: [1; 16],
            fragment_index: 0,
            fragment_count: 1,
            total_length: 3,
            fragment: b"abc".to_vec(),
        };
        let first = encode_frame(&frame)?;
        let second = encode_frame(&frame)?;
        assert_eq!(first.len(), BYTES_CELL_BODY);
        assert_eq!(decode_frame(&first)?, frame);
        assert_ne!(first[35..], second[35..]);
        Ok(())
    }
}
