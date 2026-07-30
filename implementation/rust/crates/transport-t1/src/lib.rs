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

#[derive(Debug, Clone)]
struct Outbound {
    suite: [u8; 2],
    fragments: Vec<Vec<u8>>,
    acknowledged: u32,
    sent_at_ms: Vec<Option<u64>>,
    send_count: Vec<u8>,
    recovery_rounds: u8,
}

#[derive(Debug, Clone)]
pub struct Sender {
    pending: HashMap<[u8; 16], Outbound>,
    new_queue: VecDeque<([u8; 16], u16)>,
    retry_queue: VecDeque<([u8; 16], u16)>,
}

impl Sender {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            new_queue: VecDeque::new(),
            retry_queue: VecDeque::new(),
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
        for index in 0..fragments.len() {
            self.new_queue.push_back((transmission_id, index as u16));
        }
        self.pending.insert(
            transmission_id,
            Outbound {
                suite,
                sent_at_ms: vec![None; fragments.len()],
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
        outbound.sent_at_ms[position] = Some(now_ms);
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

    pub fn next_retry(&mut self, now_ms: u64) -> Option<Frame> {
        while let Some((id, index)) = self.retry_queue.pop_front() {
            if let Some(frame) = self.frame_for(id, index, now_ms) {
                return Some(frame);
            }
        }
        None
    }

    pub fn next_new(&mut self, now_ms: u64) -> Option<Frame> {
        while let Some((id, index)) = self.new_queue.pop_front() {
            if let Some(frame) = self.frame_for(id, index, now_ms) {
                return Some(frame);
            }
        }
        None
    }

    pub fn on_ack(
        &mut self,
        transmission_id: [u8; 16],
        fragment_count: u16,
        bitmap: u32,
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
        outbound.acknowledged |= bitmap;
        if outbound.acknowledged == mask {
            self.pending.remove(&transmission_id);
            return Ok(true);
        }
        Ok(false)
    }

    pub fn poll_timeouts(&mut self, now_ms: u64) -> Result<usize, TransportError> {
        let mut queued = 0;
        for (id, outbound) in &mut self.pending {
            let due = outbound.sent_at_ms.iter().enumerate().any(|(index, sent)| {
                outbound.acknowledged & (1_u32 << index) == 0
                    && sent
                        .is_some_and(|time| now_ms.saturating_sub(time) >= LIMIT_T1_RTO_MS as u64)
            });
            if !due {
                continue;
            }
            if usize::from(outbound.recovery_rounds) >= LIMIT_MAX_T1_RETRIES {
                return Err(TransportError::RetryExhausted);
            }
            outbound.recovery_rounds = outbound.recovery_rounds.saturating_add(1);
            for index in 0..outbound.fragments.len() {
                if outbound.acknowledged & (1_u32 << index) == 0 {
                    self.retry_queue.push_back((*id, index as u16));
                    queued += 1;
                }
            }
        }
        Ok(queued)
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn queue_depth(&self) -> usize {
        self.new_queue.len() + self.retry_queue.len()
    }

    pub fn abort_all(&mut self) -> usize {
        let count = self.pending.len();
        self.pending.clear();
        self.new_queue.clear();
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveResult {
    pub ack: Frame,
    pub complete: Option<([u8; 2], Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct Receiver {
    inbound: HashMap<[u8; 16], Inbound>,
    reserved_bytes: usize,
}

impl Receiver {
    pub fn new() -> Self {
        Self {
            inbound: HashMap::new(),
            reserved_bytes: 0,
        }
    }

    pub fn expire(&mut self, now_ms: u64) -> usize {
        let expired: Vec<[u8; 16]> = self
            .inbound
            .iter()
            .filter_map(|(id, value)| {
                (now_ms.saturating_sub(value.created_ms) >= LIMIT_REASSEMBLY_TIMEOUT_MS as u64)
                    .then_some(*id)
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
                },
            );
        }

        let metadata_mismatch = self.inbound.get(&transmission_id).is_none_or(|entry| {
            entry.suite != suite
                || entry.fragment_count != fragment_count
                || entry.total_length != total_length
        });
        if metadata_mismatch {
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
            self.remove_inbound(transmission_id);
            return Err(TransportError::Malformed);
        }
        let (bitmap, complete_now) = {
            let entry = self
                .inbound
                .get_mut(&transmission_id)
                .ok_or(TransportError::Malformed)?;
            if entry.fragments[position].is_none() {
                entry.fragments[position] = Some(fragment);
            }
            let mut bitmap = 0_u32;
            for (index, value) in entry.fragments.iter().enumerate() {
                if value.is_some() {
                    bitmap |= 1_u32 << index;
                }
            }
            (bitmap, entry.fragments.iter().all(Option::is_some))
        };

        let ack = Frame::Ack {
            suite,
            transmission_id,
            fragment_count,
            ack_delay_ms: 0,
            bitmap,
        };
        let complete = if complete_now {
            let removed = self
                .inbound
                .remove(&transmission_id)
                .ok_or(TransportError::Malformed)?;
            self.reserved_bytes = self
                .reserved_bytes
                .saturating_sub(usize::from(removed.total_length));
            let mut message = Vec::with_capacity(usize::from(removed.total_length));
            for fragment in removed.fragments {
                message.extend_from_slice(fragment.as_deref().ok_or(TransportError::Malformed)?);
            }
            if message.len() != usize::from(removed.total_length) {
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
        sender.on_ack(id, fragment_count, bitmap)?;
        sender.poll_timeouts(LIMIT_T1_RTO_MS as u64)?;
        let retry = sender
            .next_retry(LIMIT_T1_RTO_MS as u64)
            .ok_or(TransportError::Malformed)?;
        let completed = receiver
            .accept(retry, LIMIT_T1_RTO_MS as u64)?
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
        assert!(sender.on_ack(id, fragment_count, bitmap)?);
        assert_eq!(sender.pending_count(), 0);
        let _ = first;
        Ok(())
    }

    #[test]
    fn burst_loss_retry_exhaustion_is_bounded_and_reclaimable() -> Result<(), TransportError> {
        let mut sender = Sender::new();
        let id = [4_u8; 16];
        sender.enqueue(SUITE_R1, id, b"burst-loss")?;
        let _initial = sender.next_new(0).ok_or(TransportError::Malformed)?;
        for round in 1..=LIMIT_MAX_T1_RETRIES {
            let now = (round * LIMIT_T1_RTO_MS) as u64;
            sender.poll_timeouts(now)?;
            let _retry = sender.next_retry(now).ok_or(TransportError::Malformed)?;
        }
        let exhausted_at = ((LIMIT_MAX_T1_RETRIES + 1) * LIMIT_T1_RTO_MS) as u64;
        assert_eq!(
            sender.poll_timeouts(exhausted_at),
            Err(TransportError::RetryExhausted)
        );
        assert_eq!(sender.abort_all(), 1);
        assert_eq!(sender.pending_count(), 0);
        assert_eq!(sender.queue_depth(), 0);
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
