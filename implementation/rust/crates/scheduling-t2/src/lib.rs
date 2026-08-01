// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "Frozen fixed-rate T2 P1 scheduler."]

use protocol_registry::{
    suite_is_network_valid, FIXED_T2_CELLS_PER_EPOCH, FIXED_T2_EPOCH_MS, FIXED_T2_PROFILE_ID,
    FIXED_T2_QUEUE_CELLS_GLOBAL, FIXED_T2_SLOT_INTERVAL_US, LIFECYCLE_PROFILE_E1,
    PRIVACY_PROFILE_U1, SCHEDULE_PROFILE_T2, T2_ACTION_ACCEPT, T2_ACTION_OFFER, T2_ACTION_REJECT,
    T2_FRAME_SCHEDULE, VERSION,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotClass {
    Ack,
    Retransmission,
    NewData,
    Chaff,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScheduleMetrics {
    pub slots: u64,
    pub ack_cells: u64,
    pub retransmission_cells: u64,
    pub new_data_cells: u64,
    pub chaff_cells: u64,
    /// Slots released a whole interval or more after their deadline.
    pub late_slots: u64,
    /// Slot positions that passed with nothing emitted on them.
    pub missed_slots: u64,
    /// Worst single overrun observed, in milliseconds.
    pub worst_lateness_ms: u64,
    /// Times the negotiated rate class changed on this link.
    pub rate_class_changes: u64,
    /// Worst overrun *within* one slot interval, in microseconds.
    ///
    /// Reported separately because it is the part `fixed_trace_valid` does not
    /// judge: an emission 3ms after its instant still occupies its own slot,
    /// so the trace keeps its declared shape, but it is not a claim that every
    /// cell left at its exact scheduled microsecond.
    pub worst_jitter_us: u64,
}

#[derive(Debug, Clone)]
pub struct FixedSchedule {
    next: Instant,
    interval: Duration,
    rate_class: u8,
    metrics: ScheduleMetrics,
}

impl FixedSchedule {
    pub fn new(origin: Instant) -> Self {
        debug_assert_eq!(FIXED_T2_PROFILE_ID, 1);
        debug_assert_eq!(
            FIXED_T2_SLOT_INTERVAL_US * FIXED_T2_CELLS_PER_EPOCH,
            FIXED_T2_EPOCH_MS * 1000
        );
        Self {
            next: origin,
            interval: Duration::from_micros(FIXED_T2_SLOT_INTERVAL_US as u64),
            rate_class: default_rate_class(),
            metrics: ScheduleMetrics::default(),
        }
    }

    /// Rate class currently in force.
    #[must_use]
    pub fn rate_class(&self) -> u8 {
        self.rate_class
    }

    /// Adopt a negotiated rate class from the menu.
    ///
    /// The epoch stays `FIXED_T2_EPOCH_MS`; only the number of slots in it
    /// changes, so the link keeps emitting on a constant cadence and only the
    /// cadence itself moves. Refuses a class outside the menu, and counts the
    /// change so a run says how often its rate moved.
    pub fn set_rate_class(&mut self, class: u8) -> Result<(), ScheduleError> {
        let cells = *RATE_MENU_CELLS_PER_EPOCH
            .get(usize::from(class))
            .ok_or(ScheduleError::Malformed)?;
        if cells == 0 {
            return Err(ScheduleError::Malformed);
        }
        if class == self.rate_class {
            return Ok(());
        }
        self.rate_class = class;
        self.interval = Duration::from_micros((FIXED_T2_EPOCH_MS as u64 * 1_000) / cells as u64);
        self.metrics.rate_class_changes = self.metrics.rate_class_changes.saturating_add(1);
        Ok(())
    }

    /// Cells this link may emit in one epoch at its current class.
    #[must_use]
    pub fn cells_per_epoch(&self) -> usize {
        RATE_MENU_CELLS_PER_EPOCH
            .get(usize::from(self.rate_class))
            .copied()
            .unwrap_or(FIXED_T2_CELLS_PER_EPOCH)
    }

    pub fn next_deadline(&self) -> Instant {
        self.next
    }

    /// Record one emission and step to the next slot.
    ///
    /// `now` is when the cell actually went out. Advancing blindly from the
    /// old deadline means that after a thread stall the runtime emits as fast
    /// as it can until it catches up, producing a burst rather than records at
    /// the declared slot positions. That silently breaks the fixed-trace claim
    /// the P1 profile rests on, so the overrun is measured and the schedule
    /// resynchronised instead of absorbed.
    pub fn advance_at(&mut self, class: SlotClass, now: Instant) {
        let lateness = now.saturating_duration_since(self.next);
        if lateness < self.interval {
            // Inside the tolerance: the cell still occupies its own slot, so
            // the trace shape holds. Record how close it came anyway.
            let jitter_us = lateness.as_micros().try_into().unwrap_or(u64::MAX);
            self.metrics.worst_jitter_us = self.metrics.worst_jitter_us.max(jitter_us);
        }
        if lateness >= self.interval {
            let missed = (lateness.as_micros() / self.interval.as_micros().max(1)) as u64;
            self.metrics.late_slots = self.metrics.late_slots.saturating_add(1);
            self.metrics.missed_slots = self.metrics.missed_slots.saturating_add(missed);
            let lateness_ms = lateness.as_millis().try_into().unwrap_or(u64::MAX);
            self.metrics.worst_lateness_ms = self.metrics.worst_lateness_ms.max(lateness_ms);
            // Resynchronise onto the current slot boundary rather than firing
            // the whole backlog back to back.
            self.next = now;
        }
        self.advance(class);
    }

    /// True while every slot position was occupied by exactly one emission.
    ///
    /// This is a claim about slot occupancy, with one slot interval as the
    /// stated tolerance: it says no slot position passed empty and none was
    /// filled late enough to displace its successor. It is deliberately not a
    /// claim that every cell left at its exact scheduled instant — sub-slot
    /// lateness is real and is reported separately as
    /// [`ScheduleMetrics::worst_jitter_us`], so a reader can judge the timing
    /// against a tighter tolerance if a later profile needs one.
    #[must_use]
    pub fn fixed_trace_valid(&self) -> bool {
        self.metrics.missed_slots == 0
    }

    /// One slot interval: the tolerance [`Self::fixed_trace_valid`] applies.
    #[must_use]
    pub fn trace_tolerance(&self) -> Duration {
        self.interval
    }

    pub fn advance(&mut self, class: SlotClass) {
        self.metrics.slots = self.metrics.slots.saturating_add(1);
        match class {
            SlotClass::Ack => self.metrics.ack_cells = self.metrics.ack_cells.saturating_add(1),
            SlotClass::Retransmission => {
                self.metrics.retransmission_cells =
                    self.metrics.retransmission_cells.saturating_add(1);
            }
            SlotClass::NewData => {
                self.metrics.new_data_cells = self.metrics.new_data_cells.saturating_add(1);
            }
            SlotClass::Chaff => {
                self.metrics.chaff_cells = self.metrics.chaff_cells.saturating_add(1);
            }
        }
        self.next += self.interval;
    }

    pub fn metrics(&self) -> ScheduleMetrics {
        self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stalled_worker_reports_its_overrun_instead_of_bursting() {
        let origin = Instant::now();
        let mut schedule = FixedSchedule::new(origin);
        let interval = Duration::from_micros(FIXED_T2_SLOT_INTERVAL_US as u64);

        // On-time slots leave the trace claim intact.
        schedule.advance_at(SlotClass::NewData, origin);
        assert!(schedule.fixed_trace_valid());
        assert_eq!(schedule.metrics().late_slots, 0);
        assert_eq!(schedule.metrics().worst_jitter_us, 0);
        assert_eq!(schedule.trace_tolerance(), interval);

        // Lateness inside one interval keeps the slot, so the claim holds, but
        // it is recorded rather than treated as free.
        let jittered = schedule.next_deadline() + interval / 4;
        schedule.advance_at(SlotClass::NewData, jittered);
        assert!(schedule.fixed_trace_valid(), "the slot is still its own");
        assert_eq!(schedule.metrics().late_slots, 0);
        assert_eq!(
            schedule.metrics().worst_jitter_us,
            (interval / 4).as_micros() as u64,
            "sub-slot lateness is reported, not hidden"
        );

        // A stall past several slot positions is recorded, not absorbed. The
        // next deadline resynchronises to now, so the runtime does not fire
        // the whole backlog back to back to catch up.
        let stalled = schedule.next_deadline() + interval * 4;
        schedule.advance_at(SlotClass::NewData, stalled);
        assert_eq!(schedule.metrics().late_slots, 1);
        assert_eq!(schedule.metrics().missed_slots, 4);
        assert!(!schedule.fixed_trace_valid(), "the claim is invalidated");
        assert_eq!(schedule.next_deadline(), stalled + interval);
    }

    #[test]
    fn fixed_profile_is_exactly_sixteen_slots_per_epoch() {
        let origin = Instant::now();
        let mut schedule = FixedSchedule::new(origin);
        for _ in 0..FIXED_T2_CELLS_PER_EPOCH {
            schedule.advance(SlotClass::Chaff);
        }
        assert_eq!(
            schedule.next_deadline().duration_since(origin),
            Duration::from_millis(FIXED_T2_EPOCH_MS as u64)
        );
        assert_eq!(
            schedule.metrics().chaff_cells,
            FIXED_T2_CELLS_PER_EPOCH as u64
        );
    }
}

/// Quantized rate classes offered by the fixed profile's rate menu.
pub const RATE_MENU_CELLS_PER_EPOCH: [usize; 4] = [8, 16, 32, 64];

/// Class whose rate is the frozen fixed profile, which is where every link
/// starts and where a link that never negotiates stays.
#[must_use]
pub fn default_rate_class() -> u8 {
    RATE_MENU_CELLS_PER_EPOCH
        .iter()
        .position(|cells| *cells == FIXED_T2_CELLS_PER_EPOCH)
        .and_then(|index| u8::try_from(index).ok())
        .unwrap_or(1)
}

/// Negotiation action carried by a SCHEDULE frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScheduleAction {
    Offer = T2_ACTION_OFFER,
    Accept = T2_ACTION_ACCEPT,
    Reject = T2_ACTION_REJECT,
}

impl TryFrom<u8> for ScheduleAction {
    type Error = ScheduleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            T2_ACTION_OFFER => Ok(Self::Offer),
            T2_ACTION_ACCEPT => Ok(Self::Accept),
            T2_ACTION_REJECT => Ok(Self::Reject),
            _ => Err(ScheduleError::Malformed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleError {
    Malformed,
    UnsupportedSuite,
}

impl std::fmt::Display for ScheduleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed T2 schedule frame",
            Self::UnsupportedSuite => "unsupported T2 suite",
        })
    }
}

impl std::error::Error for ScheduleError {}

/// A T2 rate-class negotiation frame (`transport-profile-t2.md` section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleFrame {
    pub suite: [u8; 2],
    pub negotiation_id: [u8; 16],
    pub effective_epoch: u32,
    pub current_rate_class: u8,
    pub requested_rate_class: u8,
    pub maximum_rate_class: u8,
    pub action: ScheduleAction,
}

/// Encode the 32-byte SCHEDULE header. The remaining payload is padding, which
/// the caller fills, so every cell keeps one constant length.
pub fn encode_schedule_header(frame: &ScheduleFrame) -> Result<[u8; 32], ScheduleError> {
    if !suite_is_network_valid(frame.suite) {
        return Err(ScheduleError::UnsupportedSuite);
    }
    if frame.negotiation_id == [0_u8; 16] {
        return Err(ScheduleError::Malformed);
    }
    let classes = [
        frame.current_rate_class,
        frame.requested_rate_class,
        frame.maximum_rate_class,
    ];
    if classes
        .iter()
        .any(|class| usize::from(*class) >= RATE_MENU_CELLS_PER_EPOCH.len())
    {
        return Err(ScheduleError::Malformed);
    }
    // Section 5: a peer must never be asked for more than it advertised, and
    // "a transition cannot skip a class" - the request is one step from where
    // the link currently is, so a rate change is always gradual.
    if frame.requested_rate_class > frame.maximum_rate_class
        || frame
            .current_rate_class
            .abs_diff(frame.requested_rate_class)
            > 1
    {
        return Err(ScheduleError::Malformed);
    }

    let mut header = [0_u8; 32];
    header[0] = SCHEDULE_PROFILE_T2;
    header[1] = VERSION;
    header[2] = PRIVACY_PROFILE_U1;
    header[3] = LIFECYCLE_PROFILE_E1;
    header[4..6].copy_from_slice(&frame.suite);
    header[6] = T2_FRAME_SCHEDULE;
    header[7] = 0;
    header[8..24].copy_from_slice(&frame.negotiation_id);
    header[24..28].copy_from_slice(&frame.effective_epoch.to_be_bytes());
    header[28] = frame.current_rate_class;
    header[29] = frame.requested_rate_class;
    header[30] = frame.maximum_rate_class;
    header[31] = frame.action as u8;
    Ok(header)
}

/// Decode a SCHEDULE header, rejecting every non-canonical encoding.
pub fn decode_schedule_header(input: &[u8; 32]) -> Result<ScheduleFrame, ScheduleError> {
    if input[0] != SCHEDULE_PROFILE_T2
        || input[1] != VERSION
        || input[2] != PRIVACY_PROFILE_U1
        || input[3] != LIFECYCLE_PROFILE_E1
        || input[6] != T2_FRAME_SCHEDULE
        || input[7] != 0
    {
        return Err(ScheduleError::Malformed);
    }
    let suite = [input[4], input[5]];
    if !suite_is_network_valid(suite) {
        return Err(ScheduleError::UnsupportedSuite);
    }
    let mut negotiation_id = [0_u8; 16];
    negotiation_id.copy_from_slice(&input[8..24]);
    if negotiation_id == [0_u8; 16] {
        return Err(ScheduleError::Malformed);
    }
    let frame = ScheduleFrame {
        suite,
        negotiation_id,
        effective_epoch: u32::from_be_bytes([input[24], input[25], input[26], input[27]]),
        current_rate_class: input[28],
        requested_rate_class: input[29],
        maximum_rate_class: input[30],
        action: ScheduleAction::try_from(input[31])?,
    };
    if [
        frame.current_rate_class,
        frame.requested_rate_class,
        frame.maximum_rate_class,
    ]
    .iter()
    .any(|class| usize::from(*class) >= RATE_MENU_CELLS_PER_EPOCH.len())
        || frame.requested_rate_class > frame.maximum_rate_class
        || frame
            .current_rate_class
            .abs_diff(frame.requested_rate_class)
            > 1
    {
        return Err(ScheduleError::Malformed);
    }
    Ok(frame)
}

#[cfg(test)]
mod schedule_tests {
    use super::*;

    fn frame_from(
        vectors: &test_vectors::Value,
        path: &str,
        action: ScheduleAction,
    ) -> Result<ScheduleFrame, ScheduleError> {
        let get = |field: &str| {
            test_vectors::u64_at(vectors, &format!("{path}/{field}"))
                .map_err(|_| ScheduleError::Malformed)
        };
        Ok(ScheduleFrame {
            suite: test_vectors::hex_array_at::<2>(vectors, "crypto_suite")
                .unwrap_or(protocol_registry::SUITE_R1),
            negotiation_id: test_vectors::hex_array_at::<16>(
                vectors,
                &format!("{path}/negotiation_id"),
            )
            .map_err(|_| ScheduleError::Malformed)?,
            effective_epoch: get("effective_epoch")? as u32,
            current_rate_class: get("current_rate_class")? as u8,
            requested_rate_class: get("requested_rate_class")? as u8,
            maximum_rate_class: get("maximum_rate_class")? as u8,
            action,
        })
    }

    #[test]
    fn published_t2_vectors_pin_the_schedule_headers() -> Result<(), ScheduleError> {
        let vectors = test_vectors::t2().map_err(|_| ScheduleError::Malformed)?;
        assert_eq!(
            test_vectors::u64_at(&vectors, "record_bytes").map_err(|_| ScheduleError::Malformed)?,
            protocol_registry::BYTES_CELL_RECORD as u64
        );
        assert_eq!(
            test_vectors::u64_at(&vectors, "transport_profile")
                .map_err(|_| ScheduleError::Malformed)?,
            SCHEDULE_PROFILE_T2 as u64
        );
        let menu = test_vectors::u64_list_at(&vectors, "rate_menu_cells_per_epoch")
            .map_err(|_| ScheduleError::Malformed)?;
        assert_eq!(
            menu,
            RATE_MENU_CELLS_PER_EPOCH
                .iter()
                .map(|value| *value as u64)
                .collect::<Vec<_>>()
        );

        // Only the OFFER vector publishes a header plaintext. The ACCEPT
        // vector records digests covering the random padding, which the
        // generator draws from a seeded Mersenne Twister, so they pin Python's
        // PRNG rather than a protocol property.
        let offer = frame_from(&vectors, "offer", ScheduleAction::Offer)?;
        let expected =
            test_vectors::hex_array_at::<32>(&vectors, "offer/encrypted_header_plaintext")
                .map_err(|_| ScheduleError::Malformed)?;
        assert_eq!(encode_schedule_header(&offer)?, expected, "OFFER header");
        assert_eq!(
            decode_schedule_header(&expected)?,
            offer,
            "OFFER round trip"
        );

        // The ACCEPT vector still pins the invariant it encodes: the accepted
        // class never exceeds the advertised maximum.
        let requested = test_vectors::u64_at(&vectors, "accept/requested_rate_class")
            .map_err(|_| ScheduleError::Malformed)?;
        let maximum = test_vectors::u64_at(&vectors, "accept/maximum_rate_class")
            .map_err(|_| ScheduleError::Malformed)?;
        assert!(requested <= maximum, "accepted class within the maximum");
        let accept = ScheduleFrame {
            action: ScheduleAction::Accept,
            requested_rate_class: requested as u8,
            maximum_rate_class: maximum as u8,
            effective_epoch: test_vectors::u64_at(&vectors, "accept/effective_epoch")
                .map_err(|_| ScheduleError::Malformed)? as u32,
            ..offer
        };
        let encoded = encode_schedule_header(&accept)?;
        assert_eq!(
            decode_schedule_header(&encoded)?,
            accept,
            "ACCEPT round trip"
        );
        Ok(())
    }

    #[test]
    fn a_transition_may_not_skip_a_rate_class() -> Result<(), ScheduleError> {
        // transport-profile-t2.md:119 - "A transition cannot skip a class."
        // Without this a peer could jump straight from class 0 to class 3 and
        // multiply its emission rate eightfold in one epoch.
        let base = ScheduleFrame {
            suite: protocol_registry::SUITE_R1,
            negotiation_id: [2_u8; 16],
            effective_epoch: 7,
            current_rate_class: 0,
            requested_rate_class: 3,
            maximum_rate_class: 3,
            action: ScheduleAction::Offer,
        };
        assert_eq!(encode_schedule_header(&base), Err(ScheduleError::Malformed));

        // One step up, and one step down, are both fine.
        for requested in [0, 1] {
            let header = encode_schedule_header(&ScheduleFrame {
                requested_rate_class: requested,
                ..base
            })?;
            assert_eq!(
                decode_schedule_header(&header)?.requested_rate_class,
                requested
            );
        }
        let header = encode_schedule_header(&ScheduleFrame {
            current_rate_class: 2,
            requested_rate_class: 1,
            ..base
        })?;
        assert_eq!(decode_schedule_header(&header)?.requested_rate_class, 1);

        // A decoder refuses a skipping frame however it was produced.
        let mut forged = encode_schedule_header(&ScheduleFrame {
            requested_rate_class: 1,
            ..base
        })?;
        forged[29] = 3;
        assert_eq!(
            decode_schedule_header(&forged),
            Err(ScheduleError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn a_request_may_not_exceed_the_advertised_maximum() -> Result<(), ScheduleError> {
        // Section 5: the requested class is bounded by what the peer offered.
        let frame = ScheduleFrame {
            suite: protocol_registry::SUITE_R1,
            negotiation_id: [1_u8; 16],
            effective_epoch: 3,
            current_rate_class: 0,
            requested_rate_class: 3,
            maximum_rate_class: 1,
            action: ScheduleAction::Offer,
        };
        assert_eq!(
            encode_schedule_header(&frame),
            Err(ScheduleError::Malformed)
        );

        // An out-of-menu class and an unknown action are equally refused.
        let mut header = encode_schedule_header(&ScheduleFrame {
            requested_rate_class: 1,
            maximum_rate_class: 1,
            ..frame
        })?;
        header[31] = 0x7f;
        assert_eq!(
            decode_schedule_header(&header),
            Err(ScheduleError::Malformed)
        );
        let mut header = encode_schedule_header(&ScheduleFrame {
            requested_rate_class: 1,
            maximum_rate_class: 1,
            ..frame
        })?;
        header[30] = 9;
        assert_eq!(
            decode_schedule_header(&header),
            Err(ScheduleError::Malformed)
        );
        Ok(())
    }
}

/// Weighted deficit round robin over per-peer DATA classes.
///
/// `transport-profile-t2.md` section 6: one unit of deficit pays for one DATA
/// cell; visiting a backlogged class adds `w * quantum` to its deficit, cells
/// are emitted while the deficit is at least one, and an empty class resets.
/// Weights are local policy and are never carried across relays.
#[derive(Debug, Clone)]
pub struct DeficitScheduler {
    classes: Vec<DeficitClass>,
    cursor: usize,
    quantum: u32,
}

#[derive(Debug, Clone, Copy)]
struct DeficitClass {
    weight: u32,
    deficit: u32,
    backlog: usize,
}

impl DeficitScheduler {
    /// Build a scheduler over `weights`, one entry per DATA class.
    #[must_use]
    pub fn new(weights: &[u32], quantum: u32) -> Self {
        Self {
            classes: weights
                .iter()
                .map(|weight| DeficitClass {
                    weight: (*weight).max(1),
                    deficit: 0,
                    backlog: 0,
                })
                .collect(),
            cursor: 0,
            quantum: quantum.max(1),
        }
    }

    /// Record how many cells a class currently has queued.
    pub fn set_backlog(&mut self, class: usize, cells: usize) {
        if let Some(entry) = self.classes.get_mut(class) {
            entry.backlog = cells;
            if cells == 0 {
                // Section 6: an empty class resets its deficit, so an idle
                // flow cannot bank credit and then burst.
                entry.deficit = 0;
            }
        }
    }

    /// Choose the class whose turn it is, or `None` when nothing is backlogged.
    pub fn next_class(&mut self) -> Option<usize> {
        if self.classes.iter().all(|class| class.backlog == 0) {
            return None;
        }
        for _ in 0..self.classes.len() * 2 {
            let index = self.cursor % self.classes.len();
            let class = &mut self.classes[index];
            if class.backlog == 0 {
                class.deficit = 0;
                self.cursor += 1;
                continue;
            }
            if class.deficit == 0 {
                // Starting this class's turn: it may emit w * quantum cells
                // before the cursor moves on.
                class.deficit = class.weight.saturating_mul(self.quantum);
            }
            class.deficit -= 1;
            class.backlog -= 1;
            if class.deficit == 0 || class.backlog == 0 {
                // Turn spent, or nothing left to send: hand over.
                self.cursor += 1;
            }
            return Some(index);
        }
        None
    }
}

/// Proof that a given number of cells is reserved in a [`QueueBudget`].
///
/// Releasing takes the token by value, so the budget can only ever be credited
/// for a reservation that was actually made, exactly once. That is why release
/// does not use `saturating_sub`: a double release would silently under-count
/// and let the queue exceed its ceiling.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "an unreleased reservation leaks queue capacity"]
pub struct Reservation {
    cells: usize,
}

impl Reservation {
    #[must_use]
    pub fn cells(&self) -> usize {
        self.cells
    }
}

/// Queue admission counted in cells (`transport-profile-t2.md` section 7).
///
/// A transmission reserves its whole fragment set before its first emission,
/// so an over-budget transmission is refused up front rather than being
/// admitted and then abandoned part-way. The unit is the cell, not the logical
/// message: 64 messages of 17 fragments are 1,088 cells, four times the
/// per-peer ceiling, so counting messages does not bound the queue at all.
#[derive(Debug, Clone, Copy)]
pub struct QueueBudget {
    capacity_cells: usize,
    reserved_cells: usize,
    rejected: u64,
}

impl QueueBudget {
    /// A budget bounded by `capacity_cells`, e.g.
    /// `FIXED_T2_QUEUE_CELLS_PER_PEER` or `FIXED_T2_QUEUE_CELLS_GLOBAL`.
    #[must_use]
    pub fn new(capacity_cells: usize) -> Self {
        Self {
            capacity_cells,
            reserved_cells: 0,
            rejected: 0,
        }
    }

    /// Reserve `cells` atomically, or refuse the whole transmission.
    pub fn reserve(&mut self, cells: usize) -> Option<Reservation> {
        if self.reserved_cells.saturating_add(cells) > self.capacity_cells {
            self.rejected = self.rejected.saturating_add(1);
            return None;
        }
        self.reserved_cells += cells;
        Some(Reservation { cells })
    }

    /// Give the cells back once the transmission completes or is abandoned.
    pub fn release(&mut self, reservation: Reservation) {
        debug_assert!(
            self.reserved_cells >= reservation.cells,
            "released more cells than were reserved"
        );
        self.reserved_cells -= reservation.cells.min(self.reserved_cells);
    }

    #[must_use]
    pub fn capacity_cells(&self) -> usize {
        self.capacity_cells
    }

    #[must_use]
    pub fn reserved_cells(&self) -> usize {
        self.reserved_cells
    }

    #[must_use]
    pub fn rejected(&self) -> u64 {
        self.rejected
    }
}

impl Default for QueueBudget {
    fn default() -> Self {
        Self::new(FIXED_T2_QUEUE_CELLS_GLOBAL)
    }
}

#[cfg(test)]
mod fairness_tests {
    use super::*;
    use protocol_registry::{
        FIXED_T2_QUEUE_CELLS_PER_PEER, LIMIT_MAX_FRAGMENTS, LIMIT_MAX_SENDER_TRANSMISSIONS_PER_PEER,
    };

    #[test]
    fn deficit_round_robin_shares_slots_by_weight() {
        // Two backlogged classes weighted 1 and 3 should split emissions about
        // one to three over a long run.
        let mut scheduler = DeficitScheduler::new(&[1, 3], 1);
        let mut counts = [0_usize; 2];
        for _ in 0..400 {
            scheduler.set_backlog(0, 100);
            scheduler.set_backlog(1, 100);
            if let Some(class) = scheduler.next_class() {
                counts[class] += 1;
            }
        }
        let ratio = counts[1] as f64 / counts[0].max(1) as f64;
        assert!(
            (2.0..=4.0).contains(&ratio),
            "weight 3 class should take roughly three times the slots, got {ratio}"
        );
    }

    #[test]
    fn an_idle_class_cannot_bank_credit() {
        let mut scheduler = DeficitScheduler::new(&[1, 8], 4);
        // Class 1 stays idle while class 0 is served.
        for _ in 0..20 {
            scheduler.set_backlog(0, 10);
            scheduler.set_backlog(1, 0);
            scheduler.next_class();
        }
        // When it finally has traffic it starts from zero deficit, so it
        // cannot immediately monopolise the link.
        scheduler.set_backlog(0, 10);
        scheduler.set_backlog(1, 1);
        let mut served_one = 0;
        for _ in 0..4 {
            if scheduler.next_class() == Some(1) {
                served_one += 1;
            }
            scheduler.set_backlog(1, 0);
        }
        assert!(served_one <= 1, "an idle class does not bank credit");
    }

    #[test]
    fn the_global_budget_reserves_whole_transmissions() -> Result<(), ScheduleError> {
        let mut budget = QueueBudget::default();
        let whole = budget
            .reserve(FIXED_T2_QUEUE_CELLS_GLOBAL)
            .ok_or(ScheduleError::Malformed)?;
        assert_eq!(budget.reserved_cells(), FIXED_T2_QUEUE_CELLS_GLOBAL);

        // One more cell does not fit, and the refusal is atomic: nothing of the
        // rejected transmission is reserved.
        assert!(budget.reserve(1).is_none());
        assert_eq!(budget.reserved_cells(), FIXED_T2_QUEUE_CELLS_GLOBAL);
        assert_eq!(budget.rejected(), 1);

        budget.release(whole);
        assert_eq!(budget.reserved_cells(), 0);
        assert!(budget.reserve(1).is_some());
        Ok(())
    }

    #[test]
    fn the_per_peer_ceiling_is_counted_in_cells_not_messages() -> Result<(), ScheduleError> {
        // The sender admits 64 transmissions per peer and each may hold 17
        // fragments, so counting messages would let one peer queue 1,088
        // first-send cells against a 256-cell ceiling.
        let mut budget = QueueBudget::new(FIXED_T2_QUEUE_CELLS_PER_PEER);
        let mut held = Vec::new();
        for _ in 0..LIMIT_MAX_SENDER_TRANSMISSIONS_PER_PEER {
            match budget.reserve(LIMIT_MAX_FRAGMENTS) {
                Some(reservation) => held.push(reservation),
                None => break,
            }
        }
        assert_eq!(
            held.len(),
            FIXED_T2_QUEUE_CELLS_PER_PEER / LIMIT_MAX_FRAGMENTS,
            "admission stops at the cell ceiling, not the message ceiling"
        );
        assert!(budget.reserved_cells() <= FIXED_T2_QUEUE_CELLS_PER_PEER);
        assert!(budget.rejected() >= 1);

        // Completing one transmission frees exactly its own cells.
        let reservation = held.pop().ok_or(ScheduleError::Malformed)?;
        let before = budget.reserved_cells();
        budget.release(reservation);
        assert_eq!(budget.reserved_cells(), before - LIMIT_MAX_FRAGMENTS);
        Ok(())
    }
}

/// Rate-class negotiation for one adjacent link (`transport-profile-t2.md`
/// section 5).
///
/// Only one side proposes, so two peers cannot offer past each other; the
/// responder answers whatever arrives. Proposals move one class at a time,
/// never exceed what the peer advertised, and are rate-limited by a hysteresis
/// interval so a link cannot oscillate. A negotiation that is stale,
/// conflicting, or unanswered leaves the next epoch at the current class,
/// which is what keeps a link that never negotiates on the frozen profile.
#[derive(Debug, Clone)]
pub struct RateNegotiation {
    suite: [u8; 2],
    current: u8,
    maximum: u8,
    proposer: bool,
    pending: Option<PendingOffer>,
    /// `None` until the class has actually moved. Hysteresis damps
    /// oscillation between changes; it must not hold off the first proposal,
    /// when nothing has changed yet to oscillate.
    last_change_epoch: Option<u32>,
    hysteresis_epochs: u32,
    accepted: u64,
    rejected: u64,
}

#[derive(Debug, Clone, Copy)]
struct PendingOffer {
    negotiation_id: [u8; 16],
    requested: u8,
    effective_epoch: u32,
}

impl RateNegotiation {
    /// `proposer` decides which end offers; give it to exactly one peer.
    #[must_use]
    pub fn new(suite: [u8; 2], proposer: bool, hysteresis_epochs: u32) -> Self {
        Self {
            suite,
            current: default_rate_class(),
            maximum: (RATE_MENU_CELLS_PER_EPOCH.len() - 1) as u8,
            proposer,
            pending: None,
            last_change_epoch: None,
            hysteresis_epochs,
            accepted: 0,
            rejected: 0,
        }
    }

    #[must_use]
    pub fn current(&self) -> u8 {
        self.current
    }

    #[must_use]
    pub fn accepted(&self) -> u64 {
        self.accepted
    }

    #[must_use]
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Propose a step toward `target`, or `None` if there is nothing to do.
    ///
    /// `backlog_cells` is what the link has queued; the caller maps that to a
    /// target class. The step is always adjacent, because section 5 forbids
    /// skipping a class.
    pub fn offer(
        &mut self,
        target: u8,
        epoch: u32,
        negotiation_id: [u8; 16],
    ) -> Option<ScheduleFrame> {
        if !self.proposer || self.pending.is_some() || negotiation_id == [0_u8; 16] {
            return None;
        }
        if self
            .last_change_epoch
            .is_some_and(|last| epoch.saturating_sub(last) < self.hysteresis_epochs)
        {
            return None;
        }
        let target = target.min(self.maximum);
        let requested = match target.cmp(&self.current) {
            std::cmp::Ordering::Equal => return None,
            std::cmp::Ordering::Greater => self.current.saturating_add(1),
            std::cmp::Ordering::Less => self.current.saturating_sub(1),
        };
        let effective_epoch = epoch.saturating_add(1);
        let frame = ScheduleFrame {
            suite: self.suite,
            negotiation_id,
            effective_epoch,
            current_rate_class: self.current,
            requested_rate_class: requested,
            maximum_rate_class: self.maximum,
            action: ScheduleAction::Offer,
        };
        self.pending = Some(PendingOffer {
            negotiation_id,
            requested,
            effective_epoch,
        });
        Some(frame)
    }

    /// Handle a frame from the peer, returning any reply to emit.
    ///
    /// The class actually adopted, if any, is available from
    /// [`Self::current`] afterwards.
    pub fn on_frame(&mut self, frame: &ScheduleFrame, epoch: u32) -> Option<ScheduleFrame> {
        match frame.action {
            ScheduleAction::Offer => {
                if self.proposer {
                    // Both ends offering would race; only one end proposes.
                    return None;
                }
                let granted = frame.requested_rate_class.min(self.maximum);
                let action = if granted == frame.requested_rate_class {
                    self.current = granted;
                    self.last_change_epoch = Some(epoch);
                    self.accepted = self.accepted.saturating_add(1);
                    ScheduleAction::Accept
                } else {
                    self.rejected = self.rejected.saturating_add(1);
                    ScheduleAction::Reject
                };
                Some(ScheduleFrame {
                    suite: self.suite,
                    negotiation_id: frame.negotiation_id,
                    effective_epoch: frame.effective_epoch,
                    current_rate_class: frame.current_rate_class,
                    requested_rate_class: frame.requested_rate_class,
                    maximum_rate_class: self.maximum,
                    action,
                })
            }
            ScheduleAction::Accept | ScheduleAction::Reject => {
                // A reply for a negotiation this end never opened, or for one
                // that has already been superseded, leaves the class alone.
                let Some(pending) = self.pending else {
                    return None;
                };
                if pending.negotiation_id != frame.negotiation_id
                    || pending.requested != frame.requested_rate_class
                    || pending.effective_epoch != frame.effective_epoch
                {
                    return None;
                }
                self.pending = None;
                if frame.action == ScheduleAction::Accept {
                    self.current = pending.requested;
                    self.last_change_epoch = Some(epoch);
                    self.accepted = self.accepted.saturating_add(1);
                } else {
                    self.rejected = self.rejected.saturating_add(1);
                }
                None
            }
        }
    }

    /// Abandon an offer that was never answered, so the link can try again.
    pub fn expire_pending(&mut self, epoch: u32) {
        if let Some(pending) = self.pending {
            if epoch > pending.effective_epoch {
                self.pending = None;
                self.rejected = self.rejected.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod negotiation_tests {
    use super::*;

    fn pair() -> (RateNegotiation, RateNegotiation) {
        (
            RateNegotiation::new(protocol_registry::SUITE_R1, true, 0),
            RateNegotiation::new(protocol_registry::SUITE_R1, false, 0),
        )
    }

    #[test]
    fn a_link_climbs_one_class_at_a_time() -> Result<(), ScheduleError> {
        let (mut proposer, mut responder) = pair();
        let start = proposer.current();

        // Asking for the top class moves one step, because section 5 forbids
        // skipping and the codec would refuse the frame outright.
        let offer = proposer
            .offer(3, 1, [1_u8; 16])
            .ok_or(ScheduleError::Malformed)?;
        assert_eq!(offer.requested_rate_class, start + 1);
        assert!(encode_schedule_header(&offer).is_ok(), "adjacency holds");

        let reply = responder
            .on_frame(&offer, 1)
            .ok_or(ScheduleError::Malformed)?;
        assert_eq!(reply.action, ScheduleAction::Accept);
        assert_eq!(responder.current(), start + 1);

        assert!(proposer.on_frame(&reply, 1).is_none());
        assert_eq!(proposer.current(), start + 1, "both ends agree");

        // The next step is again adjacent.
        let next = proposer
            .offer(3, 2, [2_u8; 16])
            .ok_or(ScheduleError::Malformed)?;
        assert_eq!(next.requested_rate_class, start + 2);
        Ok(())
    }

    #[test]
    fn only_one_end_proposes_and_replies_must_match() -> Result<(), ScheduleError> {
        let (mut proposer, mut responder) = pair();
        let offer = proposer
            .offer(3, 1, [3_u8; 16])
            .ok_or(ScheduleError::Malformed)?;

        // The proposing end ignores an offer, so two peers cannot race.
        let (mut other, _) = pair();
        assert!(other.on_frame(&offer, 1).is_none());

        // A reply naming a different negotiation leaves the class alone.
        let mut forged = responder
            .on_frame(&offer, 1)
            .ok_or(ScheduleError::Malformed)?;
        let before = proposer.current();
        forged.negotiation_id = [9_u8; 16];
        assert!(proposer.on_frame(&forged, 1).is_none());
        assert_eq!(proposer.current(), before, "a stale reply changes nothing");
        Ok(())
    }

    #[test]
    fn hysteresis_and_an_unanswered_offer_leave_the_class_alone() -> Result<(), ScheduleError> {
        let mut proposer = RateNegotiation::new(protocol_registry::SUITE_R1, true, 4);
        let start = proposer.current();

        // One offer at a time.
        assert!(proposer.offer(3, 10, [1_u8; 16]).is_some());
        assert!(proposer.offer(3, 10, [2_u8; 16]).is_none());

        // Unanswered, it lapses and the class is unchanged.
        proposer.expire_pending(12);
        assert_eq!(proposer.current(), start);

        // Hysteresis then holds off the next proposal until enough epochs pass.
        let mut settled = RateNegotiation::new(protocol_registry::SUITE_R1, true, 4);
        let offer = settled
            .offer(3, 10, [4_u8; 16])
            .ok_or(ScheduleError::Malformed)?;
        let mut responder = RateNegotiation::new(protocol_registry::SUITE_R1, false, 4);
        let reply = responder
            .on_frame(&offer, 10)
            .ok_or(ScheduleError::Malformed)?;
        settled.on_frame(&reply, 10);
        assert!(settled.offer(3, 11, [5_u8; 16]).is_none(), "too soon");
        assert!(settled.offer(3, 20, [6_u8; 16]).is_some(), "settled");
        Ok(())
    }
}
