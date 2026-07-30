// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "Frozen fixed-rate T2 P1 scheduler."]

use protocol_registry::{
    FIXED_T2_CELLS_PER_EPOCH, FIXED_T2_EPOCH_MS, FIXED_T2_PROFILE_ID, FIXED_T2_SLOT_INTERVAL_US,
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
}

#[derive(Debug, Clone)]
pub struct FixedSchedule {
    next: Instant,
    interval: Duration,
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
            metrics: ScheduleMetrics::default(),
        }
    }

    pub fn next_deadline(&self) -> Instant {
        self.next
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
