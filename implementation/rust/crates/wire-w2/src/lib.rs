// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "Fixed-size authenticated Trahens W2 adjacent-link records."]

use protocol_registry::{BYTES_CELL_BODY, BYTES_CELL_RECORD, LIMIT_REPLAY_WINDOW_CELLS};
use std::collections::BTreeSet;
use trahens_crypto::{aead_open, aead_seal, CryptoError};

pub const LINK_HEADER_BYTES: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Malformed,
    Authentication,
    Replay,
    WrongEpoch,
}

impl From<CryptoError> for WireError {
    fn from(_value: CryptoError) -> Self {
        Self::Authentication
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed W2 record",
            Self::Authentication => "W2 authentication failed",
            Self::Replay => "W2 replay rejected",
            Self::WrongEpoch => "W2 epoch rejected",
        })
    }
}

impl std::error::Error for WireError {}

fn header(epoch: u32, sequence: u64) -> [u8; LINK_HEADER_BYTES] {
    let mut output = [0_u8; LINK_HEADER_BYTES];
    output[..4].copy_from_slice(&epoch.to_be_bytes());
    output[4..].copy_from_slice(&sequence.to_be_bytes());
    output
}

pub fn seal_record(
    key: &[u8; 32],
    epoch: u32,
    sequence: u64,
    plaintext: &[u8; BYTES_CELL_BODY],
) -> Result<[u8; BYTES_CELL_RECORD], WireError> {
    let public = header(epoch, sequence);
    let ciphertext = aead_seal(key, &public, plaintext, &public)?;
    if ciphertext.len() != BYTES_CELL_BODY + 16 {
        return Err(WireError::Authentication);
    }
    let mut output = [0_u8; BYTES_CELL_RECORD];
    output[..LINK_HEADER_BYTES].copy_from_slice(&public);
    output[LINK_HEADER_BYTES..].copy_from_slice(&ciphertext);
    Ok(output)
}

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    epoch: u32,
    width: u64,
    highest: Option<u64>,
    admitted: BTreeSet<u64>,
}

impl ReplayWindow {
    pub fn new(epoch: u32) -> Self {
        Self {
            epoch,
            width: LIMIT_REPLAY_WINDOW_CELLS as u64,
            highest: None,
            admitted: BTreeSet::new(),
        }
    }

    pub fn precheck(&self, epoch: u32, sequence: u64) -> Result<(), WireError> {
        if epoch != self.epoch {
            return Err(WireError::WrongEpoch);
        }
        if self.admitted.contains(&sequence) {
            return Err(WireError::Replay);
        }
        if let Some(highest) = self.highest {
            if sequence.saturating_add(self.width) <= highest {
                return Err(WireError::Replay);
            }
        }
        Ok(())
    }

    pub fn commit(&mut self, epoch: u32, sequence: u64) -> Result<(), WireError> {
        self.precheck(epoch, sequence)?;
        self.highest = Some(self.highest.map_or(sequence, |value| value.max(sequence)));
        self.admitted.insert(sequence);
        if let Some(highest) = self.highest {
            let minimum = highest.saturating_sub(self.width.saturating_sub(1));
            self.admitted = self.admitted.split_off(&minimum);
        }
        Ok(())
    }

    pub fn entries(&self) -> usize {
        self.admitted.len()
    }
}

pub fn open_record(
    key: &[u8; 32],
    expected_epoch: u32,
    record: &[u8],
    replay: &mut ReplayWindow,
) -> Result<(u64, [u8; BYTES_CELL_BODY]), WireError> {
    if record.len() != BYTES_CELL_RECORD {
        return Err(WireError::Malformed);
    }
    let mut public = [0_u8; LINK_HEADER_BYTES];
    public.copy_from_slice(&record[..LINK_HEADER_BYTES]);
    let epoch = u32::from_be_bytes([public[0], public[1], public[2], public[3]]);
    let sequence = u64::from_be_bytes([
        public[4], public[5], public[6], public[7], public[8], public[9], public[10], public[11],
    ]);
    if epoch != expected_epoch {
        return Err(WireError::WrongEpoch);
    }
    replay.precheck(epoch, sequence)?;
    let plaintext = aead_open(key, &public, &record[LINK_HEADER_BYTES..], &public)?;
    if plaintext.len() != BYTES_CELL_BODY {
        return Err(WireError::Authentication);
    }
    let mut body = [0_u8; BYTES_CELL_BODY];
    body.copy_from_slice(&plaintext);
    replay.commit(epoch, sequence)?;
    Ok((sequence, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trip_and_replay_rejection() -> Result<(), WireError> {
        let key = [7_u8; 32];
        let body = [9_u8; BYTES_CELL_BODY];
        let record = seal_record(&key, 1, 3, &body)?;
        assert_eq!(record.len(), BYTES_CELL_RECORD);
        let mut replay = ReplayWindow::new(1);
        assert_eq!(open_record(&key, 1, &record, &mut replay)?.1, body);
        assert_eq!(
            open_record(&key, 1, &record, &mut replay),
            Err(WireError::Replay)
        );
        Ok(())
    }

    #[test]
    fn unauthenticated_future_sequence_does_not_commit() -> Result<(), WireError> {
        let key = [1_u8; 32];
        let mut record = seal_record(&key, 5, 900, &[0_u8; BYTES_CELL_BODY])?;
        record[100] ^= 1;
        let mut replay = ReplayWindow::new(5);
        assert_eq!(
            open_record(&key, 5, &record, &mut replay),
            Err(WireError::Authentication)
        );
        assert_eq!(replay.entries(), 0);
        Ok(())
    }
}
