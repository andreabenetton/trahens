// SPDX-License-Identifier: Apache-2.0
//! The append-only admission store.
//!
//! Implements ADR 0047. A node that admits peers has to remember what it has
//! already spent and whom it has already pinned, and had nowhere to remember it
//! before this: every node took its peer set from the command line and kept
//! nothing across a restart.
//!
//! **The ordering is the security property, not the format.** [`Store::append`]
//! returns only once the record is on disk, and the caller must not complete the
//! handshake the record belongs to until it has. A spent marker written after
//! the handshake completes is one a crash can lose, and losing it re-opens the
//! invitation that handshake just consumed.
//!
//! This is local state and not a wire format — no peer parses it — so it is
//! deliberately not published as vectors or given a second implementation. What
//! it does need is to survive the failures a file has, which is what the tests
//! are about.

use crate::CookieError;
use protocol_registry::{
    B12_STORE_INVITATION_SPENT, B12_STORE_PEER_PINNED, B12_STORE_PEER_REMOVED,
    BYTES_B12_INVITATION_ID, BYTES_B12_STORE_CHECKSUM, BYTES_B12_STORE_LENGTH,
    DOMAIN_B12_STORE_RECORD,
};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use trahens_crypto::sha256;

type Result<T> = std::result::Result<T, CookieError>;

/// One change to a node's admission state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// An invitation was consumed. ADR 0046 D8 makes them single-use, and this
    /// is what makes that survive a restart.
    InvitationSpent {
        identifier: [u8; BYTES_B12_INVITATION_ID],
    },
    /// A static key learned by admission was promoted into the manifest.
    PeerPinned {
        peer_id: u32,
        static_public: [u8; 32],
    },
    /// A pinned key was withdrawn at this node. ADR 0046 D9; it says nothing to
    /// any other node and does not tear down a live link.
    PeerRemoved { peer_id: u32 },
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::InvitationSpent { identifier } => {
                let mut out = vec![B12_STORE_INVITATION_SPENT];
                out.extend_from_slice(identifier);
                out
            }
            Self::PeerPinned {
                peer_id,
                static_public,
            } => {
                let mut out = vec![B12_STORE_PEER_PINNED];
                out.extend_from_slice(&peer_id.to_be_bytes());
                out.extend_from_slice(static_public);
                out
            }
            Self::PeerRemoved { peer_id } => {
                let mut out = vec![B12_STORE_PEER_REMOVED];
                out.extend_from_slice(&peer_id.to_be_bytes());
                out
            }
        }
    }

    fn decode(payload: &[u8]) -> Result<Self> {
        let (kind, rest) = payload.split_first().ok_or(CookieError)?;
        match *kind {
            B12_STORE_INVITATION_SPENT => Ok(Self::InvitationSpent {
                identifier: rest.try_into().map_err(|_| CookieError)?,
            }),
            B12_STORE_PEER_PINNED => {
                let id: [u8; 4] = rest
                    .get(..4)
                    .ok_or(CookieError)?
                    .try_into()
                    .map_err(|_| CookieError)?;
                Ok(Self::PeerPinned {
                    peer_id: u32::from_be_bytes(id),
                    static_public: rest
                        .get(4..)
                        .ok_or(CookieError)?
                        .try_into()
                        .map_err(|_| CookieError)?,
                })
            }
            B12_STORE_PEER_REMOVED => {
                let id: [u8; 4] = rest.try_into().map_err(|_| CookieError)?;
                Ok(Self::PeerRemoved {
                    peer_id: u32::from_be_bytes(id),
                })
            }
            _ => Err(CookieError),
        }
    }
}

/// Detects a torn or corrupted record. Not a MAC: anyone who can write the file
/// can rewrite it, and this claims only to catch damage rather than tampering.
fn checksum(payload: &[u8]) -> Result<[u8; BYTES_B12_STORE_CHECKSUM]> {
    let mut input = Vec::with_capacity(DOMAIN_B12_STORE_RECORD.len() + payload.len());
    input.extend_from_slice(DOMAIN_B12_STORE_RECORD);
    input.extend_from_slice(payload);
    let digest = sha256(&input)?;
    Ok(digest
        .get(..BYTES_B12_STORE_CHECKSUM)
        .ok_or(CookieError)?
        .try_into()
        .map_err(|_| CookieError)?)
}

/// Why a store would not load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The file exists and does not parse. ADR 0047 D11: a node does not know
    /// what it already spent, so it refuses to start rather than admit on that
    /// basis.
    Damaged,
    /// The file could not be read or written.
    Io,
    /// A record was malformed in a way encoding cannot produce.
    Encoding,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Damaged => "admission store is damaged",
            Self::Io => "admission store could not be read or written",
            Self::Encoding => "admission store record is malformed",
        })
    }
}

impl std::error::Error for StoreError {}

pub struct Store {
    path: PathBuf,
    spent: HashSet<[u8; BYTES_B12_INVITATION_ID]>,
    pinned: HashMap<u32, [u8; 32]>,
}

impl Store {
    /// Load, or start empty if the file is absent.
    ///
    /// ADR 0047 D11. Absence is a first run. A record that fails its checksum
    /// *before* the end of the file is damage and refuses; a short or
    /// overrunning record *at* the end is what a crash during append looks
    /// like, and is discarded — the change it represents never took effect,
    /// because the flush had not returned.
    pub fn open(path: &Path) -> std::result::Result<Self, StoreError> {
        let mut store = Self {
            path: path.to_path_buf(),
            spent: HashSet::new(),
            pinned: HashMap::new(),
        };
        let mut bytes = Vec::new();
        match File::open(path) {
            Ok(mut file) => {
                file.read_to_end(&mut bytes).map_err(|_| StoreError::Io)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(store),
            Err(_) => return Err(StoreError::Io),
        }

        let header = BYTES_B12_STORE_LENGTH + BYTES_B12_STORE_CHECKSUM;
        let mut cursor = 0_usize;
        while cursor < bytes.len() {
            let Some(length_bytes) = bytes.get(cursor..cursor + BYTES_B12_STORE_LENGTH) else {
                break; // torn tail: not even a length
            };
            let length =
                u32::from_be_bytes(length_bytes.try_into().map_err(|_| StoreError::Encoding)?)
                    as usize;
            let Some(payload) = bytes
                .get(cursor + BYTES_B12_STORE_LENGTH..cursor + BYTES_B12_STORE_LENGTH + length)
            else {
                break; // torn tail: the payload was not fully written
            };
            let Some(found) =
                bytes.get(cursor + BYTES_B12_STORE_LENGTH + length..cursor + header + length)
            else {
                break; // torn tail: the checksum was not fully written
            };
            let expected = checksum(payload).map_err(|_| StoreError::Encoding)?;
            if found != expected {
                // A full record that does not check out is not a crash
                // artifact, whether or not it is the last one.
                return Err(StoreError::Damaged);
            }
            let record = Record::decode(payload).map_err(|_| StoreError::Damaged)?;
            store.apply(&record);
            cursor += header + length;
        }
        Ok(store)
    }

    fn apply(&mut self, record: &Record) {
        match *record {
            Record::InvitationSpent { identifier } => {
                self.spent.insert(identifier);
            }
            Record::PeerPinned {
                peer_id,
                static_public,
            } => {
                self.pinned.insert(peer_id, static_public);
            }
            Record::PeerRemoved { peer_id } => {
                self.pinned.remove(&peer_id);
            }
        }
    }

    /// Append one record and return only once it is on disk.
    ///
    /// The caller must not complete the handshake this record belongs to until
    /// this has returned. An implementation that logs a write failure and
    /// proceeds has re-created the lost marker ADR 0047 exists to prevent,
    /// which is why the error is returned rather than swallowed.
    pub fn append(&mut self, record: &Record) -> std::result::Result<(), StoreError> {
        let payload = record.encode();
        let length = u32::try_from(payload.len()).map_err(|_| StoreError::Encoding)?;
        let sum = checksum(&payload).map_err(|_| StoreError::Encoding)?;

        let mut framed = Vec::with_capacity(payload.len() + 12);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(&payload);
        framed.extend_from_slice(&sum);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| StoreError::Io)?;
        file.write_all(&framed).map_err(|_| StoreError::Io)?;
        file.sync_all().map_err(|_| StoreError::Io)?;
        self.apply(record);
        Ok(())
    }

    #[must_use]
    pub fn is_spent(&self, identifier: &[u8; BYTES_B12_INVITATION_ID]) -> bool {
        self.spent.contains(identifier)
    }

    #[must_use]
    pub fn pinned(&self, peer_id: u32) -> Option<[u8; 32]> {
        self.pinned.get(&peer_id).copied()
    }

    #[must_use]
    pub fn pinned_count(&self) -> usize {
        self.pinned.len()
    }
}
