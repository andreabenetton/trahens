// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "B1.1 authenticated adjacent-link handshake (Noise XX / XXpsk0)."]

//! Implements `spec/link-handshake-b1.md`.
//!
//! The crate is presently a shell. Its first deliverable was the cross-check in
//! `tests/cross_check_snow.rs`, which replays the published vectors through an
//! independent Noise implementation: until that agrees, an implementation built
//! here would inherit any mistake in the Python reference rather than expose
//! it.
//!
//! The state machine follows once v1.8 is the active profile and the registry
//! generates B1 bindings. Hardcoding those widths and domains here in the
//! meantime would put a second copy of values the registry is supposed to own,
//! which is the drift the repository's generated-bindings rule exists to
//! prevent.
