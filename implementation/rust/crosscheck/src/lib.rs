// SPDX-License-Identifier: Apache-2.0
#![doc = "Independent cross-checks of published vectors. Tests only."]

//! This crate carries no implementation. It exists so the Noise cross-check in
//! `tests/` can depend on `snow` without that dependency reaching the
//! workspace, whose build floor and libsodium-only posture it would break.
