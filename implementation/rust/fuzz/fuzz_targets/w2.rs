// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use wire_w2::{open_record, ReplayWindow};

fuzz_target!(|data: &[u8]| {
    let mut replay = ReplayWindow::new(1);
    let _ = open_record(&[0x42; 32], 1, data, &mut replay);
});
