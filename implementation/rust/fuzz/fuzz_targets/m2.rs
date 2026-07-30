#![no_main]

use codec_m2::decode;
use libfuzzer_sys::fuzz_target;
use protocol_registry::LIMIT_MAX_LOGICAL_MESSAGE_BYTES;

fuzz_target!(|data: &[u8]| {
    if data.len() <= LIMIT_MAX_LOGICAL_MESSAGE_BYTES {
        let _ = decode(data);
    }
});
