#![forbid(unsafe_code)]
#![doc = "Generated Trahens v1.5 protocol identifiers and limits."]

include!("generated.rs");

pub fn suite_is_network_valid(value: [u8; 2]) -> bool {
    value == SUITE_C1_V2 || value == SUITE_C2_SYMBOLIC || value == SUITE_R1
}
