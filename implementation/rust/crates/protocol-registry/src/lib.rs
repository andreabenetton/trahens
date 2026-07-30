// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "Generated Trahens v1.5 protocol identifiers and limits."]

include!("generated.rs");

pub fn suite_is_network_valid(value: [u8; 2]) -> bool {
    value == SUITE_C1_V2 || value == SUITE_C2_SYMBOLIC || value == SUITE_R1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operative_suites_are_accepted() {
        assert!(suite_is_network_valid(SUITE_C1_V2));
        assert!(suite_is_network_valid(SUITE_R1));
    }

    #[test]
    fn symbolic_c2_is_accepted_as_a_research_only_suite() {
        // message-codec-m2.md defines a parser for 0x0002 and marks it
        // research-only rather than rejected, unlike the retired 0x0001 and
        // the reserved audit suite 0x7f02. The Python reference decoder
        // (_require_suite_id in trahens_codec/m2w2.py) admits the same three.
        assert!(suite_is_network_valid(SUITE_C2_SYMBOLIC));
    }

    #[test]
    fn retired_and_disabled_suites_are_rejected() {
        assert!(!suite_is_network_valid(SUITE_C1_V1_RETIRED));
        assert!(!suite_is_network_valid(SUITE_C2_K2_DISABLED));
    }

    #[test]
    fn unallocated_suites_are_rejected() {
        assert!(!suite_is_network_valid([0x00, 0x00]));
        assert!(!suite_is_network_valid([0x01, 0x02]));
        assert!(!suite_is_network_valid([0xff, 0xff]));
    }

    #[test]
    fn cell_geometry_is_self_consistent() {
        assert_eq!(BYTES_CELL_HEADER + BYTES_CELL_PAYLOAD, BYTES_CELL_BODY);
        assert_eq!(BYTES_CELL_PAYLOAD, 992);
        assert_eq!(BYTES_CELL_RECORD, 1052);
    }

    #[test]
    fn fragment_limit_covers_the_largest_logical_message() {
        let per_fragment = BYTES_CELL_PAYLOAD;
        let needed = LIMIT_MAX_LOGICAL_MESSAGE_BYTES.div_ceil(per_fragment);
        assert!(
            needed <= LIMIT_MAX_FRAGMENTS,
            "{needed} fragments needed but only {LIMIT_MAX_FRAGMENTS} permitted"
        );
    }
}
