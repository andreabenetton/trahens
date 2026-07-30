#![forbid(unsafe_code)]
#![doc = "Generated Trahens v1.5 protocol identifiers and limits."]

include!("generated.rs");

pub fn suite_is_network_valid(value: [u8; 2]) -> bool {
    value == SUITE_C1_V2 || value == SUITE_C2_SYMBOLIC || value == SUITE_R1
}

#[cfg(test)]
mod tests {
    use super::*;

    // SUITE_C2_SYMBOLIC is deliberately not asserted here: core-v1.5.md names
    // only C1 v2 and R1 as network suites, but suite_is_network_valid accepts
    // the symbolic suite as well. Resolving that is a spec decision, so no
    // expectation is frozen in either direction until it is settled.

    #[test]
    fn operative_suites_are_accepted() {
        assert!(suite_is_network_valid(SUITE_C1_V2));
        assert!(suite_is_network_valid(SUITE_R1));
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
