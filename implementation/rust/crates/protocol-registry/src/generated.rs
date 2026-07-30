// SPDX-License-Identifier: Apache-2.0
// Generated from spec/protocol-registry-v1.5.json; do not edit.
pub const REGISTRY_VERSION: &str = "1.5.0";

pub const VERSION: u8 = 1;
pub const PRIVACY_PROFILE_U1: u8 = 1;
pub const LIFECYCLE_PROFILE_E1: u8 = 1;
pub const MESSAGE_PROFILE_M2: u8 = 2;
pub const WIRE_PROFILE_W2: u8 = 2;
pub const TRANSPORT_PROFILE_T1: u8 = 3;
pub const SCHEDULE_PROFILE_T2: u8 = 4;

pub const SUITE_C1_V1_RETIRED: [u8; 2] = [0x00, 0x01];
pub const SUITE_C2_SYMBOLIC: [u8; 2] = [0x00, 0x02];
pub const SUITE_C1_V2: [u8; 2] = [0x00, 0x03];
pub const SUITE_R1: [u8; 2] = [0x01, 0x01];
pub const SUITE_C2_K2_DISABLED: [u8; 2] = [0x7f, 0x02];

pub const MESSAGE_CHAFF: u8 = 0;
pub const MESSAGE_DISCOVER: u8 = 32;
pub const MESSAGE_CANDIDATE: u8 = 33;
pub const MESSAGE_COMMIT: u8 = 34;
pub const MESSAGE_READY: u8 = 35;
pub const MESSAGE_CANCEL: u8 = 36;
pub const MESSAGE_ABORT: u8 = 37;
pub const MESSAGE_CLOSE: u8 = 38;
pub const MESSAGE_RENDEZVOUS_OPEN: u8 = 39;
pub const MESSAGE_RENDEZVOUS_RESULT: u8 = 40;
pub const MESSAGE_DATA: u8 = 41;

pub const T1_FRAME_DATA: u8 = 0;
pub const T1_FRAME_ACK: u8 = 1;
pub const T1_FRAME_CHAFF: u8 = 2;

pub const T2_FRAME_SCHEDULE: u8 = 3;

pub const T2_ACTION_OFFER: u8 = 0;
pub const T2_ACTION_ACCEPT: u8 = 1;
pub const T2_ACTION_REJECT: u8 = 2;

pub const P1_PAYLOAD_GATEWAY_OFFER: u8 = 64;
pub const P1_PAYLOAD_RELAY_CANDIDATE_LAYER: u8 = 65;
pub const P1_PAYLOAD_COMMIT: u8 = 80;
pub const P1_PAYLOAD_READY: u8 = 81;
pub const P1_PAYLOAD_RENDEZVOUS_OPEN: u8 = 82;
pub const P1_PAYLOAD_RENDEZVOUS_RESULT: u8 = 83;
pub const P1_PAYLOAD_DATA: u8 = 84;
pub const P1_PAYLOAD_CLOSE: u8 = 85;

pub const ERROR_MALFORMED: u16 = 1;
pub const ERROR_UNSUPPORTED_VERSION: u16 = 2;
pub const ERROR_UNSUPPORTED_PROFILE: u16 = 3;
pub const ERROR_UNSUPPORTED_SUITE: u16 = 4;
pub const ERROR_AUTHENTICATION_FAILED: u16 = 5;
pub const ERROR_REPLAY: u16 = 6;
pub const ERROR_EXPIRED: u16 = 7;
pub const ERROR_RESOURCE_EXHAUSTED: u16 = 8;
pub const ERROR_STATE_VIOLATION: u16 = 9;
pub const ERROR_CAPABILITY_INVALID: u16 = 10;
pub const ERROR_TIMEOUT: u16 = 11;
pub const ERROR_CANCELLED: u16 = 12;
pub const ERROR_INTERNAL: u16 = 13;

pub const BYTES_SUITE_ID: usize = 2;
pub const BYTES_BRANCH_TOKEN: usize = 16;
pub const BYTES_CANDIDATE_TOKEN: usize = 16;
pub const BYTES_LOCAL_LABEL: usize = 16;
pub const BYTES_TRANSMISSION_ID: usize = 16;
pub const BYTES_NEGOTIATION_ID: usize = 16;
pub const BYTES_REPLY_PUBLIC_KEY: usize = 32;
pub const BYTES_R1_DISCOVERY_NONCE: usize = 32;
pub const BYTES_R1_CAPABILITY: usize = 32;
pub const BYTES_GATEWAY_PSEUDONYM: usize = 16;
pub const BYTES_ROUTE_SECRET: usize = 32;
pub const BYTES_LINK_EPOCH: usize = 4;
pub const BYTES_LINK_SEQUENCE: usize = 8;
pub const BYTES_LINK_HEADER: usize = 12;
pub const BYTES_LINK_TAG: usize = 16;
pub const BYTES_CELL_BODY: usize = 1024;
pub const BYTES_CELL_HEADER: usize = 32;
pub const BYTES_CELL_PAYLOAD: usize = 992;
pub const BYTES_CELL_RECORD: usize = 1052;
pub const BYTES_REPLY_ENCAPSULATION: usize = 32;
pub const BYTES_REPLY_AEAD_TAG: usize = 16;
pub const BYTES_REPLY_KEY_COMMITMENT: usize = 32;

pub const LIMIT_MAX_LOGICAL_MESSAGE_BYTES: usize = 16384;
pub const LIMIT_MAX_CONTROL_PROTECTED_BYTES: usize = 8192;
pub const LIMIT_MAX_FRAGMENTS: usize = 17;
pub const LIMIT_MAX_REASSEMBLY_MESSAGES_PER_PEER: usize = 64;
pub const LIMIT_MAX_REASSEMBLY_BYTES_GLOBAL: usize = 131072;
pub const LIMIT_REASSEMBLY_TIMEOUT_MS: usize = 1500;
pub const LIMIT_MAX_SENDER_TRANSMISSIONS_PER_PEER: usize = 64;
pub const LIMIT_MAX_ROUTES_PER_PEER: usize = 256;
pub const LIMIT_MAX_ROUTES_GLOBAL: usize = 2048;
pub const LIMIT_MAX_CANDIDATE_LAYERS: usize = 16;
pub const LIMIT_MAX_T1_RETRIES: usize = 8;
pub const LIMIT_T1_RTO_MS: usize = 100;
pub const LIMIT_REPLAY_WINDOW_CELLS: usize = 1024;
pub const LIMIT_COMPLETION_CACHE_MS: usize = 1000;
pub const LIMIT_ROUTE_TTL_MS: usize = 5000;
pub const LIMIT_CAPABILITY_TTL_MS: usize = 5000;
pub const LIMIT_MAX_FAILED_REDEMPTIONS_PER_ROUTE: usize = 2;

pub const FIXED_T2_PROFILE_ID: usize = 1;
pub const FIXED_T2_EPOCH_MS: usize = 200;
pub const FIXED_T2_CELLS_PER_EPOCH: usize = 16;
pub const FIXED_T2_SLOT_INTERVAL_US: usize = 12500;
pub const FIXED_T2_ACK_RESERVE_PER_EPOCH: usize = 4;
pub const FIXED_T2_RETRANSMIT_RESERVE_PER_EPOCH: usize = 4;
pub const FIXED_T2_QUEUE_CELLS_PER_PEER: usize = 256;
pub const FIXED_T2_QUEUE_CELLS_GLOBAL: usize = 2048;
pub const FIXED_T2_MODE: &str = "fixed";

pub const DOMAIN_C1_LABEL_PREFIX: &[u8] = b"Trahens-C1-v2";
pub const DOMAIN_C1_SCALAR: &[u8] = b"Trahens-C1-scalar-v2";
pub const DOMAIN_C1_ELEMENT: &[u8] = b"Trahens-C1-element-v2";
pub const DOMAIN_C1_URE_R0: &[u8] = b"Trahens-C1-ure-r0-v2";
pub const DOMAIN_C1_URE_R1: &[u8] = b"Trahens-C1-ure-r1-v2";
pub const DOMAIN_C1_URE_S0: &[u8] = b"Trahens-C1-ure-s0-v2";
pub const DOMAIN_C1_URE_S1: &[u8] = b"Trahens-C1-ure-s1-v2";
pub const DOMAIN_C1_REPLY_EPHEMERAL: &[u8] = b"Trahens-C1-reply-ephemeral-v2";
pub const DOMAIN_C1_CANDIDATE_AAD: &[u8] = b"Trahens-C1-candidate-layer-aad-v2";
pub const DOMAIN_C1_CANDIDATE_INFO: &[u8] = b"Trahens-C1-candidate-layer-info-v2";
pub const DOMAIN_C1_COMMIT: &[u8] = b"Trahens-C1-COMMIT-v2";
pub const DOMAIN_C1_READY: &[u8] = b"Trahens-C1-READY-v2";
pub const DOMAIN_C1_ACTIVE_TAG_SCALAR: &[u8] = b"Trahens-C1-active-tag-scalar-v2";
pub const DOMAIN_C1_REPLY_COMMIT: &[u8] = b"Trahens-C1-reply-key-commitment-v2";
pub const DOMAIN_W2_LINK_KEY: &[u8] = b"Trahens-W2-link-key-v1";
pub const DOMAIN_R1_CAPABILITY: &[u8] = b"Trahens-R1-capability-v1";
pub const DOMAIN_P1_ROUTE_KEY: &[u8] = b"Trahens-P1-route-key-v1";
