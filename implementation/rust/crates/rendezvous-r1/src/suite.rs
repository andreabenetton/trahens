// SPDX-License-Identifier: Apache-2.0
#![doc = "Eligibility-suite interface and its providers."]

//! `spec/eligibility-suite-interface-v1.md` requires lifecycle code to depend
//! on this interface rather than importing a concrete eligibility scheme.
//! Every operation shares one uniform failure class so a rejection reveals
//! nothing about which check failed.

use protocol_registry::{SUITE_C1_V2, SUITE_C2_K2_DISABLED, SUITE_R1};
use trahens_crypto::{c1, random_bytes, CryptoError};

/// The single externally observable failure class for every suite operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EligibilityFailure;

impl std::fmt::Display for EligibilityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("eligibility operation failed")
    }
}

impl std::error::Error for EligibilityFailure {}

impl From<CryptoError> for EligibilityFailure {
    fn from(_value: CryptoError) -> Self {
        Self
    }
}

/// Which side of a hop is evaluating a discovery field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Relay,
    Gateway,
}

/// `Initial`, `Transform`, and `Accept` over a suite's discovery field.
pub trait EligibilitySuite {
    /// Registry suite identifier.
    fn suite_id(&self) -> [u8; 2];

    /// False for research-only providers, which a production configuration
    /// MUST NOT select.
    fn network_enabled(&self) -> bool;

    /// Produce a fresh discovery field for an endpoint.
    fn initial(&self) -> Result<Vec<u8>, EligibilityFailure>;

    /// Replace the field at a relay so it is unlinkable to its predecessor.
    fn transform(&self, field: &[u8]) -> Result<Vec<u8>, EligibilityFailure>;

    /// Decide whether a field is well formed for this role.
    fn accepts(&self, role: Role, field: &[u8]) -> bool;
}

/// R1: the active P1 provider. The discovery field is a fresh 32-byte nonce
/// replaced at every hop, carrying no endpoint-specific material.
#[derive(Debug, Clone, Copy, Default)]
pub struct R1Suite;

impl R1Suite {
    /// Width of an R1 discovery nonce.
    pub const NONCE_BYTES: usize = 32;

    fn fresh_nonce() -> Result<[u8; 32], EligibilityFailure> {
        for _ in 0..32 {
            let value = random_bytes::<32>()?;
            if value != [0_u8; 32] {
                return Ok(value);
            }
        }
        Err(EligibilityFailure)
    }
}

impl EligibilitySuite for R1Suite {
    fn suite_id(&self) -> [u8; 2] {
        SUITE_R1
    }

    fn network_enabled(&self) -> bool {
        true
    }

    fn initial(&self) -> Result<Vec<u8>, EligibilityFailure> {
        Ok(Self::fresh_nonce()?.to_vec())
    }

    fn transform(&self, field: &[u8]) -> Result<Vec<u8>, EligibilityFailure> {
        if !self.accepts(Role::Relay, field) {
            return Err(EligibilityFailure);
        }
        // Replacement, not derivation: the outgoing nonce must be independent
        // of the incoming one.
        Ok(Self::fresh_nonce()?.to_vec())
    }

    fn accepts(&self, _role: Role, field: &[u8]) -> bool {
        field.len() == Self::NONCE_BYTES && field.iter().any(|byte| *byte != 0)
    }
}

/// C1: research-only, never selected on the network (ADR 0038).
#[derive(Debug, Clone, Copy, Default)]
pub struct C1Suite;

impl EligibilitySuite for C1Suite {
    fn suite_id(&self) -> [u8; 2] {
        SUITE_C1_V2
    }

    fn network_enabled(&self) -> bool {
        false
    }

    fn initial(&self) -> Result<Vec<u8>, EligibilityFailure> {
        let keys = c1::build_endpoint_keys(b"c1-provider")?;
        let capsule = c1::ure_encrypt(
            &keys.eligibility_public,
            None,
            &trahens_crypto::random_scalar()?,
            &trahens_crypto::random_scalar()?,
        )?;
        Ok(capsule.encode()?.to_vec())
    }

    fn transform(&self, field: &[u8]) -> Result<Vec<u8>, EligibilityFailure> {
        let capsule = c1::UreCiphertext::decode(field)?;
        let rerandomized = c1::ure_rerandomize(
            &capsule,
            &trahens_crypto::random_scalar()?,
            &trahens_crypto::random_scalar()?,
        )?;
        Ok(rerandomized.encode()?.to_vec())
    }

    fn accepts(&self, _role: Role, field: &[u8]) -> bool {
        c1::UreCiphertext::decode(field).is_ok()
    }
}

/// True when a suite identifier may appear on the network.
///
/// The symbolic C2 suite is research-only but has a defined parser
/// (`message-codec-m2.md`); the k=2 audit suite `0x7f02` and the retired C1 v1
/// suite are rejected outright.
#[must_use]
pub fn suite_is_selectable_for_production(suite: [u8; 2]) -> bool {
    suite == SUITE_R1
}

/// Suites a network decoder must never admit.
#[must_use]
pub fn suite_is_rejected(suite: [u8; 2]) -> bool {
    suite == SUITE_C2_K2_DISABLED
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_registry::SUITE_C2_SYMBOLIC;

    #[test]
    fn r1_replaces_the_nonce_at_every_hop() -> Result<(), EligibilityFailure> {
        let suite = R1Suite;
        assert_eq!(suite.suite_id(), SUITE_R1);
        assert!(suite.network_enabled());

        let first = suite.initial()?;
        assert!(suite.accepts(Role::Relay, &first));
        assert!(suite.accepts(Role::Gateway, &first));

        let second = suite.transform(&first)?;
        assert_ne!(first, second, "the nonce is replaced, never derived");
        assert!(suite.accepts(Role::Relay, &second));

        // Malformed fields share one failure class.
        assert!(!suite.accepts(Role::Relay, &[0_u8; 32]));
        assert!(!suite.accepts(Role::Relay, &[1_u8; 31]));
        assert_eq!(suite.transform(&[0_u8; 32]), Err(EligibilityFailure));
        Ok(())
    }

    #[test]
    fn c1_is_research_only_and_rerandomizes() -> Result<(), EligibilityFailure> {
        let suite = C1Suite;
        assert_eq!(suite.suite_id(), SUITE_C1_V2);
        assert!(
            !suite.network_enabled(),
            "C1 must never be selected on the network"
        );
        let first = suite.initial()?;
        let second = suite.transform(&first)?;
        assert_ne!(first, second);
        assert!(suite.accepts(Role::Relay, &second));
        Ok(())
    }

    #[test]
    fn only_r1_is_selectable_and_the_audit_suite_is_rejected() {
        assert!(suite_is_selectable_for_production(SUITE_R1));
        assert!(!suite_is_selectable_for_production(SUITE_C1_V2));
        assert!(!suite_is_selectable_for_production(SUITE_C2_SYMBOLIC));
        assert!(suite_is_rejected(SUITE_C2_K2_DISABLED));
        assert!(!suite_is_rejected(SUITE_R1));
    }
}
