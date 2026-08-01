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

/// Refuse a provider that must not drive a live node.
///
/// The check is deliberately at the provider, not at the call site: nothing
/// else stops a node being wired to a research-only suite, and the failure
/// would be silent — research crypto on the wire, with the run still looking
/// healthy. Selecting one is a configuration error, so it fails at startup.
///
/// C1 is refused on three independent grounds, any one of which is decisive:
/// it declares itself not network enabled (ADR 0038 decision 1), its suite
/// identifier is not selectable for production, and the P1 semantics above M2
/// are bound to a 32-byte R1 nonce.
///
/// The last is not about encoding. `message-codec-m2.md` already gives
/// `discovery_field` a length prefix and already fixes R1 at 32 bytes, C1 v2
/// at 128, and symbolic C2 at 640, so M2 can carry a capsule today. The
/// obstacle is that one 32-byte value currently does three jobs at once: it is
/// the eligibility field, it binds each link of the returned candidate chain,
/// and it is the key the per-offer labels are derived from. It is not carried
/// end to end — each hop replaces it independently, which is the U1 property —
/// but every hop's value is 32 bytes and all three jobs assume that.
///
/// Separating the routing nonce from the eligibility field is what makes any
/// suite selectable, and that is a profile revision rather than a flag.
pub fn require_network_provider<S: EligibilitySuite + ?Sized>(
    suite: &S,
) -> Result<(), EligibilityFailure> {
    if !suite.network_enabled() || !suite_is_selectable_for_production(suite.suite_id()) {
        return Err(EligibilityFailure);
    }
    Ok(())
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

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn only_a_network_enabled_provider_may_drive_a_node() {
        // R1 is the mandatory P1 provider.
        assert!(require_network_provider(&R1Suite).is_ok());

        // C1 is refused, and on grounds that do not depend on each other.
        assert!(require_network_provider(&C1Suite).is_err());
        assert!(!C1Suite.network_enabled(), "declares itself research-only");
        assert!(
            !suite_is_selectable_for_production(C1Suite.suite_id()),
            "its identifier is not selectable for production"
        );
    }

    #[test]
    fn the_c1_discovery_field_does_not_fit_the_p1_chain() -> Result<(), EligibilityFailure> {
        // The structural half of the boundary, which no flag could turn off:
        // P1 carries a 32-byte discovery nonce at every hop, derives offer
        // labels from it, and compares it layer by layer in the candidate
        // chain. C1's field is a four-point URE capsule.
        let r1 = R1Suite.initial()?;
        let c1 = C1Suite.initial()?;
        assert_eq!(r1.len(), 32, "P1 carries a 32-byte nonce");
        assert_eq!(c1.len(), 128, "C1 carries a four-point capsule");
        assert_ne!(r1.len(), c1.len());

        // Both still round-trip through their own transform, which is what
        // the library exists to check.
        assert_eq!(R1Suite.transform(&r1)?.len(), r1.len());
        assert_eq!(C1Suite.transform(&c1)?.len(), c1.len());
        Ok(())
    }
}
