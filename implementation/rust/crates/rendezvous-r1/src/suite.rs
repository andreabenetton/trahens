// SPDX-License-Identifier: Apache-2.0
#![doc = "Eligibility-suite interface and its providers."]

//! `spec/eligibility-suite-interface-v1.md` requires lifecycle code to depend
//! on this interface rather than importing a concrete eligibility scheme.
//! Every operation shares one uniform failure class so a rejection reveals
//! nothing about which check failed.

use protocol_registry::{SUITE_C1_V2, SUITE_C2_K2_DISABLED, SUITE_R1};
use trahens_crypto::{c1, random_bytes, CryptoError, SecretBytes};

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

/// C1: universal re-encryption, selectable only on the experimental profile.
///
/// Unlike R1 the field is not inert: an initiator encrypts an eligibility
/// marker to a recipient's key, every relay rerandomises the capsule so no two
/// hops are linkable, and the recipient decides by decrypting. Which of those
/// three a node does depends on the key material it holds, so the provider
/// carries it rather than taking it per call.
#[derive(Default)]
pub struct C1Suite {
    /// Key an initiator encrypts to. Absent at a relay, which only
    /// rerandomises and needs nothing.
    recipient_public: Option<[u8; 32]>,
    /// Key a recipient tests with. Absent everywhere else, and a gateway
    /// without one is never eligible rather than always eligible.
    recipient_secret: Option<SecretBytes<32>>,
}

impl C1Suite {
    /// A relay: rerandomises, holds no keys, decides nothing.
    #[must_use]
    pub fn relay() -> Self {
        Self::default()
    }

    /// An initiator encrypting to `recipient_public`.
    #[must_use]
    pub fn initiator(recipient_public: [u8; 32]) -> Self {
        Self {
            recipient_public: Some(recipient_public),
            recipient_secret: None,
        }
    }

    /// A recipient testing capsules with its own secret.
    #[must_use]
    pub fn recipient(recipient_secret: SecretBytes<32>) -> Self {
        Self {
            recipient_public: None,
            recipient_secret: Some(recipient_secret),
        }
    }
}

impl EligibilitySuite for C1Suite {
    fn suite_id(&self) -> [u8; 2] {
        SUITE_C1_V2
    }

    fn network_enabled(&self) -> bool {
        false
    }

    fn initial(&self) -> Result<Vec<u8>, EligibilityFailure> {
        // Only an initiator produces a field, and only to a known recipient.
        let recipient = self.recipient_public.ok_or(EligibilityFailure)?;
        let capsule = c1::ure_encrypt(
            &recipient,
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

    fn accepts(&self, role: Role, field: &[u8]) -> bool {
        let Ok(capsule) = c1::UreCiphertext::decode(field) else {
            return false;
        };
        match role {
            // A relay learns nothing and decides nothing: it checks the shape
            // and rerandomises. That is the property C1 exists for.
            Role::Relay => true,
            // The recipient is the only party that can tell whether a
            // discovery is for it, and it does so by decrypting.
            Role::Gateway => self
                .recipient_secret
                .as_ref()
                .is_some_and(|secret| c1::ure_is_eligible(&secret.0, &capsule)),
        }
    }
}

/// Which profile a node is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// The frozen mandatory path. R1 only.
    Mandatory,
    /// Research profiles. Admits any suite the registry calls network-valid,
    /// so C1 v2 is selectable while the retired C1 v1 and the disabled C2 k=2
    /// audit suite stay refused everywhere.
    Experimental,
}

/// Refuse a provider that must not drive a live node.
///
/// The check is deliberately at the provider, not at the call site: nothing
/// else stops a node being wired to a research-only suite, and the failure
/// would be silent — research crypto on the wire, with the run still looking
/// healthy. Selecting one is a configuration error, so it fails at startup.
///
/// On the mandatory profile C1 is refused because it declares itself not
/// network enabled and its identifier is not selectable for production. Since
/// v1.6 that is the whole of it: the routing-nonce split removed the
/// structural obstacle, so C1 is selectable on the experimental profile
/// (ADR 0040).
pub fn require_network_provider<S: EligibilitySuite + ?Sized>(
    suite: &S,
) -> Result<(), EligibilityFailure> {
    require_provider(Profile::Mandatory, suite)
}

/// Refuse a provider the given profile does not permit.
///
/// The mandatory profile still admits R1 alone. The experimental profile
/// admits what the registry calls network-valid, which is what makes C1
/// selectable without making it reachable by accident: selecting it takes an
/// explicit profile *and* an explicit suite.
pub fn require_provider<S: EligibilitySuite + ?Sized>(
    profile: Profile,
    suite: &S,
) -> Result<(), EligibilityFailure> {
    let permitted = match profile {
        Profile::Mandatory => {
            suite.network_enabled() && suite_is_selectable_for_production(suite.suite_id())
        }
        Profile::Experimental => protocol_registry::suite_is_network_valid(suite.suite_id()),
    };
    if permitted {
        Ok(())
    } else {
        Err(EligibilityFailure)
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
        let keys = c1::build_endpoint_keys(b"research-only")?;
        let suite = C1Suite::initiator(keys.eligibility_public);
        assert_eq!(suite.suite_id(), SUITE_C1_V2);
        assert!(
            !suite.network_enabled(),
            "C1 is never selected on the mandatory profile"
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
        assert!(require_network_provider(&C1Suite::relay()).is_err());
        assert!(
            !C1Suite::relay().network_enabled(),
            "declares itself research-only"
        );
        assert!(
            !suite_is_selectable_for_production(C1Suite::relay().suite_id()),
            "its identifier is not selectable for production"
        );
    }

    #[test]
    fn a_wider_eligibility_field_no_longer_blocks_selection() -> Result<(), EligibilityFailure> {
        // Before v1.6 this width difference was decisive, because one 32-byte
        // value was both the eligibility field and the routing nonce. Route
        // discovery now uses a separate nonce, so the widths may differ.
        let keys = c1::build_endpoint_keys(b"width-check")?;
        let r1 = R1Suite.initial()?;
        let c1_field = C1Suite::initiator(keys.eligibility_public).initial()?;
        assert_eq!(r1.len(), 32);
        assert_eq!(c1_field.len(), 128);

        // Each suite still round-trips its own transform, and neither accepts
        // the other's field.
        assert_eq!(R1Suite.transform(&r1)?.len(), r1.len());
        assert_eq!(C1Suite::relay().transform(&c1_field)?.len(), c1_field.len());
        assert!(!R1Suite.accepts(Role::Relay, &c1_field));
        assert!(!C1Suite::relay().accepts(Role::Relay, &r1));
        Ok(())
    }

    #[test]
    fn only_the_recipient_can_tell_a_c1_discovery_is_for_it() -> Result<(), EligibilityFailure> {
        // This is what C1 is for: a relay forwards and rerandomises without
        // learning anything, and the recipient decides by decrypting.
        let mine = c1::build_endpoint_keys(b"intended-recipient")?;
        let theirs = c1::build_endpoint_keys(b"someone-else")?;
        let field = C1Suite::initiator(mine.eligibility_public).initial()?;

        let recipient = C1Suite::recipient(SecretBytes(mine.eligibility_secret.0));
        assert!(recipient.accepts(Role::Gateway, &field), "addressed to me");

        let other = C1Suite::recipient(SecretBytes(theirs.eligibility_secret.0));
        assert!(
            !other.accepts(Role::Gateway, &field),
            "a gateway that is not the recipient declines"
        );

        // A relay accepts the shape and cannot decide, which is the property
        // that keeps the eligibility target hidden from the path.
        assert!(C1Suite::relay().accepts(Role::Relay, &field));
        assert!(
            !C1Suite::relay().accepts(Role::Gateway, &field),
            "no key, never eligible: absence must not read as acceptance"
        );

        // Rerandomising at a hop does not change who it is for.
        let hopped = C1Suite::relay().transform(&field)?;
        assert_ne!(hopped, field, "no two hops carry the same bytes");
        assert!(recipient.accepts(Role::Gateway, &hopped));
        assert!(!other.accepts(Role::Gateway, &hopped));
        Ok(())
    }
}
