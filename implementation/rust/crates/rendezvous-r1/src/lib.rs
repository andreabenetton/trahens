// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "Bounded one-time R1 rendezvous capability registry."]

pub mod suite;

use protocol_registry::{
    BYTES_R1_CAPABILITY, DOMAIN_R1_CAPABILITY, LIMIT_ENDPOINT_HANDLE_TTL_MS,
    LIMIT_MAX_REGISTRATIONS_PER_ENDPOINT, LIMIT_MAX_REGISTRATIONS_PER_GATEWAY,
    LIMIT_MAX_ROUTES_GLOBAL,
};
use std::collections::HashMap;
use trahens_crypto::{sha256, CryptoError, SecretBytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendezvousError {
    Invalid,
    Duplicate,
    Exhausted,
    Crypto,
}

impl From<CryptoError> for RendezvousError {
    fn from(_value: CryptoError) -> Self {
        Self::Crypto
    }
}

impl std::fmt::Display for RendezvousError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "invalid rendezvous capability",
            Self::Duplicate => "duplicate rendezvous capability",
            Self::Exhausted => "rendezvous state exhausted",
            Self::Crypto => "rendezvous cryptographic failure",
        })
    }
}

impl std::error::Error for RendezvousError {}

#[derive(Debug)]
pub struct Registration {
    pub gateway_id: u32,
    /// The short-lived pseudonym this gateway advertised for the route
    /// (`rendezvous-capability-r1.md` section 3). Redemption must present the
    /// same pseudonym, so a capability is bound to the advertisement it
    /// arrived with rather than to the gateway identity alone.
    pub gateway_pseudonym: [u8; 16],
    pub endpoint_handle: Vec<u8>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Default)]
pub struct Registry {
    records: HashMap<(u32, [u8; 32]), Registration>,
}

/// Domain for the commitment a client presents to prove capability
/// possession. Distinct from the gateway-local record key below; the Python
/// reference uses the same separation.
const DOMAIN_R1_CAPABILITY_COMMITMENT: &[u8] = b"Trahens-R1-capability-commitment-v1";

/// Issue a fresh non-zero capability token.
pub fn issue_capability() -> Result<SecretBytes<32>, RendezvousError> {
    for _ in 0..32 {
        let value = trahens_crypto::random_bytes::<32>().map_err(|_| RendezvousError::Crypto)?;
        if value != [0_u8; BYTES_R1_CAPABILITY] {
            return Ok(SecretBytes(value));
        }
    }
    Err(RendezvousError::Crypto)
}

/// Commitment to a capability, revealing nothing about the token itself.
pub fn capability_commitment(token: &[u8; 32]) -> Result<[u8; 32], RendezvousError> {
    if *token == [0_u8; BYTES_R1_CAPABILITY] {
        return Err(RendezvousError::Invalid);
    }
    let mut input = Vec::with_capacity(DOMAIN_R1_CAPABILITY_COMMITMENT.len() + token.len());
    input.extend_from_slice(DOMAIN_R1_CAPABILITY_COMMITMENT);
    input.extend_from_slice(token);
    Ok(sha256(&input)?)
}

fn token_hash(token: &[u8; 32]) -> Result<[u8; 32], RendezvousError> {
    if *token == [0_u8; 32] {
        return Err(RendezvousError::Invalid);
    }
    let mut input = Vec::with_capacity(DOMAIN_R1_CAPABILITY.len() + token.len());
    input.extend_from_slice(DOMAIN_R1_CAPABILITY);
    input.extend_from_slice(token);
    Ok(sha256(&input)?)
}

impl Registry {
    pub fn register(
        &mut self,
        gateway_id: u32,
        gateway_pseudonym: [u8; 16],
        token: &SecretBytes<32>,
        endpoint_handle: Vec<u8>,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<(), RendezvousError> {
        if ttl_ms == 0 || endpoint_handle.is_empty() || gateway_pseudonym == [0_u8; 16] {
            return Err(RendezvousError::Invalid);
        }
        if ttl_ms > LIMIT_ENDPOINT_HANDLE_TTL_MS as u64 {
            return Err(RendezvousError::Invalid);
        }
        // section 7: bound registrations globally, per gateway, and per
        // endpoint handle.
        if self.records.len() >= LIMIT_MAX_ROUTES_GLOBAL {
            return Err(RendezvousError::Exhausted);
        }
        let per_gateway = self
            .records
            .values()
            .filter(|record| record.gateway_id == gateway_id)
            .count();
        if per_gateway >= LIMIT_MAX_REGISTRATIONS_PER_GATEWAY {
            return Err(RendezvousError::Exhausted);
        }
        let per_endpoint = self
            .records
            .values()
            .filter(|record| record.endpoint_handle == endpoint_handle)
            .count();
        if per_endpoint >= LIMIT_MAX_REGISTRATIONS_PER_ENDPOINT {
            return Err(RendezvousError::Exhausted);
        }
        let digest = token_hash(&token.0)?;
        let key = (gateway_id, digest);
        if self.records.contains_key(&key) {
            return Err(RendezvousError::Duplicate);
        }
        self.records.insert(
            key,
            Registration {
                gateway_id,
                gateway_pseudonym,
                endpoint_handle,
                created_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add(ttl_ms),
            },
        );
        Ok(())
    }

    pub fn redeem(
        &mut self,
        gateway_id: u32,
        token: &SecretBytes<32>,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, RendezvousError> {
        let digest = token_hash(&token.0)?;
        let key = (gateway_id, digest);
        let Some(record) = self.records.remove(&key) else {
            return Ok(None);
        };
        if record.created_at_ms <= now_ms && now_ms < record.expires_at_ms {
            Ok(Some(record.endpoint_handle))
        } else {
            Ok(None)
        }
    }

    /// Redeem, additionally requiring the advertised pseudonym to match.
    ///
    /// Every failure returns `None`, so replay, wrong gateway, wrong pseudonym
    /// and expiry stay one generic outcome to the caller. Only a match consumes
    /// the record: a wrong pseudonym leaves it live, exactly as a wrong gateway
    /// already did by addressing a different key. Consuming on mismatch let
    /// anyone holding the capability but not the pseudonym destroy a live
    /// registration, and the uniform return value means declining to consume
    /// tells a prober nothing.
    pub fn redeem_for_pseudonym(
        &mut self,
        gateway_id: u32,
        gateway_pseudonym: &[u8; 16],
        token: &SecretBytes<32>,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, RendezvousError> {
        let digest = token_hash(&token.0)?;
        let key = (gateway_id, digest);
        let Some(record) = self.records.get(&key) else {
            return Ok(None);
        };
        if record.gateway_pseudonym != *gateway_pseudonym
            || record.created_at_ms > now_ms
            || now_ms >= record.expires_at_ms
        {
            return Ok(None);
        }
        Ok(self
            .records
            .remove(&key)
            .map(|record| record.endpoint_handle))
    }

    pub fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.records.len();
        self.records
            .retain(|_, record| now_ms < record.expires_at_ms);
        before - self.records.len()
    }

    pub fn live_records(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_registry::SUITE_R1;

    const PSEUDONYM: [u8; 16] = [0x5a; 16];

    /// R1 is one-time *per gateway*, not globally. A destination may register
    /// one capability at several gateways, and each registration redeems once.
    /// Pinned as a test because the paper previously claimed the global
    /// property: if the semantics are ever changed to global one-shot, this
    /// fails and the claim has to be revisited deliberately.
    #[test]
    fn one_capability_redeems_once_at_each_registered_gateway() -> Result<(), RendezvousError> {
        let mut registry = Registry::default();
        let token = SecretBytes([3_u8; 32]);
        registry.register(1, PSEUDONYM, &token, b"handle".to_vec(), 0, 100)?;
        registry.register(2, PSEUDONYM, &token, b"handle".to_vec(), 0, 100)?;
        assert_eq!(registry.live_records(), 2);

        assert_eq!(registry.redeem(1, &token, 1)?, Some(b"handle".to_vec()));
        assert_eq!(
            registry.redeem(2, &token, 1)?,
            Some(b"handle".to_vec()),
            "the second gateway's registration is independent"
        );
        assert_eq!(
            registry.redeem(1, &token, 1)?,
            None,
            "neither redeems twice"
        );
        assert_eq!(registry.redeem(2, &token, 1)?, None);
        assert_eq!(registry.live_records(), 0);
        Ok(())
    }

    #[test]
    fn one_time_wrong_gateway_and_expiry() -> Result<(), RendezvousError> {
        let mut registry = Registry::default();
        let token = SecretBytes([1_u8; 32]);
        registry.register(7, [9_u8; 16], &token, b"endpoint".to_vec(), 10, 5)?;
        assert_eq!(registry.redeem(8, &token, 11)?, None);
        assert_eq!(registry.live_records(), 1);
        assert_eq!(registry.redeem(7, &token, 11)?, Some(b"endpoint".to_vec()));
        assert_eq!(registry.redeem(7, &token, 11)?, None);

        let expired = SecretBytes([2_u8; 32]);
        registry.register(7, [9_u8; 16], &expired, b"endpoint".to_vec(), 20, 2)?;
        assert_eq!(registry.redeem(7, &expired, 22)?, None);
        Ok(())
    }

    #[test]
    fn published_r1_capability_vector_matches() -> Result<(), RendezvousError> {
        // spec/r1-test-vectors.json had no consumer on either side: only a
        // regeneration byte-compare in check_repo.sh. It pins the behaviours
        // this registry reimplements independently of the Python reference.
        let vectors = test_vectors::r1().map_err(|_| RendezvousError::Invalid)?;

        assert_eq!(
            test_vectors::hex_at(&vectors, "suite_id").map_err(|_| RendezvousError::Invalid)?,
            SUITE_R1.to_vec(),
            "suite id"
        );
        assert_eq!(
            test_vectors::u64_at(&vectors, "sizes/capability_bytes")
                .map_err(|_| RendezvousError::Invalid)? as usize,
            BYTES_R1_CAPABILITY,
        );

        let token = SecretBytes(
            test_vectors::hex_array_at::<32>(&vectors, "capability/token")
                .map_err(|_| RendezvousError::Invalid)?,
        );
        let handle = test_vectors::hex_at(&vectors, "capability/endpoint_handle")
            .map_err(|_| RendezvousError::Invalid)?;
        let gateway_id = u32::try_from(
            test_vectors::u64_at(&vectors, "capability/gateway_id")
                .map_err(|_| RendezvousError::Invalid)?,
        )
        .map_err(|_| RendezvousError::Invalid)?;
        let created = test_vectors::u64_at(&vectors, "capability/created_at_ms")
            .map_err(|_| RendezvousError::Invalid)?;
        let expires = test_vectors::u64_at(&vectors, "capability/expires_at_ms")
            .map_err(|_| RendezvousError::Invalid)?;

        // The client-presented commitment and the gateway-local record key
        // use distinct domains and must both match.
        assert_eq!(
            capability_commitment(&token.0)?.to_vec(),
            test_vectors::hex_at(&vectors, "capability/commitment")
                .map_err(|_| RendezvousError::Invalid)?,
            "capability commitment"
        );
        assert_eq!(
            token_hash(&token.0)?.to_vec(),
            test_vectors::hex_at(&vectors, "capability/registry_hash")
                .map_err(|_| RendezvousError::Invalid)?,
            "gateway-local registry hash"
        );

        let mut registry = Registry::default();
        registry.register(
            gateway_id,
            PSEUDONYM,
            &token,
            handle.clone(),
            created,
            expires - created,
        )?;

        // A wrong gateway is rejected and leaves the record intact.
        assert!(
            test_vectors::value_is_null(&vectors, "capability/wrong_gateway_redemption"),
            "vector expects no handle for the wrong gateway"
        );
        assert_eq!(registry.redeem(gateway_id + 1, &token, created + 1)?, None);
        assert_eq!(registry.live_records(), 1);

        // First redemption returns the handle; the replay returns nothing.
        assert_eq!(
            registry.redeem(gateway_id, &token, created + 1)?,
            Some(
                test_vectors::hex_at(&vectors, "capability/first_redemption")
                    .map_err(|_| RendezvousError::Invalid)?
            ),
            "first redemption"
        );
        assert!(test_vectors::value_is_null(
            &vectors,
            "capability/replay_redemption"
        ));
        assert_eq!(registry.redeem(gateway_id, &token, created + 1)?, None);
        assert_eq!(
            registry.live_records(),
            test_vectors::u64_at(&vectors, "capability/live_records_after_redemption")
                .map_err(|_| RendezvousError::Invalid)? as usize,
        );

        // An expired capability yields nothing and leaves no live record.
        let mut registry = Registry::default();
        registry.register(
            gateway_id,
            PSEUDONYM,
            &token,
            handle,
            created,
            expires - created,
        )?;
        assert_eq!(registry.redeem(gateway_id, &token, expires)?, None);
        assert_eq!(
            registry.live_records(),
            test_vectors::u64_at(&vectors, "capability/expired_live_records")
                .map_err(|_| RendezvousError::Invalid)? as usize,
        );

        // An all-zero token is never a valid capability.
        assert_eq!(token_hash(&[0_u8; 32]), Err(RendezvousError::Invalid));

        // A wrong advertised pseudonym fails exactly like any other bad
        // redemption, but must not consume the record: otherwise anyone holding
        // the capability without the pseudonym could destroy a live
        // registration, and the legitimate endpoint would find nothing left.
        let mut registry = Registry::default();
        registry.register(
            gateway_id,
            PSEUDONYM,
            &token,
            b"handle".to_vec(),
            created,
            expires - created,
        )?;
        assert_eq!(
            registry.redeem_for_pseudonym(gateway_id, &[0xff; 16], &token, created + 1)?,
            None,
            "wrong pseudonym is rejected"
        );
        assert_eq!(
            registry.live_records(),
            1,
            "and the registration survives for its rightful holder"
        );
        assert_eq!(
            registry.redeem_for_pseudonym(gateway_id, &PSEUDONYM, &token, created + 1)?,
            Some(b"handle".to_vec()),
            "which can still redeem it"
        );
        assert_eq!(registry.live_records(), 0, "and that consumes it");
        Ok(())
    }
}
