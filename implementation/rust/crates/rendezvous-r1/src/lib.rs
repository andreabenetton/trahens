#![forbid(unsafe_code)]
#![doc = "Bounded one-time R1 rendezvous capability registry."]

use protocol_registry::{DOMAIN_R1_CAPABILITY, LIMIT_MAX_ROUTES_GLOBAL};
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
    pub endpoint_handle: Vec<u8>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Default)]
pub struct Registry {
    records: HashMap<(u32, [u8; 32]), Registration>,
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
        token: &SecretBytes<32>,
        endpoint_handle: Vec<u8>,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<(), RendezvousError> {
        if ttl_ms == 0 || endpoint_handle.is_empty() {
            return Err(RendezvousError::Invalid);
        }
        if self.records.len() >= LIMIT_MAX_ROUTES_GLOBAL {
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

    #[test]
    fn one_time_wrong_gateway_and_expiry() -> Result<(), RendezvousError> {
        let mut registry = Registry::default();
        let token = SecretBytes([1_u8; 32]);
        registry.register(7, &token, b"endpoint".to_vec(), 10, 5)?;
        assert_eq!(registry.redeem(8, &token, 11)?, None);
        assert_eq!(registry.live_records(), 1);
        assert_eq!(registry.redeem(7, &token, 11)?, Some(b"endpoint".to_vec()));
        assert_eq!(registry.redeem(7, &token, 11)?, None);

        let expired = SecretBytes([2_u8; 32]);
        registry.register(7, &expired, b"endpoint".to_vec(), 20, 2)?;
        assert_eq!(registry.redeem(7, &expired, 22)?, None);
        Ok(())
    }
}
