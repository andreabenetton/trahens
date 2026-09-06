// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "B1.2 stateless admission cookie."]

//! Implements `spec/admission-cookie-b12.md`: an HMAC over the observed
//! source, the time window and the parameters offered so far, under a rotating
//! responder secret, checkable before any public-key operation or handshake
//! allocation.
//!
//! It is a denial-of-service control and **not** an identity proof. A sender
//! that presents a valid cookie has shown that it receives datagrams at the
//! address it claims, and nothing else.

pub mod advertisement;
pub mod invitation;
pub use advertisement::Advertisement;
pub use invitation::{invitation_psk, Invitation};

use protocol_registry::{
    BYTES_B12_COOKIE, DOMAIN_B12_COOKIE, LIMIT_COOKIE_WINDOWS_ACCEPTED, LIMIT_COOKIE_WINDOW_MS,
};
use trahens_crypto::{constant_time_equal, hmac_sha256, CryptoError, SecretBytes};

pub const SECRET_BYTES: usize = 32;

/// Every failure is one outcome; a sender is never told which check refused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieError;

impl std::fmt::Display for CookieError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("B1.2 cookie failed")
    }
}

impl std::error::Error for CookieError {}

impl From<CryptoError> for CookieError {
    fn from(_value: CryptoError) -> Self {
        Self
    }
}

type Result<T> = std::result::Result<T, CookieError>;

/// Which window a moment falls in.
///
/// Absolute rather than relative to any node's start, so two responders agree
/// on the window regardless of uptime.
#[must_use]
pub fn window_id(now_ms: u64) -> u64 {
    now_ms / (LIMIT_COOKIE_WINDOW_MS as u64).max(1)
}

/// Compute the cookie for one (source, port, window, offer).
///
/// Every variable-length field is length-prefixed: without it a source address
/// and an offer could be split differently and build the same message, so a
/// cookie issued for one pair would verify for another.
pub fn issue(
    secret: &[u8; SECRET_BYTES],
    source: &[u8],
    port: u16,
    window: u64,
    offer: &[u8],
) -> Result<[u8; BYTES_B12_COOKIE]> {
    let mut message = Vec::with_capacity(DOMAIN_B12_COOKIE.len() + source.len() + offer.len() + 14);
    message.extend_from_slice(DOMAIN_B12_COOKIE);
    message.extend_from_slice(&length_prefix(source)?);
    message.extend_from_slice(source);
    message.extend_from_slice(&port.to_be_bytes());
    message.extend_from_slice(&window.to_be_bytes());
    message.extend_from_slice(&length_prefix(offer)?);
    message.extend_from_slice(offer);

    let full = hmac_sha256(secret, &message)?;
    let taken = full.get(..BYTES_B12_COOKIE).ok_or(CookieError)?;
    let mut cookie = [0_u8; BYTES_B12_COOKIE];
    cookie.copy_from_slice(taken);
    Ok(cookie)
}

fn length_prefix(field: &[u8]) -> Result<[u8; 2]> {
    Ok(u16::try_from(field.len())
        .map_err(|_| CookieError)?
        .to_be_bytes())
}

/// Whether `cookie` is one this responder issued and still accepts.
///
/// `secrets` is newest first: the current window's, then the retained previous
/// ones. Every candidate is evaluated rather than returning on the first
/// match, so the time taken does not say which window the cookie came from.
#[must_use]
pub fn verify(
    secrets: &[SecretBytes<SECRET_BYTES>],
    cookie: &[u8],
    source: &[u8],
    port: u16,
    offer: &[u8],
    now_ms: u64,
) -> bool {
    if cookie.len() != BYTES_B12_COOKIE {
        return false;
    }
    let current = window_id(now_ms);
    let mut accepted = false;
    for (index, secret) in secrets
        .iter()
        .take(LIMIT_COOKIE_WINDOWS_ACCEPTED)
        .enumerate()
    {
        let Some(window) = current.checked_sub(index as u64) else {
            continue;
        };
        let Ok(expected) = issue(&secret.0, source, port, window, offer) else {
            continue;
        };
        accepted |= constant_time_equal(&expected, cookie);
    }
    accepted
}

/// The responder's rotating secrets, newest first.
///
/// More than one is retained because a cookie issued just before a window
/// boundary must still verify just after it; with a single secret every
/// rotation would reject the senders mid-exchange. The oldest is zeroized as
/// it falls out, so a cookie under a retired secret stops verifying even
/// inside a window that is otherwise still accepted.
pub struct Secrets {
    window: u64,
    secrets: Vec<SecretBytes<SECRET_BYTES>>,
}

impl Secrets {
    #[must_use]
    pub fn new(now_ms: u64, secret: [u8; SECRET_BYTES]) -> Self {
        Self {
            window: window_id(now_ms),
            secrets: vec![SecretBytes(secret)],
        }
    }

    /// Install `fresh` if the window has moved on, and drop what has aged out.
    ///
    /// The caller supplies the new secret rather than the type generating one,
    /// so a failure of randomness is handled where the rest of the node
    /// handles it instead of being swallowed here.
    pub fn rotate(&mut self, now_ms: u64, fresh: [u8; SECRET_BYTES]) {
        let current = window_id(now_ms);
        if current <= self.window {
            return;
        }
        self.window = current;
        self.secrets.insert(0, SecretBytes(fresh));
        while self.secrets.len() > LIMIT_COOKIE_WINDOWS_ACCEPTED {
            // SecretBytes zeroizes on drop, so aging out is what retires it.
            self.secrets.pop();
        }
    }

    #[must_use]
    pub fn verify(
        &self,
        cookie: &[u8],
        source: &[u8],
        port: u16,
        offer: &[u8],
        now_ms: u64,
    ) -> bool {
        verify(&self.secrets, cookie, source, port, offer, now_ms)
    }

    /// The current window's secret, for issuing.
    #[must_use]
    pub fn current(&self) -> Option<&[u8; SECRET_BYTES]> {
        self.secrets.first().map(|secret| &secret.0)
    }
}
