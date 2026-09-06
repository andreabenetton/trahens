// SPDX-License-Identifier: Apache-2.0
//! The discovery advertisement datagram.
//!
//! Implements `spec/discovery-advertisement-b12.md`. One cell wide, because
//! discovery precedes any link and there is no encryption to hide a length
//! under; the first byte is a discriminator from the range
//! `link-handshake-b1.md` section 3 reserves.
//!
//! Verifying one shows that the advertiser holds the short-lived key and that
//! the fields are intact. It carries no binding to the admission identity the
//! advertiser will later use, so a verified advertisement is a hint about where
//! to try rather than a statement about who will answer.

use crate::CookieError;
use protocol_registry::{
    B12_DATAGRAM_ADVERTISEMENT, BYTES_B12_ADVERTISEMENT, BYTES_B12_ADVERTISEMENT_BODY,
    BYTES_B12_ADVERTISEMENT_SIGNATURE, BYTES_B12_COOKIE, DOMAIN_B12_ADVERTISEMENT,
    LIMIT_MAX_OFFERED_PROFILES_PER_CLASS,
};
use trahens_crypto::{sign, verify, SecretBytes};

type Result<T> = std::result::Result<T, CookieError>;

/// What `network-bootstrap-b1.md` section 6 permits, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    pub version: u8,
    /// The short-lived advertisement key of ADR 0045 D5, and the only identity
    /// this datagram carries.
    pub key: [u8; 32],
    pub expiry_ms: u64,
    pub capacity_class: u8,
    pub auth_modes: u8,
    pub w2_profiles: Vec<u8>,
    pub t1_profiles: Vec<u8>,
    pub t2_profiles: Vec<u8>,
    pub suites: Vec<u16>,
    pub cookie: Option<[u8; BYTES_B12_COOKIE]>,
}

fn push_list_u8(out: &mut Vec<u8>, values: &[u8]) -> Result<()> {
    if values.is_empty() || values.len() > LIMIT_MAX_OFFERED_PROFILES_PER_CLASS {
        return Err(CookieError);
    }
    out.push(u8::try_from(values.len()).map_err(|_| CookieError)?);
    out.extend_from_slice(values);
    Ok(())
}

fn push_list_u16(out: &mut Vec<u8>, values: &[u16]) -> Result<()> {
    if values.is_empty() || values.len() > LIMIT_MAX_OFFERED_PROFILES_PER_CLASS {
        return Err(CookieError);
    }
    out.push(u8::try_from(values.len()).map_err(|_| CookieError)?);
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
    Ok(())
}

fn take_list_u8(body: &[u8], cursor: &mut usize) -> Result<Vec<u8>> {
    let count = usize::from(*body.get(*cursor).ok_or(CookieError)?);
    *cursor += 1;
    if count == 0 || count > LIMIT_MAX_OFFERED_PROFILES_PER_CLASS {
        return Err(CookieError);
    }
    let taken = body
        .get(*cursor..*cursor + count)
        .ok_or(CookieError)?
        .to_vec();
    *cursor += count;
    Ok(taken)
}

fn take_list_u16(body: &[u8], cursor: &mut usize) -> Result<Vec<u16>> {
    let count = usize::from(*body.get(*cursor).ok_or(CookieError)?);
    *cursor += 1;
    if count == 0 || count > LIMIT_MAX_OFFERED_PROFILES_PER_CLASS {
        return Err(CookieError);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let pair = body.get(*cursor..*cursor + 2).ok_or(CookieError)?;
        values.push(u16::from_be_bytes([pair[0], pair[1]]));
        *cursor += 2;
    }
    Ok(values)
}

impl Advertisement {
    fn encode_body(&self) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(64);
        body.push(self.version);
        body.extend_from_slice(&self.key);
        body.extend_from_slice(&self.expiry_ms.to_be_bytes());
        body.push(self.capacity_class);
        body.push(self.auth_modes);
        push_list_u8(&mut body, &self.w2_profiles)?;
        push_list_u8(&mut body, &self.t1_profiles)?;
        push_list_u8(&mut body, &self.t2_profiles)?;
        push_list_u16(&mut body, &self.suites)?;
        match self.cookie {
            None => body.push(0),
            Some(cookie) => {
                body.push(1);
                body.extend_from_slice(&cookie);
            }
        }
        Ok(body)
    }

    fn decode_body(body: &[u8]) -> Result<Self> {
        if body.len() < 44 {
            return Err(CookieError);
        }
        let key: [u8; 32] = body
            .get(1..33)
            .ok_or(CookieError)?
            .try_into()
            .map_err(|_| CookieError)?;
        let expiry_bytes: [u8; 8] = body
            .get(33..41)
            .ok_or(CookieError)?
            .try_into()
            .map_err(|_| CookieError)?;
        let mut cursor = 43_usize;
        let w2_profiles = take_list_u8(body, &mut cursor)?;
        let t1_profiles = take_list_u8(body, &mut cursor)?;
        let t2_profiles = take_list_u8(body, &mut cursor)?;
        let suites = take_list_u16(body, &mut cursor)?;
        let present = *body.get(cursor).ok_or(CookieError)?;
        cursor += 1;
        let cookie = match present {
            0 => None,
            1 => {
                let taken: [u8; BYTES_B12_COOKIE] = body
                    .get(cursor..cursor + BYTES_B12_COOKIE)
                    .ok_or(CookieError)?
                    .try_into()
                    .map_err(|_| CookieError)?;
                cursor += BYTES_B12_COOKIE;
                Some(taken)
            }
            // Any other flag value is refused rather than read as present.
            _ => return Err(CookieError),
        };
        if cursor != body.len() {
            return Err(CookieError);
        }
        Ok(Self {
            version: body[0],
            key,
            expiry_ms: u64::from_be_bytes(expiry_bytes),
            capacity_class: body[41],
            auth_modes: body[42],
            w2_profiles,
            t1_profiles,
            t2_profiles,
            suites,
            cookie,
        })
    }
}

/// One signed datagram, exactly `b12_advertisement` bytes.
///
/// The signature covers the discriminator and the whole framed region, padding
/// included, so neither the type byte nor the padding can be altered without
/// detection.
pub fn encode(advertisement: &Advertisement, signing_secret: &SecretBytes<64>) -> Result<Vec<u8>> {
    let body = advertisement.encode_body()?;
    if body.len() + 2 > BYTES_B12_ADVERTISEMENT_BODY {
        return Err(CookieError);
    }
    let mut datagram = Vec::with_capacity(BYTES_B12_ADVERTISEMENT);
    datagram.push(B12_DATAGRAM_ADVERTISEMENT);
    datagram.extend_from_slice(
        &u16::try_from(body.len())
            .map_err(|_| CookieError)?
            .to_be_bytes(),
    );
    datagram.extend_from_slice(&body);
    datagram.resize(
        BYTES_B12_ADVERTISEMENT - BYTES_B12_ADVERTISEMENT_SIGNATURE,
        0,
    );

    let mut signed = Vec::with_capacity(DOMAIN_B12_ADVERTISEMENT.len() + datagram.len());
    signed.extend_from_slice(DOMAIN_B12_ADVERTISEMENT);
    signed.extend_from_slice(&datagram);
    datagram.extend_from_slice(&sign(signing_secret, &signed)?);
    if datagram.len() != BYTES_B12_ADVERTISEMENT {
        return Err(CookieError);
    }
    Ok(datagram)
}

/// Parse and verify. The key that signed is the key the datagram carries.
pub fn decode(datagram: &[u8]) -> Result<Advertisement> {
    if datagram.len() != BYTES_B12_ADVERTISEMENT
        || datagram.first() != Some(&B12_DATAGRAM_ADVERTISEMENT)
    {
        return Err(CookieError);
    }
    let split = BYTES_B12_ADVERTISEMENT - BYTES_B12_ADVERTISEMENT_SIGNATURE;
    let head = datagram.get(..split).ok_or(CookieError)?;
    let signature: [u8; BYTES_B12_ADVERTISEMENT_SIGNATURE] = datagram
        .get(split..)
        .ok_or(CookieError)?
        .try_into()
        .map_err(|_| CookieError)?;

    let framed = head.get(1..).ok_or(CookieError)?;
    let length = usize::from(u16::from_be_bytes([
        *framed.first().ok_or(CookieError)?,
        *framed.get(1).ok_or(CookieError)?,
    ]));
    if 2 + length > framed.len() {
        return Err(CookieError);
    }
    // The padding is inside the signed region, but it is checked here as well:
    // a receiver must not accept a datagram whose declared length leaves
    // anything but zeros behind it.
    if framed
        .get(2 + length..)
        .ok_or(CookieError)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(CookieError);
    }
    let advertisement = Advertisement::decode_body(framed.get(2..2 + length).ok_or(CookieError)?)?;

    let mut signed = Vec::with_capacity(DOMAIN_B12_ADVERTISEMENT.len() + head.len());
    signed.extend_from_slice(DOMAIN_B12_ADVERTISEMENT);
    signed.extend_from_slice(head);
    verify(&advertisement.key, &signed, &signature)?;
    Ok(advertisement)
}
