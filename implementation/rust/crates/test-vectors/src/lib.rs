// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "Loaders for the published spec test vectors, for use in Rust tests."]

pub use serde_json::Value;

/// Error returned when a vector file cannot be read as expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorError(pub String);

impl std::fmt::Display for VectorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "vector error: {}", self.0)
    }
}

impl std::error::Error for VectorError {}

fn parse(name: &str, raw: &str) -> Result<Value, VectorError> {
    serde_json::from_str(raw).map_err(|error| VectorError(format!("{name}: {error}")))
}

/// `spec/t1-test-vectors.json`.
pub fn t1() -> Result<Value, VectorError> {
    parse(
        "t1",
        include_str!("../../../../../spec/t1-test-vectors.json"),
    )
}

/// `spec/t2-test-vectors.json`.
pub fn t2() -> Result<Value, VectorError> {
    parse(
        "t2",
        include_str!("../../../../../spec/t2-test-vectors.json"),
    )
}

/// `spec/r1-test-vectors.json`.
pub fn r1() -> Result<Value, VectorError> {
    parse(
        "r1",
        include_str!("../../../../../spec/r1-test-vectors.json"),
    )
}

/// `spec/b1-test-vectors.json`.
pub fn b1() -> Result<Value, VectorError> {
    parse(
        "b1",
        include_str!("../../../../../spec/b1-test-vectors.json"),
    )
}

/// `spec/protocol-registry-v1.8.json`, the B1.1 draft.
///
/// v1.8 is not the active profile and generates no bindings, so a test that
/// needs a v1.8 width reads it from here rather than hardcoding a number the
/// registry is supposed to own.
pub fn protocol_registry_v18() -> Result<Value, VectorError> {
    parse(
        "protocol-registry-v1.8",
        include_str!("../../../../../spec/protocol-registry-v1.8.json"),
    )
}

/// `spec/crypto-test-vectors-c1.json`.
pub fn crypto_c1() -> Result<Value, VectorError> {
    parse(
        "crypto-c1",
        include_str!("../../../../../spec/crypto-test-vectors-c1.json"),
    )
}

/// Read a hex string at `path` (slash-separated) and decode it.
pub fn hex_at(root: &Value, path: &str) -> Result<Vec<u8>, VectorError> {
    let text = str_at(root, path)?;
    decode_hex(&text).ok_or_else(|| VectorError(format!("{path}: invalid hex")))
}

/// Read a hex string at `path` and decode it into a fixed-size array.
pub fn hex_array_at<const N: usize>(root: &Value, path: &str) -> Result<[u8; N], VectorError> {
    let bytes = hex_at(root, path)?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| VectorError(format!("{path}: expected {N} bytes")))
}

/// Read a string at `path`.
pub fn str_at(root: &Value, path: &str) -> Result<String, VectorError> {
    value_at(root, path)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| VectorError(format!("{path}: not a string")))
}

/// Read an unsigned integer at `path`.
pub fn u64_at(root: &Value, path: &str) -> Result<u64, VectorError> {
    value_at(root, path)?
        .as_u64()
        .ok_or_else(|| VectorError(format!("{path}: not an unsigned integer")))
}

/// Read a boolean at `path`.
pub fn bool_at(root: &Value, path: &str) -> Result<bool, VectorError> {
    value_at(root, path)?
        .as_bool()
        .ok_or_else(|| VectorError(format!("{path}: not a boolean")))
}

/// Read an array of unsigned integers at `path`.
pub fn u64_list_at(root: &Value, path: &str) -> Result<Vec<u64>, VectorError> {
    value_at(root, path)?
        .as_array()
        .ok_or_else(|| VectorError(format!("{path}: not an array")))?
        .iter()
        .map(|item| {
            item.as_u64()
                .ok_or_else(|| VectorError(format!("{path}: non-integer element")))
        })
        .collect()
}

/// True when `path` exists and is JSON null.
#[must_use]
pub fn value_is_null(root: &Value, path: &str) -> bool {
    value_at(root, path).map(Value::is_null).unwrap_or(false)
}

fn value_at<'a>(root: &'a Value, path: &str) -> Result<&'a Value, VectorError> {
    let mut cursor = root;
    for segment in path.split('/') {
        cursor = cursor
            .get(segment)
            .ok_or_else(|| VectorError(format!("{path}: missing at {segment}")))?;
    }
    Ok(cursor)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        output.push(((high << 4) | low) as u8);
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_published_vector_file_parses() -> Result<(), VectorError> {
        assert_eq!(str_at(&t1()?, "profile")?, "Trahens-T1");
        assert_eq!(str_at(&r1()?, "suite_id")?, "0101");
        assert_eq!(str_at(&crypto_c1()?, "suite_id")?, "0003");
        assert!(t2()?.is_object());
        Ok(())
    }

    #[test]
    fn hex_decoding_rejects_malformed_input() {
        assert_eq!(decode_hex("00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("zz"), None);
    }
}
