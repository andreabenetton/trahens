// SPDX-License-Identifier: Apache-2.0
//! Cross-check the published B1.1 vectors against an independent Noise
//! implementation.
//!
//! The vectors in `spec/b1-test-vectors.json` are produced by the Python
//! reference in `simulator/trahens_crypto/b1.py`. Verifying only that they
//! reproduce would leave any mistake in that reference shared by everything
//! built against them rather than exposed. These tests instead replay the same
//! exchanges through `snow`, which knows nothing about Trahens, and require the
//! Noise layer to agree: the wire bytes each message carries, and the handshake
//! hash the transcript ends on.
//!
//! What is compared is the Noise message, which is the record minus the
//! Trahens prefix. The framing, the fixed record width and the payload padding
//! are Trahens' own and have no counterpart in snow.

use snow::{params::NoiseParams, Builder, HandshakeState};
use std::error::Error;
use test_vectors::Value;

type Fallible<T> = Result<T, Box<dyn Error>>;

/// A width from the v1.8 draft registry. Read rather than hardcoded: v1.8
/// generates no bindings yet, and a copied number is exactly the drift the
/// registry exists to prevent.
fn width(name: &str) -> Fallible<usize> {
    let registry = test_vectors::protocol_registry_v18()?;
    let value = registry
        .get("widths_bytes")
        .and_then(|widths| widths.get(name))
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("the v1.8 registry has no width {name}"))?;
    Ok(usize::try_from(value)?)
}

fn field(vector: &Value, name: &str) -> Fallible<String> {
    Ok(vector
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("vector is missing {name}"))?
        .to_owned())
}

fn bytes(vector: &Value, name: &str) -> Fallible<Vec<u8>> {
    Ok(hex::decode(field(vector, name)?)?)
}

/// The Noise message a record carries, without the Trahens prefix.
fn noise_message(vector: &Value, name: &str) -> Fallible<Vec<u8>> {
    let record = bytes(vector, name)?;
    assert_eq!(
        record.len(),
        width("b1_record")?,
        "{name} must be exactly one cell"
    );
    assert_eq!(record[0], 0, "{name} must begin with a zero byte");
    Ok(record[width("b1_record_prefix")?..].to_vec())
}

fn vector(rekey: bool) -> Fallible<Value> {
    let document = test_vectors::b1()?;
    let vectors = document
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or("b1 vectors document has no vectors array")?
        .clone();
    vectors
        .into_iter()
        .find(|candidate| candidate.get("rekey").and_then(Value::as_bool) == Some(rekey))
        .ok_or_else(|| format!("no vector with rekey={rekey}").into())
}

/// Trahens payload framing: a two-byte length, the body, zero padding.
fn framed(body: &[u8], width: usize) -> Fallible<Vec<u8>> {
    let mut out = Vec::with_capacity(width);
    out.extend_from_slice(&u16::try_from(body.len())?.to_be_bytes());
    out.extend_from_slice(body);
    out.resize(width, 0);
    Ok(out)
}

/// Replay one published exchange through snow and return its handshake hash.
///
/// Every input is taken from the vector: both static secrets, both ephemeral
/// secrets, the prologue, the chained key, and the exact payloads. snow
/// therefore has no freedom to produce anything but the same bytes, if the
/// reference was right.
fn replay(rekey: bool) -> Fallible<Vec<u8>> {
    let vector = vector(rekey)?;
    // Both exchanges are psk0; only the prologue and the pre-shared key differ.
    let params: NoiseParams = "Noise_XXpsk0_25519_ChaChaPoly_SHA256".parse()?;

    // Domain separation only. The key material enters as the psk0 pre-shared
    // key, not here; see spec/link-handshake-b1.md section 2.
    let prologue: &[u8] = if rekey {
        b"Trahens-B1-rekey-chain-v1"
    } else {
        b"Trahens-B1-prologue-v1"
    };
    // Published rather than derived here, exactly as the chained export key
    // always was: snow checks that these records follow from this key, and the
    // derivation of the key itself is pinned by the vector and reproduced by
    // both implementations.
    let psk: [u8; 32] = bytes(&vector, "psk")?
        .try_into()
        .map_err(|_| "the pre-shared key must be 32 bytes")?;

    // The Builder borrows what it is given, so it is consumed here rather than
    // returned: handing a Builder back out of the closure would outlive the
    // slices it holds.
    let configure = |local: &[u8], ephemeral: &[u8], initiator: bool| -> Fallible<HandshakeState> {
        let builder = Builder::new(params.clone())
            .local_private_key(local)?
            .prologue(prologue)?
            .psk(0, &psk)?
            .fixed_ephemeral_key_for_testing_only(ephemeral);
        Ok(if initiator {
            builder.build_initiator()?
        } else {
            builder.build_responder()?
        })
    };

    let initiator_static = bytes(&vector, "initiator_static_secret")?;
    let responder_static = bytes(&vector, "responder_static_secret")?;
    let initiator_ephemeral = bytes(&vector, "initiator_ephemeral_secret")?;
    let responder_ephemeral = bytes(&vector, "responder_ephemeral_secret")?;

    let mut initiator = configure(&initiator_static, &initiator_ephemeral, true)?;
    let mut responder = configure(&responder_static, &responder_ephemeral, false)?;

    let mut buffer = vec![0_u8; 4096];
    let mut scratch = vec![0_u8; 4096];

    // The payloads are rebuilt here from the vector's own offer and selection
    // rather than lifted out of the reference's records, so the comparison is
    // not circular.
    let initiate_width = width("b1_initiate_payload_psk")?;
    let steps: [(&str, Vec<u8>, bool); 3] = [
        (
            "message_1",
            framed(&bytes(&vector, "offer")?, initiate_width)?,
            true,
        ),
        (
            "message_2",
            framed(&bytes(&vector, "selection")?, width("b1_respond_payload")?)?,
            false,
        ),
        ("message_3", framed(&[], width("b1_finish_payload")?)?, true),
    ];

    for (name, payload, from_initiator) in steps {
        let expected = noise_message(&vector, name)?;
        let (writer, reader) = if from_initiator {
            (&mut initiator, &mut responder)
        } else {
            (&mut responder, &mut initiator)
        };
        let written = writer.write_message(&payload, &mut buffer)?;
        assert_eq!(
            &buffer[..written],
            expected.as_slice(),
            "{name} disagrees with snow"
        );
        reader.read_message(&buffer[..written], &mut scratch)?;
    }

    let hash = initiator.get_handshake_hash().to_vec();
    assert_eq!(
        hash,
        responder.get_handshake_hash(),
        "snow's two sides disagree with each other"
    );
    Ok(hash)
}

#[test]
fn the_initial_handshake_matches_an_independent_noise_implementation() -> Fallible<()> {
    let vector = vector(false)?;
    assert_eq!(
        hex::encode(replay(false)?),
        field(&vector, "handshake_hash")?,
        "handshake hash disagrees with snow"
    );
    Ok(())
}

#[test]
fn the_chained_rekey_matches_an_independent_noise_implementation() -> Fallible<()> {
    let vector = vector(true)?;
    assert_eq!(
        hex::encode(replay(true)?),
        field(&vector, "handshake_hash")?,
        "handshake hash disagrees with snow"
    );
    Ok(())
}
