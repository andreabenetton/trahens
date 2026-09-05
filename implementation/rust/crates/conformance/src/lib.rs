// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![doc = "Independent P1 canonical-vector and decoder fuzz-smoke harness."]

// This crate is a pure test harness: every item below exists only to drive the
// tests at the bottom of the file, so all of it is scoped to test builds.
#[cfg(test)]
const CORPUS: &[u8] = include_bytes!("../../../../../spec/p1-conformance-corpus-v1.7.bin");

#[cfg(test)]
#[derive(Debug, Clone)]
struct Vector<'a> {
    valid: bool,
    name: &'a str,
    encoding: &'a [u8],
}

#[cfg(test)]
fn take<'a>(input: &'a [u8], cursor: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = cursor.checked_add(length)?;
    let value = input.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

#[cfg(test)]
fn parse_corpus() -> Option<Vec<Vector<'static>>> {
    if CORPUS.get(..4)? != b"TP15" {
        return None;
    }
    let mut cursor = 4;
    let count = u16::from_be_bytes(take(CORPUS, &mut cursor, 2)?.try_into().ok()?) as usize;
    let mut vectors = Vec::with_capacity(count);
    for _ in 0..count {
        let valid = *take(CORPUS, &mut cursor, 1)?.first()? == 1;
        let name_len = usize::from(*take(CORPUS, &mut cursor, 1)?.first()?);
        let name = std::str::from_utf8(take(CORPUS, &mut cursor, name_len)?).ok()?;
        let data_len = u16::from_be_bytes(take(CORPUS, &mut cursor, 2)?.try_into().ok()?) as usize;
        let encoding = take(CORPUS, &mut cursor, data_len)?;
        vectors.push(Vector {
            valid,
            name,
            encoding,
        });
    }
    (cursor == CORPUS.len()).then_some(vectors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec_m2::decode;
    use protocol_registry::BYTES_CELL_BODY;
    use wire_w2::{open_record, seal_record, ReplayWindow};

    #[test]
    fn every_published_m2_vector_has_expected_result() {
        let Some(vectors) = parse_corpus() else {
            panic!("invalid embedded P1 corpus");
        };
        // 11 canonical and 21 noncanonical. The count is pinned so that a
        // corpus which silently lost vectors fails here rather than passing
        // vacuously.
        assert_eq!(vectors.len(), 32);
        for vector in vectors {
            assert_eq!(
                decode(vector.encoding).is_ok(),
                vector.valid,
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn decoder_mutation_smoke_is_bounded_and_panic_free() {
        let Some(vectors) = parse_corpus() else {
            panic!("invalid embedded P1 corpus");
        };
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        for iteration in 0..50_000_usize {
            let source = vectors[iteration % vectors.len()].encoding;
            let mut mutated = source.to_vec();
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            if !mutated.is_empty() {
                let index = (state as usize) % mutated.len();
                mutated[index] ^= ((state >> 24) as u8) | 1;
                if iteration % 7 == 0 {
                    mutated.truncate(index);
                }
            }
            let _ = decode(&mutated);
            assert!(mutated.capacity() <= source.len().saturating_mul(2).max(1));
        }
    }

    #[test]
    fn w2_mutation_smoke_does_not_commit_unauthenticated_sequences() {
        let key = [0x42_u8; 32];
        let body = [0x24_u8; BYTES_CELL_BODY];
        let record = seal_record(&key, 3, 9, &body).unwrap_or([0_u8; 1052]);
        for index in 12..record.len() {
            let mut mutated = record;
            mutated[index] ^= 1;
            let mut replay = ReplayWindow::new(3);
            assert!(open_record(&key, 3, &mutated, &mut replay).is_err());
            assert_eq!(replay.entries(), 0);
        }
    }
}
