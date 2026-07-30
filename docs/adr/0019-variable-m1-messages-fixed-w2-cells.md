<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0019: Separate logical message encoding from fixed-size wire cells

- Status: Accepted
- Date: 2026-07-30

## Context

The W1 profile encoded every control message directly into one 1,024-byte authenticated plaintext and therefore one 1,052-byte adjacent-link record. This gave a simple length-equality invariant, but it coupled protocol semantics to the transport cell size. The coupling imposed a 960-byte candidate-blob ceiling and made route depth a wire-profile selection problem.

Padding before encryption hides length only when all padded plaintexts have the same final size. Variable random padding still exposes the resulting ciphertext length. The privacy property therefore belongs at the adjacent-link transmission unit, not at the logical message representation.

## Decision

Trahens separates the two layers:

1. **M1** is a canonical variable-length logical message encoding. It contains no semantic padding.
2. **W2** fragments one M1 message into one or more 1,024-byte authenticated cell plaintexts.
3. Every W2 cell is encrypted into one 1,052-byte adjacent-link record.
4. Every fragment is padded inside the encrypted cell before adjacent-link encryption.
5. The adjacent-link message identifier is fresh, peer-direction scoped, and replaced after relay reassembly and transformation.
6. A relay reassembles the complete M1 message before semantic processing, reconstructs a new M1 message, and emits new W2 cells. It never forwards received fragments unchanged.

## Consequences

- Short messages still consume one fixed-size cell.
- Candidate messages can exceed one cell without introducing a second public record length.
- The number and timing of cells can reveal a size class unless a traffic-scheduling profile hides it.
- Fragment loss can prevent reassembly and raises the cost of long candidate paths.
- Relays require explicitly bounded reassembly state.
- The maximum logical message size and maximum fragment count remain normative resource limits.

## Rejected alternatives

### Variable ciphertext lengths with random padding

Rejected because the ciphertext length remains observable and message classes retain distinguishable length distributions.

### Multiple fixed W1 record classes

Rejected as the default because the selected class becomes a public fingerprint. Quantized classes may be specified later as a separately analyzed efficiency profile.

### Unlimited fragmentation

Rejected because a peer could reserve unbounded reassembly memory and fragment metadata state.
