# Trahens W2 fixed-size adjacent-link cell profile

- Status: Active research profile
- Applies to: Trahens Core v1.3 with U1, E1, R1, M2, T1, and T2
- Reference implementation: `simulator/trahens_codec/m2w2.py`

## 1. Purpose

W2 carries canonical variable-length M2 messages over authenticated adjacent links while preserving one public transmission-unit length. It fragments an M2 message into fixed-size plaintext cells, pads every cell before encryption, and reassembles the message under explicit time and memory bounds.

W2 removes exact per-cell length and plaintext message-class leakage. It does not hide the number, direction, or timing of cells. A traffic-scheduling profile is required to conceal those observables.

## 2. Cell and record lengths

| Item | Length |
|---|---:|
| Encrypted cell plaintext | 1,024 bytes |
| W2 fragment header | 32 bytes |
| Fragment payload capacity | 992 bytes |
| Public link epoch | 4 bytes |
| Public link sequence | 8 bytes |
| ChaCha20-Poly1305 tag | 16 bytes |
| Complete adjacent-link record | 1,052 bytes |

For every emitted cell `c`:

```text
length(SealLink(c)) = 1,052 bytes
```

A receiver MUST reject every adjacent-link record whose length is not exactly 1,052 bytes before allocating reassembly or route state.

## 3. Public adjacent-link header

The public header is:

```text
epoch(4) || sequence(8)
```

Both values are unsigned big-endian integers. The 12-byte header is the ChaCha20-Poly1305 nonce and associated data. Sequence numbers are scoped to one direction of one adjacent-link epoch. Key and nonce reuse is forbidden.

The receiver MAY perform a non-mutating replay-window precheck from the public epoch and sequence before decryption, but it MUST commit replay admission only after successful adjacent-link authentication. Authenticated exact replay rejection occurs before fragment decoding. Public epoch and sequence values are link-local and are not copied when a relay forwards a logical message.

## 4. Encrypted fragment header

The first 32 plaintext bytes are:

```text
wire_profile(1)
protocol_version(1)
privacy_profile(1)
lifecycle_profile(1)
suite_id(2)
flags(1)
reserved(1)
message_local_id(16)
fragment_index(2)
fragment_count(2)
fragment_length(2)
total_message_length(2)
```

Current values:

- W2 wire profile: `0x02`;
- protocol version: `0x01`;
- U1: `0x01`;
- E1: `0x01`;
- R1 active suite: `0x0101`;
- C1 negative-control suite: `0x0001` (research only);
- C2 symbolic suite: `0x0002` (research only);
- C2 k=2 audit suite: `0x7f02` (rejected on the network);
- flags and reserved: zero.

All fields in this header are adjacent-link encrypted. `message_local_id` is a non-zero 128-bit identifier generated independently for one message on one authenticated link direction. It MUST be replaced after relay reassembly and semantic transformation. It MUST NOT be derived from a discovery, candidate, endpoint, route, or prior-hop identifier.

## 5. Canonical fragmentation

Let `L` be the complete M2 length and `P = 992` the fragment capacity. The fragment count is:

```text
q = ceil(L / P)
```

The profile requires:

- `1 <= L <= 16,384`;
- `1 <= q <= 17`;
- `0 <= fragment_index < q`;
- every non-final fragment has length 992;
- the final fragment has length `L - 992 * (q - 1)`;
- `fragment_count` equals the canonical value `ceil(L / 992)`.

A sender MUST NOT create additional short fragments. A receiver rejects non-canonical counts or lengths even when concatenation could produce the declared total. Canonical fragmentation prevents alternative wire representations of the same M2 message.

The remaining bytes after `fragment` are fresh random padding. A relay MUST discard received padding, reassemble the message, perform the specified transformation, encode a new M2 message, choose a fresh `message_local_id`, and generate new W2 padding and link ciphertexts.

## 6. Reassembly state

Reassembly is keyed by:

```text
(authenticated_link_direction, message_local_id)
```

A context records:

- the immutable cryptographic suite identifier;
- creation and half-open expiry times;
- immutable `fragment_count` and `total_message_length`;
- received fragment indexes and bytes;
- reserved logical-byte accounting.

The reference defaults are:

| Resource | Default |
|---|---:|
| Reassembly timeout | 40 ms |
| Concurrent incomplete messages | 64 |
| Aggregate reserved logical bytes | 128 KiB |

The simulator uses configurable bounds and reports peak reserved bytes. A deployment MAY lower these defaults. Raising the M2 message maximum or W2 fragment maximum requires a new profile identifier.

## 7. Reassembly behavior

A receiver processes each authenticated cell as follows:

1. validate fixed record length and parse the public epoch and sequence;
2. perform an optional non-mutating replay-window precheck;
3. authenticate and decrypt the link cell;
4. commit replay admission and reject an authenticated exact duplicate;
5. validate the W2 header and canonical fragmentation tuple;
6. expire old reassembly contexts;
7. admit the context against message-count and reserved-byte budgets;
8. accept a previously unseen fragment index;
9. ignore an exact duplicate fragment carried under a fresh authenticated link sequence;
10. invalidate the entire context on conflicting duplicate bytes or inconsistent metadata;
11. concatenate fragments only when every index `0..q-1` is present;
12. require the concatenated length to equal `total_message_length`;
13. decode the complete M2 envelope;
14. require the M2 suite identifier to equal the W2 reassembly suite;
15. submit the decoded message to protocol semantics and remove the reassembly context.

An incomplete context that reaches its deadline is removed without protocol error and without route-state allocation.

## 8. Loss, ordering, and retransmission

W2 accepts fragments in any order. It does not define retransmission. Loss of one cell prevents completion until the message expires unless a separately specified reliability profile retransmits the missing fragment under bounded rules.

A retransmission profile must preserve:

- adjacent-link replay semantics;
- finite retry counts;
- reassembly deadlines;
- per-peer and node-wide byte budgets;
- no stable identifier beyond the authenticated adjacent link.

## 9. Fragment-count leakage

W2 hides the exact logical length within the final cell but does not by itself hide how many cells are associated with a message. An observer able to group cells by timing may infer an approximate size class. Interleaving, scheduled release, cover cells, or padded transaction cell counts belong to a separate traffic-privacy profile.

The protocol therefore distinguishes:

- **cell-length equality**, provided by W2;
- **message-size-class concealment**, not provided without scheduling;
- **traffic-flow unlinkability**, not claimed by M2 or W2.

## 10. Security boundary

W2 is cryptographically suite-neutral. It does not repair active weaknesses in an end-to-end eligibility primitive: a compromised relay can emit a new, correctly authenticated W2 representation containing attacker-selected logical bytes. W2 provides canonical framing, local identifier replacement, bounded reassembly, suite-consistency checks, and adjacent-link integrity. Active discovery semantics are supplied by R1: the M2 field is a non-semantic per-hop nonce, and endpoint capability material is prohibited from DISCOVER. W2 does not provide private descriptor lookup, capability secrecy above the route layer, active timing-tag resistance, or traffic-flow unlinkability. C1 and C2 remain research-only providers.
