<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v1.7 — P1 interoperability profile

- Status: Active experimental wire profile. Supersedes v1.6, which is history.
- Date: 2026-09-05
- Registry version: 1.7.0
- Mandatory interoperability profiles: U1, E1, R1, M2, W2, T1, fixed T2/P1
- Selectable experimental profiles: adaptive T2, C1 eligibility
- Experimental analysis profiles: T3, T4, D1
- Normative registry: `protocol-registry-v1.7.json`

v1.7 rebuilds the end-to-end route channel and the signed gateway offer. The
route channel gains a directional key schedule with counter nonces and a
per-direction replay window, so a recorded protected body can no longer be
replayed by an intermediate relay; the gateway offer is signed over a transcript
that binds the protocol version, suite, reply key, and parameter digest. The
protocol version byte becomes `2`, so a v1.6 encoding does not decode under v1.7
and the two do not interoperate. `docs/adr/0041-directional-route-channel.md`
records the decision and its consequences.

v1.6 separated the suite-independent routing nonce from the suite's eligibility
field, which added 32 bytes to `DISCOVER`; v1.7 keeps that encoding unchanged.
`docs/adr/0040-routing-nonce-split.md` records that earlier decision.

## 1. Purpose

Core v1.7 defines the smallest profile needed for independently started
user-space nodes to discover a rendezvous gateway, establish a bounded route,
redeem a one-time capability, exchange bidirectional data, and reclaim all
remote state. It is implemented over ordinary UDP so W2 framing, T1 recovery,
retransmission, and fixed T2 scheduling remain observable and testable protocol
behavior.

Core v1.7 does not claim production readiness, global traffic-flow
unlinkability, a complete private-directory system, autonomous network
bootstrap, or post-quantum security. Reply-layer privacy remains conditional on
external review of key privacy and the nested multi-user composition.

P1 starts only after an adjacent authenticated graph already exists. Peer
discovery, node admission, adjacent-link key exchange, gateway-service
advertisement, and directory-root discovery are outside this profile. The
non-normative `network-bootstrap-b1.md` records the future work required to
remove the current static-configuration assumption.

## 2. Frozen protocol set

The following are mandatory for v1.7 P1 interoperability:

- U1 branch-local replacement and no stable cross-hop route handle;
- E1 typed route lifecycle and authoritative local expiry;
- R1 generic gateway discovery and post-READY one-time redemption;
- M2 canonical logical messages;
- W2 authenticated 1,052-byte adjacent-link records;
- T1 hop-local fragmentation, selective ACK, bounded retries, and fresh retry ciphertext;
- fixed T2/P1: 16 records per 200 ms epoch, one every 12,500 microseconds.

Adaptive T2 and C1 eligibility are selectable experimental profiles with their
own narrower gates. They MUST NOT be required for mandatory v1.7
interoperability and MUST NOT be cited as evidence for a mandatory gate line.
T3 and T4 remain analysis profiles. D1 remains non-normative.

## 3. Registry authority

`protocol-registry-v1.7.json` is normative for profile numbers, suite IDs,
message IDs, frame IDs, error IDs, byte order, widths, limits, fixed-T2
parameters, domain separators, and field-protection classifications. Generated
Python, Rust, and Markdown bindings MUST compare byte-for-byte with fresh
generator output in CI.

All fixed-width integers are unsigned big-endian. M2 variable lengths use the
canonical minimal varuint defined in `message-codec-m2.md`. Values outside the
registry limits are malformed and MUST be rejected before dependent state is
allocated.

C1 v1 suite `0x0001` is retired and MUST be rejected on the network. C1 v2 is
suite `0x0003`; R1 is suite `0x0101`. R1 is the only suite admitted by the
mandatory profile. C1 v2 is selectable only on the experimental profile, which
requires an explicit profile as well as an explicit suite. Symbolic C2
`0x0002` and the disabled C2 k=2 audit suite `0x7f02` are refused by live
network decoders.

## 4. Adjacent-link and wire contract

Each directed adjacent link has an independently derived key, 32-bit epoch,
64-bit sequence space, replay window, T1 sender/receiver state, and fixed T2
scheduler. The only public W2 fields are epoch and sequence. The remaining
1,024-byte cell body is link-encrypted and authenticated. Every UDP datagram
emitted by a conforming P1 node is exactly 1,052 bytes.

Authentication MUST complete before replay state is committed. An
authentication failure MUST NOT advance or poison the replay window.
Retransmission MUST use a fresh sequence, fresh padding, fresh AEAD tag, and
fresh ciphertext.

How adjacent peers discover one another, authenticate identities, negotiate
this profile, and derive the initial link keys is outside P1. A deployment MAY
use static configuration, as the prototype does, but MUST NOT describe that as
Trahens network bootstrap.

## 5. Discovery transformation

An endpoint sends `DISCOVER` with:

- a fresh non-zero 16-byte branch token;
- bounded hop, fan-out, and expiry fields;
- a fresh non-identity Ristretto reply public key;
- a fresh non-zero 32-byte routing nonce;
- an eligibility field whose width the active suite fixes.

The routing nonce and eligibility field serve different purposes and MUST NOT
be conflated. The routing nonce is suite-independent: it binds this hop's link
in the returned candidate chain and is the key from which per-offer labels are
derived. The eligibility field belongs to the suite: R1 carries a fresh nonce
with no endpoint-specific material, while C1 v2 carries a 128-byte universal
re-encryption capsule. Because route discovery reads only the routing nonce, a
suite may choose its eligibility width without changing route discovery.

For every forwarded child, a relay MUST independently replace the branch token,
routing nonce, and adjacent-link transmission ID, and MUST separately ask the
suite to transform the eligibility field. The two replacements are independent:
the routing nonce is fresh randomness, while the suite decides what transforming
its field means — replacement for R1, rerandomisation for C1. The relay samples
a non-zero scalar `b`, changes the reply key from `X` to `bX`, and retains only
the bounded local mapping needed for the reverse path. None of the parent token,
parent routing nonce, T1 ID, replay sequence, queue metadata, or retry metadata
is copied to the child link.

A recipient decides whether a well-formed eligibility field addresses it. That
decision is distinct from well-formedness, is reported under a distinct local
error identifier, and MUST be externally indistinguishable from any other
refusal.

## 6. Candidate return

A gateway candidate is signed and reply-encrypted to the final blinded reply
key. The encrypted gateway offer contains gateway ID, expiry, gateway
pseudonym, route secret, commit challenge, final routing nonce, signing public
key, and signature.

The signature is computed over the `p1_gateway_offer` transcript, which binds,
in this order and each length-prefixed: protocol version, suite ID, gateway ID,
gateway pseudonym, offer deadline, the reply public key the offer is sealed to,
route secret, commit challenge, routing nonce, gateway signing key, and the
profile parameter digest. The digest covers the protocol version, the six
profile numbers, and the fixed T2 epoch, cells per epoch, and slot interval, so
the parameter set both ends assume is part of what the gateway signs rather
than something each side supplies from its own registry.

An initiator MUST verify the signature over the transcript it recomputes
itself, including the reply key. It recomputes that key as the public
counterpart of the secret that opened the gateway layer, which is the blinded
key the gateway sealed to. The hash of this transcript is the route channel
binding in section 7; an implementation MUST NOT accept an offer whose
transcript it cannot reconstruct.

Each relay adds an authenticated reply layer encrypted to its incoming reply
key. The layer contains its non-zero blinding factor, child candidate token,
forward label, parent routing nonce, child routing nonce, and child blob. Both
nonces are 32 bytes whatever the suite, so a candidate layer does not grow with
the eligibility width. The endpoint opens layers from the first relay toward
the gateway, checks the complete routing-nonce replacement chain, derives each
blinded secret, validates the gateway signature, checks expiry, and rejects any
noncanonical or extra layer.

The chain binds routing nonces and does not cover the eligibility field. That
field is hop-local, replaced or rerandomised at every hop, and
integrity-protected by W2 on the adjacent link it crosses. The chain exists to
prove that a candidate returned along the branch the initiator opened, which
the routing nonce still proves. A suite whose eligibility field requires
end-to-end authenticity MUST supply its own binding.

The C1 v2 reply ciphertext is:

```text
32-byte encapsulation || AEAD ciphertext and tag || 32-byte recipient-bound commitment
```

Commitment and AEAD verification produce one external authentication-failure
class. The commitment supplies robustness/key commitment; it is not a completed
proof of recipient anonymity.

## 7. Route lifecycle

The mandatory lifecycle is:

```text
DISCOVERING -> CANDIDATE -> COMMITTED -> READY -> OPEN -> RECLAIMED
```

Only typed events may change phase. COMMIT authenticates possession of the route
secret and challenge. READY is end-to-end authenticated. R1 capability
presentation occurs only after READY. A successful atomic redemption moves the
route to OPEN. DATA is accepted only in OPEN. CLOSE, CANCEL, ABORT, timeout,
retry exhaustion, and peer loss reclaim all associated route, transport,
reassembly, queue, and secret state.

Relays never decrypt end-to-end controls. They authenticate the adjacent W2
record, validate the hop-local label, generation, and state, replace only the
hop-local label, and forward a newly encoded M2 message on the next link.

### 7.1 Route channel

The route channel is directional. Both ends derive two keys from the route
secret by HKDF: an extract step over `p1_route_extract || route_secret`, then
one expand per direction under `p1_route_key_e2g` and `p1_route_key_g2e`, with
the selected offer's transcript hash as expansion context. A route secret
presented under any other offer therefore derives different keys and fails
closed.

Each record's AEAD nonce is a 32-bit direction code followed by a 64-bit
sequence, which fills the nonce exactly. Sequences begin at zero and increase by
one per record sent in that direction. An implementation MUST NOT reuse a
sequence under one key and MUST fail closed rather than wrap when the sequence
space is exhausted.

A receiver MUST reject a record whose direction code is not the one it expects,
MUST keep a bounded acceptance window per direction sized by
`limits.route_replay_window`, and MUST commit a sequence to that window only
after the record authenticates. This is the only protection against end-to-end
replay: a duplicate carried in a fresh T1 transmission is legitimately new link
traffic, so the adjacent-link replay window admits it correctly and cannot be
what rejects it.

The nonce travels in the clear inside the link encryption, so a relay on the
path learns the direction and a per-route counter. That is a deliberate
disclosure, recorded in `field_protection` as `link-encrypted` and in ADR 0041;
a relay could already count records and infer direction from their travel.

The `direction` and `sequence` fields inside the DATA payload are superseded by
the nonce and retained only for encoding compatibility within this profile. The
nonce is authoritative.

## 8. Security and resource requirements

A conforming P1 implementation MUST:

1. enforce every per-peer and global registry limit;
2. bound reassembly bytes, fragments, contexts, retries, queues, and route state;
3. allocate no route state before complete adjacent authentication and canonical M2 decoding;
4. zeroize expired route, capability, scalar, nonce-key, and key material;
5. use authenticated replay windows and commit them only after authentication;
6. normalize malformed and cryptographic failures at the remote interface;
7. log stable event/error identifiers without keys, capabilities, route secrets, or private mappings;
8. reject capability replay, wrong gateway, wrong pseudonym, and expiry;
9. fail closed when T1 retry, reassembly, queue, or route budgets are exhausted;
10. keep all emitted W2 records constant-size.

## 9. Conformance

`p1-conformance-vectors-v1.7.json` and
`p1-conformance-corpus-v1.7.bin` are encoded by a generator that reads only the
normative v1.7 registry, not either implementation. Every M2 message type has a
positive and negative vector. Implementations MUST reject nonminimal lengths,
reserved flags, retired or unknown suites, invalid widths, invalid points,
impossible fragment metadata, and trailing bytes.

The historical v1.5 registry, vectors, corpus, and generated Markdown remain in
the repository only to keep that superseded profile reproducible. No current
binary speaks v1.5.

The Linux harness topology is:

```text
Endpoint -> Relay 1 -> ... -> Relay N -> Rendezvous Gateway
```

Each node runs as a separate process in a separate network namespace with veth
links, configurable MTU, `tc netem`, and per-link capture. The mandatory
acceptance gate is defined in `p1-prototype-profile-v1.7.md`. Adaptive T2 and C1
eligibility have separate experimental gates.

## 10. Evidence boundary

A passing P1 harness demonstrates implementation coherence, bounded failure
behavior, and wire interoperability for the tested topology and impairments. It
does not prove anonymity, key privacy, directory privacy, autonomous bootstrap,
resistance to a global observer, or production security. Large measured
divergences from the deterministic models require specification review before
parameter tuning.