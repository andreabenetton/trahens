# Trahens Core v1.0

- Status: Active experimental research design
- Date: 2026-07-30
- Active profiles: U1, E1, R1, M2, W2
- Research-only profiles: C1 negative control, symbolic C2, disabled C2-k2 audit

## 1. Purpose

Trahens Core discovers generic rendezvous gateways within a bounded graph radius and establishes opaque bidirectional forwarding state to one selected gateway. Endpoint-specific rendezvous occurs only after the route reaches READY through a private, short-lived, single-use R1 capability.

A relay learns only its adjacent predecessor and successor relationships and the local capabilities required to forward messages. The protocol never transmits a complete source route. Every forwarded branch receives a fresh adjacent capability, a tweaked reply public key, a replacement R1 service-query nonce, a new M2 logical message, a fresh W2 message-local identifier, new padding, and new adjacent-link ciphertexts.

## 2. Why R1 is active

The prior endpoint-specific design required receiver-anonymous, publicly rerandomizable, active-tag-resistant encryption. The repository retains:

- C1 as an executable negative control that exhibits a persistent ratio tag;
- symbolic C2 as an ideal composition oracle;
- a disabled exact k=2 transcription audit of Wang et al., CRYPTO 2021.

The concrete audit cannot enable full rerandomization under the literal finite-field interpretation. The alternative updatable/randomizable PKE of Dowling et al., ASIACRYPT 2022, randomizes an encryption key and ciphertext together and does not implement the ciphertext-only, same-recipient transform required by the earlier architecture. Core v1.0 therefore adopts Gate B: endpoint-specific eligibility is removed from active DISCOVER traffic and replaced by R1 rendezvous capabilities.

See:

- `spec/rendezvous-capability-r1.md`;
- `spec/eligibility-suite-interface-v1.md`;
- `docs/crypto-review/c2-author-query.md`;
- `docs/crypto-review/alternative-primitive-assessment.md`.

## 3. Bound profiles

- **U1**: branch-local structural unlinkability. Branch tokens, reply keys, route labels, candidate tokens, message identifiers, padding, and link ciphertexts are replaced at each hop.
- **E1**: deterministic event time, half-open deadlines, candidate windows, delayed candidates, cancellation races, COMMIT, READY, expiry, and cleanup.
- **R1**: generic rendezvous-gateway discovery plus post-READY one-time capability redemption.
- **M2**: canonical suite-agile variable-length logical messages without semantic padding.
- **W2**: fixed 1,052-byte authenticated adjacent-link cells with canonical fragmentation and bounded reassembly.

## 4. Goals

Core v1.0 MUST provide:

1. bounded discovery by hop limit, fan-out, time, branch state, logical bytes, W2 cells, and cryptographic work;
2. no endpoint address, endpoint public key, deterministic endpoint selector, or endpoint capability in DISCOVER;
3. no stable discovery identifier visible across non-adjacent links;
4. fresh branch-local representation for every forwarded child;
5. authenticated responder candidates returned through a nested reply chain;
6. tentative route establishment before initiator selection;
7. explicit COMMIT, READY, CANCEL, ABORT, CLOSE, and expiry behavior;
8. no data-plane authorization before final READY;
9. one-time, finite-lifetime rendezvous capability redemption after route activation;
10. deterministic fail-closed behavior for disabled research suites;
11. hard limits on reassembly and route state;
12. exact separation between cell-length equality, passive structural unlinkability, active tagging, and traffic-flow privacy.

## 5. Non-goals

Core v1.0 does not itself provide:

- private directory queries or descriptor distribution;
- protection from a malicious gateway correlating registration and redemption;
- global endpoint lookup;
- inter-domain policy or incentives;
- Sybil resistance;
- traffic-flow unlinkability against a global timing observer;
- a production-ready implementation;
- post-quantum security;
- a replacement for IP or a link layer.

## 6. System model

The network is an undirected graph `G=(V,E)`. A node may act as initiator, ordinary relay, rendezvous gateway, or any combination. An edge denotes an authenticated adjacent-link association.

A route is a sequence `(n_0,...,n_d)` with adjacent pairs in `E`. The route is never transmitted as one object. Route state consists only of peer-bound local labels and mappings.

## 7. Adjacent-link contract

The adjacent-link transport MUST provide:

- peer authentication or an explicitly anonymous authenticated association;
- confidentiality and integrity;
- exact record boundaries;
- directional epoch and replay sequence;
- key and nonce uniqueness;
- connection and disconnection notification.

W2 pads each cell plaintext to 1,024 bytes and emits a 1,052-byte record. The public 12-byte header contains only the link epoch and sequence. W2 hides exact per-cell content length but not cell count, direction, or timing.

## 8. Discovery and R1

The endpoint registers a random 32-byte capability at selected rendezvous gateways and privately distributes a descriptor containing the capability, expiration, and acceptable short-lived gateway pseudonyms.

An R1 DISCOVER message contains a fresh 32-byte service-query nonce. The nonce has no endpoint semantics. Every honest relay replaces it with a fresh non-zero value for each child. A node responds only if it locally serves as a rendezvous gateway.

The candidate payload contains the gateway's short-lived pseudonym inside the authenticated end-to-end candidate chain. The initiator accepts only candidates listed in the private descriptor.

After READY, the initiator sends the capability through the active end-to-end route. The gateway hashes it, verifies a live registration, atomically removes the registration, and returns the endpoint handle to the local rendezvous process. Replay and expiry produce one generic failure.

## 9. Forward discovery

The initiator performs bounded expanding-ring discovery. Ring schedule, candidate threshold, transmission budget, and setup timeout are local and absent from the wire.

For each first-hop branch the initiator creates:

- a fresh branch token;
- a fresh C1 reply key pair used only for candidate return;
- a fresh R1 service-query nonce;
- bounded propagation fields.

For each forwarded child an honest relay:

1. authenticates and fully reassembles W2 cells;
2. canonically decodes M2;
3. verifies local bounds;
4. allocates one branch context;
5. creates a fresh child token;
6. additively tweaks the reply public key with a fresh scalar;
7. replaces the R1 nonce;
8. constructs a new M2 message;
9. fragments it canonically;
10. emits fresh W2 link ciphertexts.

## 10. Candidate return

A gateway creates a signed responder payload containing its short-lived pseudonym, offer expiry, final reply key, commit challenge, and nonce. It seals the payload to the current reply public key.

Each reverse relay adds one authenticated layer containing its local forwarding labels and reply-key delta. The initiator opens the nested chain, reconstructs the reply-key sequence, verifies the gateway signature, checks the descriptor pseudonym set, and records a candidate.

## 11. Route activation

CANDIDATE installs tentative mappings. COMMIT reserves the selected path and moves mappings to `PENDING_READY`. READY confirms responder activation in reverse and converts mappings to `ACTIVE`. Application data MUST NOT be forwarded before the initiator authenticates the final READY proof.

CANCEL, ABORT, and CLOSE are advisory cleanup controls. Every state also has an independent local half-open expiration deadline.

## 12. M2 and W2

M2 encodes one complete semantic control message with canonical lengths and no semantic padding. W2 fragments M2 into 992-byte payload fragments, pads each cell plaintext to 1,024 bytes, and applies adjacent-link AEAD.

For an M2 message of length `L`:

```text
q = ceil(L / 992)
1 <= L <= 16384
1 <= q <= 17
```

Non-final fragments contain exactly 992 message bytes. Alternative fragmentations are non-canonical. A relay MUST complete reassembly before allocating branch or route state.

Suite `0x0101` is active R1. Suites `0x0001` and `0x0002` are research controls. Reserved suite `0x7f02` MUST be rejected by M2/W2 network decoders.

## 13. Resource safety

Implementations MUST bound:

- per-peer and global cell rate;
- concurrent reassemblies and reserved bytes;
- message and fragment count;
- branch contexts per peer and node;
- candidate, tentative, pending, and active mappings;
- cryptographic operations;
- gateway registrations and failed redemptions;
- queue length and timer count;
- transmission and setup time.

Unauthenticated input MUST NOT advance replay state. A failed earlier stage MUST NOT consume resources assigned to later stages.

## 14. Security claims

### 14.1 Claimed structurally

- all W2 cells have equal complete length;
- endpoint-specific capability bytes do not appear in DISCOVER;
- every branch-local token and service nonce is replaced at an honest relay;
- candidate and route labels are local capabilities;
- one-time capability replay is rejected by atomic redemption;
- all state is eventually reclaimed by local expiry.

### 14.2 Conditional

Batch-local passive message unlinkability requires an honest transformation and an explicit scheduling profile with a nontrivial anonymity set. W2 alone does not provide it.

### 14.3 Not claimed

- traffic-flow unlinkability;
- anonymity against a malicious directory and malicious rendezvous gateway colluding with network observers;
- active-security properties of C1 or the concrete C2 transcription;
- production cryptographic security.

## 15. Research providers

The lifecycle imports only the abstract eligibility-suite interface.

- `R1RendezvousSuite`: active experimental provider; non-semantic nonce replacement.
- `C1NegativeControlSuite`: reproduces the ratio-tag attack; not network enabled.
- `C2SymbolicControlSuite`: ideal replay-equivalence oracle; not cryptography.
- `C2K2ExperimentalDisabledSuite`: every protocol operation fails closed.

## 16. Conformance and evidence

The repository includes:

- deterministic C1 and symbolic C2 vectors;
- exact C2-k2 transcription audit;
- exhaustive small-chain test of the literal finite-field map;
- deterministic R1 vectors plus nonce replacement and capability redemption tests;
- R1 versus C1/C2 active-tagging comparison;
- M2/W2 fragmentation, reassembly, malformed-input, and replay tests;
- E1 lifecycle tests under delay, loss, duplication, cancellation, and resource pressure.

These artifacts are regression and falsification tools, not cryptographic proofs.
