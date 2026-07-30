# Trahens Rendezvous Capability Profile R1

- Status: Active experimental fallback
- Date: 2026-07-30
- Suite identifier: `0x0101`
- Replaces: endpoint-specific eligibility in active DISCOVER traffic

## 1. Rationale

**Complete-system boundary.** R1 is not an endpoint-anonymity system by itself. It removes endpoint-specific selectors from route discovery but requires an authorized initiator to obtain a private descriptor. Until `private-directory-d1.md` or an equivalent reviewed profile is implemented, directory enumeration, lookup correlation, publication timing, and directory--gateway collusion remain unresolved.

R1 removes the unresolved universal-rerandomization dependency from active route discovery. The endpoint-specific secret is not carried, encrypted or otherwise, in a DISCOVER message. Discovery selects a generic rendezvous-gateway service. A short-lived, single-use capability is presented only after the route to a selected gateway reaches READY.

This architecture resembles the separation between service descriptors, introduction points, and rendezvous points in Tor onion services, but R1 is not a Tor protocol and does not inherit Tor's security analysis. Tor's current protocol overview and rendezvous specification are useful precedents for separating endpoint identity from a relay-mediated rendezvous operation: [Tor onion-service protocol overview](https://spec.torproject.org/rend-spec/protocol-overview.html) and [Tor rendezvous protocol](https://spec.torproject.org/rend-spec/rendezvous-protocol.html).

## 2. Roles

- `D`: destination endpoint.
- `Q`: private directory or capability-distribution service.
- `G`: rendezvous gateway.
- `S`: route initiator.
- `R`: ordinary Trahens relay.

The directory and gateway roles are outside Core's trustless claim. R1 explicitly trades an unusual cryptographic primitive for operational rendezvous infrastructure.

## 3. Capability issuance

For each registration epoch, `D` selects one or more gateways and samples a uniformly random 32-byte capability:

```text
tau <- {0,1}^256 \ {0^256}
```

For each selected gateway `G`, `D` registers:

```text
H("Trahens-R1-capability-v1" || tau)
expiration
ephemeral endpoint handle
short-lived gateway pseudonym
```

The raw capability MUST NOT be retained by the gateway. The registration MUST have a finite expiration and MUST be removed atomically on successful redemption.

`Q` privately delivers to an authorized initiator:

```text
RDesc = (
  epoch,
  expiration,
  tau,
  acceptable gateway pseudonyms,
  endpoint authentication material
)
```

How `Q` answers privately, authenticates clients, resists enumeration, and replicates records is a separate directory profile. D1 records a non-normative two-replica PIR / oblivious-relay strawman; it is not enabled by R1 and supplies no inherited security claim.

## 4. Discovery

R1 DISCOVER messages contain:

- a fresh branch token;
- the C1-derived reply public key used by the candidate return path;
- a 32-byte `service_query_nonce`;
- suite identifier `0x0101`.

The nonce has no endpoint-specific semantics. Every honest relay MUST replace it with a fresh independent non-zero 32-byte value when forwarding a child branch. Gateways decide eligibility from their local rendezvous-service role, not from the nonce.

A gateway candidate includes its short-lived gateway pseudonym inside the end-to-end authenticated candidate payload. The initiator accepts only candidates whose pseudonym appears in `RDesc`. The pseudonym is not exposed in DISCOVER.

## 5. Route activation and redemption

After COMMIT and READY, `S` sends an end-to-end protected `RENDEZVOUS_OPEN` payload over the active route:

```text
RENDEZVOUS_OPEN = (
  tau,
  client_nonce,
  expiration,
  endpoint_handshake
)
```

`G` computes the capability hash, looks up the registration, verifies the half-open validity interval, atomically removes the record, and only then returns the endpoint handle to its local rendezvous process. A repeated, expired, malformed, or wrong-gateway token produces one generic failure.

The capability MUST NOT appear in DISCOVER, CANDIDATE, COMMIT, READY, W2 fragmentation metadata, logs, or detailed error telemetry.

## 6. Security properties

R1 provides the following structural properties:

1. no endpoint public key, address hash, deterministic selector, or encrypted endpoint marker appears in DISCOVER;
2. the per-hop service nonce is replaceable rather than rerandomizable and has no endpoint semantics;
3. the one-time capability is exposed only inside an end-to-end protected active route;
4. capability replay is rejected by atomic redemption;
5. gateway candidates are filtered using pseudonyms protected inside the candidate chain.

R1 does not by itself provide:

- meaningful complete-system endpoint anonymity;
- an implemented or proven private directory;
- protection from a malicious gateway correlating registration and redemption;
- protection if the capability is stolen before use;
- traffic-flow unlinkability;
- gateway Sybil resistance;
- availability against selective gateway refusal;
- trustless direct discovery of an endpoint.

## 7. Resource bounds

An implementation MUST bound:

- registration records per endpoint and gateway;
- capability lifetime;
- gateways listed in one descriptor;
- candidate gateway responses per discovery;
- failed redemptions per route and peer;
- endpoint-handle lifetime;
- private-directory response size.

## 8. Test requirements

The tracked `spec/r1-test-vectors.json` file fixes deterministic reference values for the suite identifier, service class, nonce replacement, commitment, gateway-local token hash, first redemption, replay, wrong-gateway rejection, and expiry. Conformance tests MUST establish:

- the capability never appears in encoded DISCOVER bytes;
- every relay replacement changes the service nonce;
- an upstream literal nonce tag does not survive an honest replacement;
- the correct gateway redeems once;
- replay, expiry, wrong gateway, all-zero token, and duplicate registration fail;
- no failed redemption leaves a live record or active route state beyond its deadline.
