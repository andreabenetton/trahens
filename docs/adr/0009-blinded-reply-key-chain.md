<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0009: Use a multiplicatively blinded reply-key chain for candidate return

- Status: Accepted with an explicit composition proof obligation
- Date: 2026-07-30
- Amended: 2026-07-30 after independent review

## Context

A responder must encrypt its candidate to a key that changes at every hop while allowing the initiator to reconstruct the corresponding private-key sequence. Reusing one reply public key would provide a direct equality handle to non-adjacent relays.

The original research implementation used additive scalar tweaks. Although algebraically correct, that construction was a deviation from the multiplicative blinding pattern analysed in Sphinx and had no game-based argument for the complete reply-layer composition.

## Decision

Use multiplicative blinding in a prime-order group. The initiator creates an independent non-zero root secret `x_0` and public key `X_0=x_0 B` for every first-hop branch. Each relay samples an independent non-zero factor `b_i` and computes:

```text
X_(i+1) = b_i X_i
x_(i+1) = b_i x_i mod q
```

The relay stores `b_i` in local child state and returns it only inside the authenticated encrypted reverse layer. The production reply-seal API generates its encapsulation secret internally from a CSPRNG; deterministic ephemerals are isolated in gated test support.

## Security statement

For every fixed non-identity `X`, the map `b -> bX` from the non-zero scalars to the non-identity group elements is a bijection. Therefore one honest relay makes the outgoing public key exactly uniform. This proves only the distribution of the public key.

The complete reply-layer unlinkability claim remains conditional on key privacy / receiver anonymity of the reply encryption, multi-user chosen-ciphertext analysis, transcript binding, and composition review. No Sphinx theorem is inherited merely by using the same multiplicative pattern.

## Consequences

- a public reply key no longer provides a stable equality handle across one honest relay;
- the initiator reconstructs the private sequence without public derivation indices;
- relays do not learn child candidate plaintexts;
- the custom reply KEM remains a review blocker for production use;
- exact route depth and traffic timing require independent padding and scheduling treatment;
- deterministic vector hooks cannot be called through the production API.

## Rejected alternatives

- **One static reply public key:** rejected because separated relays can compare it directly.
- **Additive scalar tweaks:** removed because the complete composition lacked an analysis and deviated unnecessarily from the established multiplicative pattern.
- **Non-hardened BIP32 derivation:** rejected as a wallet-specific mechanism with unsuitable compromise semantics.
