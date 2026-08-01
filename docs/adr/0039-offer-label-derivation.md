<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0039: Per-offer labels derived from the child discovery nonce

## Status

Accepted for v1.5 (registry 1.5.1). Extends ADR 0038.

## Context

`core-v0.1.md` section 11 has a relay create a tentative mapping from a
parent-facing label to a child-facing one and receive `COMMIT` on that
parent-facing label. `core-v0.3.md` section 14 restates it as replacing the
child candidate token with a fresh parent candidate token.

Neither says how the parent resolves a label it did not mint. With one child
per branch the question does not arise, because the branch token identifies the
only chain. Under fan-out it does: several gateways answer through one branch,
the initiator selects at its window boundary, and a `COMMIT` addressed to the
branch names the branch but not which child answered.

The Rust implementation previously took the first candidate to arrive, which is
rarely the one the initiator selects. `docs/p1-acceptance-evidence.md` recorded
the resulting off-route subtree as a known gap and named
`open_candidate_chain`'s `first_forward_label` as the field that would close
it. That was wrong: a relay passes its own parent label as `forward_label`, so
the field only ever held the initiator's own branch token. It has been removed.

`CANDIDATE` carries exactly one token field, so the child cannot send both a
label the parent already knows and a fresh per-offer one.

## Decision

1. **Offer labels are derived, not transported.** The label for the `index`-th
   offer returned on a branch is

   ```text
   HMAC-SHA256(child_discovery_nonce,
               "Trahens-P1-offer-label-v1" || uint16_be(index))[0..16]
   ```

   Both ends can compute it: the parent independently replaces the discovery
   nonce for each child and sends it in the `DISCOVER`, so the value the parent
   holds as `child_discovery_nonce` is the value the child holds as
   `parent_discovery_nonce`. No additional selector crosses the wire, the
   truncation matches the existing 16-byte label width, and `index` admits
   several responses per branch.

   A counter, or the branch token XORed with an index, would also have been
   derivable, but successive labels would then be trivially linkable by a
   passive observer, which U1 exists to prevent.

2. **The discovery nonce is key material.** It is confidential to the hop that
   generated it, appears only inside the adjacent authenticated W2 link, and is
   never reused across children, branches, or link epochs. Anyone holding it
   can compute every label that child will answer on, so the unlinkability in
   decision 1 rests entirely on its confidentiality.

   `RelayChild` and `RelayRoute` therefore store nonces and blinding factors in
   `SecretBytes`, which wipes on drop, and neither type is `Clone`. Control
   forwarding takes a `RouteView` holding only labels and link indices.

3. **Parents reserve a sliding window.** A parent registers
   `OFFER_LABEL_WINDOW` labels per child up front and registers the next as
   each is consumed, so offers may arrive out of order within the window while
   live state stays small. The total per child remains bounded by
   `LIMIT_MAX_CANDIDATE_RESPONSES_PER_DISCOVERY`.

4. **`CANCEL` and `ABORT` are hop-authenticated.** They carry no end-to-end
   payload, because the relay that sends one holds no route secret for the
   gateway it is addressed to. A node acts on them without opening a sealed
   body, on the authority of the authenticated link they arrived on and of the
   selector and generation resolving to a live route. Previously the gateway
   treated them as authentication failures and ignored them, so a stood-down
   subtree ran to its own expiry.

## Consequences

`COMMIT` names one chain end to end, so a relay activates the child the
initiator chose and cancels its siblings. In the `netns-fanout.sh` topology
traffic fell from 2,774 to 486 cells, because the losing subtree stops instead
of running to expiry.

No M2 or W2 format changes, so the frozen vectors and the conformance corpus
are unaffected: only the value carried in an existing token field changes.

The security of the scheme is now stated to depend on nonce confidentiality and
freshness. A profile that reused a discovery nonce across children, or exposed
it outside the adjacent link, would make successive offer labels linkable and
would need a different derivation.
