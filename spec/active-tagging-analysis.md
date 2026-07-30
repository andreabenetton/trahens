# Active-tagging analysis for the C1 eligibility capsule

- Status: Blocking security analysis
- Applies to: C1 universal rerandomizable eligibility encryption
- Claim affected: active-adversary message unlinkability

## 1. Result

The current C1 URE construction does not provide active-tagging resistance. A malicious relay can replace the consistency pair with a recognizable algebraic relation that survives any number of honest rerandomizations. A colluding downstream relay can test the relation without knowing the destination key.

Consequently:

- passive wire-image unlinkability remains a conditional research claim;
- active-adversary message unlinkability is explicitly **not claimed**;
- C1 is not eligible for production deployment;
- the attack must be resolved or the URE design replaced before an active-security gate can pass.

## 2. C1 consistency pair

A valid C1 eligibility capsule contains:

\[
(U_1,V_1)=(r_1A,r_1B),
\]

where `A = aB` is the hidden eligibility public key. Honest rerandomization samples non-zero `s_1` and computes:

\[
(U'_1,V'_1)=(s_1U_1,s_1V_1).
\]

The operation changes the encodings but preserves every homogeneous algebraic relation between the two points.

## 3. Persistent ratio-tag attack

Let a malicious relay choose a known non-zero scalar `c`. It replaces the pair by:

\[
(\widetilde U_1,\widetilde V_1)=(cV_1,V_1).
\]

Both points are canonical non-identity `ristretto255` elements. A relay that does not know `A` cannot distinguish the tagged pair from a syntactically valid pair.

After an honest relay rerandomizes with scalar `s_1`:

\[
(\widetilde U'_1,\widetilde V'_1)=(s_1cV_1,s_1V_1).
\]

A colluding downstream relay tests:

\[
\widetilde U'_1 \stackrel{?}= c\widetilde V'_1.
\]

The equality always holds. The tag therefore survives the honest transformation and gives the colluding relays a deterministic cross-hop correlation handle.

## 4. Effect at the destination

The endpoint consistency check computes:

\[
T=\widetilde U'_1-a\widetilde V'_1=(c-a)s_1V_1.
\]

Except when `c = a`, which the attacker need not know and occurs with negligible probability for a randomly selected tag, the check fails. The tagged branch therefore does not produce a candidate. If the attacker can observe candidate return or later route activation, the absence of a response can also become a confirmation channel.

The attack combines linkability with denial of service; generic error handling prevents a detailed error oracle but does not remove the observable suppression of the branch.

## 5. Why strict parsing is insufficient

The following checks are necessary but do not stop the ratio tag:

- fixed record length;
- canonical point encoding;
- non-identity points;
- fresh adjacent-link AEAD;
- independent honest rerandomization;
- generic cryptographic failure;
- candidate signature verification.

The malicious pair satisfies the public syntactic checks. Its invalidity is visible only to the endpoint holding `a`, while the tag relation is visible to colluders that know `c`.

## 6. Reference demonstration

The reference code implements the attack in:

- `simulator/trahens_crypto/tagging.py`;
- `simulator/tests/test_active_tagging.py`;
- `simulator/trahens_sim/tagging_compare.py`.

On a five-node line with malicious relays at positions 1 and 3, the first relay tags the branch, the honest relay at position 2 rerandomizes it, and the second malicious relay recognizes the ratio. The endpoint rejects the capsule and no route becomes READY.

The deterministic comparison in `reports/iteration-0007-wire-tagging-comparison.csv` records:

- 100% route success in the clean integrated scenario;
- 0% success under the ratio tag;
- one downstream tag observation per colluding run;
- complete eventual state cleanup in every evaluated scenario.

These model results demonstrate the algebraic mechanism; they are not a security proof or a measurement of real-network detection probability.

## 7. Candidate remedies

No remedy is adopted yet. The next cryptographic design review must compare at least:

1. a universally rerandomizable construction with a formal active-security or non-malleability definition;
2. a rerandomizable zero-knowledge proof that the consistency pair is well formed for the hidden destination key;
3. a verifiable-shuffle or proof-carrying transformation whose proof is replaced at every hop without becoming a correlation handle;
4. a different destination-discovery mechanism that avoids universally malleable ciphertexts;
5. a Sphinx-like authenticated packet mechanism adapted to discovery without revealing the destination or complete route.

Any replacement must preserve destination-key privacy, public rerandomization, fixed-size encoding, branch-local transformation, and bounded verification cost. A solution that merely detects the tag at the destination is insufficient because the colluding-relay correlation has already occurred.

## 8. Security gate

The active-security gate remains closed until all of the following exist:

- a precise active-adversary game;
- a construction satisfying the selected game under stated assumptions;
- a proof or independently reviewed reduction;
- negative vectors for algebraic, truncation, replay, substitution, and selective-failure tags;
- integration tests showing that malformed and tagged records cannot create a distinguishable forwarding or error behavior beyond unavoidable denial of service;
- independent cryptographic review.
