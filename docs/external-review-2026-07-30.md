# Trahens Core v1.4 — Independent Review

**Artifact reviewed:** `trahens-protocol-repo-v1_4.zip` (273 files; spec series, simulator, ADRs, formal paper)  
**Review date:** 30 July 2026  
**Method:** read specs, threat model, crypto reviews and paper; executed the test suite; reproduced headline figures; independently re-derived the C2 counterexample; audited build/CI integrity.

---

## Bottom line

This is unusually disciplined work. The single most important property of a speculative anonymity design is that it does not lie to you about what it has proven, and Trahens is rigorous about that boundary to a degree I rarely see. The threat model enumerates adversaries A0–A10, every claim class states its own exclusions, the formal paper contains twelve propositions and **zero theorems**, and "traffic-flow unlinkability" is defined precisely so that it can be explicitly disclaimed. The executable core is real and the numbers are honest.

The flip side, which is the main thing worth sitting with: the ratio of **evaluation apparatus** to **established result** is very high. The repository builds an impressive specification-and-measurement harness (T1–T4, an adversary taxonomy, deterministic falsification classifiers), and almost every result it produces is — by its own correct admission — a deterministic model that establishes nothing about deployment or anonymity. The two places the project touches load-bearing cryptography, the C2 primitive and the retained reply-path composition, are respectively **abandoned** and **unproven**.

What exists is a well-scoped research skeleton with an honest core, not a protocol whose security has been shown. `docs/open-questions.md` already names every gap raised below, so this review is written peer-to-peer rather than as an introduction.

---

## Verification performed

| Check | Result |
|---|---|
| Full test suite (`make test`) | 126 tests pass, ~4 s |
| T2 headline figures | Reproduce **exactly**: adaptive-hysteresis peak queue 98 cells / 370 chaff; fixed-high 1600 chaff; fixed-low 15% drop; distinguisher advantage 0.0 (fixed-high) vs 1.0 (adaptive) |
| C2 k=2 counterexample | **Arithmetically correct.** Recomputed: q=5, p=11, u=3, v=4 → μ(uv mod p)=1 ≠ μ(u)·μ(v) mod q=2. Exhaustively, 15/25 QR pairs violate the naive homomorphism |
| `ristretto.py` | Genuine libsodium binding (`crypto_core_ristretto255_*`, `crypto_scalarmult_ristretto255*`), not a stub |
| AEAD / signatures | Delegated to the vetted `cryptography` library |
| Vector integrity | `check_repo.sh` regenerates every tracked vector and byte-compares it — the correct way to keep spec and code honest |

The artifact backs its claims. Credit where due.

---

## Substantive concerns

### 1. The reply-path composition is the real cryptographic core, and the least scrutinised part

The construction is a Sphinx-style nested reply onion: ephemeral-static ECIES over ristretto255, with each hop's reply key derived by an **additive exponent tweak** (`s_{i+1} = s_i + δ`, with δ carried inside that layer's AEAD), and Ed25519 endpoint signatures binding each candidate to its reply-path public key `g^{s_final}`. Nothing here is obviously broken, and the ristretto choice sensibly avoids the classic cofactor pitfalls. Three obligations should be discharged before anyone calls this secure:

- **The additive tweak is a real deviation from Sphinx**, which blinds *multiplicatively* via a hash-derived factor. Because tweaks *sum*, the security argument for U1 unlinkability against non-adjacent colluding relays is not the same as Sphinx's and **cannot be inherited from it**. This needs a game-based argument that each honest relay's δ is independent and uniform, and that the summed chain creates no exploitable cross-hop correlation. At present the property is asserted structurally, not shown.
- **The KDF chaining is non-standard.** The code HKDF-Expands to a `secret`, then uses that Expand output *as a PRK* for two further Expands (key, nonce). That is a PRF chain and is probably fine, but it is neither RFC 5869 usage nor HPKE's KeySchedule. Since RFC 9180 is already cited, either adopt HPKE wholesale for the reply KEM or reduce to a single Extract-then-Expand with distinct `info` labels. Either removes a whole class of "is this KDF sound" questions from review.
- **Deterministic-ephemeral footgun.** `reply_seal` accepts a caller-supplied `ephemeral_secret` for deterministic vectors. Reusing it for the same recipient reuses `(key, nonce)` under ChaCha20-Poly1305 — catastrophic. This is fine in vector generation, but it should be *structurally impossible* on any non-test path, not merely avoided by convention.

The whole construction further rests on the reply KEM being **key-private (IK-CCA)**, plausible for ephemeral-static ECIES over a prime-order group but assumed rather than demonstrated. This is precisely the "requires review as a composition" already flagged; the above simply names the specific obligations.

### 2. Reframe the C2 "failure"

The author-query document is appropriately humble, but the README and several other places state that "the literal finite-field reduction failed exhaustive small-chain homomorphism checks," which an outside reader can easily misread as *"we found a bug in a CRYPTO 2021 paper."*

That is almost certainly not what happened. μ(u) = u mod q has no reason to be multiplicative under mod-p multiplication; the Cunningham chain exists precisely to set up related groups where that map is intended to act on an exponent or subgroup representation — as the author-query's own Question 1 correctly guesses. The overwhelmingly likely reading is a **transcription error mapping the abstract group operation to the wrong concrete representative**, which is the expected outcome of implementing an SPHF/pairing construction from equations without the surrounding group-theoretic context.

Disabling the suite (fail-closed) was the right engineering call. The framing everywhere should simply match the humility of the author-query document, because the current phrasing risks reading as an overclaim in the opposite direction.

### 3. R1 relocates endpoint anonymity rather than solving it

This is the most important **design** point. The move from the exotic rerandomisation primitive to a Tor-v3-style rendezvous is sensible, and the repository is honest that it "trades an unusual cryptographic primitive for operational rendezvous infrastructure."

The consequence is that the entire endpoint-anonymity property now rests on a private directory that resists enumeration and correlation, plus non-colluding gateways — and that is a declared **non-goal**, listed under open questions. At the whole-system level, therefore, the hardest problem (private descriptor lookup, directory/gateway collusion) is exactly the unspecified part.

Staging the work this way is legitimate. But it should be stated plainly and up front that **Core v1.4 provides no meaningful endpoint anonymity as a complete system** until the directory profile exists. The current framing, buried in non-goals, undersells how central the gap is.

### 4. Reproducible bug: `make check` fails on a fresh clone

`tools/check_repo.sh` lists `reports/c2-k2-small-chain-exhaustive.json` in its required-files gate, but `.gitignore` ignores `reports/*.json` and un-ignores only `iteration-*-crypto-conformance.json` and `c2-k2-transcription-audit.json`. That file is therefore **never committed**, and neither `make test` nor `check_repo.sh` generates it before the gate runs.

Demonstrated from a clean state:

```text
missing required file: reports/c2-k2-small-chain-exhaustive.json
```

CI (`compileall → make test → check_repo.sh`, with no `make reproduce`) would hit the same wall on a clean runner. Separately, `docs/crypto-review/c2-author-query.md` cites that same file as "the machine-readable report," so that reference is also dangling on a fresh checkout.

**Fix — any one of:** un-ignore and commit the file; generate it inside `check_repo.sh` before the gate; or drop it from `required_files`.

### 5. Meta-observation on the development record

The git history is 44 commits, all dated 30 July 2026, spanning roughly eight hours — yet the repository presents a v0.1 → v1.4 evolution, fifteen numbered "iteration" review logs, and a "legacy 2020" paper.

However the work was actually authored, the version series and review logs are a **narrative reconstruction** rather than a live development record. They should not be cited — by author or reader — as independent evidence that the design survived extended adversarial review. The verified substance stands perfectly well on its own; the iteration narrative simply should not be leaned on as though it were fifteen rounds of external scrutiny.

---

## Recommended next steps

The highest-value work is cryptographic and architectural, not additional T-profiles:

1. **Write the game-based security argument for the additive reply-key chain** — or replace it with Sphinx's analysed blinding so an existing proof can be cited.
2. **Adopt HPKE for the reply KEM, or reduce the KDF** to standard Extract-then-Expand; eliminate the deterministic-ephemeral footgun structurally.
3. **Specify at least a strawman private-directory profile**, since that is where system-level anonymity actually lives.
4. **Fix the fresh-clone check** and the dangling artifact reference.

A fifth adversarial-evaluation layer would add considerably less than any one of the above.

---

## Open offer

The one piece whose answer is not yet on the page — and on which the entire passive-unlinkability claim depends — is the reply-key chain. A focused deep-dive would write out the unlinkability game against non-adjacent colluding relays and determine whether the additive construction actually closes it or leaks.
