# ADR 0024: Adopt R1 rendezvous capability as the active eligibility profile

- Status: Accepted
- Date: 2026-07-30

## Context

The active endpoint-specific design depended on a receiver-anonymous, publicly rerandomizable, active-tag-resistant encryption construction. The symbolic C2 oracle validates protocol composition but is not deployable. The literal k=2 finite-field transcription of Wang et al. remains fail-closed because the audited tag projection is not multiplicative under ordinary group multiplication. The updatable/randomizable PKE of Dowling et al. randomizes an encryption key and ciphertext together and does not provide the ciphertext-only, same-recipient transform required by Trahens.

## Decision

Adopt R1 as the active experimental network suite. DISCOVER targets a generic rendezvous-gateway role and contains a replaceable non-semantic nonce. Endpoint-specific selection occurs after READY through a private, short-lived, single-use capability registered at selected gateways.

C1, symbolic C2, and C2-k2 remain research providers behind a common eligibility-suite interface. They are not active network suites.

## Consequences

### Positive

- removes unresolved URE from the active protocol;
- removes endpoint-specific selectors from DISCOVER;
- permits exact provider isolation and fail-closed suite selection;
- makes the remaining privacy assumptions operationally explicit.

### Negative

- introduces directory and gateway trust assumptions;
- requires endpoint pre-registration and private descriptor delivery;
- allows a malicious gateway to correlate registration and redemption;
- may increase candidate and registration overhead.

## Rejected alternatives

- enabling the partial C2-k2 transcription;
- treating the symbolic oracle as cryptography;
- using ASIACRYPT 2022 urPKE as a drop-in URE replacement;
- retaining C1 with only a warning about active tagging.
