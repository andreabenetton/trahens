<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Eligibility Suite Interface v1

- Status: Active protocol boundary
- Date: 2026-07-30
- Purpose: decouple route discovery and lifecycle processing from destination-eligibility implementations

## 1. Interface

An eligibility suite exposes the following abstract operations:

```text
Setup() -> params
KeyGen(params) -> endpoint_context
Initial(endpoint_context; coins) -> eligibility_field
Transform(eligibility_field; coins) -> eligibility_field'
Accept(local_role, eligibility_field) -> boolean
IsEligible(endpoint_context, eligibility_field) -> boolean
```

Since v1.6 the field this interface owns is the **eligibility field** alone.
The routing nonce that binds the candidate chain and keys per-offer labels is
suite-independent and is not passed here, which is what allows a suite to size
its field freely (`core-v1.6.md` section 5, ADR 0040).

`Accept` and `IsEligible` answer different questions and MUST NOT be merged.
`Accept` is well-formedness for the given role. `IsEligible` is the recipient's
decision that a well-formed field addresses it, and only a recipient can
answer it: a relay MUST NOT be able to, which is the property a rerandomising
suite exists to provide. A suite carrying no endpoint-specific material, such
as R1, answers `IsEligible` true for every well-formed field. A recipient
holding no key MUST answer false rather than true — absence must not read as
acceptance.

The route protocol additionally assigns each suite:

```text
suite_id
network_enabled
endpoint_specific
minimum_length
maximum_length
failure_policy
```

All four operations MUST have one uniform externally observable failure class:
a well-formed field that is not addressed to this recipient MUST be refused
indistinguishably from a malformed one. The two MAY be, and are, distinguished
in local counters under separate registry error identifiers. A disabled suite
MUST fail before branch-state allocation.

## 2. Active and research providers

| Provider | Suite ID | Network status | Endpoint-specific | Purpose |
|---|---:|---|---|---|
| R1 rendezvous capability | `0x0101` | Active experimental | No | Generic gateway discovery; endpoint token used after READY |
| C1 v2 negative control | `0x0003` | Research only | Yes | Reproduce persistent algebraic tagging; `0x0001` retired |
| C2 symbolic oracle | `0x0002` | Research only | Yes | Test ideal active-security composition |
| C2 k=2 audit | `0x7f02` | Disabled | Yes | Equation and encoding audit; fail closed |

## 3. Source-independent security requirements

A future endpoint-specific suite MAY be activated only if it provides:

1. correctness;
2. message confidentiality;
3. receiver anonymity or key privacy in the multi-recipient setting;
4. public ciphertext-only transformation without the recipient key;
5. transformed-ciphertext distributional independence;
6. resistance to persistent active tags and selective-failure linkage;
7. canonical key, ciphertext, proof, and error encodings;
8. subgroup and malformed-input validation;
9. composition with branch replacement, M2, W2, and E1;
10. independently reproduced vectors and cryptographic review.

These requirements are informed by the application-level URE treatment in Banfi, Maurer, and Ritsch, [IACR ePrint 2023/1165](https://eprint.iacr.org/2023/1165), but this interface does not depend on one paper's notation.

## 4. Provider isolation

The simulator and future implementation MUST depend on this interface rather than import a concrete eligibility scheme in the lifecycle code. Candidate authentication, reply-key handling, M2/W2 encoding, and route-state activation remain separate components.

A provider marked `network_enabled = false` MUST NOT be selected by a production configuration. Suite `0x7f02` MUST be rejected by every network decoder.
