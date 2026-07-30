# Trahens Eligibility Suite Interface v1

- Status: Active protocol boundary
- Date: 2026-07-30
- Purpose: decouple route discovery and lifecycle processing from destination-eligibility implementations

## 1. Interface

An eligibility suite exposes the following abstract operations:

```text
Setup() -> params
KeyGen(params) -> endpoint_context
Initial(endpoint_context; coins) -> discover_field
Transform(discover_field; coins) -> discover_field'
Accept(local_role, endpoint_context, discover_field) -> boolean
```

The route protocol additionally assigns each suite:

```text
suite_id
network_enabled
endpoint_specific
minimum_length
maximum_length
failure_policy
```

`Initial`, `Transform`, and `Accept` MUST have one uniform externally observable failure class. A disabled suite MUST fail before branch-state allocation.

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
