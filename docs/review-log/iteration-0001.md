<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Iteration 0001 - Scope and executable baseline

- Date: 2026-07-30
- Status: Completed

## Question

Can the legacy design be reduced to a coherent, testable protocol nucleus without first solving a new link layer, global directory, and strong traffic-analysis resistance?

## Changes

- Preserved the legacy LaTeX and PDF without semantic edits.
- Repositioned the project as an overlay-first research protocol.
- Split local bounded discovery from long-range directory resolution.
- Replaced implicit left/right label derivation with abstract direction-bound random hop labels.
- Added explicit DISCOVER, CANDIDATE, COMMIT, READY, ABORT, and CLOSE semantics.
- Added discovery, tentative, and active state lifecycles.
- Added resource bounds and validation ordering.
- Declared the stable discovery ID privacy weakness rather than claiming unlinkability.
- Added a deterministic simulator for bounded outward discovery.

## Accepted conclusions

1. The local state-installation idea can be specified independently of the global directory.
2. Explicit COMMIT and READY phases make route selection and activation less ambiguous than the legacy acknowledgement pair.
3. The first-parent rule provides simple loop suppression and bounded state but may reduce path diversity.
4. A stable discovery ID makes the first simulator and resource model tractable, but it prevents the original non-adjacent unlinkability claim.
5. Degree obfuscation should not be a prerequisite for forwarding correctness.

## Next question

How much reachability and responder-discovery probability is lost when strict first-parent suppression and small fan-out limits are used to control amplification?
