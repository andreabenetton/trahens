# ADR-0012: Gate route use on reverse READY

- Status: Accepted
- Date: 2026-07-30

## Context

Activating relay mappings during forward COMMIT can leave a route partially active when COMMIT or READY is lost. The initiator could otherwise transmit before knowing that the responder and every required relay accepted the selected transcript.

## Decision

Candidate return creates `TENTATIVE` mappings. COMMIT reserves route capacity and moves each relay mapping to `PENDING_READY`. Application data remains prohibited. The responder returns READY after authenticating the commit challenge. READY moves backward and changes each matching pending mapping to `ACTIVE`.

The initiator exposes the route to the data plane only after authenticating the final READY. Pending or partially active state is reclaimed by finite local deadlines when READY is lost.

## Consequences

- route use is bound to an authenticated end-to-end readiness signal;
- active capacity must be reserved during COMMIT even though data is not yet authorized;
- READY loss can leave temporary partial state, but not indefinite state;
- setup latency includes a full forward COMMIT and reverse READY traversal;
- cleanup correctness does not depend on a final acknowledgement.
