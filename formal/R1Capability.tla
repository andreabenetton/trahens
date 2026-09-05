--------------------------- MODULE R1Capability ---------------------------
\* SPDX-License-Identifier: Apache-2.0
\*
\* R1 rendezvous capability redemption.
\*
\* Scope. R1 specifies one-time-PER-GATEWAY redemption. A destination may
\* register the same capability at several gateways
\* (spec/rendezvous-capability-r1.md, "one or more gateways"), and each
\* registration is removed atomically on its own successful redemption. A
\* capability registered at k gateways therefore admits k redemptions by
\* design. GlobalAtMostOnce below records the property R1 deliberately does
\* NOT claim, so that the boundary is explicit rather than implied.
EXTENDS Naturals, FiniteSets

CONSTANTS Capabilities, Gateways, Endpoints, NoEndpoint
VARIABLES registrations, redeemed

vars == <<registrations, redeemed>>

\* Registrations are keyed by (capability, gateway), matching the
\* HashMap<(u32, [u8; 32]), Registration> of crates/rendezvous-r1.
Records == Capabilities \X Gateways

TypeOK ==
    /\ registrations \in [Records ->
        [endpoint : Endpoints \cup {NoEndpoint}, expiry : Nat, live : BOOLEAN]]
    /\ redeemed \in [Records -> Nat]

Init ==
    /\ registrations = [r \in Records |->
        [endpoint |-> NoEndpoint, expiry |-> 0, live |-> FALSE]]
    /\ redeemed = [r \in Records |-> 0]

\* A registration is admitted only when this (capability, gateway) pair is
\* neither live nor already spent. The redeemed guard is what makes
\* AtMostOncePerGateway hold across expiry and re-registration; without it a
\* spent capability could be resurrected and redeemed again.
Register(c, g, e, expiry) ==
    /\ ~registrations[<<c, g>>].live
    /\ redeemed[<<c, g>>] = 0
    /\ expiry > 0
    /\ registrations' = [registrations EXCEPT
        ![<<c, g>>] = [endpoint |-> e, expiry |-> expiry, live |-> TRUE]]
    /\ UNCHANGED redeemed

Redeem(c, g, now) ==
    /\ registrations[<<c, g>>].live
    /\ now < registrations[<<c, g>>].expiry
    /\ registrations' = [registrations EXCEPT ![<<c, g>>].live = FALSE]
    /\ redeemed' = [redeemed EXCEPT ![<<c, g>>] = @ + 1]

Reject(c, g, now) ==
    /\ \/ ~registrations[<<c, g>>].live
       \/ now >= registrations[<<c, g>>].expiry
    /\ UNCHANGED vars

Expire(now) ==
    /\ registrations' = [r \in Records |->
        IF registrations[r].live /\ now >= registrations[r].expiry
        THEN [registrations[r] EXCEPT !.live = FALSE]
        ELSE registrations[r]]
    /\ UNCHANGED redeemed

Next ==
    \/ \E c \in Capabilities, g \in Gateways, e \in Endpoints, x \in 1..3 :
        Register(c, g, e, x)
    \/ \E c \in Capabilities, g \in Gateways, n \in 0..3 : Redeem(c, g, n)
    \/ \E c \in Capabilities, g \in Gateways, n \in 0..3 : Reject(c, g, n)
    \/ \E n \in 0..3 : Expire(n)

Spec == Init /\ [][Next]_vars

\* The normative R1 property: each (capability, gateway) registration is
\* redeemed at most once, including across expiry and re-registration.
AtMostOncePerGateway == \A r \in Records : redeemed[r] <= 1

\* Deliberately NOT an invariant, and not listed in R1Capability.cfg. A
\* capability registered at k gateways can be redeemed once at each. Global
\* one-shot semantics would require cross-gateway spent-token state, which R1
\* does not specify.
RedeemedGateways(c) == {g \in Gateways : redeemed[<<c, g>>] > 0}
GlobalAtMostOnce ==
    \A c \in Capabilities : Cardinality(RedeemedGateways(c)) <= 1

=============================================================================
