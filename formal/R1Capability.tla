--------------------------- MODULE R1Capability ---------------------------
\* SPDX-License-Identifier: Apache-2.0
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Capabilities, Gateways, Endpoints, NoEndpoint
VARIABLE registrations

vars == <<registrations>>

TypeOK == registrations \in [Capabilities ->
    [gateway : Gateways, endpoint : Endpoints \cup {NoEndpoint}, expiry : Nat, live : BOOLEAN]]

Init == registrations = [c \in Capabilities |->
    [gateway |-> CHOOSE g \in Gateways : TRUE,
     endpoint |-> NoEndpoint, expiry |-> 0, live |-> FALSE]]

Register(c, g, e, expiry) ==
    /\ ~registrations[c].live
    /\ expiry > 0
    /\ registrations' = [registrations EXCEPT
        ![c] = [gateway |-> g, endpoint |-> e, expiry |-> expiry, live |-> TRUE]]

Redeem(c, g, now) ==
    /\ registrations[c].live
    /\ registrations[c].gateway = g
    /\ now < registrations[c].expiry
    /\ registrations' = [registrations EXCEPT ![c].live = FALSE]

Reject(c, g, now) ==
    /\ \/ ~registrations[c].live
       \/ registrations[c].gateway # g
       \/ now >= registrations[c].expiry
    /\ UNCHANGED registrations

Expire(now) ==
    registrations' = [c \in Capabilities |->
        IF registrations[c].live /\ now >= registrations[c].expiry
        THEN [registrations[c] EXCEPT !.live = FALSE]
        ELSE registrations[c]]

Next ==
    \/ \E c \in Capabilities, g \in Gateways, e \in Endpoints, x \in 1..3 : Register(c,g,e,x)
    \/ \E c \in Capabilities, g \in Gateways, n \in 0..3 : Redeem(c,g,n)
    \/ \E c \in Capabilities, g \in Gateways, n \in 0..3 : Reject(c,g,n)
    \/ \E n \in 0..3 : Expire(n)

AtMostOnce == \A c \in Capabilities : registrations[c].live \in BOOLEAN

Spec == Init /\ [][Next]_vars

=============================================================================
