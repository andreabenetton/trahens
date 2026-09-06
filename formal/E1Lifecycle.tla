---------------------------- MODULE E1Lifecycle ----------------------------
\* SPDX-License-Identifier: Apache-2.0
EXTENDS Naturals, FiniteSets

CONSTANT Routes
VARIABLE phase, allocated

Phases == {"ABSENT", "DISCOVERING", "CANDIDATE", "COMMITTED", "READY", "OPEN"}
vars == <<phase, allocated>>

Init ==
    /\ phase = [r \in Routes |-> "ABSENT"]
    /\ allocated = [r \in Routes |-> FALSE]

Start(r) ==
    /\ phase[r] = "ABSENT"
    /\ phase' = [phase EXCEPT ![r] = "DISCOVERING"]
    /\ allocated' = [allocated EXCEPT ![r] = TRUE]

Candidate(r) ==
    /\ phase[r] = "DISCOVERING"
    /\ phase' = [phase EXCEPT ![r] = "CANDIDATE"]
    /\ UNCHANGED allocated

Commit(r) ==
    /\ phase[r] = "CANDIDATE"
    /\ phase' = [phase EXCEPT ![r] = "COMMITTED"]
    /\ UNCHANGED allocated

Ready(r) ==
    /\ phase[r] = "COMMITTED"
    /\ phase' = [phase EXCEPT ![r] = "READY"]
    /\ UNCHANGED allocated

Open(r) ==
    /\ phase[r] = "READY"
    /\ phase' = [phase EXCEPT ![r] = "OPEN"]
    /\ UNCHANGED allocated

Cleanup(r) ==
    /\ phase[r] # "ABSENT"
    /\ phase' = [phase EXCEPT ![r] = "ABSENT"]
    /\ allocated' = [allocated EXCEPT ![r] = FALSE]

Next == \E r \in Routes :
    Start(r) \/ Candidate(r) \/ Commit(r) \/ Ready(r) \/ Open(r) \/ Cleanup(r)

TypeOK == phase \in [Routes -> Phases] /\ allocated \in [Routes -> BOOLEAN]
AllocationIffState == \A r \in Routes : allocated[r] <=> phase[r] # "ABSENT"

\* A route enters OPEN only from READY.
\*
\* This is an action property, not a state invariant, and that is the whole
\* point: no predicate over a single state can see how the state was reached,
\* so no state invariant can express an ordering. An earlier NoOpenBeforeReady
\* tried, and asserted `phase[r] = "OPEN" => allocated[r]` instead -- which
\* says nothing about READY, and is implied by AllocationIffState, since an
\* OPEN route is not ABSENT. It passed unchanged when Open was given a path
\* from CANDIDATE, so it never checked what its name claimed. That is the same
\* defect the 2026-09-04 review raised as TR-05 against R1Capability's
\* AtMostOnce; this is the sibling model it was not generalised to.
OpenOnlyFromReady == \A r \in Routes :
    phase'[r] = "OPEN" => phase[r] \in {"READY", "OPEN"}

Spec == Init /\ [][Next]_vars
OpenAlwaysFromReady == [][OpenOnlyFromReady]_vars

=============================================================================
