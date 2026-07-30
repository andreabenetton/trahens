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
NoOpenBeforeReady == \A r \in Routes : phase[r] = "OPEN" => allocated[r]

Spec == Init /\ [][Next]_vars

=============================================================================
