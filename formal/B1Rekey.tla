----------------------------- MODULE B1Rekey -----------------------------
\* SPDX-License-Identifier: Apache-2.0
\*
\* B1.1 rekey key-generation overlap (spec/link-handshake-b1.md section 7).
\*
\* A rekey installs a new session while records sealed under the previous one
\* may still be in flight, so a link briefly holds two usable generations. The
\* danger in that arrangement is not the overlap itself but its accumulation: a
\* node that kept every generation it installed would keep every key it had
\* ever held, and a retired key that could become usable again would undo the
\* point of rekeying at all.
\*
\* The set of usable generations is therefore modelled as a set rather than as
\* a current/previous pair. Under a pair the bound below could not fail and
\* would prove nothing; as a set, a rekey that accumulated instead of replacing
\* is a reachable state and the bound is what rejects it.
\*
\* What a generation *is* -- keys, epoch, replay window -- is the handshake's
\* business and is fixed by the vectors. What is modelled here is which
\* generations a link may open a record under, and when.
EXTENDS Naturals, FiniteSets

CONSTANT MaxGeneration

VARIABLES
    current,  \* the generation records are sealed under now
    usable,   \* every generation a received record may still be opened under
    retired   \* every generation put beyond use

vars == <<current, usable, retired>>

TypeOK ==
    /\ current \in 0..MaxGeneration
    /\ usable \subseteq 0..MaxGeneration
    /\ retired \subseteq 0..MaxGeneration

Init ==
    /\ current = 0
    /\ usable = {0}
    /\ retired = {}

\* A completed rekey. The new generation becomes current and the one it
\* replaces enters its overlap; anything else that was still usable is retired
\* in the same step, because the implementation holds one previous receive key
\* rather than a history. Dropping the `\ {current}` here is the accumulation
\* this model exists to reject.
Rekey ==
    /\ current < MaxGeneration
    /\ current' = current + 1
    /\ usable' = {current + 1, current}
    /\ retired' = retired \cup (usable \ {current})

\* The overlap elapsed. A separate step because it is driven by a deadline
\* rather than by the peer, so it may fall either side of a further rekey.
Retire ==
    /\ \E generation \in usable \ {current} :
        /\ usable' = usable \ {generation}
        /\ retired' = retired \cup {generation}
    /\ UNCHANGED current

Next == Rekey \/ Retire

Spec == Init /\ [][Next]_vars

\* A retired generation is never usable again: a link cannot be walked back
\* onto a key it has already given up.
RetiredNeverReturns == retired \cap usable = {}

\* Key material does not grow with the number of rekeys a long-lived link
\* performs. This is the property the set-valued model exists to make checkable.
AtMostTwoUsable == Cardinality(usable) <= 2

\* The overlap only ever holds the generation immediately before the current
\* one, which is what makes the bound above hold for any number of rekeys
\* rather than only the first.
OverlapIsImmediatelyPrior == usable \subseteq {current, current - 1}

\* The generation being sealed under is always openable. A rekey that installed
\* a send key without its matching receive state would strand the link.
CurrentIsUsable == current \in usable

=============================================================================
