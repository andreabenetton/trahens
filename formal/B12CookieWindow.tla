-------------------------- MODULE B12CookieWindow --------------------------
\* SPDX-License-Identifier: Apache-2.0
\*
\* B1.2 admission cookie window rotation (spec/admission-cookie-b12.md
\* section 3).
\*
\* A responder holds `cookie_windows_accepted` secrets and rotates as the clock
\* crosses a window boundary. The construction has to satisfy two things that
\* pull against each other: a cookie must stop verifying once its secret has
\* aged out, and a cookie issued moments before a boundary must still verify
\* moments after it -- otherwise every rotation would refuse the senders that
\* were mid-exchange, which is the whole reason more than one secret is
\* retained.
\*
\* What is modelled is which secrets a responder holds and which cookies those
\* secrets still verify. The HMAC is not modelled: a cookie is identified by the
\* window it was issued in, because that is what decides acceptance and the rest
\* is fixed by the published vectors.
\*
\* Held secrets are a *set* rather than a current/previous pair, for the same
\* reason B1Rekey models generations as a set: under a pair the bound below
\* could not fail and would prove nothing. As a set, a rotation that retained
\* instead of replacing is a reachable state and the bound is what rejects it.
EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxWindow,        \* how far the clock is allowed to run
    WindowsAccepted   \* cookie_windows_accepted

VARIABLES
    window,   \* the window the responder's clock is in
    held,     \* the windows whose secrets the responder still holds
    issued,   \* every window a cookie has been issued under
    accepted  \* every (cookie window, verifying window) pair that verified

vars == <<window, held, issued, accepted>>

Windows == 0..MaxWindow

TypeOK ==
    /\ window \in Windows
    /\ held \subseteq Windows
    /\ issued \subseteq Windows
    /\ accepted \subseteq (Windows \X Windows)

Init ==
    /\ window = 0
    /\ held = {0}
    /\ issued = {}
    /\ accepted = {}

\* The clock crosses a boundary. A fresh secret is installed for the new window
\* and the oldest is dropped once more than WindowsAccepted are held. Dropping
\* that trim is the accumulation this model exists to reject: a responder that
\* kept every secret would verify a cookie for ever.
Rotate ==
    /\ window < MaxWindow
    /\ window' = window + 1
    /\ LET grown == held \cup {window + 1}
       IN held' = IF Cardinality(grown) > WindowsAccepted
                  THEN grown \ {m \in grown : \A n \in grown : m <= n}
                  ELSE grown
    /\ UNCHANGED <<issued, accepted>>

\* A responder issues a cookie under the window it is in. Nothing else can be
\* issued: the window is inside the MAC, not carried beside it, so a sender
\* cannot choose one.
Issue ==
    /\ issued' = issued \cup {window}
    /\ UNCHANGED <<window, held, accepted>>

\* A sender presents a cookie issued under `w`. It verifies exactly when the
\* responder still holds that window's secret -- which is the implementation:
\* every retained secret is tried, and a retired one has been zeroized.
Verify ==
    /\ \E w \in issued :
        /\ w \in held
        /\ accepted' = accepted \cup {<<w, window>>}
    /\ UNCHANGED <<window, held, issued>>

Next == Rotate \/ Issue \/ Verify

Spec == Init /\ [][Next]_vars

\* -------------------------------------------------------------------------
\* What the construction has to hold.
\* -------------------------------------------------------------------------

\* Key material does not grow with uptime. A responder that retained every
\* secret would still verify a cookie issued days earlier, and the lifetime the
\* spec claims for a cookie would be fiction.
AtMostAcceptedHeld == Cardinality(held) <= WindowsAccepted

\* A secret is never reinstated. Rotation is one-way, so a cookie that has
\* stopped verifying cannot start again -- which is what makes "expires quickly"
\* a property rather than a tendency.
HeldAreRecent == \A w \in held : w <= window /\ window - w < WindowsAccepted

\* The bound stated as the spec states it: nothing verifies more than
\* WindowsAccepted - 1 windows after it was issued.
NothingVerifiesTooLate ==
    \A pair \in accepted : pair[2] - pair[1] < WindowsAccepted

\* And nothing verifies before it was issued, which would mean a responder
\* accepting under a secret it had not installed yet.
NothingVerifiesEarly == \A pair \in accepted : pair[1] <= pair[2]

\* The other half, and the reason more than one secret is retained: a cookie
\* issued in the window a rotation is leaving must still verify in the window it
\* arrives at. Without this every boundary would refuse the senders that were
\* mid-exchange.
\*
\* An earlier version guarded this with `window' - w < WindowsAccepted`, which
\* made it vacuous: that antecedent is the very bound the property is supposed
\* to justify, so at WindowsAccepted = 1 nothing satisfied it and the property
\* passed while describing a responder that refuses everyone. It is written
\* against the window being left instead, so setting WindowsAccepted to 1 breaks
\* it, which is what makes it worth checking.
\*
\* An action property rather than an invariant, because it is about what a
\* rotation may do; an invariant over `accepted` would hold in every state where
\* nobody had presented a cookie.
StillGoodAfterOneRotation ==
    [][(window \in issued /\ window' = window + 1) => window \in held']_vars

=============================================================================
