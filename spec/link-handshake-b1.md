<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens B1.1 authenticated adjacent-link handshake

- Status: Normative. Core v1.8 is the active profile.
- Decisions: `docs/adr/0043-b1.1-handshake-decisions.md`,
  `docs/adr/0044-authenticating-the-first-handshake-message.md`
- Scope: `docs/b1.1-scope.md`
- Registry: `protocol-registry-v1.8.json`
- Reference: `simulator/trahens_crypto/b1.py`; vectors in `b1-test-vectors.json`

## 1. Purpose

B1.1 replaces the pre-shared W2 base key and configured epoch with a handshake
that authenticates both peers, negotiates the profile set inside the
authenticated transcript, and derives the directional W2 keys, the epoch, and
an export key from the finished exchange. Every process session therefore has
its own keys, and the restart hazard recorded in `p1-prototype-profile-v1.7.md`
ceases to exist rather than being an operator obligation.

Peers remain manually named. What each peer knows in advance is the other's
peer id, address, and expected static public key, from a manifest.

## 2. Construction

Both exchanges are Noise revision 34, pattern `XX` under the `psk0` modifier,
instantiated as `Noise_XXpsk0_25519_ChaChaPoly_SHA256`. The protocol name is
the registry domain `b1_noise_protocol` and MUST match that string exactly,
because it is the initial hash and chaining key.

```text
-> e
<- e, ee, s, es
-> s, se
```

The prologue is domain separation only: `b1_prologue` for an initial handshake,
`b1_rekey_chain` for a rekey. No key material is carried in the prologue. A
prologue reaches only the handshake hash, so binding a key that way would leave
the traffic keys unbound to it — with the same ephemerals two exchanges would
derive the same keys, because `Split()` reads the chaining key. Key material
therefore enters as the `psk0` pre-shared key, through `MixKeyAndHash`, which
reaches the chaining key as well.

The pre-shared key differs by exchange:

- a **rekey** uses the export key of the session it replaces, which is what
  stops an unrelated exchange being spliced in as a rekey and what makes a
  rekey's traffic keys differ from the replaced session's;
- an **initial handshake** uses `HMAC-SHA256(k = X25519(s, rs), m =
  b1_static_psk)`, the static-static Diffie-Hellman between the two manifest
  identities. Both peers compute it offline from what they already hold, so
  nothing carries it and no exchange establishes it.

The static-static value is keyed as the HMAC key rather than the message
because it is a fixed 32 bytes and the domain is not, which is the arrangement
both a Python and a Rust implementation can express identically.

An initial handshake therefore requires the manifest entry to *begin*, not only
to verify. That is not a new assumption — section 1 already has each peer
holding the other's expected static public key, and section 4 already refuses
anything else — but it does foreclose any trust-on-first-use path on this
exchange, which B1.1 forecloses anyway.

Static handshake keys are X25519 keys used for nothing else. A node's Ed25519
signing key is not converted into its handshake identity.

## 3. Records

Every handshake record is exactly `b1_record` (1,052) bytes, so invariant 1
holds from the first record on a link. A record begins with a two-byte prefix:
a zero byte, then the record type from `b1_record_types`. Derived epochs always
have their top bit set (section 6), so a receiver distinguishes a handshake
record from a W2 cell by its first byte, with no trial decryption.

That leaves the first byte allocated as follows, and the gap is reserved:

| first byte | meaning |
|---|---|
| `0x00` | B1.1 handshake record; the next byte is the type |
| `0x01`–`0x7f` | **reserved**; no datagram this profile defines uses it |
| `0x80`–`0xff` | W2 cell, the leading byte of a derived epoch |

A later datagram type carried on the same port MUST take its discriminator from
the reserved range. Confirmed against captures: every epoch observed on the
wire begins `0x80` or above, and every handshake record begins `0x00`. A
receiver that reaches the reserved range today treats the datagram as a cell
with an unopenable epoch and drops it, which is correct but not a reservation —
a receiver that adds a type MUST check the range before attempting W2, or the
new type is eaten by the cell path.

```text
initiate            0x00 type                          e(32)  enc(payload)(1018)
respond             0x00 type  e(32)  enc(s)(48)              enc(payload)(970)
finish              0x00 type         enc(s)(48)              enc(payload)(1002)
admission_initiate  0x00 type  id(16) cookie(32)       e(32)  enc(payload)(970)
cookie_challenge    0x00 type  id(16) cookie(32)       padding
```

The last two are the admission exchange of ADR 0048 and are described in
section 4.1. They keep the `0x00` first byte and differ in the second, like
every other record type, so section 3's allocation is unchanged and a receiver
needs no new discriminator.

Each payload is a two-byte big-endian length, the body, and zero padding to a
fixed width. The padding is inside the region Noise hashes and, where a key
exists, encrypts, so it is authenticated. A receiver MUST reject non-zero
padding. The finish payload is empty.

The framed widths are `b1_initiate_payload_psk`, `b1_respond_payload`,
`b1_finish_payload` and, for an admission initiate, `b1_admission_payload` —
narrower by the `b1_admission_header` (48) bytes its cleartext header spends. Under `psk0` a key exists from the start, so the first
payload is encrypted and its ciphertext carries a 16-byte tag; that holds for
both exchanges.

Every `e` token also mixes the public ephemeral into the chaining key, not only
into the hash, as Noise section 9 requires of a PSK handshake. Without it the
ephemeral would contribute nothing to the key for the first message, since
under `psk0` a key already exists before any Diffie-Hellman.

Because the first message is encrypted under a key the sender can only hold by
knowing the manifest identity, a receiver refuses a forged or mismatched first
record where it arrives — before performing any Diffie-Hellman, and without
answering. Under plain `XX` that message was unencrypted: anyone able to reach
the port could produce one, and the responder replied with two Diffie-Hellman
operations and its own static key. `docs/adr/0044-authenticating-the-first-handshake-message.md`
records why this was changed and why `KK`, which would also have hidden the
responder's identity, would not have fixed the work: its first message carries
`es` and `ss`, so a responder must compute before it can reject.

## 4. Message processing

Both sides follow the Noise `XX` token sequence exactly as the reference does.
Two checks are added, in this order, at the point the peer's static key has
been decrypted and authenticated:

1. The presented static key MUST equal the manifest entry for this peer id.
   A mismatch aborts. Trust on first use is not a B1.1 behaviour.
2. The responder's selection MUST be within the initiator's offer
   (section 5). Either side aborts otherwise.

No key is derived and no W2 or P1 state is allocated until the third message
has authenticated. Every failure is one generic outcome to the peer: the
receiver does not say why.

### Admission handshakes

Check 1 has one exception, and it is not trust on first use. B1.2 admits a peer
the responder has no manifest entry for, keying `psk0` from an invitation
instead of the static-static value (ADR 0046). A responder in that mode has
nothing to compare the presented static key against, so it **records** the key
rather than checking it, and the caller promotes it into the manifest. Later
handshakes between those two peers take the manifest path and check 1 applies
again.

What authenticates such a peer is the admission key the whole exchange ran
under: without it the first message does not decrypt, so nothing reaches the
point where a key could be recorded. That is why an invitation is per-joiner
and single-use — a shared or reusable one would make this recording an
impersonation vector rather than an admission.

An implementation MUST NOT make recording reachable on the manifest path. A
responder that both pins and records is one refactor away from one that only
records, which is the trust-on-first-use behaviour B1.1 excludes. The reference
exposes the recorded key only in admission mode and leaves it unset otherwise,
and a responder MUST refuse to start with neither a manifest entry nor an
admission key, since that combination authenticates the peer by nothing at all.

### 4.1 How an admission exchange starts

A responder cannot decrypt an admission initiate until it knows which invitation
keys it, and MUST NOT allocate a handshake context until the sender has proved
it receives datagrams at the address it claims. Both facts therefore travel in
the clear, in the record's first 48 bytes, and both are read before anything is
allocated:

```text
admission_initiate  0x00 type  id(16) cookie(32)  e(32)  enc(payload)(970)
```

The header is cleartext but not unprotected. It is mixed into the transcript
before the ephemeral, so a modified identifier or cookie makes the payload fail
to open. A man in the middle can neither strip the cookie nor move it onto
another invitation.

A joiner has no cookie the first time it writes, so it sends 48 bytes of which
the last 32 are zero. **An absent cookie is not a distinct case.** It fails
verification, and failing verification means one thing:

1. The joiner sends `admission_initiate` with a cookie that does not verify.
2. The responder allocates nothing, performs no Diffie-Hellman, and answers
   `cookie_challenge` carrying a cookie bound to the observed source, echoing
   the identifier so a joiner with several attempts outstanding can match it.
3. The joiner resends `admission_initiate` with that cookie.
4. The responder allocates, and the exchange proceeds as section 4 describes.

A responder MUST NOT distinguish an absent cookie from a wrong one, so that
there is no branch a sender can steer and no state held for a first attempt.
The two attempts do not share a transcript, because the cookie is inside it, so
a cookie cannot be carried from one attempt into another.

A `cookie_challenge` is one cell wide like every other record, so a responder
that answers a spoofed source amplifies by a factor of one and a reflector gains
nothing it would not gain by sending to the victim directly. This is why no
bound on challenge issuance is specified: there is nothing for one to prevent.

A challenge carries no authentication of its own and claims none. A forged one
makes a joiner echo a cookie that will not verify and be challenged again, which
is a denial of service by an attacker that can already reach the joiner. A
receiver MUST reject a challenge whose padding is non-zero, as for every other
record.

`admission-cookie-b12.md` defines the cookie's `offer` input as the parameters
offered so far; on this path that is **the invitation identifier**, the header's
first field. It cannot be the whole header, which contains the cookie itself.
Binding it means a cookie issued for one invitation cannot be spent on another
from the same address.

The second message's payload differs on this path, and only on this path:

```text
manifest, rekey:  selection
admission:        selection || advertisement_key(32) || transition(64)
```

`transition = Ed25519-Sign(advertisement_secret, b1_transition || h)`, where `h`
is the handshake hash at the moment that payload is about to be encrypted — the
same value the AEAD takes as associated data, so both ends hold it without
carrying a second transcript. It already covers both ephemerals, the responder's
static key and the cleartext admission header, so one signature binds the
advertisement key to this responder, this joiner and this exchange.

The transcript is signed rather than the static key. A signature over the static
key alone would be a standing certificate: replayable into any exchange by
anyone who saw it once, which is ADR 0045 D5's "the two halves can be attacked
separately".

An initiator MUST verify it against the key the payload carries. That proves
whoever completed the exchange holds that advertisement key. Comparing the key
against a **cached advertisement** is a separate step and is the one that makes
it a statement about the candidate the joiner chose; a joiner that arrived
without an advertisement has nothing to compare and is no worse off than before.

It is unconditional here and absent everywhere else (ADR 0049 D16). A responder
that could decline to bind itself would present a joiner with the one case it
cannot tell apart from an attack, so an admitting node holds an advertisement
key whether or not it has advertised. The payload framing is unchanged —
`b1_respond_payload` (954) has room — so the record stays one cell and the
manifest and rekey exchanges are byte-identical to what v1.8 publishes.

A responder MUST issue a challenge whether or not it holds the invitation the
identifier names, and whether or not that invitation has been spent. Replying
only for invitations it holds would make the reply an oracle: a prober could
enumerate which identifiers a node is carrying, and — because a spent invitation
stops being live — which it has already used.

A responder MUST look the invitation up **after** allocating, not before. Before
the gate, anyone holding a cookie could probe for valid identifiers at the cost
of a hash lookup; after it, a probe spends the prober's own public-key budget and
counts toward its backoff. The context MUST be released as a *failure* when the
lookup refuses, or the probe costs nothing after all.

A node that holds no admission state MUST refuse rather than challenge. ADR 0047
D12 requires a store path for any node that can admit, and a challenge a node
could not follow through on is a reply it should not have sent.

Nothing acknowledges the third message, so an initiator that sent it cannot
know it arrived. A responder that has not received it MUST keep resending its
second message, and an initiator MUST resend its third on receiving a repeated
second — that repeat is the only signal the record was lost. Without this a
single dropped datagram strands a responder that is still waiting while the
initiator believes the link is up, and on a path of several links the chance of
that is not small.

## 5. Negotiation

The initiator's offer is:

```text
version(1) || n || w2 profile ids (n bytes)
           || n || t1 profile ids
           || n || t2 profile ids
           || n || suite ids (2n bytes)
           || resource class(1)
```

Each `n` is at least 1 and at most `max_offered_profiles_per_class`. The
version MUST equal the registry's protocol version. A suite the registry marks
retired or disabled, or the symbolic C2 control, MUST be rejected at parse; it
cannot be offered, so it cannot be selected.

The responder's selection is:

```text
version(1) || w2(1) || t1(1) || t2(1) || suite(2) || resource class(1)
```

It MUST name one value from each offered list and the same version and
resource class. Because both payloads are transcript-bound, a peer that strips
a stronger profile from the offer, or substitutes a suite, causes the handshake
to fail rather than to succeed on the weaker set. There is no pre-shared-key
path to fall back to.

## 6. Derivation

After the third message, with `ck` the final chaining key and `h` the
handshake hash, using the Noise HKDF:

```text
(k_i2r, k_r2i) = HKDF(ck, "", 2)                    -- Noise Split
export_key     = HKDF(ck, b1_export || h, 1)[0]
epoch          = HKDF(ck, b1_epoch  || h, 1)[0][0..4] with byte 0 |= 0x80
```

`k_i2r` is the initiator's W2 send key and the responder's receive key;
`k_r2i` the reverse. The epoch is the W2 epoch for both directions. Its top bit
is forced set so that no derived epoch begins with a zero byte, which is what
section 3 relies on.

Uniqueness of the epoch follows from both ephemeral contributions being fresh,
not from any stored counter. `docs/adr/0042-link-epoch-strategy.md` records why
the alternatives were rejected.

## 7. Rekey

A rekey is a complete new handshake on the established link, using the
`rekey_*` record types and the `psk0` instantiation, with the previous
session's export key as the pre-shared key. A responder that receives a
`rekey_initiate` record MUST run the handshake with the export key of the
session it currently holds; an initiator chained to any other session produces
a first message the responder cannot decrypt. This is what prevents an
unrelated handshake from being spliced in as a rekey, and because the export
key reaches the chaining key, it also means a rekey's traffic keys differ from
the replaced session's even if every ephemeral were to repeat.

Only the initiator opens a rekey, by the same lower-identifier rule that decides
who opens the initial handshake, so two ends cannot rekey past each other. A
rekey is carried in band on a link that is already passing traffic: records are
distinguished from cells by the leading zero byte, the outstanding record is
resent on a timer until the peer answers, and normal traffic continues under the
current keys throughout.

`formal/B1Rekey.tla` models the generation overlap: a retired generation never
becomes usable again, at most two are live at once however many rekeys a link
performs, and the overlap only ever holds the immediately preceding generation.

The initiator MUST rekey before `rekey_after_cells` cells have been sent in
either direction or `rekey_after_ms` has elapsed, whichever comes first. Those
registry values are ceilings, not mandates: an implementation MAY rekey sooner,
and a conformance run is expected to, because no realistic run reaches the
ceiling. On
completion each side installs the new generation for receiving and keeps the
old receive key for at most `rekey_overlap_ms`, then zeroizes it. A record that
authenticates under neither key is rejected.

The two ends switch their **send** keys at different moments, and the asymmetry
is required. A responder switches on reading the finish record, because the
peer that wrote it already holds both keys. An initiator MUST NOT: nothing
acknowledges the finish record, so writing it is no evidence the responder read
it. An initiator therefore keeps sending under the old key until it opens a
record under the new receive epoch, which only a peer that installed the
generation can produce — and because a link emits chaff on every slot, that
arrives within one slot rather than waiting for real traffic. Until it does,
the initiator MUST NOT open another rekey.

Switching on write instead makes every cell unreadable until the finish record
lands, and if that record is lost the damage is not bounded by the loss: the
initiator has advanced its chain, so its next rekey is one the responder cannot
answer, and the two ends diverge permanently. Measured on a five-percent link
rekeying every 48 cells, that turned into roughly a thousand undecryptable
cells per link and a route that never completed, in about one run in four.

## 8. Bounds and failure

A node MUST bound, from the registry: outstanding handshake contexts
(`max_handshake_contexts`); public-key operations per source per interval
(`handshake_pubkey_ops_per_interval`, `handshake_interval_ms`); handshake
duration (`handshake_timeout_ms`) and retransmissions
(`max_handshake_retransmits`); and consecutive failures before backing off a
source (`max_failed_handshakes_before_backoff`, `handshake_backoff_ms`).

How each is met differs between a node with only configured links and one that
accepts handshakes from a source it was not told about, and the difference is
worth stating exactly.

- `handshake_timeout_ms` and `max_handshake_retransmits` are enforced directly
  on every path: each attempt runs to a deadline and divides it into that many
  sends.
- On the P1 topology alone, `max_handshake_contexts` has nothing to count. A
  node opens exactly one context per configured link, at startup, and accepts
  handshakes on no other path: each link owns a UDP socket connected to its
  peer, so the kernel drops anything from another address before the process
  sees it. There is no listener, so there is no unsolicited context to exhaust.
- On that same topology `handshake_pubkey_ops_per_interval` is bounded twice
  over. A responder performs its Diffie-Hellman work in one `write_respond` per
  attempt and attempts are capped, so the ceiling is a few operations per link
  rather than a rate to police. And since section 2, it reaches that work only
  for a first message that decrypted under the static-static key: a sender who
  does not hold the manifest identity cannot make a responder compute at all,
  whatever its address.

A node that admits an unconfigured source has none of those structural
arguments, and the counters are what replace them. `admission-b12`'s gate
enforces all four, in an order that is itself the requirement: each check is
cheaper than the one after it, and each is reached only by a sender that passed
the one before.

1. The cookie of `admission-cookie-b12.md`, one HMAC, proving the sender
   receives datagrams at the address it claims.
2. Backoff, one lookup: a source that has failed
   `max_failed_handshakes_before_backoff` times consecutively is refused for
   `handshake_backoff_ms`. A success clears the run, so a lossy link is not
   eventually banned; a handshake abandoned past `handshake_timeout_ms` counts
   as a failure, so abandoning is not cheaper than failing.
3. The per-source public-key rate, `handshake_pubkey_ops_per_interval` per
   `handshake_interval_ms`, charged when a context is allocated because that is
   when the responder does the work.
4. The global context pool, `max_handshake_contexts`, which is the only step
   that allocates. It is checked last on purpose: it is the shared resource, and
   a source must have spent its own budget before it can compete for it.

A node MUST NOT reverse that order, because each inversion lets a cheaper attack
reach a more expensive resource.

Per-source accounting is itself state an attacker would otherwise grow for free,
so it is bounded by `max_tracked_sources` and refuses rather than evicting: a
flood that could evict entries could flush a backoff it had just earned. What
makes that bound safe is the cookie coming first — an entry appears only for an
address that answered, so a sender cannot populate the table from addresses it
does not hold.

`implementation/harness/netns-p1.sh --scenario hostile-peer` puts a deliberately
misbehaving peer on a link: it never handshakes and floods its neighbour with
well-framed records carrying rubbish. On the connected-socket topology it does
not exercise the bounds above, and is not claimed to; what it establishes is the
property those bounds protect — that adversarial volume on one link leaves the
other links' fixed-T2 cadence untouched.

`node_runtime::listener` is the listening socket, and its tests are where the
bounds are exercised end to end: a joiner challenged and admitted over a real
socket, an invitation that stays spent across a restart, a cookie that does not
transfer between sources, an abandoned exchange reclaimed at
`handshake_timeout_ms`, and a flood of rubbish that takes no context and leaves
no tracking entry. A listener holds one exchange per source rather than running
one to completion inside its receive loop, because the latter would serialise
admission: a joiner that fell silent would hold every other joiner out for
`handshake_timeout_ms`, and `max_handshake_contexts` would never bind because
the socket would bind first.

A listener MUST read a bounded number of datagrams per turn. A receive loop that
drained the socket would let a flood hold a node past its next scheduled slot,
breaking the fixed-T2 cadence with the flood rather than with the protocol.

`implementation/harness/netns-admission.sh` carries that to a network. Its
`hostile` arm points the same flooding peer at a listening socket rather than a
link, and two further arms check what the bounds are for rather than merely that
they exist:

- `spoof` presents a cookie issued for one address from another, and requires it
  to be refused. A cookie that travelled with its holder would prove nothing
  about where that holder receives datagrams, which is the only thing a cookie
  claims.
- `exhaustion` has one address open `handshake_pubkey_ops_per_interval + 8`
  exchanges and abandon each, and requires the gate to have refused some, no
  context to remain held at the end, and a joiner **at a different address** to
  be admitted regardless. The count comes from the registry rather than being
  written down, so the arm keeps exceeding the budget when the budget moves.

The third address is what makes the last of those an assertion at all: the gate
accounts per source, so an attacker and a victim sharing an address would share
a budget, and the victim's refusal would say nothing about isolation.

A peer that keeps waiting for a record MUST NOT be left worse off by the
records it refuses. A reader commits nothing to its transcript until a whole
record has validated, so a record that fails to open leaves the exchange
exactly as it was. Without that the retry loops this section relies on are
worthless: the transcript has already absorbed the bad record, so the genuine
one that follows can no longer agree with the peer's, and a single malformed
datagram ends the exchange. An initial handshake's first message is
unencrypted, so producing one costs an attacker nothing, and ordinary loss
produces them without an attacker at all.

An implementation SHOULD retry a failed handshake a bounded number of times
before treating the link as unusable. A single attempt is not enough: an outage
that outlasts one attempt would otherwise leave the link down for the lifetime
of the process, so a peer briefly unreachable at startup would be unreachable
permanently.

Retrying does not by itself make a delayed link usable end to end. A node that
starts a protocol clock when it queues a message, rather than when its link is
established, may find that state expired by the time the link carries it: the
initiator's branch TTL and the gateway's capability registration are both
wall-clock lifetimes that an outage can consume before the first cell moves. So
a node MUST NOT start a lifetime whose expiry it does not control until the
link that lifetime depends on has completed its handshake. This is a property
of how a node drives its links rather than of the handshake, and B1.1 supplies
only the signal: the link reports when it is up.

A node with several links cannot obtain that by blocking. Its links do not come
up together, and a node not reading events from the ones already up will stall
their workers in delivery long enough to miss a scheduled slot, breaking the
fixed-T2 trace with the wait itself. A relay therefore does not wait, and does
not need to. It allocates branch state when a DISCOVER arrives, and a DISCOVER
cannot arrive before the link that carried it is up. It may still forward that
branch into a child link that is still handshaking — the send waits for the
link rather than being lost, while the branch's TTL runs — but that cannot be
what fails a route, because the initiator holds the binding lifetime: a relay's
branch lives `branch_ttl_ms` (8,000) from a moment strictly later than the
initiator began its own `route_ttl_ms` (5,000), and every further hop begins
later still. Any delay long enough to expire a relay's branch expired the
initiator's at least three seconds earlier. The ordering, not a wait, is what
closes this.

`implementation/harness/netns-p1.sh --scenario late-peer` is the test. It holds
every link down for longer than one handshake attempt and longer than both
five-second lifetimes, so a run passes only if neither clock started at process
start.

Under plain `XX` a responder performed Diffie-Hellman work to answer any
well-formed first message, before it knew who sent it, and its reply disclosed
its static key to that sender. The `psk0` construction of section 2 closes
both: a first message that does not decrypt under the static-static key is
refused before any Diffie-Hellman and draws no reply, so an unauthenticated
prober obtains neither the work nor the identity.

`implementation/harness/netns-p1.sh --scenario wrong-pin` checks this on the
wire rather than in a unit test. It gives an initiator a static key its peer
does not hold, so the derived pre-shared key differs, and asserts from the
capture that the link carries initiate records and **no** respond record. Under
plain `XX` the responder answered anything well formed, so the same run would
have shown both.

What remains is what the pre-shared key cannot cover. A peer that holds the
manifest identity — a compromised neighbour, or anyone who has obtained a
static key — can still open exchanges and spend a responder's bounded
per-attempt work; the registry bounds are what cap that, and they are the
answer for an authenticated peer misbehaving rather than a stranger. And a
deployment that must accept handshakes from peers it has no manifest entry for
cannot use this construction at all: it has no static-static value to derive
from, so it needs a different first-message defence, and that is B1.2.

## 9. Conformance

`b1-test-vectors.json` fixes, for an initial handshake and a chained rekey,
every key, both negotiation payloads, all three records, the handshake hash,
both directional keys, the epoch, and the export key. An implementation MUST
reproduce every record byte for byte and derive identical outputs.

Both exchanges are additionally replayed through an independent Noise
implementation, which is given the same statics, ephemerals, prologue, chained
key and payloads and must produce the same message bytes and the same handshake
hash (`implementation/rust/crosscheck/tests/cross_check_snow.rs`, kept outside
the workspace so that implementation's dependency tree does not reach it).
That check is what makes the reference trustworthy rather than merely
self-consistent: it found a real defect in the `psk0` path, where the reference
had omitted the `MixKey(e.public_key)` that Noise section 9 requires of an `e`
token in a PSK handshake.
