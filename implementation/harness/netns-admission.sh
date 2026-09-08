#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# B1.2 admission over a listening socket, on a real network.
#
# Everything below this has been tested in process. What only two namespaces and
# a veth pair show is that a node accepts a peer it was never configured with:
# the joiner is a separate process with its own address, and the admitting node
# learns of it from the datagram it sends and from nothing else.
#
# The scenarios and what each is for:
#
#   ok         a joiner is admitted, and the invitation and pin reach the store
#   replay     a second joiner presenting the same invitation is refused (D8)
#   restart    the admitting node restarts; the invitation is still spent
#   hostile    trahens-hostile floods the listening socket, and a legitimate
#              joiner is still admitted afterwards -- the bounds of section 8
#              against the peer they were written for
#   spoof      a cookie issued for one address does not work from another
#   exhaustion a peer at one address opens exchanges and abandons them, and a
#              joiner at a different address is admitted regardless
#   seeded     a joiner follows a signed seed manifest and confirms, after the
#              exchange, that it reached the node the manifest named
#   malicious-seed
#              a manifest signed by the same trusted key names the wrong
#              advertisement key, and the joiner refuses
#   discovery  a node advertises, another caches what it receives, and the
#              advertisement is the only thing that put a candidate there
#
# The last two need a third namespace, because the property they check is that
# one source's behaviour does not decide another's. With attacker and victim at
# the same address there would be nothing to tell apart: the gate's per-source
# accounting keys on the address, so a two-namespace run would have the innocent
# joiner sharing the attacker's budget and its refusal would prove nothing.
#
# Every adversarial arm asserts the attack happened before asserting it failed.
# A flood that did not arrive, or an exchange that was never opened, would leave
# the rest of the run trivially true.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCENARIO=ok
OUTPUT=${OUTPUT:-$ROOT/build/p1-admission}
TAG=${TAG:-a}
# Prebuilt, like netns-p1.sh. This script runs under sudo, and root's PATH does
# not carry cargo on a CI runner, so building here would fail with a bare 127
# rather than with anything a reader could act on.
BIN=${BIN_DIR:-$ROOT/implementation/rust/target/release}

while (( $# )); do
  case "$1" in
    --scenario) SCENARIO="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --bin-dir) BIN="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$SCENARIO" in
  ok|replay|restart|hostile|spoof|exhaustion|seeded|malicious-seed|discovery) ;;
  *) echo "unknown scenario: $SCENARIO" >&2; exit 2 ;;
esac

for binary in trahens-admit trahens-join trahens-hostile trahens-seed; do
  [[ -x "${BIN}/${binary}" ]] || {
    echo "missing binary: ${BIN}/${binary}" >&2
    echo "build it first: cargo build --release -p ${binary}" >&2
    exit 2
  }
done

mkdir -p "$OUTPUT"
rm -f "$OUTPUT"/*

INVITER_NS="ta${TAG}inviter"
JOINER_NS="ta${TAG}joiner"
OTHER_NS="ta${TAG}other"
LEFT="ta${TAG}l"
RIGHT="ta${TAG}r"
LEFT2="ta${TAG}m"
RIGHT2="ta${TAG}n"
INVITER_IP=10.201.0.1
JOINER_IP=10.201.0.2
# A second joiner on its own subnet, so it is a different source to the gate.
INVITER_IP2=10.201.1.1
OTHER_IP=10.201.1.2
PORT=45301

PIDS=()
cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  ip netns del "$INVITER_NS" 2>/dev/null
  ip netns del "$JOINER_NS" 2>/dev/null
  ip netns del "$OTHER_NS" 2>/dev/null
}
trap cleanup EXIT

ip netns add "$INVITER_NS"
ip netns add "$JOINER_NS"
ip netns add "$OTHER_NS"
ip -n "$INVITER_NS" link set lo up
ip -n "$JOINER_NS" link set lo up
ip -n "$OTHER_NS" link set lo up
ip link add "$LEFT" type veth peer name "$RIGHT"
ip link set "$LEFT" netns "$INVITER_NS"
ip link set "$RIGHT" netns "$JOINER_NS"
ip -n "$INVITER_NS" addr add "$INVITER_IP/30" dev "$LEFT"
ip -n "$JOINER_NS" addr add "$JOINER_IP/30" dev "$RIGHT"
ip -n "$INVITER_NS" link set "$LEFT" up
ip -n "$JOINER_NS" link set "$RIGHT" up

ip link add "$LEFT2" type veth peer name "$RIGHT2"
ip link set "$LEFT2" netns "$INVITER_NS"
ip link set "$RIGHT2" netns "$OTHER_NS"
ip -n "$INVITER_NS" addr add "$INVITER_IP2/30" dev "$LEFT2"
ip -n "$OTHER_NS" addr add "$OTHER_IP/30" dev "$RIGHT2"
ip -n "$INVITER_NS" link set "$LEFT2" up
ip -n "$OTHER_NS" link set "$RIGHT2" up

# One invitation per joiner, because ADR 0046 D8 makes them per-joiner. The
# second is offered in every scenario and used only by `replay`, so that arm
# differs from `ok` in exactly one thing: which invitation the second joiner
# presents.
INVITER_SECRET=1111111111111111111111111111111111111111111111111111111111111111
JOINER_SECRET=2222222222222222222222222222222222222222222222222222222222222222
SECOND_JOINER_SECRET=3333333333333333333333333333333333333333333333333333333333333333
SEED_SIGNING_SEED=4444444444444444444444444444444444444444444444444444444444444444
INVITER_ADVERTISEMENT=5555555555555555555555555555555555555555555555555555555555555555
ID_ONE=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
ID_TWO=b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
SECRET_ONE=7777777777777777777777777777777777777777777777777777777777777777
SECRET_TWO=8888888888888888888888888888888888888888888888888888888888888888
STORE="$OUTPUT/admission.store"

ADMIT_TIMEOUT_MS=${ADMIT_TIMEOUT_MS:-9000}
if [[ "$SCENARIO" == hostile ]]; then
  ADMIT_TIMEOUT_MS=12000
fi

start_inviter() {
  local log="$1"
  # The wildcard, because the inviter has an interface per joiner subnet and a
  # node that admits strangers does not know which one a stranger arrives on.
  ip netns exec "$INVITER_NS" "$BIN/trahens-admit" \
    --bind "0.0.0.0:$PORT" \
    --store "$STORE" \
    --static-secret "$INVITER_SECRET" \
    --advertisement-secret "$INVITER_ADVERTISEMENT" \
    --invitations "$ID_ONE:$SECRET_ONE,$ID_TWO:$SECRET_TWO" \
    --first-peer-id 1000 \
    --timeout-ms "$ADMIT_TIMEOUT_MS" \
    >"$log" 2>"${log%.log}.err" &
  PIDS+=($!)
  # Wait for the listening event rather than sleeping a guess: a fixed sleep is
  # either too short on a loaded runner or wasted on an idle one, and this is
  # the only thing the joiner actually needs to have happened.
  for _ in $(seq 1 200); do
    if grep -qs '"event":"listening"' "$log"; then return 0; fi
    sleep 0.05
  done
  echo "admission: the inviter never reported listening" >&2
  return 1
}

# The joiner pins the inviter's static key, which an invitation carries out of
# band. Reading it from the inviter's own event rather than deriving it here
# keeps one source for it: a second derivation is a second place to be wrong.
inviter_static() {
  grep -o '"static_public":"[0-9a-f]*"' "$1" | head -1 | grep -o '[0-9a-f]\{64\}'
}

# Wait for the inviter to have read a joiner's third message.
#
# The two ends do not finish together and cannot: nothing acknowledges the third
# message (section 8), so a joiner is done when it sends one and the inviter
# only when it reads one. A scenario that tore the inviter down as soon as the
# joiner returned would be racing that gap rather than testing anything.
wait_for_admission() {
  local log="$1" count="$2" seen
  for _ in $(seq 1 200); do
    # grep -c exits non-zero when it counts none, so the count is taken with
    # `|| true` rather than with a fallback that would print a second line into
    # the arithmetic below.
    seen=$(grep -c '"event":"admitted"' "$log" 2>/dev/null || true)
    if (( ${seen:-0} >= count )); then
      return 0
    fi
    sleep 0.05
  done
  echo "admission: the inviter did not record ${count} admission(s)" >&2
  return 1
}

# join <log> <static> <id> <invitation-secret> <inviter-static> <port> [extra...]
#
# Runs in the joiner namespace. `join_from` is the same thing anywhere else, and
# exists because the scenarios that matter are about two sources being told
# apart.
join() {
  join_from "$JOINER_NS" "$JOINER_IP" "$INVITER_IP" "$@"
}

join_from() {
  local ns="$1" from="$2" to="$3" log="$4" secret="$5" identifier="$6"
  local invitation_secret="$7" static="$8" port="$9"
  shift 9
  ip netns exec "$ns" "$BIN/trahens-join" \
    --bind "$from:$port" \
    --peer "$to:$PORT" \
    --static-secret "$secret" \
    --invitation-id "$identifier" \
    --invitation-secret "$invitation_secret" \
    --inviter-static "$static" \
    --timeout-ms 6000 \
    "$@" \
    >"$log" 2>"${log%.log}.err"
}

cookie_from() {
  grep -o '"cookie":"[0-9a-f]*"' "$1" | head -1 | grep -o '[0-9a-f]\{64\}'
}

FIRST_INVITER_LOG="$OUTPUT/inviter.log"
INVITER_LOG="$FIRST_INVITER_LOG"
start_inviter "$INVITER_LOG"
STATIC=$(inviter_static "$INVITER_LOG")
if [[ -z "$STATIC" ]]; then
  echo "admission: the inviter did not publish its static key" >&2
  exit 1
fi

SEED_ARGS=()
if [[ "$SCENARIO" == seeded || "$SCENARIO" == malicious-seed ]]; then
  # What the inviter actually holds, read from its own event rather than
  # derived a second time here.
  ADVERTISED=$(grep -o '"advertisement_public":"[0-9a-f]*"' "$INVITER_LOG" |
    head -1 | grep -o '[0-9a-f]\{64\}')
  if [[ -z "$ADVERTISED" ]]; then
    echo "admission: the inviter did not publish its advertisement key" >&2
    exit 1
  fi
  # The malicious arm differs in exactly one thing: which key the manifest
  # names. Same signer, same address, same everything else, so what the joiner
  # reacts to can only be the key.
  NAMED="$ADVERTISED"
  if [[ "$SCENARIO" == malicious-seed ]]; then
    NAMED=$(printf 'ee%.0s' {1..32})
  fi
  "$BIN/trahens-seed" \
    --out "$OUTPUT/seed.manifest" \
    --signing-seed "$SEED_SIGNING_SEED" \
    --entries "${NAMED}@${INVITER_IP}:${PORT}" \
    --issued-ms 0 --lifetime-ms 3600000 \
    >"$OUTPUT/seed.log" 2>"$OUTPUT/seed.err"
  SEED_PUBLIC=$(grep -o '"seed_public":"[0-9a-f]*"' "$OUTPUT/seed.log" |
    head -1 | grep -o '[0-9a-f]\{64\}')
  if [[ -z "$SEED_PUBLIC" ]]; then
    echo "admission: no seed manifest was written" >&2
    cat "$OUTPUT/seed.err" >&2 || true
    exit 1
  fi
  SEED_ARGS=(--seed "$OUTPUT/seed.manifest" --seed-key "$SEED_PUBLIC")
fi

if [[ "$SCENARIO" == hostile ]]; then
  # The flood runs against the listening socket itself, which is the case
  # section 8's bounds were written for and which no scenario reached before.
  ip netns exec "$JOINER_NS" "$BIN/trahens-hostile" \
    --bind "$JOINER_IP:45399" \
    --peer "$INVITER_IP:$PORT" \
    --timeout-ms 4000 \
    >"$OUTPUT/hostile.log" 2>"$OUTPUT/hostile.err" &
  PIDS+=($!)
  sleep 4.5
fi

if [[ "$SCENARIO" == discovery ]]; then
  # A second admitting node in the joiner namespace, advertising to the first.
  # Two admitters rather than an admitter and a joiner because the candidate
  # cache lives behind a listening socket: only a node that listens can receive
  # an advertisement, which is D6's separation showing up in the topology.
  ip netns exec "$JOINER_NS" "$BIN/trahens-admit" \
    --bind "$JOINER_IP:$PORT" \
    --store "$OUTPUT/advertiser.store" \
    --static-secret "$SECOND_JOINER_SECRET" \
    --advertisement-secret "$(printf '66%.0s' {1..32})" \
    --invitations "$ID_TWO:$SECRET_TWO" \
    --first-peer-id 2000 \
    --advertise-to "$INVITER_IP:$PORT" \
    --advertise-interval-ms 100 \
    --timeout-ms "$ADMIT_TIMEOUT_MS" \
    >"$OUTPUT/advertiser.log" 2>"$OUTPUT/advertiser.err" &
  PIDS+=($!)
  for _ in $(seq 1 200); do
    if grep -qs '"event":"listening"' "$OUTPUT/advertiser.log"; then break; fi
    sleep 0.05
  done
fi

if [[ "$SCENARIO" == exhaustion ]]; then
  # One address opens exchanges and walks away from each. The count is derived
  # from the budget rather than written down, so the scenario moves when the
  # registry does instead of leaving a literal behind that silently stops
  # exceeding anything: at or below the budget nothing is refused and the
  # assertion below has no signal to read.
  BUDGET=$(python3 "$ROOT/tools/registry_limit.py" handshake_pubkey_ops_per_interval)
  ATTEMPTS=$((BUDGET + 8))
  ABANDONED=0
  for index in $(seq 1 "$ATTEMPTS"); do
    if join_from "$JOINER_NS" "$JOINER_IP" "$INVITER_IP" \
      "$OUTPUT/abandon-${index}.log" "$JOINER_SECRET" "$ID_TWO" "$SECRET_TWO" \
      "$STATIC" $((45400 + index)) --abandon 1; then
      ABANDONED=$((ABANDONED + 1))
    fi
  done
fi

if [[ "$SCENARIO" == discovery ]]; then
  # No joiner: what is under test is that an advertisement, and only an
  # advertisement, put a candidate in the receiver's cache.
  # Both nodes report their counters when they stop, and they do not stop
  # together: the advertiser started later, so reading its log when the receiver
  # finished would read it before it had written anything.
  for _ in $(seq 1 600); do
    if grep -qs '"event":"stopped"' "$INVITER_LOG" &&
      grep -qs '"event":"stopped"' "$OUTPUT/advertiser.log"; then
      break
    fi
    sleep 0.05
  done
  SENT=$(grep -o '"advertisements_sent":"[0-9]*"' "$OUTPUT/advertiser.log" |
    grep -o '[0-9]*' | tail -1 || true)
  CACHED=$(grep -o '"advertisements_cached":"[0-9]*"' "$INVITER_LOG" |
    grep -o '[0-9]*' | tail -1 || true)
  CANDIDATES=$(grep -o '"candidates":"[0-9]*"' "$INVITER_LOG" |
    grep -o '[0-9]*' | tail -1 || true)
  if [[ -z "$SENT" ]] || (( SENT < 2 )); then
    echo "scenario discovery: the advertiser sent ${SENT:-no} advertisements, so" >&2
    echo "the receiver having none proves nothing" >&2
    exit 1
  fi
  if [[ "${CACHED:-0}" == "0" ]]; then
    echo "scenario discovery: ${SENT} advertisements were sent and none was" >&2
    echo "cached, so nothing reached the receiver or nothing verified" >&2
    exit 1
  fi
  if [[ "${CANDIDATES:-0}" == "0" ]]; then
    echo "scenario discovery: advertisements were cached and the candidate cache" >&2
    echo "is empty, which cannot both be true" >&2
    exit 1
  fi
  # D6: receiving an advertisement allocates nothing but a cache entry.
  OPEN=$(grep -o '"handshake_contexts_open":"[0-9]*"' "$INVITER_LOG" |
    grep -o '[0-9]*' | tail -1 || true)
  ADMITTED=$(grep -o '"admissions_completed":"[0-9]*"' "$INVITER_LOG" |
    grep -o '[0-9]*' | tail -1 || true)
  if [[ "${OPEN:-1}" != "0" || "${ADMITTED:-1}" != "0" ]]; then
    echo "scenario discovery: discovery allocated handshake state, which ADR 0045" >&2
    echo "D6 forbids: ${OPEN} contexts open, ${ADMITTED} admissions" >&2
    exit 1
  fi
  echo "scenario discovery: ${SENT} advertisements sent, ${CACHED} cached," \
    "${CANDIDATES} candidate(s) held, and no handshake state allocated"
  exit 0
fi

JOIN_STATUS=0
if [[ "$SCENARIO" == exhaustion ]]; then
  # The innocent joiner is at a different address, which is the whole point: the
  # gate accounts per source, so a run with both at one address would prove
  # nothing about isolation.
  join_from "$OTHER_NS" "$OTHER_IP" "$INVITER_IP2" \
    "$OUTPUT/joiner-1.log" "$SECOND_JOINER_SECRET" "$ID_ONE" "$SECRET_ONE" \
    "$STATIC" 45311 || JOIN_STATUS=$?
else
  join "$OUTPUT/joiner-1.log" "$JOINER_SECRET" "$ID_ONE" "$SECRET_ONE" "$STATIC" 45311 \
    ${SEED_ARGS[@]+"${SEED_ARGS[@]}"} || JOIN_STATUS=$?
fi

case "$SCENARIO" in
  replay)
    # The same invitation, a different joiner. D8 makes it single-use, so this
    # must be refused -- and refused after the cookie, so the joiner is
    # challenged and then simply never answered.
    SECOND_STATUS=0
    join "$OUTPUT/joiner-2.log" "$SECOND_JOINER_SECRET" "$ID_ONE" "$SECRET_ONE" \
      "$STATIC" 45312 || SECOND_STATUS=$?
    ;;
  spoof)
    # A cookie proves the sender receives datagrams where it says. Handing one
    # to a peer at a different address must not carry that proof with it.
    STOLEN=$(cookie_from "$OUTPUT/joiner-1.log")
    if [[ -z "$STOLEN" ]]; then
      echo "scenario spoof: the first joiner reported no cookie, so there was" >&2
      echo "nothing to present from elsewhere" >&2
      exit 1
    fi
    SECOND_STATUS=0
    join_from "$OTHER_NS" "$OTHER_IP" "$INVITER_IP2" \
      "$OUTPUT/joiner-2.log" "$SECOND_JOINER_SECRET" "$ID_TWO" "$SECRET_TWO" \
      "$STATIC" 45312 --cookie "$STOLEN" || SECOND_STATUS=$?
    ;;
  restart)
    # Stop the inviter, start a new one over the same store, and re-offer every
    # invitation as an operator would: its own list has no idea a handshake
    # happened.
    #
    # The first admission has to have landed before the process goes, or this
    # arm would be testing a crash mid-handshake rather than a restart after
    # one -- a different property, and one the store's ordering rule covers
    # separately.
    wait_for_admission "$INVITER_LOG" 1
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    PIDS=()
    wait 2>/dev/null || true
    INVITER_LOG="$OUTPUT/inviter-restarted.log"
    start_inviter "$INVITER_LOG"
    SECOND_STATUS=0
    join "$OUTPUT/joiner-2.log" "$SECOND_JOINER_SECRET" "$ID_ONE" "$SECRET_ONE" \
      "$STATIC" 45313 || SECOND_STATUS=$?
    ;;
esac

# Let the inviter read whatever is still in flight before it is stopped, so the
# assertions below see its view rather than a snapshot of it mid-exchange.
wait_for_admission "$FIRST_INVITER_LOG" 1

# And let it run out its own timeout rather than killing it. Its final event
# carries the counters the assertions need -- how many contexts it still holds,
# how much it dropped -- and a killed process reports none of them, which would
# leave the hostile arm asserting against an absence.
for _ in $(seq 1 400); do
  if grep -qs '"event":"stopped"' "$INVITER_LOG"; then break; fi
  sleep 0.05
done
if ! grep -qs '"event":"stopped"' "$INVITER_LOG"; then
  echo "scenario ${SCENARIO}: the inviter never reported its counters" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Assertions.
# ---------------------------------------------------------------------------

if [[ "$SCENARIO" == malicious-seed ]]; then
  # The joiner is expected to refuse, so the ordinary success assertions below
  # do not apply and this arm finishes here.
  if (( JOIN_STATUS == 0 )); then
    echo "scenario malicious-seed: the joiner accepted a peer the manifest did" >&2
    echo "not name, so the transition of ADR 0049 is not being checked" >&2
    exit 1
  fi
  if ! grep -qs '"event":"seed_mismatch"' "$OUTPUT/joiner-1.log"; then
    echo "scenario malicious-seed: the joiner failed for some other reason than" >&2
    echo "the advertisement key, so the run says nothing about the seed" >&2
    cat "$OUTPUT/joiner-1.log" >&2 || true
    exit 1
  fi
  # Non-vacuity: the exchange has to have got far enough to produce a
  # transition, or a refusal proves nothing about checking one.
  if ! grep -qs '"event":"challenged"' "$OUTPUT/joiner-1.log"; then
    echo "scenario malicious-seed: the joiner never reached the exchange" >&2
    exit 1
  fi
  echo "scenario malicious-seed: the manifest was signed and trusted, named the" \
    "wrong advertisement key, and the joiner refused after the exchange"
  exit 0
fi

if (( JOIN_STATUS != 0 )); then
  echo "scenario ${SCENARIO}: the first joiner was not admitted" >&2
  cat "$OUTPUT/joiner-1.log" >&2 || true
  exit 1
fi
if ! grep -qs '"event":"challenged"' "$OUTPUT/joiner-1.log"; then
  echo "scenario ${SCENARIO}: the joiner was admitted without being challenged," >&2
  echo "so the cookie was not required and ADR 0048 D13 is not in force" >&2
  exit 1
fi
if ! grep -qs '"event":"admitted"' "$OUTPUT/joiner-1.log"; then
  echo "scenario ${SCENARIO}: the joiner reported no admission" >&2
  exit 1
fi

# The inviter's own view has to agree. A joiner that believed it was admitted
# while the inviter did not would be the half-completed handshake the store's
# ordering exists to prevent.
if ! grep -qs '"event":"admitted"' "$FIRST_INVITER_LOG"; then
  echo "scenario ${SCENARIO}: the inviter reported no admission" >&2
  exit 1
fi

# And it has to be on disk. This is ADR 0047 in the only place it can be
# observed from outside the process.
if [[ ! -s "$STORE" ]]; then
  echo "scenario ${SCENARIO}: the admission store is empty, so nothing was" >&2
  echo "recorded and a restart would re-open the invitation" >&2
  exit 1
fi

case "$SCENARIO" in
  ok)
    echo "scenario ok: a joiner with no manifest entry was challenged, admitted," \
      "and recorded"
    ;;
  seeded)
    if ! grep -qs '"event":"seed_confirmed"' "$OUTPUT/joiner-1.log"; then
      echo "scenario seeded: the joiner did not confirm the advertisement key," >&2
      echo "so it followed the manifest without checking where it arrived" >&2
      exit 1
    fi
    echo "scenario seeded: the joiner followed a signed manifest and confirmed" \
      "after the exchange that it reached the node the manifest named"
    ;;
  replay|restart)
    if (( SECOND_STATUS == 0 )); then
      echo "scenario ${SCENARIO}: the spent invitation admitted a second joiner" >&2
      exit 1
    fi
    # Non-vacuity: the second joiner must have got as far as being challenged,
    # or it failed for some unrelated reason and proves nothing about D8.
    if ! grep -qs '"event":"challenged"' "$OUTPUT/joiner-2.log"; then
      echo "scenario ${SCENARIO}: the second joiner was never challenged, so its" >&2
      echo "failure says nothing about the invitation being spent" >&2
      exit 1
    fi
    echo "scenario ${SCENARIO}: the second joiner was challenged and then refused," \
      "so the invitation stayed spent"
    ;;
  spoof)
    if (( SECOND_STATUS == 0 )); then
      echo "scenario spoof: a cookie issued for another address was accepted," >&2
      echo "so it proves nothing about where its holder receives datagrams" >&2
      exit 1
    fi
    # Non-vacuity: the second joiner has to have reached the point of presenting
    # the stolen cookie. A run where it never got that far would fail for an
    # unrelated reason and say nothing about binding.
    if ! grep -qs '"event":"challenged"' "$OUTPUT/joiner-2.log"; then
      echo "scenario spoof: the second joiner never presented a cookie" >&2
      exit 1
    fi
    echo "scenario spoof: a cookie issued for one address did not admit its" \
      "holder from another"
    ;;
  exhaustion)
    if (( ABANDONED <= BUDGET )); then
      echo "scenario exhaustion: ${ABANDONED} exchanges were opened against a" >&2
      echo "budget of ${BUDGET}, so nothing exceeded it and the refusal below" >&2
      echo "would have nothing to read" >&2
      exit 1
    fi
    REFUSED=$(grep -o '"dropped_by_gate":"[0-9]*"' "$FIRST_INVITER_LOG" |
      grep -o '[0-9]*' | tail -1 || true)
    if [[ -z "$REFUSED" ]] || (( REFUSED < 1 )); then
      echo "scenario exhaustion: the gate refused nothing, so ${ABANDONED} abandoned" >&2
      echo "exchanges from one source were all allocated for" >&2
      exit 1
    fi
    OPEN=$(grep -o '"handshake_contexts_open":"[0-9]*"' "$FIRST_INVITER_LOG" |
      grep -o '[0-9]*' | tail -1 || true)
    if [[ "${OPEN:-1}" != "0" ]]; then
      echo "scenario exhaustion: ${OPEN} contexts were still held at the end, so" >&2
      echo "abandoning an exchange costs the responder indefinitely" >&2
      exit 1
    fi
    echo "scenario exhaustion: ${ABANDONED} abandoned exchanges from one address," \
      "${REFUSED} refused by the gate, and a joiner elsewhere still admitted"
    ;;
  hostile)
    # `|| true` on each: an empty grep exits non-zero, and with pipefail that
    # would end the run with no message rather than with the assertion below.
    SENT=$(grep -o '"datagrams_sent":"[0-9]*"' "$OUTPUT/hostile.log" 2>/dev/null |
      grep -o '[0-9]*' | tail -1 || true)
    if [[ -z "$SENT" ]] || (( SENT < 1000 )); then
      echo "scenario hostile: the flood sent ${SENT:-no} datagrams, so the run" >&2
      echo "proves nothing about behaviour under adversarial volume" >&2
      exit 1
    fi
    # The listening node must have seen the flood and refused it without
    # spending a handshake context on any of it.
    OPEN=$(grep -o '"handshake_contexts_open":"[0-9]*"' "$FIRST_INVITER_LOG" |
      grep -o '[0-9]*' | tail -1 || true)
    RECEIVED=$(grep -o '"datagrams_received":"[0-9]*"' "$FIRST_INVITER_LOG" |
      grep -o '[0-9]*' | tail -1 || true)
    # The flood has to have reached the listening node, not merely been sent at
    # it: a run where netem or a wrong address swallowed everything would leave
    # every assertion below trivially true.
    if [[ -z "$RECEIVED" ]] || (( RECEIVED < 1000 )); then
      echo "scenario hostile: the listening node received ${RECEIVED:-no} datagrams," >&2
      echo "so the flood never reached it and the run proves nothing" >&2
      exit 1
    fi
    if [[ "${OPEN:-1}" != "0" ]]; then
      echo "scenario hostile: ${OPEN} handshake contexts were still open, so the" >&2
      echo "flood held state the bounds were supposed to release" >&2
      exit 1
    fi
    echo "scenario hostile: ${SENT} adversarial datagrams against the listening" \
      "socket, and a legitimate joiner was still admitted"
    ;;
esac
