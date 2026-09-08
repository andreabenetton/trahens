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
#   ok        a joiner is admitted, and the invitation and pin reach the store
#   replay    a second joiner presenting the same invitation is refused (D8)
#   restart   the admitting node restarts; the invitation is still spent (D8+D10)
#   hostile   trahens-hostile floods the listening socket, and a legitimate
#             joiner is still admitted afterwards -- the bounds of section 8
#             against the peer they were written for
#
# The hostile arm is the one that needs care. A flood that did not happen would
# leave every assertion below trivially true, so the run asserts the flood
# occurred before asserting it did no harm.
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
  ok|replay|restart|hostile) ;;
  *) echo "unknown scenario: $SCENARIO" >&2; exit 2 ;;
esac

for binary in trahens-admit trahens-join trahens-hostile; do
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
LEFT="ta${TAG}l"
RIGHT="ta${TAG}r"
INVITER_IP=10.201.0.1
JOINER_IP=10.201.0.2
PORT=45301

PIDS=()
cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  ip netns del "$INVITER_NS" 2>/dev/null
  ip netns del "$JOINER_NS" 2>/dev/null
}
trap cleanup EXIT

ip netns add "$INVITER_NS"
ip netns add "$JOINER_NS"
ip -n "$INVITER_NS" link set lo up
ip -n "$JOINER_NS" link set lo up
ip link add "$LEFT" type veth peer name "$RIGHT"
ip link set "$LEFT" netns "$INVITER_NS"
ip link set "$RIGHT" netns "$JOINER_NS"
ip -n "$INVITER_NS" addr add "$INVITER_IP/30" dev "$LEFT"
ip -n "$JOINER_NS" addr add "$JOINER_IP/30" dev "$RIGHT"
ip -n "$INVITER_NS" link set "$LEFT" up
ip -n "$JOINER_NS" link set "$RIGHT" up

# One invitation per joiner, because ADR 0046 D8 makes them per-joiner. The
# second is offered in every scenario and used only by `replay`, so that arm
# differs from `ok` in exactly one thing: which invitation the second joiner
# presents.
INVITER_SECRET=1111111111111111111111111111111111111111111111111111111111111111
JOINER_SECRET=2222222222222222222222222222222222222222222222222222222222222222
SECOND_JOINER_SECRET=3333333333333333333333333333333333333333333333333333333333333333
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
  ip netns exec "$INVITER_NS" "$BIN/trahens-admit" \
    --bind "$INVITER_IP:$PORT" \
    --store "$STORE" \
    --static-secret "$INVITER_SECRET" \
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

join() {
  local log="$1" secret="$2" identifier="$3" invitation_secret="$4" static="$5" port="$6"
  ip netns exec "$JOINER_NS" "$BIN/trahens-join" \
    --bind "$JOINER_IP:$port" \
    --peer "$INVITER_IP:$PORT" \
    --static-secret "$secret" \
    --invitation-id "$identifier" \
    --invitation-secret "$invitation_secret" \
    --inviter-static "$static" \
    --timeout-ms 6000 \
    >"$log" 2>"${log%.log}.err"
}

FIRST_INVITER_LOG="$OUTPUT/inviter.log"
INVITER_LOG="$FIRST_INVITER_LOG"
start_inviter "$INVITER_LOG"
STATIC=$(inviter_static "$INVITER_LOG")
if [[ -z "$STATIC" ]]; then
  echo "admission: the inviter did not publish its static key" >&2
  exit 1
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

JOIN_STATUS=0
join "$OUTPUT/joiner-1.log" "$JOINER_SECRET" "$ID_ONE" "$SECRET_ONE" "$STATIC" 45311 \
  || JOIN_STATUS=$?

case "$SCENARIO" in
  replay)
    # The same invitation, a different joiner. D8 makes it single-use, so this
    # must be refused -- and refused after the cookie, so the joiner is
    # challenged and then simply never answered.
    SECOND_STATUS=0
    join "$OUTPUT/joiner-2.log" "$SECOND_JOINER_SECRET" "$ID_ONE" "$SECRET_ONE" \
      "$STATIC" 45312 || SECOND_STATUS=$?
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
