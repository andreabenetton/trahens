#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

RELAYS=2
LOSS=0
# Gilbert-Elliott "p,r": p is the good-to-bad transition probability and r
# the bad-to-good one, so a small r produces long outage runs.
BURST_LOSS=""
DELAY=5ms
JITTER=1ms
DUPLICATE=0
REORDER=0
MTU=1500
TIMEOUT_MS=30000
OUTPUT="${PWD}/build/p1-netns"
BIN_DIR="${PWD}/implementation/rust/target/release"
# ok | replay | wrong-capability | expired-capability | no-candidate |
# transport-failure | burst-loss | c1-not-eligible
SCENARIO=ok
# Which T2 schedule profile the nodes run. The mandatory arms use fixed and
# assert the constant cadence they claim; adaptive renegotiates its rate, so
# this script refuses to assert the fixed trace when it is selected. Neither
# profile may make the other's claim.
SCHEDULE_PROFILE=fixed
ELIGIBILITY_SUITE=r1
INITIATOR_LABEL=
# Interoperability mode: run a third-party initiator against our relays and
# gateway. The foreign command receives exactly the arguments our own endpoint
# does, so the CLI contract is the only thing it has to match beyond the wire.
EXTERNAL_ENDPOINT=""

while (($#)); do
  case "$1" in
    --relays) RELAYS="$2"; shift 2 ;;
    --loss) LOSS="$2"; shift 2 ;;
    --burst-loss) BURST_LOSS="$2"; shift 2 ;;
    --delay) DELAY="$2"; shift 2 ;;
    --jitter) JITTER="$2"; shift 2 ;;
    --duplicate) DUPLICATE="$2"; shift 2 ;;
    --reorder) REORDER="$2"; shift 2 ;;
    --mtu) MTU="$2"; shift 2 ;;
    --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --scenario) SCENARIO="$2"; shift 2 ;;
    --schedule-profile) SCHEDULE_PROFILE="$2"; shift 2 ;;
    --eligibility-suite) ELIGIBILITY_SUITE="$2"; shift 2 ;;
    # The initiator addresses its capsule to this label's key; giving the
    # initiator a different one from the gateway is the negative arm.
    --initiator-label) INITIATOR_LABEL="$2"; shift 2 ;;
    --external-endpoint) EXTERNAL_ENDPOINT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "netns-p1.sh must run as root" >&2
  exit 2
fi
for tool in ip tc tcpdump python3 /usr/bin/time; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
for binary in trahens-endpoint trahens-relay trahens-rendezvous; do
  [[ -x "${BIN_DIR}/${binary}" ]] || { echo "missing binary: ${BIN_DIR}/${binary}" >&2; exit 2; }
done

SIGNING_SEED=$(printf '11%.0s' {1..32})
CAPABILITY=$(printf '22%.0s' {1..32})
# The pseudonym a descriptor would publish. Configured on both sides so the
# initiator's authorisation check is actually exercised rather than skipped.
# A scenario can move the gateway's advertised value away from the set the
# initiator authorises while leaving the signing key alone.
GATEWAY_PSEUDONYM=$(printf '33%.0s' {1..16})
ENDPOINT_PSEUDONYMS=$GATEWAY_PSEUDONYM

# Scenario wiring. Negative arms must still reclaim all remote state, which is
# what the P1 gate requires of a rejected redemption.
GATEWAY_TTL_MS=5000
ENDPOINT_CAPABILITY="$CAPABILITY"
ENDPOINT_EXTRA=()
EXPECT_ENDPOINT_FAILURE=0
BLACKHOLE_AFTER_MS=0
EXPECT_RETRY_EXHAUSTION=0
case "$SCENARIO" in
  ok) ;;
  replay)
    # The endpoint presents the same capability twice. The replay never
    # reaches the gateway: the relay only forwards RENDEZVOUS_OPEN while the
    # route is in PENDING_READY, and redemption has already advanced it, so
    # the second presentation is dropped in-path. The endpoint therefore times
    # out rather than receiving a rejection, which still satisfies the gate:
    # the replay is refused and every node reclaims its state.
    ENDPOINT_EXTRA=(--redeem-twice 1)
    EXPECT_ENDPOINT_FAILURE=1 ;;
  wrong-capability)
    # A capability the gateway never registered: the token hash misses.
    ENDPOINT_CAPABILITY=$(printf '33%.0s' {1..32})
    EXPECT_ENDPOINT_FAILURE=1 ;;
  expired-capability)
    # The registration lapses before the route reaches redemption.
    GATEWAY_TTL_MS=1
    EXPECT_ENDPOINT_FAILURE=1 ;;
  no-candidate)
    # Every ring is too shallow to reach the gateway, so the schedule is
    # exhausted and discovery terminates with NO_CANDIDATE. Each ring's branch
    # is cancelled, and every node must still finish with no live routes.
    ENDPOINT_EXTRA=(--rings "1:300,1:300")
    EXPECT_ENDPOINT_FAILURE=1 ;;
  burst-loss)
    # Gilbert-Elliott bursts long enough that a sender runs out its whole T1
    # retry budget. The gate requires that to terminate cleanly, so the
    # assertions below additionally demand that some node actually reported
    # exhaustion rather than the run merely failing some other way.
    #
    # Spending the budget takes about twelve seconds: eight rounds with the RTO
    # doubling from 100ms and clamped at 3s. The initiator has to stay alive
    # for at least that long, so this arm gets one long ring window. With the
    # default window it gave up with NO_CANDIDATE first and tore the path down
    # before any transmission reached exhaustion, which is why the arm was
    # flaky rather than deterministic.
    # A two-state channel only spends the whole budget if its bad state
    # outlasts it, so this is a long outage rather than a stutter: entered
    # quickly (p=40%) and left very slowly (r=0.01%, a mean run far longer than
    # the twelve seconds the budget takes). "20,20" averaged five-packet
    # bursts, which recovery absorbed, so exhaustion happened only by luck.
    BURST_LOSS="40,0.01"
    ENDPOINT_EXTRA=(--rings "16:20000")
    EXPECT_ENDPOINT_FAILURE=1
    EXPECT_RETRY_EXHAUSTION=1 ;;
  c1-not-eligible)
    # The initiator addresses its capsule to a key the gateway does not hold,
    # so the gateway decrypts it, finds it is not the recipient, and declines.
    # Discovery then exhausts its schedule. This is the property C1 exists for:
    # only the recipient can tell, and the relays in between cannot.
    ELIGIBILITY_SUITE=c1
    INITIATOR_LABEL="not-this-gateway"
    EXPECT_ENDPOINT_FAILURE=1 ;;
  wrong-pin)
    # The initiator is given a static key for its peer that the peer does not
    # hold. Under Noise XX the peer's real key still authenticates, so only the
    # manifest pin can reject it -- and it must, before any key is derived.
    #
    # Discovery still starts: spawn_link returns before the handshake finishes,
    # so the endpoint sends a DISCOVER into a link that never comes up. It goes
    # nowhere, that link carries no cell, and the run ends in NO_CANDIDATE. The
    # assertion below is on the handshake failure rather than on the endpoint's
    # exit, so the scenario has to fail for the right reason.
    P1_WRONG_PIN=99
    EXPECT_ENDPOINT_FAILURE=1 ;;
  rekey)
    # Force a rekey inside the run by lowering the trigger far below the
    # registry ceiling, which no run would otherwise reach. Fixed T2 emits 16
    # cells per 200 ms epoch on every link, so a few dozen cells is a second or
    # two: the route is established, rekeys underneath, and must keep working.
    # The gate is the ordinary success gate -- data both ways, clean teardown --
    # because the whole point is that a rekey is invisible to the route above it.
    P1_REKEY_AFTER_CELLS=48 ;;
  unauthorized-pseudonym)
    # The gateway signs with the key the initiator expects but advertises a
    # pseudonym the descriptor does not list, which is what a stale descriptor
    # instance looks like. The signature verifies, so only the authorisation
    # check can reject it; discovery then exhausts its schedule. Without that
    # check the initiator would commit and spend its capability on the wrong
    # instance.
    GATEWAY_PSEUDONYM=$(printf '44%.0s' {1..16})
    EXPECT_ENDPOINT_FAILURE=1 ;;
  transport-failure)
    # The far link blackholes after setup begins, so a sender exhausts its T1
    # retry budget. The gate requires that path to reclaim all remote state.
    BLACKHOLE_AFTER_MS=120
    EXPECT_ENDPOINT_FAILURE=1 ;;
  *) echo "unknown scenario: $SCENARIO" >&2; exit 2 ;;
esac

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUTPUT=$(mkdir -p "$OUTPUT" && cd "$OUTPUT" && pwd)
TAG=$(printf '%04x' $(( $$ & 65535 )))
NODES=$((RELAYS + 2))
PIDS=()
NAMES=()

cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  for name in "${NAMES[@]:-}"; do ip netns del "$name" 2>/dev/null; done
}
trap cleanup EXIT
rm -f "$OUTPUT"/*

for ((i=0; i<NODES; i++)); do
  name="tp${TAG}n${i}"
  NAMES+=("$name")
  ip netns add "$name"
  ip -n "$name" link set lo up
done

for ((i=0; i<NODES-1; i++)); do
  left="t${TAG}${i}a"
  right="t${TAG}${i}b"
  ip link add "$left" type veth peer name "$right"
  ip link set "$left" netns "${NAMES[$i]}"
  ip link set "$right" netns "${NAMES[$((i+1))]}"
  ip -n "${NAMES[$i]}" addr add "10.200.${i}.1/30" dev "$left"
  ip -n "${NAMES[$((i+1))]}" addr add "10.200.${i}.2/30" dev "$right"
  ip -n "${NAMES[$i]}" link set "$left" mtu "$MTU" up
  ip -n "${NAMES[$((i+1))]}" link set "$right" mtu "$MTU" up
  for side in "${NAMES[$i]}:$left" "${NAMES[$((i+1))]}:$right"; do
    ns=${side%%:*}; dev=${side#*:}
    # A burst channel severe enough to exhaust a retry budget is a near-total
    # outage, and netem drops on egress before tcpdump's tap sees the packet.
    # Applying it to every link therefore leaves every capture empty and the
    # 1,052-byte record assertion with nothing to check. Scope it to the
    # gateway-facing link: one sender still starves, and every other link
    # keeps emitting on schedule so the captures stay meaningful.
    if [[ -n "$BURST_LOSS" && $i -eq $((NODES-2)) ]]; then
      ip netns exec "$ns" tc qdisc add dev "$dev" root netem \
        loss gemodel "${BURST_LOSS%,*}%" "${BURST_LOSS#*,}%" \
        delay "$DELAY" "$JITTER" duplicate "${DUPLICATE}%" reorder "${REORDER}%"
    else
      ip netns exec "$ns" tc qdisc add dev "$dev" root netem \
        loss "${LOSS}%" delay "$DELAY" "$JITTER" duplicate "${DUPLICATE}%" reorder "${REORDER}%"
    fi
  done
  # --immediate-mode as well as -U: -U flushes the output file per packet, but
  # libpcap still holds packets in the kernel ring until its buffer fills or a
  # 1s poll timeout elapses. A scenario that completes in well under a second
  # is killed first, and tcpdump reports "0 packets captured" against a
  # non-zero "received by filter" for a run that worked perfectly.
  ip netns exec "${NAMES[$i]}" tcpdump -i "$left" -U --immediate-mode \
    -w "$OUTPUT/link-${i}.pcap" udp \
    >/dev/null 2>"$OUTPUT/link-${i}.tcpdump" &
  PIDS+=("$!")
done

# tcpdump is asynchronous and writes its pcap global header when it opens the
# output file, before it attaches to the interface, so file size is not a
# readiness signal. Wait for the "listening on" line it prints once the capture
# is live; otherwise a fast exchange completes uncaptured and the 1,052-byte
# record assertion fails with an empty capture.
capture_ready_deadline=$(( SECONDS + 15 ))
for ((i=0; i<NODES-1; i++)); do
  until grep -q "listening on" "$OUTPUT/link-${i}.tcpdump" 2>/dev/null; do
    if (( SECONDS >= capture_ready_deadline )); then
      echo "capture on link ${i} did not start within 15s" >&2
      exit 2
    fi
    sleep 0.05
  done
done

# The initiator's candidate window has to cover a candidate returning along
# the whole path, not a fixed stopwatch. Return time grows with the number of
# hops, and under loss a multi-fragment candidate needs several T1 recovery
# rounds on top. A flat window made the five-relay arm marginal: it passes on
# a quiet machine and reports NO_CANDIDATE on a slower one, which measures the
# runner rather than recovery. Scenarios that set their own schedule keep it.
PORT=4242
# No EPOCH: since v1.8 the link epoch is derived from the B1.1 handshake rather
# than configured, which is what makes restarting into a used epoch impossible.
# Shared with multihost-p1.sh so the two harnesses cannot drift into testing
# different protocols.
P1_ADAPTIVE=(--schedule-profile "$SCHEDULE_PROFILE")
P1_SUITE=(--eligibility-suite "$ELIGIBILITY_SUITE")
P1_ENDPOINT_EXTRA=("${ENDPOINT_EXTRA[@]}")
# shellcheck source=implementation/harness/p1-node-args.sh
source "$ROOT/implementation/harness/p1-node-args.sh"

if [[ ${#P1_ENDPOINT_EXTRA[@]} -eq 0 || ! " ${P1_ENDPOINT_EXTRA[*]} " =~ " --rings " ]]; then
  P1_ENDPOINT_EXTRA+=(--rings "16:$(p1_ring_window_ms "$RELAYS")")
fi
GATEWAY_PUBLIC=$(p1_gateway_public "$SIGNING_SEED")



run_node() {
  local ns=$1 name=$2 offset=$3
  shift 3
  ip netns exec "$ns" env TRAHENS_CLOCK_OFFSET_MS="$offset" \
    /usr/bin/time -v -o "$OUTPUT/${name}.time.txt" "$@" \
    >"$OUTPUT/${name}.log" 2>"$OUTPUT/${name}.err" &
  PIDS+=("$!")
}

GIDX=$((NODES-1))
p1_gateway_args "$GIDX" \
  "10.200.$((GIDX-1)).2:${PORT}" "10.200.$((GIDX-1)).1:${PORT}" \
  $((GIDX-1)) "$GATEWAY_TTL_MS"
run_node "${NAMES[$GIDX]}" rendezvous 7 \
  "$BIN_DIR/trahens-rendezvous" "${P1_NODE_ARGS[@]}"

for ((r=RELAYS; r>=1; r--)); do
  p1_relay_args "$r" \
    "10.200.$((r-1)).2:${PORT}" "10.200.$((r-1)).1:${PORT}" $((r-1)) \
    "10.200.${r}.1:${PORT}" "10.200.${r}.2:${PORT}" "$r"
  run_node "${NAMES[$r]}" "relay-${r}" "$((r-RELAYS/2))" \
    "$BIN_DIR/trahens-relay" "${P1_NODE_ARGS[@]}"
done

sleep 0.2
if [[ -n "$EXTERNAL_ENDPOINT" ]]; then
  # Word-split deliberately: the caller supplies a command, possibly with
  # arguments of its own, e.g. "python3 my_endpoint.py".
  read -r -a ENDPOINT_CMD <<< "$EXTERNAL_ENDPOINT"
  echo "interop: initiator is external: ${ENDPOINT_CMD[*]}"
else
  ENDPOINT_CMD=("$BIN_DIR/trahens-endpoint")
fi
if [[ -n "$INITIATOR_LABEL" ]]; then
  P1_SUITE+=(--eligibility-label "$INITIATOR_LABEL")
fi
p1_endpoint_args "10.200.0.1:${PORT}" "10.200.0.2:${PORT}" 0 \
  "$GATEWAY_PUBLIC" "$ENDPOINT_CAPABILITY"
run_node "${NAMES[0]}" endpoint -7 \
  "${ENDPOINT_CMD[@]}" "${P1_NODE_ARGS[@]}"

if (( BLACKHOLE_AFTER_MS > 0 )); then
  (
    sleep "$(python3 -c "print(${BLACKHOLE_AFTER_MS}/1000)")"
    last=$((NODES-2))
    ip netns exec "${NAMES[$last]}" tc qdisc change dev "t${TAG}${last}a" root netem loss 100% \
      >/dev/null 2>&1 || true
  ) &
  PIDS+=("$!")
fi

NODE_START=$((NODES-1))
STATUS=0
for ((i=NODE_START; i<${#PIDS[@]}; i++)); do
  if ! wait "${PIDS[$i]}"; then STATUS=1; fi
done

# Let tcpdump drain its ring buffer before teardown, then wait for each
# capture to exit so its file is closed and flushed. Killing immediately loses
# whatever is still queued: tcpdump reports it as "0 packets captured" against
# a non-zero "received by filter", and the run fails on an empty capture.
sleep 0.5
for pid in "${PIDS[@]:0:NODES-1}"; do kill "$pid" 2>/dev/null || true; done
for pid in "${PIDS[@]:0:NODES-1}"; do wait "$pid" 2>/dev/null || true; done
python3 "$ROOT/tools/check_pcap_cells.py" "$OUTPUT"/*.pcap
python3 "$ROOT/tools/summarize_p1_run.py" --directory "$OUTPUT" --output "$OUTPUT/run-metrics.json"
python3 - "$OUTPUT" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
files=list(root.glob('*.metrics.json'))
# A third-party initiator is not required to emit our metrics format, so it
# may contribute no file. Every node that does emit one must still show no
# leaked state, and there must be at least one: a run where nothing reported
# proves nothing.
assert files, 'no process metrics'
for path in files:
    value=json.loads(path.read_text())
    assert value['live_routes'] == 0, f"state leak in {path}"
report=json.loads((root/'run-metrics.json').read_text())
assert report['all_remote_state_reclaimed']
PY

# The two schedule profiles make different claims and neither may make the
# other's. Fixed asserts the constant cadence the P1 gate rests on; adaptive
# asserts that negotiation happened and stayed within its rules, and is refused
# the fixed-trace assertion entirely.
python3 - "$OUTPUT" "$SCHEDULE_PROFILE" <<'SCHED'
import json, pathlib, sys

root, profile = pathlib.Path(sys.argv[1]), sys.argv[2]
links = [
    (path.name, link)
    for path in sorted(root.glob("*.metrics.json"))
    for link in json.loads(path.read_text()).get("links", [])
]
assert links, "no link metrics"

if profile == "fixed":
    for name, link in links:
        assert link["fixed_trace_valid"], f"{name}: fixed trace broken"
        assert link["missed_slots"] == 0, f"{name}: missed a slot"
        assert link["rate_class_changes"] == 0, f"{name}: rate changed on fixed"
        assert link["schedule_cells"] == 0, f"{name}: SCHEDULE cell on fixed"
    print(f"fixed profile: {len(links)} links held a constant cadence")
elif profile == "adaptive":
    negotiating = [(n, l) for n, l in links if l["schedule_cells"] > 0]
    assert negotiating, "adaptive profile negotiated on no link"
    changed = sum(l["rate_class_changes"] for _, l in links)
    assert changed >= 1, "adaptive profile never changed rate"
    # An adaptive run says nothing about a constant cadence, so the value is
    # reported and deliberately not asserted.
    traces = {l["fixed_trace_valid"] for _, l in links}
    print(
        f"adaptive profile: {len(negotiating)} links negotiated, "
        f"{changed} rate change(s); fixed-trace not asserted (observed {traces})"
    )
else:
    raise SystemExit(f"unknown schedule profile: {profile}")
SCHED
if (( EXPECT_RETRY_EXHAUSTION )); then
  if ! grep -lq "retry budget exhausted" "$OUTPUT"/*.err 2>/dev/null; then
    echo "scenario ${SCENARIO}: no node reached T1 retry exhaustion" >&2
    exit 1
  fi
  # Exhaustion must be reported once per transmission and leave nothing behind;
  # the live_routes assertion above already covers the state side.
  echo "scenario ${SCENARIO}: retry exhaustion reached cleanly"
fi
if [[ -n "${P1_REKEY_AFTER_CELLS:-}" ]]; then
  # A run that lowered the trigger but rekeyed nothing would pass the ordinary
  # gate while testing nothing, so the count is the assertion.
  REKEYS=$(cat "$OUTPUT"/*.metrics.json | grep -o '"rekeys":[0-9]*' | cut -d: -f2 |
    awk '{ total += $1 } END { print total + 0 }')
  if (( REKEYS == 0 )); then
    echo "scenario ${SCENARIO}: no link rekeyed, so the run proved nothing" >&2
    exit 1
  fi
  echo "scenario ${SCENARIO}: ${REKEYS} rekey(s) completed under live traffic"
fi
if [[ -n "${P1_WRONG_PIN:-}" ]]; then
  if ! grep -qs "link_handshake_failed" "$OUTPUT"/*.log "$OUTPUT"/*.err; then
    echo "scenario ${SCENARIO}: no link reported a handshake failure, so the" >&2
    echo "run may have failed for some unrelated reason" >&2
    exit 1
  fi
  echo "scenario ${SCENARIO}: the manifest pin refused the link"
fi
if (( EXPECT_ENDPOINT_FAILURE )); then
  if (( STATUS == 0 )); then
    echo "scenario ${SCENARIO}: expected the redemption to be rejected" >&2
    exit 1
  fi
  echo "scenario ${SCENARIO}: rejected as required, all state reclaimed"
  exit 0
fi
exit "$STATUS"
