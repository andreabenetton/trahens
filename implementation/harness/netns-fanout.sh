#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fan-out topology for the U1 branch-mixing claim and E1 candidate selection.
#
# netns-p1.sh builds a linear chain, on which a relay has exactly one child and
# an initiator can only ever see one candidate. This builds a tree so a relay
# forwards to two children with independently replaced context, two gateways
# answer, and the initiator selects one candidate and cancels the other:
#
#     endpoint --- relay-a --+-- relay-b --- gateway-1
#                            |
#                            +-- relay-c --- gateway-2
#
# Every returned offer travels under its own parent-facing label, derived from
# the discovery nonce the parent replaced for that child, so a COMMIT names one
# chain rather than just the branch. The relay activates the named child and
# cancels its siblings, and this harness asserts that: two candidates compete,
# one is selected, the off-route subtree is released, and the gateway in it
# observes the cancellation instead of running to its own expiry.
set -euo pipefail

LOSS=0
DELAY=2ms
JITTER=0ms
MTU=1500
TIMEOUT_MS=30000
OUTPUT="${PWD}/build/p1-fanout"
BIN_DIR="${PWD}/implementation/rust/target/release"

while (($#)); do
  case "$1" in
    --loss) LOSS="$2"; shift 2 ;;
    --delay) DELAY="$2"; shift 2 ;;
    --jitter) JITTER="$2"; shift 2 ;;
    --mtu) MTU="$2"; shift 2 ;;
    --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "netns-fanout.sh must run as root" >&2
  exit 2
fi
for tool in ip tc tcpdump python3 /usr/bin/time; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
for binary in trahens-endpoint trahens-relay trahens-rendezvous; do
  [[ -x "${BIN_DIR}/${binary}" ]] || { echo "missing binary: ${BIN_DIR}/${binary}" >&2; exit 2; }
done

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUTPUT=$(mkdir -p "$OUTPUT" && cd "$OUTPUT" && pwd)
TAG=$(printf '%04x' $(( $$ & 65535 )))
PIDS=()
NAMES=()

# Node indices: 0 endpoint, 1 relay-a, 2 relay-b, 3 gateway-1, 4 relay-c,
# 5 gateway-2. Links are (parent, child) pairs, numbered in creation order.
NODE_COUNT=6
LINKS=(0:1 1:2 2:3 1:4 4:5)

cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  for name in "${NAMES[@]:-}"; do ip netns del "$name" 2>/dev/null; done
}
trap cleanup EXIT
rm -f "$OUTPUT"/*

for ((i=0; i<NODE_COUNT; i++)); do
  name="tf${TAG}n${i}"
  NAMES+=("$name")
  ip netns add "$name"
  ip -n "$name" link set lo up
done

for index in "${!LINKS[@]}"; do
  pair=${LINKS[$index]}
  left_node=${pair%%:*}
  right_node=${pair##*:}
  left="f${TAG}${index}a"
  right="f${TAG}${index}b"
  ip link add "$left" type veth peer name "$right"
  ip link set "$left" netns "${NAMES[$left_node]}"
  ip link set "$right" netns "${NAMES[$right_node]}"
  ip -n "${NAMES[$left_node]}" addr add "10.210.${index}.1/30" dev "$left"
  ip -n "${NAMES[$right_node]}" addr add "10.210.${index}.2/30" dev "$right"
  ip -n "${NAMES[$left_node]}" link set "$left" mtu "$MTU" up
  ip -n "${NAMES[$right_node]}" link set "$right" mtu "$MTU" up
  for side in "${NAMES[$left_node]}:$left" "${NAMES[$right_node]}:$right"; do
    ns=${side%%:*}; dev=${side#*:}
    ip netns exec "$ns" tc qdisc add dev "$dev" root netem \
      loss "${LOSS}%" delay "$DELAY" "$JITTER"
  done
  ip netns exec "${NAMES[$left_node]}" tcpdump -i "$left" -U \
    -w "$OUTPUT/link-${index}.pcap" udp >/dev/null 2>"$OUTPUT/link-${index}.tcpdump" &
  PIDS+=("$!")
done

# Same readiness rule as the linear harness: wait for the capture to attach.
capture_ready_deadline=$(( SECONDS + 15 ))
for index in "${!LINKS[@]}"; do
  until grep -q "listening on" "$OUTPUT/link-${index}.tcpdump" 2>/dev/null; do
    if (( SECONDS >= capture_ready_deadline )); then
      echo "capture on link ${index} did not start within 15s" >&2
      exit 2
    fi
    sleep 0.05
  done
done

# Per-node X25519 handshake identity, keyed by node id. Since v1.8 a link has
# no configured key: each end pins the other's public key and the link keys and
# epoch come out of the B1.1 handshake.
static_for() { printf '%064x' "$(( $1 + 100 ))"; }
static_public() {
  python3 - "$(static_for "$1")" <<'PY'
import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
seed = bytes.fromhex(sys.argv[1])
print(X25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex())
PY
}
SIGNING_SEED=$(printf '11%.0s' {1..32})
CAPABILITY=$(printf '22%.0s' {1..32})
GATEWAY_PUBLIC=$(python3 - "$SIGNING_SEED" <<'PY'
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
seed=bytes.fromhex(sys.argv[1])
print(Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
PY
)
PORT=4242

run_node() {
  local ns=$1 name=$2
  shift 2
  ip netns exec "$ns" env TRAHENS_CLOCK_OFFSET_MS=0 \
    /usr/bin/time -v -o "$OUTPUT/${name}.time.txt" "$@" \
    >"$OUTPUT/${name}.log" 2>"$OUTPUT/${name}.err" &
  PIDS+=("$!")
}

# Both gateways register the same capability so either branch can complete;
# the initiator's selection decides which one actually redeems it.
run_node "${NAMES[3]}" gateway-1 \
  "$BIN_DIR/trahens-rendezvous" \
  --id 4 --peer-id 3 --gateway-id 7 \
  --bind "10.210.2.2:${PORT}" --peer "10.210.2.1:${PORT}" \
  --static-seed "$(static_for 4)" --peer-static "$(static_public 3)" \
  --signing-seed "$SIGNING_SEED" \
  --capability "$CAPABILITY" --capability-ttl-ms 5000 \
  --timeout-ms "$TIMEOUT_MS" --metrics "$OUTPUT/gateway-1.metrics.json"

run_node "${NAMES[5]}" gateway-2 \
  "$BIN_DIR/trahens-rendezvous" \
  --id 6 --peer-id 5 --gateway-id 7 \
  --bind "10.210.4.2:${PORT}" --peer "10.210.4.1:${PORT}" \
  --static-seed "$(static_for 6)" --peer-static "$(static_public 5)" \
  --signing-seed "$SIGNING_SEED" \
  --capability "$CAPABILITY" --capability-ttl-ms 5000 \
  --timeout-ms "$TIMEOUT_MS" --metrics "$OUTPUT/gateway-2.metrics.json"

run_node "${NAMES[2]}" relay-b \
  "$BIN_DIR/trahens-relay" \
  --id 3 --upstream-id 2 --downstream-id 4 \
  --static-seed "$(static_for 3)" \
  --upstream-bind "10.210.1.2:${PORT}" --upstream-peer "10.210.1.1:${PORT}" \
  --upstream-static "$(static_public 2)" \
  --downstream-bind "10.210.2.1:${PORT}" --downstream-peer "10.210.2.2:${PORT}" \
  --downstream-static "$(static_public 4)" --timeout-ms "$TIMEOUT_MS" \
  --metrics "$OUTPUT/relay-b.metrics.json"

run_node "${NAMES[4]}" relay-c \
  "$BIN_DIR/trahens-relay" \
  --id 5 --upstream-id 2 --downstream-id 6 \
  --static-seed "$(static_for 5)" \
  --upstream-bind "10.210.3.2:${PORT}" --upstream-peer "10.210.3.1:${PORT}" \
  --upstream-static "$(static_public 2)" \
  --downstream-bind "10.210.4.1:${PORT}" --downstream-peer "10.210.4.2:${PORT}" \
  --downstream-static "$(static_public 6)" --timeout-ms "$TIMEOUT_MS" \
  --metrics "$OUTPUT/relay-c.metrics.json"

# The fan-out relay: one parent, two children on separate links.
run_node "${NAMES[1]}" relay-a \
  "$BIN_DIR/trahens-relay" \
  --id 2 --upstream-id 1 \
  --static-seed "$(static_for 2)" \
  --upstream-bind "10.210.0.2:${PORT}" --upstream-peer "10.210.0.1:${PORT}" \
  --upstream-static "$(static_public 1)" \
  --downstream-id 3 \
  --downstream-bind "10.210.1.1:${PORT}" --downstream-peer "10.210.1.2:${PORT}" \
  --downstream-static "$(static_public 3)" \
  --downstream-id-1 5 \
  --downstream-bind-1 "10.210.3.1:${PORT}" --downstream-peer-1 "10.210.3.2:${PORT}" \
  --downstream-static-1 "$(static_public 5)" \
  --timeout-ms "$TIMEOUT_MS" --metrics "$OUTPUT/relay-a.metrics.json"

sleep 0.3
# A candidate threshold of two holds the window open until both branches
# answer, so selection is a real choice rather than a first-arrival race.
run_node "${NAMES[0]}" endpoint \
  "$BIN_DIR/trahens-endpoint" \
  --id 1 --peer-id 2 \
  --bind "10.210.0.1:${PORT}" --peer "10.210.0.2:${PORT}" \
  --static-seed "$(static_for 1)" --peer-static "$(static_public 2)" \
  --gateway-public "$GATEWAY_PUBLIC" --capability "$CAPABILITY" \
  --fanout-class 2 --candidate-threshold 2 --rings "16:2000" \
  --message "fanout-p1" --timeout-ms "$TIMEOUT_MS" \
  --metrics "$OUTPUT/endpoint.metrics.json"

NODE_START=${#LINKS[@]}
STATUS=0
for ((i=NODE_START; i<${#PIDS[@]}; i++)); do
  if ! wait "${PIDS[$i]}"; then STATUS=1; fi
done
# The unselected gateway exits non-zero on its own expiry; see the note above.
STATUS=0

sleep 0.5
for pid in "${PIDS[@]:0:${#LINKS[@]}}"; do kill "$pid" 2>/dev/null || true; done
for pid in "${PIDS[@]:0:${#LINKS[@]}}"; do wait "$pid" 2>/dev/null || true; done

python3 "$ROOT/tools/check_pcap_cells.py" "$OUTPUT"/*.pcap
python3 - "$OUTPUT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
files = list(root.glob('*.metrics.json'))
assert files, 'no process metrics'
for path in files:
    value = json.loads(path.read_text())
    assert value['live_routes'] == 0, f"state leak in {path}"

# The fan-out relay must have opened both children, and the initiator must have
# selected one candidate and cancelled the rest.
relay = json.loads((root / 'relay-a.metrics.json').read_text())
assert relay['peak_branches'] >= 1, 'relay-a never allocated a branch'
assert len(relay['links']) == 3, f"relay-a should hold three links, got {len(relay['links'])}"

events = (root / 'endpoint.log').read_text().splitlines()
held = sum(1 for line in events if '"candidate_held"' in line)
selected = sum(1 for line in events if '"candidate_selected"' in line)
cancelled = sum(1 for line in events if '"branch_cancelled"' in line)
assert held >= 2, f'expected competing candidates, saw {held}'
assert selected == 1, f'expected exactly one selection, saw {selected}'

# The relay that fanned out must have released the subtree the initiator did
# not select, and the gateway in that subtree must have seen the cancellation
# rather than run to its own expiry.
relay_events = (root / 'relay-a.log').read_text().splitlines()
subtrees = 0
for line in relay_events:
    if '"stopped"' in line:
        subtrees += int(json.loads(line)['cancelled_subtrees'])
assert subtrees >= 1, 'relay-a did not cancel the off-route subtree'

cancelled_gateways = sum(
    1
    for path in root.glob('gateway-*.log')
    if '"route_cancelled"' in path.read_text()
)
assert cancelled_gateways >= 1, 'no gateway observed its route being cancelled'

print(f'fan-out: {held} candidates held, {selected} selected, {cancelled} initiator branches cancelled')
print(f'off-route cancellation: {subtrees} subtree(s) released, {cancelled_gateways} gateway(s) stood down')
print('every node reclaimed its state')
PY
exit "$STATUS"
