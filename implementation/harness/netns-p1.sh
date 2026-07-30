#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

RELAYS=2
LOSS=0
DELAY=5ms
JITTER=1ms
DUPLICATE=0
REORDER=0
MTU=1500
TIMEOUT_MS=30000
OUTPUT="${PWD}/build/p1-netns"
BIN_DIR="${PWD}/implementation/rust/target/release"

while (($#)); do
  case "$1" in
    --relays) RELAYS="$2"; shift 2 ;;
    --loss) LOSS="$2"; shift 2 ;;
    --delay) DELAY="$2"; shift 2 ;;
    --jitter) JITTER="$2"; shift 2 ;;
    --duplicate) DUPLICATE="$2"; shift 2 ;;
    --reorder) REORDER="$2"; shift 2 ;;
    --mtu) MTU="$2"; shift 2 ;;
    --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
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
    ip netns exec "$ns" tc qdisc add dev "$dev" root netem \
      loss "${LOSS}%" delay "$DELAY" "$JITTER" duplicate "${DUPLICATE}%" reorder "${REORDER}%"
  done
  ip netns exec "${NAMES[$i]}" tcpdump -i "$left" -U -w "$OUTPUT/link-${i}.pcap" udp >/dev/null 2>&1 &
  PIDS+=("$!")
done

key_for() { printf '%064x' "$(( $1 + 1 ))"; }
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
EPOCH=1

run_node() {
  local ns=$1 name=$2 offset=$3
  shift 3
  ip netns exec "$ns" env TRAHENS_CLOCK_OFFSET_MS="$offset" \
    /usr/bin/time -v -o "$OUTPUT/${name}.time.txt" "$@" \
    >"$OUTPUT/${name}.log" 2>"$OUTPUT/${name}.err" &
  PIDS+=("$!")
}

GIDX=$((NODES-1))
run_node "${NAMES[$GIDX]}" rendezvous 7 \
  "$BIN_DIR/trahens-rendezvous" \
  --id "$((GIDX+1))" --peer-id "$GIDX" --gateway-id 7 --epoch "$EPOCH" \
  --bind "10.200.$((GIDX-1)).2:${PORT}" --peer "10.200.$((GIDX-1)).1:${PORT}" \
  --key "$(key_for $((GIDX-1)))" --signing-seed "$SIGNING_SEED" \
  --capability "$CAPABILITY" --capability-ttl-ms 5000 \
  --timeout-ms "$TIMEOUT_MS" --metrics "$OUTPUT/rendezvous.metrics.json"

for ((r=RELAYS; r>=1; r--)); do
  run_node "${NAMES[$r]}" "relay-${r}" "$((r-RELAYS/2))" \
    "$BIN_DIR/trahens-relay" \
    --id "$((r+1))" --upstream-id "$r" --downstream-id "$((r+2))" --epoch "$EPOCH" \
    --upstream-bind "10.200.$((r-1)).2:${PORT}" --upstream-peer "10.200.$((r-1)).1:${PORT}" \
    --upstream-key "$(key_for $((r-1)))" \
    --downstream-bind "10.200.${r}.1:${PORT}" --downstream-peer "10.200.${r}.2:${PORT}" \
    --downstream-key "$(key_for "$r")" --timeout-ms "$TIMEOUT_MS" \
    --metrics "$OUTPUT/relay-${r}.metrics.json"
done

sleep 0.2
run_node "${NAMES[0]}" endpoint -7 \
  "$BIN_DIR/trahens-endpoint" \
  --id 1 --peer-id 2 --epoch "$EPOCH" \
  --bind "10.200.0.1:${PORT}" --peer "10.200.0.2:${PORT}" --key "$(key_for 0)" \
  --gateway-public "$GATEWAY_PUBLIC" --capability "$CAPABILITY" \
  --message "interoperable-p1" --timeout-ms "$TIMEOUT_MS" \
  --metrics "$OUTPUT/endpoint.metrics.json"

NODE_START=$((NODES-1))
STATUS=0
for ((i=NODE_START; i<${#PIDS[@]}; i++)); do
  if ! wait "${PIDS[$i]}"; then STATUS=1; fi
done

for pid in "${PIDS[@]:0:NODES-1}"; do kill "$pid" 2>/dev/null || true; done
sleep 0.1
python3 "$ROOT/tools/check_pcap_cells.py" "$OUTPUT"/*.pcap
python3 "$ROOT/tools/summarize_p1_run.py" --directory "$OUTPUT" --output "$OUTPUT/run-metrics.json"
python3 - "$OUTPUT" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
files=list(root.glob('*.metrics.json'))
assert files, 'no process metrics'
for path in files:
    value=json.loads(path.read_text())
    assert value['live_routes'] == 0, f"state leak in {path}"
report=json.loads((root/'run-metrics.json').read_text())
assert report['all_remote_state_reclaimed']
PY
exit "$STATUS"
