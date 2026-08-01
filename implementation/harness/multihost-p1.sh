#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run a P1 path across separately provisioned hosts.
#
# netns-p1.sh proves the protocol works between separately started processes on
# one kernel, with one scheduler, one clock, and synthetic impairment. That is
# not the same claim as working across a real network, so this runs one node
# per host and leaves the network alone.
#
# It orchestrates only. Connectivity, firewalling, and clock discipline are the
# operator's, exactly as they would be in a deployment.
#
#   ./multihost-p1.sh --node 0=alice@10.0.0.1 --node 1=alice@10.0.0.2 \
#                     --node 2=alice@10.0.0.3 --relays 1
#
# Node 0 is the initiator, node N-1 the gateway, and the rest relays in order.
# Addresses default to the host part of each --node entry; --address overrides
# where a node is reachable at one address and should bind another.
#
# --runner replaces ssh. It is invoked as `RUNNER <host> <shell-command>`, the
# same shape ssh has, so a two-line local stand-in runs every node over
# loopback. That is what makes this testable without a second machine: it
# exercises the orchestration and the node contract end to end, and it
# establishes nothing about real networks. The summary says so.
set -euo pipefail

RELAYS=1
PORT=4242
EPOCH=1
TIMEOUT_MS=45000
OUTPUT="${PWD}/build/p1-multihost"
BIN_DIR="implementation/rust/target/release"
RUNNER="ssh"
declare -A NODE_HOST=()
declare -A NODE_ADDR=()

# --node and --address are index=value, so a path can be given in any order and
# a gap is an error rather than a silent off-by-one.
parse_indexed() {
  local -n table=$1
  local entry=$2
  [[ "$entry" == *=* ]] || { echo "expected index=value, got: $entry" >&2; exit 2; }
  local index=${entry%%=*} value=${entry#*=}
  [[ "$index" =~ ^[0-9]+$ ]] || { echo "not an index: $index" >&2; exit 2; }
  table[$index]=$value
}

while (($#)); do
  case "$1" in
    --node) parse_indexed NODE_HOST "$2"; shift 2 ;;
    --address) parse_indexed NODE_ADDR "$2"; shift 2 ;;
    --relays) RELAYS="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --runner) RUNNER="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

NODES=$((RELAYS + 2))
for ((i=0; i<NODES; i++)); do
  [[ -n "${NODE_HOST[$i]:-}" ]] || {
    echo "missing --node ${i}=<host>; ${RELAYS} relays needs indices 0..$((NODES-1))" >&2
    exit 2
  }
done

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUTPUT=$(mkdir -p "$OUTPUT" && cd "$OUTPUT" && pwd)
SIGNING_SEED=$(printf '11%.0s' {1..32})
CAPABILITY=$(printf '22%.0s' {1..32})
# shellcheck source=implementation/harness/p1-node-args.sh
source "$ROOT/implementation/harness/p1-node-args.sh"

# index -> where this node is reached, and where its peers address it.
host_of() { echo "${NODE_HOST[$1]}"; }
addr_of() {
  # Default: the host part of user@host, which is the common case. --address
  # overrides it where a node is reached at one address and binds another.
  echo "${NODE_ADDR[$1]:-${NODE_HOST[$1]##*@}}"
}

# Each link i joins node i and node i+1. Both ends need the same base key, and
# each end binds its own address on the shared port.
link_port() { echo $(( PORT + $1 )); }

PIDS=()
cleanup() { for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT
rm -f "$OUTPUT"/*

run_remote() {
  local index=$1 name=$2
  shift 2
  local host
  host=$(host_of "$index")
  # The runner receives one shell command; quoting is the runner's problem
  # beyond this point, which is why the command is assembled as one string.
  # shellcheck disable=SC2086
  $RUNNER "$host" "$*" >"$OUTPUT/${name}.log" 2>"$OUTPUT/${name}.err" &
  PIDS+=("$!")
}

GATEWAY_PUBLIC=$(p1_gateway_public "$SIGNING_SEED")
P1_ENDPOINT_EXTRA=(--rings "16:$(p1_ring_window_ms "$RELAYS")")

GIDX=$((NODES-1))
GLINK=$((GIDX-1))
p1_gateway_args "$GIDX" \
  "$(addr_of "$GIDX"):$(link_port "$GLINK")" \
  "$(addr_of "$GLINK"):$(link_port "$GLINK")" \
  "$GLINK" 5000
run_remote "$GIDX" rendezvous "$BIN_DIR/trahens-rendezvous" "${P1_NODE_ARGS[@]}"

for ((r=1; r<=RELAYS; r++)); do
  p1_relay_args "$r" \
    "$(addr_of "$r"):$(link_port $((r-1)))" "$(addr_of $((r-1))):$(link_port $((r-1)))" $((r-1)) \
    "$(addr_of "$r"):$(link_port "$r")" "$(addr_of $((r+1))):$(link_port "$r")" "$r"
  run_remote "$r" "relay-${r}" "$BIN_DIR/trahens-relay" "${P1_NODE_ARGS[@]}"
done

sleep 1
p1_endpoint_args \
  "$(addr_of 0):$(link_port 0)" "$(addr_of 1):$(link_port 0)" 0 \
  "$GATEWAY_PUBLIC" "$CAPABILITY"
run_remote 0 endpoint "$BIN_DIR/trahens-endpoint" "${P1_NODE_ARGS[@]}"

STATUS=0
for pid in "${PIDS[@]}"; do
  if ! wait "$pid"; then STATUS=1; fi
done

# Metrics are written on each remote host. Collecting them is deployment
# specific, so assert on what the orchestrator can see locally: the exit status
# of every node, and any metrics that happen to be on a shared filesystem.
shopt -s nullglob
metrics=("$OUTPUT"/*.metrics.json)
if (( ${#metrics[@]} > 0 )); then
  python3 - "$OUTPUT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for path in sorted(root.glob('*.metrics.json')):
    value = json.loads(path.read_text())
    assert value['live_routes'] == 0, f"state leak in {path}"
print(f"{len(list(root.glob('*.metrics.json')))} node(s) reported no leaked state")
PY
else
  echo "no metrics on the orchestrator's filesystem; collect them per host" >&2
fi

if [[ "$RUNNER" == ssh* ]]; then
  echo "multihost: ${NODES} nodes across ${#NODE_HOST[@]} hosts, status ${STATUS}"
else
  echo "multihost: ${NODES} nodes via runner '${RUNNER}', status ${STATUS}"
  echo "note: a non-ssh runner exercises orchestration and the node contract only;" >&2
  echo "      it establishes nothing about behaviour on a real network." >&2
fi
exit "$STATUS"
