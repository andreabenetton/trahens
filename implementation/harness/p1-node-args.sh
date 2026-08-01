# SPDX-License-Identifier: Apache-2.0
#
# Shared node contract for the P1 harnesses.
#
# Sourced by netns-p1.sh and multihost-p1.sh so the two cannot drift into
# testing different protocols. It computes the keys and the gateway public key,
# and builds each node's argument list into P1_NODE_ARGS.
#
# Callers supply, before sourcing:
#   SIGNING_SEED, CAPABILITY, PORT, EPOCH, TIMEOUT_MS, OUTPUT
# and, before each *_args call, the addresses for that node.
#
# P1_ADAPTIVE and P1_ENDPOINT_EXTRA must be declared as arrays by the caller,
# empty if unused. They are expanded without ':-' on purpose: that form injects
# an empty-string argument for an empty array, which a node then rejects as an
# unexpected argument.
declare -a P1_ADAPTIVE=("${P1_ADAPTIVE[@]:-}")
declare -a P1_ENDPOINT_EXTRA=("${P1_ENDPOINT_EXTRA[@]:-}")
# Drop the empty element the line above introduces when the caller left the
# array unset.
[[ ${#P1_ADAPTIVE[@]} -eq 1 && -z "${P1_ADAPTIVE[0]}" ]] && P1_ADAPTIVE=()
[[ ${#P1_ENDPOINT_EXTRA[@]} -eq 1 && -z "${P1_ENDPOINT_EXTRA[0]}" ]] && P1_ENDPOINT_EXTRA=()

# Per-link base key: link i is keyed by i+1 so no link ever gets the zero key.
p1_key_for() { printf '%064x' "$(( $1 + 1 ))"; }

# Ed25519 public key the initiator pins for the gateway's candidate signature.
p1_gateway_public() {
  python3 - "$1" <<'PY'
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
seed=bytes.fromhex(sys.argv[1])
print(Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
PY
}

# The initiator's candidate window has to cover a candidate returning along the
# whole path, not a fixed stopwatch: return time grows with the number of hops,
# and under loss a multi-fragment candidate needs several T1 recovery rounds on
# top. A flat window makes a long path marginal, so it passes on a quiet
# machine and reports NO_CANDIDATE on a slower one, measuring the host rather
# than recovery.
p1_ring_window_ms() { echo $(( 1500 + $1 * 600 )); }

# p1_endpoint_args <bind> <peer> <link-index> <gateway-public> <capability>
# Extra arguments for the caller's scenario go in P1_ENDPOINT_EXTRA.
p1_endpoint_args() {
  P1_NODE_ARGS=(
    --id 1 --peer-id 2 --epoch "$EPOCH"
    "${P1_ADAPTIVE[@]}"
    --bind "$1" --peer "$2" --key "$(p1_key_for "$3")"
    --gateway-public "$4" --capability "$5"
    "${P1_ENDPOINT_EXTRA[@]}"
    --message "interoperable-p1" --timeout-ms "$TIMEOUT_MS"
    --metrics "$OUTPUT/endpoint.metrics.json"
  )
}

# p1_relay_args <index> <up-bind> <up-peer> <up-link> <down-bind> <down-peer> <down-link>
p1_relay_args() {
  P1_NODE_ARGS=(
    --id "$(( $1 + 1 ))" --upstream-id "$1" --downstream-id "$(( $1 + 2 ))" --epoch "$EPOCH"
    "${P1_ADAPTIVE[@]}"
    --upstream-bind "$2" --upstream-peer "$3" --upstream-key "$(p1_key_for "$4")"
    --downstream-bind "$5" --downstream-peer "$6" --downstream-key "$(p1_key_for "$7")"
    --timeout-ms "$TIMEOUT_MS" --metrics "$OUTPUT/relay-$1.metrics.json"
  )
}

# p1_gateway_args <node-index> <bind> <peer> <link-index> <capability-ttl-ms>
p1_gateway_args() {
  P1_NODE_ARGS=(
    --id "$(( $1 + 1 ))" --peer-id "$1" --gateway-id 7 --epoch "$EPOCH"
    "${P1_ADAPTIVE[@]}"
    --bind "$2" --peer "$3" --key "$(p1_key_for "$4")"
    --signing-seed "$SIGNING_SEED"
    --capability "$CAPABILITY" --capability-ttl-ms "$5"
    --timeout-ms "$TIMEOUT_MS" --metrics "$OUTPUT/rendezvous.metrics.json"
  )
}
