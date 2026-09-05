#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Restart safety: two runs of the same topology, with the same static keys and
# the same peer list, must not share a link epoch.
#
# This is the falsification test for the hazard v1.7 could only state as an
# operator obligation. Until v1.8 the epoch arrived by configuration, so a
# restarted pair began with an empty replay window on a key and epoch it had
# already used, and previously recorded records could authenticate again.
# Nothing detected it. Since B1.1 the epoch is derived from a handshake whose
# transcript includes both sides' fresh ephemerals, so neither end chooses one
# and a repeat would mean the ephemerals repeated.
#
# The epoch is the one W2 field on the wire in the clear, so the captures are
# enough to check it: run twice, and require the two epoch sets to be disjoint.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUTPUT=${OUTPUT:-$ROOT/build/p1-restart}
RELAYS=${RELAYS:-2}

rm -rf "$OUTPUT"
mkdir -p "$OUTPUT/first" "$OUTPUT/second"

echo "restart: first run"
"$ROOT/implementation/harness/netns-p1.sh" \
  --relays "$RELAYS" --loss 0 --output "$OUTPUT/first" >"$OUTPUT/first.log" 2>&1

echo "restart: second run, same keys and peers"
"$ROOT/implementation/harness/netns-p1.sh" \
  --relays "$RELAYS" --loss 0 --output "$OUTPUT/second" >"$OUTPUT/second.log" 2>&1

FIRST=$(PYTHONPATH="$ROOT/tools" python3 "$ROOT/tools/w2_epochs.py" "$OUTPUT"/first/link-*.pcap | sort -u)
SECOND=$(PYTHONPATH="$ROOT/tools" python3 "$ROOT/tools/w2_epochs.py" "$OUTPUT"/second/link-*.pcap | sort -u)

if [[ -z "$FIRST" || -z "$SECOND" ]]; then
  echo "restart: no epochs captured, so the run proved nothing" >&2
  exit 1
fi

SHARED=$(comm -12 <(echo "$FIRST") <(echo "$SECOND"))
if [[ -n "$SHARED" ]]; then
  echo "restart: an epoch was reused across a restart:" >&2
  echo "$SHARED" >&2
  exit 1
fi

echo "restart: $(echo "$FIRST" | wc -l) and $(echo "$SECOND" | wc -l) epochs, none shared"
echo "restart: a restarted pair cannot reuse an epoch, because neither end picks one"
