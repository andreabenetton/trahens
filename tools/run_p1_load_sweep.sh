#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Sweep the P1 path across path length and loss, recording what it costs.
#
# The acceptance gate asks whether the protocol works. This asks what it costs
# when it does: bandwidth, CPU per cell, memory, setup latency, and how well
# the fixed schedule actually held. Those are the numbers a deployment decision
# needs and the ones the gate never produced.
#
# The output is a measurement, not a derived artifact. It is not reproducible
# byte for byte on another machine and must not join the regenerate-and-compare
# set in tools/check_repo.sh. Every row therefore carries the host, kernel, and
# toolchain that produced it.
set -euo pipefail

RELAY_SET=${RELAY_SET:-"0 2 5 12"}
LOSS_SET=${LOSS_SET:-"0 5"}
REPEATS=${REPEATS:-3}
OUTPUT=${OUTPUT:-"reports/iteration-0019-p1-load-sweep.csv"}
WORK=${WORK:-"build/p1-load-sweep"}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

if [[ ${EUID} -ne 0 ]]; then
  echo "run_p1_load_sweep.sh must run as root: it drives the namespace harness" >&2
  exit 2
fi

HOST_KERNEL=$(uname -r)
HOST_CPU=$(nproc)
TOOLCHAIN=$(cargo --version 2>/dev/null | tr -d ',' || echo "cargo unavailable")

mkdir -p "$(dirname "$OUTPUT")" "$WORK"
{
  echo "# host_kernel=${HOST_KERNEL} cpus=${HOST_CPU} toolchain=${TOOLCHAIN}"
  echo "# measurement, not a derived artifact: not byte-reproducible on another host"
  echo "relays,loss_percent,repeat,ok,setup_latency_ms,cells_sent,bytes_sent,retransmission_cells,cpu_seconds,cpu_us_per_cell,rss_kib,chaff_to_real,cleanup_ms_max,worst_jitter_us,missed_slots,fixed_trace_valid"
} > "$OUTPUT"

for relays in $RELAY_SET; do
  for loss in $LOSS_SET; do
    for ((run=1; run<=REPEATS; run++)); do
      dir="${WORK}/r${relays}-l${loss}-${run}"
      rm -rf "$dir"; mkdir -p "$dir"
      ok=1
      implementation/harness/netns-p1.sh \
        --relays "$relays" --loss "$loss" --delay 8ms --jitter 2ms \
        --timeout-ms 90000 --output "$dir" >/dev/null 2>&1 || ok=0
      python3 - "$dir" "$relays" "$loss" "$run" "$ok" >> "$OUTPUT" <<'PY'
import json, pathlib, sys

directory, relays, loss, run, ok = sys.argv[1:6]
root = pathlib.Path(directory)
summary_path = root / "run-metrics.json"
if not summary_path.exists():
    # A run that failed before summarising still occupies a row: a sweep that
    # silently drops its failures reports only the conditions that worked.
    print(f"{relays},{loss},{run},0,,,,,,,,,,,,")
    raise SystemExit(0)

s = json.loads(summary_path.read_text())

# Schedule health is per link, so take the worst across every node: one link
# that lost its slot shape is enough to invalidate the run's trace claim.
worst_jitter = 0
missed = 0
for path in root.glob("*.metrics.json"):
    for link in json.loads(path.read_text()).get("links", []):
        worst_jitter = max(worst_jitter, link.get("worst_jitter_us", 0))
        missed += link.get("missed_slots", 0)


def value(name, default=""):
    got = s.get(name)
    return default if got is None else got


print(
    f"{relays},{loss},{run},{ok},"
    f"{value('route_setup_latency_ms')},{value('cells_sent')},{value('bytes_sent')},"
    f"{value('retransmission_cells')},{value('cpu_seconds')},"
    f"{value('cpu_microseconds_per_sent_cell')},{value('maximum_process_rss_kib')},"
    f"{value('chaff_to_real_cell_ratio')},{value('cleanup_time_ms_max')},"
    f"{worst_jitter},{missed},{'true' if missed == 0 else 'false'}"
)
PY
      rm -rf "$dir"
    done
  done
done

rows=$(( $(wc -l < "$OUTPUT") - 3 ))
echo "wrote ${rows} measurement rows to ${OUTPUT}"
