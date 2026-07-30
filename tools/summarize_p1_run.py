#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Aggregate P1 process metrics, structured logs, and /usr/bin/time output."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def structured(path: Path) -> list[dict]:
    values = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            values.append(value)
    return values


def time_metrics(path: Path) -> tuple[float, int]:
    text = path.read_text(errors="replace") if path.exists() else ""
    user = re.search(r"User time \(seconds\):\s*([0-9.]+)", text)
    system = re.search(r"System time \(seconds\):\s*([0-9.]+)", text)
    rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", text)
    cpu = float(user.group(1)) if user else 0.0
    cpu += float(system.group(1)) if system else 0.0
    return cpu, int(rss.group(1)) if rss else 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    metric_files = sorted(args.directory.glob("*.metrics.json"))
    logs = sorted(args.directory.glob("*.log"))
    times = sorted(args.directory.glob("*.time.txt"))
    node_metrics = [json.loads(path.read_text()) for path in metric_files]
    events = [event for path in logs for event in structured(path)]
    total_sent = sum(link["sent_cells"] for node in node_metrics for link in node["links"])
    total_received = sum(link["received_cells"] for node in node_metrics for link in node["links"])
    retransmissions = sum(link["retransmission_cells"] for node in node_metrics for link in node["links"])
    chaff = sum(link["chaff_cells"] for node in node_metrics for link in node["links"])
    real = sum(link["new_data_cells"] + link["retransmission_cells"] + link["ack_cells"] for node in node_metrics for link in node["links"])
    peak_queue = max((link["peak_queue_cells"] for node in node_metrics for link in node["links"]), default=0)
    cpu_seconds = 0.0
    max_rss_kib = 0
    for path in times:
        cpu, rss = time_metrics(path)
        cpu_seconds += cpu
        max_rss_kib = max(max_rss_kib, rss)
    setup = next((int(e["setup_latency_ms"]) for e in events if e.get("event") == "p1_complete"), None)
    redemption = next((int(e["redemption_latency_us"]) for e in events if e.get("event") == "stopped" and e.get("node") == "rendezvous"), None)
    report = {
        "schema": "trahens-p1-run-metrics-v1",
        "nodes": len(node_metrics),
        "route_setup_latency_ms": setup,
        "cells_sent": total_sent,
        "cells_received": total_received,
        "bytes_sent": total_sent * 1052,
        "retransmission_cells": retransmissions,
        "peak_queue_cells": peak_queue,
        "cpu_seconds": cpu_seconds,
        "cpu_microseconds_per_sent_cell": (cpu_seconds * 1_000_000 / total_sent) if total_sent else None,
        "maximum_process_rss_kib": max_rss_kib,
        "approx_memory_kib_per_active_route": max_rss_kib,
        "rendezvous_redemption_latency_us": redemption,
        "cleanup_time_ms_max": max((node["cleanup_ms"] for node in node_metrics), default=0),
        "chaff_cells": chaff,
        "real_or_control_cells": real,
        "chaff_to_real_cell_ratio": (chaff / real) if real else None,
        "all_remote_state_reclaimed": all(node["live_routes"] == 0 for node in node_metrics),
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
