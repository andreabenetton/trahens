# SPDX-License-Identifier: Apache-2.0
"""Command-line interface for the Trahens discovery simulator."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .model import DiscoveryConfig, Graph, simulate_discovery


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Simulate bounded Trahens Core discovery"
    )
    parser.add_argument("--nodes", type=int, default=100)
    parser.add_argument("--average-degree", type=float, default=4.0)
    parser.add_argument("--origin", type=int, default=0)
    parser.add_argument("--hop-limit", type=int, default=4)
    parser.add_argument("--initial-fanout", type=int, default=4)
    parser.add_argument("--relay-fanout", type=int, default=3)
    parser.add_argument("--candidate-limit", type=int, default=4)
    parser.add_argument("--responder-fraction", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--transmission-budget", type=int)
    parser.add_argument("--state-budget", type=int)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def _load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("configuration root must be an object")
    return value


def main() -> None:
    args = _parser().parse_args()
    values: dict[str, Any] = {
        "nodes": args.nodes,
        "average_degree": args.average_degree,
        "origin": args.origin,
        "hop_limit": args.hop_limit,
        "initial_fanout": args.initial_fanout,
        "relay_fanout": args.relay_fanout,
        "candidate_limit": args.candidate_limit,
        "responder_fraction": args.responder_fraction,
        "seed": args.seed,
        "transmission_budget": args.transmission_budget,
        "state_budget": args.state_budget,
    }
    if args.config is not None:
        values.update(_load_config(args.config))

    graph = Graph.random_connected(
        node_count=int(values["nodes"]),
        average_degree=float(values["average_degree"]),
        seed=int(values["seed"]),
    )
    config = DiscoveryConfig(
        origin=int(values["origin"]),
        hop_limit=int(values["hop_limit"]),
        initial_fanout=int(values["initial_fanout"]),
        relay_fanout=int(values["relay_fanout"]),
        candidate_limit=int(values["candidate_limit"]),
        responder_fraction=float(values["responder_fraction"]),
        seed=int(values["seed"]),
        transmission_budget=(
            None
            if values.get("transmission_budget") is None
            else int(values["transmission_budget"])
        ),
        state_budget=(
            None
            if values.get("state_budget") is None
            else int(values["state_budget"])
        ),
    )
    result = simulate_discovery(graph, config)
    payload = {
        "parameters": values,
        "result": result.to_dict(),
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True)

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
