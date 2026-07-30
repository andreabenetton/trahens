"""Command-line interface for expanding-ring Trahens discovery."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .model import (
    ExpandingRingConfig,
    Graph,
    parse_ring_schedule,
    ring_schedule_to_string,
    simulate_expanding_ring,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Simulate bounded expanding-ring Trahens discovery"
    )
    parser.add_argument("--nodes", type=int, default=500)
    parser.add_argument("--average-degree", type=float, default=8.0)
    parser.add_argument("--origin", type=int, default=0)
    parser.add_argument(
        "--rings",
        type=parse_ring_schedule,
        default=parse_ring_schedule("2:2,3:2,4:3,5:4"),
    )
    parser.add_argument("--candidate-limit", type=int, default=8)
    parser.add_argument("--required-candidates", type=int, default=1)
    parser.add_argument("--responder-fraction", type=float, default=0.02)
    parser.add_argument("--transmission-budget", type=int, default=1200)
    parser.add_argument("--state-budget", type=int, default=1200)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--output", type=Path)
    return parser


def main() -> None:
    args = _parser().parse_args()
    graph = Graph.random_connected(
        node_count=args.nodes,
        average_degree=args.average_degree,
        seed=args.seed,
    )
    config = ExpandingRingConfig(
        origin=args.origin,
        rings=args.rings,
        candidate_limit=args.candidate_limit,
        required_candidates=args.required_candidates,
        responder_fraction=args.responder_fraction,
        seed=args.seed,
        total_transmission_budget=args.transmission_budget,
        total_state_allocation_budget=args.state_budget,
    )
    result = simulate_expanding_ring(graph, config)
    payload = {
        "parameters": {
            "nodes": args.nodes,
            "average_degree": args.average_degree,
            "origin": args.origin,
            "rings": ring_schedule_to_string(args.rings),
            "candidate_limit": args.candidate_limit,
            "required_candidates": args.required_candidates,
            "responder_fraction": args.responder_fraction,
            "transmission_budget": args.transmission_budget,
            "state_budget": args.state_budget,
            "seed": args.seed,
        },
        "result": result.to_dict(),
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if args.output is None:
        print(rendered)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
