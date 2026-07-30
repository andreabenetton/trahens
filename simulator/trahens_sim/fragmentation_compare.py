"""Deterministic M1/W2 encoding and lifecycle comparison."""

from __future__ import annotations

import argparse
import csv
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean

from trahens_codec.m1w2 import (
    CELL_RECORD_BYTES,
    CandidateRecord,
    ControlRecord,
    DiscoverRecord,
    MessageType,
    fragment_message,
    encode_candidate,
    encode_chaff,
    encode_control,
    encode_discover,
)
os.environ.setdefault("TRAHENS_TEST_CRYPTO", "1")

from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import (
    build_endpoint_keys,
    reply_blind_public,
    ure_encrypt,
)
from trahens_crypto.candidate import build_responder_payload
from tools.vector_candidate_support import (
    seal_responder_candidate_deterministic,
    wrap_relay_candidate_deterministic,
)

from .event_model import (
    EventLifecycleConfig,
    TimedRingStep,
    simulate_event_lifecycle,
)
from .model import Graph


@dataclass(frozen=True)
class EncodingRow:
    message_class: str
    relay_wrappers: int
    candidate_layers: int
    logical_bytes: int
    w2_cells: int
    w2_wire_bytes: int
    w1_feasible: bool
    w1_wire_bytes: int | None


@dataclass(frozen=True)
class LifecycleRow:
    scenario: str
    route_hops: int
    runs: int
    success_rate: float
    cleanup_rate: float
    mean_logical_messages: float
    mean_wire_cells: float
    mean_fragmented_messages: float
    mean_wire_bytes: float
    mean_peak_reassembly_bytes: float
    mean_reassembly_timeouts: float


def _line_graph(node_count: int) -> Graph:
    graph = Graph(node_count)
    for node in range(node_count - 1):
        graph.add_edge(node, node + 1)
    return graph


def _candidate_blob(relay_wrappers: int) -> bytes:
    endpoint = build_endpoint_keys(b"m1-w2-capacity-endpoint")
    root_secret = r255.scalar_from_label(b"m1-w2-capacity-root")
    publics = [r255.scalarmult_base(root_secret)]
    blinding_factors: list[bytes] = []
    for index in range(relay_wrappers):
        blinding_factor = r255.scalar_from_label(
            index.to_bytes(4, "big"),
            dst=b"Trahens-M1-W2-capacity-blinding-v1",
        )
        blinding_factors.append(blinding_factor)
        publics.append(reply_blind_public(publics[-1], blinding_factor))
    payload = build_responder_payload(
        endpoint,
        responder_id=7,
        offer_expires_ms=10_000,
        final_reply_public=publics[-1],
        commit_challenge=b"C" * 32,
        responder_nonce=b"N" * 16,
    )
    blob = seal_responder_candidate_deterministic(
        publics[-1],
        payload,
        ephemeral_secret=r255.scalar_from_label(b"m1-w2-responder-e"),
    )
    for index in reversed(range(relay_wrappers)):
        blob = wrap_relay_candidate_deterministic(
            publics[index],
            blinding_factor=blinding_factors[index],
            child_candidate_token=(index + 1).to_bytes(16, "big"),
            forward_label=(index + 101).to_bytes(16, "big"),
            child_blob=blob,
            ephemeral_secret=r255.scalar_from_label(
                index.to_bytes(4, "big"),
                dst=b"Trahens-M1-W2-relay-e-v1",
            ),
        )
    return blob


def encoding_rows(max_relay_wrappers: int = 16) -> list[EncodingRow]:
    endpoint = build_endpoint_keys(b"m1-w2-discover-endpoint")
    discover = encode_discover(
        DiscoverRecord(
            branch_token=b"D" * 16,
            hop_remaining=4,
            fanout_class=3,
            expiry_class=1,
            options=0,
            reply_public_key=r255.scalarmult_base(
                r255.scalar_from_label(b"m1-w2-discover-reply")
            ),
            eligibility_capsule=ure_encrypt(
                endpoint.eligibility_public,
                r0=r255.scalar_from_label(b"m1-w2-r0"),
                r1=r255.scalar_from_label(b"m1-w2-r1"),
            ),
        )
    )
    short_messages = {
        "CHAFF": encode_chaff(),
        "DISCOVER": discover,
        "COMMIT": encode_control(
            ControlRecord(
                message_type=MessageType.COMMIT,
                local_label=b"L" * 16,
                generation=1,
                expiry_class=1,
                protected_body=b"P" * 32,
            )
        ),
        "READY": encode_control(
            ControlRecord(
                message_type=MessageType.READY,
                local_label=b"R" * 16,
                generation=1,
                expiry_class=1,
                protected_body=b"P" * 32,
            )
        ),
    }
    rows: list[EncodingRow] = []
    for name, encoded in short_messages.items():
        cells = fragment_message(
            encoded,
            message_local_id=(len(rows) + 1).to_bytes(16, "big"),
        )
        rows.append(
            EncodingRow(
                message_class=name,
                relay_wrappers=0,
                candidate_layers=0,
                logical_bytes=len(encoded),
                w2_cells=len(cells),
                w2_wire_bytes=len(cells) * CELL_RECORD_BYTES,
                w1_feasible=True,
                w1_wire_bytes=1_052,
            )
        )
    for wrappers in range(max_relay_wrappers + 1):
        blob = _candidate_blob(wrappers)
        encoded = encode_candidate(
            CandidateRecord(
                candidate_token=b"Q" * 16,
                expiry_class=1,
                layer_count=wrappers + 1,
                candidate_blob=blob,
            )
        )
        cells = fragment_message(
            encoded,
            message_local_id=(wrappers + 100).to_bytes(16, "big"),
        )
        feasible = len(blob) <= 960
        rows.append(
            EncodingRow(
                message_class="CANDIDATE",
                relay_wrappers=wrappers,
                candidate_layers=wrappers + 1,
                logical_bytes=len(encoded),
                w2_cells=len(cells),
                w2_wire_bytes=len(cells) * CELL_RECORD_BYTES,
                w1_feasible=feasible,
                w1_wire_bytes=1_052 if feasible else None,
            )
        )
    return rows


def lifecycle_rows(
    *,
    route_hops: tuple[int, ...] = (2, 5, 8, 12),
    runs: int = 40,
) -> list[LifecycleRow]:
    rows: list[LifecycleRow] = []
    for scenario, loss in (("clean", 0.0), ("cell_loss_2pct", 0.02)):
        for hops in route_hops:
            results = []
            graph = _line_graph(hops + 1)
            for run in range(runs):
                config = EventLifecycleConfig(
                    rings=(TimedRingStep(hops, 1, 1, 80),),
                    seed=10_000 + hops * 100 + run,
                    discover_delay_min_ms=1,
                    discover_delay_max_ms=3,
                    candidate_delay_min_ms=1,
                    candidate_delay_max_ms=3,
                    control_delay_min_ms=1,
                    control_delay_max_ms=2,
                    responder_offer_delay_min_ms=1,
                    responder_offer_delay_max_ms=2,
                    branch_ttl_ms=240,
                    offer_ttl_ms=260,
                    tentative_ttl_ms=180,
                    ready_hold_ms=100,
                    route_setup_timeout_ms=220,
                    active_lifetime_ms=60,
                    max_simulation_ms=600,
                    transmission_budget=5_000,
                    branch_capacity=1_000,
                    tentative_capacity=500,
                    active_capacity=100,
                    per_node_branch_limit=100,
                    candidate_response_limit=100,
                    reassembly_timeout_ms=20,
                    reassembly_max_messages=128,
                    reassembly_max_bytes=256 * 1024,
                    loss_probability=loss,
                )
                results.append(
                    simulate_event_lifecycle(
                        graph,
                        config,
                        responders={hops},
                    )
                )
            rows.append(
                LifecycleRow(
                    scenario=scenario,
                    route_hops=hops,
                    runs=runs,
                    success_rate=mean(1.0 if result.success else 0.0 for result in results),
                    cleanup_rate=mean(
                        1.0 if result.cleanup_complete else 0.0 for result in results
                    ),
                    mean_logical_messages=mean(
                        result.logical_messages_sent for result in results
                    ),
                    mean_wire_cells=mean(
                        result.total_transmissions for result in results
                    ),
                    mean_fragmented_messages=mean(
                        result.fragmented_messages_sent for result in results
                    ),
                    mean_wire_bytes=mean(result.wire_bytes for result in results),
                    mean_peak_reassembly_bytes=mean(
                        result.peak_reassembly_reserved_bytes for result in results
                    ),
                    mean_reassembly_timeouts=mean(
                        result.reassembly_timeouts for result in results
                    ),
                )
            )
    return rows


def _write_csv(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError("cannot write an empty report")
    fieldnames = list(asdict(rows[0]).keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def write_reports(
    encoding_output: Path,
    lifecycle_output: Path,
) -> None:
    _write_csv(encoding_output, encoding_rows())
    _write_csv(lifecycle_output, lifecycle_rows())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic Trahens M1/W2 capacity and lifecycle reports."
    )
    parser.add_argument(
        "--capacity-output",
        type=Path,
        required=True,
        help="CSV path for logical-message and W2 cell capacity results.",
    )
    parser.add_argument(
        "--lifecycle-output",
        type=Path,
        required=True,
        help="CSV path for integrated lifecycle and fragmentation results.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=40,
        help="Deterministic runs per lifecycle scenario (default: 40).",
    )
    parser.add_argument(
        "--max-relay-wrappers",
        type=int,
        default=16,
        help="Maximum candidate relay-wrapper count (default: 16).",
    )
    args = parser.parse_args(argv)
    if args.runs <= 0:
        parser.error("--runs must be positive")
    if args.max_relay_wrappers < 0:
        parser.error("--max-relay-wrappers must be non-negative")
    _write_csv(args.capacity_output, encoding_rows(args.max_relay_wrappers))
    _write_csv(args.lifecycle_output, lifecycle_rows(runs=args.runs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
