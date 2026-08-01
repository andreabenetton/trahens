# SPDX-License-Identifier: Apache-2.0
"""Deterministic T1 reliability and scheduled-cell model.

The model runs the current Trahens route-setup exchange over a line topology:
DISCOVER outward, CANDIDATE inward, COMMIT outward, and READY inward. Every
hop regenerates a canonical M2 logical message and transmits it through the T1
adjacent-link profile.

T1 uses selective encrypted acknowledgements, bounded timeout recovery, fresh
padding and AEAD ciphertexts on retransmission, round-robin fragment
interleaving, and an optional fixed-rate cell scheduler that emits CHAFF in
otherwise idle slots. The implementation is designed for reproducible protocol
analysis, not as a production transport or congestion controller.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
import hashlib
import heapq
from math import sqrt
import random
from statistics import mean
from typing import Any

from trahens_codec.m2w2 import (
    CELL_RECORD_BYTES,
    CandidateRecord,
    ControlRecord,
    DiscoverRecord,
    MessageType,
    decode_message,
    derive_link_key,
    encode_candidate,
    encode_control,
    encode_discover,
)
from trahens_codec.t1 import (
    T1AckFrame,
    T1ChaffFrame,
    T1DataFrame,
    T1FrameType,
    ack_bitmap,
    encode_ack_body,
    encode_data_body,
    open_record,
    seal_body,
    split_message,
)
from trahens_crypto import ristretto as r255
from trahens_crypto.eligibility import R1_DISCOVERY_NONCE_BYTES, R1_SUITE_ID


@dataclass(frozen=True)
class T1Config:
    slot_interval_ms: int = 2
    schedule_epoch_ms: int = 700
    scheduler_mode: str = "constant"  # constant | work-conserving
    propagation_delay_min_ms: int = 1
    propagation_delay_max_ms: int = 3
    ack_delay_ms: int = 2
    initial_rto_ms: int = 14
    min_rto_ms: int = 8
    max_rto_ms: int = 96
    max_retransmission_rounds: int = 3
    loss_probability: float = 0.02
    queue_capacity_cells: int = 256
    receiver_cache_ttl_ms: int = 80
    seed: int = 1

    def validate(self) -> None:
        for name in (
            "slot_interval_ms",
            "schedule_epoch_ms",
            "initial_rto_ms",
            "min_rto_ms",
            "max_rto_ms",
            "queue_capacity_cells",
            "receiver_cache_ttl_ms",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")
        if self.scheduler_mode not in {"constant", "work-conserving"}:
            raise ValueError("scheduler_mode must be constant or work-conserving")
        if self.propagation_delay_min_ms < 0:
            raise ValueError("propagation delay cannot be negative")
        if self.propagation_delay_max_ms < self.propagation_delay_min_ms:
            raise ValueError("propagation delay maximum is below minimum")
        if self.ack_delay_ms < 0 or self.ack_delay_ms > 0xFFFF:
            raise ValueError("ack_delay_ms is out of range")
        if self.min_rto_ms > self.initial_rto_ms or self.initial_rto_ms > self.max_rto_ms:
            raise ValueError("RTO bounds are inconsistent")
        if self.max_retransmission_rounds < 0:
            raise ValueError("max_retransmission_rounds cannot be negative")
        if not 0.0 <= self.loss_probability <= 1.0:
            raise ValueError("loss_probability must be between zero and one")


@dataclass(frozen=True)
class T1Result:
    route_hops: int
    success: bool
    stop_reason: str
    setup_latency_ms: int | None
    scheduler_mode: str
    loss_probability: float
    logical_messages: int
    fragmented_messages: int
    data_cells: int
    ack_cells: int
    chaff_cells: int
    retransmitted_data_cells: int
    lost_cells: int
    total_cells: int
    wire_bytes: int
    acked_fragments: int
    timeout_events: int
    retransmission_rounds: int
    retry_exhaustions: int
    queue_drops: int
    malformed_cells: int
    duplicate_fragments: int
    external_trace_rate_cv: float
    per_direction_trace_cells_min: int
    per_direction_trace_cells_max: int
    peak_sender_transmissions: int
    peak_receiver_contexts: int
    final_sender_transmissions: int
    final_receiver_contexts: int
    cleanup_complete: bool
    completed_at_ms: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(order=True)
class _Event:
    time_ms: int
    priority: int
    sequence: int
    kind: str = field(compare=False)
    data: dict[str, Any] = field(compare=False)


@dataclass
class _RttEstimator:
    initial_rto_ms: int
    min_rto_ms: int
    max_rto_ms: int
    srtt_ms: float | None = None
    rttvar_ms: float | None = None
    rto_ms: float = 0.0

    def __post_init__(self) -> None:
        self.rto_ms = float(self.initial_rto_ms)

    def sample(self, rtt_ms: float) -> None:
        rtt_ms = max(rtt_ms, 1.0)
        if self.srtt_ms is None:
            self.srtt_ms = rtt_ms
            self.rttvar_ms = rtt_ms / 2.0
        else:
            assert self.rttvar_ms is not None
            # RFC 6298 order: update RTTVAR against the old SRTT, then SRTT.
            self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * abs(
                self.srtt_ms - rtt_ms
            )
            self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * rtt_ms
        assert self.rttvar_ms is not None and self.srtt_ms is not None
        calculated = self.srtt_ms + max(1.0, 4.0 * self.rttvar_ms)
        self.rto_ms = min(max(calculated, self.min_rto_ms), self.max_rto_ms)

    def backoff(self) -> None:
        self.rto_ms = min(self.rto_ms * 2.0, float(self.max_rto_ms))


@dataclass
class _Transmission:
    transmission_id: bytes
    sender: int
    receiver: int
    logical_message: bytes
    frames: tuple[T1DataFrame, ...]
    app_context: tuple[Any, ...]
    created_at_ms: int
    acked_bitmap: int = 0
    next_unsent: int = 0
    retransmission_rounds: int = 0
    attempts: list[int] = field(default_factory=list)
    last_sent_at_ms: list[int | None] = field(default_factory=list)
    timer_generation: int = 0
    timer_pending: bool = False
    completed: bool = False
    failed: bool = False

    @property
    def fragment_count(self) -> int:
        return len(self.frames)

    @property
    def complete_bitmap(self) -> int:
        return (1 << self.fragment_count) - 1

    def missing_indexes(self) -> tuple[int, ...]:
        return tuple(
            index
            for index in range(self.fragment_count)
            if not (self.acked_bitmap & (1 << index))
        )


@dataclass
class _ReceiveContext:
    sender: int
    receiver: int
    suite_id: bytes
    transmission_id: bytes
    fragment_count: int
    total_length: int
    fragments: dict[int, bytes] = field(default_factory=dict)
    first_received_at_ms: int = 0
    last_received_at_ms: int = 0
    delivered: bool = False
    expires_at_ms: int = 0

    @property
    def bitmap(self) -> int:
        return ack_bitmap(set(self.fragments), self.fragment_count)

    @property
    def complete(self) -> bool:
        return len(self.fragments) == self.fragment_count


@dataclass
class _AckPending:
    suite_id: bytes
    transmission_id: bytes
    fragment_count: int
    bitmap: int
    due_at_ms: int
    first_received_at_ms: int


@dataclass
class _LinkDirection:
    sender: int
    receiver: int
    next_sequence: int = 1
    new_order: deque[bytes] = field(default_factory=deque)
    retransmit_queue: deque[tuple[bytes, int]] = field(default_factory=deque)
    pending_acks: dict[bytes, _AckPending] = field(default_factory=dict)
    external_trace: list[int] = field(default_factory=list)
    estimator: _RttEstimator | None = None


class _T1PathSimulator:
    def __init__(self, route_hops: int, config: T1Config, *, start_protocol: bool) -> None:
        if route_hops < 1:
            raise ValueError("route_hops must be positive")
        config.validate()
        self.route_hops = route_hops
        self.config = config
        self.start_protocol = start_protocol
        self.rng = random.Random(config.seed)
        self.queue: list[_Event] = []
        self.event_sequence = 0
        self.now_ms = 0
        self.used_transmission_ids: set[bytes] = set()

        self.links: dict[tuple[int, int], _LinkDirection] = {}
        for node in range(route_hops):
            for sender, receiver in ((node, node + 1), (node + 1, node)):
                self.links[(sender, receiver)] = _LinkDirection(
                    sender=sender,
                    receiver=receiver,
                    estimator=_RttEstimator(
                        config.initial_rto_ms,
                        config.min_rto_ms,
                        config.max_rto_ms,
                    ),
                )

        self.transmissions: dict[tuple[int, int, bytes], _Transmission] = {}
        self.receive_contexts: dict[tuple[int, int, bytes], _ReceiveContext] = {}

        self.success = False
        self.failed = False
        self.stop_reason = "schedule_epoch_complete"
        self.setup_latency_ms: int | None = None

        self.logical_messages = 0
        self.fragmented_messages = 0
        self.data_cells = 0
        self.ack_cells = 0
        self.chaff_cells = 0
        self.retransmitted_data_cells = 0
        self.lost_cells = 0
        self.acked_fragments = 0
        self.timeout_events = 0
        self.retransmission_rounds = 0
        self.retry_exhaustions = 0
        self.queue_drops = 0
        self.malformed_cells = 0
        self.duplicate_fragments = 0
        self.peak_sender_transmissions = 0
        self.peak_receiver_contexts = 0

    def run(self) -> T1Result:
        for edge in self.links:
            self._schedule(0, 2, "SLOT", {"edge": edge})
        if self.start_protocol:
            self._schedule(0, 0, "START", {})

        while self.queue:
            event = heapq.heappop(self.queue)
            if event.time_ms > self.config.schedule_epoch_ms:
                self.now_ms = self.config.schedule_epoch_ms
                break
            self.now_ms = event.time_ms
            if event.kind == "START":
                self._start_route_setup()
            elif event.kind == "SLOT":
                self._handle_slot(tuple(event.data["edge"]))
            elif event.kind == "DELIVER":
                self._handle_delivery(event.data)
            elif event.kind == "TIMEOUT":
                self._handle_timeout(event.data)
            elif event.kind == "RX_EXPIRE":
                self._handle_receive_expiry(event.data)
            else:  # pragma: no cover - programming error
                raise AssertionError(f"unknown T1 event {event.kind}")
            self.peak_sender_transmissions = max(
                self.peak_sender_transmissions,
                sum(
                    1
                    for tx in self.transmissions.values()
                    if not tx.completed and not tx.failed
                ),
            )
            self.peak_receiver_contexts = max(
                self.peak_receiver_contexts, len(self.receive_contexts)
            )

        live_tx = sum(
            1 for tx in self.transmissions.values() if not tx.completed and not tx.failed
        )
        if self.start_protocol and not self.success and not self.failed:
            self.failed = True
            self.stop_reason = "schedule_epoch_timeout"
            for tx in self.transmissions.values():
                if not tx.completed:
                    tx.failed = True
            live_tx = 0
        # Expire receive caches at the end of the finite observation epoch.
        self.receive_contexts.clear()
        pending_acks = sum(len(link.pending_acks) for link in self.links.values())
        queued = sum(
            len(link.new_order) + len(link.retransmit_queue)
            for link in self.links.values()
        )
        cleanup_complete = live_tx == 0 and pending_acks == 0 and queued == 0

        cvs = [self._trace_cv(link.external_trace) for link in self.links.values()]
        trace_counts = [len(link.external_trace) for link in self.links.values()]
        total_cells = self.data_cells + self.ack_cells + self.chaff_cells
        return T1Result(
            route_hops=self.route_hops,
            success=self.success,
            stop_reason=self.stop_reason,
            setup_latency_ms=self.setup_latency_ms,
            scheduler_mode=self.config.scheduler_mode,
            loss_probability=self.config.loss_probability,
            logical_messages=self.logical_messages,
            fragmented_messages=self.fragmented_messages,
            data_cells=self.data_cells,
            ack_cells=self.ack_cells,
            chaff_cells=self.chaff_cells,
            retransmitted_data_cells=self.retransmitted_data_cells,
            lost_cells=self.lost_cells,
            total_cells=total_cells,
            wire_bytes=total_cells * CELL_RECORD_BYTES,
            acked_fragments=self.acked_fragments,
            timeout_events=self.timeout_events,
            retransmission_rounds=self.retransmission_rounds,
            retry_exhaustions=self.retry_exhaustions,
            queue_drops=self.queue_drops,
            malformed_cells=self.malformed_cells,
            duplicate_fragments=self.duplicate_fragments,
            external_trace_rate_cv=mean(cvs) if cvs else 0.0,
            per_direction_trace_cells_min=min(trace_counts) if trace_counts else 0,
            per_direction_trace_cells_max=max(trace_counts) if trace_counts else 0,
            peak_sender_transmissions=self.peak_sender_transmissions,
            peak_receiver_contexts=self.peak_receiver_contexts,
            final_sender_transmissions=live_tx,
            final_receiver_contexts=len(self.receive_contexts),
            cleanup_complete=cleanup_complete,
            completed_at_ms=self.now_ms,
        )

    @staticmethod
    def _trace_cv(trace: list[int]) -> float:
        if len(trace) < 3:
            return 0.0
        intervals = [b - a for a, b in zip(trace, trace[1:])]
        average = mean(intervals)
        if average == 0:
            return 0.0
        variance = mean((value - average) ** 2 for value in intervals)
        return sqrt(variance) / average

    def _schedule(self, time_ms: int, priority: int, kind: str, data: dict[str, Any]) -> None:
        self.event_sequence += 1
        heapq.heappush(
            self.queue,
            _Event(time_ms, priority, self.event_sequence, kind, data),
        )

    def _randbytes(self, length: int) -> bytes:
        return bytes(self.rng.getrandbits(8) for _ in range(length))

    def _transmission_id(self) -> bytes:
        while True:
            value = self._randbytes(16)
            if value != bytes(16) and value not in self.used_transmission_ids:
                self.used_transmission_ids.add(value)
                return value

    def _token(self, length: int) -> bytes:
        while True:
            value = self._randbytes(length)
            if value != bytes(length):
                return value

    def _delay(self) -> int:
        return self.rng.randint(
            self.config.propagation_delay_min_ms,
            self.config.propagation_delay_max_ms,
        )

    def _start_route_setup(self) -> None:
        self._queue_message(
            0,
            1,
            self._discover_message(hop_remaining=self.route_hops - 1),
            ("DISCOVER", 1),
        )

    def _discover_message(self, *, hop_remaining: int) -> bytes:
        reply_secret = r255.scalar_from_label(
            self._randbytes(32), dst=b"Trahens-T1-model-reply-v1"
        )
        return encode_discover(
            DiscoverRecord(
                branch_token=self._token(16),
                hop_remaining=hop_remaining,
                fanout_class=1,
                expiry_class=1,
                depth=0,
                routing_nonce=bytes(range(1, 33)),
                reply_public_key=r255.scalarmult_base(reply_secret),
                eligibility_capsule=self._token(R1_DISCOVERY_NONCE_BYTES),
                crypto_suite_id=R1_SUITE_ID,
            )
        )

    def _candidate_message(self, *, layer_count: int) -> bytes:
        # The measured candidate construction grows by approximately 115 bytes
        # per reverse relay. This deterministic body reproduces the resulting
        # W2/T1 fragmentation boundary without pretending to replace the
        # cryptographic candidate implementation.
        length = 219 + 115 * layer_count
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            stream.extend(
                hashlib.sha256(
                    b"Trahens-T1-candidate-body-v1"
                    + self.config.seed.to_bytes(8, "big")
                    + layer_count.to_bytes(2, "big")
                    + counter.to_bytes(4, "big")
                ).digest()
            )
            counter += 1
        return encode_candidate(
            CandidateRecord(
                candidate_token=self._token(16),
                expiry_class=1,
                layer_count=layer_count,
                candidate_blob=bytes(stream[:length]),
                crypto_suite_id=R1_SUITE_ID,
            )
        )

    def _control_message(self, message_type: MessageType) -> bytes:
        return encode_control(
            ControlRecord(
                message_type=message_type,
                local_label=self._token(16),
                generation=1,
                expiry_class=1,
                protected_body=self._token(32),
                crypto_suite_id=R1_SUITE_ID,
            )
        )

    def _queue_message(
        self,
        sender: int,
        receiver: int,
        logical_message: bytes,
        app_context: tuple[Any, ...],
    ) -> None:
        if self.failed or self.success:
            return
        edge = (sender, receiver)
        if edge not in self.links:
            raise AssertionError(f"non-adjacent T1 message {edge}")
        txid = self._transmission_id()
        frames = split_message(logical_message, transmission_id=txid)
        link = self.links[edge]
        queued_cells = len(link.retransmit_queue) + sum(
            max(0, tx.fragment_count - tx.next_unsent)
            for key, tx in self.transmissions.items()
            if key[:2] == edge and not tx.completed and not tx.failed
        )
        if queued_cells + len(frames) > self.config.queue_capacity_cells:
            self.queue_drops += 1
            self._fail("sender_queue_capacity")
            return
        tx = _Transmission(
            transmission_id=txid,
            sender=sender,
            receiver=receiver,
            logical_message=logical_message,
            frames=frames,
            app_context=app_context,
            created_at_ms=self.now_ms,
            attempts=[0] * len(frames),
            last_sent_at_ms=[None] * len(frames),
        )
        self.transmissions[(sender, receiver, txid)] = tx
        link.new_order.append(txid)
        self.logical_messages += 1
        if len(frames) > 1:
            self.fragmented_messages += 1

    def _handle_slot(self, edge: tuple[int, int]) -> None:
        link = self.links[edge]
        chosen: tuple[T1FrameType, Any] | None = None

        due_acks = [
            pending
            for pending in link.pending_acks.values()
            if pending.due_at_ms <= self.now_ms
        ]
        if due_acks:
            pending = min(due_acks, key=lambda item: (item.due_at_ms, item.transmission_id))
            link.pending_acks.pop(pending.transmission_id, None)
            chosen = (T1FrameType.ACK, pending)
        else:
            while link.retransmit_queue and chosen is None:
                txid, index = link.retransmit_queue.popleft()
                tx = self.transmissions.get((edge[0], edge[1], txid))
                if tx is None or tx.completed or tx.failed:
                    continue
                if tx.acked_bitmap & (1 << index):
                    continue
                chosen = (T1FrameType.DATA, (tx, index, True))

            attempts = len(link.new_order)
            while chosen is None and attempts > 0:
                attempts -= 1
                txid = link.new_order.popleft()
                tx = self.transmissions.get((edge[0], edge[1], txid))
                if tx is None or tx.completed or tx.failed:
                    continue
                while tx.next_unsent < tx.fragment_count and (
                    tx.acked_bitmap & (1 << tx.next_unsent)
                ):
                    tx.next_unsent += 1
                if tx.next_unsent < tx.fragment_count:
                    index = tx.next_unsent
                    tx.next_unsent += 1
                    if tx.next_unsent < tx.fragment_count:
                        link.new_order.append(txid)
                    chosen = (T1FrameType.DATA, (tx, index, False))

        if chosen is None and self.config.scheduler_mode == "constant":
            chosen = (T1FrameType.CHAFF, None)
        if chosen is not None:
            self._emit(edge, chosen)

        next_slot = self.now_ms + self.config.slot_interval_ms
        if next_slot <= self.config.schedule_epoch_ms:
            self._schedule(next_slot, 2, "SLOT", {"edge": edge})

    def _emit(self, edge: tuple[int, int], chosen: tuple[T1FrameType, Any]) -> None:
        sender, receiver = edge
        link = self.links[edge]
        frame_type, value = chosen
        sequence = link.next_sequence
        link.next_sequence += 1
        key = derive_link_key(self.config.seed, sender, receiver)

        if frame_type is T1FrameType.DATA:
            tx, index, retransmission = value
            frame = tx.frames[index]
            body = encode_data_body(frame, rng=self.rng)
            self.data_cells += 1
            if retransmission or tx.attempts[index] > 0:
                self.retransmitted_data_cells += 1
            tx.attempts[index] += 1
            tx.last_sent_at_ms[index] = self.now_ms
            # Restart one transmission timer after every emitted DATA frame.
            tx.timer_generation += 1
            tx.timer_pending = True
            estimator = link.estimator
            assert estimator is not None
            timeout_at = self.now_ms + int(round(estimator.rto_ms))
            self._schedule(
                timeout_at,
                1,
                "TIMEOUT",
                {
                    "edge": edge,
                    "transmission_id": tx.transmission_id,
                    "generation": tx.timer_generation,
                },
            )
        elif frame_type is T1FrameType.ACK:
            pending: _AckPending = value
            body = encode_ack_body(
                crypto_suite_id=pending.suite_id,
                transmission_id=pending.transmission_id,
                fragment_count=pending.fragment_count,
                acknowledged_bitmap=pending.bitmap,
                ack_delay_ms=min(
                    max(self.now_ms - pending.first_received_at_ms, 0), 0xFFFF
                ),
                rng=self.rng,
            )
            self.ack_cells += 1
        else:
            # CHAFF has no receive-side semantics. The codec is exercised by
            # conformance tests; the large scheduling experiments count a
            # correctly sized encrypted record without spending an AEAD
            # operation for every idle slot. This does not alter the public
            # timestamp or byte trace used by the experiment.
            self.chaff_cells += 1
            link.external_trace.append(self.now_ms)
            if self.rng.random() < self.config.loss_probability:
                self.lost_cells += 1
            return

        record = seal_body(
            body,
            key=key,
            epoch=1,
            sequence=sequence,
        )
        link.external_trace.append(self.now_ms)
        if self.rng.random() < self.config.loss_probability:
            self.lost_cells += 1
            return
        self._schedule(
            self.now_ms + self._delay(),
            0,
            "DELIVER",
            {
                "sender": sender,
                "receiver": receiver,
                "sequence": sequence,
                "record": record,
            },
        )

    def _handle_delivery(self, data: dict[str, Any]) -> None:
        sender = int(data["sender"])
        receiver = int(data["receiver"])
        key = derive_link_key(self.config.seed, sender, receiver)
        try:
            _, _, frame = open_record(
                bytes(data["record"]),
                key=key,
                expected_epoch=1,
                expected_sequence=int(data["sequence"]),
            )
        except Exception:
            self.malformed_cells += 1
            return

        if isinstance(frame, T1DataFrame):
            self._receive_data(sender, receiver, frame)
        elif isinstance(frame, T1AckFrame):
            self._receive_ack(sender, receiver, frame)
        elif isinstance(frame, T1ChaffFrame):
            return
        else:  # pragma: no cover
            raise AssertionError("unexpected T1 frame")

    def _receive_data(self, sender: int, receiver: int, frame: T1DataFrame) -> None:
        key = (sender, receiver, frame.transmission_id)
        context = self.receive_contexts.get(key)
        if context is None:
            context = _ReceiveContext(
                sender=sender,
                receiver=receiver,
                suite_id=frame.crypto_suite_id,
                transmission_id=frame.transmission_id,
                fragment_count=frame.fragment_count,
                total_length=frame.total_message_length,
                first_received_at_ms=self.now_ms,
                last_received_at_ms=self.now_ms,
                expires_at_ms=self.now_ms + self.config.receiver_cache_ttl_ms,
            )
            self.receive_contexts[key] = context
        elif (
            context.suite_id != frame.crypto_suite_id
            or context.fragment_count != frame.fragment_count
            or context.total_length != frame.total_message_length
        ):
            self.malformed_cells += 1
            self.receive_contexts.pop(key, None)
            return

        existing = context.fragments.get(frame.fragment_index)
        if existing is not None:
            if existing != frame.fragment:
                self.malformed_cells += 1
                self.receive_contexts.pop(key, None)
                return
            self.duplicate_fragments += 1
        else:
            context.fragments[frame.fragment_index] = frame.fragment
        context.last_received_at_ms = self.now_ms
        context.expires_at_ms = self.now_ms + self.config.receiver_cache_ttl_ms
        self._schedule(
            context.expires_at_ms,
            1,
            "RX_EXPIRE",
            {"key": key, "expires_at_ms": context.expires_at_ms},
        )

        reverse = self.links[(receiver, sender)]
        pending = reverse.pending_acks.get(frame.transmission_id)
        due = self.now_ms + self.config.ack_delay_ms
        bitmap = context.bitmap
        if pending is None:
            reverse.pending_acks[frame.transmission_id] = _AckPending(
                suite_id=frame.crypto_suite_id,
                transmission_id=frame.transmission_id,
                fragment_count=frame.fragment_count,
                bitmap=bitmap,
                due_at_ms=due,
                first_received_at_ms=context.first_received_at_ms,
            )
        else:
            pending.bitmap = bitmap
            pending.due_at_ms = min(pending.due_at_ms, due)

        if context.complete and not context.delivered:
            try:
                message = b"".join(
                    context.fragments[index] for index in range(context.fragment_count)
                )
                if len(message) != context.total_length:
                    raise ValueError("length mismatch")
                decode_message(message)
            except Exception:
                self.malformed_cells += 1
                self.receive_contexts.pop(key, None)
                return
            context.delivered = True
            tx = self.transmissions.get(key)
            if tx is None:
                self.malformed_cells += 1
                return
            self._on_logical_delivery(receiver, tx.app_context)

    def _receive_ack(self, sender: int, receiver: int, frame: T1AckFrame) -> None:
        # ACK sender/receiver are reversed relative to the DATA transmission.
        tx_key = (receiver, sender, frame.transmission_id)
        tx = self.transmissions.get(tx_key)
        if tx is None or tx.completed or tx.failed:
            return
        if tx.fragment_count != frame.fragment_count:
            self.malformed_cells += 1
            return
        new_bits = frame.acknowledged_bitmap & ~tx.acked_bitmap
        if new_bits:
            link = self.links[(tx.sender, tx.receiver)]
            estimator = link.estimator
            assert estimator is not None
            for index in range(tx.fragment_count):
                if not (new_bits & (1 << index)):
                    continue
                self.acked_fragments += 1
                # Karn-style sampling: do not sample a retransmitted fragment.
                sent_at = tx.last_sent_at_ms[index]
                if tx.attempts[index] == 1 and sent_at is not None:
                    observed = max(
                        self.now_ms - sent_at - min(frame.ack_delay_ms, self.now_ms - sent_at),
                        1,
                    )
                    estimator.sample(float(observed))
            tx.acked_bitmap |= frame.acknowledged_bitmap
        if tx.acked_bitmap == tx.complete_bitmap:
            tx.completed = True
            tx.timer_pending = False

    def _handle_timeout(self, data: dict[str, Any]) -> None:
        edge = tuple(data["edge"])
        txid = bytes(data["transmission_id"])
        tx = self.transmissions.get((edge[0], edge[1], txid))
        if tx is None or tx.completed or tx.failed:
            return
        if int(data["generation"]) != tx.timer_generation:
            return
        tx.timer_pending = False
        self.timeout_events += 1
        missing = tx.missing_indexes()
        if not missing:
            return
        if tx.retransmission_rounds >= self.config.max_retransmission_rounds:
            tx.failed = True
            self.retry_exhaustions += 1
            self._fail("retransmission_limit")
            return
        tx.retransmission_rounds += 1
        self.retransmission_rounds += 1
        estimator = self.links[edge].estimator
        assert estimator is not None
        estimator.backoff()
        for index in missing:
            self.links[edge].retransmit_queue.append((txid, index))

    def _handle_receive_expiry(self, data: dict[str, Any]) -> None:
        key = tuple(data["key"])
        context = self.receive_contexts.get(key)
        if context is None:
            return
        if context.expires_at_ms == int(data["expires_at_ms"]) and context.expires_at_ms <= self.now_ms:
            self.receive_contexts.pop(key, None)

    def _on_logical_delivery(self, receiver: int, context: tuple[Any, ...]) -> None:
        if self.failed or self.success:
            return
        stage = str(context[0])
        position = int(context[1])
        if stage == "DISCOVER":
            if receiver != position:
                self._fail("discover_context_mismatch")
                return
            if receiver < self.route_hops:
                self._queue_message(
                    receiver,
                    receiver + 1,
                    self._discover_message(
                        hop_remaining=self.route_hops - receiver - 1
                    ),
                    ("DISCOVER", receiver + 1),
                )
            else:
                self._queue_message(
                    receiver,
                    receiver - 1,
                    self._candidate_message(layer_count=1),
                    ("CANDIDATE", receiver - 1, 1),
                )
        elif stage == "CANDIDATE":
            layer_count = int(context[2])
            if receiver != position:
                self._fail("candidate_context_mismatch")
                return
            if receiver > 0:
                self._queue_message(
                    receiver,
                    receiver - 1,
                    self._candidate_message(layer_count=layer_count + 1),
                    ("CANDIDATE", receiver - 1, layer_count + 1),
                )
            else:
                self._queue_message(
                    0,
                    1,
                    self._control_message(MessageType.COMMIT),
                    ("COMMIT", 1),
                )
        elif stage == "COMMIT":
            if receiver != position:
                self._fail("commit_context_mismatch")
                return
            if receiver < self.route_hops:
                self._queue_message(
                    receiver,
                    receiver + 1,
                    self._control_message(MessageType.COMMIT),
                    ("COMMIT", receiver + 1),
                )
            else:
                self._queue_message(
                    receiver,
                    receiver - 1,
                    self._control_message(MessageType.READY),
                    ("READY", receiver - 1),
                )
        elif stage == "READY":
            if receiver != position:
                self._fail("ready_context_mismatch")
                return
            if receiver > 0:
                self._queue_message(
                    receiver,
                    receiver - 1,
                    self._control_message(MessageType.READY),
                    ("READY", receiver - 1),
                )
            else:
                self.success = True
                self.stop_reason = "ready"
                self.setup_latency_ms = self.now_ms
        else:
            self._fail("unknown_application_stage")

    def _fail(self, reason: str) -> None:
        if self.success or self.failed:
            return
        self.failed = True
        self.stop_reason = reason
        for tx in self.transmissions.values():
            if not tx.completed:
                tx.failed = True
        for link in self.links.values():
            link.new_order.clear()
            link.retransmit_queue.clear()
            link.pending_acks.clear()


def simulate_t1_path(
    route_hops: int,
    config: T1Config,
    *,
    start_protocol: bool = True,
) -> T1Result:
    """Run one deterministic T1 route-setup experiment."""

    return _T1PathSimulator(route_hops, config, start_protocol=start_protocol).run()


__all__ = ["T1Config", "T1Result", "simulate_t1_path"]
