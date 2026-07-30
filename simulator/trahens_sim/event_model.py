"""Deterministic discrete-event model for the Trahens route lifecycle.

The model integrates the U1 branch transformations, the E1 event lifecycle, the
C1 cryptographic operations, the M1 variable-length message codec, and the W2 fixed-size adjacent-link cell profile.
It remains a protocol model rather than a packet-timing or traffic-analysis
benchmark.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import IntEnum
import hashlib
import heapq
import hmac
import random
from typing import Any, Iterable

from trahens_codec.m1w2 import (
    CELL_RECORD_BYTES,
    CandidateRecord as WireCandidateRecord,
    CodecError,
    ControlRecord as WireControlRecord,
    DiscoverRecord as WireDiscoverRecord,
    MessageType,
    Reassembler,
    decode_cell,
    decode_message,
    derive_link_key,
    encode_candidate,
    encode_control,
    encode_discover,
    encode_to_link_cells,
    open_link_cell,
)
from trahens_crypto import ristretto as r255
from trahens_crypto.c1 import (
    CryptoError,
    URECiphertext,
    build_endpoint_keys,
    reply_tweak_public,
    ure_encrypt,
    ure_is_eligible,
    ure_rerandomize,
)
from trahens_crypto.candidate import (
    build_responder_payload,
    commit_proof,
    open_candidate_chain,
    ready_proof,
    seal_responder_candidate,
    wrap_relay_candidate,
)
from trahens_crypto.tagging import apply_ratio_tag, matches_ratio_tag

from .model import Graph, choose_responders


class EventPriority(IntEnum):
    """Deterministic ordering for events with the same timestamp.

    Expiry is processed first. A message that arrives exactly at a state expiry
    deadline therefore observes the state as expired. Candidate delivery is
    processed before a ring window closes, so a candidate arriving exactly at
    the window deadline is eligible for that decision.
    """

    EXPIRY = 0
    CANCEL = 1
    CONTROL = 2
    CANDIDATE = 3
    DISCOVER = 4
    WINDOW = 5
    ATTACK = 6


@dataclass(frozen=True)
class TimedRingStep:
    hop_limit: int
    initial_fanout: int
    relay_fanout: int
    candidate_window_ms: int

    def validate(self) -> None:
        if self.hop_limit < 1:
            raise ValueError("ring hop_limit must be positive")
        if self.initial_fanout < 1:
            raise ValueError("ring initial_fanout must be positive")
        if self.relay_fanout < 1:
            raise ValueError("ring relay_fanout must be positive")
        if self.candidate_window_ms < 1:
            raise ValueError("candidate_window_ms must be positive")


@dataclass(frozen=True)
class EventLifecycleConfig:
    origin: int = 0
    rings: tuple[TimedRingStep, ...] = (
        TimedRingStep(2, 2, 2, 18),
        TimedRingStep(3, 2, 2, 24),
        TimedRingStep(4, 3, 3, 32),
    )
    candidate_limit: int = 8
    required_candidates: int = 1
    responder_fraction: float = 0.02
    seed: int = 1

    discover_delay_min_ms: int = 1
    discover_delay_max_ms: int = 4
    candidate_delay_min_ms: int = 1
    candidate_delay_max_ms: int = 4
    control_delay_min_ms: int = 1
    control_delay_max_ms: int = 3
    responder_offer_delay_min_ms: int = 1
    responder_offer_delay_max_ms: int = 8

    branch_ttl_ms: int = 70
    offer_ttl_ms: int = 90
    tentative_ttl_ms: int = 55
    ready_hold_ms: int = 40
    route_setup_timeout_ms: int = 90
    active_lifetime_ms: int = 80
    max_simulation_ms: int = 400

    transmission_budget: int = 2_000
    branch_capacity: int = 1_200
    tentative_capacity: int = 600
    active_capacity: int = 128
    per_node_branch_limit: int = 8
    candidate_response_limit: int = 64

    loss_probability: float = 0.0
    duplicate_probability: float = 0.0
    forced_drop_types: tuple[str, ...] = ()
    enable_crypto: bool = True
    wire_tamper_probability: float = 0.0
    reassembly_timeout_ms: int = 40
    reassembly_max_messages: int = 128
    reassembly_max_bytes: int = 256 * 1024
    active_tagging: bool = False
    tag_scalar_seed: int = 23

    malicious_fraction: float = 0.0
    attack_start_ms: int = 0
    attack_bursts: int = 0
    attack_interval_ms: int = 4
    attack_branches_per_burst: int = 0
    attack_hop_limit: int = 3
    attack_fanout: int = 3

    peer_bucket_capacity: int | None = None
    peer_bucket_refill_ms: int = 10
    peer_bucket_refill_amount: int = 1

    def validate(self, graph: Graph) -> None:
        if self.origin < 0 or self.origin >= graph.node_count:
            raise ValueError("origin is outside the graph")
        if not self.rings:
            raise ValueError("at least one ring is required")
        previous_hop_limit = 0
        for ring in self.rings:
            ring.validate()
            if ring.hop_limit < previous_hop_limit:
                raise ValueError("ring hop limits must be non-decreasing")
            previous_hop_limit = ring.hop_limit
        if self.candidate_limit < 1:
            raise ValueError("candidate_limit must be positive")
        if self.required_candidates < 1:
            raise ValueError("required_candidates must be positive")
        if self.required_candidates > self.candidate_limit:
            raise ValueError("required_candidates cannot exceed candidate_limit")
        if not 0.0 <= self.responder_fraction <= 1.0:
            raise ValueError("responder_fraction must be between 0 and 1")
        for name in (
            "discover_delay_min_ms",
            "candidate_delay_min_ms",
            "control_delay_min_ms",
            "responder_offer_delay_min_ms",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        for low, high, label in (
            (
                self.discover_delay_min_ms,
                self.discover_delay_max_ms,
                "discover delay",
            ),
            (
                self.candidate_delay_min_ms,
                self.candidate_delay_max_ms,
                "candidate delay",
            ),
            (
                self.control_delay_min_ms,
                self.control_delay_max_ms,
                "control delay",
            ),
            (
                self.responder_offer_delay_min_ms,
                self.responder_offer_delay_max_ms,
                "offer delay",
            ),
        ):
            if high < low:
                raise ValueError(f"{label} maximum cannot be below minimum")
        for name in (
            "branch_ttl_ms",
            "offer_ttl_ms",
            "tentative_ttl_ms",
            "ready_hold_ms",
            "route_setup_timeout_ms",
            "active_lifetime_ms",
            "max_simulation_ms",
            "transmission_budget",
            "branch_capacity",
            "tentative_capacity",
            "active_capacity",
            "per_node_branch_limit",
            "candidate_response_limit",
            "reassembly_timeout_ms",
            "reassembly_max_messages",
            "reassembly_max_bytes",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")
        for name in (
            "loss_probability",
            "duplicate_probability",
            "wire_tamper_probability",
        ):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.tag_scalar_seed < 0:
            raise ValueError("tag_scalar_seed cannot be negative")
        if not 0.0 <= self.malicious_fraction <= 1.0:
            raise ValueError("malicious_fraction must be between 0 and 1")
        if self.attack_start_ms < 0:
            raise ValueError("attack_start_ms cannot be negative")
        if self.attack_bursts < 0:
            raise ValueError("attack_bursts cannot be negative")
        if self.attack_interval_ms < 1:
            raise ValueError("attack_interval_ms must be positive")
        if self.attack_branches_per_burst < 0:
            raise ValueError("attack_branches_per_burst cannot be negative")
        if self.attack_hop_limit < 1:
            raise ValueError("attack_hop_limit must be positive")
        if self.attack_fanout < 1:
            raise ValueError("attack_fanout must be positive")
        if self.peer_bucket_capacity is not None:
            if self.peer_bucket_capacity < 1:
                raise ValueError("peer_bucket_capacity must be positive")
            if self.peer_bucket_refill_ms < 1:
                raise ValueError("peer_bucket_refill_ms must be positive")
            if self.peer_bucket_refill_amount < 1:
                raise ValueError("peer_bucket_refill_amount must be positive")


@dataclass(order=True)
class _ScheduledEvent:
    time_ms: int
    priority: int
    sequence: int
    kind: str = field(compare=False)
    data: dict[str, Any] = field(compare=False)


@dataclass
class _BranchContext:
    context_id: int
    node: int
    ingress_peer: int
    parent_context_id: int | None
    ring_index: int | None
    hop_count: int
    hop_limit: int
    relay_fanout: int
    legitimate: bool
    expires_at_ms: int
    branch_token: bytes = b""
    reply_public_key: bytes | None = None
    reply_delta: bytes | None = None
    eligibility_capsule: URECiphertext | None = None
    root_reply_secret: bytes | None = None
    status: str = "live"
    child_context_ids: set[int] = field(default_factory=set)


@dataclass
class _TentativeState:
    candidate_id: int
    context_id: int
    node: int
    expires_at_ms: int
    status: str = "tentative"


@dataclass
class _CandidateRecord:
    candidate_id: int
    responder: int
    path_context_ids: tuple[int, ...]
    ring_index: int
    hop_count: int
    arrival_time_ms: int
    offer_expires_at_ms: int
    commit_challenge: bytes = b""


@dataclass(frozen=True)
class EventLifecycleResult:
    node_count: int
    edge_count: int
    success: bool
    stop_reason: str
    selected_responder: int | None
    selected_hop_count: int | None
    selected_ring_index: int | None
    setup_latency_ms: int | None
    rings_started: int
    candidates_received: int
    unique_candidate_responders: int
    late_candidates: int
    candidate_race_drops: int
    candidate_expiry_drops: int
    commit_failures: int
    ready_failures: int
    exact_replay_drops: int
    loss_drops: int
    transmission_budget_drops: int
    branch_capacity_drops: int
    per_node_branch_drops: int
    tentative_capacity_drops: int
    active_capacity_drops: int
    token_bucket_drops: int
    stale_parent_drops: int
    wire_auth_failures: int
    codec_failures: int
    crypto_failures: int
    crypto_discover_transforms: int
    crypto_candidate_layers: int
    tagged_branches_created: int
    tag_observations: int
    wire_bytes: int
    logical_messages_sent: int
    fragmented_messages_sent: int
    reassembly_completed: int
    reassembly_duplicate_fragments: int
    reassembly_timeouts: int
    reassembly_capacity_drops: int
    reassembly_metadata_failures: int
    peak_reassembly_messages: int
    peak_reassembly_reserved_bytes: int
    final_reassembly_messages: int
    legitimate_transmissions: int
    attack_transmissions: int
    total_transmissions: int
    message_counts: tuple[tuple[str, int], ...]
    legitimate_branch_allocations: int
    attack_branch_allocations: int
    peak_branch_state: int
    peak_offer_state: int
    peak_candidate_state: int
    peak_tentative_state: int
    peak_pending_state: int
    peak_active_state: int
    final_branch_state: int
    final_offer_state: int
    final_candidate_state: int
    final_tentative_state: int
    final_pending_state: int
    final_active_state: int
    cleanup_complete: bool
    completed_at_ms: int

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["message_counts"] = dict(self.message_counts)
        return data


@dataclass
class _TokenBucket:
    tokens: float
    last_time_ms: int


class _LifecycleSimulator:
    def __init__(
        self,
        graph: Graph,
        config: EventLifecycleConfig,
        *,
        responders: set[int],
        responder_offer_delays: dict[int, int] | None,
        malicious_nodes: set[int],
    ) -> None:
        self.graph = graph
        self.config = config
        self.responders = responders
        self.responder_offer_delays = responder_offer_delays or {}
        self.malicious_nodes = malicious_nodes
        self.rng = random.Random(config.seed)
        self.endpoint_keys = build_endpoint_keys(
            f"event-target/{config.seed}".encode("ascii")
        )
        self.tag_scalar = r255.scalar_from_label(
            config.tag_scalar_seed.to_bytes(8, "big"),
            dst=b"Trahens-C1-active-tag-scalar-v1",
        )

        self.queue: list[_ScheduledEvent] = []
        self.sequence = 0
        self.now_ms = 0
        self.next_message_id = 1
        self.next_logical_message_id = 1
        self.next_context_id = 1
        self.next_candidate_id = 1
        self.used_w2_message_ids: set[bytes] = set()

        self.branches: dict[int, _BranchContext] = {}
        self.live_branch_ids: set[int] = set()
        self.contexts_per_node: Counter[int] = Counter()
        self.tentatives: dict[tuple[int, int], _TentativeState] = {}
        self.pending_keys: set[tuple[int, int]] = set()
        self.active_keys: set[tuple[int, int]] = set()
        self.offers: dict[int, tuple[int, int, bytes]] = {}
        self.candidates: dict[int, _CandidateRecord] = {}
        self.candidate_responders: set[int] = set()
        self.replay_seen: set[tuple[str, int, int, int]] = set()
        self.buckets: dict[tuple[int, int], _TokenBucket] = {}
        self.reassembler = Reassembler(
            timeout_ms=config.reassembly_timeout_ms,
            max_messages=config.reassembly_max_messages,
            max_reserved_bytes=config.reassembly_max_bytes,
        )

        self.current_ring_index = -1
        self.rings_started = 0
        self.decision_made = False
        self.success = False
        self.route_failed = False
        self.stop_reason = "simulation_exhausted"
        self.selected_candidate_id: int | None = None
        self.selected_path_set: set[int] = set()
        self.selected_responder: int | None = None
        self.selected_hop_count: int | None = None
        self.selected_ring_index: int | None = None
        self.setup_latency_ms: int | None = None

        self.message_counts: Counter[str] = Counter()
        self.logical_messages_sent = 0
        self.fragmented_messages_sent = 0
        self.legitimate_transmissions = 0
        self.attack_transmissions = 0
        self.loss_drops = 0
        self.transmission_budget_drops = 0
        self.branch_capacity_drops = 0
        self.per_node_branch_drops = 0
        self.tentative_capacity_drops = 0
        self.active_capacity_drops = 0
        self.token_bucket_drops = 0
        self.stale_parent_drops = 0
        self.exact_replay_drops = 0
        self.late_candidates = 0
        self.candidate_race_drops = 0
        self.candidate_expiry_drops = 0
        self.commit_failures = 0
        self.ready_failures = 0
        self.legitimate_branch_allocations = 0
        self.attack_branch_allocations = 0
        self.candidate_responses = 0
        self.candidates_received_count = 0
        self.wire_auth_failures = 0
        self.codec_failures = 0
        self.crypto_failures = 0
        self.crypto_discover_transforms = 0
        self.crypto_candidate_layers = 0
        self.tagged_branches_created = 0
        self.tag_observations = 0

        self.peak_branch_state = 0
        self.peak_offer_state = 0
        self.peak_candidate_state = 0
        self.peak_tentative_state = 0
        self.peak_pending_state = 0
        self.peak_active_state = 0

    def run(self) -> EventLifecycleResult:
        self._schedule_local(0, EventPriority.WINDOW, "START_RING", {"ring": 0})
        for burst in range(self.config.attack_bursts):
            self._schedule_local(
                self.config.attack_start_ms
                + burst * self.config.attack_interval_ms,
                EventPriority.ATTACK,
                "ATTACK_BURST",
                {"burst": burst},
            )

        while self.queue:
            event = heapq.heappop(self.queue)
            if event.time_ms > self.config.max_simulation_ms:
                self.now_ms = self.config.max_simulation_ms
                break
            self.now_ms = event.time_ms
            self._dispatch(event)

        if not self.decision_made:
            self.stop_reason = "simulation_timeout"
            self._clear_local_candidates()
            self._cancel_all_live_branches(except_path=set())

        cleanup_complete = not (
            self.live_branch_ids
            or self.offers
            or self.candidates
            or self.tentatives
            or self.pending_keys
            or self.active_keys
            or self.reassembler.live_messages
        )
        reassembly = self.reassembler.stats()
        return EventLifecycleResult(
            node_count=self.graph.node_count,
            edge_count=self.graph.edge_count(),
            success=self.success,
            stop_reason=self.stop_reason,
            selected_responder=self.selected_responder,
            selected_hop_count=self.selected_hop_count,
            selected_ring_index=self.selected_ring_index,
            setup_latency_ms=self.setup_latency_ms,
            rings_started=self.rings_started,
            candidates_received=self.candidates_received_count,
            unique_candidate_responders=len(self.candidate_responders),
            late_candidates=self.late_candidates,
            candidate_race_drops=self.candidate_race_drops,
            candidate_expiry_drops=self.candidate_expiry_drops,
            commit_failures=self.commit_failures,
            ready_failures=self.ready_failures,
            exact_replay_drops=self.exact_replay_drops,
            loss_drops=self.loss_drops,
            transmission_budget_drops=self.transmission_budget_drops,
            branch_capacity_drops=self.branch_capacity_drops,
            per_node_branch_drops=self.per_node_branch_drops,
            tentative_capacity_drops=self.tentative_capacity_drops,
            active_capacity_drops=self.active_capacity_drops,
            token_bucket_drops=self.token_bucket_drops,
            stale_parent_drops=self.stale_parent_drops,
            wire_auth_failures=self.wire_auth_failures,
            codec_failures=self.codec_failures,
            crypto_failures=self.crypto_failures,
            crypto_discover_transforms=self.crypto_discover_transforms,
            crypto_candidate_layers=self.crypto_candidate_layers,
            tagged_branches_created=self.tagged_branches_created,
            tag_observations=self.tag_observations,
            wire_bytes=(
                self.legitimate_transmissions + self.attack_transmissions
            ) * CELL_RECORD_BYTES if self.config.enable_crypto else 0,
            logical_messages_sent=self.logical_messages_sent,
            fragmented_messages_sent=self.fragmented_messages_sent,
            reassembly_completed=reassembly.completed,
            reassembly_duplicate_fragments=reassembly.duplicate_fragments,
            reassembly_timeouts=reassembly.expired_messages,
            reassembly_capacity_drops=reassembly.capacity_drops,
            reassembly_metadata_failures=reassembly.metadata_failures,
            peak_reassembly_messages=reassembly.peak_messages,
            peak_reassembly_reserved_bytes=reassembly.peak_reserved_bytes,
            final_reassembly_messages=self.reassembler.live_messages,
            legitimate_transmissions=self.legitimate_transmissions,
            attack_transmissions=self.attack_transmissions,
            total_transmissions=(
                self.legitimate_transmissions + self.attack_transmissions
            ),
            message_counts=tuple(sorted(self.message_counts.items())),
            legitimate_branch_allocations=self.legitimate_branch_allocations,
            attack_branch_allocations=self.attack_branch_allocations,
            peak_branch_state=self.peak_branch_state,
            peak_offer_state=self.peak_offer_state,
            peak_candidate_state=self.peak_candidate_state,
            peak_tentative_state=self.peak_tentative_state,
            peak_pending_state=self.peak_pending_state,
            peak_active_state=self.peak_active_state,
            final_branch_state=len(self.live_branch_ids),
            final_offer_state=len(self.offers),
            final_candidate_state=len(self.candidates),
            final_tentative_state=len(self.tentatives),
            final_pending_state=len(self.pending_keys),
            final_active_state=len(self.active_keys),
            cleanup_complete=cleanup_complete,
            completed_at_ms=self.now_ms,
        )

    def _dispatch(self, event: _ScheduledEvent) -> None:
        handlers = {
            "START_RING": self._handle_start_ring,
            "RING_CLOSE": self._handle_ring_close,
            "WIRE_CELL": self._handle_wire_cell,
            "REASSEMBLY_EXPIRE": self._handle_reassembly_expire,
            "DISCOVER": self._handle_discover,
            "BRANCH_EXPIRE": self._handle_branch_expire,
            "OFFER_READY": self._handle_offer_ready,
            "OFFER_EXPIRE": self._handle_offer_expire,
            "CANDIDATE": self._handle_candidate,
            "CANDIDATE_EXPIRE": self._handle_candidate_expire,
            "TENTATIVE_EXPIRE": self._handle_tentative_expire,
            "CANCEL": self._handle_cancel,
            "COMMIT": self._handle_commit,
            "READY": self._handle_ready,
            "ROUTE_SETUP_TIMEOUT": self._handle_route_setup_timeout,
            "ACTIVE_EXPIRE": self._handle_active_expire,
            "ATTACK_BURST": self._handle_attack_burst,
        }
        try:
            handler = handlers[event.kind]
        except KeyError as exc:  # pragma: no cover - internal programming error
            raise AssertionError(f"unknown event kind: {event.kind}") from exc
        handler(event.data)
        self._update_peaks()

    def _schedule_local(
        self,
        time_ms: int,
        priority: EventPriority,
        kind: str,
        data: dict[str, Any],
    ) -> None:
        self.sequence += 1
        heapq.heappush(
            self.queue,
            _ScheduledEvent(time_ms, int(priority), self.sequence, kind, data),
        )

    def _delay(self, message_type: str) -> int:
        if message_type == "DISCOVER":
            low = self.config.discover_delay_min_ms
            high = self.config.discover_delay_max_ms
        elif message_type == "CANDIDATE":
            low = self.config.candidate_delay_min_ms
            high = self.config.candidate_delay_max_ms
        else:
            low = self.config.control_delay_min_ms
            high = self.config.control_delay_max_ms
        return self.rng.randint(low, high)

    def _randbytes(self, length: int) -> bytes:
        return bytes(self.rng.getrandbits(8) for _ in range(length))

    def _token(self) -> bytes:
        while True:
            value = self._randbytes(16)
            if value != bytes(16):
                return value

    def _message_local_id(self) -> bytes:
        while True:
            value = self._token()
            if value not in self.used_w2_message_ids:
                self.used_w2_message_ids.add(value)
                return value

    def _scalar(self, label: bytes) -> bytes:
        return r255.scalar_from_label(
            self._randbytes(32),
            dst=b"Trahens-event-model/" + label,
        )

    def _make_discover_body(
        self,
        *,
        hop_remaining: int,
        fanout_class: int,
        reply_public_key: bytes,
        eligibility_capsule: URECiphertext,
        branch_token: bytes | None = None,
    ) -> bytes:
        return encode_discover(
            WireDiscoverRecord(
                branch_token=self._token() if branch_token is None else branch_token,
                hop_remaining=hop_remaining,
                fanout_class=fanout_class,
                expiry_class=1,
                options=0,
                reply_public_key=reply_public_key,
                eligibility_capsule=eligibility_capsule,
            )
        )

    def _make_candidate_body(
        self,
        *,
        candidate_blob: bytes,
        layer_count: int,
        candidate_token: bytes | None = None,
    ) -> bytes:
        return encode_candidate(
            WireCandidateRecord(
                candidate_token=(
                    self._token() if candidate_token is None else candidate_token
                ),
                expiry_class=1,
                layer_count=layer_count,
                candidate_blob=candidate_blob,
            )
        )

    def _make_control_body(
        self, message_type: str, data: dict[str, Any]
    ) -> bytes:
        type_map = {
            "COMMIT": MessageType.COMMIT,
            "READY": MessageType.READY,
            "CANCEL": MessageType.CANCEL,
        }
        protected = data.get("protected_body")
        if not isinstance(protected, bytes):
            stable = [
                (key, value)
                for key, value in sorted(data.items())
                if isinstance(value, (bool, int, str))
            ]
            protected = hashlib.sha256(repr(stable).encode("utf-8")).digest()
        generation = int(
            data.get("candidate_id", data.get("context_id", 0))
        ) & 0xFFFFFFFF
        return encode_control(
            WireControlRecord(
                message_type=type_map[message_type],
                local_label=self._token(),
                generation=generation,
                expiry_class=1,
                protected_body=protected,
            )
        )

    @staticmethod
    def _decoded_type(
        decoded: WireDiscoverRecord
        | WireCandidateRecord
        | WireControlRecord
        | MessageType,
    ) -> MessageType:
        if isinstance(decoded, WireDiscoverRecord):
            return MessageType.DISCOVER
        if isinstance(decoded, WireCandidateRecord):
            return MessageType.CANDIDATE
        if isinstance(decoded, WireControlRecord):
            return decoded.message_type
        return decoded

    def _handle_wire_cell(self, data: dict[str, Any]) -> None:
        encoded = data.get("wire_cell")
        if not isinstance(encoded, bytes):
            self.codec_failures += 1
            return
        try:
            key = derive_link_key(
                self.config.seed,
                int(data["sender"]),
                int(data["receiver"]),
            )
            _, _, body = open_link_cell(
                encoded,
                key=key,
                expected_epoch=1,
                expected_sequence=int(data["message_id"]),
            )
        except CodecError:
            self.wire_auth_failures += 1
            return
        # Do not advance the replay window for unauthenticated input. Otherwise
        # an attacker could inject a forged record with a future public sequence
        # and cause the valid record carrying that sequence to be discarded.
        if self._is_replay(data):
            return
        try:
            fragment = decode_cell(body)
        except CodecError:
            self.codec_failures += 1
            return

        scope = (int(data["sender"]), int(data["receiver"]))
        try:
            assembled = self.reassembler.accept(
                scope,
                fragment,
                now_ms=self.now_ms,
            )
        except CodecError:
            return
        self._schedule_local(
            self.now_ms + self.config.reassembly_timeout_ms,
            EventPriority.EXPIRY,
            "REASSEMBLY_EXPIRE",
            {},
        )
        if assembled is None:
            return
        try:
            decoded = decode_message(assembled)
        except CodecError:
            self.codec_failures += 1
            return

        expected_kind = str(data["logical_kind"])
        expected_type = {
            "DISCOVER": MessageType.DISCOVER,
            "CANDIDATE": MessageType.CANDIDATE,
            "COMMIT": MessageType.COMMIT,
            "READY": MessageType.READY,
            "CANCEL": MessageType.CANCEL,
        }[expected_kind]
        if self._decoded_type(decoded) is not expected_type:
            self.codec_failures += 1
            return

        logical_data = dict(data["logical_data"])
        logical_data.update(
            {
                "sender": int(data["sender"]),
                "receiver": int(data["receiver"]),
                "message_id": int(data["logical_message_serial"]),
                "legitimate": bool(data["legitimate"]),
                "message_type": expected_kind,
                "decoded_record": decoded,
                "_replay_checked": True,
            }
        )
        if (
            expected_kind == "DISCOVER"
            and self.config.active_tagging
            and int(data["receiver"]) in self.malicious_nodes
            and isinstance(decoded, WireDiscoverRecord)
            and matches_ratio_tag(decoded.eligibility_capsule, self.tag_scalar)
        ):
            self.tag_observations += 1
        self._schedule_local(
            self.now_ms,
            EventPriority(int(data["logical_priority"])),
            expected_kind,
            logical_data,
        )

    def _handle_reassembly_expire(self, data: dict[str, Any]) -> None:
        del data
        self.reassembler.expire(self.now_ms)

    def _send(
        self,
        message_type: str,
        *,
        sender: int,
        receiver: int,
        legitimate: bool,
        data: dict[str, Any],
        priority: EventPriority,
    ) -> bool:
        if receiver not in self.graph.neighbors(sender):
            raise AssertionError(
                f"non-adjacent simulated transmission: {sender} -> {receiver}"
            )

        logical_serial = self.next_logical_message_id
        self.next_logical_message_id += 1
        payload = dict(data)
        logical_message = payload.pop("logical_message", None)
        if not self.config.enable_crypto:
            if self._total_transmissions() >= self.config.transmission_budget:
                self.transmission_budget_drops += 1
                return False
            self.message_counts[message_type] += 1
            self.logical_messages_sent += 1
            self._account_cell(legitimate)
            if (
                message_type in self.config.forced_drop_types
                or self.rng.random() < self.config.loss_probability
            ):
                self.loss_drops += 1
                return True
            payload.update(
                {
                    "sender": sender,
                    "receiver": receiver,
                    "message_id": logical_serial,
                    "legitimate": legitimate,
                    "message_type": message_type,
                }
            )
            delivery_time = self.now_ms + self._delay(message_type)
            self._schedule_local(delivery_time, priority, message_type, payload)
            if self.rng.random() < self.config.duplicate_probability:
                if self._total_transmissions() < self.config.transmission_budget:
                    self._account_cell(legitimate)
                    self._schedule_local(
                        delivery_time + self._delay(message_type),
                        priority,
                        message_type,
                        dict(payload),
                    )
                else:
                    self.transmission_budget_drops += 1
            return True

        try:
            if logical_message is None:
                if message_type in {"DISCOVER", "CANDIDATE"}:
                    raise CodecError(
                        f"missing explicit {message_type} logical message"
                    )
                logical_message = self._make_control_body(message_type, payload)
            key = derive_link_key(self.config.seed, sender, receiver)
            first_sequence = self.next_message_id
            wire_cells = list(
                encode_to_link_cells(
                    logical_message,
                    key=key,
                    epoch=1,
                    first_sequence=first_sequence,
                    message_local_id=self._message_local_id(),
                    rng=self.rng,
                )
            )
        except CodecError:
            self.codec_failures += 1
            return False

        required_cells = len(wire_cells)
        if self._total_transmissions() + required_cells > self.config.transmission_budget:
            self.transmission_budget_drops += 1
            return False
        self.next_message_id += required_cells
        self.message_counts[message_type] += 1
        self.logical_messages_sent += 1
        if required_cells > 1:
            self.fragmented_messages_sent += 1

        for offset, wire_cell in enumerate(wire_cells):
            cell_sequence = first_sequence + offset
            if self.rng.random() < self.config.wire_tamper_probability:
                mutable = bytearray(wire_cell)
                mutable[20] ^= 0x01
                wire_cell = bytes(mutable)
            self._account_cell(legitimate)
            if (
                message_type in self.config.forced_drop_types
                or self.rng.random() < self.config.loss_probability
            ):
                self.loss_drops += 1
                continue
            cell_data = {
                "sender": sender,
                "receiver": receiver,
                "message_id": cell_sequence,
                "message_type": "WIRE_CELL",
                "legitimate": legitimate,
                "logical_kind": message_type,
                "logical_priority": int(priority),
                "logical_message_serial": logical_serial,
                "logical_data": payload,
                "wire_cell": wire_cell,
            }
            delivery_time = self.now_ms + self._delay(message_type)
            self._schedule_local(
                delivery_time,
                priority,
                "WIRE_CELL",
                cell_data,
            )

            if self.rng.random() < self.config.duplicate_probability:
                if self._total_transmissions() < self.config.transmission_budget:
                    self._account_cell(legitimate)
                    self._schedule_local(
                        delivery_time + self._delay(message_type),
                        priority,
                        "WIRE_CELL",
                        dict(cell_data),
                    )
                else:
                    self.transmission_budget_drops += 1
        return True

    def _account_cell(self, legitimate: bool) -> None:
        if legitimate:
            self.legitimate_transmissions += 1
        else:
            self.attack_transmissions += 1

    def _total_transmissions(self) -> int:
        return self.legitimate_transmissions + self.attack_transmissions

    def _is_replay(self, data: dict[str, Any]) -> bool:
        if data.get("_replay_checked"):
            return False
        key = (
            str(data["message_type"]),
            int(data["receiver"]),
            int(data["sender"]),
            int(data["message_id"]),
        )
        if key in self.replay_seen:
            self.exact_replay_drops += 1
            return True
        self.replay_seen.add(key)
        return False

    def _sample(self, values: Iterable[int], limit: int) -> list[int]:
        candidates = list(values)
        self.rng.shuffle(candidates)
        return candidates[: min(limit, len(candidates))]

    def _handle_start_ring(self, data: dict[str, Any]) -> None:
        if self.decision_made:
            return
        ring_index = int(data["ring"])
        if ring_index >= len(self.config.rings):
            return
        self.current_ring_index = ring_index
        self.rings_started += 1
        ring = self.config.rings[ring_index]
        children = self._sample(
            self.graph.neighbors(self.config.origin), ring.initial_fanout
        )
        for child in children:
            message_data: dict[str, Any] = {
                "parent_context_id": None,
                "ring_index": ring_index,
                "hop_count": 1,
                "hop_limit": ring.hop_limit,
                "relay_fanout": ring.relay_fanout,
                "reply_delta": None,
            }
            if self.config.enable_crypto:
                try:
                    root_secret = self._scalar(b"root-reply")
                    root_public = r255.scalarmult_base(root_secret)
                    capsule = ure_encrypt(
                        self.endpoint_keys.eligibility_public,
                        r0=self._scalar(b"ure-root-r0"),
                        r1=self._scalar(b"ure-root-r1"),
                    )
                    message_data["origin_reply_secret"] = root_secret
                    message_data["logical_message"] = self._make_discover_body(
                        hop_remaining=max(ring.hop_limit - 1, 0),
                        fanout_class=ring.relay_fanout,
                        reply_public_key=root_public,
                        eligibility_capsule=capsule,
                    )
                except (CryptoError, CodecError, r255.RistrettoError):
                    self.crypto_failures += 1
                    continue
            self._send(
                "DISCOVER",
                sender=self.config.origin,
                receiver=child,
                legitimate=True,
                data=message_data,
                priority=EventPriority.DISCOVER,
            )
        self._schedule_local(
            self.now_ms + ring.candidate_window_ms,
            EventPriority.WINDOW,
            "RING_CLOSE",
            {"ring": ring_index},
        )

    def _valid_candidates(self) -> list[_CandidateRecord]:
        return [
            candidate
            for candidate in self.candidates.values()
            if candidate.offer_expires_at_ms > self.now_ms
        ]

    def _handle_ring_close(self, data: dict[str, Any]) -> None:
        if self.decision_made:
            return
        ring_index = int(data["ring"])
        if ring_index != self.current_ring_index:
            return
        valid = self._valid_candidates()
        is_final = ring_index == len(self.config.rings) - 1
        if len(valid) >= self.config.required_candidates or (is_final and valid):
            self._select_candidate(valid)
            return
        if is_final:
            self.decision_made = True
            self.stop_reason = "no_candidate"
            self._clear_local_candidates()
            self._cancel_all_live_branches(except_path=set())
            return
        self._schedule_local(
            self.now_ms,
            EventPriority.WINDOW,
            "START_RING",
            {"ring": ring_index + 1},
        )

    def _select_candidate(self, candidates: list[_CandidateRecord]) -> None:
        candidate = min(
            candidates,
            key=lambda item: (
                item.hop_count,
                item.arrival_time_ms,
                item.responder,
                item.candidate_id,
            ),
        )
        self.decision_made = True
        self.selected_candidate_id = candidate.candidate_id
        self.selected_path_set = set(candidate.path_context_ids)
        self.selected_responder = candidate.responder
        self.selected_hop_count = candidate.hop_count
        self.selected_ring_index = candidate.ring_index
        self._clear_local_candidates(except_candidate_id=candidate.candidate_id)
        self.stop_reason = "route_setup_pending"
        self._cancel_all_live_branches(except_path=self.selected_path_set)
        self._schedule_local(
            self.now_ms + self.config.route_setup_timeout_ms,
            EventPriority.EXPIRY,
            "ROUTE_SETUP_TIMEOUT",
            {"candidate_id": candidate.candidate_id},
        )
        self._send_commit(candidate, path_index=0)

    def _handle_discover(self, data: dict[str, Any]) -> None:
        if self._is_replay(data):
            return
        legitimate = bool(data["legitimate"])
        if legitimate and self.decision_made:
            self.candidate_race_drops += 1
            return
        parent_id = data["parent_context_id"]
        if parent_id is not None:
            parent = self.branches.get(int(parent_id))
            if parent is None or parent.status != "live":
                self.stale_parent_drops += 1
                return
        receiver = int(data["receiver"])
        sender = int(data["sender"])
        if not self._take_peer_token(receiver, sender):
            self.token_bucket_drops += 1
            return
        if len(self.live_branch_ids) >= self.config.branch_capacity:
            self.branch_capacity_drops += 1
            return
        if self.contexts_per_node[receiver] >= self.config.per_node_branch_limit:
            self.per_node_branch_drops += 1
            return

        decoded: WireDiscoverRecord | None = None
        if self.config.enable_crypto:
            candidate = data.get("decoded_record")
            if not isinstance(candidate, WireDiscoverRecord):
                self.codec_failures += 1
                return
            decoded = candidate

        context_id = self.next_context_id
        self.next_context_id += 1
        context = _BranchContext(
            context_id=context_id,
            node=receiver,
            ingress_peer=sender,
            parent_context_id=(None if parent_id is None else int(parent_id)),
            ring_index=(
                None if data["ring_index"] is None else int(data["ring_index"])
            ),
            hop_count=int(data["hop_count"]),
            hop_limit=int(data["hop_limit"]),
            relay_fanout=int(data["relay_fanout"]),
            legitimate=legitimate,
            expires_at_ms=self.now_ms + self.config.branch_ttl_ms,
            branch_token=(b"" if decoded is None else decoded.branch_token),
            reply_public_key=(
                None if decoded is None else decoded.reply_public_key
            ),
            reply_delta=data.get("reply_delta"),
            eligibility_capsule=(
                None if decoded is None else decoded.eligibility_capsule
            ),
            root_reply_secret=data.get("origin_reply_secret"),
        )
        self.branches[context_id] = context
        self.live_branch_ids.add(context_id)
        self.contexts_per_node[receiver] += 1
        if legitimate:
            self.legitimate_branch_allocations += 1
        else:
            self.attack_branch_allocations += 1
        if context.parent_context_id is not None:
            self.branches[context.parent_context_id].child_context_ids.add(
                context_id
            )
        self._schedule_local(
            context.expires_at_ms,
            EventPriority.EXPIRY,
            "BRANCH_EXPIRE",
            {"context_id": context_id},
        )

        eligible = True
        if self.config.enable_crypto:
            if context.eligibility_capsule is None:
                eligible = False
            else:
                eligible = ure_is_eligible(
                    self.endpoint_keys.eligibility_secret,
                    context.eligibility_capsule,
                )
                if receiver in self.responders and not eligible:
                    self.crypto_failures += 1
        if (
            legitimate
            and eligible
            and receiver in self.responders
            and self.candidate_responses < self.config.candidate_response_limit
        ):
            self.candidate_responses += 1
            offer_delay = self.responder_offer_delays.get(receiver)
            if offer_delay is None:
                offer_delay = self.rng.randint(
                    self.config.responder_offer_delay_min_ms,
                    self.config.responder_offer_delay_max_ms,
                )
            if offer_delay < 0:
                raise ValueError("responder offer delay cannot be negative")
            self._schedule_local(
                self.now_ms + offer_delay,
                EventPriority.CANDIDATE,
                "OFFER_READY",
                {"context_id": context_id},
            )

        if context.hop_count >= context.hop_limit:
            return
        children = self._sample(
            (
                peer
                for peer in self.graph.neighbors(receiver)
                if peer != sender
            ),
            context.relay_fanout,
        )
        for child in children:
            child_data: dict[str, Any] = {
                "parent_context_id": context_id,
                "ring_index": context.ring_index,
                "hop_count": context.hop_count + 1,
                "hop_limit": context.hop_limit,
                "relay_fanout": context.relay_fanout,
            }
            if self.config.enable_crypto:
                if (
                    context.reply_public_key is None
                    or context.eligibility_capsule is None
                ):
                    self.crypto_failures += 1
                    continue
                try:
                    delta = self._scalar(b"reply-delta")
                    child_public = reply_tweak_public(
                        context.reply_public_key, delta
                    )
                    child_capsule = ure_rerandomize(
                        context.eligibility_capsule,
                        s0=self._scalar(b"ure-s0"),
                        s1=self._scalar(b"ure-s1"),
                    )
                    self.crypto_discover_transforms += 1
                    if (
                        self.config.active_tagging
                        and legitimate
                        and receiver in self.malicious_nodes
                    ):
                        child_capsule = apply_ratio_tag(
                            child_capsule, self.tag_scalar
                        )
                        self.tagged_branches_created += 1
                    child_data["reply_delta"] = delta
                    child_data["logical_message"] = self._make_discover_body(
                        hop_remaining=max(
                            context.hop_limit - (context.hop_count + 1), 0
                        ),
                        fanout_class=context.relay_fanout,
                        reply_public_key=child_public,
                        eligibility_capsule=child_capsule,
                    )
                except (CryptoError, CodecError, r255.RistrettoError):
                    self.crypto_failures += 1
                    continue
            self._send(
                "DISCOVER",
                sender=receiver,
                receiver=child,
                legitimate=legitimate,
                data=child_data,
                priority=EventPriority.DISCOVER,
            )

    def _take_peer_token(self, node: int, peer: int) -> bool:
        capacity = self.config.peer_bucket_capacity
        if capacity is None:
            return True
        key = (node, peer)
        bucket = self.buckets.get(key)
        if bucket is None:
            bucket = _TokenBucket(float(capacity), self.now_ms)
            self.buckets[key] = bucket
        elapsed = self.now_ms - bucket.last_time_ms
        if elapsed > 0:
            increments = elapsed // self.config.peer_bucket_refill_ms
            if increments:
                bucket.tokens = min(
                    float(capacity),
                    bucket.tokens
                    + increments * self.config.peer_bucket_refill_amount,
                )
                bucket.last_time_ms += (
                    increments * self.config.peer_bucket_refill_ms
                )
        if bucket.tokens < 1.0:
            return False
        bucket.tokens -= 1.0
        return True

    def _handle_branch_expire(self, data: dict[str, Any]) -> None:
        self._release_branch(int(data["context_id"]), "expired")

    def _release_branch(self, context_id: int, status: str) -> None:
        context = self.branches.get(context_id)
        if context is None or context.status != "live":
            return
        context.status = status
        self.live_branch_ids.discard(context_id)
        self.contexts_per_node[context.node] -= 1
        if self.contexts_per_node[context.node] <= 0:
            del self.contexts_per_node[context.node]

    def _path_for_context(self, context_id: int) -> tuple[int, ...]:
        path: list[int] = []
        cursor: int | None = context_id
        while cursor is not None:
            path.append(cursor)
            cursor = self.branches[cursor].parent_context_id
        path.reverse()
        return tuple(path)

    def _handle_offer_ready(self, data: dict[str, Any]) -> None:
        context_id = int(data["context_id"])
        context = self.branches.get(context_id)
        if context is None or context.status != "live":
            self.candidate_race_drops += 1
            return
        candidate_id = self.next_candidate_id
        self.next_candidate_id += 1
        path = self._path_for_context(context_id)
        offer_expires = self.now_ms + self.config.offer_ttl_ms
        commit_challenge = self._randbytes(32)
        self.offers[candidate_id] = (
            context.node,
            offer_expires,
            commit_challenge,
        )
        self._schedule_local(
            offer_expires,
            EventPriority.EXPIRY,
            "OFFER_EXPIRE",
            {"candidate_id": candidate_id},
        )

        candidate_blob: bytes | None = None
        layer_count = 1
        if self.config.enable_crypto:
            if context.reply_public_key is None:
                self.crypto_failures += 1
                return
            try:
                responder_payload = build_responder_payload(
                    self.endpoint_keys,
                    responder_id=context.node,
                    offer_expires_ms=offer_expires,
                    final_reply_public=context.reply_public_key,
                    commit_challenge=commit_challenge,
                    responder_nonce=self._randbytes(16),
                )
                candidate_blob = seal_responder_candidate(
                    context.reply_public_key,
                    responder_payload,
                    ephemeral_secret=self._scalar(b"candidate-responder-e"),
                )
                self.crypto_candidate_layers += 1
            except (CryptoError, r255.RistrettoError):
                self.crypto_failures += 1
                self.offers.pop(candidate_id, None)
                return

        if len(path) == 1:
            self._send_candidate_to_origin(
                candidate_id,
                responder=context.node,
                path=path,
                ring_index=int(context.ring_index or 0),
                offer_expires=offer_expires,
                candidate_blob=candidate_blob,
                layer_count=layer_count,
            )
            return
        parent_index = len(path) - 2
        parent_context = self.branches[path[parent_index]]
        message_data: dict[str, Any] = {
            "candidate_id": candidate_id,
            "responder": context.node,
            "path": path,
            "path_index": parent_index,
            "ring_index": int(context.ring_index or 0),
            "offer_expires": offer_expires,
            "layer_count": layer_count,
        }
        if self.config.enable_crypto:
            assert candidate_blob is not None
            message_data["candidate_blob"] = candidate_blob
            message_data["logical_message"] = self._make_candidate_body(
                candidate_blob=candidate_blob,
                layer_count=layer_count,
            )
        self._send(
            "CANDIDATE",
            sender=context.node,
            receiver=parent_context.node,
            legitimate=True,
            data=message_data,
            priority=EventPriority.CANDIDATE,
        )

    def _handle_offer_expire(self, data: dict[str, Any]) -> None:
        candidate_id = int(data["candidate_id"])
        offer = self.offers.get(candidate_id)
        if offer is not None and offer[1] <= self.now_ms:
            self.offers.pop(candidate_id, None)

    def _handle_candidate(self, data: dict[str, Any]) -> None:
        if self._is_replay(data):
            return
        candidate_id = int(data["candidate_id"])
        offer_expires = int(data["offer_expires"])
        if offer_expires <= self.now_ms:
            self.candidate_expiry_drops += 1
            return
        path = tuple(int(value) for value in data["path"])
        path_index = int(data["path_index"])
        if path_index < 0:
            self._accept_candidate_at_origin(data, path)
            return
        context_id = path[path_index]
        context = self.branches.get(context_id)
        if context is None or context.status != "live":
            self.candidate_race_drops += 1
            return
        key = (candidate_id, context_id)
        if key not in self.tentatives:
            if (
                len(self.tentatives) + len(self.pending_keys)
                >= self.config.tentative_capacity
            ):
                self.tentative_capacity_drops += 1
                return
            tentative = _TentativeState(
                candidate_id=candidate_id,
                context_id=context_id,
                node=context.node,
                expires_at_ms=self.now_ms + self.config.tentative_ttl_ms,
            )
            self.tentatives[key] = tentative
            self._schedule_local(
                tentative.expires_at_ms,
                EventPriority.EXPIRY,
                "TENTATIVE_EXPIRE",
                {"candidate_id": candidate_id, "context_id": context_id},
            )

        next_index = path_index - 1
        outgoing_blob: bytes | None = None
        outgoing_layers = int(data.get("layer_count", 1))
        if self.config.enable_crypto:
            decoded = data.get("decoded_record")
            if not isinstance(decoded, WireCandidateRecord):
                self.codec_failures += 1
                return
            if context.reply_public_key is None or path_index + 1 >= len(path):
                self.crypto_failures += 1
                return
            child_context = self.branches[path[path_index + 1]]
            if child_context.reply_delta is None:
                self.crypto_failures += 1
                return
            try:
                outgoing_blob = wrap_relay_candidate(
                    context.reply_public_key,
                    delta=child_context.reply_delta,
                    child_candidate_token=decoded.candidate_token,
                    forward_label=self._token(),
                    child_blob=decoded.candidate_blob,
                    ephemeral_secret=self._scalar(b"candidate-relay-e"),
                )
                outgoing_layers = decoded.layer_count + 1
                self.crypto_candidate_layers += 1
            except (CryptoError, CodecError, r255.RistrettoError):
                self.crypto_failures += 1
                return

        if next_index < 0:
            self._send_candidate_to_origin(
                candidate_id,
                responder=int(data["responder"]),
                path=path,
                ring_index=int(data["ring_index"]),
                offer_expires=offer_expires,
                sender=context.node,
                candidate_blob=outgoing_blob,
                layer_count=outgoing_layers,
            )
            return
        parent_context = self.branches[path[next_index]]
        message_data: dict[str, Any] = {
            "candidate_id": candidate_id,
            "responder": int(data["responder"]),
            "path": path,
            "path_index": next_index,
            "ring_index": int(data["ring_index"]),
            "offer_expires": offer_expires,
            "layer_count": outgoing_layers,
        }
        if self.config.enable_crypto:
            assert outgoing_blob is not None
            message_data["candidate_blob"] = outgoing_blob
            message_data["logical_message"] = self._make_candidate_body(
                candidate_blob=outgoing_blob,
                layer_count=outgoing_layers,
            )
        self._send(
            "CANDIDATE",
            sender=context.node,
            receiver=parent_context.node,
            legitimate=True,
            data=message_data,
            priority=EventPriority.CANDIDATE,
        )

    def _send_candidate_to_origin(
        self,
        candidate_id: int,
        *,
        responder: int,
        path: tuple[int, ...],
        ring_index: int,
        offer_expires: int,
        candidate_blob: bytes | None = None,
        layer_count: int = 1,
        sender: int | None = None,
    ) -> None:
        if sender is None:
            sender = self.branches[path[0]].node
        message_data: dict[str, Any] = {
            "candidate_id": candidate_id,
            "responder": responder,
            "path": path,
            "path_index": -1,
            "ring_index": ring_index,
            "offer_expires": offer_expires,
            "layer_count": layer_count,
        }
        if self.config.enable_crypto:
            if candidate_blob is None:
                self.crypto_failures += 1
                return
            message_data["candidate_blob"] = candidate_blob
            try:
                message_data["logical_message"] = self._make_candidate_body(
                    candidate_blob=candidate_blob,
                    layer_count=layer_count,
                )
            except CodecError:
                self.codec_failures += 1
                return
        self._send(
            "CANDIDATE",
            sender=sender,
            receiver=self.config.origin,
            legitimate=True,
            data=message_data,
            priority=EventPriority.CANDIDATE,
        )

    def _accept_candidate_at_origin(
        self, data: dict[str, Any], path: tuple[int, ...]
    ) -> None:
        candidate_id = int(data["candidate_id"])
        if self.decision_made:
            self.late_candidates += 1
            self._abort_candidate_path(candidate_id, path)
            return
        if len(self.candidates) >= self.config.candidate_limit:
            self._abort_candidate_path(candidate_id, path)
            return

        responder = int(data["responder"])
        offer_expires = int(data["offer_expires"])
        commit_challenge = b""
        if self.config.enable_crypto:
            decoded = data.get("decoded_record")
            root_context = self.branches.get(path[0]) if path else None
            if (
                not isinstance(decoded, WireCandidateRecord)
                or root_context is None
                or root_context.root_reply_secret is None
            ):
                self.crypto_failures += 1
                return
            try:
                opened = open_candidate_chain(
                    root_context.root_reply_secret,
                    decoded.candidate_blob,
                    expected_address=self.endpoint_keys.address,
                    expected_descriptor=self.endpoint_keys.descriptor,
                    max_layers=max(8, len(path) + 1),
                )
            except CryptoError:
                self.crypto_failures += 1
                return
            if opened.layer_count != decoded.layer_count:
                self.crypto_failures += 1
                return
            responder = opened.payload.responder_id
            offer_expires = opened.payload.offer_expires_ms
            commit_challenge = opened.payload.commit_challenge
            if offer_expires <= self.now_ms:
                self.candidate_expiry_drops += 1
                return

        candidate = _CandidateRecord(
            candidate_id=candidate_id,
            responder=responder,
            path_context_ids=path,
            ring_index=int(data["ring_index"]),
            hop_count=len(path),
            arrival_time_ms=self.now_ms,
            offer_expires_at_ms=offer_expires,
            commit_challenge=commit_challenge,
        )
        self.candidates[candidate_id] = candidate
        self.candidates_received_count += 1
        self.candidate_responders.add(responder)
        self._schedule_local(
            candidate.offer_expires_at_ms,
            EventPriority.EXPIRY,
            "CANDIDATE_EXPIRE",
            {"candidate_id": candidate_id},
        )

    def _handle_candidate_expire(self, data: dict[str, Any]) -> None:
        candidate_id = int(data["candidate_id"])
        candidate = self.candidates.get(candidate_id)
        if candidate is None or candidate.offer_expires_at_ms > self.now_ms:
            return
        if candidate_id == self.selected_candidate_id and not self.route_failed:
            # Once selected, responder acceptance and the route-setup deadline
            # determine the outcome; READY may legitimately arrive after the
            # original offer deadline if COMMIT was accepted before it.
            return
        self.candidates.pop(candidate_id, None)

    def _handle_tentative_expire(self, data: dict[str, Any]) -> None:
        key = (int(data["candidate_id"]), int(data["context_id"]))
        state = self.tentatives.get(key)
        if state is None:
            return
        # An earlier expiry event remains queued when COMMIT extends a
        # tentative mapping into PENDING_READY. Ignore that stale event until
        # the state's current half-open deadline is reached.
        if self.now_ms < state.expires_at_ms:
            return
        if state.status == "tentative":
            del self.tentatives[key]
        elif state.status == "pending":
            self.pending_keys.discard(key)
            del self.tentatives[key]

    def _cancel_all_live_branches(self, *, except_path: set[int]) -> None:
        # Cancel each maximal off-path subtree. For a selected route this means
        # all non-selected roots plus every branch that diverges from a selected
        # context. Descendants are then cancelled recursively by CANCEL.
        roots = [
            context
            for context in self.branches.values()
            if context.status == "live"
            and context.legitimate
            and context.context_id not in except_path
            and (
                context.parent_context_id is None
                or context.parent_context_id in except_path
            )
        ]
        for context in roots:
            sender = self.config.origin
            if context.parent_context_id is not None:
                sender = self.branches[context.parent_context_id].node
            self._send(
                "CANCEL",
                sender=sender,
                receiver=context.node,
                legitimate=True,
                data={"context_id": context.context_id, "except_path": except_path},
                priority=EventPriority.CANCEL,
            )

    def _handle_cancel(self, data: dict[str, Any]) -> None:
        if self._is_replay(data):
            return
        context_id = int(data["context_id"])
        except_path = set(int(value) for value in data["except_path"])
        if context_id in except_path:
            return
        context = self.branches.get(context_id)
        if context is None or context.status != "live":
            return
        self._release_branch(context_id, "cancelled")
        for key in [key for key in self.tentatives if key[1] == context_id]:
            self.pending_keys.discard(key)
            self.active_keys.discard(key)
            del self.tentatives[key]
        for child_id in tuple(context.child_context_ids):
            child = self.branches.get(child_id)
            if child is None or child.status != "live" or child_id in except_path:
                continue
            self._send(
                "CANCEL",
                sender=context.node,
                receiver=child.node,
                legitimate=True,
                data={"context_id": child_id, "except_path": except_path},
                priority=EventPriority.CANCEL,
            )

    def _abort_candidate_path(
        self, candidate_id: int, path: tuple[int, ...]
    ) -> None:
        del path
        # This is initiator-local disposal only. Relay tentative/pending state
        # and responder offers are reclaimed by delivered control messages or
        # by their independent local deadlines; the simulator does not perform
        # omniscient remote deletion.
        self.candidates.pop(candidate_id, None)

    def _clear_local_candidates(
        self, *, except_candidate_id: int | None = None
    ) -> None:
        for candidate_id in tuple(self.candidates):
            if candidate_id != except_candidate_id:
                self.candidates.pop(candidate_id, None)

    def _send_commit(self, candidate: _CandidateRecord, path_index: int) -> None:
        path = candidate.path_context_ids
        context = self.branches[path[path_index]]
        sender = (
            self.config.origin
            if path_index == 0
            else self.branches[path[path_index - 1]].node
        )
        message_data: dict[str, Any] = {
            "candidate_id": candidate.candidate_id,
            "path": path,
            "path_index": path_index,
        }
        if self.config.enable_crypto:
            try:
                message_data["protected_body"] = commit_proof(
                    candidate.commit_challenge, self.endpoint_keys.address
                )
            except CryptoError:
                self.crypto_failures += 1
                self._fail_selected_route("commit_crypto_failure")
                return
        self._send(
            "COMMIT",
            sender=sender,
            receiver=context.node,
            legitimate=True,
            data=message_data,
            priority=EventPriority.CONTROL,
        )

    def _handle_commit(self, data: dict[str, Any]) -> None:
        if self._is_replay(data):
            return
        candidate_id = int(data["candidate_id"])
        path = tuple(int(value) for value in data["path"])
        index = int(data["path_index"])
        if candidate_id != self.selected_candidate_id:
            return
        context_id = path[index]
        context = self.branches[context_id]
        is_responder = index == len(path) - 1
        if is_responder:
            offer = self.offers.get(candidate_id)
            if offer is None or offer[1] <= self.now_ms:
                self.commit_failures += 1
                self._fail_selected_route("commit_offer_expired")
                return
            if self.config.enable_crypto:
                decoded = data.get("decoded_record")
                if not isinstance(decoded, WireControlRecord):
                    self.codec_failures += 1
                    self._fail_selected_route("commit_codec_failure")
                    return
                expected = commit_proof(offer[2], self.endpoint_keys.address)
                if not hmac.compare_digest(decoded.protected_body, expected):
                    self.crypto_failures += 1
                    self.commit_failures += 1
                    self._fail_selected_route("commit_authentication_failed")
                    return
            self.offers.pop(candidate_id, None)
            self._send_ready(candidate_id, path, index)
            return

        key = (candidate_id, context_id)
        tentative = self.tentatives.get(key)
        if tentative is None or tentative.status != "tentative":
            self.commit_failures += 1
            self._fail_selected_route("commit_missing_tentative")
            return
        reserved = len(self.pending_keys) + len(self.active_keys)
        if reserved >= self.config.active_capacity:
            self.active_capacity_drops += 1
            self.commit_failures += 1
            self._fail_selected_route("active_capacity")
            return
        tentative.status = "pending"
        tentative.expires_at_ms = self.now_ms + self.config.ready_hold_ms
        self.pending_keys.add(key)
        self._schedule_local(
            tentative.expires_at_ms,
            EventPriority.EXPIRY,
            "TENTATIVE_EXPIRE",
            {"candidate_id": candidate_id, "context_id": context_id},
        )
        self._send_commit(
            self.candidates[candidate_id],
            path_index=index + 1,
        )

    def _send_ready(
        self, candidate_id: int, path: tuple[int, ...], path_index: int
    ) -> None:
        next_index = path_index - 1
        sender = self.branches[path[path_index]].node
        receiver = (
            self.config.origin
            if next_index < 0
            else self.branches[path[next_index]].node
        )
        message_data: dict[str, Any] = {
            "candidate_id": candidate_id,
            "path": path,
            "path_index": next_index,
        }
        if self.config.enable_crypto:
            candidate = self.candidates.get(candidate_id)
            if candidate is None:
                self.crypto_failures += 1
                self._fail_selected_route("ready_crypto_state_missing")
                return
            try:
                message_data["protected_body"] = ready_proof(
                    candidate.commit_challenge, self.endpoint_keys.address
                )
            except CryptoError:
                self.crypto_failures += 1
                self._fail_selected_route("ready_crypto_failure")
                return
        self._send(
            "READY",
            sender=sender,
            receiver=receiver,
            legitimate=True,
            data=message_data,
            priority=EventPriority.CONTROL,
        )

    def _handle_ready(self, data: dict[str, Any]) -> None:
        if self._is_replay(data):
            return
        candidate_id = int(data["candidate_id"])
        path = tuple(int(value) for value in data["path"])
        index = int(data["path_index"])
        if candidate_id != self.selected_candidate_id:
            return
        if index < 0:
            if self.config.enable_crypto:
                candidate = self.candidates.get(candidate_id)
                decoded = data.get("decoded_record")
                if candidate is None or not isinstance(decoded, WireControlRecord):
                    self.codec_failures += 1
                    self._fail_selected_route("ready_codec_failure")
                    return
                expected = ready_proof(
                    candidate.commit_challenge, self.endpoint_keys.address
                )
                if not hmac.compare_digest(decoded.protected_body, expected):
                    self.crypto_failures += 1
                    self.ready_failures += 1
                    self._fail_selected_route("ready_authentication_failed")
                    return
            self.success = True
            self.stop_reason = "ready"
            self.setup_latency_ms = self.now_ms
            self.offers.pop(candidate_id, None)
            self.candidates.pop(candidate_id, None)
            return
        context_id = path[index]
        key = (candidate_id, context_id)
        tentative = self.tentatives.get(key)
        if tentative is None or tentative.status != "pending":
            self.ready_failures += 1
            self._fail_selected_route("ready_missing_pending")
            return
        tentative.status = "active"
        self.pending_keys.discard(key)
        self.active_keys.add(key)
        self._schedule_local(
            self.now_ms + self.config.active_lifetime_ms,
            EventPriority.EXPIRY,
            "ACTIVE_EXPIRE",
            {"candidate_id": candidate_id, "context_id": context_id},
        )
        self._send_ready(candidate_id, path, index)

    def _handle_route_setup_timeout(self, data: dict[str, Any]) -> None:
        candidate_id = int(data["candidate_id"])
        if (
            self.success
            or self.route_failed
            or candidate_id != self.selected_candidate_id
        ):
            return
        self.ready_failures += 1
        self._fail_selected_route("route_setup_timeout")

    def _fail_selected_route(self, reason: str) -> None:
        if self.success or self.route_failed:
            return
        self.route_failed = True
        self.stop_reason = reason
        if self.selected_candidate_id is not None:
            candidate = self.candidates.get(self.selected_candidate_id)
            if candidate is not None:
                self._abort_candidate_path(
                    self.selected_candidate_id, candidate.path_context_ids
                )
            else:
                self.candidates.pop(self.selected_candidate_id, None)

    def _handle_active_expire(self, data: dict[str, Any]) -> None:
        key = (int(data["candidate_id"]), int(data["context_id"]))
        if key not in self.active_keys:
            return
        self.active_keys.remove(key)
        self.tentatives.pop(key, None)

    def _handle_attack_burst(self, data: dict[str, Any]) -> None:
        del data
        if not self.malicious_nodes or self.config.attack_branches_per_burst == 0:
            return
        for attacker in sorted(self.malicious_nodes):
            neighbors = self.graph.neighbors(attacker)
            if not neighbors:
                continue
            for _ in range(self.config.attack_branches_per_burst):
                receiver = neighbors[self.rng.randrange(len(neighbors))]
                message_data: dict[str, Any] = {
                    "parent_context_id": None,
                    "ring_index": None,
                    "hop_count": 1,
                    "hop_limit": self.config.attack_hop_limit,
                    "relay_fanout": self.config.attack_fanout,
                    "reply_delta": None,
                }
                if self.config.enable_crypto:
                    try:
                        public = r255.scalarmult_base(
                            self._scalar(b"attack-root-reply")
                        )
                        capsule = ure_encrypt(
                            self.endpoint_keys.eligibility_public,
                            r0=self._scalar(b"attack-ure-r0"),
                            r1=self._scalar(b"attack-ure-r1"),
                        )
                        message_data["logical_message"] = self._make_discover_body(
                            hop_remaining=max(self.config.attack_hop_limit - 1, 0),
                            fanout_class=self.config.attack_fanout,
                            reply_public_key=public,
                            eligibility_capsule=capsule,
                        )
                    except (CryptoError, CodecError, r255.RistrettoError):
                        self.crypto_failures += 1
                        continue
                self._send(
                    "DISCOVER",
                    sender=attacker,
                    receiver=receiver,
                    legitimate=False,
                    data=message_data,
                    priority=EventPriority.DISCOVER,
                )

    def _update_peaks(self) -> None:
        self.peak_branch_state = max(
            self.peak_branch_state, len(self.live_branch_ids)
        )
        self.peak_offer_state = max(self.peak_offer_state, len(self.offers))
        self.peak_candidate_state = max(
            self.peak_candidate_state, len(self.candidates)
        )
        tentative_count = sum(
            1 for state in self.tentatives.values() if state.status == "tentative"
        )
        self.peak_tentative_state = max(
            self.peak_tentative_state, tentative_count
        )
        self.peak_pending_state = max(
            self.peak_pending_state, len(self.pending_keys)
        )
        self.peak_active_state = max(
            self.peak_active_state, len(self.active_keys)
        )


def choose_malicious_nodes(
    graph: Graph,
    *,
    origin: int,
    malicious_fraction: float,
    seed: int,
) -> set[int]:
    if not 0.0 <= malicious_fraction <= 1.0:
        raise ValueError("malicious_fraction must be between 0 and 1")
    rng = random.Random(seed ^ 0x5A5A5A5A)
    return {
        node
        for node in range(graph.node_count)
        if node != origin and rng.random() < malicious_fraction
    }


def simulate_event_lifecycle(
    graph: Graph,
    config: EventLifecycleConfig,
    *,
    responders: set[int] | None = None,
    responder_offer_delays: dict[int, int] | None = None,
    malicious_nodes: set[int] | None = None,
) -> EventLifecycleResult:
    """Run one deterministic event-driven Core lifecycle simulation."""

    config.validate(graph)
    if responders is None:
        responders = choose_responders(
            graph,
            origin=config.origin,
            responder_fraction=config.responder_fraction,
            seed=config.seed,
        )
    invalid_responders = {
        node
        for node in responders
        if node < 0 or node >= graph.node_count or node == config.origin
    }
    if invalid_responders:
        raise ValueError(f"invalid responders: {sorted(invalid_responders)}")

    if malicious_nodes is None:
        malicious_nodes = choose_malicious_nodes(
            graph,
            origin=config.origin,
            malicious_fraction=config.malicious_fraction,
            seed=config.seed,
        )
    invalid_attackers = {
        node
        for node in malicious_nodes
        if node < 0 or node >= graph.node_count or node == config.origin
    }
    if invalid_attackers:
        raise ValueError(f"invalid malicious nodes: {sorted(invalid_attackers)}")

    simulator = _LifecycleSimulator(
        graph,
        config,
        responders=set(responders),
        responder_offer_delays=responder_offer_delays,
        malicious_nodes=set(malicious_nodes),
    )
    return simulator.run()


def parse_timed_ring_schedule(value: str) -> tuple[TimedRingStep, ...]:
    """Parse ``hop:fanout:window`` or ``hop:initial:relay:window`` rings."""

    rings: list[TimedRingStep] = []
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            continue
        fields = [int(field.strip()) for field in item.split(":")]
        if len(fields) == 3:
            hop_limit, fanout, window = fields
            rings.append(TimedRingStep(hop_limit, fanout, fanout, window))
        elif len(fields) == 4:
            hop_limit, initial, relay, window = fields
            rings.append(TimedRingStep(hop_limit, initial, relay, window))
        else:
            raise ValueError(
                "each timed ring must be hop:fanout:window or "
                "hop:initial_fanout:relay_fanout:window"
            )
    if not rings:
        raise ValueError("at least one timed ring is required")
    return tuple(rings)
