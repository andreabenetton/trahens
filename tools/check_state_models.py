#!/usr/bin/env python3
"""Exhaustively check small R1 and E1 state spaces.

The checker is intentionally independent of the simulator runtime. It explores
all operations up to finite profile bounds and verifies safety invariants,
replay/expiry rejection, legal transitions, and complete cleanup reachability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

CAP_DOMAIN = b"Trahens-R1-capability-v1"


@dataclass(frozen=True, order=True)
class Registration:
    digest: bytes
    gateway: int
    endpoint: int
    created: int
    expiry: int


@dataclass(frozen=True)
class R1State:
    records: tuple[Registration, ...] = ()
    redeemed: frozenset[bytes] = frozenset()

    def register(self, token: bytes, gateway: int, endpoint: int, now: int, ttl: int) -> "R1State | None":
        digest = hashlib.sha256(CAP_DOMAIN + token).digest()
        if ttl < 1 or any(record.digest == digest and record.gateway == gateway for record in self.records):
            return None
        record = Registration(digest, gateway, endpoint, now, now + ttl)
        return R1State(tuple(sorted(self.records + (record,))), self.redeemed)

    def redeem(self, token: bytes, gateway: int, now: int) -> tuple["R1State", int | None]:
        digest = hashlib.sha256(CAP_DOMAIN + token).digest()
        selected = next(
            (
                record
                for record in self.records
                if record.digest == digest
                and record.gateway == gateway
                and record.created <= now < record.expiry
            ),
            None,
        )
        if selected is None:
            return self, None
        remaining = tuple(record for record in self.records if record != selected)
        return R1State(remaining, self.redeemed | {digest}), selected.endpoint

    def expire(self, now: int) -> "R1State":
        return R1State(tuple(record for record in self.records if now < record.expiry), self.redeemed)


class Phase(IntEnum):
    ABSENT = 0
    DISCOVERING = 1
    CANDIDATE = 2
    COMMITTED = 3
    READY = 4
    OPEN = 5


LEGAL = {
    Phase.ABSENT: (Phase.DISCOVERING,),
    Phase.DISCOVERING: (Phase.CANDIDATE, Phase.ABSENT),
    Phase.CANDIDATE: (Phase.COMMITTED, Phase.ABSENT),
    Phase.COMMITTED: (Phase.READY, Phase.ABSENT),
    Phase.READY: (Phase.OPEN, Phase.ABSENT),
    Phase.OPEN: (Phase.ABSENT,),
}


@dataclass(frozen=True)
class E1State:
    phases: tuple[Phase, ...]

    @property
    def allocated(self) -> int:
        return sum(phase is not Phase.ABSENT for phase in self.phases)

    def transition(self, route: int, target: Phase) -> "E1State | None":
        current = self.phases[route]
        if target not in LEGAL[current]:
            return None
        updated = list(self.phases)
        updated[route] = target
        return E1State(tuple(updated))


def check_r1(depth: int = 7) -> dict[str, int]:
    tokens = (b"A" * 32, b"B" * 32)
    initial = R1State()
    queue = deque([(initial, 0)])
    seen = {initial}
    transitions = 0
    redemptions = 0
    rejected_replays = 0
    rejected_wrong_gateway = 0
    rejected_expired = 0

    while queue:
        state, level = queue.popleft()
        assert len(state.records) <= 4
        assert len({(r.gateway, r.digest) for r in state.records}) == len(state.records)
        assert all(record.digest not in tokens for record in state.records)
        if level >= depth:
            continue

        successors: list[R1State] = []
        for token in tokens:
            for gateway in (0, 1):
                registered = state.register(token, gateway, endpoint=gateway + 10, now=0, ttl=2)
                if registered is not None:
                    successors.append(registered)
                for now in (0, 1, 2, 3):
                    result, endpoint = state.redeem(token, gateway, now)
                    if endpoint is not None:
                        redemptions += 1
                        digest = hashlib.sha256(CAP_DOMAIN + token).digest()
                        replay_state, replay_endpoint = result.redeem(token, gateway, now)
                        assert replay_state == result and replay_endpoint is None
                        assert digest in result.redeemed
                        rejected_replays += 1
                    else:
                        matching = [r for r in state.records if r.digest == hashlib.sha256(CAP_DOMAIN + token).digest()]
                        if matching and all(r.gateway != gateway for r in matching):
                            rejected_wrong_gateway += 1
                        if matching and all(now >= r.expiry for r in matching):
                            rejected_expired += 1
                    successors.append(result)
        for now in (0, 1, 2, 3):
            successors.append(state.expire(now))
        for successor in successors:
            transitions += 1
            if successor not in seen:
                seen.add(successor)
                queue.append((successor, level + 1))

    assert redemptions > 0
    assert rejected_replays > 0
    assert rejected_wrong_gateway > 0
    assert rejected_expired > 0
    return {
        "states": len(seen),
        "transitions": transitions,
        "successful_redemptions": redemptions,
        "replay_rejections_checked": rejected_replays,
        "wrong_gateway_rejections_observed": rejected_wrong_gateway,
        "expiry_rejections_observed": rejected_expired,
    }


def check_e1(routes: int = 2) -> dict[str, int]:
    initial = E1State((Phase.ABSENT,) * routes)
    queue = deque([initial])
    seen = {initial}
    transitions = 0
    illegal_rejections = 0

    while queue:
        state = queue.popleft()
        assert state.allocated <= routes
        for index, phase in enumerate(state.phases):
            assert (phase is not Phase.ABSENT) == (phase.value > 0)
            if phase is Phase.OPEN:
                assert state.allocated > 0
            for target in Phase:
                successor = state.transition(index, target)
                if target not in LEGAL[phase]:
                    assert successor is None
                    illegal_rejections += 1
                    continue
                assert successor is not None
                transitions += 1
                if successor not in seen:
                    seen.add(successor)
                    queue.append(successor)

    all_absent = E1State((Phase.ABSENT,) * routes)
    for state in seen:
        cleaned = state
        for index, phase in enumerate(cleaned.phases):
            if phase is not Phase.ABSENT:
                next_state = cleaned.transition(index, Phase.ABSENT)
                assert next_state is not None
                cleaned = next_state
        assert cleaned == all_absent

    return {
        "states": len(seen),
        "transitions": transitions,
        "illegal_transitions_rejected": illegal_rejections,
        "cleanup_reachability_checked": len(seen),
    }


def build_report() -> dict[str, object]:
    return {
        "profile": "Trahens v1.5 bounded state models",
        "r1": check_r1(),
        "e1": check_e1(),
        "claim_boundary": "finite exhaustive safety check; not an unbounded symbolic proof",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
