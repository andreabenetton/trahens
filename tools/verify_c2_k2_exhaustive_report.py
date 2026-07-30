#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded integrity verifier for the tracked historical C2 exhaustive report.

The full 5,000-chain-limit reproduction evaluates more than 115 million ordered
pairs and remains available through ``make c2-k2-exhaustive`` and
``make reproduce``. Routine CI verifies the parameter search, canonical report
shape, every first counterexample, exact counts for the smaller chains, and
deterministic samples for the larger chains without repeating that full sweep.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from c2_k2_exhaustive_check import audit_chain, cunningham_chains, quadratic_residues


EXACT_Q_LIMIT = 509
SAMPLE_COUNT = 64


def _first_counterexample(q: int, p: int) -> dict[str, int] | None:
    residues = quadratic_residues(p)
    for u in residues:
        for v in residues:
            product = (u * v) % p
            left = product % q
            right = ((u % q) * (v % q)) % q
            if left != right:
                return {
                    "u": u,
                    "v": v,
                    "product_mod_p": product,
                    "left_reduction": left,
                    "right_product": right,
                }
    return None


def _sample_large_chain(q: int, p: int, failures: int) -> None:
    residues = quadratic_residues(p)
    if len(residues) != q:
        raise ValueError(f"unexpected QR size for q={q}")
    observed_failure = False
    state = (q << 17) ^ p ^ 0x5A17
    for _ in range(SAMPLE_COUNT):
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        u = residues[state % q]
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        v = residues[state % q]
        left = ((u * v) % p) % q
        right = ((u % q) * (v % q)) % q
        observed_failure |= left != right
    if failures > 0 and not observed_failure:
        raise ValueError(f"large-chain sample found no reported failure for q={q}")


def verify_report(path: Path) -> dict[str, object]:
    raw = path.read_text()
    report = json.loads(raw)
    canonical = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if raw != canonical:
        raise ValueError("report is not canonical sorted JSON")

    if report.get("tool") != "c2_k2_exhaustive_check":
        raise ValueError("unexpected tool identifier")
    limit = report.get("search_limit")
    if not isinstance(limit, int) or limit <= 0:
        raise ValueError("invalid search limit")

    expected_chains = cunningham_chains(limit)
    rows = report.get("chains")
    if not isinstance(rows, list):
        raise ValueError("chains must be a list")
    if report.get("chains_found") != len(expected_chains) or len(rows) != len(expected_chains):
        raise ValueError("chain count does not match a fresh parameter search")

    for row, (q, p, r) in zip(rows, expected_chains, strict=True):
        if (row.get("q"), row.get("p"), row.get("r")) != (q, p, r):
            raise ValueError(f"chain tuple mismatch for q={q}")
        if row.get("qr_p_size") != q or row.get("equations_tested") != q * q:
            raise ValueError(f"size accounting mismatch for q={q}")
        failures = row.get("failures")
        if not isinstance(failures, int) or not 0 <= failures <= q * q:
            raise ValueError(f"invalid failure count for q={q}")
        if row.get("homomorphism_holds") != (failures == 0):
            raise ValueError(f"homomorphism flag mismatch for q={q}")

        first = _first_counterexample(q, p)
        if row.get("first_counterexample") != first:
            raise ValueError(f"first counterexample mismatch for q={q}")

        if q <= EXACT_Q_LIMIT:
            exact = audit_chain(q, p, r)
            if row != exact:
                raise ValueError(f"exact small-chain audit mismatch for q={q}")
        else:
            _sample_large_chain(q, p, failures)

    nontrivial = [row for row in rows if row["q"] > 2]
    expected_all_fail = bool(nontrivial) and all(not row["homomorphism_holds"] for row in nontrivial)
    if report.get("all_nontrivial_chains_fail") != expected_all_fail:
        raise ValueError("aggregate failure flag mismatch")

    return {
        "chains_verified": len(rows),
        "exact_chains": sum(1 for row in rows if row["q"] <= EXACT_Q_LIMIT),
        "sampled_chains": sum(1 for row in rows if row["q"] > EXACT_Q_LIMIT),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "report",
        type=Path,
        nargs="?",
        default=Path("reports/c2-k2-small-chain-exhaustive.json"),
    )
    args = parser.parse_args()
    result = verify_report(args.report)
    print(
        "verified C2 exhaustive report: "
        f"{result['chains_verified']} chains "
        f"({result['exact_chains']} exact, {result['sampled_chains']} sampled)"
    )


if __name__ == "__main__":
    main()
