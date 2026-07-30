#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exhaustively test the literal finite-field tag reduction on small chains.

The checked equation is the one needed if ``mu(u) = u mod q`` is interpreted as
multiplicative from QR*_p to Z_q^*: mu(u v) = mu(u) mu(v).  Parameter triples
(q, p=2q+1, r=2p+1) are small Cunningham chains of the first kind.  This tool is
an arithmetic transcription check, not a cryptographic security analysis.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def cunningham_chains(limit: int) -> list[tuple[int, int, int]]:
    output: list[tuple[int, int, int]] = []
    for q in range(2, limit + 1):
        p = 2 * q + 1
        r = 2 * p + 1
        if is_prime(q) and is_prime(p) and is_prime(r):
            output.append((q, p, r))
    return output


def quadratic_residues(modulus: int) -> list[int]:
    return sorted({(value * value) % modulus for value in range(1, modulus)})


def audit_chain(q: int, p: int, r: int) -> dict[str, object]:
    residues = quadratic_residues(p)
    equations = 0
    failures = 0
    first_counterexample: dict[str, int] | None = None
    for u in residues:
        for v in residues:
            equations += 1
            product = (u * v) % p
            left = product % q
            right = ((u % q) * (v % q)) % q
            if left != right:
                failures += 1
                if first_counterexample is None:
                    first_counterexample = {
                        "u": u,
                        "v": v,
                        "product_mod_p": product,
                        "left_reduction": left,
                        "right_product": right,
                    }
    return {
        "q": q,
        "p": p,
        "r": r,
        "qr_p_size": len(residues),
        "equations_tested": equations,
        "failures": failures,
        "homomorphism_holds": failures == 0,
        "first_counterexample": first_counterexample,
    }


def build_report(limit: int, minimum_chains: int) -> dict[str, object]:
    chains = cunningham_chains(limit)
    if len(chains) < minimum_chains:
        raise ValueError(
            f"only {len(chains)} chains found below {limit}; need {minimum_chains}"
        )
    audits = [audit_chain(*chain) for chain in chains]
    nontrivial = [row for row in audits if row["q"] > 2]
    return {
        "tool": "c2_k2_exhaustive_check",
        "interpretation": "mu(u)=u mod q under ordinary QR*_p multiplication",
        "search_limit": limit,
        "chains_found": len(audits),
        "chains": audits,
        "all_nontrivial_chains_fail": bool(nontrivial)
        and all(not bool(row["homomorphism_holds"]) for row in nontrivial),
        "scope": (
            "Arithmetic check of the literal finite-field interpretation only; "
            "not a result about the generic Re-T-SPHF framework or a corrected instantiation."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--minimum-chains", type=int, default=4)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/c2-k2-small-chain-exhaustive.json"),
    )
    args = parser.parse_args()
    report = build_report(args.limit, args.minimum_chains)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        f"checked {report['chains_found']} Cunningham chains below {args.limit}; "
        f"all nontrivial chains fail={report['all_nontrivial_chains_fail']}"
    )


if __name__ == "__main__":
    main()
