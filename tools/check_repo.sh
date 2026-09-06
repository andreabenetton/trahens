#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

required_files="
README.md
ROADMAP.md
docs/strategy.md
docs/citation-audit.md
docs/threat-model.md
docs/adr/0008-branch-local-unlinkable-contexts.md
docs/adr/0009-blinded-reply-key-chain.md
docs/adr/0010-rerandomizable-eligibility-capsule.md
docs/adr/0011-explicit-event-time.md
docs/adr/0012-ready-gated-route-activation.md
docs/adr/0013-ingress-peer-token-buckets.md
docs/adr/0014-concrete-c1-cryptographic-profile.md
docs/adr/0015-generic-cryptographic-failure.md
docs/adr/0016-fixed-size-w1-wire-record.md
docs/adr/0017-active-tagging-claim-boundary.md
docs/adr/0018-integrate-crypto-codec-lifecycle.md
docs/adr/0019-variable-m1-messages-fixed-w2-cells.md
docs/adr/0020-bounded-w2-reassembly.md
docs/adr/0021-c2-anonymous-rerandomizable-rcca-eligibility.md
docs/adr/0022-suite-agile-m2-envelope.md
docs/adr/0023-c2-k2-transcription-audit.md
docs/adr/0024-adopt-r1-rendezvous-capability.md
docs/adr/0025-hop-local-selective-recovery.md
docs/adr/0026-fixed-schedule-and-chaff.md
docs/adr/0027-quantized-adaptive-schedule.md
docs/adr/0028-weighted-drr-overload.md
docs/adr/0029-equal-budget-traffic-analysis.md
docs/adr/0030-multilink-classifier-and-active-probe.md
docs/adr/0031-packet-level-emulation-and-clock-model.md
docs/adr/0032-open-world-churn-and-selective-delay.md
docs/adr/0033-independent-review-remediation.md
docs/adr/0034-machine-readable-protocol-registry.md
docs/adr/0035-reply-key-commitment.md
docs/adr/0036-reply-path-post-quantum-redesign.md
docs/adr/0037-p1-user-space-prototype.md
docs/review-remediation-v1.5.md
docs/crypto-review/reply-key-privacy-v1.5.md
formal/R1Capability.tla
formal/E1Lifecycle.tla
formal/B1Rekey.tla
spec/core-v1.5.md
spec/messages-v1.5.md
spec/state-machines-v1.5.md
spec/invariants-v1.5.md
spec/resource-accounting-v1.5.md
spec/p1-prototype-profile-v1.5.md
spec/protocol-registry-v1.5.json
spec/protocol-registry-v1.5.md
spec/p1-conformance-vectors-v1.5.json
spec/p1-conformance-corpus-v1.5.bin
spec/protocol-registry-v1.6.json
spec/protocol-registry-v1.6.md
spec/p1-conformance-vectors-v1.6.json
spec/p1-conformance-corpus-v1.6.bin
spec/core-v1.7.md
spec/messages-v1.7.md
spec/state-machines-v1.7.md
spec/invariants-v1.7.md
spec/resource-accounting-v1.7.md
spec/p1-prototype-profile-v1.7.md
spec/protocol-registry-v1.7.json
spec/protocol-registry-v1.7.md
spec/p1-conformance-vectors-v1.7.json
spec/p1-conformance-corpus-v1.7.bin
spec/protocol-registry-v1.8.json
spec/protocol-registry-v1.8.md
spec/core-v1.8.md
spec/messages-v1.8.md
spec/state-machines-v1.8.md
spec/invariants-v1.8.md
spec/resource-accounting-v1.8.md
spec/p1-prototype-profile-v1.8.md
spec/p1-conformance-vectors-v1.8.json
spec/p1-conformance-corpus-v1.8.bin
spec/link-handshake-b1.md
spec/b1-test-vectors.json
simulator/trahens_crypto/b1.py
simulator/tests/test_b1_handshake.py
tools/generate_b1_vectors.py
spec/route-channel-test-vectors.json
simulator/trahens_crypto/route.py
simulator/tests/test_route_channel.py
tools/generate_route_vectors.py
reports/v1.5-bounded-state-models.json
reports/v1.5-t3-anonymity-metrics.json
simulator/trahens_spec/generated.py
simulator/trahens_sim/anonymity_metrics.py
simulator/tests/test_protocol_registry.py
simulator/tests/test_p1_conformance_vectors.py
simulator/tests/test_state_models.py
simulator/tests/test_anonymity_metrics.py
tools/generate_protocol_registry.py
tools/generate_p1_conformance.py
tools/check_state_models.py
tools/generate_anonymity_metrics.py
tools/check_pcap_cells.py
tools/summarize_p1_run.py
implementation/rust/Cargo.toml
implementation/rust/crates/protocol-registry/src/generated.rs
implementation/rust/crates/codec-m2/src/lib.rs
implementation/rust/crates/wire-w2/src/lib.rs
implementation/rust/crates/transport-t1/src/lib.rs
implementation/rust/crates/scheduling-t2/src/lib.rs
implementation/rust/crates/state-machine/src/lib.rs
implementation/rust/crates/rendezvous-r1/src/lib.rs
implementation/rust/crates/node-runtime/src/lib.rs
implementation/rust/crates/node-runtime/src/p1.rs
implementation/rust/crates/conformance/src/lib.rs
implementation/rust/bins/trahens-endpoint/src/main.rs
implementation/rust/bins/trahens-relay/src/main.rs
implementation/rust/bins/trahens-rendezvous/src/main.rs
implementation/rust/fuzz/Cargo.toml
implementation/rust/fuzz/fuzz_targets/m2.rs
implementation/rust/fuzz/fuzz_targets/w2.rs
implementation/harness/netns-p1.sh
implementation/harness/netns-restart.sh
implementation/rust/bins/trahens-hostile/src/main.rs
tools/w2_epochs.py
tools/b1_records.py
tools/registry_limit.py
docs/external-review-2026-07-30.md
docs/external-review-2026-09-04.md
docs/review-verification-2026-09-04.md
docs/review-remediation-v1.4.1.md
docs/review-remediation-v1.7.md
docs/review-remediation-v1.8.md
docs/development-record.md
docs/crypto-review/reply-path-security.md
spec/core-v1.4.1.md
spec/eligibility-suite-interface-v1.md
spec/rendezvous-capability-r1.md
spec/unlinkability-profile-u1.md
spec/event-lifecycle-profile-e1.md
spec/crypto-profile-c1.md
spec/crypto-profile-c2.md
spec/crypto-profile-c2-k2.md
spec/active-unlinkability-games-c2.md
spec/crypto-transcript-v0.2.md
spec/crypto-test-vectors-c1.json
spec/crypto-test-vectors-c2-symbolic.json
spec/r1-test-vectors.json
spec/t1-test-vectors.json
spec/t2-test-vectors.json
spec/t3-test-vectors.json
spec/t4-test-vectors.json
spec/message-codec-m2.md
spec/wire-cell-w2.md
spec/active-tagging-analysis.md
spec/transport-profile-t1.md
spec/transport-profile-t2.md
spec/transport-profile-t3.md
spec/transport-profile-t4.md
spec/messages-v1.4.1.md
spec/state-machines-v1.4.1.md
spec/invariants-v1.4.1.md
spec/resource-accounting-v1.4.1.md
spec/private-directory-d1.md
simulator/trahens_crypto/ristretto.py
simulator/trahens_crypto/c1.py
simulator/trahens_crypto/c2_ideal.py
simulator/trahens_crypto/c2_klinear.py
simulator/trahens_crypto/candidate.py
tools/vector_crypto_support.py
tools/vector_candidate_support.py
simulator/trahens_crypto/tagging.py
simulator/trahens_crypto/eligibility.py
simulator/trahens_codec/m2w2.py
simulator/trahens_codec/t1.py
simulator/trahens_codec/t2.py
simulator/tests/test_crypto_c1.py
simulator/tests/test_crypto_c2_ideal.py
simulator/tests/test_crypto_c2_vectors.py
simulator/tests/test_crypto_c2_klinear.py
simulator/tests/test_message_cell_codec_m2.py
simulator/tests/test_candidate_chain.py
simulator/tests/test_active_tagging.py
simulator/tests/test_event_model.py
simulator/tests/test_t1_codec.py
simulator/tests/test_t1_model.py
simulator/tests/test_t2_codec.py
simulator/tests/test_t2_model.py
simulator/tests/test_t3_model.py
simulator/tests/test_t4_model.py
simulator/tests/test_eligibility_providers.py
simulator/trahens_sim/fragmentation_compare.py
simulator/trahens_sim/c2_compare.py
simulator/trahens_sim/t1_model.py
simulator/trahens_sim/t1_compare.py
simulator/trahens_sim/t2_model.py
simulator/trahens_sim/t2_compare.py
simulator/trahens_sim/t3_model.py
simulator/trahens_sim/t3_compare.py
simulator/trahens_sim/t4_model.py
simulator/trahens_sim/t4_compare.py
tools/generate_crypto_vectors.py
tools/generate_c2_symbolic_vectors.py
tools/generate_c2_k2_audit.py
tools/generate_r1_vectors.py
tools/generate_t1_vectors.py
tools/generate_t2_vectors.py
tools/generate_t3_vectors.py
tools/generate_t4_vectors.py
tools/c2_k2_exhaustive_check.py
tools/verify_c2_k2_exhaustive_report.py
tools/run_r1_comparison.sh
tools/run_fragmentation_comparison.sh
tools/run_c2_comparison.sh
tools/run_t1_comparison.sh
tools/run_t2_comparison.sh
tools/run_t3_comparison.sh
tools/run_t4_comparison.sh
paper/legacy/trahens-2020.tex
paper/legacy/trahens-2020.pdf
paper/rewrite/main.tex
reports/iteration-0004-unlinkability-comparison.csv
reports/iteration-0005-lifecycle-comparison.csv
reports/iteration-0006-crypto-conformance.json
reports/iteration-0007-wire-tagging-comparison.csv
reports/iteration-0008-message-cell-capacity.csv
reports/iteration-0008-lifecycle-fragmentation.csv
reports/iteration-0009-c2-active-security.csv
reports/c2-k2-transcription-audit.json
reports/c2-k2-small-chain-exhaustive.json
reports/iteration-0011-r1-gate-b.csv
reports/iteration-0012-t1-reliability.csv
reports/iteration-0012-t1-trace-equivalence.csv
reports/iteration-0013-t2-congestion.csv
reports/iteration-0013-t2-schedule-leakage.csv
reports/iteration-0013-t2-burst-loss.csv
reports/iteration-0013-t2-multilink-correlation.csv
reports/iteration-0014-t3-route-classification.csv
reports/iteration-0014-t3-active-probing.csv
reports/iteration-0014-t3-equal-budget.csv
reports/iteration-0015-t4-open-world.csv
reports/iteration-0015-t4-packet-emulation.csv
reports/iteration-0015-t4-selective-delay.csv
docs/review-log/iteration-0006.md
docs/review-log/iteration-0007.md
docs/review-log/iteration-0008.md
docs/review-log/iteration-0009.md
docs/review-log/iteration-0010.md
docs/review-log/iteration-0011.md
docs/review-log/iteration-0012.md
docs/review-log/iteration-0013.md
docs/review-log/iteration-0014.md
docs/review-log/iteration-0015.md
docs/crypto-review/c2-author-query.md
docs/crypto-review/alternative-primitive-assessment.md
"

for path in $required_files; do
    if [ ! -f "$path" ]; then
        echo "missing required file: $path" >&2
        exit 1
    fi
done

# The exhaustive C2 report is cited by the review material and must exist in a
# fresh clone, not only in a maintainer's working tree.
git ls-files --error-unmatch reports/c2-k2-small-chain-exhaustive.json >/dev/null

python -m compileall -q simulator
PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v

vectors_tmp=$(mktemp)
r1_vectors_tmp=$(mktemp)
c2_vectors_tmp=$(mktemp)
c2_k2_tmp=$(mktemp)
t1_vectors_tmp=$(mktemp)
t2_vectors_tmp=$(mktemp)
t3_vectors_tmp=$(mktemp)
t4_vectors_tmp=$(mktemp)
registry_py_tmp=$(mktemp)
registry_rs_tmp=$(mktemp)
registry_md_tmp=$(mktemp)
p1_vectors_tmp=$(mktemp)
p1_corpus_tmp=$(mktemp)
state_models_tmp=$(mktemp)
anonymity_tmp=$(mktemp)
trap 'rm -f "$vectors_tmp" "$r1_vectors_tmp" "$c2_vectors_tmp" "$c2_k2_tmp" "$t1_vectors_tmp" "$t2_vectors_tmp" "$t3_vectors_tmp" "$t4_vectors_tmp" "$registry_py_tmp" "$registry_rs_tmp" "$registry_md_tmp" "$p1_vectors_tmp" "$p1_corpus_tmp" "$state_models_tmp" "$anonymity_tmp" /tmp/trahens-r1-smoke.csv /tmp/trahens-expanding-smoke.json /tmp/trahens-u1-smoke.csv /tmp/trahens-e1-smoke.csv /tmp/trahens-tag-smoke.csv /tmp/trahens-m1w2-capacity.csv /tmp/trahens-m1w2-life.csv /tmp/trahens-c2-smoke.csv /tmp/trahens-t1-smoke.csv /tmp/trahens-t1-trace-smoke.csv /tmp/trahens-t2-congestion-smoke.csv /tmp/trahens-t2-leak-smoke.csv /tmp/trahens-t2-burst-smoke.csv /tmp/trahens-t2-correlation-smoke.csv /tmp/trahens-t3-class-smoke.csv /tmp/trahens-t3-probe-smoke.csv /tmp/trahens-t3-budget-smoke.csv /tmp/trahens-t4-open-smoke.csv /tmp/trahens-t4-packet-smoke.csv /tmp/trahens-t4-probe-smoke.csv' EXIT
PYTHONPATH=simulator python tools/generate_crypto_vectors.py --output "$vectors_tmp"
cmp spec/crypto-test-vectors-c1.json "$vectors_tmp"
python tools/generate_protocol_registry.py \
    --python-output "$registry_py_tmp" \
    --rust-output "$registry_rs_tmp" \
    --markdown-output "$registry_md_tmp"
cmp simulator/trahens_spec/generated.py "$registry_py_tmp"
cmp implementation/rust/crates/protocol-registry/src/generated.rs "$registry_rs_tmp"
cmp spec/protocol-registry-v1.8.md "$registry_md_tmp"
# v1.5, v1.6 and v1.7 are retained and must still regenerate from their own
# registries, so each frozen profile stays reproducible even though the
# binaries target v1.8.
registry_md_old_tmp=$(mktemp)
for retired_series in 1.5 1.6 1.7; do
    python tools/generate_protocol_registry.py \
        --registry "spec/protocol-registry-v$retired_series.json" \
        --markdown-output "$registry_md_old_tmp"
    cmp "spec/protocol-registry-v$retired_series.md" "$registry_md_old_tmp"
done
rm -f "$registry_md_old_tmp"
python tools/generate_p1_conformance.py \
    --json-output "$p1_vectors_tmp" \
    --corpus-output "$p1_corpus_tmp"
cmp spec/p1-conformance-vectors-v1.8.json "$p1_vectors_tmp"
cmp spec/p1-conformance-corpus-v1.8.bin "$p1_corpus_tmp"
# v1.5, v1.6 and v1.7 are retained and must still regenerate from their own
# registries.
p1_vectors_old_tmp=$(mktemp)
p1_corpus_old_tmp=$(mktemp)
for retired_series in 1.5 1.6 1.7; do
    python tools/generate_p1_conformance.py \
        --registry "spec/protocol-registry-v$retired_series.json" \
        --json-output "$p1_vectors_old_tmp" \
        --corpus-output "$p1_corpus_old_tmp"
    cmp "spec/p1-conformance-vectors-v$retired_series.json" "$p1_vectors_old_tmp"
    cmp "spec/p1-conformance-corpus-v$retired_series.bin" "$p1_corpus_old_tmp"
done
rm -f "$p1_vectors_old_tmp" "$p1_corpus_old_tmp"
python tools/check_state_models.py --output "$state_models_tmp"
cmp reports/v1.5-bounded-state-models.json "$state_models_tmp"
PYTHONPATH=simulator python tools/generate_anonymity_metrics.py --output "$anonymity_tmp"
cmp reports/v1.5-t3-anonymity-metrics.json "$anonymity_tmp"
PYTHONPATH=simulator python tools/generate_r1_vectors.py --output "$r1_vectors_tmp"
cmp spec/r1-test-vectors.json "$r1_vectors_tmp"
b1_vectors_tmp=$(mktemp)
PYTHONPATH=simulator python tools/generate_b1_vectors.py --output "$b1_vectors_tmp"
cmp spec/b1-test-vectors.json "$b1_vectors_tmp"
rm -f "$b1_vectors_tmp"
route_vectors_tmp=$(mktemp)
PYTHONPATH=simulator python tools/generate_route_vectors.py --output "$route_vectors_tmp"
cmp spec/route-channel-test-vectors.json "$route_vectors_tmp"
rm -f "$route_vectors_tmp"
PYTHONPATH=simulator python tools/generate_t1_vectors.py --output "$t1_vectors_tmp"
cmp spec/t1-test-vectors.json "$t1_vectors_tmp"
PYTHONPATH=simulator python tools/generate_t2_vectors.py --output "$t2_vectors_tmp"
cmp spec/t2-test-vectors.json "$t2_vectors_tmp"
PYTHONPATH=simulator python tools/generate_t3_vectors.py --output "$t3_vectors_tmp"
cmp spec/t3-test-vectors.json "$t3_vectors_tmp"
PYTHONPATH=simulator python tools/generate_t4_vectors.py --output "$t4_vectors_tmp"
cmp spec/t4-test-vectors.json "$t4_vectors_tmp"
PYTHONPATH=simulator python tools/generate_c2_symbolic_vectors.py --output "$c2_vectors_tmp"
cmp spec/crypto-test-vectors-c2-symbolic.json "$c2_vectors_tmp"
PYTHONPATH=simulator python tools/generate_c2_k2_audit.py --output "$c2_k2_tmp"
cmp reports/c2-k2-transcription-audit.json "$c2_k2_tmp"
# The complete historical sweep exceeds 115 million pair checks. Keep it in
# `make reproduce`; routine CI independently verifies its chain search, all
# first counterexamples, exact small-chain counts, and bounded large-chain samples.
PYTHONPATH=tools python tools/verify_c2_k2_exhaustive_report.py \
    reports/c2-k2-small-chain-exhaustive.json

# Full experiment sweeps belong to `make reproduce`. Unit tests and
# deterministic vector regeneration exercise the historical models. CI adds
# bounded T3 and T4 CLI smoke runs to verify the current report interfaces.
PYTHONPATH=simulator python -m trahens_sim.t3_compare \
    --classification-windows 16 \
    --probe-epochs 16 \
    --budget-epochs 16 \
    --training-per-class 1 \
    --testing-per-class 1 \
    --probe-training 1 \
    --probe-testing 1 \
    --budget-samples 1 \
    --classification-output /tmp/trahens-t3-class-smoke.csv \
    --probe-output /tmp/trahens-t3-probe-smoke.csv \
    --budget-output /tmp/trahens-t3-budget-smoke.csv

test -s /tmp/trahens-t3-class-smoke.csv
test -s /tmp/trahens-t3-probe-smoke.csv
test -s /tmp/trahens-t3-budget-smoke.csv

PYTHONPATH=simulator python -m trahens_sim.t4_compare \
    --epochs 24 \
    --training-per-monitored 1 \
    --calibration-per-route 1 \
    --testing-per-monitored 1 \
    --testing-per-unknown-route 1 \
    --probe-training 1 \
    --probe-testing 1 \
    --open-world-output /tmp/trahens-t4-open-smoke.csv \
    --packet-output /tmp/trahens-t4-packet-smoke.csv \
    --probe-output /tmp/trahens-t4-probe-smoke.csv

test -s /tmp/trahens-t4-open-smoke.csv
test -s /tmp/trahens-t4-packet-smoke.csv
test -s /tmp/trahens-t4-probe-smoke.csv

# The standalone current paper must not contain historical architecture or iteration narration.
if command -v rg >/dev/null 2>&1; then
    paper_search="rg -n -i"
else
    paper_search="grep -Eni"
fi
if $paper_search 'Nexus|original paper|2020|draft iteration|Core v0\.|W1|M1' paper/rewrite/main.tex >/tmp/trahens-paper-forbidden.txt; then
    cat /tmp/trahens-paper-forbidden.txt >&2
    rm -f /tmp/trahens-paper-forbidden.txt
    echo "forbidden historical term found in current paper" >&2
    exit 1
fi
rm -f /tmp/trahens-paper-forbidden.txt

# Documentation staleness. A profile revision leaves prose behind, and an audit
# found several documents still calling the superseded profile active — one of
# them CLAUDE.md, which steers later work. These checks exist so the next drift
# fails here instead of needing another manual sweep.
python3 - <<'STALE'
import json, pathlib, re, sys

root = pathlib.Path(".")
registry = json.loads((root / "spec/protocol-registry-v1.6.json").read_text())
version = registry["registry_version"]
series = ".".join(version.split(".")[:2])

problems = []

# The changelog must name the registry the tree actually ships.
changelog = (root / "CHANGELOG.md").read_text()
if version not in changelog:
    problems.append(f"CHANGELOG.md does not mention registry {version}")

# No live document may present a superseded profile as the active one. Files
# that are themselves historical, or that discuss the supersession, are exempt.
live = [
    root / "README.md",
    root / "CLAUDE.md",
    root / "ROADMAP.md",
    root / "spec/README.md",
    root / "docs/implementing-trahens-p1.md",
    root / "docs/p1-acceptance-evidence.md",
]
claim = re.compile(r"active[^.\n]{0,40}v1\.5|v1\.5[^.\n]{0,20}is (the )?active", re.I)
for path in live:
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if claim.search(line):
            problems.append(f"{path}:{number}: calls v1.5 active")

# The active series must actually have a core spec, which is the gap that
# prompted this check.
if not (root / f"spec/core-v{series}.md").exists():
    problems.append(f"registry is {version} but spec/core-v{series}.md does not exist")

if problems:
    print("\n".join(problems), file=sys.stderr)
    raise SystemExit("documentation is stale relative to the registry")
print(f"documentation matches registry {version}")
STALE

bash -n implementation/harness/netns-p1.sh
bash -n implementation/harness/multihost-p1.sh
bash -n implementation/harness/netns-fanout.sh
bash -n implementation/harness/netns-restart.sh
python -m compileall -q tools

if command -v cargo >/dev/null 2>&1; then
    cargo test --manifest-path implementation/rust/Cargo.toml --all-targets
else
    echo "cargo not available: Rust tests deferred to the mandatory CI Rust job" >&2
fi

echo "repository checks passed"
