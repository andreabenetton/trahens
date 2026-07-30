#!/bin/sh
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
spec/core-v1.2.md
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
spec/message-codec-m2.md
spec/wire-cell-w2.md
spec/active-tagging-analysis.md
spec/transport-profile-t1.md
spec/transport-profile-t2.md
spec/messages-v1.2.md
spec/state-machines-v1.2.md
spec/invariants-v1.2.md
spec/resource-accounting-v1.2.md
simulator/trahens_crypto/ristretto.py
simulator/trahens_crypto/c1.py
simulator/trahens_crypto/c2_ideal.py
simulator/trahens_crypto/c2_klinear.py
simulator/trahens_crypto/candidate.py
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
simulator/tests/test_eligibility_providers.py
simulator/trahens_sim/fragmentation_compare.py
simulator/trahens_sim/c2_compare.py
simulator/trahens_sim/t1_model.py
simulator/trahens_sim/t1_compare.py
simulator/trahens_sim/t2_model.py
simulator/trahens_sim/t2_compare.py
tools/generate_crypto_vectors.py
tools/generate_c2_symbolic_vectors.py
tools/generate_c2_k2_audit.py
tools/generate_r1_vectors.py
tools/generate_t1_vectors.py
tools/generate_t2_vectors.py
tools/c2_k2_exhaustive_check.py
tools/run_r1_comparison.sh
tools/run_fragmentation_comparison.sh
tools/run_c2_comparison.sh
tools/run_t1_comparison.sh
tools/run_t2_comparison.sh
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
docs/review-log/iteration-0006.md
docs/review-log/iteration-0007.md
docs/review-log/iteration-0008.md
docs/review-log/iteration-0009.md
docs/review-log/iteration-0010.md
docs/review-log/iteration-0011.md
docs/review-log/iteration-0012.md
docs/review-log/iteration-0013.md
docs/crypto-review/c2-author-query.md
docs/crypto-review/alternative-primitive-assessment.md
"

for path in $required_files; do
    if [ ! -f "$path" ]; then
        echo "missing required file: $path" >&2
        exit 1
    fi
done

python -m compileall -q simulator
PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v

vectors_tmp=$(mktemp)
r1_vectors_tmp=$(mktemp)
c2_vectors_tmp=$(mktemp)
c2_k2_tmp=$(mktemp)
c2_k2_exhaustive_tmp=$(mktemp)
t1_vectors_tmp=$(mktemp)
t2_vectors_tmp=$(mktemp)
trap 'rm -f "$vectors_tmp" "$r1_vectors_tmp" "$c2_vectors_tmp" "$c2_k2_tmp" "$c2_k2_exhaustive_tmp" "$t1_vectors_tmp" "$t2_vectors_tmp" /tmp/trahens-expanding-smoke.json /tmp/trahens-u1-smoke.csv /tmp/trahens-e1-smoke.csv /tmp/trahens-tag-smoke.csv /tmp/trahens-m1w2-capacity.csv /tmp/trahens-m1w2-life.csv /tmp/trahens-c2-smoke.csv /tmp/trahens-t1-smoke.csv /tmp/trahens-t1-trace-smoke.csv /tmp/trahens-t2-congestion-smoke.csv /tmp/trahens-t2-leak-smoke.csv /tmp/trahens-t2-burst-smoke.csv /tmp/trahens-t2-correlation-smoke.csv' EXIT
PYTHONPATH=simulator python tools/generate_crypto_vectors.py --output "$vectors_tmp"
cmp spec/crypto-test-vectors-c1.json "$vectors_tmp"
PYTHONPATH=simulator python tools/generate_r1_vectors.py --output "$r1_vectors_tmp"
cmp spec/r1-test-vectors.json "$r1_vectors_tmp"
PYTHONPATH=simulator python tools/generate_t1_vectors.py --output "$t1_vectors_tmp"
cmp spec/t1-test-vectors.json "$t1_vectors_tmp"
PYTHONPATH=simulator python tools/generate_t2_vectors.py --output "$t2_vectors_tmp"
cmp spec/t2-test-vectors.json "$t2_vectors_tmp"
PYTHONPATH=simulator python tools/generate_c2_symbolic_vectors.py --output "$c2_vectors_tmp"
cmp spec/crypto-test-vectors-c2-symbolic.json "$c2_vectors_tmp"
PYTHONPATH=simulator python tools/generate_c2_k2_audit.py --output "$c2_k2_tmp"
cmp reports/c2-k2-transcription-audit.json "$c2_k2_tmp"
PYTHONPATH=simulator python tools/c2_k2_exhaustive_check.py --output "$c2_k2_exhaustive_tmp"
cmp reports/c2-k2-small-chain-exhaustive.json "$c2_k2_exhaustive_tmp"

./tools/run_experiments.sh
./tools/run_r1_comparison.sh

PYTHONPATH=simulator python -m trahens_sim.expanding_cli \
    --nodes 50 \
    --average-degree 4 \
    --rings 1:1,3:2 \
    --responder-fraction 0.1 \
    --transmission-budget 100 \
    --state-budget 100 \
    --seed 17 \
    --output /tmp/trahens-expanding-smoke.json

test -s /tmp/trahens-expanding-smoke.json

PYTHONPATH=simulator python -m trahens_sim.unlinkability_compare \
    --nodes 40 \
    --average-degree 4 \
    --runs 2 \
    --hop-limits 2 \
    --fanouts 2 \
    --responder-fractions 0.1 \
    --transmission-budget 100 \
    --state-budget 100 \
    --per-node-context-limit 4 \
    --output /tmp/trahens-u1-smoke.csv

test -s /tmp/trahens-u1-smoke.csv

PYTHONPATH=simulator python -m trahens_sim.lifecycle_compare \
    --nodes 40 \
    --average-degree 4 \
    --runs 2 \
    --rings 2:2:10 \
    --responder-fraction 0.1 \
    --seed-base 41 \
    --output /tmp/trahens-e1-smoke.csv

test -s /tmp/trahens-e1-smoke.csv

PYTHONPATH=simulator python -m trahens_sim.tagging_compare \
    --runs 2 \
    --output /tmp/trahens-tag-smoke.csv

test -s /tmp/trahens-tag-smoke.csv

PYTHONPATH=simulator python -m trahens_sim.fragmentation_compare \
    --capacity-output /tmp/trahens-m1w2-capacity.csv \
    --lifecycle-output /tmp/trahens-m1w2-life.csv \
    --runs 2

test -s /tmp/trahens-m1w2-capacity.csv
test -s /tmp/trahens-m1w2-life.csv

PYTHONPATH=simulator python -m trahens_sim.c2_compare \
    --runs 2 \
    --output /tmp/trahens-c2-smoke.csv

test -s /tmp/trahens-c2-smoke.csv

PYTHONPATH=simulator python -m trahens_sim.t1_compare \
    --runs 2 \
    --output /tmp/trahens-t1-smoke.csv \
    --trace-output /tmp/trahens-t1-trace-smoke.csv

test -s /tmp/trahens-t1-smoke.csv
test -s /tmp/trahens-t1-trace-smoke.csv

PYTHONPATH=simulator python -m trahens_sim.t2_compare \
    --runs 2 \
    --leak-runs 2 \
    --burst-runs 2 \
    --correlation-runs 2 \
    --congestion-output /tmp/trahens-t2-congestion-smoke.csv \
    --leakage-output /tmp/trahens-t2-leak-smoke.csv \
    --burst-output /tmp/trahens-t2-burst-smoke.csv \
    --correlation-output /tmp/trahens-t2-correlation-smoke.csv

test -s /tmp/trahens-t2-congestion-smoke.csv
test -s /tmp/trahens-t2-leak-smoke.csv
test -s /tmp/trahens-t2-burst-smoke.csv
test -s /tmp/trahens-t2-correlation-smoke.csv

# The standalone current paper must not contain historical architecture or iteration narration.
if rg -n -i 'Nexus|original paper|2020|draft iteration|Core v0\.|W1|M1' paper/rewrite/main.tex >/tmp/trahens-paper-forbidden.txt; then
    cat /tmp/trahens-paper-forbidden.txt >&2
    rm -f /tmp/trahens-paper-forbidden.txt
    echo "forbidden historical term found in current paper" >&2
    exit 1
fi
rm -f /tmp/trahens-paper-forbidden.txt

echo "repository checks passed"
