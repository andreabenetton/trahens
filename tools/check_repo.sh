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
docs/adr/0029-equal-budget-traffic-analysis.md
docs/adr/0030-multilink-classifier-and-active-probe.md
spec/core-v1.3.md
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
spec/message-codec-m2.md
spec/wire-cell-w2.md
spec/active-tagging-analysis.md
spec/transport-profile-t1.md
spec/transport-profile-t2.md
spec/transport-profile-t3.md
spec/messages-v1.3.md
spec/state-machines-v1.3.md
spec/invariants-v1.3.md
spec/resource-accounting-v1.3.md
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
simulator/tests/test_t3_model.py
simulator/tests/test_eligibility_providers.py
simulator/trahens_sim/fragmentation_compare.py
simulator/trahens_sim/c2_compare.py
simulator/trahens_sim/t1_model.py
simulator/trahens_sim/t1_compare.py
simulator/trahens_sim/t2_model.py
simulator/trahens_sim/t2_compare.py
simulator/trahens_sim/t3_model.py
simulator/trahens_sim/t3_compare.py
tools/generate_crypto_vectors.py
tools/generate_c2_symbolic_vectors.py
tools/generate_c2_k2_audit.py
tools/generate_r1_vectors.py
tools/generate_t1_vectors.py
tools/generate_t2_vectors.py
tools/generate_t3_vectors.py
tools/c2_k2_exhaustive_check.py
tools/run_r1_comparison.sh
tools/run_fragmentation_comparison.sh
tools/run_c2_comparison.sh
tools/run_t1_comparison.sh
tools/run_t2_comparison.sh
tools/run_t3_comparison.sh
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
docs/review-log/iteration-0006.md
docs/review-log/iteration-0007.md
docs/review-log/iteration-0008.md
docs/review-log/iteration-0009.md
docs/review-log/iteration-0010.md
docs/review-log/iteration-0011.md
docs/review-log/iteration-0012.md
docs/review-log/iteration-0013.md
docs/review-log/iteration-0014.md
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
t3_vectors_tmp=$(mktemp)
trap 'rm -f "$vectors_tmp" "$r1_vectors_tmp" "$c2_vectors_tmp" "$c2_k2_tmp" "$c2_k2_exhaustive_tmp" "$t1_vectors_tmp" "$t2_vectors_tmp" "$t3_vectors_tmp" /tmp/trahens-r1-smoke.csv /tmp/trahens-expanding-smoke.json /tmp/trahens-u1-smoke.csv /tmp/trahens-e1-smoke.csv /tmp/trahens-tag-smoke.csv /tmp/trahens-m1w2-capacity.csv /tmp/trahens-m1w2-life.csv /tmp/trahens-c2-smoke.csv /tmp/trahens-t1-smoke.csv /tmp/trahens-t1-trace-smoke.csv /tmp/trahens-t2-congestion-smoke.csv /tmp/trahens-t2-leak-smoke.csv /tmp/trahens-t2-burst-smoke.csv /tmp/trahens-t2-correlation-smoke.csv /tmp/trahens-t3-class-smoke.csv /tmp/trahens-t3-probe-smoke.csv /tmp/trahens-t3-budget-smoke.csv' EXIT
PYTHONPATH=simulator python tools/generate_crypto_vectors.py --output "$vectors_tmp"
cmp spec/crypto-test-vectors-c1.json "$vectors_tmp"
PYTHONPATH=simulator python tools/generate_r1_vectors.py --output "$r1_vectors_tmp"
cmp spec/r1-test-vectors.json "$r1_vectors_tmp"
PYTHONPATH=simulator python tools/generate_t1_vectors.py --output "$t1_vectors_tmp"
cmp spec/t1-test-vectors.json "$t1_vectors_tmp"
PYTHONPATH=simulator python tools/generate_t2_vectors.py --output "$t2_vectors_tmp"
cmp spec/t2-test-vectors.json "$t2_vectors_tmp"
PYTHONPATH=simulator python tools/generate_t3_vectors.py --output "$t3_vectors_tmp"
cmp spec/t3-test-vectors.json "$t3_vectors_tmp"
PYTHONPATH=simulator python tools/generate_c2_symbolic_vectors.py --output "$c2_vectors_tmp"
cmp spec/crypto-test-vectors-c2-symbolic.json "$c2_vectors_tmp"
PYTHONPATH=simulator python tools/generate_c2_k2_audit.py --output "$c2_k2_tmp"
cmp reports/c2-k2-transcription-audit.json "$c2_k2_tmp"
PYTHONPATH=simulator python tools/c2_k2_exhaustive_check.py --output "$c2_k2_exhaustive_tmp"
cmp reports/c2-k2-small-chain-exhaustive.json "$c2_k2_exhaustive_tmp"

# Full experiment sweeps belong to `make reproduce`. Unit tests and
# deterministic vector regeneration exercise the historical models. CI adds
# one bounded T3 CLI smoke run to verify the current report interface.
PYTHONPATH=simulator python -m trahens_sim.t3_compare \
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

# The standalone current paper must not contain historical architecture or iteration narration.
if rg -n -i 'Nexus|original paper|2020|draft iteration|Core v0\.|W1|M1' paper/rewrite/main.tex >/tmp/trahens-paper-forbidden.txt; then
    cat /tmp/trahens-paper-forbidden.txt >&2
    rm -f /tmp/trahens-paper-forbidden.txt
    echo "forbidden historical term found in current paper" >&2
    exit 1
fi
rm -f /tmp/trahens-paper-forbidden.txt

echo "repository checks passed"
