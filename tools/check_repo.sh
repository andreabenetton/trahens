#!/bin/sh
set -eu

required_files="
README.md
ROADMAP.md
docs/strategy.md
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
spec/core-v0.7.md
spec/unlinkability-profile-u1.md
spec/event-lifecycle-profile-e1.md
spec/crypto-profile-c1.md
spec/crypto-transcript-v0.2.md
spec/crypto-test-vectors-c1.json
spec/message-codec-m1.md
spec/wire-cell-w2.md
spec/active-tagging-analysis.md
spec/messages-v0.7.md
spec/state-machines-v0.7.md
spec/invariants-v0.7.md
spec/resource-accounting-v0.7.md
simulator/trahens_crypto/ristretto.py
simulator/trahens_crypto/c1.py
simulator/trahens_crypto/candidate.py
simulator/trahens_crypto/tagging.py
simulator/trahens_codec/m1w2.py
simulator/tests/test_crypto_c1.py
simulator/tests/test_message_cell_codec.py
simulator/tests/test_candidate_chain.py
simulator/tests/test_active_tagging.py
simulator/tests/test_event_model.py
simulator/trahens_sim/fragmentation_compare.py
tools/generate_crypto_vectors.py
tools/run_fragmentation_comparison.sh
paper/legacy/trahens-2020.tex
paper/legacy/trahens-2020.pdf
paper/rewrite/main.tex
reports/iteration-0004-unlinkability-comparison.csv
reports/iteration-0005-lifecycle-comparison.csv
reports/iteration-0006-crypto-conformance.json
reports/iteration-0007-wire-tagging-comparison.csv
reports/iteration-0008-message-cell-capacity.csv
reports/iteration-0008-lifecycle-fragmentation.csv
docs/review-log/iteration-0006.md
docs/review-log/iteration-0007.md
docs/review-log/iteration-0008.md
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
trap 'rm -f "$vectors_tmp" /tmp/trahens-expanding-smoke.json /tmp/trahens-u1-smoke.csv /tmp/trahens-e1-smoke.csv /tmp/trahens-tag-smoke.csv /tmp/trahens-m1w2-capacity.csv /tmp/trahens-m1w2-life.csv' EXIT
PYTHONPATH=simulator python tools/generate_crypto_vectors.py --output "$vectors_tmp"
cmp spec/crypto-test-vectors-c1.json "$vectors_tmp"

./tools/run_experiments.sh

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

# The standalone current paper must not contain historical architecture or iteration narration.
if rg -n -i 'Nexus|original paper|2020|draft iteration|Core v0\.|W1' paper/rewrite/main.tex >/tmp/trahens-paper-forbidden.txt; then
    cat /tmp/trahens-paper-forbidden.txt >&2
    rm -f /tmp/trahens-paper-forbidden.txt
    echo "forbidden historical term found in current paper" >&2
    exit 1
fi
rm -f /tmp/trahens-paper-forbidden.txt

echo "repository checks passed"
