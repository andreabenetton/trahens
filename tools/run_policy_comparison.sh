#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

PYTHONPATH=simulator python -m trahens_sim.policy_compare \
    --nodes 500 \
    --average-degree 8 \
    --runs 100 \
    --responder-fractions 0.01,0.02,0.05 \
    --candidate-limit 8 \
    --required-candidates 1 \
    --fixed-hop-limit 5 \
    --fixed-initial-fanout 4 \
    --fixed-relay-fanout 4 \
    --rings 2:2,3:2,4:3,5:4 \
    --transmission-budget 1200 \
    --state-budget 1200 \
    --seed-base 3000 \
    --output reports/iteration-0003-policy-comparison.csv
