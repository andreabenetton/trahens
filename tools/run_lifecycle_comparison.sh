#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

PYTHONPATH=simulator python -m trahens_sim.lifecycle_compare \
    --nodes 500 \
    --average-degree 8 \
    --runs 100 \
    --rings 2:2:18,3:2:24,4:3:32 \
    --responder-fraction 0.02 \
    --seed-base 7000 \
    --output reports/iteration-0005-lifecycle-comparison.csv
