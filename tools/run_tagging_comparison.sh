#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
PYTHONPATH=simulator python -m trahens_sim.tagging_compare \
  --runs 40 \
  --seed-base 9100 \
  --output reports/iteration-0007-wire-tagging-comparison.csv
