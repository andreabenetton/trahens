#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
PYTHONPATH=simulator python -m trahens_sim.r1_compare --runs 100 --output reports/iteration-0011-r1-gate-b.csv
