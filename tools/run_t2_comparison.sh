#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
set -eu
PYTHONPATH=simulator python -m trahens_sim.t2_compare \
  --congestion-output reports/iteration-0013-t2-congestion.csv \
  --leakage-output reports/iteration-0013-t2-schedule-leakage.csv \
  --burst-output reports/iteration-0013-t2-burst-loss.csv \
  --correlation-output reports/iteration-0013-t2-multilink-correlation.csv
