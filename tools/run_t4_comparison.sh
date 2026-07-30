#!/bin/sh
set -eu
PYTHONPATH=simulator python -m trahens_sim.t4_compare \
  --epochs 40 \
  --training-per-monitored 6 \
  --calibration-per-route 3 \
  --testing-per-monitored 4 \
  --testing-per-unknown-route 4 \
  --probe-training 6 \
  --probe-testing 6 \
  --open-world-output reports/iteration-0015-t4-open-world.csv \
  --packet-output reports/iteration-0015-t4-packet-emulation.csv \
  --probe-output reports/iteration-0015-t4-selective-delay.csv
