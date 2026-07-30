#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=simulator python - <<'PY'
from pathlib import Path
from trahens_sim.fragmentation_compare import write_reports

write_reports(
    Path("reports/iteration-0008-message-cell-capacity.csv"),
    Path("reports/iteration-0008-lifecycle-fragmentation.csv"),
)
PY
