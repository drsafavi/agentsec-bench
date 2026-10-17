#!/usr/bin/env bash
# Rebuild the task suite, run the three reference agents and print the summary.
# Deterministic: the suite checksum and the results are stable across runs.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src

echo "== regenerating task suite =="
python3 -m agentsec_bench.generate --out data/tasks

echo "== running reference agents =="
python3 -m agentsec_bench.cli run --agent all --tasks data/tasks --out results

echo "== suite checksum =="
cat data/tasks/CHECKSUMS.txt
