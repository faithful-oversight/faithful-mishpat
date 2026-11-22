#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Install the exact wheel in a directory into a clean environment and run it.
# CI and the release workflow both run this on the files they publish.
#
# Usage: scripts/smoke_test.sh <dist-directory>
#
# Products extend the marked section to run their real workflow end to end on
# synthetic data, so a broken package cannot be released.

set -euo pipefail

dist="${1:?dist directory required}"
shopt -s nullglob
wheels=("$dist"/*.whl)
[[ ${#wheels[@]} -eq 1 ]] || { echo "expected exactly one wheel in $dist" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

uv venv --quiet "$work/venv"
# The wheel's own runtime dependencies come from the lock file, with their hashes, so the
# smoke test runs what the checks locked and not whatever the index holds today. The wheel
# itself is then installed without resolving anything.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
uv export --quiet --locked --no-dev --no-emit-project --format requirements-txt \
  --project "$root" > "$work/runtime.txt"
uv pip install --quiet --python "$work/venv" --require-hashes -r "$work/runtime.txt"
uv pip install --quiet --python "$work/venv" --no-deps "${wheels[0]}"
if [[ -x "$work/venv/bin/mishpat" ]]; then
  tool="$work/venv/bin/mishpat"
  python="$work/venv/bin/python"
else
  tool="$work/venv/Scripts/mishpat"
  python="$work/venv/Scripts/python"
fi

"$tool" --version
"$tool" --help > /dev/null
# Product end to end: the synthetic example through the installed wheel.
"$tool" example "$work/demo" > /dev/null
before="$work/demo/corp-before.jsonl"
after="$work/demo/corp-after.jsonl"
for input in "$before" "$after"; do
  [[ -s "$input" ]] || { echo "mishpat example wrote no $(basename "$input")" >&2; exit 1; }
done
status=0
"$tool" compare "$before" "$after" -o "$work/demo/out" > /dev/null || status=$?
# The example has differences on purpose, so the comparison exits 1, not 0 or an error.
[[ "$status" -eq 1 ]] || { echo "expected exit code 1 (differences), got $status" >&2; exit 1; }
outputs=(mishpat-report.json mishpat-report.md mishpat-report.html mishpat-differences.csv
  mishpat-manifest.json)
for name in "${outputs[@]}"; do
  [[ -s "$work/demo/out/$name" ]] || { echo "missing $name" >&2; exit 1; }
done
# The manifest must list the four reports (it cannot list itself).
"$python" - "$work/demo/out" "${outputs[@]:0:4}" <<'PY'
import json
import sys

folder, *expected = sys.argv[1:]
with open(f"{folder}/mishpat-manifest.json", encoding="utf-8") as handle:
    listed = sorted(item["name"] for item in json.load(handle)["files"])
if listed != sorted(expected):
    sys.exit(f"the manifest lists {listed}, not {sorted(expected)}")
with open(f"{folder}/mishpat-report.json", encoding="utf-8") as handle:
    summary = json.load(handle)["summary"]
if not summary["complete"] or summary["differences"] < 1:
    sys.exit(f"the example report is not a complete report with differences: {summary}")
PY

echo "smoke test passed: ${wheels[0]}"
