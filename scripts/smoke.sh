#!/usr/bin/env bash
# PEN-AGENT smoke tests — fast, dependency-light sanity checks.
#
# Checks:
#   1. All .sh files parse (bash -n)
#   2. All .py files under tools/ compile (python3 -m py_compile)
#   3. All committed .json files parse
#   4. install.sh's .claude/settings.json template parses as JSON
#   5. tools/reporter example finding conforms to finding.schema.json
#
# Each check collects every failure in its group before failing, so one
# bad file doesn't hide the rest. The script exits non-zero on first
# failing check (not first failing file).
#
# Run locally:   bash scripts/smoke.sh
# CI:            invoked by .github/workflows/smoke.yml

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

banner() { printf '\n=== %s ===\n' "$1"; }
pass()   { printf '  OK\n'; }
fail()   { printf '  FAIL\n'; exit 1; }

# -----------------------------------------------------------------
banner "1. Shell syntax (bash -n)"
failed=0
while IFS= read -r f; do
    if ! bash -n "$f" 2>&1; then
        printf '  bash -n: %s\n' "$f"
        failed=1
    fi
done < <(find . -name "*.sh" \
    -not -path "./tools/*/.venv/*" \
    -not -path "./node_modules/*" \
    -not -path "./.git/*")
[[ $failed -eq 0 ]] && pass || fail

# -----------------------------------------------------------------
banner "2. Python syntax (py_compile)"
failed=0
while IFS= read -r f; do
    if ! python3 -m py_compile "$f" 2>&1; then
        printf '  py_compile: %s\n' "$f"
        failed=1
    fi
done < <(find tools -name "*.py" \
    -not -path "*/.venv/*" \
    -not -path "*/node_modules/*" \
    -not -path "*/__pycache__/*")
[[ $failed -eq 0 ]] && pass || fail

# -----------------------------------------------------------------
banner "3. Committed JSON files parse"
failed=0
if command -v git >/dev/null 2>&1 && [[ -d .git ]]; then
    mapfile -t json_files < <(git ls-files '*.json')
else
    mapfile -t json_files < <(find . -name "*.json" \
        -not -path "./tools/*/.venv/*" \
        -not -path "./node_modules/*" \
        -not -path "./.git/*")
fi
for f in "${json_files[@]}"; do
    if ! python3 -m json.tool < "$f" > /dev/null 2>&1; then
        printf '  invalid JSON: %s\n' "$f"
        failed=1
    fi
done
[[ $failed -eq 0 ]] && pass || fail

# -----------------------------------------------------------------
banner "4. install.sh settings.json template parses"
if ! awk '/cat > "\$settings_file" << .JSON./{flag=1; next} /^JSON$/{flag=0} flag' install.sh \
        | python3 -m json.tool > /dev/null; then
    printf '  heredoc body did not parse as JSON\n'
    fail
fi
pass

# -----------------------------------------------------------------
banner "5. tools/reporter example conforms to finding.schema.json"
python3 - <<'PY' || fail
import json, sys
try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("  jsonschema not installed; pip install jsonschema")
    sys.exit(1)

schema = json.load(open('tools/reporter/finding.schema.json'))
example = json.load(open('tools/reporter/examples/finding-prompt-injection.json'))

# Example files are single findings; validate them against $defs/finding
# while preserving the top-level $defs so internal $refs resolve.
sub = dict(schema['$defs']['finding'])
sub['$defs'] = schema['$defs']

v = Draft202012Validator(sub)
errors = list(v.iter_errors(example))
if errors:
    for e in errors:
        print(f"  {'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}")
    sys.exit(1)
PY
pass

# -----------------------------------------------------------------
printf '\nAll smoke checks passed.\n'
