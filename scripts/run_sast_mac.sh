#!/usr/bin/env bash

set -u

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date +"%Y-%m-%d_%H-%M-%S")"
REPORT_DIR="$PROJECT_ROOT/reports/sast/$TIMESTAMP"
ZIP_FILE="$PROJECT_ROOT/reports/SBOM-Analyser-SAST-$TIMESTAMP.zip"

mkdir -p "$REPORT_DIR"

cd "$PROJECT_ROOT"

echo "=================================================="
echo "SBOM Analyser SAST Scan"
echo "=================================================="
echo "Project: $PROJECT_ROOT"
echo "Reports: $REPORT_DIR"
echo

# Select the frontend source directory where available.
if [ -d "$PROJECT_ROOT/frontend/src" ]; then
    FRONTEND_TARGET="$PROJECT_ROOT/frontend/src"
else
    FRONTEND_TARGET="$PROJECT_ROOT/frontend"
fi

SEMGREP_TARGETS=(
    "$PROJECT_ROOT/app"
    "$PROJECT_ROOT/run.py"
    "$FRONTEND_TARGET"
)

SEMGREP_EXCLUDES=(
    --exclude ".git"
    --exclude ".venv"
    --exclude "venv"
    --exclude "__pycache__"
    --exclude "node_modules"
    --exclude "frontend/node_modules"
    --exclude "frontend/build"
    --exclude "frontend/dist"
    --exclude "reports"
    --exclude "coverage"
    --exclude ".pytest_cache"
    --exclude ".mypy_cache"
    --exclude "*.min.js"
    --exclude "*.map"
)

echo "[1/4] Running Semgrep JSON scan..."

semgrep scan \
    --config p/default \
    "${SEMGREP_EXCLUDES[@]}" \
    --json \
    --output "$REPORT_DIR/semgrep-sast.json" \
    "${SEMGREP_TARGETS[@]}" \
    || true

echo "[2/4] Running Semgrep SARIF scan..."

semgrep scan \
    --config p/default \
    "${SEMGREP_EXCLUDES[@]}" \
    --sarif \
    --output "$REPORT_DIR/semgrep-sast.sarif" \
    "${SEMGREP_TARGETS[@]}" \
    || true

echo "Generating Semgrep console report..."

semgrep scan \
    --config p/default \
    "${SEMGREP_EXCLUDES[@]}" \
    "${SEMGREP_TARGETS[@]}" \
    > "$REPORT_DIR/semgrep-console.txt" 2>&1 \
    || true

echo "[3/4] Running Bandit backend scan..."

bandit -r \
    "$PROJECT_ROOT/app" \
    "$PROJECT_ROOT/run.py" \
    -x "$PROJECT_ROOT/app/tests,$PROJECT_ROOT/app/__pycache__" \
    -f html \
    -o "$REPORT_DIR/bandit-backend.html" \
    --exit-zero

bandit -r \
    "$PROJECT_ROOT/app" \
    "$PROJECT_ROOT/run.py" \
    -x "$PROJECT_ROOT/app/tests,$PROJECT_ROOT/app/__pycache__" \
    -f json \
    -o "$REPORT_DIR/bandit-backend.json" \
    --exit-zero

bandit -r \
    "$PROJECT_ROOT/app" \
    "$PROJECT_ROOT/run.py" \
    -x "$PROJECT_ROOT/app/tests,$PROJECT_ROOT/app/__pycache__" \
    -f sarif \
    -o "$REPORT_DIR/bandit-backend.sarif" \
    --exit-zero

bandit -r \
    "$PROJECT_ROOT/app" \
    "$PROJECT_ROOT/run.py" \
    -x "$PROJECT_ROOT/app/tests,$PROJECT_ROOT/app/__pycache__" \
    -f txt \
    -o "$REPORT_DIR/bandit-console.txt" \
    --exit-zero

echo "[4/4] Running frontend ESLint..."

if [ -f "$PROJECT_ROOT/frontend/package.json" ]; then
    cd "$PROJECT_ROOT/frontend"

    if [ -d "src" ]; then
        ESLINT_TARGET="src"
    else
        ESLINT_TARGET="."
    fi

    npx eslint "$ESLINT_TARGET" \
        --format json \
        --output-file "$REPORT_DIR/eslint-frontend.json" \
        || true

    npx eslint "$ESLINT_TARGET" \
        --format html \
        --output-file "$REPORT_DIR/eslint-frontend.html" \
        || true

    npx eslint "$ESLINT_TARGET" \
        --format stylish \
        > "$REPORT_DIR/eslint-console.txt" 2>&1 \
        || true
else
    echo "WARNING: frontend/package.json was not found." \
        | tee "$REPORT_DIR/eslint-warning.txt"
fi

cd "$PROJECT_ROOT"

cat > "$REPORT_DIR/REPORT-INFO.txt" <<INFO
SBOM Analyser SAST Report
=========================

Generated: $(date)
Project: $PROJECT_ROOT

Source code scanned
-------------------
Backend:
- app/
- run.py

Frontend:
- $FRONTEND_TARGET

Excluded
--------
- .venv/
- node_modules/
- frontend/node_modules/
- reports/
- data/
- samples/
- tests/
- database files
- generated frontend build files

Reports
-------
Semgrep:
- semgrep-sast.json
- semgrep-sast.sarif
- semgrep-console.txt

Bandit:
- bandit-backend.html
- bandit-backend.json
- bandit-backend.sarif
- bandit-console.txt

ESLint:
- eslint-frontend.html
- eslint-frontend.json
- eslint-console.txt

Interpretation
--------------
Semgrep:
Primary SAST report covering Python and JavaScript/TypeScript.

Bandit:
Python-specific security findings.

ESLint:
Supplementary frontend code-quality and configured security-rule findings.

Note:
Dependency vulnerabilities from npm audit, pip-audit or Snyk should be
reported separately as Software Composition Analysis, not SAST.
INFO

echo "Creating ZIP report..."

cd "$PROJECT_ROOT/reports/sast"

zip -r "$ZIP_FILE" "$TIMESTAMP" >/dev/null

echo
echo "=================================================="
echo "SAST scan completed"
echo "=================================================="
echo "Report directory:"
echo "$REPORT_DIR"
echo
echo "ZIP report:"
echo "$ZIP_FILE"
echo

open "$REPORT_DIR"
