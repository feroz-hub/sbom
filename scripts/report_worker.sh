#!/usr/bin/env bash
set -euo pipefail
# Run from the repository with its Python environment activated. Isolate report
# memory/CPU from analysis; API and worker must share REPORT_ARTIFACT_STORAGE_PATH.
exec celery -A app.workers.celery_app worker -Q reports --concurrency=1 --prefetch-multiplier=1 --max-tasks-per-child=20 --loglevel=info --hostname=reports@%h
