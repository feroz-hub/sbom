#!/usr/bin/env bash
# Run from repository `sbom/` directory: ./scripts/celery_worker.sh
set -euo pipefail
cd "$(dirname "$0")/.."
exec celery -A app.workers.celery_app worker --loglevel=info
