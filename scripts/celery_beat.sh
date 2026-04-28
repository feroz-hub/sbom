#!/usr/bin/env bash
# Run the Celery beat scheduler. Beat must run as a SINGLE instance —
# multiple beat processes will fire each scheduled task multiple times.
#
# Usage:
#   ./scripts/celery_beat.sh
set -euo pipefail
cd "$(dirname "$0")/.."
exec celery -A app.workers.celery_app beat --loglevel=info
