#!/bin/sh
# Start the API immediately; refresh detection templates in the background.
#
# The template repo is ~200 MB on first fetch. Doing that before starting
# uvicorn means the health check fails and the UI shows "backend not
# responding" for several minutes on a first run — which looks like a crash.

set -e

(
  if [ ! -d /root/nuclei-templates ] || [ -z "$(ls -A /root/nuclei-templates 2>/dev/null)" ]; then
    echo "[templates] first-time download starting (~200 MB, a few minutes)…"
  else
    echo "[templates] checking for updates…"
  fi

  if nuclei -update-templates -silent 2>&1; then
    echo "[templates] ready"
  else
    echo "[templates] update failed — scans will fetch what they need on demand"
  fi
) &

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
