#!/usr/bin/env bash
# Quick incident watch (no full rebuild): refresh vendor IOC repos + CISA KEV, then list what is new in out/incidents/RADAR.md.
# Usage: scripts/radar.sh      (run ./run_all.sh afterwards only if incidents were added or changed)
set -euo pipefail
P="$(cd "$(dirname "$0")/.." && pwd)"; D="$P/data"; OUT="$P/out"
echo "[$(date -u +%H:%M:%S)] Refreshing vendor IOC repos and CISA KEV"
"$P/scripts/sync_feeds.sh" "$D"
echo "[$(date -u +%H:%M:%S)] Radar"
python3 -I "$P/scripts/incident_radar.py" "$D" "$OUT/state_sponsored" "$OUT/incidents"
