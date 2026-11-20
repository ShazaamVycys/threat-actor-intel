#!/usr/bin/env bash
# Downloads/updates the vendor IOC repos and the CISA KEV catalog (read as text/JSON only, never executed).
# Usage: scripts/sync_feeds.sh <data dir>
set -uo pipefail
D=$1; mkdir -p "$D/ext/kev"
sync_full(){ # full shallow clone or update
  local url=$1 dir=$2
  if [ -d "$dir/.git" ]; then git -C "$dir" fetch -q --depth 1 origin && git -C "$dir" reset -q --hard FETCH_HEAD
  else git clone -q --depth 1 "$url" "$dir"; fi || { echo "   WARNING: could not refresh $(basename "$dir"); using last good copy"; return 0; }
  echo "   $(basename "$dir") @ $(git -C "$dir" rev-parse --short HEAD) ($(git -C "$dir" log -1 --format=%cs))"
}
sync_full https://github.com/eset/malware-ioc.git "$D/ext/eset"
sync_full https://github.com/Cisco-Talos/IOCs.git "$D/ext/talos"
sync_full https://github.com/volexity/threat-intel.git "$D/ext/volexity"
sync_full https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel.git "$D/ext/unit42"
K="$D/ext/kev/known_exploited_vulnerabilities.json"
if curl -sSfL -m 120 -o "$K.new" https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json \
   && python3 -I "$(dirname "$0")/check_json.py" "$K.new"; then mv "$K.new" "$K"; echo "   kev @ $(python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["catalogVersion"],d["count"])' "$K")"
else rm -f "$K.new"; echo "   WARNING: could not refresh CISA KEV; using last good copy"; fi
