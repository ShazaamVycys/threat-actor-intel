#!/usr/bin/env bash
# Rebuilds every threat-actor file from the latest public sources.
# Usage: ./run_all.sh   (needs network access to GitHub raw, apt.etda.or.th)
set -euo pipefail
P="$(cd "$(dirname "$0")" && pwd)"; SC="$P/scripts"; D="$P/data"; OUT="$P/out"
FULL="$OUT/all_actors"; ST="$OUT/state_sponsored"; export CTI_STATE="$ST"
mkdir -p "$D"/{dl,etda,mitre,work,ext} "$FULL" "$ST"
log(){ echo "[$(date -u +%H:%M:%S)] $*"; }

# keep the previous state-sponsored build for the change report
rm -rf "$D/work/prev"; [ -f "$ST/state_actors_summary.csv" ] && cp -r "$ST" "$D/work/prev"

log "1/9 Downloading sources"
curl -sSfL -m 300 -o "$D/dl/threat-actor.json" https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json
curl -sSfL -m 300 -o "$D/etda/etda_groups.json" "https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=g"
curl -sSfL -m 300 -o "$D/etda/etda_tools.json"  "https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=t"
for d in enterprise mobile ics; do
  curl -sSfL -m 600 -o "$D/mitre/$d-attack.json" "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/$d-attack/$d-attack.json"
done
sync_repo(){ # sparse shallow clone or update
  local url=$1 dir=$2; shift 2
  if [ -d "$dir/.git" ]; then git -C "$dir" fetch -q --depth 1 origin && git -C "$dir" reset -q --hard FETCH_HEAD
  else git clone -q --depth 1 --filter=blob:none --sparse "$url" "$dir" && git -C "$dir" sparse-checkout set "$@" >/dev/null; fi
  echo "   $(basename "$dir") @ $(git -C "$dir" rev-parse --short HEAD) ($(git -C "$dir" log -1 --format=%cs))"
}
sync_repo https://github.com/MISP/misp-galaxy.git "$D/galaxy/repo" clusters
sync_repo https://github.com/SigmaHQ/sigma.git "$D/ext/sigma" rules rules-emerging-threats rules-threat-hunting
sync_repo https://github.com/Neo23x0/signature-base.git "$D/ext/sb" iocs

log "2/9 Safety checks (must show 0 for every risky pattern)"
for f in "$D/dl/threat-actor.json" "$D/etda/etda_groups.json" "$D/etda/etda_tools.json"; do
  echo "   $(basename "$f")"; python3 -I "$SC/check.py" "$f" | grep -E 'control|bidi|script|uri|base64|powershell|formula|template' | sed 's/^/      /'
done

log "3/9 MITRE ATT&CK groups";   python3 -I "$SC/mitre.py" "$D/mitre" "$D/mitre" | tail -2
log "4/9 Malware maps";          python3 -I "$SC/malware.py" "$D" "$D/work/malware_maps.json" | tail -3
log "5/9 Merge MISP+ETDA+MITRE"; python3 -I "$SC/merge.py" "$D/dl/threat-actor.json" "$D/etda/etda_groups.json" "$FULL" "$D/mitre/mitre_attack_groups.json" "$D/work/malware_maps.json" | tail -4
log "6/9 TTPs";                  python3 -I "$SC/ttp.py" "$D" "$FULL" | tail -2
log "7/9 Host artifacts";        python3 -I "$SC/artifacts.py" "$D" "$FULL" | tail -2
python3 -I "$SC/post_counts.py" "$FULL"

log "8/9 State-sponsored pack + descriptions + web research log"
python3 -I "$SC/state_pack.py" "$FULL" "$ST"
python3 -I "$SC/desc.py" "$D" "$FULL" "$ST/state_actors_descriptions.csv" | tail -1
python3 -I "$SC/webmerge.py" "$D" "$ST" | head -1
python3 -I "$SC/alpha.py" "$ST"/state_actors_{summary,aliases,malware,ttps,host_artifacts,descriptions,web_activity}.csv \
  "$FULL"/{merged_state_sponsored,apt_aliases_by_actor_state_sponsored,actor_malware_state_sponsored,actor_ttps_state_sponsored,actor_host_artifacts_state_sponsored}.csv

log "9/9 Workbooks + zip"
python3 -I "$SC/versions.py" "$D" | sed 's/^/   /'
python3 -I "$SC/build_full_xlsx.py" "$FULL" "$FULL/threat_actor_intel.xlsx" | tail -1
python3 -I "$SC/build_state_xlsx.py" "$FULL" "$ST/state_sponsored_threat_actor_intel.xlsx" | tail -1
(cd "$ST" && rm -f ../state_sponsored_threat_actors.zip && zip -qj ../state_sponsored_threat_actors.zip ./*)
python3 -I "$SC/changes.py" "$D/work/prev" "$ST" "$OUT/CHANGES.md" | sed 's/^/   /'
date -u +%Y-%m-%dT%H:%MZ > "$OUT/LAST_BUILD"
log "Done. Outputs in $OUT"
