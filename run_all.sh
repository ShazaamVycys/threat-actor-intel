#!/usr/bin/env bash
# Rebuilds every threat-actor file from the latest public sources.
# Usage: ./run_all.sh   (needs network access to GitHub raw, apt.etda.or.th)
set -euo pipefail
P="$(cd "$(dirname "$0")" && pwd)"; SC="$P/scripts"; D="$P/data"; OUT="$P/out"
FULL="$OUT/all_actors"; ST="$OUT/state_sponsored"; export CTI_STATE="$ST"
mkdir -p "$D"/{dl,etda,mitre,work,ext} "$FULL" "$ST"
log(){ echo "[$(date -u +%H:%M:%S)] $*"; }

# keep the previous state-sponsored build for the change report
rm -rf "$D/work/prev" "$D/work/prev_incidents"; [ -f "$ST/state_actors_summary.csv" ] && cp -r "$ST" "$D/work/prev"
[ -d "$OUT/incidents" ] && cp -r "$OUT/incidents" "$D/work/prev_incidents"

log "1/9 Downloading sources"
fetch(){ # download to a temp file; keep the last good copy (committed in the repo) if the source is unreachable
  local url=$1 out=$2
  if curl -sSfL -m 300 -o "$out.new" "$url" && python3 -I -c "import json,sys;json.load(open(sys.argv[1]))" "$out.new" 2>/dev/null; then mv "$out.new" "$out"
  else rm -f "$out.new"; [ -f "$out" ] && echo "   WARNING: could not refresh $(basename "$out"); using last good copy" || { echo "   ERROR: no copy of $(basename "$out")"; exit 1; }; fi
}
fetch https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json "$D/dl/threat-actor.json"
fetch "https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=g" "$D/etda/etda_groups.json"
fetch "https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=t" "$D/etda/etda_tools.json"
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
sync_full(){ # full shallow clone or update (vendor IOC repos; read as text only, never executed)
  local url=$1 dir=$2
  if [ -d "$dir/.git" ]; then git -C "$dir" fetch -q --depth 1 origin && git -C "$dir" reset -q --hard FETCH_HEAD
  else git clone -q --depth 1 "$url" "$dir"; fi || { echo "   WARNING: could not refresh $(basename "$dir"); using last good copy"; return 0; }
  echo "   $(basename "$dir") @ $(git -C "$dir" rev-parse --short HEAD) ($(git -C "$dir" log -1 --format=%cs))"
}
sync_full https://github.com/eset/malware-ioc.git "$D/ext/eset"
sync_full https://github.com/Cisco-Talos/IOCs.git "$D/ext/talos"
sync_full https://github.com/volexity/threat-intel.git "$D/ext/volexity"
sync_full https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel.git "$D/ext/unit42"

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

cp "$D/curation/actor_attribution_review.csv" "$ST/state_actors_attribution_review.csv"
log "8b/9 State-sponsored malware hashes (ESET, Talos, Volexity, Unit 42)"
python3 -I "$SC/hashes.py" "$D" "$ST"
log "8c/9 State-sponsored actor IOCs (all IOC types from single-actor vendor reports)"
python3 -I "$SC/state_iocs.py" "$D" "$ST"
log "8d/9 Major incidents (data/incidents/*.yaml + vendor IOC files)"
python3 -I "$SC/incidents.py" "$D" "$FULL" "$ST" "$OUT/incidents"
log "9/9 Workbooks + zip"
python3 -I "$SC/versions.py" "$D" | sed 's/^/   /'
python3 -I "$SC/build_full_xlsx.py" "$FULL" "$FULL/threat_actor_intel.xlsx" | tail -1
python3 -I "$SC/build_state_xlsx.py" "$FULL" "$ST/state_sponsored_threat_actor_intel.xlsx" | tail -1
python3 -I "$SC/build_incidents_xlsx.py" "$OUT/incidents" "$D/work/versions.txt"
(cd "$ST" && rm -f ../state_sponsored_threat_actors.zip && zip -qj ../state_sponsored_threat_actors.zip ./*)
(cd "$OUT/incidents" && rm -f ../major_incidents.zip && zip -qj ../major_incidents.zip ./*)
python3 -I "$SC/changes.py" "$D/work/prev" "$ST" "$OUT/CHANGES.md" | sed 's/^/   /'
date -u +%Y-%m-%dT%H:%MZ > "$OUT/LAST_BUILD"
log "Done. Outputs in $OUT"
