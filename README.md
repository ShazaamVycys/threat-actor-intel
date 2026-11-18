# Threat Actor Intel Pipeline

Rebuilds the threat-actor workbooks and CSVs (aliases, malware, ATT&CK TTPs, host artifacts,
descriptions, recent activity) from the latest public sources.

## Run
    ./run_all.sh          # ~2 minutes; needs Python 3, git, curl, zip, openpyxl, pyyaml

Outputs land in `out/`:
- `out/state_sponsored/` – the state-sponsored set (+ `out/state_sponsored_threat_actors.zip`)
- `out/all_actors/`      – every actor, including `threat_actor_intel.xlsx`
- `out/LAST_BUILD`       – UTC timestamp of the last successful run

## Sources (re-downloaded every run)
| Source | What it adds | Update rhythm |
|---|---|---|
| MISP galaxy `threat-actor.json` | actors, aliases, CFR sponsor, malware links | several times a week |
| ETDA Threat Group Cards (`apt.etda.or.th`) | aliases, sponsor/unit, motivation, tools | irregular (last export Aug 2025) |
| MITRE ATT&CK (enterprise/mobile/ics STIX) | groups, aliases, techniques, procedures, software | 2 major releases a year + fixes |
| MISP galaxy malware clusters | actor↔malware links | several times a week |
| SigmaHQ rules | registry/file/pipe/task/service artifacts | daily |
| signature-base `filename-iocs.txt` | file-name IOC patterns | weekly |

Every run safety-checks the downloaded JSON (no scripts, encoded blobs, hidden
characters or spreadsheet formulas) and prints the result.

## Recent-activity research (not automatic)
`data/work/web.jsonl` is the log of 2025–2026 activity gathered from vendor reports.
New findings are appended with `scripts/rec2.py` (one line per finding:
`Name|Date|Summary|URL`); names are resolved to actors through the alias index.
Re-run `./run_all.sh` afterwards to fold them into the Descriptions and Recent Activity sheets.

## Licences
Sigma rules and signature-base are under the Detection Rule License 1.1 — keep author
attribution when sharing. MITRE ATT&CK © The MITRE Corporation (royalty-free licence).
