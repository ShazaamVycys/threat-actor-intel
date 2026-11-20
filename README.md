# Threat Actor Intel Pipeline

Rebuilds the threat-actor workbooks and CSVs (aliases, malware, ATT&CK TTPs, host artifacts,
descriptions, recent activity) from the latest public sources.

## Run
    ./run_all.sh          # ~2 minutes; needs Python 3, git, curl, zip, openpyxl, pyyaml

Outputs land in `out/`:
- `out/state_sponsored/` – the state-sponsored set (+ `out/state_sponsored_threat_actors.zip`)
- `out/all_actors/`      – every actor, including `threat_actor_intel.xlsx`
- `out/incidents/`       – major breaches and compromises with IOCs, any attribution (`major_incidents.xlsx`, + `out/major_incidents.zip`)
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
| ESET `malware-ioc`, Cisco Talos `IOCs`, Volexity `threat-intel`, Unit 42 `timely-threat-intel` | hashes of named, custom malware of state-sponsored actors | with each vendor report |

Every run safety-checks the downloaded JSON (no scripts, encoded blobs, hidden
characters or spreadsheet formulas) and prints the result.

## Recent-activity research (not automatic)
`data/work/web.jsonl` is the log of 2025–2026 activity gathered from vendor reports.
New findings are appended with `scripts/rec2.py` (one line per finding:
`Name|Date|Summary|URL`); names are resolved to actors through the alias index.
Re-run `./run_all.sh` afterwards to fold them into the Descriptions and Recent Activity sheets.

## Malware hashes
`scripts/hashes.py` reads the vendor IOC repos and keeps only hashes of **named, custom malware** tied to an actor in the
state-sponsored set. Commercial, open-source, commodity and legitimate tools are excluded (`data/curation/cots_exclusions.txt`),
as are hashes the source doesn't name (listed in `state_actors_malware_hash_exclusions.csv`). The master list
`data/hashes/state_malware_hashes.csv` is cumulative: new hashes get today's date in **First Added**, existing rows are kept,
and the file is only rewritten when something changed. Rows are removed only if their actor leaves the state set or the
name becomes excluded. Workbook sheets: **Malware Hash Summary** and **Malware Hashes**.

## State-sponsored actor IOCs (all IOC types)
`scripts/state_iocs.py` reads every report in the Cisco Talos, Unit 42, Volexity and ESET IOC repos and keeps **all**
hashes, IPs, domains, URLs and emails from reports that are about **one** state-sponsored actor. The actor comes from
`data/curation/vendor_report_actors.csv` (reviewed reports; can add vendor-named clusters such as Talos UAT-xxxx with their
stated nexus, or exclude a report) or else from the actor named in the report title / file name via the alias index;
reports naming several actors are skipped. Reports whose title has state or espionage wording but no resolvable actor are
listed in `state_actors_ioc_reports_to_review.csv` for review. Network indicators are defanged; private IPs, well-known
legitimate domains and files the source calls legitimate are excluded (`state_actors_ioc_exclusions.csv`). The master
`data/iocs/state_actor_iocs.csv` is cumulative with **First Added**. Workbook sheets: **Actor IOC Summary** and **Actor IOCs**.
(The Malware Hashes sheet stays the stricter list: hashes of *named, custom* malware only.)

## Major incidents (breaches, compromises, campaigns)
Current-event incidents that need not be state-sponsored (e.g. ARTEX, a big exchange theft). One YAML file per incident in
`data/incidents/<id>.yaml` (copy `_template.yaml`): what happened, attribution (STATE, STATE_ALIGNED, CRIMINAL, HACKTIVIST,
INSIDER, UNATTRIBUTED or MIXED), actors as reported, CVEs, ATT&CK IDs, sources, and IOCs.
- **Key one in:** add a line `name | report URL | note` to `data/incidents/queue.txt` (the GitHub web editor works). The daily
  refresh researches it, writes the YAML and removes the line. The daily refresh also adds major new incidents on its own.
- **IOCs:** `ioc_feeds:` points at a report file in the vendor IOC repos (`talos:2026/11/x.json`, `unit42:…txt`, `eset:…`,
  `volexity:…`) and the build copies the values exactly; `iocs:` holds values keyed in from a report page, marked
  *transcribed – verify before blocking*. Types: hashes, IPv4/IPv6, domains, URLs, emails, file names, user agents, HTTP headers.
- Network indicators are stored **defanged** (`1.2.3[.]4`, `evil[.]com`, `hxxps://`); private IPs, placeholder and well-known
  legitimate domains, and files the source calls legitimate are excluded (`incident_ioc_exclusions.csv`). The IOC master
  `data/incidents/incident_iocs.csv` is cumulative with a **First Added** date. Any formula-like cell stops the build.
- Actor names resolve through the alias index; incidents tied to a state-sponsored actor also appear on the **Incidents** sheet
  of the state-sponsored workbook.

## Licences
Sigma rules and signature-base are under the Detection Rule License 1.1 — keep author
attribution when sharing. MITRE ATT&CK © The MITRE Corporation (royalty-free licence).
