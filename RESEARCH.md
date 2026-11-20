# Daily recent-activity research procedure

Goal: add any newly reported activity by the **state-sponsored actors** in
`out/state_sponsored/state_actors_summary.csv` to `data/work/web.jsonl`.

## 1. Window
Look at reporting published since the date in `out/LAST_BUILD` (or the last 14 days if unsure).

## 2. Where to look (reliable sources only)
**Government / national CERT advisories:** CISA, UK NCSC, CERT-UA, Australian Signals Directorate (ACSC),
Canadian Centre for Cyber Security, JPCERT/CC, KrCERT/KISA, Germany BSI, CERT-FR/ANSSI, NCSC-NL, Singapore CSA,
joint multi-agency advisories.
**Vendor and lab research (primary reporting):** Google Threat Intelligence Group / Mandiant, Microsoft Threat
Intelligence, CrowdStrike, Palo Alto Unit 42, ESET WeLiveSecurity, Kaspersky Securelist and ICS CERT, Trend Micro,
Cisco Talos, Proofpoint, Recorded Future Insikt, SentinelLabs, Check Point Research, Symantec/Broadcom, Sophos X-Ops,
Secureworks CTU, Lumen Black Lotus Labs, Volexity, Lookout, Zscaler ThreatLabz, Elastic Security Labs, AhnLab ASEC,
Genians, NSFOCUS, Positive Technologies, BI.ZONE, Trellix, Arctic Wolf, Rapid7.
**Independent research:** Citizen Lab, Amnesty Tech Security Lab, Google Project Zero.
**Established security journalism (for leads; cite the primary report when it exists):** The Record, BleepingComputer,
The Hacker News, SecurityWeek, Dark Reading, CyberScoop, Wired, Reuters, Help Net Security.
Skip: content farms, AI-generated summary sites, unsourced social posts, paste sites, vendor marketing without technical detail.

## 3. Method
1. Start with roll-ups that cover many actors at once (quarterly/half-year APT reports, monthly APT insights,
   joint advisories), then search the most active actors individually.
2. One finding per line: `Name|Date of activity|Who reported it: what happened (targets, tools, CVEs)|primary URL[,secondary URL]`
3. Record the **activity** date/period, not just the article date. Use the reporter's own wording for attribution
   confidence ("assessed", "medium confidence").
4. Append with: `CTI_STATE=out/state_sponsored python3 -I scripts/rec2.py data/work/web.jsonl < findings.txt`
   Lines whose name doesn't resolve are printed as "unresolved" — check them for a new alias, or skip if the
   actor isn't state-sponsored.
5. Re-run `./run_all.sh` so the new entries flow into the workbooks, then read `out/CHANGES.md`.

## 4. Attribution review for country-tag-only actors
`data/curation/actor_attribution_review.csv` records web research on actors whose only state link is a MISP
country tag (they would otherwise be rated **Low**). The build uses it: STATE_ATTRIBUTED → High;
STATE_ALIGNED_ASSESSED, HYBRID or STATE_ATTRIBUTED_CONTESTED → Medium; CRIMINAL, HACKTIVIST, NO_ATTRIBUTION or
NOT_FOUND → removed from the state-sponsored set. After each build, any actor still rated Low in
`out/state_sponsored/state_actors_summary.csv` is new and unreviewed: research it with the same reliable sources,
prefer the newest reporting, and add a row (actor, verdict, sponsor_country, state_agency_or_unit, attributing_source,
attribution_wording, confidence_wording, latest_report_date, url, notes, reviewed_on). Re-check a row when newer
reporting changes the picture (update latest_report_date and reviewed_on).

## 5. Major incidents (any attribution) — incident watch
Goal: stay vigilant. When a major breach, compromise, supply-chain attack or mass-exploitation campaign happens anywhere
(e.g. ARTEX in 2026, Salt Typhoon's ISP compromises in 2024), capture it quickly and keep collecting its IOCs as vendors and
agencies publish them. This runs in the incident watch (every ~6 hours) and in the daily refresh.
1. **Radar** (`scripts/radar.sh`, also run by `./run_all.sh`): refreshes the Talos, Unit 42, Volexity and ESET IOC repos and the
   CISA KEV catalog and writes `out/incidents/RADAR.md`: new vendor IOC reports (IOC counts, actors named, watched-incident
   matches, ready-to-use `ioc_feeds` refs) and new KEV entries (ransomware flag). Triage every row:
   - matches a watched incident → add the feed ref to that incident's `ioc_feeds:` (after checking the report is about it);
   - a new major incident with IOCs → create its YAML; a single-actor state report needs nothing here (section 6 / actor IOCs);
   - KEV entries: a new major incident only when reporting shows mass or high-impact exploitation (several victims,
     an advisory, a known actor, ransomware use). Otherwise ignore.
2. **Queue:** research every line in `data/incidents/queue.txt`, write `data/incidents/<id>.yaml` from `_template.yaml`,
   then delete the line. If it can't be verified from reliable sources, leave the line and say why.
3. **Breaking news sweep** (since the last watch run): CISA / NCSC / ACSC / CCCS / CERT-FR / BSI / JPCERT / CERT-UA advisories and
   joint advisories; vendor research blogs listed in section 2; then The Record, BleepingComputer, SecurityWeek, The Hacker News
   for leads (cite the primary report). Major = a large or well-known victim, a telecom/ISP, cloud, government or
   critical-infrastructure compromise, a supply-chain compromise with downstream victims, mass exploitation, significant data
   or crypto theft, destructive attacks, or a government advisory. Skip routine single-victim ransomware claims.
4. **Watched incidents** (`watch: true`): for each, search for reporting since its `updated:` date — new victims, new
   attribution, new advisories, new IOCs — and update the YAML (summary, `updated:`, sources, `ioc_feeds`, `iocs`, `keywords`).
   Set `watch: false` when the incident is contained and nothing new has been reported for ~30 days.
5. **IOCs:** prefer `ioc_feeds:` (exact values from vendor files). Only key values into `iocs:` when copied from the
   report's own IOC table, read verbatim; never type IOCs from memory or from a summary, and say in `notes:` what was left out.
6. Use the reporter's own attribution wording; `attribution: MIXED` when several unrelated actors are involved.
7. Run `./run_all.sh` if any incident changed; the `incidents:` line must show `formula-like cells: 0` and no ERROR lines.

## 6. Vendor-report attribution review (actor IOCs)
After each build, open `out/state_sponsored/state_actors_ioc_reports_to_review.csv`: vendor reports whose title has state,
APT or espionage wording but no actor that resolves to the state-sponsored set (typically a new Talos UAT-xxxx cluster).
For each, read the vendor's report and add a row to `data/curation/vendor_report_actors.csv`:
- the vendor attributes it to a known actor → `actor` = that dataset actor, `action` = include;
- the vendor names a new cluster with a state nexus ("China-nexus", "suspected North Korea-aligned") → leave `actor` empty,
  set `reported_as` = the cluster name, `sponsor` = the country, `attribution_wording` = the vendor's words, `action` = include;
- criminal, hacktivist, offensive framework or no attribution → `action` = exclude, with the reason.
Use the vendor's own wording. Then re-run `./run_all.sh` (the file should then list 0 reports).
