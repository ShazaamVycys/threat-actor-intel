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

## 5. Major incidents (any attribution)
Goal: keep `data/incidents/` current with major breaches, compromises, supply-chain attacks and campaigns in the news,
whether or not a state is behind them.
1. **Queue first:** research every line in `data/incidents/queue.txt`, write `data/incidents/<id>.yaml` from
   `_template.yaml`, then delete the line. If the report can't be verified from reliable sources, leave the line and say why.
2. **New incidents:** look for incidents first reported since `out/LAST_BUILD` that are *major*: a large or well-known victim,
   a supply-chain compromise with downstream victims, a mass-exploitation campaign, significant data/crypto theft or
   disruption, or a government advisory. Skip routine single-victim ransomware claims and leak-site posts without reporting.
   Check the existing YAML files first; if the incident is already there, update it (new facts, `updated:`, sources, IOCs)
   instead of adding another.
3. **Facts** come from the same reliable sources as section 2. Use the reporter's own attribution wording and set
   `attribution:` accordingly; use MIXED when several unrelated actors are involved.
4. **IOCs:** prefer `ioc_feeds:`; look in `data/ext/{talos,unit42,eset,volexity}` for the report's IOC file
   (`grep -ril <keyword> data/ext/...`). Only key values into `iocs:` when they are copied from the report's IOC table;
   never type IOCs from memory or from a summary. Leave out generic user agents and tools.
5. Run `./run_all.sh`; the `incidents:` line must show `formula-like cells: 0` and no ERROR lines (fix the YAML if there are).
