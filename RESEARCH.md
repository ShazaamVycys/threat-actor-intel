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
