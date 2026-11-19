# Records the exact version/date of every source used in this build (shown on the workbook Key sheet).
import json,subprocess,sys,datetime
D=sys.argv[1]
def git(d):
    try: return subprocess.check_output(['git','-C',d,'log','-1','--format=%h, %cs'],text=True).strip()
    except Exception: return '?'
m=json.load(open(D+'/dl/threat-actor.json')); e=json.load(open(D+'/etda/etda_groups.json'))
ent=[o for o in json.load(open(D+'/mitre/enterprise-attack.json'))['objects'] if o['type']=='x-mitre-collection'][0]
today=datetime.datetime.now(datetime.timezone.utc).date().isoformat()
s=(f"Built {today}. MITRE ATT&CK v{ent.get('x_mitre_version')} ({ent.get('modified','')[:10]}); MISP threat-actor.json v{m.get('version')}; "
   f"ETDA export v{e.get('version')} (groups and tools); MISP galaxy clusters (commit {git(D+'/galaxy/repo')}); "
   f"SigmaHQ rules (commit {git(D+'/ext/sigma')}, DRL 1.1); signature-base filename IOCs (commit {git(D+'/ext/sb')}, DRL 1.1); "
   f"malware hashes from ESET malware-ioc ({git(D+'/ext/eset')}), Cisco Talos IOCs ({git(D+'/ext/talos')}), Volexity threat-intel ({git(D+'/ext/volexity')}), Unit 42 timely-threat-intel ({git(D+'/ext/unit42')}); "
   f"web research log last updated {max(json.loads(l).get('logged','') for l in open(D+'/work/web.jsonl')) or 'see Recent Activity sheet'}")
open(D+'/work/versions.txt','w').write(s); print(s)
