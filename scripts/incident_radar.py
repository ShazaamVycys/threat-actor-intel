# Incident radar: what is NEW since the last radar run, from sources that publish structured data.
#   - new vendor IOC reports (Cisco Talos, Unit 42, Volexity, ESET repos), with IOC counts and the actor they resolve to
#   - new CISA Known Exploited Vulnerabilities (KEV) entries (mass-exploitation signal; ransomware use flag)
#   - matches of new reports/KEV entries against the keywords of incidents being watched (data/incidents/*.yaml, watch: true)
# It never edits incidents; it writes a triage list for the routine to research.
# State: data/incidents/radar_state.json (first run records a baseline and reports nothing as new).
# Usage: incident_radar.py <data dir> <state out dir> <incidents out dir>
import csv,os,re,sys,json,glob,datetime,collections
import importlib.util as _u
import yaml
D,ST,OUT=sys.argv[1:4]
_s=_u.spec_from_file_location('ioclib',os.path.join(os.path.dirname(os.path.abspath(__file__)),'ioclib.py')); IL=_u.module_from_spec(_s); _s.loader.exec_module(IL)
NOW=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%MZ'); TODAY=NOW[:10]
SP=D+'/incidents/radar_state.json'
state=json.load(open(SP)) if os.path.exists(SP) else {}
first=not state
seen_r=state.get('vendor_reports',{}); seen_k=state.get('kev',{})
WEB={'Cisco Talos':'https://github.com/Cisco-Talos/IOCs/blob/main/','Unit 42':'https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/',
     'Volexity':'https://github.com/volexity/threat-intel/tree/main/','ESET':'https://github.com/eset/malware-ioc/tree/master/'}
# ---- actor lookup (state set + all actors) for triage hints
n=IL.n
SA={x['actor'] for x in csv.DictReader(open(ST+'/state_actors_summary.csv',encoding='utf-8-sig'))}
ALL=collections.defaultdict(set)
ap=os.path.join(os.path.dirname(ST),'all_actors','alias_index.csv')
if os.path.exists(ap):
    for x in csv.DictReader(open(ap,encoding='utf-8-sig')): ALL[n(x['lookup_name'])].add(x['resolves_to'])
PATS=[(re.compile(r'(?<![A-Za-z0-9])'+r'[\s\-_]*'.join(map(re.escape,re.findall(r'[A-Za-z0-9]+',k)))+r'(?![A-Za-z0-9])',re.I),v) for k,v in
      ((x['lookup_name'],x['resolves_to']) for x in csv.DictReader(open(ap,encoding='utf-8-sig'))) if len(n(k))>=5] if os.path.exists(ap) else []
def actors_in(text):
    hit=sorted({a for rx,a in PATS if rx.search(text)})
    return hit[:4]
# ---- watched incidents and their keywords
watch=[]
for p in sorted(glob.glob(D+'/incidents/*.yaml')):
    if os.path.basename(p).startswith('_'): continue
    y=yaml.safe_load(open(p,encoding='utf-8')) or {}
    on=y.get('watch', y.get('status')=='ongoing')
    if not on: continue
    kws=[str(k) for k in (y.get('keywords') or [])]+[a.get('name') if isinstance(a,dict) else str(a) for a in (y.get('actors') or [])]
    kws=[k for k in kws if k and len(n(k))>=4 and not k.lower().startswith('unnamed')]
    feeds={str(f) for f in (y.get('ioc_feeds') or [])}
    watch.append((y.get('id'),y.get('name'),[re.compile(r'(?<![A-Za-z0-9])'+re.escape(k)+r'(?![A-Za-z0-9])',re.I) for k in kws],feeds))
FEEDKEY={'Cisco Talos':'talos','Unit 42':'unit42','Volexity':'volexity','ESET':'eset'}
# ---- new vendor reports
newrep=[]
for vd,rid,title,date,files in IL.vendor_reports(D+'/ext'):
    key=f'{vd}|{rid}'
    if key in seen_r: continue
    seen_r[key]=TODAY
    if first: continue
    vals=set(); body=''
    for p,rel in files:
        try:
            for t,v,ctx in IL.extract_file(p,rel):
                tt,val=IL.classify('' if t in('hash','ip') else t,v)
                if tt: vals.add(('hash' if tt in('sha256','sha1','md5') else tt,val.lower()))
            if os.path.getsize(p)<2_000_000: body+=open(p,encoding='utf-8',errors='replace').read(20000)
        except Exception: pass
    c=collections.Counter(t for t,v in vals)
    text=title+' '+rid
    acts=actors_in(text); st=[a for a in acts if a in SA]
    hits=[]
    for iid,name,rxs,feeds in watch:
        if any(rx.search(text) or rx.search(body[:20000]) for rx in rxs): hits.append(iid)
    feedrefs=[f"{FEEDKEY[vd]}:{rel}" for p,rel in files if rel.endswith(('.json','.txt','.csv'))] if vd!='ESET' else [f"eset:{rel}" for p,rel in files]
    newrep.append({'Vendor':vd,'Report':title,'Report Date':date,'IOCs':', '.join(f'{k} {v}' for k,v in c.most_common()),'IOC Total':str(sum(c.values())),
                   'Actors named':'; '.join(acts),'State-sponsored':'Yes' if st else '','Matches watched incident':'; '.join(hits),
                   'Feed refs':' '.join(feedrefs[:6]),'Link':(WEB[vd]+(files[0][1] if vd!='ESET' else rid)).replace(' ','%20'),'First Seen':NOW})
# ---- new CISA KEV entries
newkev=[]
kp=D+'/ext/kev/known_exploited_vulnerabilities.json'
if os.path.exists(kp):
    for v in json.load(open(kp,encoding='utf-8')).get('vulnerabilities',[]):
        cid=v.get('cveID','')
        if not re.fullmatch(r'CVE-\d{4}-\d{4,7}',cid) or cid in seen_k: continue
        seen_k[cid]=v.get('dateAdded','')
        if first: continue
        text=' '.join(str(v.get(k,'')) for k in ('vendorProject','product','vulnerabilityName','shortDescription','notes'))
        hits=[iid for iid,name,rxs,feeds in watch if any(rx.search(text) for rx in rxs) or cid in open(D+f'/incidents/{iid}.yaml',encoding='utf-8').read()]
        newkev.append({'CVE':cid,'Vendor / Product':IL.clean(f"{v.get('vendorProject','')} {v.get('product','')}"),'Name':IL.clean(v.get('vulnerabilityName','')),
                       'Date Added':v.get('dateAdded',''),'Ransomware Use':v.get('knownRansomwareCampaignUse',''),'Due':v.get('dueDate',''),
                       'Matches watched incident':'; '.join(hits),'Link':f'https://www.cve.org/CVERecord?id={cid}','First Seen':NOW})
# ---- write
os.makedirs(OUT,exist_ok=True)
def safe(r): return {k:(v.lstrip('=+-@\t\r') if isinstance(v,str) else v) for k,v in r.items()}
def append(path,rows,fl):
    old=list(csv.DictReader(open(path,encoding='utf-8'))) if os.path.exists(path) else []
    with open(path,'w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fl,lineterminator='\n'); w.writeheader(); w.writerows([safe(r) for r in rows]+old[:2000])
RF=['First Seen','Vendor','Report','Report Date','IOC Total','IOCs','Actors named','State-sponsored','Matches watched incident','Feed refs','Link']
KF=['First Seen','CVE','Vendor / Product','Name','Date Added','Ransomware Use','Due','Matches watched incident','Link']
append(OUT+'/radar_vendor_reports.csv',newrep,RF); append(OUT+'/radar_kev.csv',newkev,KF)
state={'baseline':state.get('baseline',NOW),'last_run':NOW,'vendor_reports':seen_r,'kev':seen_k}
json.dump(state,open(SP,'w'),indent=0,sort_keys=True)
L=[f'# Incident radar — {NOW}','',('_Baseline run: existing reports and KEV entries recorded; nothing reported as new._' if first else
   f'{len(newrep)} new vendor IOC report(s), {len(newkev)} new CISA KEV entr{"y" if len(newkev)==1 else "ies"} since the last radar run.'),'']
if newrep:
    L+=['## New vendor IOC reports','','| Vendor | Report | Date | IOCs | Actors named | Watched incident |','|---|---|---|---|---|---|']
    L+=[f"| {r['Vendor']} | [{r['Report'][:90]}]({r['Link']}) | {r['Report Date']} | {r['IOCs'] or '0'} | {r['Actors named']}{' (state)' if r['State-sponsored'] else ''} | {r['Matches watched incident']} |" for r in newrep]
    L.append('')
if newkev:
    L+=['## New CISA KEV entries','','| CVE | Product | Added | Ransomware | Watched incident |','|---|---|---|---|---|']
    L+=[f"| {k['CVE']} | {k['Vendor / Product']} | {k['Date Added']} | {k['Ransomware Use']} | {k['Matches watched incident']} |" for k in newkev]
    L.append('')
L+=['## Watched incidents','']+[f'- `{iid}` {name}' for iid,name,rxs,feeds in watch]
open(OUT+'/RADAR.md','w',encoding='utf-8').write('\n'.join(L)+'\n')
print(f"   radar: {'baseline recorded' if first else 'ok'}; {len(newrep)} new vendor reports ({sum(1 for r in newrep if r['State-sponsored'])} state-linked, "
      f"{sum(1 for r in newrep if r['Matches watched incident'])} match watched incidents); {len(newkev)} new KEV ({sum(1 for k in newkev if k['Ransomware Use']=='Known')} ransomware-linked); "
      f"{len(watch)} incidents watched")
