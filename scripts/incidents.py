# Builds the major-incidents dataset (breaches, compromises, supply-chain attacks, campaigns) from data/incidents/*.yaml.
# Incidents need not be state-sponsored. IOCs come from two places:
#   ioc_feeds: files in the vendor IOC repos downloaded by run_all.sh (exact values, read as text, never executed)
#   iocs:      values keyed in by hand from a report (marked "transcribed - verify before blocking")
# Network IOCs (IPs, domains, URLs, emails) are stored defanged (1.2.3[.]4, evil[.]com, hxxps://...); hashes as lowercase hex.
# The IOC master data/incidents/incident_iocs.csv is cumulative: new IOCs get today's date in First Added and existing rows keep theirs.
# Usage: incidents.py <data dir> <all-actors out dir> <state out dir> <incidents out dir>
import csv,os,re,sys,json,io,glob,ipaddress,datetime,collections
import yaml
D,FULL,ST,OUT=sys.argv[1:5]
ROOT=os.path.realpath(os.path.join(D,'..')); INC=D+'/incidents'
TODAY=datetime.datetime.now(datetime.timezone.utc).date().isoformat()
import importlib.util as _u
_s=_u.spec_from_file_location('ioclib',os.path.join(os.path.dirname(os.path.abspath(__file__)),'ioclib.py')); IL=_u.module_from_spec(_s); _s.loader.exec_module(IL)
IL.FEEDS.update(IL.feeds(D))
globals().update({k:getattr(IL,k) for k in dir(IL) if not k.startswith('_')})
CATS={'breach','data-theft','supply-chain','ransomware','extortion','crypto-theft','exploitation','malware-campaign','tool-abuse','espionage','destructive','ddos','other'}
ATTR={'STATE','STATE_ALIGNED','CRIMINAL','HACKTIVIST','INSIDER','UNATTRIBUTED','MIXED'}
err=[]; bad=0
# ---------- actor resolution
AL=collections.defaultdict(set)
for x in csv.DictReader(open(FULL+'/alias_index.csv',encoding='utf-8-sig')): AL[n(x['lookup_name'])].add(x['resolves_to'])
SA={x['actor']:x for x in csv.DictReader(open(ST+'/state_actors_summary.csv',encoding='utf-8-sig'))}
def resolve(name):
    k=n(name); r=AL.get(k) or AL.get(k+'group') or set()
    st=sorted(a for a in r if a in SA)
    return (st or sorted(r)), bool(st)
# ---------- load incidents
inc=[]; iocs=[]; excl=[]; feedstat=collections.Counter()
for p in sorted(glob.glob(INC+'/*.yaml')):
    if os.path.basename(p).startswith('_'): continue
    try: y=yaml.safe_load(open(p,encoding='utf-8')) or {}
    except Exception as e: err.append(f'{os.path.basename(p)}: YAML error {e}'); continue
    iid=clean(y.get('id',''))
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{2,60}',iid) or iid+'.yaml'!=os.path.basename(p): err.append(f'{os.path.basename(p)}: id must match the file name (lowercase, digits, hyphens)'); continue
    cat=clean(y.get('category','')); at=clean(y.get('attribution',''))
    if cat not in CATS: err.append(f'{iid}: category {cat!r} not one of {sorted(CATS)}')
    if at not in ATTR: err.append(f'{iid}: attribution {at!r} not one of {sorted(ATTR)}')
    srcs=[s if isinstance(s,dict) else {'url':s} for s in (y.get('sources') or [])]
    if not srcs: err.append(f'{iid}: needs at least one source')
    acts=[]; linked=[]; state=False
    for a in (y.get('actors') or []):
        a=a if isinstance(a,dict) else {'name':a}
        r,isst=resolve(a.get('name','')); state|=isst
        acts.append(clean(a.get('name',''))+(f" ({clean(a['attribution'])})" if a.get('attribution') else ''))
        linked+=[x for x in r if x not in linked]
    J=lambda k:'; '.join(clean(v) for v in (y.get(k) or []))
    row={'Incident ID':iid,'Incident':clean(y.get('name','')),'Category':cat,'Status':clean(y.get('status','')),'Activity Period':clean(y.get('activity','')),
         'First Reported':clean(y.get('disclosed','')),'Last Updated':clean(y.get('updated','')),'Victims / Targets':clean(y.get('victims','')),
         'Sectors':J('sectors'),'Countries':J('countries'),'Attribution':at,'Actors (as reported)':'; '.join(acts),
         'Linked Actors (dataset)':'; '.join(linked),'State-Sponsored Link':'Yes' if state else 'No',
         'Summary':clean(y.get('summary','')),'CVEs':J('cves'),'ATT&CK Techniques':J('techniques'),
         'Sources':' '.join(clean(s.get('url','')) for s in srcs),'Reporters':'; '.join(clean(s.get('reporter','')) for s in srcs if s.get('reporter')),
         'IOC Feeds':'; '.join(clean(f) for f in (y.get('ioc_feeds') or [])),'Notes':clean(y.get('notes',''))}
    for c in('CVEs',):
        for v in (y.get('cves') or []):
            if not re.fullmatch(r'CVE-\d{4}-\d{4,7}',str(v)): err.append(f'{iid}: bad CVE {v}')
    for v in (y.get('techniques') or []):
        if not re.fullmatch(r'T\d{4}(\.\d{3})?',str(v)): err.append(f'{iid}: bad ATT&CK ID {v}')
    inc.append(row)
    def add(t,v,ctx,prov,src):
        tt,val=classify(t,v)
        if not tt: excl.append({'Incident ID':iid,'Value':clean(v)[:200],'Why excluded':val,'Context':ctx,'Source':src}); return
        if tt in('sha256','sha1','md5') and NOTMAL.search(ctx or ''): excl.append({'Incident ID':iid,'Value':val,'Why excluded':'source says the file is legitimate or a decoy','Context':ctx,'Source':src}); return
        iocs.append({'Incident ID':iid,'Incident':row['Incident'],'Type':tt,'Indicator':defang(tt,val),'Context':clean(ctx)[:240],'Provenance':prov,'Source':src})
    for f in (y.get('ioc_feeds') or []):
        try: got,web=read_feed(str(f))
        except Exception as e: err.append(f'{iid}: feed {f}: {e}'); continue
        if got is None: feedstat['feed file not found (kept earlier IOCs)']+=1; continue
        feedstat['feed files read']+=1
        for t,v,c in got: add(t,v,c,'vendor IOC repo (exact)',web)
    for i in (y.get('iocs') or []):
        if not isinstance(i,dict) or 'value' not in i: err.append(f'{iid}: each iocs entry needs type and value'); continue
        add(clean(i.get('type','')),str(i['value']),clean(i.get('context','')),'transcribed from report - verify before blocking',clean(i.get('source','')) or (srcs[0].get('url','') if srcs else ''))
# ---------- dedupe + cumulative master
ORDER={t:i for i,t in enumerate(TYPES)}
seen={};
for r in iocs:
    k=(r['Incident ID'],r['Type'],r['Indicator'].lower())
    if k in seen:
        o=seen[k]
        if r['Provenance'].startswith('vendor') and not o['Provenance'].startswith('vendor'): o.update(Provenance=r['Provenance'],Source=r['Source'])
        if r['Context'] and r['Context'] not in o['Context'] and len(o['Context'])<200: o['Context']=(o['Context']+' | '+r['Context']).strip(' |')[:240]
    else: seen[k]=r
M=INC+'/incident_iocs.csv'; F=['Incident ID','Incident','Type','Indicator','Context','Provenance','Source','First Added']
old={}
if os.path.exists(M):
    for r in csv.DictReader(open(M,encoding='utf-8')): old[(r['Incident ID'],r['Type'],r['Indicator'].lower())]=r
ids={r['Incident ID'] for r in inc}
out=[]; new=0
for k,r in seen.items():
    r['First Added']=old[k]['First Added'] if k in old else TODAY; new+=k not in old; out.append(r)
kept=0
for k,r in old.items():                      # keep IOCs whose feed file has since disappeared, while the incident exists
    if k not in seen and k[0] in ids: out.append(r); kept+=1
removed=sum(1 for k in old if k[0] not in ids)
out.sort(key=lambda r:(r['Incident ID'],ORDER.get(r['Type'],99),r['Indicator']))
for r in inc+out+excl:
    for k,v in r.items():
        if isinstance(v,str) and not cell_ok(v): bad+=1
def write(path,rs,fl):
    b=io.StringIO(); w=csv.DictWriter(b,fieldnames=fl,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rs); s=b.getvalue()
    if not os.path.exists(path) or open(path,encoding='utf-8').read()!=s: open(path,'w',encoding='utf-8',newline='').write(s); return True
    return False
if err:
    print('   ERROR in incident files:'); [print('     '+e) for e in err]; sys.exit(2)
if bad:
    print(f'   incidents: formula-like cells: {bad} - stopping'); sys.exit(3)
os.makedirs(OUT,exist_ok=True)
cnt=collections.Counter((r['Incident ID'],r['Type']) for r in out)
for r in inc:
    r['IOC Count']=str(sum(v for (i,t),v in cnt.items() if i==r['Incident ID']))
    r['IOC Types']=', '.join(f'{t} {cnt[(r["Incident ID"],t)]}' for t in TYPES if cnt[(r['Incident ID'],t)])
IF=list(inc[0]) if inc else ['Incident ID']
inc.sort(key=lambda r:(r['Last Updated'] or r['First Reported']),reverse=True)
changed=write(M,out,F)
write(OUT+'/incidents.csv',inc,IF); write(OUT+'/incident_iocs.csv',out,F)
write(OUT+'/incident_ioc_exclusions.csv',excl,['Incident ID','Value','Why excluded','Context','Source'])
stl=[r for r in inc if r['State-Sponsored Link']=='Yes']
write(ST+'/state_actors_incidents.csv',stl,IF)
print(f"   incidents: {len(inc)} ({len(stl)} linked to state-sponsored actors); IOCs {len(out)} ({new} new, {kept} kept from earlier feeds, {removed} removed with their incident); "
      f"by type {dict(collections.Counter(r['Type'] for r in out))}; excluded {dict(collections.Counter(r['Why excluded'] for r in excl))}; {dict(feedstat)}; "
      f"master {'updated' if changed else 'unchanged'}; formula-like cells: {bad}")
