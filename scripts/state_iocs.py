# Builds the state-sponsored actor IOC list from vendor IOC repositories (Cisco Talos, Unit 42, Volexity, ESET):
# every hash, IP, domain, URL and email in a vendor report that the vendor attributes to ONE state-sponsored actor.
# Attribution per report: data/curation/vendor_report_actors.csv first (manual review; can include vendor-named clusters
# such as Talos UAT-xxxx that are not in MISP/ETDA/MITRE, or exclude a report), otherwise the actor named in the report
# title / file name, resolved through the state-sponsored alias index. Reports naming several actors are skipped.
# Network IOCs are stored defanged; private IPs, well-known legitimate domains and files the source calls legitimate are excluded.
# The master data/iocs/state_actor_iocs.csv is cumulative (First Added); rows go only if the actor leaves the state set
# or the report is excluded in the curation file.
# Usage: state_iocs.py <data dir> <state out dir>
import csv,os,re,sys,json,io,subprocess,datetime,collections
import importlib.util as _u
D,ST=sys.argv[1:3]
_s=_u.spec_from_file_location('ioclib',os.path.join(os.path.dirname(os.path.abspath(__file__)),'ioclib.py')); IL=_u.module_from_spec(_s); _s.loader.exec_module(IL)
TODAY=datetime.datetime.now(datetime.timezone.utc).date().isoformat()
n=IL.n; clean=IL.clean
EXT=D+'/ext'
WEB={'Cisco Talos':'https://github.com/Cisco-Talos/IOCs/blob/main/','Unit 42':'https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/',
     'Volexity':'https://github.com/volexity/threat-intel/tree/main/','ESET':'https://github.com/eset/malware-ioc/tree/master/'}
KEEP={'sha256','sha1','md5','ipv4','ipv6','domain','url','email'}
# ---------- reference data
S={x['actor']:x for x in csv.DictReader(open(ST+'/state_actors_summary.csv',encoding='utf-8-sig'))}
ALIAS=collections.defaultdict(set); PRIM={}
for x in csv.DictReader(open(ST+'/state_actors_alias_index.csv',encoding='utf-8-sig')):
    ALIAS[n(x['lookup_name'])].add(x['resolves_to'])
    if x['name_type']=='primary': PRIM[n(x['lookup_name'])]=x['resolves_to']
STOP={'chromium','snake','unknown','other','group','operation','campaign','malware','threat','actor','none','apt','team'}
def pat(name): return re.compile(r'(?<![A-Za-z0-9])'+r'[\s\-_]*'.join(re.escape(c) for c in re.findall(r'[A-Za-z0-9]+',name))+r'(?![A-Za-z0-9])',re.I)
APAT=[]
for x in csv.DictReader(open(ST+'/state_actors_alias_index.csv',encoding='utf-8-sig')):
    for nm in {x['lookup_name'],re.sub(r'(?i)\s+(group|team)$','',x['lookup_name'])}:
        k=n(nm)
        if len(k)>=5 and k not in STOP and not k.isdigit(): APAT.append((pat(nm),x['resolves_to'],k in PRIM))
HM={}
hp=D+'/hashes/state_malware_hashes.csv'
if os.path.exists(hp):
    for r in csv.DictReader(open(hp,encoding='utf-8')):
        for h in (r['SHA256'],r['SHA1'],r['MD5']):
            if h: HM[h]=r['Malware']
CUR={}
cp=D+'/curation/vendor_report_actors.csv'
if os.path.exists(cp):
    for r in csv.DictReader(open(cp,encoding='utf-8')): CUR[(r['vendor'],r['report'])]=r
def title_actor(text):
    hits=collections.defaultdict(bool)
    for rx,a,isprim in APAT:
        if a in S and rx.search(text): hits[a]|=isprim
    if len(hits)>1:                                   # prefer actors whose primary name is in the title (e.g. UAT-7237 vs its parent)
        prim=[a for a,p in hits.items() if p]
        if len(prim)==1: return prim[0],''
        return None,'several actors named'
    return (next(iter(hits)),'') if hits else (None,'no state-sponsored actor named')
reports=lambda: IL.vendor_reports(EXT); extract=IL.extract_file
NOTMAL=re.compile(r'(?i)\b(legitimate|benign|clean|decoy|signed by microsoft|not malicious|original installer|vulnerable driver)\b')
# ---------- build
rows=[]; excl=[]; stat=collections.Counter(); used=[]; review=[]
NEXUS=re.compile(r'(?i)\b(china|chinese|north korea\w*|dprk|russia\w*|iran\w*|pakistan\w*|india\w*|belarus\w*|vietnam\w*|kazakh\w*|state[- ]sponsored|nation[- ]state|apt|espionage)\b')
for vd,rid,title,date,files in reports():
    cur=CUR.get((vd,rid))
    if cur and cur['action']=='exclude': stat[f'{vd}: excluded in curation file']+=1; continue
    if cur:
        actor=cur['actor'] if cur['actor'] in S else ''
        reported=cur['reported_as'] or cur['actor']; sponsor=cur['sponsor'] or (S[actor]['Suspected-State-Sponsor'] if actor else '')
        basis='reviewed: '+cur['attribution_wording'] if cur['attribution_wording'] else 'reviewed'
        if not actor and not cur['sponsor']: stat[f'{vd}: curated actor not in state set']+=1; continue
    else:
        actor,why=title_actor(title+' '+rid.replace('/',' ').replace('_',' ').replace('-',' '))
        if not actor:
            stat[f'{vd}: skipped ({why})']+=1
            if NEXUS.search(title): review.append(f'{vd}|{rid}|{title[:110]}')
            continue
        reported=actor; sponsor=S[actor]['Suspected-State-Sponsor']; basis='actor named in report title / file name'
    got=[]
    for p,rel in files:
        try: got+=[(t,v,c,rel) for t,v,c in extract(p,rel)]
        except Exception as ex: stat[f'{vd}: unreadable file']+=1
    if not got: continue
    stat[f'{vd}: reports used']+=1; used.append((vd,rid,actor or reported))
    for t,v,c,rel in got:
        tt,val=IL.classify('' if t in('hash','ip') else t,v)
        link=WEB[vd]+(rel if vd!='ESET' else rid)
        base={'Actor':actor or reported,'Reported As':reported,'In Actor Set':'Yes' if actor else 'No - vendor-named cluster','Sponsor':sponsor,
              'Vendor':vd,'Report ID':rid,'Report':title,'Report Date':date,'Attribution Basis':basis,'Link':link.replace(' ','%20')}
        if not tt: excl.append(dict(base,Value=clean(v)[:200],**{'Why excluded':val})); continue
        if tt not in KEEP: continue
        if tt in('sha256','sha1','md5') and NOTMAL.search(c or ''): excl.append(dict(base,Value=val,**{'Why excluded':'source says the file is legitimate or a decoy','Context':c})); continue
        rows.append(dict(base,Type=tt,Indicator=IL.defang(tt,val),Context=clean(c)[:240],Malware=HM.get(val,'')))
# ---------- dedupe per (actor, type, indicator), keep first report, list others
TXT=lambda v:v.lstrip('=+-@ \t\r') if isinstance(v,str) else v
for r in rows+excl:
    for k in ('Context','Report','Reported As','Value'):
        if k in r and k!='Value': r[k]=TXT(r[k])
ORDER={t:i for i,t in enumerate(IL.TYPES)}
seen={}
for r in rows:
    k=(r['Actor'],r['Type'],r['Indicator'].lower())
    if k in seen:
        o=seen[k]
        if r['Report'] not in o['Report'] and len(o.get('Also In',''))<300: o['Also In']=(o.get('Also In','')+'; '+r['Vendor']+': '+r['Report']).strip('; ')
        if not o['Context'] and r['Context']: o['Context']=r['Context']
    else: seen[k]=dict(r,**{'Also In':''})
M=D+'/iocs/state_actor_iocs.csv'; os.makedirs(D+'/iocs',exist_ok=True)
F=['Actor','Reported As','In Actor Set','Sponsor','State-Link','Type','Indicator','Malware','Context','Vendor','Report ID','Report','Report Date','Attribution Basis','Also In','Link','First Added']
old={}
if os.path.exists(M):
    for r in csv.DictReader(open(M,encoding='utf-8')): old[(r['Actor'],r['Type'],r['Indicator'].lower())]=r
excluded_reports={(r['vendor'],r['report']) for r in CUR.values() if r['action']=='exclude'}
final={}; added=removed=0
for k,r in old.items():
    if (r['In Actor Set']=='Yes' and r['Actor'] not in S) or (r['Vendor'],r['Report ID']) in excluded_reports:
        removed+=1; continue
    final[k]=dict(r,**{c:v for c,v in seen.pop(k,{}).items() if c!='First Added'})
for k,r in seen.items(): final[k]=dict(r,**{'First Added':TODAY}); added+=1
for r in final.values(): r['State-Link']=S[r['Actor']]['state-link-confidence'] if r['Actor'] in S else 'Vendor assessment'
out=sorted(final.values(),key=lambda r:(r['Sponsor'],r['Actor'].lower(),ORDER.get(r['Type'],99),r['Indicator']))
bad=sum(1 for r in out+excl for v in r.values() if isinstance(v,str) and not IL.cell_ok(v))
if bad: print(f'   actor IOCs: formula-like cells: {bad} - stopping'); sys.exit(3)
def write(path,rs,fl):
    b=io.StringIO(); w=csv.DictWriter(b,fieldnames=fl,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rs); s=b.getvalue()
    if not os.path.exists(path) or open(path,encoding='utf-8').read()!=s: open(path,'w',encoding='utf-8',newline='').write(s); return True
    return False
changed=write(M,out,F); write(ST+'/state_actors_iocs.csv',out,F)
EF=['Actor','Vendor','Report','Value','Why excluded','Context','Link']
write(ST+'/state_actors_ioc_exclusions.csv',sorted(excl,key=lambda r:(r['Why excluded'],r['Actor'])),EF)
write(ST+'/state_actors_ioc_reports.csv',[{'Vendor':a,'Report ID':b,'Actor':c} for a,b,c in used],['Vendor','Report ID','Actor'])
bt=collections.Counter(r['Type'] for r in out); bv=collections.Counter(r['Vendor'] for r in out)
print(f"   actor IOCs: {len(out)} ({added} new, {removed} removed), {len({r['Actor'] for r in out})} actors, {len(used)} reports; by type {dict(bt)}; by vendor {dict(bv)}; "
      f"excluded {dict(collections.Counter(r['Why excluded'] for r in excl))}; master {'updated' if changed else 'unchanged'}; formula-like cells: {bad}")
for k,v in sorted(stat.items()): print(f'      {k}: {v}')
write(ST+'/state_actors_ioc_reports_to_review.csv',[dict(zip(['Vendor','Report ID','Title'],r.split('|',2))) for r in review],['Vendor','Report ID','Title'])
print(f'      reports with state/espionage wording but no resolvable actor (review in data/curation/vendor_report_actors.csv): {len(review)} -> state_actors_ioc_reports_to_review.csv')
