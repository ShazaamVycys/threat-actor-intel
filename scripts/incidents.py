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
FEEDS={'talos':(D+'/ext/talos','https://github.com/Cisco-Talos/IOCs/blob/main/'),'unit42':(D+'/ext/unit42','https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/'),
       'eset':(D+'/ext/eset','https://github.com/eset/malware-ioc/tree/master/'),'volexity':(D+'/ext/volexity','https://github.com/volexity/threat-intel/tree/main/')}
CATS={'breach','data-theft','supply-chain','ransomware','extortion','crypto-theft','exploitation','malware-campaign','tool-abuse','espionage','destructive','ddos','other'}
ATTR={'STATE','STATE_ALIGNED','CRIMINAL','HACKTIVIST','INSIDER','UNATTRIBUTED','MIXED'}
TYPES=['sha256','sha1','md5','ipv4','ipv6','domain','url','email','file-name','user-agent','http-header','other']
n=lambda s:re.sub(r'[^a-z0-9]','',str(s).lower())
err=[]; bad=0
# ---------- text hygiene (same rules as the source safety checks)
CTRL=re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f​-‏‪-‮⁦-⁩﻿]')
def clean(s):
    s=CTRL.sub('',str(s if s is not None else '')).strip()
    return ' '.join(s.split())
def cell_ok(s): return not (s and s[0] in '=+-@\t\r')
# ---------- IOC normalisation
def refang(s):
    s=s.strip().strip('"\'<>,;')
    s=re.sub(r'(?i)\[(\.|dot)\]|\((\.|dot)\)|\{\.\}','.',s); s=re.sub(r'\[:\]',':',s); s=re.sub(r'(?i)\[(@|at)\]','@',s)
    s=re.sub(r'(?i)^hxxp','http',s); s=re.sub(r'(?i)^fxp','ftp',s); s=s.replace('[/]','/')
    return s
def defang(t,v):
    if t in('ipv4',): return re.sub(r'\.(\d+)$',r'[.]\1',v)
    if t=='ipv6': return v.replace(':','[:]',1)
    if t in('domain','email'): return v.replace('.','[.]')
    if t=='url':
        m=re.match(r'(?i)(https?|ftp)://([^/]+)(.*)',v)
        if not m: return v.replace('.','[.]')
        return re.sub(r'(?i)^http','hxxp',m.group(1))+'://'+m.group(2).replace('.','[.]')+m.group(3)
    return v
BADTLD={'invalid','example','test','localhost','local','lan','internal','corp','home','arpa','onion'}
FILEEXT={'html','htm','js','php','asp','aspx','jsp','exe','dll','sys','ps1','bat','cmd','vbs','lnk','zip','rar','7z','txt','json','xml','pdf','doc','docx','xls','xlsx','png','jpg','gif','map','py','sh','so','bin','dat','tmp','iso','msi','jar','apk','yaml','yml','conf','log','css','svg'}
DOM=re.compile(r'^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$')
BENIGN={'microsoft.com','google.com','github.com','githubusercontent.com','virustotal.com','talosintelligence.com','paloaltonetworks.com','welivesecurity.com','eset.com',
        'volexity.com','cisco.com','apple.com','amazon.com','amazonaws.com','cloudflare.com','windows.net','office.com','live.com','mitre.org','w3.org','schema.org','example.com'}
def benign(d): return any(d==b or d.endswith('.'+b) for b in BENIGN)
def classify(t,v):
    """return (type, normalised value) or (None, reason)"""
    if t in('file-name','user-agent','http-header','other'):
        v=CTRL.sub('',v).strip()
        return (t,v) if 0<len(v)<=300 else (None,'empty or too long')
    v=refang(v); low=v.lower()
    if t in('sha256','sha1','md5','hash',''):
        L={64:'sha256',40:'sha1',32:'md5'}
        if re.fullmatch(r'[0-9a-fA-F]+',v) and len(v) in L and (t in('hash','') or L[len(v)]==t) and len(set(low))>3: return L[len(v)],low
        if t not in('',): return None,'not a valid '+(t or 'hash')
    if t in('ipv4','ipv6','ip',''):
        try: ip=ipaddress.ip_address(v.split('/')[0] if t else v)
        except ValueError: ip=None
        if ip:
            if not ip.is_global: return None,'private/reserved IP'
            return ('ipv4' if ip.version==4 else 'ipv6'),str(ip)
        if t: return None,'not a valid IP'
    if t in('domain',''):
        d=low.rstrip('.')
        if DOM.match(d):
            tld=d.rsplit('.',1)[1]
            if tld in BADTLD: return None,'placeholder/reserved TLD'
            if tld in FILEEXT: return None,'looks like a file name'
            if benign(d): return None,'well-known legitimate domain'
            return 'domain',d
        if t: return None,'not a valid domain'
    if t in('url',''):
        m=re.match(r'(?i)^(https?|ftp)://([^/:?#]+)',v)
        if m:
            h=m.group(2).lower()
            if benign(h): return None,'well-known legitimate domain'
            try:
                if not ipaddress.ip_address(h).is_global: return None,'private/reserved IP'
            except ValueError: pass
            return 'url',v
        if t: return None,'not a valid URL'
    if t in('email',''):
        if re.fullmatch(r'[^@\s]+@[a-z0-9.-]+\.[a-z]{2,}',low):
            if low.rsplit('.',1)[1] in BADTLD: return None,'placeholder/reserved TLD'
            return 'email',low
        if t: return None,'not a valid email'
    if t in('file-name','user-agent','http-header','other'):
        if 0<len(v)<=300: return t,v
        return None,'empty or too long'
    return None,'unrecognised type '+t
# ---------- feed readers (exact values from vendor repos)
STIX=re.compile(r"(ipv4-addr|ipv6-addr|domain-name|url|email-addr):value\s*=\s*'([^']+)'|file:hashes\.'?(SHA-256|SHA-1|MD5)'?\s*=\s*'([0-9A-Fa-f]+)'")
STYPE={'ipv4-addr':'ipv4','ipv6-addr':'ipv6','domain-name':'domain','url':'url','email-addr':'email','SHA-256':'sha256','SHA-1':'sha1','MD5':'md5'}
MISPT={'ip-dst':'ip','ip-src':'ip','domain':'domain','hostname':'domain','url':'url','link':None,'md5':'md5','sha1':'sha1','sha256':'sha256','email-src':'email','email-dst':'email','filename':'file-name','user-agent':'user-agent'}
NOTMAL=re.compile(r'(?i)\b(legitimate|benign|clean file|decoy|signed by microsoft|not malicious)\b')
def from_text(txt):
    head=''
    for line in txt.splitlines():
        s=line.strip()
        if not s: continue
        if re.fullmatch(r'[A-Z][A-Za-z0-9 &/()\-]{2,80}:',s) or (s.endswith(":") and len(s)<260): head=s.rstrip(':'); continue
        if re.match(r'(?i)^(https?://|- https?://)',s): continue          # plain reference links are sources, not IOCs
        ctx=lambda tok: clean((head+' — ' if head else '')+re.sub(r'\s+',' ',s.replace(tok,'').strip(' -–()'))[:200]).strip(' —')
        for m in re.finditer(r'([A-Za-z0-9-]+(?:\[\.\][A-Za-z0-9-]+)*)\[\.\]\(([a-z|]{2,40})\)',s):     # name[.](xyz|com)
            for tld in m.group(2).split('|'): yield 'domain',m.group(1)+'.'+tld,ctx(m.group(0))
        for m in re.finditer(r'(?<![0-9A-Fa-f])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])',s): yield 'hash',m.group(1),ctx(m.group(1))
        for m in re.finditer(r'(?<![\d.])(\d{1,3}(?:\[?\.\]?\d{1,3}){3})(?![\d.]|\[\.\])',s): yield 'ip',m.group(1),ctx(m.group(1))
        for m in re.finditer(r'(?i)\bhxxps?\[?:\]?//\S+',s): yield 'url',m.group(0).rstrip('.,);'),ctx(m.group(0))
        for m in re.finditer(r'(?i)(?<![\w@/.\[])((?:[a-z0-9-]+(?:\[\.\]|\.))+?[a-z0-9-]+\[\.\][a-z]{2,24})(?![\w(\[])',s):
            if '@' not in s[max(0,m.start()-1):m.start()] : yield 'domain',m.group(1),ctx(m.group(1))
        for m in re.finditer(r'(?i)\b([\w.+-]+\[@\][\w.-]+(?:\[\.\][a-z]{2,})+)',s): yield 'email',m.group(1),ctx(m.group(1))
def from_stix(d):
    rep=next((clean(o.get('name','')) for o in d.get('objects',[]) if o.get('type')=='report'),'')
    for o in d.get('objects',[]):
        if o.get('type')!='indicator': continue
        c=clean(o.get('name','') or o.get('description','') or ('Report: '+rep if rep else ''))[:200]
        for m in STIX.finditer(o.get('pattern','')):
            if m.group(1): yield STYPE[m.group(1)],m.group(2),c
            else: yield STYPE[m.group(3)],m.group(4),c
        for m in re.finditer(r"(?:src|dst)_ref\.value\s*=\s*'([^']+)'",o.get('pattern','')): yield '',m.group(1),c
def from_misp(d):
    evs=d if isinstance(d,list) else [d]
    for e in evs:
        e=e.get('Event',e) if isinstance(e,dict) else {}
        atts=list(e.get('Attribute',[]))
        for ob in e.get('Object',[]): atts+=ob.get('Attribute',[])
        for a in atts:
            t=a.get('type',''); v=a.get('value','')
            if '|' in t:
                for tt,vv in zip(t.split('|'),v.split('|')):
                    if MISPT.get(tt): yield MISPT[tt],vv,clean(a.get('comment',''))[:200]
            elif MISPT.get(t): yield MISPT[t],v,clean(a.get('comment',''))[:200]
def read_feed(ref):
    if ':' not in ref: raise ValueError('feed must look like talos:2026/11/report.json')
    k,rel=ref.split(':',1)
    if k not in FEEDS: raise ValueError('unknown feed '+k)
    base,web=FEEDS[k]; p=os.path.realpath(os.path.join(base,rel))
    if not p.startswith(os.path.realpath(base)+os.sep): raise ValueError('path escapes the feed folder')
    if not os.path.exists(p): return None,web+rel
    txt=open(p,encoding='utf-8',errors='replace').read()
    if p.endswith('.json'):
        d=json.loads(txt)
        return (list(from_stix(d)) if isinstance(d,dict) and 'objects' in d else list(from_misp(d))),web+rel
    return list(from_text(txt)),web+rel
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
