# Builds the state-sponsored malware hash list from vendor IOC repositories (ESET, Cisco Talos, Volexity, Unit 42).
# Keeps only hashes of NAMED, custom malware tied to an actor in the current state-sponsored set; commercial,
# open-source, commodity and legitimate software is excluded (data/curation/cots_exclusions.txt).
# The master list data/hashes/state_malware_hashes.csv is cumulative: new hashes are added with today's date, existing rows
# keep their first_added date, and the file is only rewritten when something changed.
# Usage: hashes.py <data dir> <state out dir>
import csv,os,re,sys,json,collections,subprocess,datetime
D,ST=sys.argv[1:3]
EXT=D+'/ext'; SRC={'ESET':EXT+'/eset','Cisco Talos':EXT+'/talos','Volexity':EXT+'/volexity','Unit 42':EXT+'/unit42'}
URL={'ESET':'https://github.com/eset/malware-ioc/tree/master/','Cisco Talos':'https://github.com/Cisco-Talos/IOCs/blob/main/',
     'Volexity':'https://github.com/volexity/threat-intel/tree/main/','Unit 42':'https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/'}
TODAY=datetime.datetime.now(datetime.timezone.utc).date().isoformat()
n=lambda s:re.sub(r'[^a-z0-9]','',s.lower())
HX=re.compile(r'(?<![0-9A-Fa-f])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])')
TY={32:'md5',40:'sha1',64:'sha256'}
# ---- reference data from this build
S={x['actor']:x for x in csv.DictReader(open(ST+'/state_actors_summary.csv',encoding='utf-8-sig'))}
canon=dict(json.load(open(D+'/work/malware_maps.json'))['canon'])
amw=collections.defaultdict(set); users=collections.defaultdict(set); mtype={}
for x in csv.DictReader(open(ST+'/state_actors_malware.csv',encoding='utf-8-sig')):
    m=x['Malware / Tool']
    if m=='(none recorded)': continue
    canon.setdefault(n(m),m); c=canon[n(m)]; amw[x['Actor']].add(c); users[c].add(x['Actor']); mtype[c]=x['Type']
ALIAS=collections.defaultdict(set)
for x in csv.DictReader(open(ST+'/state_actors_alias_index.csv',encoding='utf-8-sig')): ALIAS[n(x['lookup_name'])].add(x['resolves_to'])
COTS={n(l) for l in open(D+'/curation/cots_exclusions.txt',encoding='utf-8') if l.strip() and not l.startswith('#')}
NOTMAL=re.compile(r'(?i)\b(legitimate|clean|benign|decoy|lure document|lure|bait document|signed by microsoft|vulnerable driver|original installer)\b')
WINBIN={'stealer','maldocs','maldoc','documents','reports','wiper','sha256','docx','none','delivery','imphash','windowsdriver','officerce','additionalmalicious','targetedsqllang','exfiltrationrpc','lures','images','resources','scripts','sample','tools','unknownfile','axinstsv','regsvr32','rundll32','svchost','user','users','admin','version','update','setup','install','test','windows','system','service','explorer','powershell','cmd','mshta','wscript','cscript','msiexec','conhost','dllhost','taskhost','winlogon','lsass','spoolsv','unknown','other','android','linux','macos','python','golang','java','first','second','stage','final','initial','backdoor','implant','trojan','stealer','downloader','webshell','shellcode','encrypted','decrypted','original','modified','legit','main','core','client','server','agent','payloads'}
GENERIC={'agent','trojandownloader','trojandropper','kryptik','spy','exploit','rozena','injector','genkryptik','packed','filecoder','shellcode','generik','dropper','downloader','backdoor','trojan','tiny','small','autorun','delf','obfuscated','htmlphish','phishing','pdf','pua','hacktool','riskware','rootkit','bat','lnk'}
# ESET folder names that are not an actor name in the alias index -> actor, per ESET's own report attribution
ESET_MAP={'dukes':'APT29','nukesped_lazarus':'Lazarus Group','interception':'Lazarus Group','okrum_ke3chang':'APT15','donot':'VICEROY TIGER',
 'aridspy':'AridViper','vajraspy':'QUILTED TIGER','industroyer':'Sandworm','dynowiper':'Sandworm','mythicratatoskr':'Sandworm',
 'deceptivedevelopment':'WageMole','sprysocks':'Earth Lusca'}
SKIP_DIRS={'quarterly_reports','exchange_exploitation'}            # reports that mix several actors
STOPNAMES={'chromium','snake','unknown','other','group','operation','campaign','malware','threat','actor','none'}
RX={k:re.compile(r'(?<![A-Za-z0-9])'+r'[\s_.-]*'.join(map(re.escape,re.findall(r'[A-Za-z0-9]+',v)))+r'(?![A-Za-z0-9])',re.I) for k,v in canon.items() if len(k)>=4}
isgroup=lambda c:any(k in ALIAS for k in (n(c),n(c)+'group',n(c)+'team'))
def family(label,actor,allow_alias=True):
    """known malware name appearing as a whole word in the label; prefer names linked to this actor; skip group names"""
    if not label: return ''
    label=re.sub(r'(?i)\S+\.(exe|dll|sys|ps1|js|vbs|bat|cmd|lnk|apk|jar|py|sh|elf|bin|dat|tmp|zip|rar|docx?|xlsx?|pdf|hta|msi|iso|vhdx?)\b',' ',label)
    cands=[]
    for d in re.findall(r'\b(?:Win32|Win64|MSIL|Linux|Android|OSX|MacOS|JS|VBS|PowerShell|Python|Java|PHP|BAT|LNK|HTML|Doc|iOS)/(?:[A-Za-z]+\.)?([A-Za-z][A-Za-z0-9_]{3,})',label):
        k=n(d)
        if k not in GENERIC and k in canon: cands.append(canon[k])
    for k in sorted(RX,key=len,reverse=True):
        if RX[k].search(label): cands.append(canon[k])
    cands=[c for c in cands if not isgroup(c) or (allow_alias and mtype.get(c)=='Malware' and c in amw.get(actor,()))]
    cands=[c for c in cands if n(c) not in WINBIN and n(c) not in GENERIC]
    if not cands: return ''
    mine=[c for c in cands if c in amw.get(actor,())]
    return (mine or cands)[0]
def clean_label(l):
    l=re.sub(r'[`*|]+',' ',l); l=re.sub(r'^[=.#\s]+|[:\s]+$','',l); return ' '.join(l.split())[:140]
JUNK=re.compile(r'(?i)^(sha-?1|sha-?256|md5|hash(es)?|samples?|file ?hashes|indicators.*|iocs?|network.*|domains?|ips?|c&c.*|c2.*|url.*|ip addresses|file names|registry.*|mutex.*|eset detection.*|$)')
def headed_hashes(text):
    """yield (hash,label) using table-row text or the nearest heading line above the hash block"""
    head=''
    for line in text.splitlines():
        s=line.strip(); hs=HX.findall(s)
        if hs:
            rest=clean_label(HX.sub(' ',s))
            lab=rest if len(rest)>3 and not re.fullmatch(r'[\w./\\-]{1,60}',rest or '') else ''
            lab=lab or (clean_label(rest)+' '+head if rest else head)
            for h in hs: yield h.lower(),lab.strip()
            continue
        if not s: continue
        if re.search(r'\[\.\]|https?://|^\d{1,3}(\.\d{1,3}){3}',s) or re.fullmatch(r'[\w.-]+\.[a-z]{2,}',s): continue
        c=clean_label(s)
        if not JUNK.match(c) and len(c)<=120: head=c
def pick(acts,hint=''):
    acts=[a for a in acts if a in S]
    for a in acts:
        if hint and n(a)==n(hint): return a
    return acts[0] if acts else None
def resolve(name):
    k=n(name); return ALIAS.get(k) or ALIAS.get(k+'group') or set()
def read(p): return open(p,encoding='utf-8',errors='replace').read()
rows=[]; stats=collections.Counter()
# ---- ESET: one folder per actor/campaign, samples.{md5,sha1,sha256} + README.adoc tables
E=SRC['ESET']
if os.path.isdir(E):
    lab={}
    for r,d,fs in os.walk(E):
        if '.git' in r: continue
        for f in fs:
            if f.endswith('.adoc'):
                for h,l in headed_hashes(read(os.path.join(r,f))): lab.setdefault(h,l)
    for r,d,fs in os.walk(E):
        if '.git' in r or 'samples.sha1' not in fs and 'samples.sha256' not in fs: continue
        rel=os.path.relpath(r,E).replace(os.sep,'/'); parts=rel.split('/'); top=parts[0]
        if top in SKIP_DIRS: continue
        a=pick([ESET_MAP[top]]) if top in ESET_MAP else None
        if not a:
            for p in reversed(parts):
                a=pick(sorted(resolve(p)),p)
                if a: break
        if not a: stats['eset folders not state-sponsored']+=1; continue
        cols={t:[l.strip().lower() for l in open(os.path.join(r,'samples.'+t)) if l.strip()] if os.path.exists(os.path.join(r,'samples.'+t)) else [] for t in ('md5','sha1','sha256')}
        main='sha1' if cols['sha1'] else 'sha256'; k=len(cols[main])
        aligned=all(len(v)==k for v in cols.values()) and not (k>3 and all(v==sorted(v) for v in cols.values()))
        for i in range(k):
            x={t:(cols[t][i] if aligned or t==main else '') for t in cols}
            x.update(actor=a,vendor='ESET',report=rel,link=URL['ESET']+rel,title='',label=lab.get(x['sha1']) or lab.get(x['sha256']) or lab.get(x['md5']) or '')
            rows.append(x)
# ---- Talos / Volexity / Unit 42: one file per report; actor from the report title (only single-actor reports)
APAT=[(re.compile(r'(?<![A-Za-z0-9])'+r'[\s\-_]*'.join(re.escape(c) for c in re.findall(r'[A-Za-z0-9]+',x['lookup_name']))+r'(?![A-Za-z0-9])',re.I),x['resolves_to'])
      for x in csv.DictReader(open(ST+'/state_actors_alias_index.csv',encoding='utf-8-sig'))
      if len(n(x['lookup_name']))>=5 and n(x['lookup_name']) not in STOPNAMES and not n(x['lookup_name']).isdigit()]
def reports():
    t=SRC['Cisco Talos']
    if os.path.isdir(t):
        for f in subprocess.run(['git','-C',t,'ls-files'],capture_output=True,text=True).stdout.split('\n'):
            if f.endswith('.txt') and re.match(r'\d{4}/\d\d/',f):
                p=os.path.join(t,f); title=os.path.basename(f)[:-4].replace('-',' ')
                j=p[:-4]+'.json'
                if os.path.exists(j):
                    try:
                        for o in json.load(open(j)).get('objects',[]):
                            if o.get('type')=='report': title=o.get('name',title)+' '+o.get('description','')[:400]
                    except Exception: pass
                yield 'Cisco Talos',f,title,p
    v=SRC['Volexity']
    if os.path.isdir(v):
        for r,d,fs in os.walk(v):
            if '.git' in r: continue
            for fn in fs:
                if fn.endswith(('.csv','.txt')):
                    p=os.path.join(r,fn); rel=os.path.relpath(p,v).replace(os.sep,'/'); body=read(p)
                    yield 'Volexity',rel,(rel.split('/')+[''])[1]+' '+' '.join(sorted(set(re.findall(r',([^,\n]{3,80}),',body)))[:50]),p
    u=SRC['Unit 42']
    if os.path.isdir(u):
        for fn in sorted(os.listdir(u)):
            p=os.path.join(u,fn)
            if os.path.isfile(p) and re.match(r'\d{4}',fn):
                yield 'Unit 42',fn,fn.replace('-',' ')+' '+'\n'.join(read(p).splitlines()[:20]),p
have={h for x in rows for h in (x['md5'],x['sha1'],x['sha256']) if h}
for vd,rp,title,p in reports():
    text=read(p); hs=sorted({h.lower() for h in HX.findall(text)})
    if not hs: continue
    acts={a for rx,a in APAT if rx.search(title)}
    if len(acts)!=1: stats[f'{vd} reports skipped (no single actor)']+=1; continue
    a=pick(acts)
    labels={}
    if p.endswith('.csv'):
        for x in csv.DictReader(text.splitlines()):
            vals=[v for v in x.values() if isinstance(v,str)]; h=next((v.strip() for v in vals if v and HX.fullmatch(v.strip())),None)
            if h: labels[h.lower()]=' '.join(v for v in vals if v and v.strip()!=h and v not in('file','sha256','md5','sha1'))
    else:
        for h,l in headed_hashes(text): labels.setdefault(h,l)
    tt=re.sub(r'[-_/]',' ',rp.rsplit('.',1)[0])
    for h in hs:
        if h in have: continue
        have.add(h); t=TY[len(h)]
        rows.append(dict(md5=h if t=='md5' else '',sha1=h if t=='sha1' else '',sha256=h if t=='sha256' else '',actor=a,vendor=vd,report=rp,link=URL[vd]+rp,label=labels.get(h,''),title=tt))
# ---- name + filter
SAFE=lambda v:("'"+v) if v[:1] in ('=','+','-','@') else re.sub(r'[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩]','',v)
kept={};excl=[];why=collections.Counter()
for x in rows:
    fam=family(x['label'],x['actor']); basis='named next to the hash in the source'
    if not fam and x['title']:
        tf=family(x['title'],x['actor'],allow_alias=False)
        if tf: fam,basis=tf,'named in the report title (whole report)'
    if not fam and x['vendor']=='ESET':
        tf=family(x['report'].replace('_',' ').replace('/',' '),x['actor'],allow_alias=False)
        if tf: fam,basis=tf,'named in the ESET report folder (whole report)'
    if not fam:
        raw=re.sub(r'(?i)\b(sample|samples|file|payload|hash(es)?|malware|exe|dll|js|ps1|htas?|lnks?|archives?|zip|rar|docs?|scripts?|installation|installer|loader|dropper|variant|component|module|plugin|agent|config(uration)?( file)?( for)?|startup script( for)?|x32|x64|32-bit|64-bit|v?\d+(\.\d+)*)\b','',x['label'])
        raw=' '.join(re.sub(r'(?i)^(encoded|decoded|packed|unpacked|new|old)\s+','',raw).split()).strip(' -:,.()')
        if re.fullmatch(r'[A-Za-z][A-Za-z0-9]{3,}( [A-Za-z][A-Za-z0-9]{2,})?',raw) and not isgroup(raw) and n(raw) not in GENERIC and n(raw) not in WINBIN and not NOTMAL.search(raw):
            fam,basis=raw,'name given in the source (not yet in MISP/ETDA/MITRE)'
    reason=''
    if not fam: reason='no malware name in the source'
    elif n(fam) in COTS: reason='commercial / open-source / commodity tool'
    elif mtype.get(fam)=='Tool': reason='listed as a tool, not malware'
    elif NOTMAL.search(x['label']): reason='source says the file is legitimate, a decoy or a lure'
    key=(x['sha256'] or x['sha1'] or x['md5'],x['actor'])
    if reason:
        why[reason]+=1; excl.append({'Name in source':fam,'Actor':x['actor'],'Why excluded':reason,'SHA256':x['sha256'],'SHA1':x['sha1'],'MD5':x['md5'],
            'Source detail':SAFE(x['label'][:200]),'Vendor':x['vendor'],'Report':x['report'],'Link':x['link']}); continue
    u=users.get(fam,set())
    kept[key]={'Malware':SAFE(fam),'Actor':x['actor'],
      'Known for this actor (MISP/ETDA/MITRE)':'Yes' if fam in amw.get(x['actor'],()) else 'No - from vendor report',
      'Malware sharing':'Unique to this actor' if u<={x['actor']} else 'Shared with other state actors: '+', '.join(sorted(u-{x['actor']})[:6])+(' …' if len(u)>7 else ''),
      'How the name was found':basis,'SHA256':x['sha256'],'SHA1':x['sha1'],'MD5':x['md5'],
      'Source detail':SAFE(x['label'][:200]),'Vendor':x['vendor'],'Report':x['report'],'Link':x['link']}
# ---- merge with the cumulative master list
M=D+'/hashes/state_malware_hashes.csv'; os.makedirs(D+'/hashes',exist_ok=True)
F=['Malware','Actor','Sponsor','State-Link','SHA256','SHA1','MD5','First Added','Known for this actor (MISP/ETDA/MITRE)','Malware sharing',
   'How the name was found','Source detail','Vendor','Report','Link']
old={}
if os.path.exists(M):
    for r in csv.DictReader(open(M,encoding='utf-8')): old[(r['SHA256'] or r['SHA1'] or r['MD5'],r['Actor'])]=r
added=removed=0; final={}
exkeys={(r['SHA256'] or r['SHA1'] or r['MD5'],r['Actor']) for r in excl if r['Why excluded']!='no malware name in the source'}
for k,r in old.items():                      # keep everything already recorded, unless its actor left the state set
    if r['Actor'] not in S or k in exkeys: removed+=1; continue
    final[k]=dict(r,**kept.pop(k,{}))       # refresh labels/naming if the source improved; keep First Added
for k,r in kept.items(): final[k]=dict(r,**{'First Added':TODAY}); added+=1
for r in final.values():
    s=S[r['Actor']]; r['Sponsor']=s['Suspected-State-Sponsor']; r['State-Link']=s['state-link-confidence']
    for h,L in (('SHA256',64),('SHA1',40),('MD5',32)):
        if r[h] and not re.fullmatch('[0-9a-f]{%d}'%L,r[h]): raise SystemExit(f'invalid {h}: {r[h]!r}')
out=sorted(final.values(),key=lambda r:(r['Sponsor'],r['Actor'].lower(),r['Malware'].lower(),r['SHA256'],r['SHA1'],r['MD5']))
def write(path,rs,fl):
    import io
    b=io.StringIO(); w=csv.DictWriter(b,fieldnames=fl,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rs)
    new=b.getvalue()
    if not os.path.exists(path) or open(path,encoding='utf-8').read()!=new: open(path,'w',encoding='utf-8',newline='').write(new); return True
    return False
changed=write(M,out,F)
write(ST+'/state_actors_malware_hashes.csv',out,F)
excl.sort(key=lambda r:(r['Why excluded'],r['Actor'].lower(),r['SHA256'],r['SHA1']))
write(ST+'/state_actors_malware_hash_exclusions.csv',excl,list(excl[0]) if excl else ['Why excluded'])
bad=sum(1 for r in out for v in r.values() if isinstance(v,str) and v and v[0] in '=+-@')
print(f"   hashes: {len(out)} kept ({added} new, {removed} removed (actor dropped or now excluded)), {len({r['Malware'] for r in out})} malware families, {len({r['Actor'] for r in out})} actors; "
      f"excluded {dict(why)}; master {'updated' if changed else 'unchanged'}; formula-like cells: {bad}")
for k,v in sorted(stats.items()): print(f'      {k}: {v}')
