import json,sys,re,csv,collections,glob,os,yaml
S,M=sys.argv[1],sys.argv[2]
norm=lambda s:re.sub(r'[^a-z0-9]','',s.lower())
nk=lambda s:(lambda k:(re.sub(r'(rat|backdoor|project)$','',k) if len(re.sub(r'(rat|backdoor|project)$','',k))>=4 else k))(norm(s))
eid=lambda o:next((r['external_id'] for r in o.get('external_references',[]) if r.get('source_name') in('mitre-attack','mitre-mobile-attack','mitre-ics-attack')),'')
clean=lambda t:' '.join(re.sub(r'\[([^\]]+)\]\([^)]+\)',r'\1',re.sub(r'\(Citation:[^)]*\)','',t or '')).split())
live=lambda o:o and not o.get('revoked') and not o.get('x_mitre_deprecated')
# ---------- actors ----------
rows=list(csv.DictReader(open(M+'/merged_all_actors.csv',encoding='utf-8-sig')))
A={r['actor']:r for r in rows}
gid2actor={r['mitre_id']:r['actor'] for r in rows if r['mitre_name']}
mal2actors=collections.defaultdict(set); maldisp={}
for r in rows:
    for n in r['malware'].split('; '):
        if n: mal2actors[nk(n)].add(r['actor']); maldisp.setdefault(nk(n),n)
GENERIC=set('apt group team unknown hacker hackers spider panda bear kitten dragon tiger china russia iran korea operation threat actor'.split())
name_idx={}  # lowercase name -> ('actor',set) / ('malware',key)
for r in rows:
    for n in [r['actor']]+r['aliases (all)'].split('; '):
        n=n.strip()
        if len(n)<5 or n.lower() in GENERIC or n.isdigit() or re.fullmatch(r'(?i)(TG|TA|UNC|DEV|Storm)-?\d{1,3}',n): continue
        name_idx.setdefault(('a',n.lower()),set()).add(r['actor'])
for k,n in maldisp.items():
    if len(n)>=5 and n.lower() not in GENERIC: name_idx.setdefault(('m',n.lower()),set()).add(k)
names_sorted=sorted(name_idx,key=lambda x:-len(x[1]))
def find_names(text):
    t=' '+re.sub(r'[_\-/]',' ',text.lower())+' '; hits=[]
    for kind,n in names_sorted:
        nn=re.sub(r'[_\-/]',' ',n)
        if nn in t and re.search(r'(?<![a-z0-9])'+re.escape(nn)+r'(?![a-z0-9])',t): hits.append((kind,n))
    return hits
# ---------- text extraction ----------
P=r'[^\s,;"\'<>()\]\[“”‘’`]+'
RX=[('Registry',re.compile(r'(?i)\b(?:HKLM|HKCU|HKU|HKCR|HKEY_[A-Z_]+)\\'+P)),
    ('File path',re.compile(r'(?i)(?<![\w%])(?:[A-Z]:\\|%[A-Z_]+%\\|\\\\\.\\pipe\\)'+P)),
    ('File path',re.compile(r'(?<![\w.])/(?:tmp|etc|var|usr|dev/shm|opt|lib|bin|sbin|root|home|Library|private|System)/'+P)),
    ('File name',re.compile(r'(?i)(?<![\w\\/%.-])[\w-][\w.-]{0,60}\.(?:exe|dll|sys|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|scr|tmp|dat|bin|ini|cfg|conf|log|py|sh|so|elf|jar|msi|docm|xlsm|iso|img|ocx|cpl|drv|plist|service|aspx|asp|php|jsp)\b')),
    ('Mutex',re.compile(r'(?i)mutex(?:es)?\b[^.]{0,40}?(`[^`]{3,80}`|"[^"]{3,80}"|“[^”]{3,80}”)')),
    ('Mutex',re.compile(r'(?i)mutex(?:es)?\s+(?:named|called)\s+([A-Za-z0-9_{}\\-]{4,80})')),
    ('Scheduled task',re.compile(r'(?i)(?:scheduled )?tasks?\s+(?:named|called|with the name)\s+(`[^`]{3,80}`|"[^"]{3,80}"|“[^”]{3,80}”|\\[^\s,;]+|[A-Za-z0-9_.-]{3,60})')),
    ('Service',re.compile(r'(?i)services?\s+(?:named|called|with the name)\s+(`[^`]{3,80}`|"[^"]{3,80}"|“[^”]{3,80}”|[A-Za-z0-9_.-]{3,60})')),
    ('Named pipe',re.compile(r'(\\\\\.\\pipe\\[^\s,;"”\'`]+)'))]
LOLBIN=set('cmd.exe powershell.exe rundll32.exe regsvr32.exe svchost.exe explorer.exe mshta.exe wscript.exe cscript.exe schtasks.exe at.exe net.exe net1.exe reg.exe sc.exe wmic.exe certutil.exe bitsadmin.exe msiexec.exe taskkill.exe tasklist.exe whoami.exe ipconfig.exe netstat.exe systeminfo.exe ping.exe nltest.exe vssadmin.exe wevtutil.exe conhost.exe lsass.exe winlogon.exe services.exe csrss.exe ntdll.dll kernel32.dll advapi32.dll user32.dll ws2_32.dll wininet.dll msvcrt.dll iexplore.exe winword.exe excel.exe outlook.exe notepad.exe calc.exe dllhost.exe taskhost.exe taskhostw.exe spoolsv.exe lsm.exe smss.exe userinit.exe ntoskrnl.exe msbuild.exe installutil.exe regasm.exe regsvcs.exe forfiles.exe expand.exe makecab.exe esentutl.exe ntdsutil.exe dsquery.exe adfind.exe psexec.exe procdump.exe 7z.exe rar.exe winrar.exe curl.exe tar.exe ssh.exe python.exe java.exe chrome.exe firefox.exe msedge.exe mimikatz.exe'.split())
SYSPATH=re.compile(r'(?i)^(%(systemroot|windir)%|c:\\windows)\\(system32|syswow64)\\[^\\]+\.(exe|dll)$')
def tidy(t,v):
    v=v.strip().strip('`"“”\'').rstrip('.:').strip()
    v=re.sub(r'[\\]+$','',v) if t!='Registry' else v.rstrip('\\')
    return v
def extract(text):
    out=[]; spans=[]
    for t,rx in RX:
        for m in rx.finditer(text):
            v=m.group(1) if m.groups() else m.group(0); v=tidy(t,v)
            if len(v)<4: continue
            if t=='File name' and any(a<=m.start()<b for a,b in spans): continue
            spans.append(m.span())
            s=max(0,m.start()-110); out.append((t,v,text[s:m.end()+110].strip()))
    return out
def note(t,v):
    b=v.lower().split('\\')[-1].split('/')[-1]
    if t.startswith(('File name','File path')) and b.strip('*') in LOLBIN and (t.startswith('File name') or SYSPATH.match(v) or v.lstrip('*\\').lower()==b.strip('*')): return 'Common system/dual-use binary - weak on its own'
    return ''
ART=[]   # dict(actor, type, value, attribution, source, context)
def add(actors,t,v,attr,src,ctx):
    for a in actors: ART.append(dict(actor=a,type=t,value=v,attr=attr,src=src,ctx=ctx))
# ---------- MITRE ----------
sid2name={}
for dom in ('enterprise','mobile','ics'):
    objs=json.load(open(f'{S}/mitre/{dom}-attack.json'))['objects']; by={o['id']:o for o in objs}
    camp2g={}
    for o in objs:
        if o['type']=='relationship' and o.get('relationship_type')=='attributed-to' and live(o):
            s,g=by.get(o['source_ref']),by.get(o['target_ref'])
            if live(s) and live(g) and s['type']=='campaign' and g['type']=='intrusion-set': camp2g.setdefault(s['id'],[]).append(eid(g))
    for o in objs:
        if o['type'] in('malware','tool') and live(o): sid2name[eid(o)]=(o['name'],o['type'])
    for o in objs:
        if o['type']!='relationship' or o.get('relationship_type')!='uses' or not live(o): continue
        s=by.get(o['source_ref'])
        if not live(s): continue
        txt=clean(o.get('description'))
        if not txt: continue
        ex=extract(txt)
        if not ex: continue
        if s['type']=='intrusion-set':
            acts={gid2actor[eid(s)]} if eid(s) in gid2actor else set(); attr='Actor (documented)'; src=f'MITRE ATT&CK procedure ({eid(s)})'
        elif s['type']=='campaign':
            acts={gid2actor[g] for g in camp2g.get(s['id'],[]) if g in gid2actor}; attr='Actor (documented)'; src=f'MITRE ATT&CK campaign {eid(s)} {s["name"]}'
        elif s['type']=='malware':
            acts=mal2actors.get(nk(s['name']),set()); attr=f'Via malware: {s["name"]}'; src=f'MITRE ATT&CK software {eid(s)}'
        else: continue
        for t,v,c in ex: add(acts,t,v,attr,src,c)
# ---------- ETDA tool descriptions ----------
for v in json.load(open(f'{S}/etda/etda_tools.json'))['values']:
    cat=v['meta'].get('category'); cat=cat if isinstance(cat,str) else ' '.join(cat or [])
    if cat!='Malware': continue
    nm=v['value'].split(',')[0].strip(); acts=mal2actors.get(nk(nm),set())
    if not acts: continue
    for t,val,c in extract(' '.join((v.get('description') or '').split())): add(acts,t,val,f'Via malware: {nm}','ETDA tool card',c)
# ---------- Sigma ----------
FIELDS={'TargetObject':'Registry','TargetFilename':'File path','ImageLoaded':'File path','Image':'File path','OriginalFileName':'File name','PipeName':'Named pipe','ServiceName':'Service','ServiceFileName':'File path','ImagePath':'File path','TaskName':'Scheduled task','FileName':'File name'}
def walk(sel,out):
    if isinstance(sel,list):
        for x in sel: walk(x,out)
    elif isinstance(sel,dict):
        for k,val in sel.items():
            f,*mods=k.split('|')
            if f in FIELDS:
                vals=val if isinstance(val,list) else [val]
                for x in vals:
                    if not isinstance(x,str) or len(x)<4: continue
                    x=('*' if ('contains' in mods or 'endswith' in mods) else '')+x+('*' if ('contains' in mods or 'startswith' in mods) else '')
                    out.append((FIELDS[f],x))
nsig=0
for f in glob.glob(f'{S}/ext/sigma/rules*/**/*.yml',recursive=True):
    try: r=yaml.safe_load(open(f,encoding='utf-8'))
    except Exception: continue
    if not isinstance(r,dict) or not isinstance(r.get('detection'),dict): continue
    tags=[str(t).lower() for t in r.get('tags') or []]
    acts=set(); attr=None
    for t in tags:
        m=re.fullmatch(r'attack\.(g\d{4})',t)
        if m and m.group(1).upper() in gid2actor: acts.add(gid2actor[m.group(1).upper()]); attr='Actor (Sigma rule tag)'
    rel=os.path.relpath(f,f'{S}/ext/sigma'); parts=rel.split(os.sep)
    via=None
    if not acts and 'rules-emerging-threats' in parts:
        folder=parts[-2] if parts[-3] in('TA','Malware') else ''
        hits=find_names(folder+' '+str(r.get('title','')))
        a_hits=[h for h in hits if h[0]=='a']; m_hits=[h for h in hits if h[0]=='m']
        if a_hits:
            for h in a_hits: acts|=name_idx[h]
            attr='Actor (Sigma rule name)'
        elif m_hits:
            k=next(iter(name_idx[m_hits[0]])); acts=mal2actors[k]; via=maldisp[k]; attr=f'Via malware: {via}'
    if not acts: continue
    out=[]
    for k,sel in r['detection'].items():
        if k in('condition','timeframe') or k.lower().startswith('filter'): continue
        walk(sel,out)
    for t,v in out: add(acts,t,v,attr,f'Sigma: {r.get("title","")} ({rel})',str(r.get('description',''))[:220]); nsig+=1
# ---------- signature-base filename IOCs ----------
section=''; nsb=0
for line in open(f'{S}/ext/sb/iocs/filename-iocs.txt',encoding='utf-8',errors='replace'):
    line=line.rstrip('\n')
    if line.startswith('#'):
        if len(line.strip('# -'))>2: section=line.strip('# ').strip()
        continue
    if not line.strip() or ';' not in line: continue
    rx=line.rsplit(';',2)[0] if line.count(';')>=2 else line.rsplit(';',1)[0]
    hits=find_names(section)
    a_hits=[h for h in hits if h[0]=='a']; m_hits=[h for h in hits if h[0]=='m']
    if a_hits: acts=set().union(*[name_idx[h] for h in a_hits]); attr='Actor (signature-base section)'
    elif m_hits: k=next(iter(name_idx[m_hits[0]])); acts=mal2actors[k]; attr=f'Via malware: {maldisp[k]}'
    else: continue
    readable=re.sub(r'\(\?i\)','',rx).replace('\\\\','\\').replace('\\.','.')
    t='Registry' if re.search(r'(?i)HK(LM|CU|EY)',readable) else ('File path' if '\\' in readable or '/' in readable else 'File name')
    add(acts,t+' (regex)',rx,attr,f'signature-base filename-iocs: {section}',readable); nsb+=1
print('raw artifacts',len(ART),'sigma',nsig,'sigbase',nsb)
# ---------- dedupe + write ----------
key=lambda x:(x['actor'],x['type'].replace(' (regex)',''),x['value'].lower())
D=collections.OrderedDict()
for x in ART:
    k=key(x); d=D.setdefault(k,dict(x,srcs=[],attrs=[]))
    if x['src'] not in d['srcs']: d['srcs'].append(x['src'])
    if x['attr'] not in d['attrs']: d['attrs'].append(x['attr'])
state=[r['actor'] for r in csv.DictReader(open(M+'/merged_state_sponsored.csv',encoding='utf-8-sig'))]; oi={a:i for i,a in enumerate(state)}
TO={'Registry':0,'File path':1,'File name':2,'Mutex':3,'Named pipe':4,'Service':5,'Scheduled task':6}
recs=[]
for d in D.values():
    r=A[d['actor']]; actor_doc=any(a.startswith('Actor') for a in d['attrs'])
    recs.append({'Actor':d['actor'],'Artifact Type':d['type'],'Artifact':d['value'],
      'Attribution':'Actor (documented)' if actor_doc else '; '.join(dict.fromkeys(d['attrs']))[:200],
      'Note':note(d['type'],d['value']),'Source':' | '.join(d['srcs'][:4])+(' | …' if len(d['srcs'])>4 else ''),'Source Count':len(d['srcs']),
      'Suspected State Sponsor':r['Suspected-State-Sponsor'],'State-Link Confidence':r['state-link-confidence'],'MITRE ID':r['mitre_id'],'Context':d['ctx'][:400]})
# ---------- uniqueness: is this artifact seen for one actor only, or shared? ----------
def ukey(v):   # compare values regardless of case, wildcards and doubled backslashes
    v=v.lower().replace('\\\\','\\').strip('*').strip('\\').strip()
    return re.sub(r'^(hkey_local_machine|hklm)\\',r'hklm\\',re.sub(r'^(hkey_current_user|hkcu)\\',r'hkcu\\',v))
# standard persistence keys / everyday folders: never distinctive on their own, even if only one actor lists them
GEN_REG=re.compile(r'(?i)^hk(lm|cu)\\(software\\(wow6432node\\)?microsoft\\windows( nt)?\\currentversion\\(run|runonce|runservices|winlogon|explorer\\shell folders|explorer\\user shell folders|image file execution options|policies\\explorer\\run|windows)|system\\currentcontrolset\\(services|control\\(session manager|lsa|terminal server)))\\?$')
GEN_DIR=re.compile(r'(?i)^(%(temp|tmp|appdata|localappdata|programdata|public|userprofile|systemroot|windir|programfiles|allusersprofile|startup)%|[a-z]:\\(windows(\\(system32|syswow64|temp|tasks))?|programdata|users\\public|users|temp|program files( \(x86\))?|perflogs)|/(tmp|var/tmp|dev/shm|etc|usr/bin|usr/lib|bin|sbin|root|home|opt))\\?/?$')
GEN_NAME=re.compile(r'(?i)^(\\)?(\*?\.(exe|dll|ps1|bat|vbs|js|lnk|tmp|dat|zip|rar|txt|log|ini)|[a-z]{1,3}\.(exe|dll))$')
GEN_FILE=re.compile(r'(?i)^(/?(usr/)?s?bin/[\w.+-]+|/?var/log/[\w./-]*|/?etc/(passwd|shadow|hosts|crontab|rc\.local|profile|ld\.so\.preload|resolv\.conf|sudoers)|(auth|syslog|secure|messages|wtmp|utmp|btmp|lastlog)(\.log)?|\.?bash_history|\.bashrc|\.profile|desktop\.ini|thumbs\.db|ntuser\.dat|hosts)$')
users=collections.defaultdict(set)
for x in recs: users[ukey(x['Artifact'])].add(x['Actor'])
for x in recs:
    k=ukey(x['Artifact']); others=sorted(users[k]-{x['Actor']},key=str.lower)
    if x['Note']: u='Common - system/dual-use binary'
    elif GEN_REG.match(k) or GEN_DIR.match(k) or GEN_NAME.match(k) or GEN_FILE.match(k) or len(k)<4: u='Common - standard location or name'
    elif not others: u='Unique to this actor'
    else: u=f'Shared ({len(others)+1} actors)'
    x['Uniqueness']=u; x['Shared With']='; '.join(others[:10])+(f' … (+{len(others)-10})' if len(others)>10 else '')
srt=lambda x:(x['Actor'].lower(),x['Uniqueness']!='Unique to this actor',x['Attribution']!='Actor (documented)',x['Note']!='',TO.get(x['Artifact Type'].replace(' (regex)',''),9),x['Artifact'].lower())
recs.sort(key=srt)
F=['Actor','Artifact Type','Artifact','Uniqueness','Shared With']+[k for k in recs[0] if k not in('Actor','Artifact Type','Artifact','Uniqueness','Shared With')]
def w(p,rs):
    with open(p,'w',newline='',encoding='utf-8-sig') as f:
        x=csv.DictWriter(f,fieldnames=F);x.writeheader();x.writerows(rs)
w(M+'/actor_host_artifacts_all.csv',recs)
st=sorted([x for x in recs if x['Actor'] in oi],key=lambda x:(oi[x['Actor']],)+srt(x)[1:]); w(M+'/actor_host_artifacts_state_sponsored.csv',st)
C=collections.Counter
print('deduped',len(recs),'state',len(st),'actors',len({x['Actor'] for x in recs}),'state actors',len({x['Actor'] for x in st}))
print(C(x['Artifact Type'] for x in recs)); print(C('documented' if x['Attribution'].startswith('Actor') else 'via malware' for x in recs))
print('weak',sum(1 for x in recs if x['Note']))
print('uniqueness',C(x['Uniqueness'].split(' (')[0] for x in recs),'| state',C(x['Uniqueness'].split(' (')[0] for x in st))
json.dump({a:sum(1 for x in recs if x['Actor']==a) for a in A},open(M+'/_art_summary.json','w'))
