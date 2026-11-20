# Shared IOC helpers: validation, refang/defang, and readers for vendor IOC files (STIX, MISP JSON, plain text).
# Vendor files are read as text only, never executed.
import re,os,json,ipaddress,csv,subprocess,collections

def feeds(D):
    return {'talos':(D+'/ext/talos','https://github.com/Cisco-Talos/IOCs/blob/main/'),'unit42':(D+'/ext/unit42','https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/'),
            'eset':(D+'/ext/eset','https://github.com/eset/malware-ioc/tree/master/'),'volexity':(D+'/ext/volexity','https://github.com/volexity/threat-intel/tree/main/')}
FEEDS={}

TYPES=['sha256','sha1','md5','ipv4','ipv6','domain','url','email','file-name','user-agent','http-header','docker-image','app-id','other']
n=lambda s:re.sub(r'[^a-z0-9]','',str(s).lower())
# ---------- text hygiene (same rules as the source safety checks)
CTRL=re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f​-‏‪-‮⁦-⁩﻿]')
def clean(s):
    s=CTRL.sub('',str(s if s is not None else '')).strip()
    return ' '.join(s.split())
def cell_ok(s): return not (s and s[0] in '=+-@\t\r')
# ---------- IOC normalisation
def refang(s):
    s=s.strip().strip('"\'<>,;')
    s=re.sub(r'\[:?//\]|\[://\]','://',s); s=s.replace('[://]','://')
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
FILEEXT={'html','htm','js','php','asp','aspx','jsp','exe','dll','sys','ps1','bat','cmd','vbs','lnk','zip','rar','7z','txt','json','xml','pdf','doc','docx','xls','xlsx','png','jpg','gif','map','py','sh','so','bin','dat','tmp','iso','msi','jar','apk','yaml','yml','conf','log','css','svg','ini','mod','cfg','inf','bak','lst','vbe','wsf','hta','sct','ocx','cpl','scr','drv','dmp','plist','dylib','rtf','docm','xlsm','pptx','ppt','csv','sqlite','jpeg','bmp','ico','b64','enc','pem','crt','cer','tar','gz','cab','vhd','vhdx','img'}
DOM=re.compile(r'^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$')
BENIGN={'microsoft.com','google.com','github.com','githubusercontent.com','virustotal.com','talosintelligence.com','paloaltonetworks.com','welivesecurity.com','eset.com',
        'volexity.com','cisco.com','apple.com','amazon.com','amazonaws.com','cloudflare.com','windows.net','office.com','live.com','mitre.org','w3.org','schema.org','example.com'}
def benign(d): return any(d==b or d.endswith('.'+b) for b in BENIGN)
def classify(t,v):
    """return (type, normalised value) or (None, reason)"""
    if t in('file-name','user-agent','http-header','docker-image','app-id','other'):
        v=CTRL.sub('',v).strip()
        return (t,v) if 0<len(v)<=300 else (None,'empty or too long')
    v=refang(v); low=v.lower()
    if t=='url' and not re.match(r'(?i)^(https?|ftp)://',v): t=''          # vendor 'url' rows that are bare hosts or IPs
    if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}:\d{1,5}',v): v=v.rsplit(':',1)[0]; low=v
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
            h=m.group(2).lower(); path=v[m.end():]
            if benign(h) and len(path.strip('/'))<4: return None,'well-known legitimate domain'   # a specific path on a legitimate host (e.g. an attacker's GitHub file) is kept
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
    if t in('file-name','user-agent','http-header','docker-image','app-id','other'):
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
        if s.startswith(':') or s.startswith('//'): continue                                    # asciidoc attributes / comments
        if re.fullmatch(r'[A-Z][A-Za-z0-9 &/()\-]{2,80}:',s) or (s.endswith(":") and len(s)<260): head=s.rstrip(':').lstrip('=# '); continue
        if re.match(r'(?i)^(https?://|- https?://)',s): continue          # plain reference links are sources, not IOCs
        if re.fullmatch(r"[=#]*\s*[A-Za-z][\w &()'+,:-]{1,70}",s) and not re.search(r'[0-9A-Fa-f]{32}',s): head=s.strip(' -*#=:'); continue   # short label line (malware name / heading above a hash block); no dots, slashes or IOC-like text
        ctx=lambda tok: clean((head+' — ' if head else '')+re.sub(r'[`|+]{1,}',' ',re.sub(r'\s+',' ',s.replace(tok,'').strip(' -–()')))[:200]).strip(' —')
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
def read_text_file(p):
    """IOCs from one vendor file by extension"""
    txt=open(p,encoding='utf-8',errors='replace').read()
    if p.endswith('.json'):
        try: d=json.loads(txt)
        except ValueError: return list(from_text(txt))
        return list(from_stix(d)) if isinstance(d,dict) and 'objects' in d else list(from_misp(d))
    return list(from_text(txt))
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
# ---------- report enumeration: (vendor, report id, title, date, [files])
def git_files(d):
    return subprocess.run(['git','-C',d,'ls-files'],capture_output=True,text=True).stdout.split('\n') if os.path.isdir(d+'/.git') else []
def vendor_reports(EXT):
    t=EXT+'/talos'; grp=collections.defaultdict(list)
    for f in git_files(t):
        if re.match(r'\d{4}/\d\d/',f) and f.endswith(('.json','.txt','.csv')): grp[f.rsplit('.',1)[0]].append(f)
    for base,fs in sorted(grp.items()):
        title=os.path.basename(base).replace('-',' ').replace('_',' '); date=base[:7]
        j=base+'.json'
        if j in fs:
            try:
                for o in json.load(open(os.path.join(t,j))).get('objects',[]):
                    if o.get('type')=='report': title=clean(o.get('name',title)); date=(o.get('published') or date)[:10]
            except Exception: pass
        yield 'Cisco Talos',base,title,date,[(os.path.join(t,f),f) for f in sorted(fs)]
    u=EXT+'/unit42'
    for f in git_files(u):
        if re.match(r'\d{4}-\d\d-\d\d',f) and f.endswith('.txt'):
            first=open(os.path.join(u,f),encoding='utf-8',errors='replace').readline()
            yield 'Unit 42',f,clean(re.sub(r'^\d{4}-\d\d-\d\d\s*(\([A-Za-z]+\))?:?\s*','',first)) or f,f[:10],[(os.path.join(u,f),f)]
    v=EXT+'/volexity'; grp=collections.defaultdict(list)
    for f in git_files(v):
        parts=f.split('/')
        if len(parts)>=3 and re.fullmatch(r'\d{4}',parts[0]) and f.endswith(('.csv','.txt')): grp['/'.join(parts[:2])].append(f)
    for base,fs in sorted(grp.items()):
        nm=base.split('/')[1]; m=re.match(r'(\d{4}-\d\d-\d\d)\s*[-–]?\s*(.*)',nm)
        yield 'Volexity',base,(m.group(2) if m else nm),(m.group(1) if m else base[:4]),[(os.path.join(v,f),f) for f in sorted(fs)]
    e=EXT+'/eset'; grp=collections.defaultdict(list)
    for f in git_files(e):
        if '/' in f and (f.endswith(('.adoc','.txt','.csv')) or re.search(r'samples\.(md5|sha1|sha256)$',f)): grp[f.split('/')[0]].append(f)
    for top,fs in sorted(grp.items()):
        title=top
        rd=os.path.join(e,top,'README.adoc')
        if os.path.exists(rd):
            for l in open(rd,encoding='utf-8',errors='replace'):
                if l.startswith('= ') or l.startswith('== '): title=clean(l.lstrip('= ')); break
        yield 'ESET',top,title,'',[(os.path.join(e,f),f) for f in sorted(fs)]
# ---------- IOC extraction from one file
TICK=re.compile(r'`(?:\+\+)?([^`+\s|]{4,300}?)(?:\+\+)?`')
def extract_file(p,rel=None):
    out=[]
    if p.endswith('.csv'):
        try:
            rows=list(csv.DictReader(open(p,encoding='utf-8-sig',errors='replace')))
            if rows and 'value' in rows[0] and 'entity_type' in rows[0]:
                T={'file':'hash','hostname':'domain','ipaddress':'ip','url':'url','emailsender':'email','emailwhois':'email'}
                for r in rows:
                    v=(r.get('value') or '').strip(); t=T.get((r.get('entity_type') or '').strip(),'')
                    if t=='url' and re.fullmatch(r'[\d.]+:\d+',v): t,v='ip',v.split(':')[0]
                    if t=='url' and not re.match(r'(?i)^(https?|hxxps?|ftp)',v): t='domain' if '/' not in v else ''
                    out.append((t,v,clean(r.get('description',''))[:200]))
                return out
        except Exception: pass
    txt=open(p,encoding='utf-8',errors='replace').read()
    if p.endswith('.json'): return read_text_file(p)
    if re.search(r'samples\.(md5|sha1|sha256)$',p):
        return [('hash',l.strip(),'') for l in txt.splitlines() if l.strip()]
    out=list(from_text(txt))
    if p.endswith('.adoc'):                                   # ESET tables: values in backticks, not defanged
        head=''
        for line in txt.splitlines():
            if line.startswith('='): head=clean(line.lstrip('= '))
            cells=[c.strip() for c in line.split('|')]
            for m in TICK.finditer(line):
                val=m.group(1)
                if re.fullmatch(r'[0-9A-Fa-f]{32,64}',val): continue      # hashes already found by from_text
                desc=clean(' '.join(c for c in cells[-2:] if '`' not in c))[:200]
                out.append(('',val,(head+' — ' if head else '')+desc))
    return out
