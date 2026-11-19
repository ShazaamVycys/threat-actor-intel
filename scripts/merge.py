import json,sys,re,csv,collections
misp=json.load(open(sys.argv[1]))['values']; etda=json.load(open(sys.argv[2]))['values']; out=sys.argv[3]; mitre=json.load(open(sys.argv[4]))['groups']; MW=json.load(open(sys.argv[5]))
norm=lambda s:re.sub(r'(group|team|gang)$','',re.sub(r'[^a-z0-9]','',s.lower())) or re.sub(r'[^a-z0-9]','',s.lower())
def clean(n): return ' '.join(n.split()).strip(' ,;')
# ---- reviewed attribution research (data/curation/actor_attribution_review.csv): drops criminal / hacktivist /
#      unattributed actors from the state set and records the researched basis for the ones kept
import os
_rp=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','data','curation','actor_attribution_review.csv')
REVIEW={x['actor']:x for x in csv.DictReader(open(_rp,encoding='utf-8'))} if os.path.exists(_rp) else {}
REVIEW_DROP={'CRIMINAL','HACKTIVIST','NO_ATTRIBUTION','NOT_FOUND'}
REVIEW_KEEP={'STATE_ATTRIBUTED':('High','attributed to a state'),'STATE_ATTRIBUTED_CONTESTED':('Medium','attributed by an adversary government only (contested)'),'STATE_ALIGNED_ASSESSED':('Medium','assessed state-aligned'),'HYBRID':('Medium','hybrid: crime + state-aligned espionage')}
tier_rank={'High':0,'Medium':1,'Low':2}
# ---- MISP names
M=[]
for v in misp:
    m=v.get('meta',{}); prim=clean(v['value'])
    c=[prim]+list(m.get('synonyms') or [])+[x.rsplit(':',1)[0] for x in (m.get('name-attribution') or [])]+[k[7:] for k in m if k.startswith('origin:')]
    M.append(dict(uuid=v['uuid'],primary=prim,names=[clean(x) for x in c if clean(x)],meta=m,desc=' '.join((v.get('description') or '').split())))
# ---- ETDA names
E=[]
for v in etda:
    m=v.get('meta',{}); parts=[clean(x) for x in v['value'].split(',')]
    c=parts+list(m.get('synonyms') or [])
    card=next((r for r in m.get('refs',[]) if 'apt.etda.or.th' in r),'')
    E.append(dict(uuid=v['uuid'],primary=parts[0],names=list(dict.fromkeys(clean(x) for x in c if clean(x))),meta=m,desc=' '.join((v.get('description') or '').split()),card=card))
idx=collections.defaultdict(set)
for i,a in enumerate(M):
    for n in a['names']: idx[norm(n)].add(i)
prim_idx=collections.defaultdict(set)
for i,a in enumerate(M): prim_idx[norm(a['primary'])].add(i)
GENERIC={'grizzlysteppe','unknown','apt','plaunit61398'}
match={}; claimed=collections.defaultdict(list)
for j,e in enumerate(E):
    keys={norm(n) for n in e['names']}-GENERIC
    score=collections.Counter()
    for k in keys:
        hits=idx.get(k,set())
        w=1.0/len(hits) if hits else 0
        for i in hits: score[i]+=w
    for i in prim_idx.get(norm(e['primary']),()): score[i]+=3
    for k in {norm(n) for n in e['names'][1:3]}-{norm(e['primary'])}:
        for i in prim_idx.get(k,()): score[i]+=1.5
    for i in list(score): score[i]+=len(M[i]['names'])*1e-4   # tie-break: richer MISP entry
    if not score: continue
    (best,s),*rest=score.most_common(2)+[(None,0)]
    second=rest[0][1] if rest else 0
    if s>=1 and s>second: match[j]=best; claimed[best].append((s,j))
# ---- one ETDA per MISP actor; the rest stay separate with an overlap note
groups=[]; overlap={}
for i,a in enumerate(M):
    c=sorted(claimed.get(i,[]),key=lambda x:(norm(E[x[1]]['primary'])==norm(a['primary']),x[0]),reverse=True)
    if c:
        groups.append(dict(m=a,e=E[c[0][1]],note=''))
        for _,j in c[1:]: overlap[j]=a['primary']
    else: groups.append(dict(m=a,e=None,note=''))
for j,e in enumerate(E):
    if j not in match: groups.append(dict(m=None,e=e,note=''))
    elif j in overlap: groups.append(dict(m=None,e=e,note='ETDA tracks separately; MISP folds into '+overlap[j]))

print('MISP',len(M),'ETDA',len(E),'matched ETDA',len(match),'unmatched ETDA',len(E)-len(match),'MISP w/ >1 ETDA',sum(1 for v in claimed.values() if len(v)>1))
import random;random.seed(2);print('unmatched sample',[E[j]['primary'] for j in random.sample([j for j in range(len(E)) if j not in match],30)])
import pickle; pickle.dump((groups,),open(out+'/_groups.pkl','wb'))

# ================= build outputs =================
NORM={'Iran (Islamic Republic of)':'Iran','Russian Federation':'Russia',"Korea (Democratic People's Republic of)":'North Korea','Korea (Republic of)':'South Korea',"People's Republic of China":'China','US':'United States'}
CC={'CN':'China','RU':'Russia','IR':'Iran','KP':'North Korea','KR':'South Korea','VN':'Vietnam','IN':'India','PK':'Pakistan','LB':'Lebanon','TR':'Turkey','BY':'Belarus','US':'United States','IL':'Israel','AE':'United Arab Emirates','PS':'Palestine','UA':'Ukraine','GB':'United Kingdom','FR':'France','ES':'Spain','SY':'Syria','KZ':'Kazakhstan','SA':'Saudi Arabia','EG':'Egypt','TW':'Taiwan','ID':'Indonesia','NG':'Nigeria','BR':'Brazil','DE':'Germany','IQ':'Iraq','MA':'Morocco','LY':'Libya','TN':'Tunisia','RO':'Romania'}
VENDOR=[(r'\bTyphoon$','China','Microsoft'),(r'\bBlizzard$','Russia','Microsoft'),(r'\bSandstorm$','Iran','Microsoft'),(r'\bSleet$','North Korea','Microsoft'),
 (r'\bHail$','South Korea','Microsoft'),(r'\bCyclone$','Vietnam','Microsoft'),(r'\bDust$','Turkey','Microsoft'),(r'\bRain$','Lebanon','Microsoft'),
 (r'(?i)\bpanda$','China','CrowdStrike'),(r'(?i)\bbear$','Russia','CrowdStrike'),(r'(?i)\bkitten$','Iran','CrowdStrike'),(r'(?i)\bchollima$','North Korea','CrowdStrike'),
 (r'(?i)\bleopard$','Pakistan','CrowdStrike'),(r'(?i)\bbuffalo$','Vietnam','CrowdStrike'),(r'(?i)\bcrane$','South Korea','CrowdStrike'),
 (r'(?i)\btaurus$','China','Unit 42'),(r'(?i)\bursa$','Russia','Unit 42'),(r'(?i)\bserpens$','Iran','Unit 42'),(r'(?i)\bpisces$','North Korea','Unit 42'),
 (r'(?i)\bmanticore$','Iran','Check Point'),(r'(?i)^BRONZE ','China','Secureworks'),(r'(?i)^IRON ','Russia','Secureworks'),(r'(?i)^COBALT ','Iran','Secureworks'),(r'(?i)^NICKEL ','North Korea','Secureworks')]
MANDIANT=re.compile(r'^APT ?\d+$')
CRIME=re.compile(r'(?i)(\bspider$|\btempest$|^GOLD |^FIN ?\d+$)')
NOTSTATE=re.compile(r'(?i)hacktivis|DDoS|pro-[A-Z][a-z]+ hack|financially motivated|ransomware|cybercrim|fraud|banking|leaks? regarding')
STATEWORDS=re.compile(r'(?i)espionage|regime|state[- ]sponsored|nation[- ]state')
DESC=re.compile(r'(?i)state[- ]sponsored|nation[- ]state|state[- ]backed|government[- ]backed|state[- ]linked|\bMSS\b|Ministry of State Security|\bGRU\b|\bFSB\b|\bSVR\b|\bIRGC\b|Reconnaissance General Bureau|PLA Unit')
HACK=re.compile(r'(?i)anonymous|\bteam\b|squad|army|cyber ?(fighters|islamic|berkut|av3ngers|serp)|hackers?\b|kill3rs|resistance|ababil|edalat|\bcrew\b')


def L(x): return x if isinstance(x,list) else ([x] if x else [])
GID=re.compile(r'^G\d{4}$')
# ---------- MITRE matching ----------
for g in groups: g['t']=None
def gnames(g):
    ns=[]
    if g['m']: ns+=g['m']['names']
    if g['e']: ns+=g['e']['names']
    return ns
gprim=lambda g:(g['m'] or g['e'])['primary']
gidx=collections.defaultdict(set); gid_idx=collections.defaultdict(set); gprim_idx=collections.defaultdict(set)
for i,g in enumerate(groups):
    for n in gnames(g):
        (gid_idx if GID.match(n) else gidx)[n if GID.match(n) else norm(n)].add(i)
    for n in ([g['m']['primary']] if g['m'] else [])+([g['e']['primary']] if g['e'] else []): gprim_idx[norm(n)].add(i)
tmatch={}; extra=[]
mitre=sorted(mitre,key=lambda t:(norm(t['actor']) not in gprim_idx, t['mitre_id']))
for t in mitre:
    names=[t['actor']]+[a for a in t['aliases'].split('; ') if a]
    sc=collections.Counter()
    for i in gprim_idx.get(norm(t['actor']),()): sc[i]+=5
    for i in gid_idx.get(t['mitre_id'],()): sc[i]+=3/len(gid_idx[t['mitre_id']])
    for n in names:
        k=norm(n)
        if k in GENERIC: continue
        h=gidx.get(k,set())
        for i in h: sc[i]+=1/len(h)
    for i in list(sc): sc[i]+= (0.5 if groups[i]['m'] else 0) + len(gnames(groups[i]))*1e-4
    best=[i for i,_ in sc.most_common() if groups[i]['t'] is None]
    if best and sc[best[0]]>=1:
        groups[best[0]]['t']=t; tmatch[t['mitre_id']]=best[0]
    else:
        note='' if not sc else 'MITRE tracks separately; overlaps '+gprim(groups[sc.most_common(1)[0][0]])
        extra.append(dict(m=None,e=None,t=t,note=note))
groups+=extra
print('MITRE matched',len(tmatch),'MITRE-only rows',len(extra),[ (x['t']['actor'],x['note']) for x in extra][:12])

ORDER=['MISP','ETDA','MITRE']
lab=lambda s:' + '.join(x for x in ORDER if x in s)
rows=[]; index=[]; longrows=[]
taken={norm(g['m']['primary']) for g in groups if g['m']}
for g in groups:
    m,e,t=g['m'],g['e'],g['t']
    actor=m['primary'] if m else (e['primary'] if e else t['actor'])
    if not m and norm(actor) in taken: actor+=' (ETDA)' if e else ' (MITRE)'
    taken.add(norm(actor))
    tnames=([t['actor']]+[a for a in t['aliases'].split('; ') if a]) if t else []
    per=collections.OrderedDict()   # norm -> [display, set(sources)]
    for src,ns in (('MITRE',tnames),('MISP',m['names'] if m else []),('ETDA',e['names'] if e else [])):
        for n in ns:
            k=norm(n)
            if not k: continue
            per.setdefault(k,[n,set()])[1].add(src)
    p=norm(re.sub(r' \((ETDA|MITRE)\)$','',actor)); mitre_ids=set()
    if t: mitre_ids.add(t['mitre_id'])
    aliases=[]
    for k,(n,ss) in per.items():
        if GID.match(n): (mitre_ids.add(n) if not t else None); continue
        if k==p: continue
        aliases.append((n,ss))
    aliases.sort(key=lambda x:(-len(x[1]),'MITRE' not in x[1],x[0].lower()))
    srcs=set(); m and srcs.add('MISP'); e and srcs.add('ETDA'); t and srcs.add('MITRE')
    psrc=per.get(p,[None,srcs])[1] or srcs
    index.append({'lookup_name':actor,'resolves_to':actor,'name_type':'primary','source':lab(psrc)})
    for n,ss in aliases: index.append({'lookup_name':n,'resolves_to':actor,'name_type':'alias','source':lab(ss)})
    mm=m['meta'] if m else {}; em=e['meta'] if e else {}
    cfr=(mm.get('cfr-suspected-state-sponsor') or '').strip(); esp=(em.get('cfr-suspected-state-sponsor') or '').strip()
    motiv='; '.join(L(em.get('motivation')))
    descs=[d for d in [(t or {}).get('description',''),m['desc'] if m else '',e['desc'] if e else ''] if d]
    desc=descs[0] if descs else ''
    alld=' '.join(descs)
    country=mm.get('country') or em.get('country') or ''
    allnames=[actor]+[n for n,_ in aliases]
    basis=[];sp=collections.OrderedDict()
    if cfr: basis.append('MISP: CFR sponsor'); cfr!='Unknown' and sp.setdefault(NORM.get(cfr,cfr),1)
    if re.match(r'(?i)(seems )?state-sponsored',esp): basis.append('ETDA: state-sponsored')
    for n in allnames:
        if CRIME.search(n): continue
        for rx,c,lb in VENDOR:
            if re.search(rx,n):
                sp.setdefault(c,1); b=f'{lb} name ({n})'
                if b not in basis: basis.append(b)
        if MANDIANT.match(n) and 'Mandiant APT designation' not in basis: basis.append('Mandiant APT designation')
    if t and DESC.search(t['description']): basis.append('MITRE: description')
    elif DESC.search(alld): basis.append('description')
    crime=[n for n in allnames if CRIME.search(n)]
    espionage_only = motiv and 'espionage' in motiv.lower() and 'financ' not in motiv.lower()
    if espionage_only and country: basis.append('ETDA: espionage motive')
    strong=[b for b in basis if b.startswith(('MISP: CFR','ETDA: state','MITRE: desc','Microsoft','CrowdStrike','Unit 42','Secureworks','Check Point','Mandiant'))]
    fin_only = motiv and 'financ' in motiv.lower() and 'espionage' not in motiv.lower() and 'sabotage' not in motiv.lower()
    excluded = (not strong and ((NOTSTATE.search(alld) and not STATEWORDS.search(alld)) or fin_only or crime)) \
               or (basis==['description'] and crime) or actor.startswith('[') \
               or (esp and not re.match(r'(?i)(seems )?state-sponsored',esp) and not cfr)
    if not basis and country in CC and not crime and not HACK.search(actor) and desc and not fin_only and not (NOTSTATE.search(alld) and not STATEWORDS.search(alld)):
        basis.append('country tag only')
    if not sp and country: sp[CC.get(country,country)]=1
    if not sp and t:
        hits=[c for c,rx in [('China',r"\b(China|Chinese|People's Republic of China|PRC)\b"),('Russia',r'\bRussia'),('Iran',r'\bIran'),('North Korea',r'North Korea|DPRK')] if re.search(r'(?i)(attributed to|sponsored|backed|linked to|based in|operat\w+ (on behalf of|from))[^.]{0,80}'+rx,t['description'])]
        if len(hits)==1: sp[hits[0]]=1
    conf='' if (excluded or not basis) else ('High' if strong else 'Medium' if any(b in basis for b in ('description','ETDA: espionage motive')) else 'Low')
    rv=REVIEW.get(actor)
    if rv and conf:
        v=rv['verdict']
        if v in REVIEW_DROP: conf=''
        elif v in REVIEW_KEEP:
            lvl,label=REVIEW_KEEP[v]
            if tier_rank[lvl]<tier_rank[conf]: conf=lvl
            basis=[b for b in basis if b!='country tag only']+[f"research: {label} ({rv['attributing_source']}, {rv['latest_report_date']})"]
            sp=collections.OrderedDict([(rv['sponsor_country'] or 'Unknown',1)])
    rec={'actor':actor,'sources':lab(srcs),'misp_name':m['primary'] if m else '','etda_name':e['primary'] if e else '','mitre_name':t['actor'] if t else '','merge_note':g['note'],
      'state-link-confidence':conf,'Suspected-State-Sponsor':('; '.join(sp) or ('Unknown' if conf else '')),
      'sponsoring-org (ETDA)':esp if esp and not re.fullmatch(r'(?i)state-sponsored',esp) else '','state-evidence':'; '.join(basis) if conf else '',
      'also-has-criminal-group-names':'; '.join(crime),'motivation (ETDA)':motiv,
      'attribution-confidence (MISP)':mm.get('attribution-confidence',''),'attribution-confidence (ETDA)':em.get('attribution-confidence',''),
      'country':country,'mitre_id':';'.join(sorted(mitre_ids)),'mitre_last_modified':t['last_modified'] if t else '','alias_count':len(aliases),
      'aliases (all)':'; '.join(n for n,_ in aliases),
      'aliases in MITRE':'; '.join(n for n,s in aliases if 'MITRE' in s),'aliases in MISP':'; '.join(n for n,s in aliases if 'MISP' in s),'aliases in ETDA':'; '.join(n for n,s in aliases if 'ETDA' in s),
      'mitre_url':t['url'] if t else '','etda_card':e['card'] if e else '',
      'research-verdict':rv['verdict'] if rv else '','research-attribution':(rv['attribution_wording']+(' ['+rv['confidence_wording']+']' if rv['confidence_wording'] else '')) if rv else '',
      'research-latest-report':rv['latest_report_date'] if rv else '','research-url':rv['url'] if rv else '','description':desc}
    mw=collections.OrderedDict()
    def addmw(n,typ,src):
        c=MW['canon'].get(norm(n),n); k=norm(c); k2=re.sub(r'(rat|backdoor|project)$','',k)
        k=k2 if len(k2)>=4 else k
        if k in mw and len(c)<len(mw[k][0]): mw[k][0]=c
        x=mw.setdefault(k,[c,'',set()]); x[2].add(src)
        if typ and not x[1]: x[1]=typ
    TY={'Tools':'Tool','Exploits':'Exploit','Other':''}
    if t:
        for n,ty in MW['mitre'].get(t['mitre_id'],{}).items(): addmw(n,ty,'MITRE')
    if e:
        for n,ty in MW['etda'].get(e['uuid'],{}).items(): addmw(n,TY.get(ty,ty),'ETDA')
    if m:
        for n,ty in MW['misp'].get(m['uuid'],{}).items(): addmw(n,{'malware':'Malware','tool':'Tool'}.get(MW['mtype'].get(MW['canon'].get(norm(n),n),''),''),'MISP')
    mwl=sorted(mw.values(),key=lambda x:({'Malware':0,'Tool':2,'Exploit':3}.get(x[1],1),-len(x[2]),x[0].lower()))
    rec['malware_count']=sum(1 for x in mwl if x[1]!='Tool' and x[1]!='Exploit'); rec['tool_count']=sum(1 for x in mwl if x[1] in('Tool','Exploit'))
    rec['malware']='; '.join(x[0] for x in mwl if x[1] not in('Tool','Exploit')); rec['tools & exploits']='; '.join(x[0] for x in mwl if x[1] in('Tool','Exploit'))
    rec['_mw']=[(x[0],x[1] or 'Malware',lab(x[2])) for x in mwl]
    rows.append(rec)
    for n,ss in (aliases or [('(no known aliases)',set())]):
        longrows.append((rec,n,lab(ss)))
def w(path,rs,fields=None):
    fl=fields or [k for k in rs[0] if not k.startswith('_') and k!='description']+(['description'] if 'description' in rs[0] else [])
    with open(path,'w',newline='',encoding='utf-8-sig') as f:
        x=csv.DictWriter(f,fieldnames=fl,extrasaction='ignore');x.writeheader();x.writerows(rs)
key=lambda r:r['actor'].lower()
rows.sort(key=key); w(out+'/merged_all_actors.csv',rows)
tier={'High':0,'Medium':1,'Low':2}
skey=lambda r:(tier[r['state-link-confidence']],r['Suspected-State-Sponsor'] if r['Suspected-State-Sponsor']!='Unknown' else 'zz',r['actor'].lower())
st=sorted([r for r in rows if r['state-link-confidence']],key=skey); w(out+'/merged_state_sponsored.csv',st)
index.sort(key=lambda r:(r['lookup_name'].lower(),r['resolves_to'].lower())); w(out+'/alias_index.csv',index)
H=['Actor','Alias','Alias Source','Suspected State Sponsor','State-Link Confidence','Sponsoring Org (ETDA)','MITRE ID','Actor Sources','Alias Count']
def longw(path,flt,sk):
    rs=[x for x in longrows if flt(x[0])]; order={id(r):i for i,r in enumerate(sorted({id(x[0]):x[0] for x in rs}.values(),key=sk))}
    rs.sort(key=lambda x:order[id(x[0])])
    with open(path,'w',newline='',encoding='utf-8-sig') as f:
        cw=csv.writer(f); cw.writerow(H)
        for r,n,s in rs: cw.writerow([r['actor'],n,s,r['Suspected-State-Sponsor'],r['state-link-confidence'],r['sponsoring-org (ETDA)'],r['mitre_id'],r['sources'],r['alias_count']])
    return len(rs)
print('long',longw(out+'/apt_aliases_by_actor_state_sponsored.csv',lambda r:r['state-link-confidence'],skey),longw(out+'/apt_aliases_by_actor_all.csv',lambda r:True,key))
C=collections.Counter
print('rows',len(rows),C(r['sources'] for r in rows)); print('state',len(st),C(r['state-link-confidence'] for r in st))
print(C(r['Suspected-State-Sponsor'] for r in st).most_common(8))
print('index',len(index),C(r['source'] for r in index))

MH=['Actor','Malware / Tool','Type','Source','Suspected State Sponsor','State-Link Confidence','MITRE ID','Actor Sources','Malware Count','Tool Count']
def mwrite(path,rs):
    n=0
    with open(path,'w',newline='',encoding='utf-8-sig') as f:
        cw=csv.writer(f); cw.writerow(MH)
        for r in rs:
            for nm,ty,src in (r['_mw'] or [('(none recorded)','','')]):
                cw.writerow([r['actor'],nm,ty,src,r['Suspected-State-Sponsor'],r['state-link-confidence'],r['mitre_id'],r['sources'],r['malware_count'],r['tool_count']]); n+=1
    return n
print('malware long',mwrite(out+'/actor_malware_state_sponsored.csv',st),mwrite(out+'/actor_malware_all.csv',rows))
print('actors with any malware',sum(1 for r in rows if r['_mw']),'state w/ malware',sum(1 for r in st if r['_mw']))
