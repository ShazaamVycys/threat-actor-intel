import json,csv,re,collections,sys
S=sys.argv[1]; D=sys.argv[2]
W=[json.loads(l) for l in open(S+'/work/web.jsonl',encoding='utf-8')]
T={t['actor'] for t in json.load(open(S+'/work/web_targets.json'))}
MON={'H1':6,'H2':12,'Q1':3,'Q2':6,'Q3':9,'Q4':12}
def dkey(s):
    s=(s or '').split('(')[0]
    best=(0,0)
    for m in re.finditer(r'(20\d\d)(?:[- ](\d\d)(?!\d)|\s*(Q[1-4]|H[12]))?',s):
        y=int(m.group(1)); mo=int(m.group(2)) if m.group(2) else (MON[m.group(3)] if m.group(3) else 6)
        # a bare quarter after a range like 'Q2–Q3' belongs to the same year
        best=max(best,(y,mo))
    for m in re.finditer(r'–\s*(Q[1-4]|H[12])\b',s):
        yrs=re.findall(r'20\d\d',s)
        if yrs: best=max(best,(int(yrs[-1]),MON[m.group(1)]))
    return best
by=collections.defaultdict(list)
seen=set()
for w in W:
    k=(w['actor'],w['summary'])
    if k in seen: continue
    seen.add(k); by[w['actor']].append(w)
rows=list(csv.DictReader(open(D+'/state_actors_descriptions.csv',encoding='utf-8-sig')))
longrows=[]
for r in rows:
    a=r['Actor']; ws=by.get(a,[])
    prof=[w for w in ws if w['kind'] in('profile','note','none')]
    rec=sorted([w for w in ws if w['kind']=='recent'],key=lambda w:dkey(w['date']),reverse=True)
    r['Web Profile']=' '.join(w['summary'] for w in prof)
    r['Recent Activity (2025–2026 web)']=' || '.join(f"{w['date']}: {w['summary']}" for w in rec)
    latest=rec[0]['date'] if rec else (prof[0]['date'] if prof and prof[0]['date'] else '')
    r['Most Recent Reported Activity']=latest
    srcs=list(dict.fromkeys(u for w in rec+prof for u in w['sources']))
    r['Web Sources']=' | '.join(srcs)
    if rec: st='Found recent activity'
    elif any(w['kind']=='note' for w in prof): st='Note added (duplicate / likely not state)'
    elif any(w['kind']=='profile' for w in prof): st='Profile added from web'
    elif any(w['kind']=='none' for w in prof): st='Researched - no public profile found'
    elif a in T: st='Checked against reports - no 2025-2026 activity found'
    else: st='Not web-researched (Medium/Low tier)'
    r['Web Research Status']=st
    for w in rec+prof:
        longrows.append({'Actor':a,'Suspected State Sponsor':r['Suspected State Sponsor'],'State-Link Confidence':r['State-Link Confidence'],'Kind':{'recent':'Recent activity','profile':'Profile','note':'Note','none':'No public profile'}[w['kind']],
            'Date / Period':w['date'],'Reported As':w.get('reported_as',''),'Summary':w['summary'],'Sources':' | '.join(w['sources'])})
F=list(rows[0])
with open(D+'/state_actors_descriptions.csv','w',newline='',encoding='utf-8-sig') as f:
    x=csv.DictWriter(f,fieldnames=F);x.writeheader();x.writerows(rows)
order={r['Actor']:i for i,r in enumerate(rows)}
longrows.sort(key=lambda x:(order[x['Actor']],x['Kind']!='Profile',x['Kind']!='Note',tuple(-v for v in dkey(x['Date / Period']))))
with open(D+'/state_actors_web_activity.csv','w',newline='',encoding='utf-8-sig') as f:
    x=csv.DictWriter(f,fieldnames=list(longrows[0]));x.writeheader();x.writerows(longrows)
C=collections.Counter
print(C(r['Web Research Status'] for r in rows))
print('tier x status',C((r['State-Link Confidence'],r['Web Research Status'][:12]) for r in rows))
print('long rows',len(longrows),'sources',len({u for w in W for u in w['sources']}))
for a in ('APT28','Sandworm','MuddyWater'):
    r=next(x for x in rows if x['Actor']==a); print(a,'| latest',r['Most Recent Reported Activity'],'|',r['Recent Activity (2025–2026 web)'][:200])
