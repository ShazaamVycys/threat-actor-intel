import json,sys,re,csv,collections
S,M=sys.argv[1],sys.argv[2]
norm=lambda s:re.sub(r'[^a-z0-9]','',s.lower())
nk=lambda s:(lambda k:(re.sub(r'(rat|backdoor|project)$','',k) if len(re.sub(r'(rat|backdoor|project)$','',k))>=4 else k))(norm(s))
eid=lambda o:next((r['external_id'] for r in o.get('external_references',[]) if r.get('source_name') in('mitre-attack','mitre-mobile-attack','mitre-ics-attack')),'')
clean=lambda t:' '.join(re.sub(r'\[([^\]]+)\]\([^)]+\)',r'\1',re.sub(r'\(Citation:[^)]*\)','',t or '')).split())
TACT=['reconnaissance','resource-development','initial-access','execution','persistence','privilege-escalation','stealth','defense-impairment','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact',
      'inhibit-response-function','impair-process-control','evasion']
tech={}; group_t=collections.defaultdict(dict); soft_t=collections.defaultdict(dict); soft_names={}; soft_id={}
for dom in ('enterprise','mobile','ics'):
    objs=json.load(open(f'{S}/mitre/{dom}-attack.json'))['objects']; by={o['id']:o for o in objs}
    live=lambda o:o and not o.get('revoked') and not o.get('x_mitre_deprecated')
    # technique names (with parent for subtechniques)
    for o in objs:
        if o['type']=='attack-pattern' and live(o):
            tid=eid(o); tech[o['id']]=dict(id=tid,name=o['name'],tactics=[p['phase_name'] for p in o.get('kill_chain_phases',[])],dom=dom)
    for t in tech.values():
        if '.' in t['id'] and 'full' not in t:
            par=next((x for x in tech.values() if x['id']==t['id'].split('.')[0]),None); t['full']=(par['name']+': ' if par else '')+t['name']
    for t in tech.values(): t.setdefault('full',t['name'])
    camp2g={}
    for o in objs:
        if o['type']=='relationship' and o.get('relationship_type')=='attributed-to' and live(o):
            s,g=by.get(o['source_ref']),by.get(o['target_ref'])
            if live(s) and live(g) and s['type']=='campaign' and g['type']=='intrusion-set': camp2g.setdefault(s['id'],[]).append((eid(g),eid(s),s['name']))
    for o in objs:
        if o['type'] in('malware','tool') and live(o):
            soft_id[o['id']]=eid(o)
            for n in [o['name']]+(o.get('x_mitre_aliases') or []): soft_names.setdefault(nk(n),(eid(o),o['name']))
    for o in objs:
        if o['type']!='relationship' or o.get('relationship_type')!='uses' or not live(o): continue
        s,t=by.get(o['source_ref']),by.get(o['target_ref'])
        if not live(s) or not live(t) or t['type']!='attack-pattern' or t['id'] not in tech: continue
        proc=clean(o.get('description'))
        if s['type']=='intrusion-set':
            group_t[eid(s)].setdefault(t['id'],[]).append(('Direct (ATT&CK group)',proc))
        elif s['type']=='campaign':
            for gid,cid,cn in camp2g.get(s['id'],[]): group_t[gid].setdefault(t['id'],[]).append((f'Campaign {cid} {cn}',proc))
        elif s['type'] in('malware','tool'):
            soft_t[eid(s)].setdefault(t['id'],proc)
print('techniques',len(tech),'groups w/ TTPs',len(group_t),'software w/ TTPs',len(soft_t))
rows=list(csv.DictReader(open(M+'/merged_all_actors.csv',encoding='utf-8-sig')))
state={r['actor'] for r in csv.DictReader(open(M+'/merged_state_sponsored.csv',encoding='utf-8-sig'))}
out=[]; summ={}
tord=lambda t:(min([TACT.index(x) for x in t['tactics'] if x in TACT] or [99]),t['id'])
for r in rows:
    gid=r['mitre_id'] if r['mitre_name'] else ''
    rec={}
    if gid in group_t:
        for k,lst in group_t[gid].items():
            rec[k]=dict(basis='; '.join(dict.fromkeys(b for b,_ in lst)),proc=next((p for _,p in lst if p),''),via='')
    else:
        for n in [x for x in (r['malware'].split('; ')+r['tools & exploits'].split('; ')) if x]:
            hit=soft_names.get(nk(n))
            if not hit: continue
            sid,sname=hit
            for k,proc in soft_t.get(sid,{}).items():
                x=rec.setdefault(k,dict(basis='Inferred from software',proc=proc,via=[]))
                x['via'].append(f'{sname} ({sid})')
        for x in rec.values(): x['via']='; '.join(x['via'][:6])+(' …' if len(x['via'])>6 else '')
    for k,x in sorted(rec.items(),key=lambda kv:tord(tech[kv[0]])):
        t=tech[k]
        out.append({'Actor':r['actor'],'Technique ID':t['id'],'Technique':t['full'],'Tactic(s)':', '.join(p.replace('-',' ').title() for p in t['tactics']),
          'Basis':x['basis'],'Via Software':x['via'],'ATT&CK Domain':t['dom'].title(),'Suspected State Sponsor':r['Suspected-State-Sponsor'],'State-Link Confidence':r['state-link-confidence'],
          'MITRE ID':r['mitre_id'],'Procedure Example':x['proc'][:1500],'_state':r['actor'] in state})
    summ[r['actor']]=(sum(1 for v in rec.values() if v['basis']!='Inferred from software'),sum(1 for v in rec.values() if v['basis']=='Inferred from software'))
F=[k for k in out[0] if not k.startswith('_')]
def w(p,rs):
    with open(p,'w',newline='',encoding='utf-8-sig') as f:
        x=csv.DictWriter(f,fieldnames=F,extrasaction='ignore');x.writeheader();x.writerows(rs)
order=[r['actor'] for r in csv.DictReader(open(M+'/merged_state_sponsored.csv',encoding='utf-8-sig'))]; oi={a:i for i,a in enumerate(order)}
st=sorted([x for x in out if x['_state']],key=lambda x:oi[x['Actor']])
w(M+'/actor_ttps_state_sponsored.csv',st); w(M+'/actor_ttps_all.csv',out)
json.dump(summ,open(M+'/_ttp_summary.json','w'))
C=collections.Counter
print('rows all',len(out),'state',len(st)); print('actors w/ direct',sum(1 for a,(d,i) in summ.items() if d),'inferred only',sum(1 for a,(d,i) in summ.items() if i and not d))
print('state actors w/ direct',sum(1 for a in state if summ[a][0]),'inferred',sum(1 for a in state if summ[a][1] and not summ[a][0]),'none',sum(1 for a in state if not any(summ[a])))
print(C(x['Basis'].split(' C')[0] for x in out).most_common(4))
for a in ('APT29','Volt Typhoon','GhostEmperor'):
    xs=[x for x in out if x['Actor']==a]; print(a,len(xs),[(x['Technique ID'],x['Technique'][:40],x['Tactic(s)']) for x in xs[:4]])
