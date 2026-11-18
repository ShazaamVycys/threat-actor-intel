import json,sys,re,csv,collections
S,M,OUT=sys.argv[1:4]
clean=lambda t:' '.join(re.sub(r'\[([^\]]+)\]\([^)]+\)',r'\1',re.sub(r'\(Citation:[^)]*\)','',t or '')).split())
misp={v['value'].strip():v for v in json.load(open(S+'/dl/threat-actor.json'))['values']}
etda={v['value'].split(',')[0].strip():v for v in json.load(open(S+'/etda/etda_groups.json'))['values']}
mitre={g['actor']:g for g in json.load(open(S+'/mitre/mitre_attack_groups.json'))['groups']}
print('ETDA meta keys',collections.Counter(k for v in etda.values() for k in v['meta']).most_common(25))
st=list(csv.DictReader(open(M+'/merged_state_sponsored.csv',encoding='utf-8-sig')))
L=lambda x:'; '.join(x) if isinstance(x,list) else (x or '')
out=[]
for r in st:
    m=misp.get(r['misp_name']); e=etda.get(r['etda_name']); t=mitre.get(r['mitre_name'])
    em=e['meta'] if e else {}
    out.append({'Actor':r['actor'],'Suspected State Sponsor':r['Suspected-State-Sponsor'],'State-Link Confidence':r['state-link-confidence'],'MITRE ID':r['mitre_id'],
      'Sponsoring Org (ETDA)':r['sponsoring-org (ETDA)'],
      'MITRE Description':clean(t['description']) if t else '','MISP Description':' '.join((m.get('description') or '').split()) if m else '','ETDA Description':' '.join((e.get('description') or '').split()) if e else '',
      'First Seen (ETDA)':L(em.get('date')),'Observed Sectors (ETDA)':L(em.get('cfr-target-category')),'Observed Countries (ETDA)':L(em.get('cfr-suspected-victims')),
      'MISP Target Sectors':L((m or {}).get('meta',{}).get('cfr-target-category')),'MISP Victims':L((m or {}).get('meta',{}).get('cfr-suspected-victims')),
      'Description Sources':', '.join(s for s,x in (('MITRE',t),('MISP',m and m.get('description')),('ETDA',e and e.get('description'))) if x)})
C=collections.Counter
n=lambda x:len([1 for k in ('MITRE Description','MISP Description','ETDA Description') if x[k]])
print('sources per actor',C(n(x) for x in out))
print('by tier with 0 or only-short (<200 chars total)',C(x['State-Link Confidence'] for x in out if sum(len(x[k]) for k in ('MITRE Description','MISP Description','ETDA Description'))<200))
print('lengths median',sorted(sum(len(x[k]) for k in ('MITRE Description','MISP Description','ETDA Description')) for x in out)[270])
with open(OUT,'w',newline='',encoding='utf-8-sig') as f:
    w=csv.DictWriter(f,fieldnames=list(out[0]));w.writeheader();w.writerows(out)
print(out[0]['Actor'],{k:v[:80] for k,v in out[0].items() if v})
