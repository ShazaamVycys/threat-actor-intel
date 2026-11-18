import json,sys,re,collections,csv
D=sys.argv[1]; out=sys.argv[2]
groups={}; meta={}
for dom in ('enterprise','mobile','ics'):
    raw=open(f'{D}/{dom}-attack.json','rb').read(); t=raw.decode('utf-8')
    b=json.loads(t)
    objs=b['objects']
    col=[o for o in objs if o['type']=='x-mitre-collection']
    meta[dom]=(col[0].get('x_mitre_version') if col else '?', col[0].get('modified') if col else '?', len(objs))
    for o in objs:
        if o['type']!='intrusion-set': continue
        ext=next((r for r in o.get('external_references',[]) if r.get('source_name')=='mitre-attack'),{})
        g=groups.setdefault(o['id'],dict(o=o,ext=ext,domains=set()))
        g['domains'].add(dom)
print('collections',meta)
allg=list(groups.values())
active=[g for g in allg if not g['o'].get('revoked') and not g['o'].get('x_mitre_deprecated')]
print('intrusion-sets',len(allg),'active',len(active))
# safety scan over group objects only
txt=json.dumps([g['o'] for g in allg],ensure_ascii=False)
for n,r in {'script/html':r'<\s*(script|iframe|object|embed|svg)','js uri':r'javascript:','data uri':r'data:[a-z]+/[a-z]+;base64','long base64':r'[A-Za-z0-9+/]{200,}={0,2}','formula':r'"[=+@][A-Za-z]+\(','bidi/zw':'[‪-‮⁦-⁩​﻿]','ctrl':r'[\x00-\x08\x0b\x0c\x0e-\x1f]'}.items():
    print(n,len(re.findall(r,txt)))
dom=collections.Counter(u.lower() for u in re.findall(r'https?://([^/\s"]+)',txt)); print('domains',len(dom),dom.most_common(8))
rows=[];idx=[]
for g in sorted(active,key=lambda g:g['ext'].get('external_id','')):
    o=g['o']; name=o['name']; al=[a for a in o.get('aliases',[]) if a.strip().lower()!=name.lower()]
    desc=' '.join(re.sub(r'\(Citation:[^)]*\)','',o.get('description','')).split())
    rows.append({'mitre_id':g['ext'].get('external_id',''),'actor':name,'alias_count':len(al),'aliases':'; '.join(al),'domains':', '.join(sorted(g['domains'])),
      'created':o.get('created','')[:10],'last_modified':o.get('modified','')[:10],'attack_version':o.get('x_mitre_version',''),'url':g['ext'].get('url',''),'description':desc})
    for a in [name]+al: idx.append({'lookup_name':a,'resolves_to':name,'mitre_id':g['ext'].get('external_id',''),'name_type':'primary' if a==name else 'alias'})
with open(out+'/mitre_attack_groups.csv','w',newline='',encoding='utf-8-sig') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
with open(out+'/mitre_attack_groups.json','w') as f: json.dump({'source':'MITRE ATT&CK attack-stix-data','versions':meta,'groups':rows},f,indent=1,ensure_ascii=False)
print('rows',len(rows),'aliases',sum(r['alias_count'] for r in rows),'with aliases',sum(1 for r in rows if r['alias_count']))
print([ (r['mitre_id'],r['actor'],r['aliases'][:80]) for r in rows if r['actor'] in('APT29','Lazarus Group','Volt Typhoon')])
