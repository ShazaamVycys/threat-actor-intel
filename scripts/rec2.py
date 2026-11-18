import json,sys,csv,re
# stdin lines: name|date|summary|url1,url2   (kind via argv[2], default recent)
norm=lambda s:re.sub(r'[^a-z0-9]','',s.lower())
idx={}; prim={}
for x in csv.DictReader(open(__import__('os').environ['CTI_STATE']+'/state_actors_alias_index.csv',encoding='utf-8-sig')):
    idx.setdefault(norm(x['lookup_name']),set()).add(x['resolves_to'])
    if x['name_type']=='primary': prim[norm(x['lookup_name'])]=x['resolves_to']
EXTRA={'sednit':'APT28','scarcruft':'APT37','lazarus':'Lazarus Group'}
kind=sys.argv[2] if len(sys.argv)>2 else 'recent'
n=0;miss=[]
with open(sys.argv[1],'a',encoding='utf-8') as f:
    for line in sys.stdin:
        line=line.strip()
        if not line or line.startswith('#'): continue
        name,date,summ,urls=[p.strip() for p in line.split('|',3)]
        k=norm(name)
        acts=({prim[k]} if k in prim else None) or ({prim[k+'group']} if k+'group' in prim else None) or ({EXTRA[k]} if k in EXTRA else None) or idx.get(k) or idx.get(k+'group') or set()
        if not acts: miss.append(name); continue
        if len(acts)>1: print('ambiguous',name,acts)
        for a in acts:
            f.write(json.dumps({'actor':a,'reported_as':name,'kind':kind,'date':date,'summary':summ,'sources':[u for u in urls.split(',') if u]},ensure_ascii=False)+'\n'); n+=1
print('recorded',n,'unresolved',miss)
