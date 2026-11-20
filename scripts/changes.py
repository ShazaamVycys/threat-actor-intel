# Compares the previous build (data/work/prev) with the new one and writes out/CHANGES.md.
import csv,sys,os,datetime,collections
prev,new,outmd=sys.argv[1:4]
def rows(d,f,keys):
    p=os.path.join(d,f)
    if not os.path.exists(p): return set()
    return {tuple(r[k] for k in keys) for r in csv.DictReader(open(p,encoding='utf-8-sig'))}
specs=[('Actors','state_actors_summary.csv',['actor']),
       ('Aliases','state_actors_aliases.csv',['Actor','Alias']),
       ('Malware / tools','state_actors_malware.csv',['Actor','Malware / Tool']),
       ('ATT&CK techniques','state_actors_ttps.csv',['Actor','Technique ID']),
       ('Host artifacts','state_actors_host_artifacts.csv',['Actor','Artifact Type','Artifact']),
       ('Recent-activity entries','state_actors_web_activity.csv',['Actor','Date / Period','Summary']),
       ('Malware hashes','state_actors_malware_hashes.csv',['Actor','Malware','SHA256','SHA1','MD5']),
       ('Actor IOCs (vendor reports)','state_actors_iocs.csv',['Actor','Type','Indicator'])]
L=[f"# What changed — build {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M} UTC",""]
first=not os.path.isdir(prev)
L.append("| Item | Added | Removed | Total |"); L.append("|---|---|---|---|")
detail=[]
for name,f,k in specs:
    a,b=rows(prev,f,k),rows(new,f,k); add,rem=b-a,a-b
    L.append(f"| {name} | {len(add) if not first else '—'} | {len(rem) if not first else '—'} | {len(b)} |")
    if not first and add and name=='Actor IOCs (vendor reports)':
        c=collections.defaultdict(collections.Counter)
        for t in add: c[t[0]][t[1]]+=1
        detail.append("\n## New actor IOCs (vendor reports)")
        for act,k in sorted(c.items()): detail.append(f"- **{act}**: "+', '.join(f'{ty} {v}' for ty,v in sorted(k.items())))
        continue
    if not first and add and name=='Malware hashes':
        c=collections.Counter((t[0],t[1]) for t in add)
        detail.append("\n## New malware hashes")
        for (act,mw),k in sorted(c.items()): detail.append(f"- **{act}**: {mw} ({k})")
        continue
    if not first and add and name in('Actors','Aliases','Malware / tools','Recent-activity entries'):
        by=collections.defaultdict(list)
        for t in sorted(add): by[t[0]].append(' — '.join(t[1:])[:160] if len(t)>1 else '')
        detail.append(f"\n## New {name.lower()}")
        for act,items in list(by.items())[:60]:
            detail.append(f"- **{act}**" + (": "+"; ".join(i for i in items if i) if any(items) else ''))
        if len(by)>60: detail.append(f"- …and {len(by)-60} more actors")
# incidents (separate output folder; previous copy in <prev>_incidents)
pi,ni=prev.rstrip('/')+'_incidents',os.path.join(os.path.dirname(new.rstrip('/')),'incidents')
if os.path.isdir(ni):
    fi=not os.path.isdir(pi)
    for name,f,k in [('Incidents','incidents.csv',['Incident ID','Incident']),('Incident IOCs','incident_iocs.csv',['Incident ID','Type','Indicator'])]:
        a,b=rows(pi,f,k),rows(ni,f,k); add,rem=b-a,a-b
        L.append(f"| {name} | {len(add) if not fi else len(b)} | {len(rem) if not fi else 0} | {len(b)} |")
        if add and name=='Incidents':
            detail.append("\n## New incidents"); detail+= [f"- **{t[1]}** (`{t[0]}`)" for t in sorted(add)]
        if add and name=='Incident IOCs':
            c=collections.Counter((t[0],t[1]) for t in add)
            detail.append("\n## New incident IOCs"); detail+=[f"- {i}: {ty} ({k})" for (i,ty),k in sorted(c.items())]
if first: L.append("\n_First build — no previous run to compare against._")
open(outmd,'w').write('\n'.join(L+detail)+'\n'); print('\n'.join(L[:10]))
