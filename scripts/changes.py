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
       ('Recent-activity entries','state_actors_web_activity.csv',['Actor','Date / Period','Summary'])]
L=[f"# What changed — build {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M} UTC",""]
first=not os.path.isdir(prev)
L.append("| Item | Added | Removed | Total |"); L.append("|---|---|---|---|")
detail=[]
for name,f,k in specs:
    a,b=rows(prev,f,k),rows(new,f,k); add,rem=b-a,a-b
    L.append(f"| {name} | {len(add) if not first else '—'} | {len(rem) if not first else '—'} | {len(b)} |")
    if not first and add and name in('Actors','Aliases','Malware / tools','Recent-activity entries'):
        by=collections.defaultdict(list)
        for t in sorted(add): by[t[0]].append(' — '.join(t[1:])[:160] if len(t)>1 else '')
        detail.append(f"\n## New {name.lower()}")
        for act,items in list(by.items())[:60]:
            detail.append(f"- **{act}**" + (": "+"; ".join(i for i in items if i) if any(items) else ''))
        if len(by)>60: detail.append(f"- …and {len(by)-60} more actors")
if first: L.append("\n_First build — no previous run to compare against._")
open(outmd,'w').write('\n'.join(L+detail)+'\n'); print('\n'.join(L[:10]))
