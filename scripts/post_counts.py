# Adds TTP and host-artifact counts (from ttp.py / artifacts.py summaries) to the merged actor CSVs.
import csv,json,sys,os
M=sys.argv[1]
t=json.load(open(M+'/_ttp_summary.json')); a=json.load(open(M+'/_art_summary.json'))
for f in ('merged_all_actors.csv','merged_state_sponsored.csv'):
    r=list(csv.DictReader(open(f'{M}/{f}',encoding='utf-8-sig')))
    fl=[k for k in r[0] if k not in('ttp_count (ATT&CK)','ttp_count (inferred from software)','host_artifact_count')]
    i=fl.index('description'); fl=fl[:i]+['ttp_count (ATT&CK)','ttp_count (inferred from software)','host_artifact_count']+fl[i:]
    for x in r:
        x['ttp_count (ATT&CK)'],x['ttp_count (inferred from software)']=t.get(x['actor'],(0,0)); x['host_artifact_count']=a.get(x['actor'],0)
    with open(f'{M}/{f}','w',newline='',encoding='utf-8-sig') as fh:
        w=csv.DictWriter(fh,fieldnames=fl);w.writeheader();w.writerows(r)
os.remove(M+'/_ttp_summary.json'); os.remove(M+'/_art_summary.json')
print('counts added')
