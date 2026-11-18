# Copies the state-sponsored subset into its own folder with friendly names, plus a filtered alias index.
import csv,shutil,sys
M,ST=sys.argv[1],sys.argv[2]
for src,dst in [('merged_state_sponsored.csv','state_actors_summary.csv'),('apt_aliases_by_actor_state_sponsored.csv','state_actors_aliases.csv'),
                ('actor_malware_state_sponsored.csv','state_actors_malware.csv'),('actor_ttps_state_sponsored.csv','state_actors_ttps.csv'),
                ('actor_host_artifacts_state_sponsored.csv','state_actors_host_artifacts.csv')]:
    shutil.copy(f'{M}/{src}',f'{ST}/{dst}')
st={r['actor'] for r in csv.DictReader(open(f'{M}/merged_state_sponsored.csv',encoding='utf-8-sig'))}
r=[x for x in csv.DictReader(open(f'{M}/alias_index.csv',encoding='utf-8-sig')) if x['resolves_to'] in st]
with open(f'{ST}/state_actors_alias_index.csv','w',newline='',encoding='utf-8-sig') as f:
    w=csv.DictWriter(f,fieldnames=list(r[0]));w.writeheader();w.writerows(r)
print('state pack',len(st),'actors')
