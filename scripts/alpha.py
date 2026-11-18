# Sorts actor files A–Z (natural order: APT1, APT2 … APT10), keeping row order within each actor.
import csv,glob,re,sys
nat=lambda s:[(0,int(t),'') if t.isdigit() else (1,0,t) for t in re.findall(r'\d+|\D+',s.casefold())]
for f in sys.argv[1:]:
    r=list(csv.DictReader(open(f,encoding='utf-8-sig')))
    if not r: continue
    fl=list(r[0]); col='Actor' if 'Actor' in fl else ('actor' if 'actor' in fl else None)
    if not col: continue
    r.sort(key=lambda x:nat(x[col]))
    with open(f,'w',newline='',encoding='utf-8-sig') as fh:
        w=csv.DictWriter(fh,fieldnames=fl);w.writeheader();w.writerows(r)
print('alphabetized',len(sys.argv)-1,'files')
