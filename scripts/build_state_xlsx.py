import csv,sys,itertools,collections
from openpyxl import Workbook
from openpyxl.styles import Font,Alignment,PatternFill,Border,Side
d=sys.argv[1]; dst=sys.argv[2]
COLS=[('Actor',24),('Alias',34),('Alias Source',22),('Suspected State Sponsor',20),('State-Link Confidence',14),('Sponsoring Org (ETDA)',40),('MITRE ID',12),('Actor Sources',22)]
thin=Side(style='thin',color='BFBFBF'); thick=Side(style='medium',color='404040')
F=Font(name='Arial',size=10); FB=Font(name='Arial',size=10,bold=True); FH=Font(name='Arial',size=10,bold=True,color='FFFFFF')
def fill(s):
    n=s.count('+')+1 if s else 0
    if not s: return None
    if n==3: return 'A9D08E'
    if n==2: return 'E2EFDA'
    return {'MISP':'DDEBF7','ETDA':'FCE4D6','MITRE':'FFF2CC'}[s]
def sheet(ws,path,COLS=COLS,inner=(('Alias',2),('Alias Source',3)),outer=((1,'Actor'),(4,'Suspected State Sponsor'),(5,'State-Link Confidence'),(6,'Sponsoring Org (ETDA)'),(7,'MITRE ID'),(8,'Actor Sources')),srccol=3,typecol=None):
    for c,(h,wd) in enumerate(COLS,1):
        x=ws.cell(1,c,h); x.font=FH; x.fill=PatternFill('solid',fgColor='1F3864'); x.alignment=Alignment(vertical='center',wrap_text=True)
        ws.column_dimensions[x.column_letter].width=wd
    ws.freeze_panes='B2'; r=2; n=0
    rows=list(csv.DictReader(open(path,encoding='utf-8-sig')))
    for actor,grp in itertools.groupby(rows,key=lambda x:x['Actor']):
        grp=list(grp); top=r; bot=r+len(grp)-1; a=grp[0]; n+=1
        for i,x in enumerate(grp):
            for k,c in inner:
                cell=ws.cell(r+i,c,x[k]); cell.font=F
                if c==srccol and fill(x[k]): cell.fill=PatternFill('solid',fgColor=fill(x[k]))
                if x.get('Uniqueness')=='Unique to this actor': cell.fill=PatternFill('solid',fgColor='FFFF00')
                if k=='Note' and x[k].startswith('Common'): cell.font=Font(name='Arial',size=10,italic=True,color='7F7F7F')
                if k=='Attribution' and x[k].startswith('Via malware'): cell.font=Font(name='Arial',size=10,italic=True,color='7F7F7F')
                if c==5 and srccol is None and x[k].startswith('Inferred'): cell.font=Font(name='Arial',size=10,italic=True,color='7F7F7F')
                if c==typecol and x[k]=='Malware': cell.font=Font(name='Arial',size=10,color='C00000')
        for c,k in outer:
            cell=ws.cell(top,c,int(a[k]) if a[k].isdigit() else a[k]); cell.font=FB if c==1 else F; cell.alignment=Alignment(vertical='top',wrap_text=True)
            if bot>top: ws.merge_cells(start_row=top,start_column=c,end_row=bot,end_column=c)
        for rr in range(top,bot+1):
            for c in range(1,len(COLS)+1): ws.cell(rr,c).border=Border(left=thin,right=thin,top=thick if rr==top else thin,bottom=thick if rr==bot else thin)
        r=bot+1
    return n
wb=Workbook(); ws=wb.active; ws.title='Aliases'
n1=sheet(ws,d+'/apt_aliases_by_actor_state_sponsored.csv'); n2=0
MC=[('Actor',24),('Malware / Tool',30),('Type',10),('Source',22),('Suspected State Sponsor',20),('State-Link Confidence',14),('MITRE ID',12),('Malware Count',10),('Tool Count',10)]
kw=dict(COLS=MC,inner=(('Malware / Tool',2),('Type',3),('Source',4)),outer=((1,'Actor'),(5,'Suspected State Sponsor'),(6,'State-Link Confidence'),(7,'MITRE ID'),(8,'Malware Count'),(9,'Tool Count')),srccol=4,typecol=3)
n3=sheet(wb.create_sheet('Malware'),d+'/actor_malware_state_sponsored.csv',**kw)
n4=0
TC=[('Actor',24),('Technique ID',12),('Technique',52),('Tactic(s)',26),('Basis',26),('Suspected State Sponsor',20),('State-Link Confidence',14),('MITRE ID',12)]
tk=dict(COLS=TC,inner=(('Technique ID',2),('Technique',3),('Tactic(s)',4),('Basis',5)),outer=((1,'Actor'),(6,'Suspected State Sponsor'),(7,'State-Link Confidence'),(8,'MITRE ID')),srccol=None,typecol=None)
n5=sheet(wb.create_sheet('TTPs'),d+'/actor_ttps_state_sponsored.csv',**tk)
n6=0
HC=[('Actor',24),('Artifact Type',16),('Artifact',58),('Uniqueness',22),('Shared With',34),('Attribution',28),('Note',24),('Source Count',8),('Suspected State Sponsor',18),('State-Link Confidence',12),('MITRE ID',11)]
hk=dict(COLS=HC,inner=(('Artifact Type',2),('Artifact',3),('Uniqueness',4),('Shared With',5),('Attribution',6),('Note',7),('Source Count',8)),outer=((1,'Actor'),(9,'Suspected State Sponsor'),(10,'State-Link Confidence'),(11,'MITRE ID')),srccol=None,typecol=None)
n7=sheet(wb.create_sheet('Host Artifacts'),d+'/actor_host_artifacts_state_sponsored.csv',**hk)
n8=0
print(n3,n4,n5,n6,n7,n8)
import csv as _csv
from openpyxl.utils import get_column_letter
def flat(ws,path,cols):
    rows=list(_csv.DictReader(open(path,encoding='utf-8-sig')))
    for c,(h,wd) in enumerate(cols,1):
        x=ws.cell(1,c,h); x.font=FH; x.fill=PatternFill('solid',fgColor='1F3864'); x.alignment=Alignment(vertical='center',wrap_text=True)
        ws.column_dimensions[get_column_letter(c)].width=wd
    for i,r in enumerate(rows,2):
        for c,(h,wd) in enumerate(cols,1):
            v=r.get(h,'')
            cell=ws.cell(i,c,int(v) if v.isdigit() and len(v)<10 else v[:32000]); cell.font=FB if c==1 else F; cell.alignment=Alignment(vertical='top',wrap_text=True)
            cell.border=Border(left=thin,right=thin,top=thin,bottom=thin)
    ws.freeze_panes='B2'; ws.auto_filter.ref=f"A1:{get_column_letter(len(cols))}{len(rows)+1}"
    return len(rows)
DC=[('Actor',22),('Suspected State Sponsor',14),('State-Link Confidence',11),('MITRE ID',10),('Web Research Status',20),('Most Recent Reported Activity',14),('Recent Activity (2025–2026 web)',70),('Web Profile',50),('MITRE Description',60),('MISP Description',60),('ETDA Description',60),('Sponsoring Org (ETDA)',28),('First Seen (ETDA)',9),('Observed Sectors (ETDA)',28),('Observed Countries (ETDA)',28),('Web Sources',40)]
n9=flat(wb.create_sheet('Descriptions',0),__import__('os').path.dirname(dst)+'/state_actors_descriptions.csv',DC)
RC=[('Actor',22),('Kind',14),('Date / Period',16),('Reported As',18),('Summary',90),('Sources',50),('Suspected State Sponsor',14),('State-Link Confidence',11)]
n10=flat(wb.create_sheet('Recent Activity',1),__import__('os').path.dirname(dst)+'/state_actors_web_activity.csv',RC)
print('desc',n9,'activity',n10)
AC=[('actor',22),('verdict',22),('sponsor_country',14),('state_agency_or_unit',26),('attributing_source',24),('attribution_wording',60),('confidence_wording',16),('latest_report_date',12),('url',50),('notes',60),('reviewed_on',11)]
n11=flat(wb.create_sheet('Attribution Review',2),__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)),'..','data','curation','actor_attribution_review.csv'),AC)
print('review',n11)
_hp=__import__('os').path.dirname(dst)+'/state_actors_malware_hashes.csv'
if __import__('os').path.exists(_hp):
    _H=list(_csv.DictReader(open(_hp,encoding='utf-8')))
    _g=collections.OrderedDict()
    for r in _H:
        x=_g.setdefault((r['Malware'],r['Actor']),{'Malware':r['Malware'],'Actor':r['Actor'],'Sponsor':r['Sponsor'],'State-Link':r['State-Link'],'Samples':0,'All 3 hashes':0,
          'Newest Added':'','Known for this actor (MISP/ETDA/MITRE)':r['Known for this actor (MISP/ETDA/MITRE)'],'Malware sharing':r['Malware sharing'],'Sources':set(),'How the name was found':set()})
        x['Samples']+=1; x['All 3 hashes']+=bool(r['SHA256'] and r['SHA1'] and r['MD5']); x['Newest Added']=max(x['Newest Added'],r['First Added'])
        x['Sources'].add(r['Vendor']); x['How the name was found'].add(r['How the name was found'])
    _rows=[dict(v,Samples=str(v['Samples']),**{'All 3 hashes':str(v['All 3 hashes']),'Sources':', '.join(sorted(v['Sources'])),'How the name was found':'; '.join(sorted(v['How the name was found']))}) for v in _g.values()]
    import tempfile
    _tmp=tempfile.NamedTemporaryFile('w',delete=False,suffix='.csv',encoding='utf-8-sig',newline='')
    _w=_csv.DictWriter(_tmp,fieldnames=list(_rows[0])); _w.writeheader(); _w.writerows(_rows); _tmp.close()
    SC_=[('Malware',22),('Actor',22),('Sponsor',14),('State-Link',10),('Samples',9),('All 3 hashes',10),('Newest Added',12),('Known for this actor (MISP/ETDA/MITRE)',18),('Malware sharing',40),('Sources',18),('How the name was found',46)]
    HC_=[('Malware',22),('Actor',22),('Sponsor',14),('State-Link',10),('SHA256',66),('SHA1',42),('MD5',34),('First Added',12),('Known for this actor (MISP/ETDA/MITRE)',18),('Malware sharing',30),('How the name was found',32),('Source detail',50),('Vendor',11),('Report',36),('Link',50)]
    n12=flat(wb.create_sheet('Malware Hash Summary',3),_tmp.name,SC_); n13=flat(wb.create_sheet('Malware Hashes',4),_hp,HC_)
    __import__('os').unlink(_tmp.name); print('hashes',n12,n13)
_ip=__import__('os').path.dirname(dst)+'/state_actors_incidents.csv'
if __import__('os').path.exists(_ip) and len(list(_csv.DictReader(open(_ip,encoding='utf-8'))))>0:
    IC_=[('Incident',30),('Linked Actors (dataset)',22),('Actors (as reported)',40),('Category',13),('Status',10),('Activity Period',15),('First Reported',11),('Last Updated',11),
         ('Attribution',13),('Victims / Targets',40),('Sectors',28),('Countries',18),('Summary',90),('CVEs',18),('IOC Count',8),('IOC Types',24),('Sources',50),('Incident ID',18)]
    print('incidents',flat(wb.create_sheet('Incidents',2),_ip,IC_))
k=wb.create_sheet('Key')
items=[('Alias Source',None,''),('All three sources','A9D08E','Alias appears in MISP, ETDA and MITRE ATT&CK (strongest agreement)'),('Two sources','E2EFDA','Alias appears in two of the three sources'),
 ('MITRE','FFF2CC','Only in MITRE ATT&CK'),('MISP','DDEBF7','Only in the MISP galaxy file'),('ETDA','FCE4D6','Only in ETDA Threat Group Cards'),('',None,''),
 ('State-Link Confidence',None,''),('High',None,'Named state sponsor (MISP/CFR or ETDA), MITRE description names state backing, Mandiant APT number, or a vendor nation-state name'),
 ('Medium',None,'Description says state-backed, or ETDA motivation is espionage only'),('Low',None,'Country of origin set, no crime/hacktivist signs - review before relying on it'),
 ('Attribution review',None,'Actors that sources only tag with a country were researched on the web (data/curation/actor_attribution_review.csv). Attributed to a state -> High; assessed state-aligned or hybrid crime/espionage -> Medium; mainly criminal, hacktivist or never tied to a government -> removed from the state-sponsored set. See the Attribution Review sheet.'),('',None,''),
 ('Type (malware sheets)',None,'Malware = malicious code (red); Tool = legitimate or dual-use software the actor abuses (e.g. Mimikatz, PsExec); Exploit = exploit kits/code'),('',None,''),
 ('Basis (TTP sheets)',None,'Direct (ATT&CK group) / Campaign = MITRE documents this group using the technique. Inferred from software (grey italic) = technique of malware/tools the actor uses; weaker evidence, and common tools like Cobalt Strike add many'),('',None,''),
 ('Attribution (artifact sheets)',None,'Actor (documented) = MITRE procedure/campaign, a Sigma rule or signature-base section tied to this actor. Via malware (grey italic) = artifact of malware the actor uses; other actors using the same malware share it'),('Artifact (regex)',None,'From signature-base: a regular expression, not a literal path; wildcards (*) come from Sigma rules'),('Note',None,'Common system/dual-use binary = legitimate Windows or admin tool name; only meaningful in an unusual path or with other context'),('',None,''),
 ('Web research (Descriptions / Recent Activity)',None,'Recent activity comes from 2025-2026 vendor reports (ESET, Google GTIG, Trend Micro, CrowdStrike, Kaspersky ICS CERT, Microsoft, Proofpoint, Recorded Future, Trellix, NSFOCUS, CybelAngel) plus targeted articles; each row cites its source. "Checked against reports" = no mention found in those reports, not proof of inactivity.'),('',None,''),
 ('Uniqueness (artifact sheets)','FFFF00','Yellow = Unique to this actor: no other actor in the full dataset (1,259 actors) has this artifact, and it is not a standard Windows/Linux location, autorun key or system binary. Not yellow = common: Shared (listed for 2+ actors, see Shared With) or Common (standard location/name or system/dual-use binary).'),('',None,''),
 ('Malware hashes',None,'Hashes of named, custom malware of state-sponsored actors, from ESET, Cisco Talos, Volexity and Unit 42 IOC repositories. Commercial, open-source, commodity and legitimate tools are excluded (data/curation/cots_exclusions.txt); hashes without a malware name are listed in state_actors_malware_hash_exclusions.csv. The list is cumulative: First Added is the build that first recorded the hash. A hash matches a known sample only; rebuilt malware gets a new hash.'),
 ('Incidents',None,'Major breaches and compromises linked to a state-sponsored actor in this set. The full incident list (any attribution) with IOCs is in out/incidents/major_incidents.xlsx.'),
 ('Data versions',None,open(__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)),'..','data','work','versions.txt')).read())]
for i,(a,f,b) in enumerate(items,1):
    k.cell(i,1,a).font=FB; k.cell(i,2,b).font=F
    if f: k.cell(i,1).fill=PatternFill('solid',fgColor=f)
k.column_dimensions['A'].width=24; k.column_dimensions['B'].width=110
wb.save(dst); print(n1,n2)
