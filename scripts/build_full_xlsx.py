import csv,sys,itertools
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
                if c==5 and srccol is None and x[k].startswith('Common'): cell.font=Font(name='Arial',size=10,italic=True,color='7F7F7F')
                if c==4 and srccol is None and x[k].startswith('Via malware'): cell.font=Font(name='Arial',size=10,italic=True,color='7F7F7F')
                if c==5 and srccol is None and x[k].startswith('Inferred'): cell.font=Font(name='Arial',size=10,italic=True,color='7F7F7F')
                if c==typecol and x[k]=='Malware': cell.font=Font(name='Arial',size=10,color='C00000')
        for c,k in outer:
            cell=ws.cell(top,c,int(a[k]) if a[k].isdigit() else a[k]); cell.font=FB if c==1 else F; cell.alignment=Alignment(vertical='top',wrap_text=True)
            if bot>top: ws.merge_cells(start_row=top,start_column=c,end_row=bot,end_column=c)
        for rr in range(top,bot+1):
            for c in range(1,len(COLS)+1): ws.cell(rr,c).border=Border(left=thin,right=thin,top=thick if rr==top else thin,bottom=thick if rr==bot else thin)
        r=bot+1
    return n
wb=Workbook(); ws=wb.active; ws.title='State-Sponsored'
n1=sheet(ws,d+'/apt_aliases_by_actor_state_sponsored.csv'); n2=sheet(wb.create_sheet('All Actors'),d+'/apt_aliases_by_actor_all.csv')
MC=[('Actor',24),('Malware / Tool',30),('Type',10),('Source',22),('Suspected State Sponsor',20),('State-Link Confidence',14),('MITRE ID',12),('Malware Count',10),('Tool Count',10)]
kw=dict(COLS=MC,inner=(('Malware / Tool',2),('Type',3),('Source',4)),outer=((1,'Actor'),(5,'Suspected State Sponsor'),(6,'State-Link Confidence'),(7,'MITRE ID'),(8,'Malware Count'),(9,'Tool Count')),srccol=4,typecol=3)
n3=sheet(wb.create_sheet('Malware - State-Sponsored'),d+'/actor_malware_state_sponsored.csv',**kw)
n4=sheet(wb.create_sheet('Malware - All Actors'),d+'/actor_malware_all.csv',**kw)
TC=[('Actor',24),('Technique ID',12),('Technique',52),('Tactic(s)',26),('Basis',26),('Suspected State Sponsor',20),('State-Link Confidence',14),('MITRE ID',12)]
tk=dict(COLS=TC,inner=(('Technique ID',2),('Technique',3),('Tactic(s)',4),('Basis',5)),outer=((1,'Actor'),(6,'Suspected State Sponsor'),(7,'State-Link Confidence'),(8,'MITRE ID')),srccol=None,typecol=None)
n5=sheet(wb.create_sheet('TTPs - State-Sponsored'),d+'/actor_ttps_state_sponsored.csv',**tk)
n6=sheet(wb.create_sheet('TTPs - All Actors'),d+'/actor_ttps_all.csv',**tk)
HC=[('Actor',24),('Artifact Type',16),('Artifact',60),('Attribution',30),('Note',26),('Source Count',8),('Suspected State Sponsor',20),('State-Link Confidence',14),('MITRE ID',12)]
hk=dict(COLS=HC,inner=(('Artifact Type',2),('Artifact',3),('Attribution',4),('Note',5),('Source Count',6)),outer=((1,'Actor'),(7,'Suspected State Sponsor'),(8,'State-Link Confidence'),(9,'MITRE ID')),srccol=None,typecol=None)
n7=sheet(wb.create_sheet('Host Artifacts - State-Spons.'),d+'/actor_host_artifacts_state_sponsored.csv',**hk)
n8=sheet(wb.create_sheet('Host Artifacts - All Actors'),d+'/actor_host_artifacts_all.csv',**hk)
print(n3,n4,n5,n6,n7,n8)
k=wb.create_sheet('Key')
items=[('Alias Source',None,''),('All three sources','A9D08E','Alias appears in MISP, ETDA and MITRE ATT&CK (strongest agreement)'),('Two sources','E2EFDA','Alias appears in two of the three sources'),
 ('MITRE','FFF2CC','Only in MITRE ATT&CK'),('MISP','DDEBF7','Only in the MISP galaxy file'),('ETDA','FCE4D6','Only in ETDA Threat Group Cards'),('',None,''),
 ('State-Link Confidence',None,''),('High',None,'Named state sponsor (MISP/CFR or ETDA), MITRE description names state backing, Mandiant APT number, or a vendor nation-state name'),
 ('Medium',None,'Description says state-backed, or ETDA motivation is espionage only'),('Low',None,'Country of origin set, no crime/hacktivist signs - review before relying on it'),('',None,''),
 ('Type (malware sheets)',None,'Malware = malicious code (red); Tool = legitimate or dual-use software the actor abuses (e.g. Mimikatz, PsExec); Exploit = exploit kits/code'),('',None,''),
 ('Basis (TTP sheets)',None,'Direct (ATT&CK group) / Campaign = MITRE documents this group using the technique. Inferred from software (grey italic) = technique of malware/tools the actor uses; weaker evidence, and common tools like Cobalt Strike add many'),('',None,''),
 ('Attribution (artifact sheets)',None,'Actor (documented) = MITRE procedure/campaign, a Sigma rule or signature-base section tied to this actor. Via malware (grey italic) = artifact of malware the actor uses; other actors using the same malware share it'),('Artifact (regex)',None,'From signature-base: a regular expression, not a literal path; wildcards (*) come from Sigma rules'),('Note',None,'Common system/dual-use binary = legitimate Windows or admin tool name; only meaningful in an unusual path or with other context'),('',None,''),
 ('Data versions',None,open(__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)),'..','data','work','versions.txt')).read())]
for i,(a,f,b) in enumerate(items,1):
    k.cell(i,1,a).font=FB; k.cell(i,2,b).font=F
    if f: k.cell(i,1).fill=PatternFill('solid',fgColor=f)
k.column_dimensions['A'].width=24; k.column_dimensions['B'].width=110
wb.save(dst); print(n1,n2)
