# Builds out/incidents/major_incidents.xlsx from the CSVs written by incidents.py.
# Usage: build_incidents_xlsx.py <incidents out dir> <versions.txt>
import csv,sys,os,collections
from openpyxl import Workbook
from openpyxl.styles import Font,Alignment,PatternFill,Border,Side
from openpyxl.utils import get_column_letter
O,V=sys.argv[1:3]
thin=Side(style='thin',color='BFBFBF')
F=Font(name='Arial',size=10); FB=Font(name='Arial',size=10,bold=True); FH=Font(name='Arial',size=10,bold=True,color='FFFFFF')
FI=Font(name='Arial',size=10,italic=True,color='7F7F7F')
def rows(f): return list(csv.DictReader(open(os.path.join(O,f),encoding='utf-8')))
def flat(ws,rs,cols,hl=None):
    for c,(h,wd) in enumerate(cols,1):
        x=ws.cell(1,c,h); x.font=FH; x.fill=PatternFill('solid',fgColor='1F3864'); x.alignment=Alignment(vertical='center',wrap_text=True)
        ws.column_dimensions[get_column_letter(c)].width=wd
    for i,r in enumerate(rs,2):
        for c,(h,wd) in enumerate(cols,1):
            v=r.get(h,'') or ''
            cell=ws.cell(i,c,int(v) if v.isdigit() and len(v)<10 else v[:32000])
            cell.font=FB if c==1 else F; cell.alignment=Alignment(vertical='top',wrap_text=wd>=30)
            cell.border=Border(left=thin,right=thin,top=thin,bottom=thin)
            if hl: hl(r,h,cell)
    ws.freeze_panes='B2'; ws.auto_filter.ref=f"A1:{get_column_letter(len(cols))}{len(rs)+1}"
    return len(rs)
I=rows('incidents.csv'); X=rows('incident_iocs.csv')
wb=Workbook(); ws=wb.active; ws.title='Incidents'
IC=[('Incident',30),('Category',13),('Status',10),('Activity Period',15),('First Reported',11),('Last Updated',11),('Attribution',13),('State-Sponsored Link',9),
    ('Actors (as reported)',40),('Linked Actors (dataset)',22),('Victims / Targets',40),('Sectors',28),('Countries',18),('Summary',90),('CVEs',18),('ATT&CK Techniques',18),
    ('Watching',9),('IOC Count',8),('IOC Types',24),('Reporters',28),('Sources',50),('Notes',50),('Incident ID',18)]
def hi(r,h,c):
    if h=='State-Sponsored Link' and r[h]=='Yes': c.fill=PatternFill('solid',fgColor='FCE4D6')
flat(ws,I,IC,hi)
summ=collections.OrderedDict()
for r in X:
    summ.setdefault(r['Incident ID'],collections.Counter())[r['Type']]+=1
newest=collections.defaultdict(str); prov=collections.defaultdict(collections.Counter)
for r in X: newest[r['Incident ID']]=max(newest[r['Incident ID']],r['First Added']); prov[r['Incident ID']][r['Provenance'].split(' (')[0].split(' -')[0]]+=1
name={r['Incident ID']:r['Incident'] for r in I}
T=['sha256','sha1','md5','ipv4','ipv6','domain','url','email','file-name','user-agent','http-header','docker-image','app-id','other']
SR=[dict({'Incident':name.get(k,k),'Total':str(sum(c.values())),'Newest Added':newest[k],
          'From vendor repos':str(prov[k].get('vendor IOC repo',0)),'Transcribed':str(prov[k].get('transcribed from report',0))},**{t:str(c.get(t,0)) for t in T}) for k,c in summ.items()]
flat(wb.create_sheet('IOC Summary'),SR,[('Incident',36),('Total',8),('Newest Added',12),('From vendor repos',10),('Transcribed',10)]+[(t,8) for t in T])
def hx(r,h,c):
    if h=='Provenance' and r[h].startswith('transcribed'): c.font=FI
XC=[('Incident',30),('Type',10),('Indicator',48),('Context',60),('Provenance',26),('First Added',11),('Source',60),('Incident ID',18)]
flat(wb.create_sheet('IOCs'),X,XC,hx)
k=wb.create_sheet('Key')
items=[('What this is','Major breaches, compromises, supply-chain attacks and campaigns in the news, whether or not a state is behind them. One YAML file per incident in data/incidents/; key new ones into data/incidents/queue.txt.'),
 ('Attribution','STATE = a government attributes it to a state actor; STATE_ALIGNED = vendor assesses state alignment; CRIMINAL; HACKTIVIST; INSIDER; UNATTRIBUTED; MIXED = several unrelated actors (e.g. a tool used by many groups).'),
 ('State-Sponsored Link','Yes (orange) = at least one reported actor is in the state-sponsored set; these incidents also appear on the Incidents sheet of the state-sponsored workbook.'),
 ('Linked Actors (dataset)','The reported actor names resolved through the alias index (MISP, ETDA, MITRE ATT&CK).'),
 ('Defanged indicators','IPs, domains, URLs and emails are defanged (1.2.3[.]4, evil[.]com, hxxps://) so they cannot be clicked or auto-linked. Refang before loading into a blocklist or SIEM. Hashes are plain lowercase hex.'),
 ('Provenance','vendor IOC repo (exact) = copied by the build from the vendor\'s own IOC file (Cisco Talos, Unit 42, ESET, Volexity). transcribed (grey italic) = keyed in from a report web page; verify against the source before blocking.'),
 ('Not all indicators are malicious','Some reports (e.g. ARTEX) list infrastructure also used for authorized testing. Read the Context and Notes before blocking.'),
 ('Excluded values','Private/reserved IPs, placeholder domains (.invalid, .example), well-known legitimate domains and files the source calls legitimate or decoys are left out; see incident_ioc_exclusions.csv.'),
 ('First Added','The build that first recorded the indicator. The list is cumulative.'),
 ('Watching','Yes = the incident watch keeps checking new vendor IOC reports and CISA KEV entries for its keywords (out/incidents/RADAR.md) and new reporting on the web, and adds new IOCs as they are published.'),
 ('Data versions',open(V).read() if os.path.exists(V) else '')]
for i,(a,b) in enumerate(items,1):
    k.cell(i,1,a).font=FB; c=k.cell(i,2,b); c.font=F; c.alignment=Alignment(wrap_text=True,vertical='top')
k.column_dimensions['A'].width=24; k.column_dimensions['B'].width=110
wb.save(os.path.join(O,'major_incidents.xlsx')); print(f'   incidents workbook: {len(I)} incidents, {len(X)} IOCs')
