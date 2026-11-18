import json, sys, re, collections
p=sys.argv[1]
raw=open(p,'rb').read()
print("bytes",len(raw))
txt=raw.decode('utf-8')  # strict
ctrl=[c for c in txt if ord(c)<32 and c not in '\n\r\t']
print("control chars:",len(ctrl))
bidi=[c for c in txt if c in '‪‫‬‭‮⁦⁧⁨⁩​﻿']
print("bidi/zero-width chars:",len(bidi))
d=json.loads(txt)
print("top keys",list(d.keys()))
print("name",d.get('name'),"version",d.get('version'),"uuid",d.get('uuid'))
vals=d['values']; print("actors",len(vals))
keys=collections.Counter(k for v in vals for k in v); print("value keys",dict(keys))
mk=collections.Counter(k for v in vals for k in v.get('meta',{})); print("meta keys",dict(mk))
syn=sum(len(v.get('meta',{}).get('synonyms',[])) for v in vals); print("total synonyms",syn)
pats={'script/html':r'<\s*(script|iframe|object|embed|img|svg|a\s)','js uri':r'javascript:','data uri':r'data:[a-z]+/[a-z]+;base64','long base64':r'[A-Za-z0-9+/]{200,}={0,2}','powershell':r'(?i)powershell\s+-e','formula inj':r'(^|")[=+@-][A-Za-z]+\(','template':r'\{\{|\$\{'}
for n,r in pats.items():
    m=re.findall(r,txt); print(f"{n}: {len(m)}")
urls=re.findall(r'https?://([^/\s"]+)',txt)
dom=collections.Counter(u.lower() for u in urls)
print("urls",len(urls),"unique domains",len(dom))
print("top domains",dom.most_common(15))
print("non-http schemes",collections.Counter(re.findall(r'"([a-z]{2,10}):\/\/',txt)))
