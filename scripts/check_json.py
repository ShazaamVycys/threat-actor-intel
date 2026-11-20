# Generic safety check for a downloaded JSON file: valid UTF-8 JSON, no control/bidi characters, scripts, encoded blobs or formulas.
# Prints the counts and exits 1 if any risky pattern is found.
import json,re,sys
t=open(sys.argv[1],'rb').read().decode('utf-8'); json.loads(t)
pats={'control chars':r'[\x00-\x08\x0b\x0c\x0e-\x1f]','bidi/zero-width chars':'[​-‏‪-‮⁦-⁩]','script/html':r'<\s*(script|iframe|object|embed|svg)',
      'js uri':r'javascript:','data uri':r'data:[a-z]+/[a-z]+;base64','long base64':r'[A-Za-z0-9+/]{200,}={0,2}','powershell':r'(?i)powershell\s+-e','formula inj':r'(^|")[=+@-][A-Za-z]+\(','template':r'\{\{|\$\{'}
bad={k:len(re.findall(v,t)) for k,v in pats.items()}
print('      '+', '.join(f'{k}: {v}' for k,v in bad.items()))
sys.exit(1 if any(bad.values()) else 0)
