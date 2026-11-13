import re, os, glob, json
ROOT='/home/z/my-project/src'
SKIP=['brand-logo','icon.svg','logo.svg','globals.css','engine.ts','/boot','splash','boot-splash']
ROSE_KW=['critical','danger','down','offline','fail','error','block','deny','denied','drop','breach','attack','threat','malicious','quarantine','reject','unreach','expired','delete','remove','sev3','high','alert','breached','compromis']
AMBER_KW=['expir','warn','degrad','pending','stale','retry','caution','attention','paused','degraded']
CLASS_RE=re.compile(r'\b(bg|text|border|ring|ring-offset|divide|from|to|via|fill|stroke|decoration|outline|shadow|accent|caret|placeholder)-(red)-(\d{2,3})(/\d{1,3})?\b')
def map_line(line):
    stripped=line.lstrip()
    if stripped.startswith(('//','*','/*','<!--')): return line,None
    if 'red-' not in line: return line,None
    low=line.lower()
    tgt='amber' if any(k in low for k in AMBER_KW) else ('rose' if any(k in low for k in ROSE_KW) else 'zinc')
    new=CLASS_RE.sub(lambda m: f"{m.group(1)}-{tgt}-{m.group(3)}{m.group(4) or ''}", line)
    return new,(tgt if new!=line else 'kept')
changed={}
for path in glob.glob(ROOT+'/**/*.tsx',recursive=True)+glob.glob(ROOT+'/**/*.ts',recursive=True):
    rel=os.path.relpath(path,ROOT)
    if any(p in rel for p in SKIP): continue
    with open(path) as f: lines=f.readlines()
    out=[];n=0;kinds={}
    for L in lines:
        new,k=map_line(L); out.append(new)
        if k and k!='kept' and k in ('rose','amber','zinc'): n+=1; kinds[k]=kinds.get(k,0)+1
    if n:
        open(path,'w').writelines(out); changed[rel]=[n,kinds]
json.dump(changed,open('/home/z/my-project/scripts/de_red_log.json','w'),indent=1)
print('FILES CHANGED:',len(changed),'TOTAL LINES:',sum(v[0] for v in changed.values()))
print('TOP:'); [print(' ',k,v[0],v[1]) for k,v in sorted(changed.items(),key=lambda x:-x[1][0])[:15]]
pp=ROOT+'/components/charts/palette.tsx'
print('=== palette.tsx dump ===')
print(open(pp).read() if os.path.exists(pp) else 'MISSING')
