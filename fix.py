python3 -c "
import re; from pathlib import Path; files=list(Path('.').glob('*.py')); total=0
for f in files:
    c=f.read_text(encoding='utf-8'); o=c
    c=re.sub(r'(st\.button\b[^)]*?),\s*width=\'stretch\'', r'\1, use_container_width=True', c)
    c=re.sub(r'(st\.button\b[^)]*?),\s*width=\'content\'', r'\1', c)
    if c!=o:
        f.write_text(c,encoding='utf-8'); n=o.count('width=')-c.count('width='); total+=n; print('Fixed',f.name)
print('Done',total,'fixes')
"