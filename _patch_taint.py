import re
f = "/data/files/66a98a8e5f647259/app/secflow-app-entry-analyse/eat_079b99042a5246bd/run/workspace-worker/entry-list-merged.md"
c = open(f).read()
c2 = re.sub(r'->(\w+)\(\)', lambda m: '->' + m.group(1), c)
open(f, 'w').write(c2)
import subprocess
result = subprocess.run(['grep', 'GetChannel', f], capture_output=True, text=True)
print("DONE. Result:", result.stdout.strip() or "(no GetChannel lines)")
