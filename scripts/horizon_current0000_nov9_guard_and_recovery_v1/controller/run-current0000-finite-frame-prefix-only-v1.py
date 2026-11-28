from actual2300_predecessors import actual2300_predecessors
actual2300_predecessors()
from pathlib import Path
import subprocess, json, os, time
p = Path(__file__).resolve().parent
r = p / 'FRAME_PREFIX_ORIGINALS'
r.mkdir(mode=448)
steps = ['capture-current0000-fleet.py', 'prepare-current0000-cli-witness-v5.py', 'execute-current0000-cli-witness-v5-r3.py', 'finalize-current0000-exact-metadata-r3-v1.py']
for i, n in enumerate(steps):
    a = ['/usr/bin/python3', str(p / n)]
    print('BEGIN', n, flush=True)
    z = subprocess.run(a, capture_output=True, text=True, timeout=700)
    fd = os.open(r / (str(i) + '-ORIGINAL-EXECUTION.json'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 384)
    with os.fdopen(fd, 'w') as h:
        json.dump(dict(argv=a, code=z.returncode, stdout=z.stdout, stderr=z.stderr), h, indent=2)
        h.flush()
        os.fsync(h.fileno())
    print(n, z.returncode, z.stdout, z.stderr, flush=True)
    assert z.returncode == 0
print('Genuine0000 fleet/Frame prefix complete; no0000 resource reader or actor inferred', flush=True)
