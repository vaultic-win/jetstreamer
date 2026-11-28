import time as _time
assert _time.time() < 1794192322, 'Original0230 startup cutoff expired'
from pathlib import Path as _Path
import hashlib as _hashlib
_bridges = [{'observer': {'path': '/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T013022Z-postcompletion154-v1.json', 'sha256': 'fa22ccada8e92460fa52cdbf7fd9ef7184db3e6a1eaef2a8da10706999976ab6'}}, {'observer': {'path': '/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T020022Z-postcompletion154-v1.json', 'sha256': 'e3fc848255d438d473e059cff501b7c62ff7b256ddb3a81645129fe747ff6b1a'}}]
for _row in _bridges:
    _binding = _row['observer']; _path = _Path(_binding['path'])
    assert _path.stat().st_mode & 0o222 == 0, 'Root readonly finalization required for both actual bridge observers'
    assert _hashlib.sha256(_path.read_bytes()).hexdigest() == _binding['sha256']
from prelaunch_phase199_binding import qualified_prelaunch_phase
qualified_prelaunch_phase()
from actual0100_predecessors import actual0100_predecessors
actual0100_predecessors()
from pathlib import Path
import subprocess, json, os, time
p = Path(__file__).resolve().parent
r = p / 'FRAME_PREFIX_ORIGINALS'
r.mkdir(mode=448)
steps = ['capture-current0230-fleet.py', 'prepare-current0230-cli-witness-v5.py', 'execute-current0230-cli-witness-v5-observer-bridges-r5.py', 'finalize-current0230-exact-metadata-observer-bridges-r5.py']
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
print('Genuine0230 fleet/Frame prefix complete; no0230 resource reader or actor inferred', flush=True)
