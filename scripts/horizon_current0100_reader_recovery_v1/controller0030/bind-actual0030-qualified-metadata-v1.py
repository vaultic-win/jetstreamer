from pathlib import Path
import json, hashlib, os, re, sys
packet = Path(__file__).resolve().parent
sys.path.insert(0, str(packet))
import qualified_bindings as q
assert Path(q.__file__).resolve() == packet / 'qualified_bindings.py'
assert q.FUTURE_HELPER27_BINDINGS_SHA256 is None
b = lambda p: dict(path=str(p), sha256=hashlib.sha256(Path(p).read_bytes()).hexdigest())
_, guard = q.current_guard()
v = json.loads((packet / 'HELPER27_BINDINGS_REQUIRED.NOT_QUALIFIED.json').read_text())
for key in ['qualification', 'exact_source_and_compiler_graph', 'normal_pool_closure']:
    v[key] = q.metadata_bound(v[key]['path'], immutable=False)
closure = json.loads(Path(v['normal_pool_closure']['path']).read_text())
assert guard in closure['required_final_qualifications']
f = packet / 'ROOT_ACTUAL_QUALIFIED_HELPER27_BINDINGS.json'
fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 256)
with os.fdopen(fd, 'w') as h:
    json.dump(v, h, indent=2)
    h.flush()
    os.fsync(h.fileno())
hash_value = b(f)['sha256']
source = packet / 'qualified_bindings.py'
s = source.read_text()
assert s.count('FUTURE_HELPER27_BINDINGS_SHA256 = None') == 1
s = s.replace('FUTURE_HELPER27_BINDINGS_SHA256 = None', 'FUTURE_HELPER27_BINDINGS_SHA256 = ' + repr(hash_value))
source.write_text(s)
q.FUTURE_HELPER27_BINDINGS_SHA256 = hash_value
assert q.helper27()[0] == q._sealed(Path(v['program_directory']), 'jetstreamer-r2', Path(v['qualification']['path']))[0]
q.current_guard()
q.closure27()
print('Actual0030 qualified bindings filled', hash_value, flush=True)
