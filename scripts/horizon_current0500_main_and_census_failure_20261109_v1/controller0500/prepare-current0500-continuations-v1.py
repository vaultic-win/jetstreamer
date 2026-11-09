from pathlib import Path
import json, os, hashlib, sys, ast
sys.path.insert(0, str(Path(__file__).resolve().parent))
from current_literal_adapter import adapt
from qualified_bindings import helper27, current_guard, closure27
q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
p = q / 'current0500-20261109-v1'
old = q / 'current0230-20261109-v1'
b = lambda f: dict(path=str(f), sha256=hashlib.sha256(Path(f).read_bytes()).hexdigest())

def save(n, v):
    fd = os.open(p / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as f:
        json.dump(v, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
helper27()
current_guard()
closure27()
accepted = json.loads((p / 'ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_ACCEPTED.json').read_text())
request = json.loads((old / 'completed145-capture-request-v2.json').read_text())
request['census_path'] = '/var/lib/jetstreamer/horizon-completed145-parent-memory-census-v2/' + accepted['observer']['sha256'] + '/census.json'
save('completed145-capture-request-v2.json', request)
params = json.loads((old / 'ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS_TEMPLATE.json').read_text())
params.update(completed145_capture_request_v2=b(p / 'completed145-capture-request-v2.json'), current_inventory=b('/home/sol/.jetstreamer-private/actual050022-visible-root-acceptance-20261109-v1/inventory050022.json'), qualified_current_guard_program=current_guard()[0])
save('ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS_TEMPLATE.json', params)
(p / 'parent').mkdir(mode=448)
prepared_parent = json.loads((Path(__file__).resolve().parent / 'PARENT_SOURCE_BINDINGS.json').read_text())
for row in prepared_parent:
    source = Path(row['prepared_source'])
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == row['prepared_source_sha256']
    ast.parse(raw.decode())
    f = p / 'parent' / source.name
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'wb') as h:
        h.write(raw)
        h.flush()
        os.fsync(h.fileno())
print('Prepared exact0230 reader13/clients4/registration4/DATA4 and UTC-correct guard-window bindings; no output digest predicted.', flush=True)
