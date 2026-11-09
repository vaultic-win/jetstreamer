from pathlib import Path
import json, hashlib, os, subprocess
base = Path('/home/sol/.jetstreamer-private')
old = base / 'epoch185-positive-current0500-reviewed-metadata-20261108-v1'
root = base / 'epoch185-positive-current0100-reviewed-metadata-20261109-v1'
from next_operation_bindings import next_operation_bindings
authority = next_operation_bindings()
image = authority['operation']['path']
b = lambda p: dict(path=str(p), sha256=hashlib.sha256(Path(p).read_bytes()).hexdigest())
assert b(image) == authority['operation']

def save(name, v):
    f = root / name
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 256)
    with os.fdopen(fd, 'w') as h:
        json.dump(v, h, indent=2)
        h.flush()
        os.fsync(h.fileno())
    fd = os.open(root, os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)
    return b(f)

def argv(template, verb, request, unit):
    a = list(template)
    i = a.index(verb)
    a[i - 1] = image
    a[i + 1] = str(request)
    a[a.index('--request-sha256') + 1] = b(request)['sha256']
    a[a.index('--self-sha256') + 1] = b(image)['sha256']
    a = ['--unit=' + unit if x.startswith('--unit=') else x for x in a]
    return a
route_binding = authority['qualified_route']
assert b(route_binding['path']) == route_binding
route = json.loads(Path(route_binding['path']).read_text())
capability = route['capability_acceptance']
assert b(capability['path']) == capability
cap = json.loads(Path(capability['path']).read_text())
lifecycle = cap['actual_persistent_reader_lifecycle_control']
assert b(lifecycle['path']) == lifecycle == authority['reader_lifecycle_control']
a = argv(json.loads((old / 'PLANNER_OPERATION_ORIGINAL_EXECUTION.json').read_text())['argv'], 'assemble-positive185', root / 'PLANNER_OPERATION_REQUEST.json', 'horizon-positive185-planner-actual0100-r3-20261109-next')
save('PLANNER_OPERATION_R3_ORIGINAL_ARGV.json', a)
z = subprocess.run(a, capture_output=True, text=True, timeout=150)
save('PLANNER_OPERATION_R3_ORIGINAL_EXECUTION.json', dict(argv=a, code=z.returncode, stdout=z.stdout, stderr=z.stderr))
print('PLANNER', z.returncode, z.stdout, z.stderr, flush=True)
assert z.returncode == 0
result = json.loads(z.stdout)
v = json.loads((old / 'START_ORIGINAL_REQUEST.json').read_text())
v.update(operation_root=str(base / 'epoch185-positive-upstream-actual0100-original-r3-20261109-next'), generation='positive-0100-20261109-next', assembly=b(root / 'ASSEMBLY_REQUEST.json'), planner_manifest=result['actual_planner_result']['metadata_plan'], qualified_route=route_binding, reader_lifecycle_control=lifecycle, normal_pool_closure=b(base / 'first-lane-full-reader-witness-qualification-20261107-v1/combined-runtime/ROOT_HELPER27_CURRENT0100_NORMAL_POOL_REVALIDATED_CLOSURE.json'))
Path(v['operation_root']).mkdir(mode=448)
save('START_ORIGINAL_REQUEST.json', v)
a = argv(json.loads((old / 'START_ORIGINAL_ARGV.json').read_text()), 'start-positive185-original', root / 'START_ORIGINAL_REQUEST.json', 'horizon-positive185-original-actual0100-r3-20261109-next')
save('START_ORIGINAL_ARGV.json', a)
z = subprocess.run(a, capture_output=True, text=True, timeout=930)
save('START_ORIGINAL_EXECUTION.json', dict(argv=a, code=z.returncode, stdout=z.stdout, stderr=z.stderr))
print('ORIGINAL', z.returncode, z.stdout, z.stderr, flush=True)
assert z.returncode == 0
