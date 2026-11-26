"""Print an exact V20 seal plan, using V19's holding image for V25-only mode."""
import argparse
import hashlib
import json
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
DEST = '/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-170-full-metered-independent-v20-joint168'
CHANGED = {'post-stop-fit', 'full146_capacity.py', 'retry4_status.py',
           'full170_capacity.py', 'focused168_capacity.py', 'build_159_price.py', 'retry5_fit.py'}
NEW = {'joint168_capacity.py', 'joint168-scope-template.json'}
parser = argparse.ArgumentParser()
parser.add_argument('--holding-image', type=Path)
parser.add_argument('--observer-binding', type=Path)
args = parser.parse_args()
assert not args.observer_binding or args.holding_image, 'the live V26 route requires the matching holding image'
source = PACKAGE_ROOT/'source'
original = (source/'deployment-seal-receipt.json').read_bytes()
assert hashlib.sha256(original).hexdigest() == '07d761337541dcf93af5cdb87720503ce17e4ec619f995da68d8a6a4e3169102'
members = []

def member(name, path, mode):
    with path.open('rb') as f:
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
    return dict(name=name, source=str(path.resolve(strict=True)), mode=int(mode,8), sha256=digest)

for old in json.loads(original)['members']:
    name = old['name']
    if name == 'SHA256SUMS':
        continue
    path = args.holding_image if name == 'holding185-price' and args.holding_image else source/name
    row = member(name,path,old['mode'])
    if name not in CHANGED and path == source/name:
        assert row['sha256'] == old['sha256'], name
    members.append(row)
for name in sorted(NEW):
    members.append(member(name,source/name,'0444'))
if args.observer_binding:
    members.append(member('v26-joint168-cadence.json',args.observer_binding,'0444'))
destination = DEST if args.observer_binding else DEST + '-prestart-v6'
print(json.dumps(dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=destination,members=members),indent=2))
