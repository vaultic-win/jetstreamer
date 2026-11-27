"""Read the second closed epoch 185 transfer from its sealed native observer."""
import json
from pathlib import Path
import subprocess

from evidence import bound, checked, need

PACKAGE = Path('/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1/cadence-tools-v1')
SEAL = '790924425b6e13cf261a1ce8863ce30ac61287d91d15d8b62e5dcb364a9e3577'
IMAGE = 'd3032a3db5412c5667fcd2f418fc2f95ea60a534e241afb3af9a32322de5ee52'


def install(c, fleet, install_result):
    prior = checked(fleet['epoch185_lanel_holding'])
    need(prior['observer'] == c.sample_ref and prior['fleet'] == c.fleet_ref
         and prior['result']['observation']['stage'] == 'custody-recorded'
         and prior['result']['active_transfer'] is None, 'lane-l handback missing from sample')
    seal = checked(dict(path=str(PACKAGE/'deployment-seal-receipt.json'), sha256=SEAL))
    image = PACKAGE/'holding-observer-k'
    member, = (row for row in seal['members'] if row['name'] == image.name)
    need(seal['destination'] == str(PACKAGE) and member['mode'] == '0555'
         and member['sha256'] == IMAGE == bound(image)['sha256'], 'different lane-k reader')
    raw = subprocess.check_output([str(image), 'reconcile-k'], timeout=60)
    install_result(c, fleet, json.loads(raw), lane='k')
