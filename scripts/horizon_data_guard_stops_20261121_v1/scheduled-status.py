"""Run the one scheduled status writer with the completed native observer's bytes."""
import os
from pathlib import Path
import sys

from evidence import bound, checked, need, sealed


def main():
    fleet_path, fleet_digest = sys.argv[1:]
    fleet = checked(dict(path=fleet_path, sha256=fleet_digest))
    config = sealed(fleet['sole_next_observer'])
    unit = fleet['sole_next_timer'].removesuffix('.timer') + '-status.service'
    need(Path('/proc/self/cgroup').read_text().strip() == '0::/system.slice/' + unit,
         'unexpected status writer unit')
    sample = bound(Path(config['output']))
    receipt = checked(sample)
    cadence = receipt['cadence']
    need(receipt['schema'] == 'jetstreamer-horizon-live-resource-sample-v2' and
         cadence['configured_not_before_utc'] == config['not_before_utc'] and
         cadence['previous_sample_sha256'] == fleet['observer']['sha256'] and
         cadence['previous_sample'] == config['previous_sample'] == fleet['observer']['path'] and
         cadence['observation_reason'] == config['observation_reason'] == 'routine' and
         cadence['routine_minimum_interval_enforced'] is True, 'missing scheduled sample')
    status = Path(__file__).with_name('status.py')
    os.execv(sys.executable, [sys.executable, '-B', str(status), fleet_path, fleet_digest, sample['sha256']])


if __name__ == '__main__':
    main()
