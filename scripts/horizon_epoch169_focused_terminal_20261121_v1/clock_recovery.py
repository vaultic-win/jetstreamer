"""Bind the first replacement of the incomplete 17:20 host census to its intact fleet."""
import os
from pathlib import Path

from evidence import BASE, bound, checked, names, need, pair, sealed, utc

ROOT = BASE / 'host-census-clock-recovery-20261121-v1'
CONFIG = ROOT / 'sealed-next/observer.json'
HEAD = pair(BASE/'root165022-live166167170-20261121-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json',
            '3e688ba96d2116f9c5d7416d0b6759b23ce61989a7d79c45fc9547fca7b5f8d4')
CLOSED = pair(BASE/'epoch168-witness-incident-20261121-v1/historical-forecast-20261121-165022-transfer-v1/CLOSED_172022.json',
              'd9a4e3fd690937a60b59ef74e7ab15bca5f3ad883cefc9bfa7fac5d76d591ef0')
TARGET = '2026-11-21T21:39:22Z'


def replacement(cfg):
    return dict(cfg, not_before_utc=TARGET, output=str(names(TARGET)['sample']))


def view(ref, fleet, cfg):
    if ref != HEAD:
        return fleet, cfg
    old = sealed(fleet['sole_next_observer'])
    receipt = checked(CLOSED)
    failed = checked(receipt['native_sample'])
    host = failed['host_resident_memory']
    need(receipt['native_sample'] == bound(Path(old['output'])) and
         host['before']['status'] == 'observed' and host['after']['status'] == 'unavailable' and
         host['after']['error'] == 'VmRSS missing' and
         not any(Path(p).exists() for p in receipt['missing_native_evidence']) and
         old['not_before_utc'] == failed['recorded_at_utc'] == '2026-11-21T17:20:22Z' and
         failed['cadence']['previous_sample_sha256'] == fleet['observer']['sha256'] and
         utc(TARGET) > utc(receipt['closed_at']), 'closed sample or accepted predecessor changed')
    ref_cfg = bound(CONFIG)
    new = sealed(ref_cfg)
    need(new == replacement(old) and cfg in (old, new), 'replacement changed observation inputs')
    evidence = dict(incomplete_sample=receipt['native_sample'], closed_window=CLOSED,
                    accepted_predecessor=HEAD, original_schedule=fleet['sole_next_observer'],
                    replacement_schedule=ref_cfg, replacement_due=TARGET)
    return dict(fleet, sole_next_timer=names(TARGET)['timer'], sole_next_observer=ref_cfg,
                recovered_host_census_window=evidence), new


def scheduled(path):
    from cycle import load_fleet
    from race166 import properties

    need(path == CONFIG, 'foreign recovery schedule')
    fleet, config, _ = load_fleet(HEAD)
    unit = fleet['sole_next_timer'].removesuffix('.timer') + '.service'
    need(Path('/proc/self/cgroup').read_text().strip() == '0::/system.slice/' + unit and
         properties(unit, 'MainPID', 'InvocationID') ==
         dict(MainPID=str(os.getpid()), InvocationID=os.environ['INVOCATION_ID']) and
         not Path(config['output']).exists(), 'recovery requires its registered native execution')
    return config, HEAD, bound(path)
