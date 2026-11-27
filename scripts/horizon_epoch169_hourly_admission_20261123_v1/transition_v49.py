"""Adopt V48's consumers, private assignments and original scheduled observer."""
from pathlib import Path

from evidence import bound, checked, need
from transition import clock
import rolling170_fourth_status as rolling
import split_status169 as hourly
import status162

V48_SHA = '9ca6211354be131c738c83edb2aaf4d0439423455d7dffca7950f76e84c32eb6'
V48_SEAL = 'e6c2609a84e2d5eb8029ebf91332a49b6f1db7dbb2b11047d4ba228c2b2a3f90'
REBOUND = 'bc74fb72fbcc58d0b8c5855ade3b097d2d340c07a96f87d83927f04cd34fc69c'


def assignments(fleet):
    """Use stable guard admission identities across the handoff, including event starts."""
    actors = {}
    for row in (hourly.reader()['current'](fleet),status162.current(fleet)):
        if row and row['phase'] != 'terminal':
            actors[row['unit']['Id']] = dict(unit=row['unit']['Id'], iid=row['unit']['InvocationID'],
                    pid=row['unit']['MainPID'], intent=row.get('hourly169_start_intent') or row['held_owner'])
    return actors


def ready(api, head, seal):
    root, base, current = api['ROOT'], api['BASE'], api['CURRENT']
    oldref = dict(path=str(root / 'FAILED166_CADENCE_V48_ACTIVE.json'), sha256=V48_SHA)
    old = checked(oldref)
    earlier = checked(old['ready'])
    previous = root / api['failed166_package'](48)
    need(earlier['package'] == dict(path=str(previous / 'deployment-seal-receipt.json'),sha256=V48_SEAL)
         and old['new']['program'] == str(previous / 'status_cycle.py'), 'unexpected V48 owner')
    listener = dict(path=str(base / 'epoch143-first-hourly-20261127-v1/REENTRY_V48_REBOUND.json'),sha256=REBOUND)
    rebound = checked(listener)
    need(rebound['original'] == earlier['retained_143_listener'] and rebound['phase'] == earlier['retained_143_phase']
         and rebound['writer_package'] == earlier['package'], '143 native exclusion changed')
    fleet = checked(head)
    need(Path(head['path']) == max(base.glob('root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json'),key=lambda f:f.stat().st_mtime_ns),
         'V49 fleet superseded')
    cfgref, timer = fleet['sole_next_observer'], fleet['sole_next_timer']
    cfg = api['sealed'](cfgref)
    done = clock(api,fleet,cfg,timer,cfgref)
    api['tail167_status'].retained_population(fleet,cfg)
    api['bridge170_status'].retained_population(fleet,cfg)
    rolling.retained_population(fleet,cfg)
    need(earlier['successor170_interface']==rolling.INTERFACE
         and earlier['prior_successor170_interface']==rolling.history.INTERFACE,'170 assignment changed')
    rebound_members = {k:bound(current.with_name(Path(ref['path']).name)) for k,ref in earlier.items()
               if isinstance(ref,dict) and 'path' in ref and Path(ref['path']).parent == previous and k != 'package'}
    return earlier | rebound_members | dict(package=seal, old_owner=oldref, fleet=head, config=cfgref, timer=timer,
               completed_sample=done, retained_143_v48_rebound=listener, protected_private_assignments=assignments(fleet),
               split_wire_receiver=bound(current.with_name('split_wire.py')))


def validate(api, proposed, seal):
    actual = ready(api,proposed['fleet'],seal)
    need(actual == proposed or proposed['completed_sample'] is None and actual['completed_sample'] is not None
         and dict(actual,completed_sample=None) == proposed,'V49 lost its observer or protected actors')
