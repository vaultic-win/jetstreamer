"""Read the adopted retry4 closure and its exclusive cadence registration."""
from pathlib import Path
import runpy
import sys

RUNTIME = Path('/var/lib/jetstreamer/horizon_runtime_data')
STATUS = RUNTIME / 'survivor172-cadence-20261122-v1'
WRITER = STATUS / 'tools-cold168-retry4-failed166-v10-entry146'
INCUMBENT = STATUS / 'tools-cold168-retry4-failed166-v8-entry146'
INCUMBENT_SEAL = '3ae90b99cc09e7b58d1f88bc5ed72e8150d0383c906c0a169e401f262dab370a'
EVIDENCE = RUNTIME / 'prefix140-status-cadence-20261122-v1/cadence-tools'
EVIDENCE_SEAL = '7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e'


def writer_seal(s):
    binding, _ = s.read(Path(__file__).resolve().with_name('cold168-writer.json'))
    return s.ref(WRITER / 'deployment-seal-receipt.json', binding['writer_seal_sha256'])


def registered_writer(s, prior):
    old_package, old_seal, old_iid, old = prior
    s.need(old_package == INCUMBENT and old_seal == s.ref(
        INCUMBENT / 'deployment-seal-receipt.json', INCUMBENT_SEAL), 'different V8 cadence predecessor')
    previous = s.ref(STATUS / 'FAILED166_CADENCE_V8_ACTIVE.json')
    active, _ = s.read(STATUS / 'FAILED166_CADENCE_V10_ACTIVE.json')
    ready = s.bound(active['ready'], STATUS / 'FAILED166_CADENCE_V10_READY.json')
    fleet = s.bound(ready['fleet'], Path(ready['fleet']['path']))
    package = writer_seal(s)
    actor = active['new']
    s.need(active['schema'] == 'horizon-epoch166-cadence-rejoin-active-v1'
           and active['producer_mutations'] is False
           and ready['schema'] == 'horizon-epoch166-cadence-rejoin-ready-v1'
           and ready['old_owner'] == previous and ready['package'] == package
           and ready['config'] == fleet['sole_next_observer'] and ready['timer'] == fleet['sole_next_timer']
           and active['old'] == old == s.bound(previous, Path(previous['path']))['new']
           and old_iid == old['invocation_id']
           and actor['unit'] == old['unit'] and actor['program'] == str(WRITER / 'status_cycle.py')
           and s.iid(actor['invocation_id']) and actor['invocation_id'] != old_iid
           and actor['pid'] > 1 and actor['start_ticks'] > old['start_ticks']
           and all(actor['lock'][key] == old['lock'][key] for key in ('path', 'device', 'inode')),
           'different V10 cadence, lease or observation handoff')
    return WRITER, package, actor['invocation_id'], actor


def current(s, load_package, fleet):
    s.need(fleet.get('cold168_local_commit') and fleet.get('cold168_guard_retirement')
           and not fleet.get('metered168_local_commit'), 'retry4 terminal and guard are not adopted')
    load_package(EVIDENCE, EVIDENCE_SEAL)
    load_package(WRITER, writer_seal(s)['sha256'])
    sys.path.insert(0, str(EVIDENCE))
    try:
        route = runpy.run_path(str(WRITER / 'cold168_commit.py'))
        s.need(Path(sys.modules['evidence'].__file__) == EVIDENCE / 'evidence.py',
               'foreign cold168 closure evidence reader')
        proof = route['current'](fleet)
        s.need(proof and fleet['retained_cold168_retry4_reservation'] == route['retained_booking'](proof),
               'missing exact cold168 retained booking')
    finally:
        sys.path.pop(0)
    return proof
