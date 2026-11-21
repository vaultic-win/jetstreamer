"""Compare all native V13 populations and the actual V2 checkpoint prices offline."""
from pathlib import Path
import hashlib
import json
import runpy

HERE = Path(__file__).resolve().parent
ROOT = Path('/var/lib/jetstreamer/horizon_runtime_data')

def read(ref):
    raw = Path(ref['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ref['sha256']
    return json.loads(raw)

def normalized(value):
    return json.loads(json.dumps(value))

def main():
    model = runpy.run_path(str(HERE/'forecast_routes.py'))
    budget = runpy.run_path(str(HERE/'transition_budget.py'))
    standby = read(dict(path=str(ROOT/'epoch199-delivery-recovery-20261121-v1/transition-state/V2_NATIVE_PREFLIGHT.json'),
                        sha256='892977c86270ac0bf7d40055902100d8413c87cec5befb67be545ac5d4215656'))['native_qa']
    qa = read(standby['focused169_matrix'])
    native = read(qa['native'])
    fleet = read(native['fleet'])
    ledger = read(native['registered_host_equation']['source'])
    prior169 = read(dict(path=str(ROOT/'epoch169-focused-admission-20261120-v4/POST_GUARD_CAPACITY.json'),
                         sha256='803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc'))
    sample = read(fleet['observer'])
    ram = sample['host_memory']['total_kib']*1024
    rows = model['price_rows'](native, fleet, ledger, prior169['protected_raw_floor_bytes'], ram, budget)
    assert len(rows) == qa['matrix']['counts']['transfer_combinations'] == 486
    for price in qa['matrix']['prices']:
        replacement, _ = model['project_population'](native,fleet,price['canonical'],price['focused169_closed'],budget)
        assert replacement['complete_required_HOME_bytes'] == price['required_HOME_bytes']
        assert replacement['required_available_memory_bytes'] == price['required_available_memory_bytes']
        assert replacement['original_aggregate_HOME_bytes']-native['epoch170_extension']['extra_bytes'] == price['raw']
    comparable = [dict(r) for r in rows if not r['private169_closed'] and r['transferred']==r['closed']]
    for row in comparable:
        del row['private169_closed']
    order = lambda row:(len(row['closed']),row['closed'])
    assert sorted(normalized(comparable),key=order) == sorted(standby['current_scenarios'],key=order)
    grant={e:110+e for e in budget['ALL_CAP']}
    closure={e:10+e for e in budget['ALL_CAP']}
    route=dict(sources=['physical'],net_bytes=1<<40,ready_ms=0,dated=True)
    selected,_=model['select_routes'](rows,closure,grant,165,0,[route])
    assert selected['row']['private169_closed'] and not set(selected['row']['transferred'])-set(selected['row']['closed'])
    assert selected['start_ms'] == max(grant[e] for e in selected['row']['transferred'])
    assert len(selected['row']['transferred']) < 5
    try:
        model['select_routes'](rows,closure,grant,165,0,[dict(route,dated=False)])
    except ValueError:
        pass
    else:
        raise AssertionError('undated physical release became an ETA')
    print('Verified 64 native V13 populations, 486 grant states, 32 original V2 prices and conditional scheduling controls.')

if __name__ == '__main__':
    main()
