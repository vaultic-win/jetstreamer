"""Generate the Foundation cadence patch from the two exact deployed inputs."""

import argparse
import ast
import hashlib
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path, help="private directory for the candidate and baseline files")
d = parser.parse_args().output
t=Path('/var/lib/jetstreamer/horizon-seven-publication-controller-v222')
baselines = {
    'cycle.py': 'f93587dcfdab48ef9279fce750a7e21c789cd338609f689883b9f19dc3b1c176',
    'native_binding.py': '568dcbe159aacf25c67c05d854695df521c561fe773857c0d3805e58397c319e',
}
originals = {name: (t / name).read_bytes() for name in baselines}
assert all(hashlib.sha256(originals[name]).hexdigest() == digest for name, digest in baselines.items())

def sub(s,old,new):
 assert s.count(old)==1,old
 return s.replace(old,new)
cycle=originals['cycle.py'].decode()
cycle=sub(cycle, "math, re, fcntl", "math, re, fcntl, time, tempfile")
cycle=sub(cycle, "    if (root(n-1)/'completion.json').exists():prevfleet=bound(ref(root(n-1)/'completion.json'))['fleet']", '''    previous_completion = root(n - 1) / 'completion.json'
    if not previous_completion.exists() and 'fleet' in last:
        recovered = bound(last['fleet'])
        assert recovered['observer_sha256'] == last['observer']['sha256']
        record(previous_completion, dict(observer=last['observer'], fleet=last['fleet'],
                                         statuses=last['statuses'], archive_publications=last['archive_publications']))
    if previous_completion.exists():
        prevfleet = bound(ref(previous_completion))['fleet']''')
cycle=sub(cycle,"import replay261\n",'''import replay261
import publication_handoff
all_claims = dict(roster)
closed = {}
def update_finished():
    # The original terminal watcher may be finishing its authenticated prefix read.
    global closed
    closed = publication_handoff.collect(all_claims, statuses, out, record)
    for e in closed:
        roster.pop(e, None)
        statuses.pop(e, None)
update_finished()
def await_finished(epoch):
    deadline = time.monotonic() + 30
    while True:
        update_finished()
        if epoch in closed: return True
        if time.monotonic() >= deadline: return False
        time.sleep(1)
''')
cycle=sub(cycle,"config=record(out/'config.json',cfg)",'''# A retry reuses the original observation and config, including an owner that
# closed during that observation. Its durable terminal receipt closes the row.
if (out/'config.json').exists():
    saved = bound(ref(out/'config.json'))
    for e in closed:
        key = 'successor247_claim' if e == 247 else f'delivery{e}_claim'
        if key not in saved: cfg.pop(key, None)
        else: assert saved[key] == cfg[key]
        if e == 247: cfg['staged247_resource_only'] = saved['staged247_resource_only']
else:
    for e in closed:
        key = 'successor247_claim' if e == 247 else f'delivery{e}_claim'
        cfg.pop(key, None)
        if e == 247: cfg['staged247_resource_only'] = False
config=record(out/'config.json',cfg)''')
cycle=sub(cycle,"    for binding in roster.values():\n","    for e,binding in list(roster.items()):\n")
cycle=sub(cycle,"        assert (u['InvocationID'],u['ExecStart'])==","        if (u['ActiveState'] != 'active' or u['MainPID'] == '0') and await_finished(e):\n            continue\n        assert (u['InvocationID'],u['ExecStart'])==")
cycle=sub(cycle,"    assert len(rows)==len(roster)","""    check_roster()
    expected = {e for e in all_claims if cfg.get('successor247_claim' if e == 247 else f'delivery{e}_claim')}
    assert {r['range'] for r in rows} == {f'{e}-{e}' for e in expected} and len(rows)==len(expected)
    assert set(roster) <= expected
    for e in expected & set(closed):
        c = bound(all_claims[e])
        row, = [r for r in rows if r['range'] == f'{e}-{e}']
        assert row['producer_unit'] == c['unit'] and row['expected_producer_invocation_id'] == c['invocation_id']""")
cycle=sub(cycle,"        if e in statuses:\n",'''        if e in closed:
            receipt = bound(closed[e])
            add(g, closed[e], receipt['archive'], receipt['playback'], receipt['deletion'])
            g['next_action'] = 'Preserve the authenticated ready pair and release eligible local storage after custody checks.'
        if e in statuses:
''')
cycle=sub(cycle,"def fleet():",'''def fleet():
    # Each changed cohort has a separate immutable attempt. The original
    # observer is reused, and only an accepted receipt can become fleet.json.
    cohort = '-'.join(map(str, sorted(closed))) or 'open'
    target = out / ('fleet-' + cohort + '.json')''')
cycle=sub(cycle,"output=str(out/'fleet.json')","output=str(target)")
cycle=sub(cycle,"binding=record(out/'seven-owner-plan.json',plan)","binding=record(out/f'seven-owner-plan-{cohort}.json',plan)")
cycle=sub(cycle,"    return ref(target)",'''    return ref(target)
def accept_fleet(candidate):
    path = out / 'fleet.json'
    if not path.exists():
        raw = Path(candidate['path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == candidate['sha256']
        with tempfile.NamedTemporaryFile(dir=out, delete=False) as temporary:
            temporary.write(raw)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary.name, path)
        directory = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    binding = ref(path)
    assert binding['sha256'] == candidate['sha256']
    return binding''')
cycle=sub(cycle,"    for e,previous in statuses.items():\n        if e==261 and cfg['replays']:replay261.refresh(previous,sample,globals())\n        else:refresh(e,previous,sample,globals())","""    for e,previous in list(statuses.items()):
        if e in closed: continue
        try:
            if e==261 and cfg['replays']:replay261.refresh(previous,sample,globals())
            else:refresh(e,previous,sample,globals())
        except (AssertionError,sp.CalledProcessError):
            if e not in all_claims or not await_finished(e): raise""")
start = cycle.index("    # The archive/status inventory has its own readback")
middle = cycle.index("    record(out/'status-audit.json',dict(", start)
end = cycle.index("    sp.run([sys.executable,'-B',T/'native_binding.py',str(n)],check=True)", middle)
audit_function = "def final_status_audit():\n" + cycle[start:middle] + '''    entries={v['epoch']:v for v in inventory['entries']}
    for e,c in closed.items():
        archive=bound(bound(c)['archive'])
        v=entries[e]
        assert v['state']=='ready-pair' and v['archive_etag']==archive['archive_etag'] and v['archive_length']==archive['archive_length'] and v['sidecar_sha256']==archive['archive_sha256']
    new_publications=len(set(closed)-{int(e) for e in last.get('completed_publications',{})}) if n>222 else len(closed)
    return dict(completed_publications=dict(closed), archive_publications=new_publications,
                observer=ref(obs), previous_native_fleet=prevfleet, statuses=published,
                active_claims=dict(roster), inventory=inventory, ready_pair_count=inventory['ready_pairs'],
                independently_verified_count=None)
'''
cycle = cycle[:start] + cycle[end:]
cycle=sub(cycle,"if __name__=='__main__':",audit_function+"\nif __name__=='__main__':")
start = cycle.index("    sample=observe()")
end = cycle.index("    sp.run([sys.executable,'-B',T/'native_binding.py',str(n)],check=True)", start)
refresh_function = "def refresh_statuses():\n" + cycle[start:end]
cycle = cycle[:start] + cycle[end:]
cycle=sub(cycle,"if __name__=='__main__':",refresh_function+"\n\nif __name__=='__main__':")
cycle=sub(cycle,"        f=fleet()\n        print(record", "        f=accept_fleet(fleet())\n        print(record")
cycle=sub(cycle,"statuses=a['statuses'],archive_publications=0","statuses=a['statuses'],archive_publications=a.get('archive_publications',0)")
native=originals['native_binding.py'].decode()
native=sub(native,"publishers=[r for r in f['active'] if str(r['epoch']) in states['active_claims']]\nassert len(publishers)==len(states['active_claims'])==7 and all(r['epoch']==261 and r['phase']=='replay' for r in f['active'] if r not in publishers)",'''import publication_handoff
sample_publishers=[r for r in f['active'] if str(r['epoch']) in states['active_claims']]
original={int(k):v['claim'] for k,v in bound(publication_handoff.ROSTER).items()}
assert {r['epoch'] for r in sample_publishers}==set(map(int,states['active_claims'])) and len(sample_publishers)==len(states['active_claims'])
assert all(r['epoch']==261 and r['phase']=='replay' for r in f['active'] if r not in sample_publishers)
live = {int(k): v for k, v in states['active_claims'].items()}
previously_closed = {int(k): bound(v)['claim'] for k, v in states['completed_publications'].items()}
assert not set(live) & set(previously_closed) and {**live, **previously_closed} == original
def record(p,v):
    if p.exists():
        assert bound(ref(p))==v
        return ref(p)
    return funds.put(p,v)
closed=publication_handoff.collect(original,{int(k):v for k,v in states['statuses'].items()},root,record)
publishers=[r for r in sample_publishers if r['epoch'] not in closed]
''')
native=sub(native,"count=len(checks),archive_publications=0","count=len(checks),completed_publications=closed,archive_publications=states.get('archive_publications',0)")
cycle=sub(cycle,"    sp.run([sys.executable,'-B',T/'native_binding.py',str(n)],check=True)",'''    acceptance = out / 'fleet-acceptance.json'
    if not acceptance.exists():
        refresh_statuses()
        while True:
            finished_before = set(closed)
            try:
                state = final_status_audit()
                assert set(closed) == finished_before
                candidate = fleet()
            except (AssertionError, sp.CalledProcessError):
                # Retry this cutoff only when a sealed handoff actually changed
                # its cohort. Never rerun the observer or retry an unrelated error.
                check_roster()
                if not set(closed) - finished_before: raise
            else:
                break
        record(acceptance, dict(state=state, candidate=candidate))
    accepted = bound(ref(acceptance))
    state, candidate = accepted['state'], accepted['candidate']
    assert state['observer'] == ref(obs) and state['previous_native_fleet'] == prevfleet
    assert bound(candidate)['observer_sha256'] == state['observer']['sha256']
    f = accept_fleet(candidate)
    record(out/'status-audit.json', dict(state, fleet=f))
    print(record(out/'completion.json', dict(observer=ref(obs), fleet=f, statuses=state['statuses'],
                                             archive_publications=state['archive_publications'])), flush=True)
    cmd = [sys.executable, '-B', T/'native_binding_handoff.py', str(n)]
    while True:
        finished_before = set(closed)
        attempt = sp.run(cmd)
        if attempt.returncode == 0: break
        check_roster()
        if not set(closed) - finished_before: attempt.check_returncode()''')
for name,data in [('cycle.py',cycle),('native_binding.py',native)]:
 ast.parse(data)
 (d/(name+'.candidate')).write_text(data)
 (d/(name+'.baseline')).write_bytes(originals[name])
