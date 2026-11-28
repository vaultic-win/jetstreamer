"""Bind native historical cgroup and allocated-block observations to exact runs."""
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

B = Path('/var/lib/jetstreamer/horizon_runtime_data/epoch199-delivery-recovery-20261121-v1')
OBS = Path('/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1')
LIB = Path('/usr/local/lib/jetstreamer')
WORKER = 'jetstreamer-historical-worker-v1-6-15'
WORKER_SHA = '9339aa0ee5c39e91ec446bfa561c0e81280a0ddc474a03cf5bb0ce07a3674893'
RUNS = {
    '191-194': ('ea93199ed2fa470d99de248c2a10b246', 2189644, 2190510, 'epochs191-194-target5-20261016-v2'),
    '196': ('d1b04cfadb034687b6100aaa9cef3031', 1784721, 1785684, 'epoch196-singleton-20261017-v1'),
    '197': ('c1a2ec00efed4b288ba8913cc87b68ab', 2298573, 2299726, 'epoch197-singleton-20261017-v1'),
    '198': ('e5612ef00a5b4fcab04df2c13a6b35b0', 1165606, 1165957, 'epoch198-readerfix-singleton-20261019-v1'),
    '199-200': ('2a1c51f557a64cd1ad691281cbb77c94', 2467217, 2467614, None)
}
G = 1 << 30

def check(ok, message):
    if not ok:
        raise ValueError(message)

def take(p, expected=None):
    p = Path(p)
    body = p.read_bytes()
    h = hashlib.sha256(body).hexdigest()
    check(expected is None or h == expected, f'source SHA mismatch {p}')
    return body, {'path': str(p), 'sha256': h, 'bytes': len(body)}

def load(p, expected=None):
    body, ref = take(p, expected)
    return json.loads(body), ref

def row(r, name, reference, when):
    iid, pid, wpid, _ = RUNS[name]
    check(r['invocation_binding_stable'] is True, 'unstable observation')
    scratch = Path(r['scratch_path'])
    check(scratch.name == ('private' if name == '199-200' else 'scratch'), 'different coverage')
    peak = []
    oom = []
    for side in ('before', 'after'):
        p = r['producer_' + side]
        w = r['worker_' + side]
        check(p['invocation_id'] == iid and p['main_pid'] == pid, 'producer identity mismatch')
        check(w and w['pid'] == wpid and w['matching_workers'] == 1 and w['executable_beneath_bound_scratch'] is True and Path(w['executable']).is_relative_to(scratch), 'worker identity mismatch')
        check(w['executable'] == r['worker_before']['executable'], 'worker switched')
        cg = p['cgroup']
        peak += [n for n in [p.get('memory_peak_bytes'),cg['gauges'].get('memory.peak')] if isinstance(n,int)]
        oom += [n for n in [cg['counters'].get('memory_events.oom_kill')] if isinstance(n,int)]
    passes = [r['scratch_pass_' + side]['physical_bytes'] for side in ['1','2']]
    check(all(isinstance(v, int) and v > 0 for v in passes) and max(passes) == r['conservative_observed_physical_bytes'], 'bad allocated passes')
    work = r['useful_work']
    check(work.get('journal_invocation_id') == iid, 'activity not bound to producer')
    last = (work.get('last') or {}).get('slot')
    return dict(reference, when=when, last_slot=last, root=str(scratch), passes=passes, peak=max(peak,default=None), oom_kill=max(oom,default=None), effective_cores=(r.get('cross_sample') or {}).get('effective_cpu_cores'),worker=r['worker_after']['executable'])

def lifetime(name, data):
    iid = RUNS[name][0]
    cmd = ['/usr/bin/journalctl','--quiet','--no-pager','-o','json','_PID=1','INVOCATION_ID='+iid]
    raw = subprocess.check_output(cmd)
    rows = [json.loads(line) for line in raw.splitlines()]
    end = [r for r in rows if r.get('MEMORY_PEAK') and r.get('CPU_USAGE_NSEC')]
    if not end and name!='199-200':
        return None
    check(len(end)==1, f'{name} lacks unique PID1 lifetime')
    r = end[0]
    check(r['UNIT'] == data['unit'] and r['INVOCATION_ID']==iid and r['_PID']=='1', 'journal unit mismatch')
    return {k:r.get(k) for k in ('__CURSOR','__REALTIME_TIMESTAMP','MESSAGE','UNIT','INVOCATION_ID','MEMORY_PEAK','MEMORY_SWAP_PEAK','CPU_USAGE_NSEC')}

def collect():
    profiles, prior = load(B/'ORIGINAL_PROFILE_RESOURCE_COMPARISON.json','d0254b5b137afbc25cab014e54f4674f49c70ed21f28bbac87530034289a4527')
    original = {Path(r['source']): r for r in profiles['samples']}
    check(len(original)==84,'199 sample count')
    refs = {}
    samples = {k: [] for k in RUNS}
    not_measured = []
    identities = {}
    october = sorted(p for p in OBS.glob('sample-202610*.json') if '20261017' <= p.name[7:15] <= '20261024')
    for path in [*october,*sorted(original)]:
        data, ref = load(path, original[path]['sha256'] if path in original else None)
        for r in data['replays']:
            k = r['range']
            if k not in RUNS or r['producer_before'].get('invocation_id') != RUNS[k][0]:
                continue
            if not (r.get('worker_before') and r['worker_before'].get('pid') and r.get('worker_after') and r['worker_after'].get('pid')):
                not_measured.append(dict(ref, range=k, reason='worker absent at an endpoint',physical_diagnostic=r.get('conservative_observed_physical_bytes')))
                continue
            sample = row(r,k,ref,data['recorded_at_utc'])
            if path in original:
                check(k=='199-200' and max(sample['passes'])==original[path]['physical_bytes'],'prior witness coverage')
            identity = {'unit':r['producer_before']['unit'],'iid':RUNS[k][0],'pid':RUNS[k][1],'worker_pid':RUNS[k][2], 'root':sample['root'],'executable':sample['worker']}
            check(identities.setdefault(k, identity) == identity, 'generation changed')
            samples[k].append(sample)
            refs[path] = ref
    check(len(samples['199-200'])==84,'full historical 199 coverage')
    index = []
    archive_members = []
    for name in RUNS:
        rows = samples[name]
        check(rows, f'missing observations {name}')
        life = lifetime(name,identities[name])
        check(life is None or int(life['MEMORY_SWAP_PEAK'])==0, 'original used swap')
        summary = dict(range=name, **identities[name], count=len(rows), max_physical=max(max(r['passes']) for r in rows), max_sampled_kernel_peak=max(r['peak'] for r in rows if r['peak'] is not None), max_oom_kill=max(r['oom_kill'] for r in rows if r['oom_kill'] is not None), max_observed_cores=max((r['effective_cores'] for r in rows if r['effective_cores'] is not None), default=None), observed_epochs=sorted({r['last_slot']//432000 for r in rows if r['last_slot']}), lifetime=life)
        check(summary['max_oom_kill']==0 and (life is None or summary['max_sampled_kernel_peak'] <= int(life['MEMORY_PEAK'])), 'kernel accounting mismatch')
        if name!='199-200':
            s, ref = load(Path('/var/lib')/('jetstreamer-root-sweep-'+RUNS[name][3])/'state.json')
            complete = s['completed'][name]
            receipt, member_ref = load(complete['receipt'],complete['receipt_sha256'])
            summary.update(state=ref, batch=member_ref, root_checkpoint_gate_sha256=complete['root_checkpoint_gate_sha256'])
            for x,m in zip(receipt['outcome']['members'],complete['members'],strict=True):
                check(x['epoch']==m['epoch'] and x['archive_sha256']==m['archive_sha256'] and x['committed_archive']['length']>0, 'archive receipt identity')
                archive_members.append({'epoch':x['epoch'],'archive_sha256':x['archive_sha256'],**x['committed_archive']})
        index.append(summary)
    check(index[0]['observed_epochs']==[191,192,193,194] and index[-1]['observed_epochs']==[199], 'sample does not cover claimed epochs')
    check(sorted(m['epoch'] for m in archive_members)==[191,192,193,194,196,197,198], 'missing comparison archives')
    workers = [take(LIB/d/WORKER, WORKER_SHA)[1] for d in ['deploy-epochs191-194-target5-20261016-v1','deploy-epoch199-singleton-20261017-v1','horizon-199200-qualified-20261121-v1']]
    scratch = max(r['max_physical'] for r in index[:-1])
    whole = index[-1]['max_physical']
    archive = max(m['length'] for m in archive_members)
    peak = max(max(r['max_sampled_kernel_peak'], int((r['lifetime'] or {}).get('MEMORY_PEAK',0))) for r in index)
    boot, bootref=load(B/'RETAINED_INPUT_AUTHORITY.json')
    bootstrap=boot['retained_bootstrap']['bytes']
    check(bootstrap==7997778185 and Path(boot['retained_bootstrap']['path']).stat().st_size==bootstrap,'bootstrap length')
    inputs=sum((B/'input-package-v1'/f'epoch-{e}-slot-ranges.raw').stat().st_size for e in (199,200))
    check(inputs==10368000,'compact input lengths')
    # Charge two independent large archives, full bootstrap, compact inputs and the
    # larger of measured scratch and all 199 scratch plus its archive. Deliberate
    # double-counting of the 199 archive covers bootstrap extraction and churn.
    base = max(scratch,whole) + 2*archive + bootstrap + inputs
    check(448*G-base>=48*G and 152*G-peak>=20*G,'candidate margins unsupported')
    return dict(schema='horizon-199-200-historical-footprint-v1',observed_at=datetime.now(timezone.utc).isoformat(),original_profile=prior, source_workers=workers, comparisons=index, committed_members=archive_members,samples=samples,excluded=not_measured,files_in_october_window=len(october),october_window_bytes=sum(p.stat().st_size for p in october),distinct_sample_references=len(refs),retained_input=bootref,estimate=dict(scratch_only_observed=scratch,original_199_whole_private=whole,per_archive_observed_max=archive,archive_charge_count=2,bootstrap=bootstrap,compact_slot_indexes=inputs,conservative_total=base,scheduler_reservation=448*G,additional_margin=448*G-base,max_kernel_peak=peak,max_memory=152*G,raw_memory_margin=152*G-peak),empirical_epoch_200=False)

def save(path, data):
    with path.open('x') as f:
        json.dump(data,f,indent=2,allow_nan=False)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.chmod(path,0o400)

if __name__ == '__main__':
    dest = B/('joint-measure-'+os.environ['INVOCATION_ID'])
    dest.mkdir(mode=0o700)
    result = collect()
    save(dest/'MEASURED.json',result)
    print(json.dumps(result['estimate']),flush=True)
