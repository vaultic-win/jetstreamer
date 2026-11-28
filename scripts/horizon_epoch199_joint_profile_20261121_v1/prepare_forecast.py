"""Prepare an immutable follow-up for an accepted cadence or its named successor."""
from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import os
import sys

ROOT = Path('/var/lib/jetstreamer/horizon_runtime_data')
INC = ROOT / 'epoch168-witness-incident-20261121-v1'
CADENCE = ROOT / 'epoch169-focused-terminal-20261121-v1/cadence-tools'
SEAL = '96f3180ef0ed6a35765f28afd698330db267f3092dcf4c9b648b819e69ef4810'
PLAN = '98c7993ec902876c7515cf0a941a3bd455be9e91999a96ed67ca20b1b47c25c0'
APPLY = 'e36663c0305b73669e452873ec05426a7dd8d401a3f26603a30edc1d981c4fcd'


def replace(text, old, new, count=1):
    if text.count(old) != count:
        raise ValueError('different forecast template near ' + old[:80])
    return text.replace(old, new)


def immutable(path, data):
    if path.exists():
        if path.read_bytes() != data or path.stat().st_uid != 0:
            raise ValueError('different generated model at ' + str(path))
    else:
        with path.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o444)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    return hashlib.sha256(data).hexdigest()


def active_controller():
    # The original owner keeps the sealed shell script on fd 255 and the stable
    # exclusive lock on fd 9 across all supported per-cycle package upgrades.
    import json
    import subprocess
    unit='horizon-archive-status-cadence-after172-20261120-v1.service'
    props=dict(line.split('=',1) for line in subprocess.check_output(
        ['systemctl','show',unit,'-p','MainPID,ActiveState,SubState,Job,InvocationID'],text=True).splitlines())
    assert props['ActiveState']=='active' and props['SubState']=='running' and not props['Job']
    proc=Path('/proc')/props['MainPID']
    script=(proc/'fd/255').readlink()
    lock=Path('/var/lib/jetstreamer/horizon_runtime_data/stable-cadence-controller-20261120-v1/consumer.lock')
    assert (proc/'fd/9').samefile(lock) and any(' FLOCK ' in line and ' WRITE ' in line for line in (proc/'fdinfo/9').read_text().splitlines())
    assert script.name=='consume' and script.parent.parent.parent==lock.parent.parent and (proc/'fd/255').samefile(script)
    seal=script.parent/'deployment-seal-receipt.json'
    data=seal.read_bytes()
    val=json.loads(data)
    assert seal.stat().st_uid==0 and not seal.stat().st_mode&0o022 and val['destination']==str(script.parent)
    for name in ('consume','evidence.py','status.py','recovered.py'):
        row,=[w for w in val['members'] if w['name']==name]
        path=script.parent/name
        assert path.stat().st_uid==0 and not path.stat().st_mode&0o022 and hashlib.sha256(path.read_bytes()).hexdigest()==row['sha256']
    return script.parent,hashlib.sha256(data).hexdigest()


def prepare(mode, fleet, paid, fit_path, fit_hash):
    assert __debug__ and sys.flags.isolated and os.geteuid() == 0
    sys.path.insert(0, str(CADENCE))
    from evidence import bound, checked, sealed, utc, names, ensure_dir, syncdir
    assert bound(CADENCE/'deployment-seal-receipt.json')['sha256'] == SEAL
    assert fleet.parent.parent == ROOT and fleet.name == 'ROOT_COMPLETE_OPERATIONAL_FLEET.json'
    assert paid.parent.parent == INC and paid.name == 'RESULT.json'
    head_ref, paid_ref = bound(fleet), bound(paid)
    head, prior = checked(head_ref), checked(paid_ref)
    assert head['all_active_status_reports_authenticated_readback'] and prior['authenticated_existing_statuses'] == 19
    previous_model = checked(prior['reconciliation'])
    semantic=ROOT/'epoch145-semantic-continuity-20261121-v1'
    original=semantic/'V5C_ACTUAL_ADVANCING_WORKER.json'
    successor=semantic/'V5D_ACTUAL_ADVANCING_WORKER.json'
    retry=semantic/'V5D_RETRY1_ACTUAL_ADVANCING_WORKER.json'
    old_worker=previous_model['actual_145_worker']
    assert old_worker in [bound(p) for p in (original,successor,retry) if p.exists()]
    if fit_path is None:
        inherited=previous_model.get('conditional_transition',{}).get('sources',{}).get('native_capacity')
        if inherited:
            fit_path,fit_hash=Path(inherited['path']),inherited['sha256']
        else:
            fit_path=ROOT/'epoch172-current-delivery-20261121-v1/event172-run-c077680a3b774395a639ee769f5c400b/fit.json'
            fit_hash='31744ff6348112e83adeaca1dac44f3c6ef3f706a888f1ad1365a893a2066445'
    assert bound(fit_path)['sha256']==fit_hash
    matched = previous_model['native_fleet'] == head_ref
    if mode == 'next':
        assert matched
        stamp = sealed(head['sole_next_observer'])['not_before_utc']
        paths = names(stamp)
        assert paths['timer'] == head['sole_next_timer'] and utc(stamp) == utc(head['sampled_at_utc'])+dt.timedelta(seconds=1800)
        out = paths['out']
        predecessor = head_ref
    else:
        # A late rescue can start after its configured slot. Status and lock
        # directories use the configured slot; the successor uses actual sample time.
        observed=checked(head['observer'])
        assert observed['recorded_at_utc']==head['sampled_at_utc']
        stamp = observed['cadence']['configured_not_before_utc']
        out = fleet.parent
        assert names(stamp)['out']==out and utc(stamp)<=utc(head['sampled_at_utc'])
        predecessor = head['previous_Root_operational_review']
        cursor=head_ref
        while cursor != previous_model['native_fleet']:
            ancestor=checked(cursor)['previous_Root_operational_review']
            assert checked(ancestor)['recorded_unix_seconds'] < checked(cursor)['recorded_unix_seconds']
            cursor=ancestor
    same_window = mode == 'current' and matched
    day, tag = utc(stamp).strftime('%Y%m%d %H%M%S').split()
    actual_slot=head['sampled_at_utc'] if mode=='current' else stamp
    closed_window = utc(actual_slot)+dt.timedelta(seconds=1800) <= dt.datetime.now(dt.timezone.utc)
    cadence, controller_hash = (CADENCE, SEAL) if closed_window else active_controller()
    terminal = ROOT/'epoch145-guarded-export-20261121-v1/state/d37f36f898a44932a19fd50d7014a6fe/failed.json'
    first_successor=successor
    if retry.exists():
        successor=retry
    successor_ref=bound(successor) if not closed_window and successor.exists() else None
    names_to_copy=('forecast_routes.py','forecast_evidence.py')
    source_hashes={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                   for name in (*names_to_copy,'prepare_forecast.py')}
    generation_inputs=dict(previous=predecessor, paid=paid_ref, fit=str(fit_path), fit_hash=fit_hash,
                           controller=controller_hash, source=source_hashes, same_window=same_window, successor=successor_ref,
                           worker_terminal=bound(terminal) if terminal.exists() else None)
    generation=hashlib.sha256(json.dumps(generation_inputs,sort_keys=True).encode()).hexdigest()[:16]
    suffix = f'{day}-{tag}-transfer-{generation}'
    dest = INC / ('forecast-'+suffix)
    ensure_dir(dest)
    template = INC / 'forecast-165022-live145v5c'
    assert bound(template/'plan.py')['sha256'] == PLAN and bound(template/'apply.py')['sha256'] == APPLY
    pin = {}
    for name in names_to_copy:
        source = Path(__file__).with_name(name).read_bytes()
        compile(source, name, 'exec')
        pin[name] = immutable(dest/name, source)
    plan = (template/'plan.py').read_text()
    for old,new in [('epoch172-current-delivery-20261121-v1/cadence-tools',str(cadence.relative_to(ROOT))),
                    ('930f0aa28fa2c4219d97eb92d1b8739799eb89539411bb9d2c510602344998a9',controller_hash),
                    ('root165022-live166167170-20261121-v1',out.name),
                    ('c09dfd8d51ed7ff59d60d923017e9b36cbab777fbc3f78e8d63510b0f27330f9',predecessor['sha256']),
                    ('dependent-forecast-162022-live145v5c',paid.parent.name),
                    ('c1f220798bd8c5fa09592c94d5fc51c14aeac43535c939201365cf87d8bb9fd6',paid_ref['sha256'])]:
        plan = replace(plan,old,new)
    if same_window:
        plan = replace(plan,'paid=checked(paid_ref)',"""paid=checked(paid_ref)
assert checked(paid['reconciliation'])['native_fleet']==fref
previous_statuses=paid['conditional_statuses_verified']
if 'full_readback' in paid:
    receipt=checked(paid['full_readback'])
    assert receipt['native_fleet']==fref and set(receipt['statuses'])==set(basis)
    previous_statuses=receipt['statuses']
for key,item in previous_statuses.items():
    row=checked(item['receipt'])
    found,_=follow_event(int(key),basis[key],row['after_etag'],body(row['after_status']))
    assert found==item['receipt'] and row['after_etag']==item.get('etag',row['after_etag']) and row['after_sha256']==item.get('sha256',row['after_sha256'])
    basis[key]=found""")
    historical = False
    if successor_ref:
        proof=checked(successor_ref)
        actual=checked(proof['start'])
        assert proof['schema']=='horizon-145-v5d-actual-advancing-original-semantic-recovery-v1'
        authentic_failure=bound(terminal)
        assert authentic_failure['sha256']=='6533e594be11534e7fb58ac0f1fd752ead37cfd114e36899a956970b8318bb29'
        assert actual['prior_frozen_recovery']['failed_status_owner']['current_boot_failure']['failure']==authentic_failure
        build=checked(bound(semantic/'tools-v5d/build-proof.json'))
        assert build['old_failure']==authentic_failure and actual['image']==build['verifier_sha256']
        assert bound(semantic/'tools-v5d/deployment-seal-receipt.json')['sha256']=='8d24b10c8df29a469ae0bb26a3605618289a8feae23565d28d792791bba58bfb'
        assert actual['image']=='3d60de86d45a497bcd1b9836c485ffab4ce1da19cb6d989d56c9d3b92ad60066'
        if successor==retry:
            assert successor_ref['sha256']=='3a41dac31746938b482133b9ff224f9d9d821569cc16f63c83f872fe907c13e0'
            manager=checked(proof['manager'])
            intent=checked(manager['intent'])
            assert manager['intent']['sha256']=='90634731ae1f0c815b9dfc8d18c118c641f7b8961d39b744f27379a489899dfd'
            assert intent['previous_advancement']==bound(first_successor) and intent['old']==checked(intent['previous_advancement'])['invocation_id']
            authentic_failure=intent['failure']
            assert authentic_failure['sha256']=='04c96683252ad3815d906d43dbbfb2f80d3ebcf542d7e671f28119f74767b107'
            stopped=checked(authentic_failure)
            assert stopped['iid']==intent['old'] and stopped['error'].strip().endswith('ValueError: foreign qualifier unit')
            assert checked(intent['fit'])['phase145']['failure']==authentic_failure
        plan=replace(plan,original.name,successor.name)
        plan=replace(plan,'6235fbd8e36064d57a9cd6b7af2ad0d05ce8b41766134cde7be7337ebc133d76',successor_ref['sha256'])
        plan=replace(plan,'34d90f2a5ae8a821109b2bbf99c5527d43c3eb141f68cea212109fc876f28c8d',actual['image'])
        plan=replace(plan,"failure_ref=last['terminal_145']",f"failure_ref={authentic_failure!r}")
    elif terminal.exists():
        terminal_ref = bound(terminal)
        stopped = checked(terminal_ref)
        assert terminal_ref['sha256']=='6533e594be11534e7fb58ac0f1fd752ead37cfd114e36899a956970b8318bb29'
        historical = utc(stamp).timestamp()+1800 <= stopped['at']
        start = plan.index('def verify_live():')
        end = plan.index('model={}',start)
        if historical:
            state_check = f"""failure_later={terminal_ref!r}
assert checked(failure_later)['at']>int(utc(head['sampled_at_utc']).timestamp())
def verify_live():
    raise ValueError('historical window closed before this terminal; never publish')
"""
        else:
            template_stopped = INC/'forecast-144959-stopped145/plan.py'
            assert bound(template_stopped)['sha256']=='c73e6c90b4f072f8db543ee2c464ab3c935363f7e6757cc3dcc96151da37f369'
            source=template_stopped.read_text()
            state_check=source[source.index('preceding_recovery_ms ='):source.index('model={}')]
            state_check=replace(state_check,'baa00ca8b52aca80b105bf5582f955af8a3f9e22ce662908ce7a75afccfb1943',terminal_ref['sha256'])
            state_check=replace(state_check,"'subprocess.TimeoutExpired:' in failure['error'] and 'timed out after 10 seconds' in failure['error']", "'ValueError: cadence publisher absent' in failure['error']")
            state_check=replace(state_check,'verify_stopped()', 'verify_live()',2)
            if utc(stamp).timestamp()>stopped['at']+7200:
                state_check += '''# The two-hour repair needs the current cadence registration and accepted head.
# A stopped verifier could not consume that interval during the publisher outage.
recovery_cursor=fref
while True:
    recovery_head=checked(recovery_cursor)
    predecessor_ref=recovery_head['previous_Root_operational_review']
    if checked(predecessor_ref)['recorded_unix_seconds']<=failure['at']:
        break
    recovery_cursor=predecessor_ref
funded_window_ms=max(failure['at']*1000,recovery_head['recorded_unix_seconds']*1000)
repair_gate=max(funded_window_ms+budget,head['recorded_unix_seconds']*1000+preceding_recovery_ms)
'''

            plan=replace(plan,'The replacement verifier is processing the retained candidate. Budget both complete semantic passes and publication from the actual funded start.','The 145 verifier stopped on the registered cadence publisher before either semantic checkpoint. Allow the previously qualified repair window, both complete semantic reads on the retained inode, and the original publication stages.')
        plan=plan[:start]+state_check+plan[end:]
    left = plan.index('for n in (199,200):')
    right = plan.index('older=checked',left)
    assert 'sorted(deadlines[k]' in plan[left:right]
    plan = plan[:left]+f"""import runpy
def sealed_model(name, checksum):
    path=Path(__file__).resolve().parent/name
    assert sha(path)==checksum
    return runpy.run_path(str(path))
routes=sealed_model('forecast_routes.py',{pin['forecast_routes.py']!r})
evidence=sealed_model('forecast_evidence.py',{pin['forecast_evidence.py']!r})
transfer=evidence['forecast_transition'](routes,checked,bound,fref,prior,deadlines,replay_end,ready,
    Path({str(fit_path)!r}),{fit_hash!r},worker_ref)
chosen=transfer['selected']
for n in (199,200):
    after(n,chosen['start_ms'],transfer['conditions'])
    model[n]['conditional_transfer']=chosen
"""+plan[right:]
    old_start = "after(141,max(ready,replay_end[167],"
    queue = """grants=chosen['row']['transferred']
joint_phases=model[199]['phase_milliseconds']
import_allowance=prior[170]['delivery_forecast']['phase_milliseconds']['assembly_close_import']
assert import_allowance==7200000 and import_allowance<joint_phases['full_plugin_boundary_and_authenticated_delivery']
joint_import_end=chosen['start_ms']+joint_phases['full_two_epoch_replay_and_checkpoints']+joint_phases['recovery_contingency']+import_allowance
donor_173=bound(rt/'epoch173-native-route-20261121-v1/TERMINAL166_SUCCESSOR_WINDOW.json')
assert donor_173['sha256']=='9dcfc65087231724d0ee8fe41c6252161c3c4b422f51743ede80025a82529b35'
assert checked(donor_173)['donor_iid']!=prior[166]['producer_invocation_id']
transfer.update(joint_import_reconciliation_ms=joint_import_end,exclusive_grants=grants,
    joint_import_allowance_ms=import_allowance,original173_donor=donor_173,
    queue_basis='Exclusive donor bookings remain with the joint 199–200 controller through both local imports and reconciliation. Use the native two-hour assembly/close/import allowance inside the ordinary delivery stage. Every successor requires a fresh fit and owner allocation; the retired original 166 grant does not transfer to 173.')
def donor_available(epoch, original):
    return max(original,joint_import_end) if epoch in grants else original
after(141,max(ready,donor_available(167,replay_end[167]),"""
    plan=replace(plan,old_start,queue)
    plan=replace(plan,"after(173,max(ready,deadlines[166]),'Retain guarded 166 delivery and 145 completion before full 173 replay.')",
        "after(173,max(ready,donor_available(166,deadlines[166])),'Budget the original 173 phases following 145, guarded 166 delivery, a separately qualified successor allocation and any exclusive 199–200 grant through joint import reconciliation.')")
    plan=replace(plan,"170:stage_end(199,['full_two_epoch_replay_and_checkpoints','recovery_contingency']),172:replay_end[172]",
        "170:donor_available(170,replay_end[170]),172:donor_available(172,replay_end[172])")
    plan_digest = immutable(dest/'plan.py',plan.encode())
    apply = (template/'apply.py').read_text()
    for old,new,count in [
        (PLAN,plan_digest,1), ('dependent-forecast-165022-live145v5c','dependent-forecast-'+suffix,1),
        ('2026-11-21T16:50:22Z',stamp,1), (" and next_time.date()==utc(head['sampled_at_utc']).date()", '',1),
        ("next_tag=next_time.strftime('%H%M%S')","next_tag=next_time.strftime('%H%M%S')\nnext_day=next_time.strftime('%Y%m%d')",1),
        ('{next_tag}-live166167170-20261121-v1.timer','{next_tag}-live166167170-{next_day}-v1.timer',1),
        ('after165022-20261121-v1','after'+tag+'-'+day+'-transfer-'+generation,1),
        ('cycle{next_tag}-live166167170-19-20261121-v1','cycle{next_tag}-live166167170-19-{next_day}-v1',2),
        ("for tag in ('165022',next_tag):",f"for tag,day in (('{tag}','{day}'),(next_tag,next_day)):",1),
        ('{tag}-live166167170-20261121-v1-status.service','{tag}-live166167170-{day}-v1-status.service',1),
        ('native_sample=checked(', "proposal['conditional_transition']=transfer\nnative_sample=checked(",1),
        ("ref,row=follow_event(n,oldref,tag,raw)", "ref,row=follow_event(n,done['receipts'][str(n)],tag,raw)",1),
    ]:
        apply = replace(apply,old,new,count)
    import inspect
    check_controller = inspect.getsource(active_controller)
    apply=replace(apply,"def window():",check_controller+"\ndef window():\n    assert active_controller()==(pkg,sha(seal))")
    apply=replace(apply,"window();remote=storage.put(n,tag,tar);tag,raw=storage.get(n)",
        """window();verify_live();remote=storage.put(n,tag,tar)
    durable(dest/'CONDITIONAL_RESPONSE.json',dict(intent=bound(ip),if_match=tag,returned_etag=remote))
    tag,raw=storage.get(n)""")
    apply=replace(apply,"   if not rp.exists():durable", """   response=dest/'CONDITIONAL_RESPONSE.json'
   if response.exists():
    observed=checked(bound(response))
    assert observed==dict(intent=bound(ip),if_match=i['before_etag'],returned_etag=tag)
   else:
    assert raw==tar and tag!=i['before_etag']
    durable(dest/'RECOVERED_READBACK.json',dict(intent=bound(ip),readback_etag=tag,readback_sha256=digest(raw)))
   if not rp.exists():durable""")
    apply=replace(apply,"  durable(q/'RESULT.json'", """  # Bind the whole post-write inventory and all 19 current authenticated bodies.
  final_statuses,final_ready,final_archives=storage.inventory()
  assert (final_statuses,final_ready,final_archives)==(statuses,ready,archives)
  readbacks={}
  for n in sorted(prior):
   tag,raw=storage.get(n)
   ref,row=follow_event(n,done['receipts'][str(n)],tag,raw)
   assert ref==(result[n]['receipt'] if n in result else basis[str(n)])
   assert row['after_etag']==tag and row['after_sha256']==digest(raw) and raw==body(row['after_status'])
   readbacks[n]=dict(receipt=ref,etag=tag,sha256=digest(raw))
  durable(q/'FINAL_READBACK.json',dict(statuses=readbacks,native_fleet=fref,ready_epochs=sorted(ready)))
  durable(q/'RESULT.json'""")
    apply=replace(apply,'conditional_statuses_verified=result)',"conditional_statuses_verified=result,full_readback=bound(q/'FINAL_READBACK.json'))")
    if terminal.exists() and not historical and not successor_ref:
        apply=replace(apply,'actual_145_start=sref,semantics_start_ms=repair_gate',
                      "actual_145_start=sref,projected_retry_start_ms=repair_gate,actual_145_failed=failure_ref")
    compile(plan,str(dest/'plan.py'),'exec')
    compile(apply,str(dest/'apply.py'),'exec')
    immutable(dest/'apply.py',apply.encode())
    syncdir(dest)
    return dest


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mode',choices=['current','next'])
    ap.add_argument('fleet',type=Path)
    ap.add_argument('paid',type=Path)
    ap.add_argument('--fit',type=Path)
    ap.add_argument('--fit-sha256')
    args = ap.parse_args()
    assert bool(args.fit)==bool(args.fit_sha256)
    directory=prepare(args.mode,args.fleet,args.paid,args.fit,args.fit_sha256)
    from evidence import bound,checked,sealed
    ref=bound(args.fleet)
    fleet=checked(ref)
    due=(sealed(fleet['sole_next_observer'])['not_before_utc'] if args.mode=='next' else
         checked(fleet['observer'])['cadence']['configured_not_before_utc'])
    print(json.dumps(dict(previous=ref, due=due, plan=bound(directory/'plan.py'), apply=bound(directory/'apply.py'))))
