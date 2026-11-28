"""Run ordinary publication of the closed 265 source from the drained 266 allocation."""
from functools import partial
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0,'/var/lib/jetstreamer/horizon249-delivery-v214-tools')
from ordinary249 import delivery248 as shared, delivery249, status248, terminal

D, V, CG = shared.D, shared.V, shared.CG
ref, bound = shared.ref, shared.bound
EPOCH, CPU = 265, 10
ORIGIN_IID = '182de64d33674f95b7758d410eb1812b'
LENGTH = 189538254413
SHA = '4fa8bae107eca8d6405774afa81976b4443a72e2d318aa12d17c54d3cfe9ef62'
ROOT = D/'horizon-upload-265-ordinary-v215'
UNIT = ROOT.name+'.service'
BOOK = V/'horizon266-closed-residual-delivery265-v215/assignment.json'
CLAIM = ROOT/'pipeline-claim.json'
PRIVATE = Path('/home/ubuntu/.jetstreamer-private/current-reader-delivery-265-v215')
DEPLOY = D/'horizon265-delivery-consumers-v215-a1/deployment.json'
KEY = 'epoch-265.epoch-status.json'
owner = sys.modules[__name__]
process = partial(shared.process,owner=owner)
registered = partial(shared.registered,owner=owner)
live_binding = partial(shared.live_binding,owner=owner)
prefix = partial(shared.prefix,owner=owner)
select_schedule = partial(shared.select_schedule,owner=owner)
census = partial(shared.census,owner=owner)


def finite_owner():
    if not BOOK.exists():
        assert not CLAIM.exists() and not (CG/UNIT).exists()
        return {}
    _, claim, book, launch = registered()
    assert book['donor']['sha256']=='c2112c2cf4d97797dbf9d1d2c347c2e00c954c14eedba5572b621aa22e7588af'
    if not (CG/UNIT).exists():
        m=shared.props(UNIT,['MainPID','ActiveState','Job'])
        assert m['MainPID']=='0' and m['ActiveState'] in ('inactive','failed') and not m['Job']
        return {}
    live_binding()
    return {UNIT:(claim['invocation_id'],int(launch['unit']['MainPID']),shared.LIMIT,{CPU,CPU+1})}


def issue(check_only):
    import retry_fit
    with shared.partition.take():
        shared.unfunded(owner)
        preflight=shared.pin(D/'horizon265-ordinary-delivery-preflight-v215-a1/assessment.json',
                             '220fd7b1558a35788bed285f6480fd1ffaa762d5d2bf65535e6c5e04d93bd44e')
        p=bound(preflight)
        deployment=shared.pin(DEPLOY,'192b1e52cc9a516177ac8dfffbdc16b67cb76054c66814b96453a6cb733dc402')
        a=bound(deployment)
        # Reader and uploader have their own compiled scope. The new observer also
        # contains the exact command and plan binding for this fourth publication lane.
        _, previous, _, _, _, _=delivery249.inputs()
        branch,paths,fixture,archive=shared.qualify(owner,previous,a,p['plan'],p['handoff'],p['drain'])
        assert fixture==p['qualified_pair'] and a['source'].startswith('448e9f0b')
        for path in ('lane265.py','register.py'):
            impl=Path(__file__).with_name(path)
            assert impl.read_text().strip()==shared.git('show',branch+':scripts/horizon266_bounded_retirement_20261123/delivery265/'+path)
        remote=prefix()
        assert set(remote)=={KEY}
        q=retry_fit.price(0,0,0,assessment_only=True)
        closed=bound(p['release'])
        assert q['closed266']==closed['terminal'] and q['issued']==closed['original']
        assert q['extent']['identity']==closed['current']['identity'] and Path('/sys/block/loop18/ro').read_text().strip()=='1'
        assert q['extent']['first']['blocks']==q['extent']['second']['blocks']==closed['retained_backing_bytes']
        assert 'closed265_delivery' in q and q['closed265_delivery'] is None
        assert set(r['epoch'] for r in bound(q['fleet'])['active'])=={247,248,249}
        donor=bound(q['issued'])
        assert donor['producer']==192000000000 and donor['cpu']==list(range(8))
        # CPU 10/11 are on the original drained 265 mask. The 266 allocation supplies RAM and disk.
        origin=bound(p['drain'])
        assert origin['producer_cgroup_drained'] and not (CG/origin['producer']['unit']['Id']).exists()
        assert shared.props(origin['producer']['unit']['Id'],['AllowedCPUs'])['AllowedCPUs']=='0-15'
        assert all({CPU,CPU+1}.isdisjoint(os.sched_getaffinity(int(shared.props(u,['MainPID'])['MainPID']))) for u in q['before'] if (CG/u).exists())
        floor=q['protected_floor']-q['extent']['remaining']+closed['qa_bytes']
        disk=q['extent']['free']-floor-shared.DISK
        ram=q['growth_margin']+donor['producer']-shared.GROSS
        assert ram>=0 and disk>=0 and floor>=bound(p['plan'])['minimum_free_bytes']
        model=dict(donor=p['release'],fit=q,hard=q['total_hard'],reserve_before=donor['producer'],
            reserve_after=donor['producer']-shared.GROSS,protected_floor=floor,
            disk_margin=disk,growth_margin=ram,cpu_donor=p['drain'],committed_disk=shared.DISK,
            additional_assignments={},replay_admitted=False)
        if check_only:
            return {'memory_margin':ram,'disk_margin':disk,'plan':p['plan'],'observer':deployment}
        old=delivery249.registered()[2]
        argv=[str(shared.IMAGE),'sync',str(archive.parent),'--epochs','265-265','--receipt-directory',str(PRIVATE/'receipts'),
            '--current-reader-plan',p['plan']['path'],'--current-reader-plan-sha256',p['plan']['sha256'],'--concurrency','2']
        props=[s.replace(str(delivery249.PRIVATE),str(PRIVATE)).replace(str(delivery249.ROOT),str(ROOT))
                .replace('AllowedCPUs=18 19','AllowedCPUs=10 11').replace('CPUAffinity=18 19','CPUAffinity=10 11') for s in old['properties']]
        assert 'AllowedCPUs=10 11' in props and 'CPUAffinity=10 11' in props and 'ProtectHome=read-only' in props and 'ProtectSystem=strict' in props
        assert 'ReadWritePaths='+' '.join(str(v) for v in [PRIVATE/'playback',PRIVATE/'receipts',PRIVATE/'tmp',shared.REPO/'.git']) in props
        assert 'StandardOutput=append:'+str(ROOT/'operation.log') in props and (PRIVATE/'tmp').is_dir()
        subprocess.run(['sudo','-n','--preserve-env=SSH_AUTH_SOCK','-u','ubuntu','ssh-add','-l'],stdout=subprocess.DEVNULL,check=True)
        ROOT.mkdir(mode=0o700);BOOK.parent.mkdir(mode=0o700)
        booking=shared.funds.put(BOOK,dict(model,service=UNIT,controller=os.environ['CODEX_THREAD_ID'],preflight=preflight,
            issue_time=time.time(),fixture=fixture,observer=deployment,plan=p['plan'],handoff=p['handoff'],drain=p['drain'],
            gross=shared.GROSS,disk=shared.DISK,automatic_release=False,prefix=remote,argv=argv,properties=props,
            source=branch,ordinary_reader_paths=paths))
        environment=['--setenv='+k for k in ('HORIZON_S3_ENDPOINT','HORIZON_ACCESS_KEY_ID','HORIZON_SECRET_ACCESS_KEY','SSH_AUTH_SOCK')]
        subprocess.run(['systemd-run','--quiet','--unit='+UNIT,*['--property='+v for v in props],*environment,
            '--setenv=HOME=/home/ubuntu','--setenv=GIT_TERMINAL_PROMPT=0','--setenv=TMPDIR='+str(PRIVATE/'tmp'),*argv],check=True)
        m=process(bound(booking))
        launch=shared.funds.put(ROOT/'launch.json',dict(booking=booking,unit=m,time=time.time()))
        claim=shared.funds.put(CLAIM,dict(epoch=EPOCH,phase='upload-readback',unit=UNIT,invocation_id=m['InvocationID'],
            expected_exec_start=m['ExecStart'],evidence=[booking,launch]))
        assert live_binding()['claim_sha256']==claim['sha256']
        return claim


if __name__=='__main__':
    # Import by the same canonical name used by census and pricing.
    import lane265
    action,=sys.argv[1:]
    if action=='status': status248.start(lane265)
    elif action=='terminal': terminal.capture(lane265)
    else:
        assert action in ('issue','check')
        print(lane265.issue(action=='check'),flush=True)
