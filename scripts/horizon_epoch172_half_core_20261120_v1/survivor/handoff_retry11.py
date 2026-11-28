"""Hand the same 167/172 cadence service and existing observer timer to the admitted retry11."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import runpy
import sys

R=Path('/var/lib/jetstreamer/horizon_runtime_data')
ROOT=R/'survivor172-cadence-20261122-v1'
OLD=ROOT/'tools-cold167-v3/status_cycle.py'
TOOL=ROOT/'tools-cold166-retry11'
NEW=TOOL/'status_cycle.py'
PRIOR=ROOT/'COLD167_V3_STATUS_ACTIVE.json'
QUAL=ROOT/'COLD166_RETRY11_STATUS_QUALIFIED.json'
ACTIVE=ROOT/'COLD166_RETRY11_STATUS_ACTIVE.json'
GUARD=R/'epoch166-retry11-guard-20261122-v1/GUARD_QUALIFIED.json'
PREPARED=R/'epoch166-retry11-rebook-20261122-v1/PREPARED.json'
members=('status_cycle.py','cold167_status.py','cold166_status.py','qualify.py','qualify_cold167.py',
         'qualify_cold167_cadence.py','qualify_cold166.py')

def prepare(c,base,commit):
    need=base['require'];write=base['write_new'];output=base['output']
    need(re.fullmatch('[0-9a-f]{40}',commit),'full committed source required')
    def git(*args):
        return output('/usr/sbin/runuser','-u','sol','--','/usr/bin/git','-C',base['REPO'],*args)
    git('merge-base','--is-ancestor',commit,'origin/account-updates')
    stage=ROOT/'retry11-status-source';c['ensure_dir'](stage)
    for name in members:write(stage/name,git('show',f'{commit}:{base["SRC"]}/{name}'))
    prior_generation=OLD.with_name('generation.json')
    need(c['bound'](prior_generation)['sha256']=='2f5407483f1d384e5a46214c7cc539768fbb0db3aa19b03a7365a4b0893427cd',
         'incumbent 167 configuration changed')
    write(stage/'generation.json',prior_generation.read_bytes())
    binding=dict(prepared=c['bound'](PREPARED),guard_qualification=c['bound'](GUARD))
    need(binding['prepared']['sha256']=='ec59431a69b7e13fbb6cd8c14b3e49e915b9f9c003a1b5ba3d70375f42ecfe8c'
         and binding['guard_qualification']['sha256']=='d43d47340cc01d97cea8a37bdff9ac2d27762761c4cbb74f0d8740dda9e5ea22',
         'different retry11 enrollment')
    c['durable'](stage/'retry11-generation.json',binding)
    files=(*members,'generation.json','retry11-generation.json')
    need({f.name for f in stage.iterdir()}==set(files),'foreign package member')
    plan=ROOT/'retry11-status-seal-plan.json'
    c['durable'](plan,dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(TOOL),
        members=[dict(name=n,mode=0o444,source=str(stage/n),sha256=c['bound'](stage/n)['sha256']) for n in files]))
    if not TOOL.exists():output(base['SEALER'],plan,'--plan-sha256',c['bound'](plan)['sha256'],'--self-sha256','e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3')
    ref=c['bound'](TOOL/'deployment-seal-receipt.json');seal=c['checked'](ref)
    need(seal['plan_sha256']==c['bound'](plan)['sha256'] and all(c['bound'](TOOL/n)['sha256']==c['bound'](stage/n)['sha256'] for n in files),'unbound retry11 package')
    if QUAL.exists():
        q=c['read_ref'](QUAL);need(q['package']==ref and q['source_commit']==commit,'different retry11 qualification')
        return c['bound'](QUAL)
    qa=ROOT/'retry11-status-qa';c['ensure_dir'](qa)
    suites={n:json.loads(output('/usr/bin/python3','-IB',TOOL/n,qa)) for n in members if n.startswith('qualify')}
    need(suites['qualify_cold166.py']['counted_native_workers']==3 and suites['qualify_cold166.py']['wrong_166_worker_rejected']
         and suites['qualify_cold166.py']['conditional_writes']==2 and suites['qualify_cold167_cadence.py']['two_guarded_owners']
         and len(set(suites['qualify.py']['conditional_epochs']))==20,'incomplete three-lane qualification')
    c['durable'](QUAL,dict(package=ref,source_commit=commit,binding=binding,suites=suites))
    return c['bound'](QUAL)

def admitted(c):
    # Validate the new package using its own module directory; the original cadence context is separate.
    child=('/usr/bin/python3','-IB',str(Path(__file__).resolve()),'check-admitted')
    import subprocess
    return json.loads(subprocess.check_output(child,timeout=15))

def admission():
    c=runpy.run_path(str(NEW));m=c['cold166_status'];module=m.reader()
    ref=c['bound'](PREPARED.parent/'ACTUAL_ADMISSION_AND_PROTECTION.json');a=c['checked'](ref)
    for epoch,check in ((166,m.check_generation),(167,c['cold167_status'].check_generation)):
        state=module.native(epoch);c['need'](state,'missing native worker')
        check(a['fleet'],c['checked'](a['fleet']),state)
        route=R/module.ROUTES[epoch][1];ad=c['read_ref'](route/'ACTUAL_ADMISSION_AND_PROTECTION.json')
        first=c['read_ref'](route/'FIRST_PROTECTED_WORKER.json');_,sample=module.guard(epoch,ad,state[1])
        m.projection(module.observe_worker(epoch,state[1],first,sample))
    return ref

def main():
    ap=argparse.ArgumentParser();ap.add_argument('mode',choices=('prepare','observe','activate','check-admitted'))
    ap.add_argument('reference',nargs='?');args=ap.parse_args()
    assert os.geteuid()==0 and sys.flags.isolated and __debug__
    common=Path(__file__).resolve().with_name('handoff_cold167.py')
    assert hashlib.sha256(common.read_bytes()).hexdigest()=='7f189ae92d13bca515099267852c1551fa43f159387eee7af5ec48839933260d'
    assert hashlib.sha256(OLD.read_bytes()).hexdigest()=='1eb66200c76f8da4399ccffd3b00af1322436b7e14ee2c076b03fb9cdf4687c0'
    if args.mode=='check-admitted':return admission()
    c=runpy.run_path(str(OLD));b=runpy.run_path(str(common));need=b['require']
    if args.mode=='prepare':return prepare(c,b,args.reference)
    prior=c['checked'](dict(path=str(PRIOR),sha256='a0ab18c5bd28557884a837d0ad125f5535267c68eca73bd286682e9f43961a3f'))
    head=c['bound'](Path(args.reference))
    need(Path(head['path']).name=='ROOT_COMPLETE_OPERATIONAL_FLEET.json' and Path(head['path']).parent.parent==R,'unbound fleet')
    if args.mode=='observe':
        return dict(schedule=b['timer_evidence'](c,head),owner=b['publisher'](c,OLD,True))
    fd=c['lock'](ROOT/'cold167-status-handoff.lock')
    try:
        return b['switch'](c,head,target=TOOL,incumbent=OLD,incumbent_iid=prior['new']['invocation_id'],
                           tag='COLD166_RETRY11_STATUS_',drop=b['DROP'].with_name('zzzzzzzzzzzzzzz-retry11.conf'),
                           admission=admitted)
    finally:os.close(fd)

if __name__=='__main__':print(json.dumps(main()))
