"""Keep one cadence writer when 170 joins before or after the independent 166 retry."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys

BASE = Path('/var/lib/jetstreamer/horizon_runtime_data')
ROOT = BASE/'survivor172-cadence-20261122-v1'
DUAL = ROOT/'tools-cold167-v3'
TRIPLE = ROOT/'tools-cold166-retry11'
# The sealer installs the same entry point in a distinct read-only directory for each attempt.
ATTEMPT = Path(__file__).resolve().parent.name.split('-',1)[0]
assert ATTEMPT in ('retry11','retry12','retry13')
TARGET = ROOT/f'tools-cold170-{ATTEMPT}-v2'
TAG = f'COLD170_{ATTEMPT.upper()}_V2_STATUS_'
QUAL = ROOT/(TAG+'QUALIFIED.json')
REFERENCES = {
    'retry11': ('8420a1b00afa2d643a24e36c5b12c82fdd0b43d5238c9045c0c0c53097021728',
                '36d057cd24d412190ca41f2d910969a1b37fd175cab51ab8c00bd61f6826416d'),
    'retry12': ('466f48f20716b258189e242eef4d4e2e54fbf6202e6ecd4ff008eb3dd0d10b19',
                '7ed9e4bffff3cdaad1bd8d0eda700c3b107e85a4b585bb067e4eca50bbab123c'),
    'retry13': ('654e6612f8ce9ee2f9f5c9f172f79f9ce5da4b0f6f02443c856f3a5228a5ca69','34ee106fc4dd290e8ad447f1ff5ab15cfe538b7ca522785a87df106566e0645c'),
}
anchor_sha,guard_sha = REFERENCES[ATTEMPT]
ANCHOR = dict(path=str(BASE/f'epoch170-{ATTEMPT}-rebook-20261122-v1/SUCCESSOR_ROOT.json'),sha256=anchor_sha)
GUARD = dict(path=str(BASE/f'epoch170-{ATTEMPT}-guard-20261122-v1/GUARD_QUALIFIED.json'),sha256=guard_sha)
PRIOR = ROOT/'COLD167_V3_STATUS_ACTIVE.json'
PRIOR_SHA = 'a0ab18c5bd28557884a837d0ad125f5535267c68eca73bd286682e9f43961a3f'
TRIPLE_QUAL = dict(path=str(ROOT/'COLD166_RETRY11_STATUS_QUALIFIED.json'),
                   sha256='5ecd660bf949538b23838b68a90798843b586d61671c983528e148ea2344c017')
MEMBERS = ('status_cycle.py','cold167_status.py','cold166_status.py','cold170_status.py','qualify.py',
           'qualify_cold167.py','qualify_cold167_cadence.py','qualify_cold166.py','qualify_cold170.py')


def prepare(c, shared, commit):
    need = c['need']
    need(re.fullmatch(r'[0-9a-f]{40}',commit), 'invalid source commit')
    def git(*args):
        return shared['output']('/usr/sbin/runuser','-u','sol','--','/usr/bin/git','-C',shared['REPO'],*args)
    git('merge-base','--is-ancestor',commit,'origin/account-updates')
    c['checked'](ANCHOR)
    c['checked'](GUARD)
    enrollment = c['checked'](TRIPLE_QUAL)
    need(enrollment['package']==c['bound'](TRIPLE/'deployment-seal-receipt.json'), 'different 166 registration')
    stage = ROOT/f'{ATTEMPT}-170-status-source-v2'
    c['ensure_dir'](stage)
    for name in MEMBERS:
        shared['write_new'](stage/name,git('show',f"{commit}:{shared['SRC']}/{name}"))
    for name in ('generation.json','retry11-generation.json'):
        shared['write_new'](stage/name,(TRIPLE/name).read_bytes())
    c['durable'](stage/f'{ATTEMPT}-170-generation.json', dict(successor_root=ANCHOR,guard_qualification=GUARD))
    names=(*MEMBERS,'generation.json','retry11-generation.json',f'{ATTEMPT}-170-generation.json')
    need({p.name for p in stage.iterdir()}==set(names),'unexpected package member')
    plan=ROOT/f'{ATTEMPT}-170-status-seal-plan-v2.json'
    c['durable'](plan,dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(TARGET),
         members=[dict(name=n,mode=0o444,source=str(stage/n),sha256=c['bound'](stage/n)['sha256']) for n in names]))
    if not TARGET.exists():
        shared['output'](shared['SEALER'],plan,'--plan-sha256',c['bound'](plan)['sha256'],'--self-sha256',
                         'e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3')
    seal=c['bound'](TARGET/'deployment-seal-receipt.json')
    need(c['checked'](seal)['plan_sha256']==c['bound'](plan)['sha256'] and all(
        c['bound'](TARGET/n)['sha256']==c['bound'](stage/n)['sha256'] for n in names),'changed 170 package')
    if not QUAL.exists():
        qa=ROOT/f'{ATTEMPT}-170-status-qa-v2';c['ensure_dir'](qa)
        suites={n:json.loads(shared['output']('/usr/bin/python3','-IB',TARGET/n,qa)) for n in MEMBERS if n.startswith('qualify')}
        population=suites['qualify_cold170.py']
        writes=(population['authenticated_fixture_writes'],population.get('carried_authenticated_replay_writes',0))
        need(population['measured_lanes']==4 and writes in ((2,0),(3,1))
             and suites['qualify_cold166.py']['counted_native_workers']==3
             and len(set(suites['qualify.py']['conditional_epochs']))==20,'incomplete 170 qualification')
        entry=json.loads(shared['output']('/usr/bin/python3','-IB',TARGET/'status_cycle.py','--check-entry'))
        need(entry==seal,'sealed deployment cannot enter production main')
        c['durable'](QUAL,dict(package=seal,entry=entry,source_commit=commit,successor_root=ANCHOR,guard=GUARD,suites=suites))
    signed=c['bound'](QUAL)
    need(c['checked'](signed)['package']==seal and c['checked'](signed)['source_commit']==commit,'foreign 170 qualifier')
    return signed


def incumbent(c):
    original=c['checked'](dict(path=str(PRIOR),sha256=PRIOR_SHA))
    third=ROOT/'COLD166_RETRY11_STATUS_ACTIVE.json'
    if not third.exists():
        return DUAL, original['new']['invocation_id']
    record=c['read_ref'](third)
    need=c['need']
    need(record['qualified']==TRIPLE_QUAL and record['old']==original['new'] and
         record['new']['program']==str(TRIPLE/'status_cycle.py') and
         record['new']['lock']==record['old']['lock'], 'unrecognized previous third-lane writer')
    return TRIPLE, record['new']['invocation_id']


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('mode',choices=('prepare','observe','activate','check-admitted'))
    ap.add_argument('reference')
    args=ap.parse_args()
    helper=Path(__file__).resolve().with_name('handoff_cold167.py')
    assert __debug__ and os.geteuid()==0 and sys.flags.isolated
    assert hashlib.sha256(helper.read_bytes()).hexdigest()=='7f189ae92d13bca515099267852c1551fa43f159387eee7af5ec48839933260d'
    assert hashlib.sha256((DUAL/'status_cycle.py').read_bytes()).hexdigest()=='1eb66200c76f8da4399ccffd3b00af1322436b7e14ee2c076b03fb9cdf4687c0'
    if args.mode=='check-admitted':
        # Load the successor by itself so its independently qualified modules take precedence.
        c=runpy.run_path(str(TARGET/'status_cycle.py'));m=c['cold_workers'];route=m.reader()
        head=c['bound'](Path(args.reference));fleet=c['checked'](head)
        enrolled=m.roster(route,head,fleet)
        for epoch in sorted(enrolled):
            _,actor=route.native(epoch)
            root=BASE/route.ROUTES[epoch][1]
            ad=c['read_ref'](root/'ACTUAL_ADMISSION_AND_PROTECTION.json')
            first=c['read_ref'](root/'FIRST_PROTECTED_WORKER.json')
            _,sample=route.guard(epoch,ad,actor)
            m.projection(route.observe_worker(epoch,actor,first,sample))
        return c['bound'](m.ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json')
    c=runpy.run_path(str(DUAL/'status_cycle.py'));shared=runpy.run_path(str(helper))
    if args.mode=='prepare':
        return prepare(c,shared,args.reference)
    head=c['bound'](Path(args.reference))
    c['need'](Path(head['path']).name=='ROOT_COMPLETE_OPERATIONAL_FLEET.json' and Path(head['path']).parent.parent==BASE,
              'incorrect fleet path')
    old,iid=incumbent(c)
    if args.mode=='observe':
        return dict(schedule=shared['timer_evidence'](c,head),owner=shared['publisher'](c,old/'status_cycle.py',True))
    def admitted(_context):
        return json.loads(subprocess.check_output(['/usr/bin/python3','-IB',str(Path(__file__).resolve()),'check-admitted',args.reference],
                                                  timeout=45))
    fd=c['lock'](ROOT/'cold167-status-handoff.lock')
    try:
        return shared['switch'](c,head,target=TARGET,incumbent=old/'status_cycle.py',incumbent_iid=iid,
                                tag=TAG,drop=shared['DROP'].with_name(f'zzzzzzzzzzzzzzzz-{ATTEMPT}-170.conf'),admission=admitted)
    finally:
        os.close(fd)


if __name__=='__main__':
    print(json.dumps(main()))
