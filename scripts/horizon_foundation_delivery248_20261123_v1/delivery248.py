"""Bind the ordinary sync to Foundation's closed 211 allocation and the shared fleet."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, '/run/horizon266-bounded-tools-v208')
from retry_fit import CG, D, V, bound, partition, props, ref
import funds

NAME = 'horizon-upload-248-ordinary-v213'
UNIT = NAME + '.service'
ROOT = D / NAME
BOOK = V / 'horizon211-residual-delivery248-v213' / 'assignment.json'
CLAIM = ROOT / 'pipeline-claim.json'
FIXTURE = D / 'horizon248-ordinary-fixture-v212-a4/completion.json'
PREFLIGHT = D / 'horizon248-ordinary-delivery-preflight-v212-a3/assessment.json'
DEPLOY = D / 'horizon248-delivery-consumers-v213-a1/deployment.json'
LIMIT = 10 << 30
GROSS = LIMIT + (512 << 20)
DISK = 1 << 30
IMAGE = V / 'horizon247-public-images-58709604-v1/jetstreamer-r2'
PRIVATE = Path('/home/ubuntu/.jetstreamer-private/current-reader-delivery-248-20261119-v2')
REPO = Path('/home/ubuntu/workspace/jetstreamer')
KEY = 'epoch-248.epoch-status.json'
SHA = 'baa3c46605d6bc2781ee37095735e953303fcfd234aa7bed79f47a8aa60f6962'
LENGTH = 186974189938
FIELDS = ['Id','LoadState','ActiveState','SubState','InvocationID','MainPID','MemoryMax','MemorySwapMax',
          'AllowedCPUs','ExecStart','NRestarts','Restart','ExecMainStartTimestampMonotonic','Job']

def pin(path, sha):
    binding = ref(path)
    assert binding['sha256'] == sha, path
    return binding

def git(*args):
    return subprocess.check_output(['sudo','-n','--preserve-env=SSH_AUTH_SOCK','-u','ubuntu','git','-C',REPO,*args], text=True).strip()

def aws(*args):
    url = urlsplit(os.environ['HORIZON_S3_ENDPOINT'])
    assert url.scheme == 'https' and url.hostname.endswith('.r2.cloudflarestorage.com')
    bucket = url.path.strip('/')
    assert bucket == 'solana-archive-with-accounts-data'
    env = dict(os.environ, AWS_ACCESS_KEY_ID=os.environ['HORIZON_ACCESS_KEY_ID'],
               AWS_SECRET_ACCESS_KEY=os.environ['HORIZON_SECRET_ACCESS_KEY'], AWS_DEFAULT_REGION='auto', AWS_EC2_METADATA_DISABLED='true')
    env.pop('AWS_SESSION_TOKEN', None)
    output = subprocess.check_output(['/home/linuxbrew/.linuxbrew/bin/aws','s3api',*args,'--bucket',bucket,
                                      '--endpoint-url','https://'+url.netloc,'--output','json','--no-cli-pager'], env=env)
    return json.loads(output) if output.strip() else {}

def prefix():
    listing = aws('list-objects-v2','--prefix','epoch-248.')
    assert not listing.get('IsTruncated')
    return {item['Key']:item for item in listing.get('Contents',[])}

def process(book):
    state = props(UNIT,FIELDS)
    assert state['Id'] == UNIT and state['LoadState'] == 'loaded' and state['ActiveState'] == 'active'
    assert state['SubState'] == 'running' and state['NRestarts'] == '0' and state['Restart'] == 'no' and not state['Job']
    assert state['MemoryMax'] == str(LIMIT) and state['MemorySwapMax'] == '0' and state['AllowedCPUs'] == '16-17'
    pid = int(state['MainPID'])
    assert pid > 1 and len(state['InvocationID']) == 32 and os.sched_getaffinity(pid) == {16,17}
    assert os.path.samefile(f'/proc/{pid}/exe',IMAGE)
    assert Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0') == [*[os.fsencode(a) for a in book['argv']],b'']
    group = CG / UNIT
    assert int((group/'memory.max').read_text()) == LIMIT and int((group/'memory.swap.max').read_text()) == 0
    assert str(pid) in (group/'cgroup.procs').read_text().split()
    return state

def registered():
    claim_ref = ref(CLAIM)
    claim = bound(claim_ref)
    book_ref = ref(BOOK)
    launch_ref = ref(ROOT/'launch.json')
    assert claim['evidence'] == [book_ref, launch_ref]
    book = bound(book_ref)
    launch = bound(launch_ref)
    assert launch['booking'] == book_ref and book['service'] == UNIT
    assert book['gross'] == GROSS and book['disk'] == DISK and not book['automatic_release']
    assert claim['epoch'] == 248 and claim['unit'] == UNIT and claim['phase'] == 'upload-readback'
    assert claim['invocation_id'] == launch['unit']['InvocationID'] and claim['expected_exec_start'] == launch['unit']['ExecStart']
    return claim_ref,claim,book,launch

def live_binding():
    claim_ref,claim,book,launch = registered()
    state = process(book)
    assert all(state[k] == launch['unit'][k] for k in ('InvocationID','MainPID','ExecMainStartTimestampMonotonic'))
    return dict(invocation_id=claim['invocation_id'],pid=int(state['MainPID']),claim_sha256=claim_ref['sha256'])

def unfunded():
    assert not BOOK.exists() and not CLAIM.exists() and not (CG/UNIT).exists()
    state = props(UNIT,['LoadState','ActiveState','MainPID','Job'])
    assert state == dict(LoadState='not-found',ActiveState='inactive',MainPID='0',Job='')
    jobs = subprocess.check_output(['systemctl','list-jobs','--no-legend','--no-pager'],text=True)
    assert not any('248' in line and ('upload' in line or 'delivery' in line) for line in jobs.splitlines())
    assert not list((PRIVATE/'receipts').glob('epoch-248*')) and not list((PRIVATE/'playback').glob('epoch-248-*'))

def issue():
    import retry_fit
    with partition.take():
        unfunded()
        base = pin(PREFLIGHT,'f7d06670e9768618b6b9241c8d0cde56cc460590204c829dca612d430aca13cb')
        pre = bound(base)
        reader_build = pin(DEPLOY,'53ee58eca48b7c3cdb987c05a917fdc375f1a2f120590871b3f618719de9331e')
        deployment = bound(reader_build)
        git('fetch','origin','refs/heads/account-updates:refs/remotes/origin/account-updates')
        head = git('rev-parse','origin/account-updates')
        git('merge-base','--is-ancestor',deployment['source'],head)
        assert not git('diff','--name-only',deployment['source'],head,'--',*deployment['branch_scope']['compiled_inputs'])
        for role,scope in pre['proofs'].items():
            changes = git('diff','--name-only','--no-renames',scope['base'],head,'--',*scope['paths']).splitlines()
            assert changes == scope['changed'] and not git('diff','--name-only',pre['branch'],head,'--',*scope['paths']),role
        src = git('show','c62bd755:jetstreamer-r2/src/current_reader.rs')
        import re
        ordinary = re.findall(r'"([^"]+)"',src.split('const READER_PATHS: &[&str] = &[')[1].split('];')[0])
        plan = bound(pre['qualified_plan'])
        assert len(ordinary) == 12 and not git('diff','--name-only',plan['reader_commit'],head,'--',*ordinary)
        fixture_ref = ref(FIXTURE)
        fixture = bound(fixture_ref)
        assert fixture['real_archives_published'] == 0 and fixture['had_single_uploaded_part'] and bound(fixture['process'])['exit'] == 0
        assert fixture['uploader_sha256'] == 'c1e99ad4b2e7f3fe56235f42a722bbe93e3f13af2003d0eb5a150553ae0a660e'
        for report in fixture['accepted_fixture_reports'].values():
            receipt = bound(report['receipt'])
            assert receipt['epoch'] == 251 and receipt['archive_length'] == 772931 and receipt['remote_sha256_readback']
            bound(report['acceptance'])
        for binding in [dict(path=str(IMAGE),sha256=fixture['uploader_sha256']),plan['pipeline'],plan['full_verifier']]:
            p = Path(binding['path'])
            assert p.resolve() == p and p.stat().st_uid == 0 and not p.stat().st_mode & 0o222
            with p.open('rb') as file:
                assert hashlib.file_digest(file,'sha256').hexdigest() == binding['sha256']
        assert plan['threads'] == 2 and plan['pipeline']['sha256'] == fixture['pipeline_sha256']
        expectation = bound(plan['epoch_expectations']['248'])
        assert expectation['epoch'] == 248
        for item in expectation['independent_evidence']:
            bound(item)
        hand = bound(pre['archive'])
        assert hand['epoch'] == 248 and bound(pre['drain'])['producer_cgroup_drained']
        source = hand['source']
        for role in ('archive','sidecar'):
            path = Path(source[role]['path'])
            st = path.lstat()
            ident = source[role]['identity']
            assert path.resolve() == path and (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns) == (
                ident['device'],ident['inode'],ident['length'],ident['modified_seconds']*10**9+ident['modified_nanoseconds'],
                ident['changed_seconds']*10**9+ident['changed_nanoseconds'])
        archive = Path(source['archive']['path'])
        assert archive.stat().st_size == LENGTH and source['archive']['sha256'] == SHA
        assert Path(source['sidecar']['path']).read_text() == SHA+'  epoch-248.jet\n'
        assert ref(Path(source['publication_receipt']['path'])) == source['publication_receipt']
        remote = prefix()
        assert set(remote) == {KEY}
        donor = pre['donor']
        manager = props(donor['unit'],list(pre['donor_manager']))
        assert manager == pre['donor_manager'] and not (CG/donor['unit']).exists()
        assert bound(pre['donor_proof'])['producer_cgroup_drained'] and donor in bound(pre['ledger'])['reservations']
        winner = bound(pre['original_held'])['winner']
        assert winner['assigned_211'] + winner['retained_211'] == donor['maximum_memory_bytes'] == 225000000000
        assert winner['retained_211'] == pre['paid_residual'] == 47657822720
        fit = retry_fit.price(0,0,0)
        fled = bound(fit['fleet'])
        assert {a['epoch'] for a in fled['active']} == {247,266}
        assert all(set((16,17)).isdisjoint(os.sched_getaffinity(int(props(u,['MainPID'])['MainPID']))) for u in fit['before'])
        assert fit['growth_margin'] >= GROSS and fit['disk_margin'] >= DISK and fit['protected_floor'] >= plan['minimum_free_bytes']
        assert pre['candidate_envelope'] == GROSS and pre['candidate_memory_limit'] == LIMIT and pre['disk'] == DISK
        git('merge-base','--is-ancestor',git('rev-parse','HEAD'),head)
        script = Path(__file__).name
        script_source = 'scripts/horizon_foundation_delivery248_20261123_v1/'+script
        assert Path(__file__).read_text().strip() == git('show',head+':'+script_source)
        unfunded()
        ROOT.mkdir(mode=0o700,exist_ok=True)
        (PRIVATE/'tmp').mkdir(mode=0o700,exist_ok=True)
        writable = [PRIVATE/n for n in ('playback','receipts','tmp')] + [REPO/'.git']
        assert all(p.resolve() == p and p.is_dir() for p in writable)
        argv = [str(IMAGE),'sync',str(archive.parent),'--epochs','248-248','--receipt-directory',str(PRIVATE/'receipts'),
                '--current-reader-plan',pre['qualified_plan']['path'],'--current-reader-plan-sha256',pre['qualified_plan']['sha256'],'--concurrency','2']
        capabilities = 'CAP_DAC_OVERRIDE CAP_SETGID CAP_SETUID'
        properties = ['Type=exec','Restart=no','KillMode=control-group',f'MemoryMax={LIMIT}','MemorySwapMax=0','AllowedCPUs=16 17',
                      'CPUAffinity=16 17','CPUQuota=200%','TasksMax=512','RuntimeMaxSec=345600','UMask=0077','ProtectSystem=strict',
                      'ProtectHome=read-only','NoNewPrivileges=yes','ReadWritePaths='+' '.join(map(str,writable)),
                      'CapabilityBoundingSet='+capabilities,'AmbientCapabilities='+capabilities,'StandardOutput=append:'+str(ROOT/'operation.log'),'StandardError=inherit']
        assert os.path.exists(os.environ['SSH_AUTH_SOCK'])
        subprocess.run(['sudo','-n','--preserve-env=SSH_AUTH_SOCK','-u','ubuntu','ssh-add','-l'],stdout=subprocess.DEVNULL,check=True)
        BOOK.parent.mkdir(mode=0o700,exist_ok=True)
        booking = funds.put(BOOK,dict(service=UNIT,controller=os.environ['CODEX_THREAD_ID'],preflight=base,fit=fit,
            issue_time=time.time(),fixture=fixture_ref,observer=reader_build,plan=pre['qualified_plan'],handoff=pre['archive'],drain=pre['drain'],
            donor=donor,donor_manager=manager,donor_terminal=pre['donor_proof'],original=pre['original_held'],
            reserve_before=winner['retained_211'],gross=GROSS,reserve_after=winner['retained_211']-GROSS,disk=DISK,
            hard=fit['total_hard'],growth_after=fit['growth']+GROSS,growth_margin=fit['growth_margin']-GROSS,
            disk_floor=fit['protected_floor']+DISK,disk_margin=fit['disk_margin']-DISK,automatic_release=False,
            prefix=remote,argv=argv,properties=properties,source=head,ordinary_reader_paths=ordinary))
        environment = ['--setenv='+k for k in ('HORIZON_S3_ENDPOINT','HORIZON_ACCESS_KEY_ID','HORIZON_SECRET_ACCESS_KEY','SSH_AUTH_SOCK')]
        subprocess.run(['systemd-run','--quiet','--unit='+UNIT,*['--property='+p for p in properties],*environment,
                        '--setenv=HOME=/home/ubuntu','--setenv=GIT_TERMINAL_PROMPT=0','--setenv=TMPDIR='+str(PRIVATE/'tmp'),*argv],check=True)
        m = process(bound(booking))
        launch = funds.put(ROOT/'launch.json',dict(booking=booking,unit=m,time=time.time()))
        claim = funds.put(CLAIM,dict(epoch=248,phase='upload-readback',unit=UNIT,invocation_id=m['InvocationID'],expected_exec_start=m['ExecStart'],evidence=[booking,launch]))
        assert live_binding()['claim_sha256'] == claim['sha256']
        print(claim,flush=True)

if __name__ == '__main__':
    issue()

def finite_owner():
    """The original hard total already contains the donor. Charge its newly assigned growth."""
    if not BOOK.exists():
        assert not CLAIM.exists() and not (CG/UNIT).exists()
        return {}
    claim_ref, claim, book, launch = registered()
    assert book['reserve_before'] == 47657822720 and book['reserve_after'] == 47657822720-GROSS
    if not (CG/UNIT).exists():
        state = props(UNIT,['MainPID','ActiveState','Job'])
        assert state['MainPID'] == '0' and state['ActiveState'] in ('inactive','failed') and not state['Job']
        return {}
    live_binding()
    return {UNIT:(claim['invocation_id'],int(launch['unit']['MainPID']),LIMIT,{16,17})}

def select_schedule(cad, version, state, replacing):
    """Keep the already-running receipt consumer and its original completion path."""
    binding = live_binding()
    old_names = cad.names
    normal = f'v{version}-bounded-retry266-{state}-v1'
    tagged = normal+'-with248'
    if replacing:
        cad.new = lambda v: tagged
    def names(tag):
        ds, directory, diag, unit = old_names(tag)
        if tag.endswith('-with248'):
            directory = old_names(tag.removesuffix('-with248'))[1]
        return ds,directory,diag,unit
    cad.names = names
    original = cad.prior_schedule
    def prior(v,completed):
        if completed:
            for timer in D.glob(f'horizon-schedule-v{v}-*-with248/timer.json'):
                tag = timer.parent.name.removeprefix('horizon-schedule-')
                ds,directory,_,_ = names(tag)
                marker = directory/'completion.json'
                if marker.is_file():
                    t = bound(ref(timer))
                    assert t['plan'] == ref(ds/'wrapper-plan.json') and t['build'] == ref(DEPLOY)
                    selected = bound(bound(t['plan'])['config'])
                    done = bound(ref(marker))
                    effective = bound(done['effective_config'])
                    assert selected['delivery248_claim'] == effective['delivery248_claim'] == binding
                    assert done['observer_exit_code'] == 0 and done['observer_output'] == selected['output'] == str(cad.sample(v))
                    return tag
        return original(v,completed)
    cad.prior_schedule = prior
    return binding

def census(plan, observation, completed):
    claim_ref,claim,book,launch = registered()
    selected = bound(completed['effective_config']).get('delivery248_claim')
    if not selected:
        return False
    assert selected['claim_sha256'] == claim_ref['sha256'] and selected['invocation_id'] == claim['invocation_id']
    matches = [r for r in observation['delivery_resources'] if r['producer_unit'] == UNIT]
    row, = matches
    assert row['status'] == 'observed' and row['delivery_resource_only'] and row['expected_producer_invocation_id'] == claim['invocation_id']
    telemetry = row['observation']
    assert telemetry['delivery_claim'] == claim_ref and telemetry['invocation_binding_stable'] and not telemetry['ordinary_replay_claim']
    assert telemetry['producer_after']['main_pid'] == int(launch['unit']['MainPID'])
    assert telemetry['mapped_image_after']['sha256'] == bound(book['fixture'])['uploader_sha256']
    existing = [q for q in plan['pipeline_claims'] if q['unit'] == UNIT]
    assert existing in ([],[claim])
    if not existing:
        plan['pipeline_claims'].append(claim)
    if UNIT not in plan['tracked_units']:
        plan['tracked_units'].append(UNIT)
    g = plan['gates']['248']
    for r in [claim_ref,*claim['evidence'],book['fixture'],book['observer']]:
        if r not in g['evidence']:
            g['evidence'].append(r)
    g['next_action'] = 'Complete local verification, multipart upload, authenticated SHA-256 and pinned public playback; confirm the native receipt and readiness sidecar.'
    return True
