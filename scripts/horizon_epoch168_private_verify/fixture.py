"""Construct the small V4 fixture and the production scope from sealed native inputs."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys,time
ROOT=Path('/home/sol/.jetstreamer-private/epoch168-private-archive-verify-20261127.0VHYTNgF'); RT=Path('/var/lib/jetstreamer/horizon_runtime_data')
PKG=RT/'epoch168-current-anza-reader-20261127-v1'
READER=RT/'epoch168-current-anza-read-only-20261127-v1/compiled-input-equivalence.json'
SRC=RT/'epoch168-joint-checkpoint-reduced-run-20261126-v1'
ACTOR=Path('/home/sol/.jetstreamer-private/epoch168-assembly-operator-20261127-v1/launch-acmxqat0')
QUAL=SRC/'assembly-source-native-qualification-20261127-v1'
EXP=SRC/'independent-v4-verification-expectation-v1'
INPUT=Path('/home/sol/.jetstreamer-private/epoch168-v4-reader-fixture-20261127.xsO0LNHm/build/fixture/fixture.json')
PASS=Path('/home/sol/.jetstreamer-private/epoch168-anza-reader-build-20261127.jMydZnTw/native-qualification-v2/v4/LOCAL_V4_ACCEPTANCE.json')
PROD=RT/'epoch168-exact-private-verification-20261127-v1'
def read(path):return json.loads(path.read_bytes())
def ref(path):
    with path.open('rb') as f: h=hashlib.file_digest(f,'sha256').hexdigest()
    return dict(path=str(path),sha256=h)
def json_save(path,data):
    with path.open('x') as f:
        os.fchmod(f.fileno(),0o400);json.dump(data,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    d=os.open(path.parent,os.O_DIRECTORY);os.fsync(d);os.close(d)
    return ref(path)
def require(ok,why):
    if not ok:raise ValueError(why)
def base(epoch,dir_,launch):
    return dict(schema='horizon-private-assembly-verification-scope-v1',fixture=epoch==251,epoch=epoch,threads=2,
                assembly_dir=str(dir_),unit=launch['Id'],invocation=launch['InvocationID'],package=ref(PKG/'PACKAGE.json'),reader_equivalence=ref(READER))
def production():
    assert PROD.parent.stat().st_dev==Path('/home/sol').stat().st_dev
    PROD.mkdir(mode=0o700,exist_ok=True)
    plan=read(ACTOR/'PLAN.json');prep=read(EXP/'VERIFY_168_PREPARATION.json')
    scope=base(168,Path(plan['output_directory']),read(ACTOR/'LAUNCH_NATIVE.json'))
    scope.update(plan=ref(ACTOR/'PLAN.json'),native_launch=ref(ACTOR/'LAUNCH_NATIVE.json'),expectation=ref(EXP/'VERIFY_168_EXPECTATION.json'),
                 preparation=ref(EXP/'VERIFY_168_PREPARATION.json'),selected=plan['qualification'],selected_native=plan['qualification_native'],
                 lineage=plan['lineage'],terminal_edge=prep['terminal_finalized_crosscheck'])
    output=PROD/'scope.json'
    if output.exists():require(read(output)==scope,'existing scope differs');return ref(output)
    return json_save(output,scope)
def populate(root):
    if os.getuid()!=0 or not __debug__:raise ValueError('privileged fixture only')
    scope_unit=root.name+'.service';iid=os.environ['INVOCATION_ID']
    group=Path('/sys/fs/cgroup'+Path('/proc/self/cgroup').read_text().strip().removeprefix('0::'))
    require(root.parent==ROOT/'qualification' and group.name==scope_unit and (group/'memory.max').read_text().strip()==str(128<<20)
          and os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'fixture unit mismatch')
    doc=read(INPUT); result=read(PASS); root_inputs=root/'inputs';root_inputs.mkdir(mode=0o700)
    assert result['fixture']['sha256']==ref(INPUT)['sha256']=='da0a04cca2922cf720c3778eb2a0b6111a223c6f97acf95b587576a79ad94609'
    assert ref(PASS)['sha256']=='6da2aa13c737a919b90a2e8740103727bd5a6cf877ea71f61ab999945a851bed' and doc['synthetic'] and not doc['publication_authorized']
    archive_dir=root/'assembled';archive_dir.mkdir(mode=0o700)
    def save(name,**data):return json_save(root_inputs/name,dict(fixture=True,**data))
    manifest=root_inputs/'prior-v4-fixture.json';shutil.copyfile(INPUT,manifest);manifest.chmod(0o400)
    truth=ref(manifest);make=lambda n,**d:save(n,**d)
    old=Path(doc['archive']['path']);archive=archive_dir/'epoch-251.jet'
    require(ref(old)['sha256']==doc['archive']['sha256']==result['archive']['sha256'],'fixture archive changed')
    shutil.copyfile(old,archive);archive.chmod(0o400);ar=ref(archive)
    m=doc['report'];e=251; seam=doc['seam']['predecessor_slot'];last=m['last_slot'];provenance=doc['expected_provenance_sha256']
    lineage=make('lineage.json',epoch=e,seam=seam,original_source=truth,selected=doc['selected_sources'])
    terminal=doc['terminal'];incoming=doc['incoming']
    selected=make('qualified.json',epoch=e,seam=seam,boundary_decoder_run=True,publication_authorized=False,lineage=lineage,
                  prefix_range=dict(start=m['first_slot'],end_exclusive=seam+1),suffix_range=dict(start=seam+1,end_exclusive=last+1),
                  selection=dict(v4_provenance_sha256=provenance,retry6_last_block_slot=terminal['slot'],retry6_last_blockhash=terminal['blockhash']))
    # The native acceptance really occurred; the fixture uses synthetic boundary data.
    qual_iid='d7e87cf8cd284be9865c9b00e586ff96'
    accepted=make('native-qualified.json',archive_bytes_written=0,publication_authorized=False,qualified_report=selected,lineage=lineage,invocation_id=qual_iid,
                  native_terminal=dict(success=True,invocation_id=qual_iid),native_v4=ref(PASS))
    edge=make('terminal-edge.json',slot=terminal['slot'],commitment='synthetic',get_block=dict(result=dict(blockhash=terminal['blockhash'])),source=truth)
    expect=make('expectation.json',schema='horizon-current-reader-epoch-expectation-v1',epoch=e,parent_slot=incoming['slot'],parent_blockhash=incoming['blockhash'],
                terminal_slot=terminal['slot'],terminal_blockhash=terminal['blockhash'],provenance_sha256=provenance,independent_evidence=[truth,ref(PASS)])
    prep=make('preparation.json',epoch=e,slots=432000,slot_range=[m['first_slot'],last],expected_result=expect,expected_assembly_report=str(archive_dir/'assembly.json'),
              selected_source_qualification=selected,selected_source_native_acceptance=accepted,terminal_finalized_crosscheck=edge,publication_authorized=False)
    native_launch=make('launch.json',Id=scope_unit,InvocationID=iid)
    admitted=make('assembler-admission.json',fits=True,unit=scope_unit,publication_authorized=False)
    plan=make('assembler-plan.json',unit=scope_unit,output_directory=str(archive_dir),publication_authorized=False,admission=admitted,lineage=lineage,
              maximum_archive_bytes=2<<20,minimum_home_free_bytes=0,qualification=selected,qualification_native=accepted)
    real=base(e,archive_dir,read(Path(native_launch['path'])))
    real.update(plan=plan,native_launch=native_launch,expectation=expect,preparation=prep,selected=selected,selected_native=accepted,lineage=lineage,terminal_edge=edge)
    json_save(root/'scope.json',real)
    asm=dict(schema='horizon-epoch168-private-v4-assembly-v1',epoch=e,unit=scope_unit,invocation_id=iid,plan=plan,qualification=selected,lineage=lineage,admission=admitted,
             qualification_native=accepted,archive_path=str(archive),archive_sha256=ar['sha256'],archive_bytes=archive.stat().st_size,provenance_sha256=provenance,
             slots=m['slots'],blocks=m['blocks'],transactions=m['transactions'],normalized_writes=sum(m[k] for k in ['epoch_updates','transaction_updates','orphan_updates']),
             minimum_home_free_bytes=0,maximum_archive_bytes=2<<20,independent_verification_pending=True,publication_authorized=False,fixture=True)
    case=os.environ.get('HORIZON_FIXTURE_CASE','correct')
    require(case in {'correct','digest','counts'},'unknown fixture case')
    if case=='counts':asm['transactions']+=1
    if case=='digest':asm['archive_sha256']='0'*64
    json_save(archive_dir/'assembly.json',asm)
if __name__=='__main__':
    os.umask(0o077)
    if sys.argv[1]=='production':print(json.dumps(production()))
    elif sys.argv[1]=='populate':populate(Path(sys.argv[2]))
