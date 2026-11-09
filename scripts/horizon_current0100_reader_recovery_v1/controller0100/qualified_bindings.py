ROOT_SUCCESSOR_ARTIFACT_VALIDATOR_INTEGRATED = False
'Narrow metadata lookup for already-qualified1800 artifacts; no operations.'
import hashlib
import json
import os
from pathlib import Path
import stat
import re
Q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
C = Q / 'combined-runtime'
FUTURE_HELPER27_BINDINGS_SHA256 = 'ee192f7c66ef9c08d984084329fea5bf9c64b478709a67150a944e2c4fd49819'  # Root binds fresh0100 closure after actual qualification
FUTURE_HELPER27_BINDINGS = Path(__file__).resolve().parent / 'ROOT_ACTUAL_QUALIFIED_HELPER27_BINDINGS.json'

def _future27():
    assert isinstance(FUTURE_HELPER27_BINDINGS_SHA256, str) and re.fullmatch('[a-f0-9]{64}', FUTURE_HELPER27_BINDINGS_SHA256), 'Root actual helper27 qualification/seal/closure binding required; no future digest invented'
    raw = _raw(FUTURE_HELPER27_BINDINGS)
    assert hashlib.sha256(raw).hexdigest() == FUTURE_HELPER27_BINDINGS_SHA256
    v = json.loads(raw)
    assert v['schema'] == 'horizon-current0100-actual-helper27-bindings-v1'
    for key in ['qualification', 'exact_source_and_compiler_graph', 'normal_pool_closure']:
        assert metadata_bound(v[key]['path'], immutable=False) == v[key]
    assert v['replay_launch_authorized'] is False and v['new_memory_or_DATA_credit_bytes'] == 0
    return v
GUARD = Path('/usr/local/lib/jetstreamer/horizon-current0100-bound-guard-window-tools-20261109-v1')

def _raw(path, immutable=True):
    path = Path(path)
    assert path.is_absolute() and path.resolve(strict=True) == path
    assert path.suffix == '.json', 'only declared qualified JSON metadata'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == 0 and (before.st_nlink == 1)
        assert not before.st_mode & (146 if immutable else 18) and before.st_size <= 32 << 20
        result = bytearray()
        while len(result) <= before.st_size:
            chunk = os.read(fd, min(65536, before.st_size + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        assert len(result) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(os.lstat(path))
    finally:
        os.close(fd)
    return bytes(result)

def metadata_bound(path, immutable=True):
    raw = _raw(path, immutable=immutable)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

def _sealed(directory, name, proof_path):
    seal = json.loads(_raw(directory / 'deployment-seal-receipt.json'))
    assert seal['schema'] == 'jetstreamer-sealed-deployment-receipt-v1' and seal['destination'] == str(directory)
    assert seal['replay_launch_authorized'] is False and seal['publication_authorized'] is False and (seal['r2_mutations'] is False)
    rows = [r for r in seal['members'] if r['name'] == name and r['mode'] == '0555']
    assert len(rows) == 1
    proofs = [r for r in seal['members'] if r['name'] == 'artifact-proof.json' and r['mode'] == '0444']
    assert len(proofs) == 1
    binding = metadata_bound(proof_path, immutable=False)
    assert proofs[0]['sha256'] == binding['sha256']
    assert metadata_bound(directory / 'artifact-proof.json')['sha256'] == binding['sha256']
    assert re.fullmatch('[a-f0-9]{64}', rows[0]['sha256'])
    return ({'path': str(directory / name), 'sha256': rows[0]['sha256']}, json.loads(_raw(directory / 'artifact-proof.json')), binding)

def helper27():
    future = _future27()
    proof = Path(future['qualification']['path'])
    program, qualification, binding = _sealed(Path(future['program_directory']), 'jetstreamer-r2', proof)
    assert qualification['schema'] == 'horizon-combined-witness-terminal145-helper-original-qualification-v1'
    assert qualification['production_artifact']['sha256'] == program['sha256']
    assert qualification['exact_source_and_compiler_graph']['path'] == future['exact_source_and_compiler_graph']['path']
    assert qualification['originals']
    assert all((qualification[k] is True for k in ['prod_clippy_passed', 'test_clippy_passed', 'all_required_tests_passed', 'genuine_current_complete_outer_adapter_passed']))
    assert qualification['replay_launch_authorized'] is False and qualification['publication_authorized'] is False
    assert qualification['memory_credit_bytes'] == qualification['DATA_credit_bytes'] == 0
    return (program, binding)

def current_guard():
    proof = C / 'current0100-window-20261109-v1/work/ARTIFACT_PROOF_BEFORE_SEAL.json'
    program, qualification, binding = _sealed(GUARD, 'horizon-current0100-guard-window', proof)
    assert qualification['schema'] == 'horizon-current0100-qualified-guard-v1'
    assert qualification['production']['sha256'] == program['sha256']
    assert qualification['sample_utc'] == '2026-11-09T01:00:22Z' and qualification['sample_unix'] == 1794186022
    assert qualification['ordinary_tests_passed'] == 65 and qualification['all_original_61_names_preserved'] is True
    assert all((qualification[k] is True for k in ['all_original_actors_drained', 'prod_clippy_passed', 'test_clippy_passed', 'all_required_tests_passed']))
    return (program, binding)

def closure27():
    path = Path(_future27()['normal_pool_closure']['path'])
    binding = metadata_bound(path, immutable=False)
    closure = json.loads(_raw(path, immutable=False))
    assert closure['schema'] == 'native163-full-reader-extra-QA6-closure-v1'
    assert closure['extra_QA_memory_bytes'] == closure['released_bytes'] == 6 << 30
    assert closure['normal_pool_released_bytes'] == 0 and closure['normal_pool_bytes'] == 6 << 30
    assert closure['complete_DATA_bytes'] >= 5162967970452
    assert all((closure[k] is True for k in ['all_original_QA_actors_terminal_and_drained', 'all_required_qualification_actors_terminal_successful_and_drained', 'source_and_DATA_promises_retained']))
    _, helper_proof = helper27()
    _, guard_proof = current_guard()
    assert helper_proof in closure['required_final_qualifications'], 'closure27 must bind actual helper27 qualification'
    assert guard_proof in closure['required_final_qualifications'], 'closure27 must follow actual0100 guard qualification'
    from next_operation_bindings import next_operation_bindings
    authority = next_operation_bindings()
    assert closure['actual_original1030_held_expiry_and_drain'] == authority['original1030_held_expiry_and_drain']
    assert closure['actual_failed1030_reader_retirement'] == authority['failed1030_reader_retirement']
    assert closure['actual_next_operation_qualification'] == authority['qualification']
    assert closure['actual_final2_qualification'] == authority['final_executor_qualification']
    assert closure['actual_helper29_QA_booking'] == authority['helper29_QA_booking'] and closure['actual_helper29_QA_closure'] == authority['helper29_QA_closure']
    assert closure['actual_original1530_completion_and_drain'] == authority['original1530_completion_and_drain']
    assert closure['actual_successful1530_reader_retirement'] == authority['successful1530_reader_retirement']
    assert authority['postreader30_qualification'] in closure['required_final_qualifications']
    assert authority['qualification'] in closure['required_final_qualifications']
    assert authority['final_executor_qualification'] in closure['required_final_qualifications']
    return binding
