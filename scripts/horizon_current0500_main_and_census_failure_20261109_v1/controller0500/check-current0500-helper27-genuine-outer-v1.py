from pathlib import Path
import json, subprocess, os
p = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/combined-runtime')
base = [x.replace('20261107-v10', '20261108-v27').replace('test-tmp-v10', 'test-native-tmp-current0500-v27-custody-r2') for x in json.loads((p / 'HELPER_ORDINARY_ARGV_V10.json').read_text())[:-2]]
(p / 'helper-qa/test-native-tmp-current0500-v27-custody-r2').mkdir(mode=448)
fixture = '/var/lib/jetstreamer/horizon-positive185-original-writer-custody-qa-20261107-v1'
m = Path(fixture).stat()
assert m.st_uid == 0 and m.st_mode & 511 == 448
base = [x.replace('MemoryHigh=8G', 'MemoryHigh=2G').replace('MemoryMax=8G', 'MemoryMax=2G') for x in base]
base += ['-p', 'ReadWritePaths=' + fixture]
image = '/usr/local/lib/jetstreamer/horizon-first-lane-combined-helper-tests-20261108-v27/helper-tests'

def save(n, v):
    fd = os.open(p / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as f:
        json.dump(v, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
tests = [('actual-terminal145', 'fleet::epoch186::accounting::live145_prefix::tests::actual_terminal_v8g1_retains_original_failure_last_token_and_all_debt', True)]
import hashlib
manifest = p.parent / 'current0500-20261109-v1/GENUINE0500_OUTER_ADAPTER_FIXTURE_MANIFEST.json'
base += ['--setenv=JETSTREAMER_CURRENT_TERMINAL145_FIXTURE_BINDING=' + json.dumps(dict(path=str(manifest), sha256=hashlib.sha256(manifest.read_bytes()).hexdigest()), separators=(',', ':'))]
tests += [('genuine-current-outer', 'fleet::epoch186::evidence::recovered_resource_frame_adapter::current_terminal145_image_registration_tests::complete_outer::genuine_current_terminal145_capture_reaches_complete_outer_adapter_and_rejects_tampering', True)]
tests += [('actual-current-coordinator', 'fleet::epoch186::accounting::live145_prefix::coordinator_tests::actual_terminal145_periodic_guard_composes_before_current_coordinator_without_hiding_other_rows', True)]
raw_report = p.parent / 'current2130/ROOT_ORIGINAL2130_FAILED_READER_AND_TWO_REAL_REPORTS_PRESERVED.json'
original_reports = json.loads(raw_report.read_text())['real_partial_reports']
report = next((x for x in original_reports if x['path'].endswith('/raw-builder-before.json')))
base += ['--setenv=JETSTREAMER_TERMINAL_MEMORY_REAL_REPORT_BINDING=' + json.dumps(dict(path=report['path'], sha256=report['sha256']), separators=(',', ':'))]
tests += [('actual-terminal-discovery', 'fleet::charge136::admission::terminal_legacy_memory::actual_live145_discovery_control::actual_saved_full_builder_accepts_only_authenticated145_discovery_rollover', True)]
for label, test, ignored in [t for t in tests if t[0] == 'genuine-current-outer']:
    a = [x.replace('horizon-first-lane-combined-helper-ordinary-20261108-v27', 'horizon-first-lane-helper-regression-current0500-' + label + '-20261109-v27-custody-r2') for x in base] + [image, test, '--test-threads=1'] + (['--ignored', '--exact'] if ignored else [])
    save('REGRESSION_CURRENT0500_R2_' + label + '_ARGV_V27.json', a)
    z = subprocess.run(a, capture_output=True, text=True, timeout=630)
    save('REGRESSION_CURRENT0500_R2_' + label + '_ORIGINAL_EXECUTION_V27.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
    print(label, z.returncode, z.stdout[-2000:], z.stderr[-1000:], flush=True)
    assert z.returncode == 0 and '0 passed;' not in z.stdout
