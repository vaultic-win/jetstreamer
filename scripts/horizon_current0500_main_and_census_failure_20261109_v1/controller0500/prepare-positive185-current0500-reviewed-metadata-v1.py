from next_operation_bindings import next_operation_bindings
operation_authority = next_operation_bindings()
from pathlib import Path
import json, os, hashlib
q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
p = q / 'current0500-20261109-v1'
parent = p / 'parent'
root = Path('/home/sol/.jetstreamer-private/epoch185-positive-current0500-reviewed-metadata-20261109-v1')
root.mkdir(mode=448)
b = lambda f: dict(path=str(f), sha256=hashlib.sha256(Path(f).read_bytes()).hexdigest())

def save(n, v):
    f = root / n
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 256)
    with os.fdopen(fd, 'w') as h:
        json.dump(v, h, indent=2)
        h.flush()
        os.fsync(h.fileno())
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)
    return b(f)
from actual0230_predecessors import actual0230_predecessors
save('ROOT_ACTUAL0230_RESOURCE_PREDECESSORS_RETAINED.json', dict(actual0230_predecessors(), no_credit_or_new_authority=True))
components_file = parent / 'ROOT_ACTUAL0500_MEMORY_AND_DATA_COMPONENTS_ACCEPTED_NOT_FULL163_ADMISSION.json'
components = json.loads(components_file.read_text())
memory = json.loads(Path(components['actual_memory_selection']['path']).read_text())
data = json.loads(Path(components['actual_DATA_selection']['path']).read_text())
current = memory['selection']['request']['current']
reader = json.loads(Path(memory['selection']['request']['current_reader']['path']).read_text())
raw = json.loads(Path(reader['accounting']['path']).read_text())
assert current == data['data_selection']['current'] and memory['selection']['request']['reader_program']['program'] == reader['image']
assert raw['protected_existing_DATA_bytes'] == components['raw_DATA_bytes']
tuple_binding = save('CURRENT_COMPLETED_TUPLE_AT0500.json', dict(schema='horizon-existing-completed-tuple-metadata-binding-v1', metadata_only_no_admission_or_new_resource_credit=True, sampled_at_utc='2026-11-09T05:00:22Z', components=b(components_file), effective_existing_memory_bytes=memory['selection']['effective_total_memory_promises_bytes'], effective_existing_DATA_bytes=data['data_selection']['projection']['proposed_protected_existing_DATA_bytes'], **current))
old_phase = Path(operation_authority['retained_phase_ledger']['path'])
assert b(old_phase) == operation_authority['retained_phase_ledger']
ledger = json.loads(old_phase.read_text())
additional_booking = json.loads(Path(operation_authority['additive_DATA_booking']['path']).read_text())
assert b(operation_authority['additive_DATA_booking']['path']) == operation_authority['additive_DATA_booking']
qa29 = json.loads(Path(operation_authority['helper29_QA_booking']['path']).read_text())
assert b(operation_authority['helper29_QA_booking']['path']) == operation_authority['helper29_QA_booking']
from observer136_data import actual_observer136_closed_booking
observer136_booking, observer136_closure, observer136_book, observer136_closed = actual_observer136_closed_booking()
additional = ledger['complete_retained_additional_DATA_bytes'] + additional_booking['additional_retained_DATA_bytes'] + qa29['new_additive_retained_DATA_bytes'] + observer136_book['new_additive_retained_DATA_bytes'] + json.loads(Path(operation_authority['helper30_QA_booking']['path']).read_text())['new_additive_retained_DATA_bytes']
additional += json.loads(Path(operation_authority['helper31_QA_booking']['path']).read_text())['new_additive_retained_DATA_bytes']
assert len({row['path'] for row in operation_authority['successor_additive_DATA_bookings']}) == len(operation_authority['successor_additive_DATA_bookings']), 'No duplicate DATA bookings'
assert sum((row['path'] == '/home/sol/.jetstreamer-private/epoch185-enrollment-composition-helper-qa-20261108-v33/ROOT_NORMAL6_BOUNDED_COMPILER3_DATA4_BOOKING.json' for row in operation_authority['successor_additive_DATA_bookings'])) == 1, 'Helper33 DATA4 must be counted exactly once'
assert sum(row['path'] == '/home/sol/.jetstreamer-private/epoch185-inherited-census-helper-qa-20261108-v34/ROOT_FRESH_EXTRA_QA5_COMPILER8_DATA4_BOOKING.json' for row in operation_authority['successor_additive_DATA_bookings']) == 1, 'Helper34 DATA4 must already be counted exactly once'
for successor_booking in operation_authority['successor_additive_DATA_bookings']:
    assert b(successor_booking['path']) == successor_booking
    document = json.loads(Path(successor_booking['path']).read_text())
    additional += document.get('new_additive_retained_DATA_bytes', document.get('additional_retained_DATA_bytes', document.get('new_retained_DATA_bytes', 0)))
guard_booking_file = Path(operation_authority['actual_guard0500_booking']['path'])
guard_booking = json.loads(guard_booking_file.read_text())
assert guard_booking['new_retained_DATA_bytes'] == 536870912 and guard_booking['complete_DATA_bytes'] >= 5162967970452
assert b(guard_booking_file) in operation_authority['successor_additive_DATA_bookings'], 'Guard DATA must already be counted exactly once'
assert additional > 0
ledger.update(complete_retained_additional_DATA_bytes=additional, schema='horizon-positive185-resource-phases-v1', exclusive_operational_owner='01a1af2a-9ce8-76a2-8939-b2112bd38f53', all_old_memory_DATA_and_raw_producer_promises_retained=True, raw_DATA_bytes=raw['protected_existing_DATA_bytes'], complete_conservative_raw_DATA_booking_bytes=raw['protected_existing_DATA_bytes'] + additional, normal_external_pool_bytes=6 << 30, temporary_QA_memory_additional_bytes=0, additional_QA_memory_bytes_retained_until_authoritative_closure=0, input163_protected_transfer_floor_after_new_helper_DATA_bytes=max(ledger['input163_protected_transfer_floor_after_new_helper_DATA_bytes'], 5114649588372), original_phase_history=b(old_phase), current=current, authoritative_extra_QA_closure=b(q / 'combined-runtime/ROOT_HELPER27_CURRENT0500_NORMAL_POOL_REVALIDATED_CLOSURE_R2.json'), actual_operation17_qualification=b('/home/sol/.jetstreamer-private/epoch185-positive-current-operation-qa-20261108-v17-r2/PRODUCTION-ORIGINAL-QUALIFICATION.json'), actual_next_operation_qualification=operation_authority['qualification'], actual_final2_qualification=operation_authority['final_executor_qualification'], actual_final2_additive_DATA_booking=operation_authority['additive_DATA_booking'], actual_failed1030_reader_retirement=operation_authority['failed1030_reader_retirement'], actual_original1030_held_expiry_and_drain=operation_authority['original1030_held_expiry_and_drain'], actual_helper29_QA_booking=operation_authority['helper29_QA_booking'], actual_helper29_QA_closure=operation_authority['helper29_QA_closure'], new_resource_credit_bytes=0)
ledger['actual_current0500_guard_DATA_booking'] = b(guard_booking_file)
assert ledger['complete_conservative_raw_DATA_booking_bytes'] >= operation_authority['current_complete_DATA_lower_bound_bytes'] >= 5162967970452
phase = save('RESOURCE_PHASES_POSITIVE185_CURRENT0500.json', ledger)
export = raw['live145_prefix_export_after']['plan']
assert export == raw['live145_prefix_export_before']['plan']
review = save('ROOT_CURRENT0500_POSITIVE_PHASE_ACCEPTANCE.json', dict(schema='horizon-epoch185-positive-phase-ledger-acceptance-v1', phase_ledger=phase, raw_accounting=reader['accounting'], current=current, protected_exporter_plan=export, all_raw_claims_preserved=True, no_resource_credit_bytes=0, normal_external_pool_bytes=6 << 30, closed_QA_additional_memory_bytes=0, admission_authorized=False, actual_repair_owner='/root', original_additional_DATA_bytes_retained=additional, current_raw_DATA_rebased_without_editing_history=True))
audit_file = json.loads(json.loads(Path('/home/sol/.jetstreamer-private/actual050022-visible-root-acceptance-20261109-v1/status-audit050022-execution.json').read_text())['stdout'])['audit']
audit = json.loads(Path(audit_file).read_text())
status = next((row['receipt'] for row in audit['outcomes'] if row['epoch'] == 185))
assert b(status['path']) == status
assembly = save('ASSEMBLY_REQUEST.json', dict(schema='horizon-positive185-upstream-assembly-request-v1', complete_tuple=tuple_binding, phase_ledger=phase, reviewed_phase_ledger=review, protected_exporter_plan=export, accepted_local_integrity_basis=b('/home/sol/.jetstreamer-private/epoch185-cohesive-capped-package-and-capability-source-20261105-v3/ROOT_ACCEPTED_LOCAL_INPUT_INTEGRITY_BASIS.json'), original_restore_receipt=b('/usr/local/lib/jetstreamer/horizon-epoch185-offline-original-restore-receipt-20261107-v1/restore-receipt.json'), status_readback=status, generation='positive-0500-20261109-next', useful_runtime_seconds=14400, reader_source_spec=b(p / 'FAILED4_READER_ACTUAL0500_SPEC.json'), reader_external_booking=b(p / 'FAILED4_READER_ACTUAL0500_EXTERNAL_BOOKING.json')))
operation_root = Path('/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0500-planner-20261109-next')
operation_root.mkdir(mode=448)
request = save('PLANNER_OPERATION_REQUEST.json', dict(operation_root=str(operation_root), generation='positive-plan-0500-next', assembly=assembly))
print(json.dumps(dict(request=request, assembly=assembly, current=current, actual_original_reader_recorded_unix_seconds=reader['recorded_unix_seconds'])), flush=True)
