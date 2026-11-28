'Bind one genuinely booked/qualified0100 guard addition over complete Root successor36 authority.'
from pathlib import Path
import json
from qualified_bindings import _raw, metadata_bound, current_guard
PACKET = Path(__file__).resolve().parent

def with_current0100_guard(authority):
    assert authority['current_complete_DATA_lower_bound_bytes'] == 5161357357716
    request = json.loads(_raw(PACKET / 'guard/ROOT_ACTUAL_GUARD0100_BOOKING_BINDING.json', immutable=False))
    assert set(request) == {'path', 'sha256'}
    assert metadata_bound(request['path'], immutable=False) == request
    booking = json.loads(_raw(request['path'], immutable=False))
    assert booking['previous_retained_DATA_lower_bound_bytes'] == 5161894228628
    assert booking['new_retained_DATA_bytes'] == 536870912
    assert booking['complete_DATA_bytes'] == 5162431099540
    assert booking['normal_pool_bytes'] == 6 << 30
    assert booking['extra_QA5_closed_before_guard_build'] is True
    qa_path = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/combined-runtime/current0100-window-20261109-v1/ROOT_QA_EXACT_BOOKING.json')
    qa_binding = metadata_bound(qa_path, immutable=False)
    assert json.loads(_raw(qa_path, immutable=False)) == booking
    program, qualification = current_guard()
    result = dict(authority)
    additions = list(authority['successor_additive_DATA_bookings'])
    assert request not in additions and qa_binding not in additions
    assert len({row['path'] for row in additions}) == len(additions)
    retire_path = Path('/home/sol/.jetstreamer-private/current0030-failed-reader-retirement-qa-20261109-v1/ROOT_NORMAL6_RETIRE0030_DATA512_BOOKING.json')
    phase_path = Path('/home/sol/.jetstreamer-private/current-reader-phase199-recovery-qa-20261109-v1/ROOT_NORMAL6_PHASE199_DATA512_BOOKING.json')
    retire_binding = metadata_bound(retire_path, immutable=False)
    phase_binding = metadata_bound(phase_path, immutable=False)
    retired = json.loads(_raw(retire_path, immutable=False))
    phase = json.loads(_raw(phase_path, immutable=False))
    assert retired['previous_retained_DATA_lower_bound_bytes'] == 5161357357716 and retired['complete_DATA_bytes'] == 5161894228628
    assert phase['previous_retained_DATA_lower_bound_bytes'] == booking['complete_DATA_bytes'] and phase['complete_DATA_bytes'] == 5162967970452
    for doc in [retired, phase]:
        assert doc['new_retained_DATA_bytes'] == 536870912 and doc['normal_pool_bytes'] == 6 << 30 and doc['extra_QA_bytes'] == 0
    assert retire_binding not in additions and phase_binding not in additions
    additions += [retire_binding, qa_binding, phase_binding]  # each genuine512MiB charged exactly once
    total = 0
    for binding in additions:
        assert metadata_bound(binding['path'], immutable=False) == binding
        doc = json.loads(_raw(binding['path'], immutable=False))
        total += doc.get('new_additive_retained_DATA_bytes', doc.get('additional_retained_DATA_bytes', doc.get('new_retained_DATA_bytes', 0)))
    assert 5133440070292 + total == phase['complete_DATA_bytes']
    result.update(successor_additive_DATA_bookings=additions,
                  current_complete_DATA_lower_bound_bytes=phase['complete_DATA_bytes'],
                  actual_guard0100_booking=qa_binding,
                  actual_guard0100_original_Root_booking=request,
                  actual_guard0100_program=program,
                  actual_guard0100_qualification=qualification)
    assert result['actual_guard0000_booking'] == authority['actual_guard0000_booking']
    assert result['actual_guard0030_booking'] == authority['actual_guard0030_booking']
    assert result['helper34_QA_closure'] == authority['helper34_QA_closure']
    return result
