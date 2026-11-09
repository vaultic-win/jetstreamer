"""Bind one genuinely booked/qualified0030 guard addition over complete Root successor36 authority."""
from pathlib import Path
import json
from prior0030_qualified_bindings import _raw, metadata_bound, current_guard
PACKET = Path(__file__).resolve().parent

def with_current0030_guard(authority):
    assert authority['current_complete_DATA_lower_bound_bytes'] == 5160820486804
    request = json.loads(_raw(PACKET / 'guard/ROOT_ACTUAL_GUARD0030_BOOKING_BINDING.json', immutable=False))
    assert set(request) == {'path', 'sha256'}
    assert metadata_bound(request['path'], immutable=False) == request
    booking = json.loads(_raw(request['path'], immutable=False))
    assert booking['previous_retained_DATA_lower_bound_bytes'] == 5160820486804
    assert booking['new_retained_DATA_bytes'] == 536870912
    assert booking['complete_DATA_bytes'] == 5161357357716
    assert booking['normal_pool_bytes'] == 6 << 30
    assert booking['extra_QA5_closed_before_guard_build'] is True
    qa_path = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/combined-runtime/current0030-window-20261109-v1/ROOT_QA_EXACT_BOOKING.json')
    qa_binding = metadata_bound(qa_path, immutable=False)
    assert json.loads(_raw(qa_path, immutable=False)) == booking
    program, qualification = current_guard()
    result = dict(authority)
    additions = list(authority['successor_additive_DATA_bookings'])
    assert request not in additions and qa_binding not in additions
    assert len({row['path'] for row in additions}) == len(additions)
    additions.append(qa_binding)  # Root booking and QA copy represent ONE addition.
    total = 0
    for binding in additions:
        assert metadata_bound(binding['path'], immutable=False) == binding
        doc = json.loads(_raw(binding['path'], immutable=False))
        total += doc.get('new_additive_retained_DATA_bytes', doc.get('additional_retained_DATA_bytes', doc.get('new_retained_DATA_bytes', 0)))
    assert 5133440070292 + total == booking['complete_DATA_bytes']
    result.update(successor_additive_DATA_bookings=additions,
                  current_complete_DATA_lower_bound_bytes=booking['complete_DATA_bytes'],
                  actual_guard0030_booking=qa_binding,
                  actual_guard0030_original_Root_booking=request,
                  actual_guard0030_program=program,
                  actual_guard0030_qualification=qualification)
    assert result['actual_guard0000_booking'] == authority['actual_guard0000_booking']
    assert result['helper34_QA_closure'] == authority['helper34_QA_closure']
    return result
