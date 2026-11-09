from qualified_bindings import metadata_bound, _raw
import json
BOOKING = {'path': '/home/sol/.jetstreamer-private/epoch136-observer4-actual-QA-booking-20261108-v1/ROOT_SERIAL_OBSERVER4_QA8_DATA1_BOOKING.json', 'sha256': 'deafd11f34b0d6b74ef8f314e44ccfcd8ded7ba20489076e1bb72cdd9299bc82'}
CLOSURE = {'path': '/home/sol/.jetstreamer-private/epoch136-observer4-actual-QA-booking-20261108-v1/ROOT_OBSERVER4_EXTRA_QA2_CLOSED_NO_GATED_ACTORS_NORMAL6_DATA1_RETAINED.json', 'sha256': '97df1a6a6514dc865a3a37812a62596e5212a90a8973da2b5badb2b70b46603c'}

def actual_observer136_closed_booking():
    for item in [BOOKING, CLOSURE]:
        assert metadata_bound(item['path'], immutable=False) == item
    b = json.loads(_raw(BOOKING['path'], immutable=False))
    c = json.loads(_raw(CLOSURE['path'], immutable=False))
    assert c['booking'] == BOOKING and c['all_own_work_terminal_before_original_deadline'] is True
    assert c['new_extra_QA_memory_bytes_closed_once'] == 2 << 30 and c['normal_pool_bytes_retained'] == 6 << 30 and (c['total_pool_bytes_after_close'] == 6 << 30)
    assert c['actual_source_copy_started'] is False and c['actual_compiler_or_test_started'] is False and (c['actual_child_units_launched'] == [])
    assert c['all_own_cgroups_empty'] is True and c['all_own_processes_drained'] is True and (c['no_new_actor_descriptors_exist'] is True)
    assert b['new_additive_retained_DATA_bytes'] == c['new_additive_DATA_bytes_retained'] == 1 << 30
    assert b['complete_DATA_lower_bound_bytes'] == c['complete_DATA_lower_bound_bytes_retained'] == 5124850135700
    assert c['previous_QA_closures_not_recredited'] is True and c['memory_credit_bytes'] == c['DATA_credit_bytes'] == 0
    for row in c['planned_unit_native_absence']:
        assert row['LoadState'] == 'not-found' and row['MainPID'] == row['ControlPID'] == row['NRestarts'] == '0' and (row['Job'] == row['ControlGroup'] == '')
    return (BOOKING, CLOSURE, b, c)
