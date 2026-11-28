"""Bind a conditional scheduling model to native receipts; never acquire resources."""
from math import ceil
from pathlib import Path
import runpy

ROOT = Path('/var/lib/jetstreamer/horizon_runtime_data')
RECOVERY = ROOT / 'epoch199-delivery-recovery-20261121-v1'
PROFILE = ROOT / 'epoch172-current-delivery-20261121-v1/event172-run-c077680a3b774395a639ee769f5c400b/fit.json'
PROFILE_SHA = '31744ff6348112e83adeaca1dac44f3c6ef3f706a888f1ad1365a893a2066445'


def forecast_transition(routes, checked, bound, fref, prior, deadlines, replay_end, ready,
                        fit_path=PROFILE, fit_hash=PROFILE_SHA, worker_ref=None):
    refs = {}

    def receipt(name, path, sha):
        ref = bound(path)
        if ref['sha256'] != sha:
            raise ValueError('Mismatched ' + name)
        refs[name] = ref
        return checked(ref)

    native = receipt('native_capacity', fit_path, fit_hash)
    if native.get('schema')=='horizon-145-nine-phase-native-qualification-v1':
        installed=ROOT/'incident-replay-fit-20261121-v1/tools-v15'
        assert fit_path==installed/'qualification.json' and fit_hash=='45a6b4627bba3fc9b242d9c7030fc9c817f49466932a9fb067f24ed1bf5a800e'
        seal=receipt('price_provider',installed/'deployment-seal-receipt.json','7f887c933698d424cd69244dede860f62cea2759a83f9edacc96f09c60c75eb6')
        assert any(m['name']=='qualification.json' and m['sha256']==fit_hash for m in seal['members'])
        assert len(native['registrations'])==9 and native['refused_crossed_modes']==13 and native['resource_credit_bytes']==0
        native=native['fit']
    passive = receipt('standby', RECOVERY/'transition-state/V2_PASSIVE_CHECKPOINT_ACTIVE.json',
                      '5f5ab81a97a5c12f42ebeb5ec0a1f80e79efad63396f7814294eeb3b837d0af7')
    budget_path = RECOVERY / 'phase-transition-v2/transition_budget.py'
    active=RECOVERY/'transition-state/V3_PASSIVE_CHECKPOINT_ACTIVE.json'
    if active.exists():
        refs['standby']=bound(active)
        passive=checked(refs['standby'])
        assert passive['package']==bound(RECOVERY/'phase-transition-v3/deployment-seal-receipt.json') and passive['package']['sha256']=='c7a2e2d183a3213ad1bec65ac883946f7a4bd558f0da10d2363af3693eb19fb2'
        assert passive['registry']==bound(RECOVERY/'phase-registry-v3/deployment-seal-receipt.json') and passive['registry']['sha256']=='6da2d82061418df532885105835ca96e9f2a1672952d6bc8d39b12bf52e7880e'
        switch=checked(passive['before'])
        assert switch['successor']==passive['package'] and switch['original']==bound(RECOVERY/'phase-transition-v2/deployment-seal-receipt.json')
        assert all(r['InvocationID']==switch['before'][k]['InvocationID'] and r['SubState']=='waiting' for k,r in passive['registered_paths'].items())
        assert len(passive['registered_paths'])==6 and passive['resource_credit_bytes']==0 and not passive['replay_started']
        installed=checked(passive['qual'])
        assert installed['package']==passive['package'] and installed['registry']==passive['registry']
        assert installed['actual_provider']['sha256']=='7f887c933698d424cd69244dede860f62cea2759a83f9edacc96f09c60c75eb6'
        assert installed['native_qa']['refused_crossed_modes']==13 and len(installed['native_qa']['nine_registered_modes'])==9
        assert checked(passive['standby'])==dict(outcome='awaiting-original-transition',real_transition_evidence=[],replay_started=False)
        refs['v3_preflight']=passive['qual']
        budget_path=RECOVERY/'phase-transition-v3/transition_budget.py'
    qual = checked(passive['qual'])['native_qa']
    matrix = checked(qual['focused169_matrix'])['matrix']
    assert matrix['counts']['transfer_combinations'] == 486 and matrix['projection_only']
    assert not passive['physical_transfer_issued'] and not qual['test_grants_installed']
    refs['v13_matrix']=qual['focused169_matrix']
    if 'v3_preflight' not in refs:
        refs['v2_preflight']=passive['qual']
    refs['native_equation'] = bound(budget_path)
    assert refs['native_equation']['sha256'] == '77b65b79097dd62ce8b591f382ccb8a1597d510a211206ca4d2caf301eb9840d'
    budget = runpy.run_path(str(budget_path))
    head = checked(fref)
    roster = checked(native['fleet'])
    cursor = fref
    while cursor != native['fleet']:
        previous = checked(cursor)['previous_Root_operational_review']
        assert checked(previous)['recorded_unix_seconds'] < checked(cursor)['recorded_unix_seconds']
        cursor = previous
    def identities(f):
        return {r['epoch']:r['unit']['InvocationID'] for k in
                ('actual_executing_replays','actual_active_private_diagnostics','actual_active_bootstraps')
                for r in f[k]}
    assert identities(roster) == identities(head) and native['fits']
    assert {e:identities(head)[e] for e in replay_end} == budget['GENERATIONS']
    assert all(head.get(k) is None for k in ('focused169_terminal','full172_local_commit'))
    assert head['all_reservation_ending_bytes'] == native['resource_credit_bytes'] == 0
    phase=native['phase145']
    predecessor='d37f36f898a44932a19fd50d7014a6fe'
    if phase.get('ActiveState')=='failed':
        generation=phase['InvocationID']
        failures={predecessor:'6533e594be11534e7fb58ac0f1fd752ead37cfd114e36899a956970b8318bb29',
                  '500c8d717a4147b087ff302b5afa7fc0':'04c96683252ad3815d906d43dbbfb2f80d3ebcf542d7e671f28119f74767b107'}
        assert phase['failure']['sha256']==failures[generation] and phase['MainPID']=='0'
        assert not phase['source_checkpoint_exists'] and phase['resource_credit_bytes']==0
        assert checked(phase['failure'])['iid']==generation and checked(phase['recovery'])['iid']==generation
        if generation!=predecessor:
            manager=checked(checked(worker_ref)['manager'])
            intent=checked(manager['intent'])
            assert intent['failure']==phase['failure'] and intent['recovery']==phase['recovery']
    else:
        if phase['invocation_id']!=predecessor:
            expected=checked(worker_ref)
            assert expected['schema']=='horizon-145-v5d-actual-advancing-original-semantic-recovery-v1'
            assert expected['invocation_id']==phase['invocation_id'] and phase['stage']=='leased-worker'
            assert checked(expected['start'])['image']=='3d60de86d45a497bcd1b9836c485ffab4ce1da19cb6d989d56c9d3b92ad60066'
    sample = checked(head['observer'])
    host_ram = sample['host_memory']['total_kib']*1024
    free_home = min(native['available_HOME_bytes'], head['same_sample_conservative_free_DATA_bytes'])
    free_memory = min(native['available_memory_bytes'], sample['host_memory']['conservative_available_kib']*1024)
    # Never improve an old price by assuming that free space grew since its capture.
    capacity = dict(native, available_HOME_bytes=free_home, available_memory_bytes=free_memory)
    ledger = checked(native['registered_host_equation']['source'])
    prior_floor = receipt('prior169', ROOT/'epoch169-focused-admission-20261120-v4/POST_GUARD_CAPACITY.json',
                          '803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc')['protected_raw_floor_bytes']
    rows = routes['price_rows'](capacity, roster, ledger, prior_floor, host_ram, budget)
    assert not any(rows[0]['transferred']) and rows[0]['complete_protected_HOME_bytes'] == native['complete_required_HOME_bytes']

    holding = receipt('private183', RECOVERY/'ACTUAL_PRIVATE183_HASH_AND_NEXT_COPY_ONLY_TRANSITION.json',
                      '5fd531237d3c4cbb559b94b3e5a4ad9602aaee54d5841cffc2f8fb5f624cde0e')
    screen = receipt('staged_sources', RECOVERY/'RECLAMATION_CANDIDATES_1018.json',
                     'f05fc6700c37447f7985d4ccfbf2a6705e8b46475cfd03a7fa69bc1e7c09e376')
    census = receipt('independent166', ROOT/'epoch166-independent-retry9-census-20261121-v1/a1ff38d47e70442cb055e02bb6408546/METADATA.json',
                     'd6062bead77df1bf231b5c2b5654ec8c6e98b4821c53337f9e87afbd54613ab8')
    receipt('protected140', RECOVERY/'ORIGINAL140_PROTECTED_PREFIX_INPUT_AND_EXACT_VERIFIERS.json',
            'b81aa9d38775e3a73662108d8ddb4056ea2947d77a644fe75022f5f48d5cd8ec')
    assert census['global_credit_bytes'] == census['removed_bytes'] == holding['resource_credit'] == 0
    held = {x['case']:x for x in screen['private_held_candidates']}
    refs['parked130_v7'] = bound(ROOT/'cold130-boot-lineage-20261121-v1/fixed-check-projection-v7.jsonl')
    assert refs['parked130_v7']['sha256'] == '648f1eaac779d9b06ae32d30070fb929d5d8bf82a0136027fc8fb556f290fffe'
    custody = checked(held['cold130']['evidence'])
    assert custody and holding['body_bytes_read'] == holding['required_future_private_restore_staging_bytes']
    assert len({(x['device'],x['inode']) for x in held.values()}) == len(held)
    # Original V7 dispatcher permits 16 min check + 32 min execute, serial on holding.
    # 183 includes the measured cold130-rate upload + full readback, then a local rehash.
    source = {
        'private183': (holding['body_bytes_read'],
                       ceil(1000*(holding['possible_new_upload_park_seconds_at_cold130_rate'] + holding['elapsed_seconds']))),
        'cold130': (held['cold130']['length'], 48*60_000),
    }
    alternatives = []
    for names in routes['subsets'](source):
        alternatives.append(dict(sources=list(names), net_bytes=sum(source[n][0] for n in names),
                                 ready_ms=ready+sum(source[n][1] for n in names), dated=True))
    # Both standard retry bodies are OUTSIDE the independent166 cap. Their old
    # staged reader graphs still fail, so they are sensitivity inputs without a date.
    for base in list(alternatives):
        names = ['166-retry7','166-retry8']
        alternatives.append(dict(sources=base['sources']+names, dated=False, ready_ms=base['ready_ms'],
                                 net_bytes=base['net_bytes']+sum(held[n]['length'] for n in names)))
    ranking = receipt('other_private_inodes', RECOVERY/'LARGE_CLOSED_SOURCE_140_STAGED_REFERENCES_AND_199_RANKING_1400.json',
                      '8f9eea7aacc29429d6559b179a65c538e7588e5a2dda8832f9486711a67c3658')
    cases = checked(ranking['source_screen'])['cases']
    extra = {c['original']['epoch']: c['original']['file_identity'][6] for c in cases
             if c['original']['epoch'] in (144,185)}
    assert set(extra) == {144,185}
    # Only a sensitivity: no completed holding and reader qualification for these siblings.
    largest = alternatives[-1]
    alternatives.append(dict(sources=largest['sources']+['private144','private185'], dated=False,
                             ready_ms=largest['ready_ms'], net_bytes=largest['net_bytes']+sum(extra.values())))
    closed = {e:end+prior[e]['delivery_forecast']['phase_milliseconds']['assembly_close_import']
              for e,end in replay_end.items()}
    diag = prior[169]['coordinated_private_diagnostic_169']
    assert diag['coordinated_sample_observed_this_invocation'] and not diag['archive_publication_authorized']
    # Price the actual focused endpoint independently from epoch 169's public status.
    progress = diag['observed_progress']
    assert progress['advancing'] and progress['ordered'] and progress['covers_interval']
    first, last = progress['first'], progress['last']
    from datetime import datetime
    sample_ms = round(datetime.fromisoformat(head['sampled_at_utc'].replace('Z','+00:00')).timestamp()*1000)
    assert last['terminal_slot'] == first['terminal_slot'] and last['terminal_slot'] > last['slot'] > first['slot']
    delta_us = last['realtime_microseconds']-first['realtime_microseconds']
    assert delta_us >= 60_000_000
    diagnostic = sample_ms + ceil((last['terminal_slot']-last['slot'])*delta_us*1.10/(1000*(last['slot']-first['slot'])))
    selected, cases = routes['select_routes'](rows, closed, deadlines, diagnostic, ready, alternatives)
    return dict(selected=selected, alternatives=cases, sources=refs, projected_populations=64,
                projected_disk_margin_bytes=selected['case']['net_bytes']-selected['row']['gaps']['disk'],
                price_assumptions='Uses the lower recorded free HOME and RAM at the fit and cycle, with native unspent bookings captured at the fit. Further retained growth, a smaller post-repair transfer or insufficient memory can change the selected route. No undated release is counted in the dashboard ETA.',
                projected_transfer_combinations=len(rows), actual_grants=0, actual_new_physical_release_bytes=0,
                measured_free_HOME_lower_bound=free_home, measured_available_RAM_lower_bound=free_memory,
                focused169_private_endpoint_ms=diagnostic, public169_status_forecast_ms=deadlines[169],
                native_terminal_and_guard_drain_forecasts=closed, verified_public_grant_forecasts={e:deadlines[e] for e in closed},
                conditions='Projected local commit includes assembly. The native guard must drain, each named exclusive grant must pass authenticated publication and preserve repair/restore, and every assumed local disposal needs a new closure and physical retirement receipt. 183 needs 145 lock release and a verified holding copy. Backed 130 needs refreshed reachable readers, three sweep locks and v7 check/execute. Each future restoration needs its full object funded. Final admission requires fresh whole-host fit.',
                excluded='Independent 166 retry9 is inside its prepaid cap. Protected 140 is retained for recovery. Standard 166 retry7/8 have unresolved staged readers. 144/185 private siblings lack qualified independent retirement. Circular 198/201 and undated adjacent boundaries cannot fund a dated route. Prior physical retirements already appear in native free HOME.')
