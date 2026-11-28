"""Reprice the funded 169 peer and its live 170 sibling after the original 168 assembler exits."""
from pathlib import Path
import runpy
import time


G = 1 << 30
M = 1 << 20
RT = Path('/var/lib/jetstreamer/horizon_runtime_data')
ISSUED = RT/'epoch169-hourly-admission-20261123-v1/issued-split-v1'
PHASE_END = RT/'epoch143-first-hourly-20261127-v1/PHASE_170_FIRST_168_RELEASED.json'
END_SHA = 'f97355db620e55478840e20ded06943a59ac9b85a6cd3a7d348882407ea1be88'


def budget169(core, native, snapshot, operations, paid, verification, extra_home, helper):
    other, peer169, peer162 = operations
    cap = other['capacity']
    fleet, ref = core.current_fleet()
    core.need(ref == native['raw']['fleet'] == snapshot['fleet'], 'superseded post-assembly fleet')
    book = fleet['retry9_auxiliary_commitments']
    campaign = runpy.run_path(str(ISSUED/'campaign-price.py'))
    support = campaign['bound_tools']()
    core.need(support.accepted_fleet(ref) == fleet, 'different accepted funding')
    compiler = support.compiler_reservation()
    recovery = support.recovery_reservation(compiler)
    serial = support.repeated_serial_slot(native['raw'], book)
    copier, micro = campaign['input_cost'](support), campaign['micro_cost'](support)
    def serial_owner():
        return helper['holding'](core,support,lambda: campaign['holding'](support))
    holder = serial_owner()
    rooms = support.margins(native, book, compiler['image_physically_funded_bytes'], serial['repeated_serial_bytes'])
    settled = cap['terminal_charges'](recovery, rooms, copier, compiler)
    v47 = core.bound(paid['funding_V47'])
    core.need(v47['fits'] and paid['fixed_HOME'] == v47['bookings']['extra_output_bytes'] + v47['additional_home_bytes']
              + paid['verification168_listener']['additional_home'] + paid['writer_overhead'] and
              verification['armed'] == paid['verification168_listener']['armed'] and
              settled['issued_input'] == copier['custody'] == paid['input170']['custody'] and
              settled['compiler_excess_ram'] == settled['concluded_copier_ram'] == G and
              serial == paid['serial'] and compiler['terminal'] and compiler['image_physically_funded_bytes'] == 4*G and
              recovery['maximum_memory'] == paid['recovery']['maximum_memory'] == 3*G, 'funded serial slots changed')
    written = paid['fixed_HOME'] - paid['verification168_listener']['additional_home'] + verification['additional_home']
    home = rooms['remaining_home'] - written - 16*M - copier['additional_home'] - micro['retained_evidence'] - extra_home
    a = snapshot['row169']
    peer169['recheck'](fleet, a)
    later = peer169['current'](fleet)
    # Retain the 8 GiB output and its control after native terminal until separately reconciled.
    amounts = cap['floor_and_margin'](native['available_home'], home, later if later['phase'] != 'terminal' else None)
    if a['phase'] != 'terminal':
        previous = cap['floor_and_margin'](native['available_home'], home, a)
        floor, growth = max(amounts['guard_floor'],previous['guard_floor']), max(amounts['remaining_output'],previous['remaining_output'])
        amounts.update(guard_floor=floor, remaining_output=growth, required_home=floor+growth, home_margin=native['available_home']-floor-growth)
    paid169 = min(snapshot['paid169'], cap['resident'](later))
    ram = rooms['post_reservation_ram_margin'] + paid169 + native['other_resident']['kernel'] + native['other_resident']['audit']
    ram -= verification['additional_ram'] + recovery['maximum_memory'] + v47['additional_RAM_bytes'] - book['build_memory_bytes']
    ram -= copier['additional_ram'] + micro['witness_ram']
    ram += settled['compiler_excess_ram'] + settled['concluded_copier_ram']
    core.need(serial_owner() == holder and campaign['input_cost'](support) == copier and
              campaign['micro_cost'](support) == micro and recovery == support.recovery_reservation(compiler) and
              cap['verification168'](book) == verification and core.current_fleet()[1] == ref,
              'post-assembly ownership changed')
    row = snapshot['row162']
    peer162['recheck'](fleet,row)
    peer169['recheck'](fleet,a)
    return dict(schema='horizon-169-split-current-native-price-v1', phase='postguard', native=native, fleet=ref,
                provider=snapshot['provider'], writer=snapshot['writer'], actor=a, peer169_grant=snapshot['grant'], prior169_post=snapshot['post'],
                accounting=dict(old_six_owner_lineage=paid['old_six_owner_lineage'], rooms=rooms, holding=holder,
                                compiler=compiler, recovery=recovery, serial=serial, input170=copier, recorder170=micro,
                                terminal_ram=settled, verification168_listener=verification, new_package_bytes=extra_home),
                observed_actors=native['observed_actors'], resource_credit_bytes=0, realized_169_anonymous_and_noswap_shmem=paid169,
                ram_margin=ram, fits=ram >= 0 and amounts['home_margin'] >= 0, **amounts,
                started_unix_seconds=snapshot['observed'], recorded_unix_seconds=time.time()), row


def price(helper, package_dir):
    current = runpy.run_path(str(package_dir/'continuation_price.py'))
    core = current['prior']
    first, operations = helper['snapshot'](core)
    other, _, _ = operations
    cap = other['capacity']
    old = core.bound(first['post'])
    paid = old['accounting']
    fleet = core.bound(first['fleet'])
    ended, end_ref = core.read(PHASE_END,END_SHA)
    terminal = ended['native_terminal']
    core.need(terminal['INVOCATION_ID'] == 'f097aed2a8f647398854fa6139f02d32' and
              terminal['MESSAGE_ID'] == '7ad2d189f7e94e70a38c781354912448' and not ended['resource_credit_bytes'],
              'different 168 assembly terminal')
    evidence, pr = core.read(current['DEP']/'FIRST_PROTECTED_PROGRESS.json',
                             '51aaa67e0eeb7bd1da0ed85e718ade911a6ae425e21be20383cb0f715c834d02')
    actor, release = core.bound(evidence['actor']), core.bound(evidence['release'])
    iid, name = actor['producer_invocation_id'], actor['unit']
    guard = core.bound(release['guard_plan'])
    core.need(release['actor'] == evidence['actor'] and (name,iid) == (current['UNIT'],'c3ab30cfeb05428bb8f5c48a5a44822c')
              and guard['invocation_id'] == iid and guard['maximum_root_physical_bytes'] == 349442555904 and
              guard['minimum_free_bytes'] == 9635346274380, 'different guarded 170 interval')
    roster = [(actor['producer_pid'],actor['start_ticks']), (evidence['worker']['pid'],evidence['worker']['start_ticks'])]
    def observe():
        sample, bounds = current['issued_tree_bounds'](actor)
        anon = current['anonymous'](name,iid,roster,48*G)
        return dict(sample=sample,bounds=bounds,anon=anon,available=core.availability())
    study = runpy.run_path(str(ISSUED/'witness-admission.py'))
    left = cap['optional_memory'](fleet,first['fleet'],study)
    before = observe()
    q = current['price']('held',native169=first['row169'],native162=first['row162'])
    after = observe()
    original = old['native']['raw']['joint']
    joint = q['joint']
    core.need(q['fleet'] == first['fleet'] and q['phase170_first'] is None and
              q['assembly168']['state'] == 'queued-or-drained' and q['assembly168']['incremental_ram'] == 0 and
              q['assembly168']['incremental_home'] == 0 and q['priced_170_invocation'] == iid
              and not q['resource_credit_bytes'] and not joint['resource_credit_bytes'] and
              all(joint[k] == original[k] for k in ('interface','charged_167','return140','booking140','loan140',
                                                    'producer_allowance','guard_sibling_allowance','producer_quota_micros')) and
              joint['required_ram']+joint['resident_lower_bytes'] >= paid['old_six_owner_lineage']['bounded_167_base'],
              'post-assembly quote lost the original six funded reservations')
    memory = min(before['anon'],after['anon'])
    free_home = min(q['available_home'],before['available'][0],after['available'][0])
    free_ram = min(q['available_ram'],before['available'][1],after['available'][1])
    remaining = guard['maximum_root_physical_bytes']-min(before['bounds'][0],after['bounds'][0],q['terminal_tree_bounds'][0])
    required_home=max(guard['minimum_free_bytes'],q['guard_floor'])+remaining
    required_ram=q['required_ram']-memory
    rows = fleet['actual_active_private_diagnostics'] + fleet['actual_active_bootstraps'] + fleet['actual_executing_replays']
    native = {r['epoch']:r['unit'] for r in rows if r['epoch'] not in (143,162,169)}
    core.need(set(native) == {146,167,170,172}, 'different incumbent fleet')
    if q['replacement143']:
        r = q['replacement143']
        native[143] = {'Id': r['unit'], 'InvocationID': r['iid']}
    for peer in (first['row169'],first['row162']):
        if peer and peer['phase'] != 'terminal':
            native[peer['epoch']] = peer['unit']
    observed = [dict(epoch=n,unit=r['Id'],invocation_id=r['InvocationID']) for n,r in sorted(native.items())]
    raw = dict(raw=q, available_home=free_home, required_home=required_home, available_ram=free_ram, required_ram=required_ram,
               historical_home_margin=q['historical_home_margin'], home_margin=min(free_home-required_home,q['historical_home_margin']),
               ram_margin=free_ram-required_ram, progress=pr, before=before, after=after, guarded_170_remaining=remaining,
               realized_170_anon=memory, observed_actors=observed, confirmed_168_terminal=end_ref, resource_credit_bytes=0)
    raw['other_resident'] = cap['optional_reduction'](left,cap['optional_memory'](fleet,first['fleet'],study),q,raw)
    verification=cap['verification168'](fleet['retry9_auxiliary_commitments'])
    # Files installed after the funded V48 operator remain occupied on HOME.
    extra_home = helper['package_home']()
    result=budget169(core,raw,first,operations,paid,verification,extra_home,helper)
    core.need(helper['current_writer'](core,first['provider']) == first['writer'], 'writer changed after post-assembly quote')
    return result
