"""Forecast the dated, conditional 199–200 admission against the passive checkpoint.

The input is a recorded native fit. Projecting a closure removes its live guard
and resident pages. An exclusive post-publication grant separately transfers the
unspent balance. Only a distinct, verified local retirement increases free HOME.
"""
from copy import deepcopy
from itertools import combinations


def subsets(items):
    for count in range(len(items) + 1):
        yield from combinations(sorted(items), count)


def project_population(native, fleet, closed, focused, budget):
    fit = deepcopy(native)
    roster = dict(fleet)
    for epoch in sorted(set(closed) | ({169} if focused else set())):
        key = str(epoch)
        if epoch in (169, 172):
            survivor = fit['survivors'].pop(key)
            guard = survivor['guard']
            fit['required_available_memory_bytes'] += survivor['resident']
            fit['bookings'][key] = dict(cap_bytes=guard['cap'], remaining_bytes=guard['remaining'],
                                        physical_bytes=guard['cap'] - guard['remaining'],
                                        historical_realized_bytes=0, plan=guard['plan'])
            equation = fit['registered_host_equation']
            equation[f'retained_{key}_remaining'] = guard['remaining']
            equation[f'retained_{key}_plan'] = guard['plan']
            if epoch == 169:
                # Local arithmetic marker only. Never persist as a terminal or a grant.
                roster.update(focused169_terminal='projection', focused169_guard_retirement='projection')
                fit['closed_focused169'] = dict(terminal='projection', guard_retirement='projection',
                                                actual_guard_plan=guard['plan'], resource_credit_bytes=0)
            else:
                fit['closed_full172'] = {'projection_only': True}
        else:
            fit['required_available_memory_bytes'] += fit['joined_resident_lower_bounds'].pop(key)
            if epoch == 168:
                fit['active168_guard_floor'] = 0
            else:
                fit['replacements'].pop(key)
    # Recompute only the outer terms touched by closure, using the native
    # rebased inner floor. calculate() independently reproduces both equations.
    g = budget['G']
    base = fit['registered_host_equation']['rebased_floor']
    for epoch, overhead in ((169, 16*g), (172, 128 << 20)):
        guard = native['survivors'][str(epoch)]['guard']
        guard_floor = guard['floor'] if str(epoch) in fit['survivors'] else 0
        base = max(base, guard_floor) + guard['remaining'] + overhead
    fit['original_aggregate_HOME_bytes'] = base + fit['epoch170_extension']['extra_bytes']
    c = fit['candidate136']
    spent = sum(prior - fit['bookings'][str(e)]['remaining_bytes'] for e,prior in budget['PRESTART'].items())
    required = max(fit['original_aggregate_HOME_bytes'] + fit['historical_baseline_deficit_bytes'] - spent,
                   c.get('guard_floor', 0)) + c['remaining']
    fit['complete_required_HOME_bytes'] = max(required, budget['STATIC'], fit['active168_guard_floor'],
        *(row['floor'] for row in fit['replacements'].values()),
        *(row['guard']['floor'] for row in fit['survivors'].values()))
    return fit, roster


def price_rows(native, fleet, ledger, prior169, host_ram, budget):
    epochs = sorted(budget['ALL_CAP'])
    rows = []
    for focused in (False, True):
        for closed in subsets(epochs):
            fit, roster = project_population(native, fleet, closed, focused, budget)
            for transferred in subsets(closed):
                grants = {e:dict(retained_growth_bytes=budget['BOOK'], maximum_transfer_bytes=budget['ALL_CAP'][e])
                          for e in transferred}
                _, row = budget['calculate'](fit, ledger, roster, prior169, grants, closed, host_ram, 64)
                rows.append(dict(row, private169_closed=focused))
    if len(rows) != 486:
        raise ValueError('incomplete transition population')
    return rows


def select_routes(rows, closure_times, grant_times, diagnostic_time, ready, alternatives):
    """Return the first feasible route for each disjoint physical-release case."""
    results = []
    for case in alternatives:
        feasible = []
        for row in rows:
            gaps = row['gaps']
            if any(gaps[k] for k in ('available_memory', 'committed_memory', 'cpu_quota_micros')):
                continue
            if gaps['disk'] > case['net_bytes']:
                continue
            start = max([ready, case['ready_ms'], *[closure_times[e] for e in row['closed']],
                         *[grant_times[e] for e in row['transferred']],
                         *([diagnostic_time] if row['private169_closed'] else [])])
            # At the projected date all prior natural completions must have drained.
            # Keeping fictitious live processes would deduct RSS that is no longer there.
            if row['private169_closed'] != (diagnostic_time <= start):
                continue
            if set(row['closed']) != {e for e,t in closure_times.items() if t <= start}:
                continue
            # Preserve the established 167-to-141 donor when equally early
            # grants use 166, whose historic 173 donor generation has already stopped.
            grants = row['transferred']
            reuse = (int(166 in grants)+int(167 in grants), int(167 in grants), int(172 in grants))
            feasible.append((start, len(grants), reuse, tuple(grants), tuple(row['closed']), row))
        if feasible:
            winner = min(feasible, key=lambda x:x[:-1])
            results.append(dict(case=case, start_ms=winner[0], row=winner[-1], eligible_states=len(feasible)))
        else:
            results.append(dict(case=case, start_ms=None, eligible_states=0))
    dated = [r for r in results if r['start_ms'] is not None and r['case']['dated']]
    if not dated:
        raise ValueError('no dated feasible route in the accepted capacity inputs')
    selected = min(dated, key=lambda r:(r['start_ms'], len(r['case']['sources']), len(r['row']['transferred']),
                                         len(r['row']['closed']), r['case']['net_bytes']))
    return selected, results
