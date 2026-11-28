"""Account only unreached HOME-backed allocations authorized for the ready queue."""
from pathlib import Path
import stat

from evidence import BASE, bound, checked, need

HOME_DEVICE = Path('/home/sol').stat().st_dev

def allocated(paths, seen, top_level_only=False):
    """Count allocated blocks once, on the HOME filesystem, without following links."""
    total = 0
    pending = [(path,0) for path in paths]
    while pending:
        path,depth = pending.pop()
        try:
            info = path.lstat()
        except FileNotFoundError:
            # A rotating file can disappear during the walk. Omitting it increases
            # remaining headroom and therefore keeps the HOME projection conservative.
            continue
        if top_level_only and depth and stat.S_ISDIR(info.st_mode):
            continue
        need(info.st_dev == HOME_DEVICE, 'unexpected filesystem inside HOME allocation '+str(path))
        inode = (info.st_dev, info.st_ino)
        if inode in seen:
            continue
        seen.add(inode)
        total += info.st_blocks * 512
        if stat.S_ISDIR(info.st_mode):
            try:
                pending.extend((child,depth+1) for child in path.iterdir())
            except FileNotFoundError:
                continue
    return total

def forecast(groups):
    marked = []
    first_seen, second_seen = set(), set()
    rows = []
    for group in groups:
        cap = group['maximum_host_allocation_bytes']
        need(type(cap) is int and cap >= 0, 'invalid ready output cap')
        paths = [Path(name) for name in group['host_paths']]
        need(paths and all(p.is_absolute() and p.resolve(strict=False)==p for p in paths), 'noncanonical budget root')
        for path in paths:
            need(not any(path == other or path in other.parents or other in path.parents for other in marked),
                 'overlapping host-side allocation roots')
            marked.append(path)
        top_level = group.get('measurement','tree')=='top_level_files'
        need(group.get('measurement','tree') in ('tree','top_level_files','files'), 'unknown output measurement')
        for path in paths:
            if path.exists():
                need(group.get('measurement')!='files' or path.is_file(), 'unexpected directory in host file list')
            else:
                need(group.get('measurement')=='files' and path.parent.stat().st_dev==HOME_DEVICE,
                     'ready accounting root disappeared')
        first = allocated(paths, first_seen, top_level)
        second = allocated(paths, second_seen, top_level)
        used = min(first, second)
        rows.append(dict(name=group['name'],paths=[str(p) for p in paths],cap_bytes=cap,
                         allocated_bytes_lower_observation=used,physical_observations=[first,second],observed_over_cap_bytes=max(0,max(first,second)-cap),
                         remaining_growth_bytes=max(0,cap-used)))
    return rows

def accounting(epoch, policy_ref=None):
    if policy_ref is None:
        gate = BASE/'ready-audit-growth-20261121-v1/REGISTERED.json'
        if not gate.exists():
            return None
        policy_ref = checked(bound(gate))['operator_basis']
    policy = checked(policy_ref)
    checked(policy['operator_budget'])
    cap = policy['maximum_total_host_allocation_bytes']
    need(type(cap) is int and 0<cap<=256<<20 and sum(v['maximum_host_allocation_bytes'] for v in policy['groups'])==cap,
         'ready output cap differs from the qualified budget')
    rows = forecast(policy['groups'])
    remaining = sum(row['remaining_growth_bytes'] for row in rows)
    return dict(schema='ready-public-queue-home-growth-v1',epoch=epoch,archive_bytes=None,resident_archive_bytes=0,
                remaining_archive_growth_bytes=0,remaining_cargo_growth_allowance_bytes=0,
                remaining_working_growth_bytes=remaining,remaining_DATA_growth_bytes=remaining,
                largest_archive_booked=False,resource_credit_bytes=0,promise_ending_bytes=0,
                output_budget=policy_ref,maximum_host_allocation_bytes=cap,host_allocation_groups=rows,
                historical_deleted_bytes_added_to_freespace=0)

def reconcile(fleet, audit, capacity, current_audit):
    """Keep the frozen 145 price input separate from the actual fleet disk charge."""
    storage = capacity['audit_storage']
    if storage.get('schema')!='ready-public-queue-home-growth-v1':
        return
    retirement = checked(audit['chronological_retirement'])
    old = checked(retirement['prior_capacity'])['audit_storage']
    need(old['remaining_DATA_growth_bytes']==18<<30 and storage['remaining_DATA_growth_bytes']<=256<<20,
         'unrecognized historical-to-ready growth transition')
    # V14/V15 natively require the old exact value when reconstructing the historical
    # epoch 168 reservation baseline. This input is never included in the current sum.
    previous = fleet['continuing_audit_obligation']
    previous['current_storage'] = dict(old, pricing_basis_only=True, retired=True,
        source=retirement['prior_capacity'], included_in_current_aggregate=False)
    previous['current_observation'] = checked(retirement['head'])['continuing_audit_obligation']['current_observation']
    previous['current_storage_role'] = 'Frozen 18 GiB input for legacy native price reproduction only'
    previous['active_storage_field'] = 'active_ready_range_audit_obligation.current_storage'
    fleet['audit_conservative_available_DATA_bytes'] = fleet['same_sample_conservative_free_DATA_bytes']
    fleet['active_ready_range_audit_obligation'] = dict(
        scope=[101,300],method='public HTTP slot-range playback',current_storage=storage,
        current_observation=current_audit,maximum_output_allocation_bytes=storage['maximum_host_allocation_bytes'],
        archive_staging_bytes=0,cargo_growth_allowance_bytes=0,chronological_retirement=audit['chronological_retirement'],
        additional_cpu_quota_micros=previous['additional_cpu_quota_micros'],
        additional_memory_bytes=previous['additional_memory_bytes'],tasks_max=previous['tasks_max'])
