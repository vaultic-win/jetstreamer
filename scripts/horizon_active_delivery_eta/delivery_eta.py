"""Guarded local and R2 delivery work remaining after a measured replay."""
from statistics import median_low

from evidence import checked, need

HOUR = 3_600_000
LEGACY_TAIL = 12 * HOUR
BASIS = {
    'sha256': '5902c26ac176169f6fde4d4dd56571653f2392b537a96375b3836da8334a10f7',
    'path': '/home/sol/.jetstreamer-private/r2-status-receipts/event-145-funded-export-after041959-20261121-v1/MODEL.json',
}
ASSEMBLY = {
    'path': '/home/sol/.jetstreamer-private/r2-status-receipts/event-141-cold-replay-after044959-20261121-v1/MODEL.json',
    'sha256': 'b0785501e36dba2f9cc00ee1f1ca46260512f6de6428b4613c19caf06a48edc5',
}
INDEPENDENT = ('assembly_close_import', 'independent_full_verification', 'current_plugin_verification', 'required_boundary_checks')
UPLOADER = ('uploader_repeated_current_full_verification', 'uploader_repeated_current_local_plugin',
            'sequential_multipart_upload', 'authenticated_whole_object_readback_sha256', 'final_source_branch_check_and_conditional_sidecar')
SCHEMA = 'horizon-current-reader-delivery-tail-v1'
DESCRIPTION = 'Measured replay with a 10 percent allowance, then serial local acceptance, uploader checks, authenticated readback and complete pinned public playback.'

def estimate(c, epoch, size, committed=False):
    evidence = checked(BASIS)
    rates = evidence['forecast_inputs']['public_playback_samples']
    total_bytes = total_seconds = 0
    for sample in rates:
        r = checked(sample['receipt'])
        need(r['status']=='passed' and r['epoch_plugin_completed'] and r['epoch']==sample['epoch'] and
             r['object']['bytes']==sample['bytes'] and r['finished_at']-r['started_at']==sample['seconds']>0,
             'invalid public playback basis')
        total_bytes += sample['bytes']
        total_seconds += sample['seconds']
    inventory = c.prior['inventory']
    entries = checked(inventory, root=False)['entries']
    neighbors = sorted((r for r in entries if r['state']=='ready-pair'), key=lambda r:(abs(r['epoch']-epoch),r['epoch']))[:5]
    need(len(neighbors)==5 and all(r['archive_length']>0 for r in neighbors) and size>=0,'missing archive size basis')
    lengths = {str(r['epoch']):r['archive_length'] for r in neighbors}
    projected = size if committed else max(size,median_low(lengths.values()))
    need(projected>0,'empty delivery size')
    independent = checked(ASSEMBLY)['phase_milliseconds']
    parts = {k:independent[k] for k in INDEPENDENT if not (committed and k=='assembly_close_import')}
    parts.update({k:evidence['phase_milliseconds'][k] for k in UPLOADER})
    need(sum(parts.values())==(17 if committed else 19)*HOUR,'reference delivery stages changed')
    parts['pinned_complete_public_playback'] = (projected*1250*total_seconds+total_bytes-1)//total_bytes
    return dict(schema=SCHEMA,epoch=epoch,archive_basis='committed local archive' if committed else 'nearby median or larger observed local archive',
                observed_archive_bytes=size,projected_archive_bytes=projected,comparable_ready_archive_bytes=lengths,
                inventory=inventory,reference_local_stages=ASSEMBLY,reference_uploader_and_public_rate=BASIS,
                measured_public_bytes=total_bytes,measured_public_seconds=total_seconds,public_contingency_percent=25,
                phase_milliseconds=parts,total_millis=sum(parts.values()))

def adjusted_remaining(old, prior, quote):
    previous = (prior or {}).get('delivery_forecast')
    if previous is None:
        previous_tail = LEGACY_TAIL
    else:
        need(previous['schema']==SCHEMA and previous['epoch']==old['epoch'] and
             previous['total_millis']==sum(previous['phase_milliseconds'].values()),'invalid prior delivery model')
        previous_tail = previous['total_millis']
    return old['estimated_remaining_millis'] + quote['total_millis'] - previous_tail

def prepare(c, epoch, size, committed=False):
    result = estimate(c,epoch,size,committed)
    if not hasattr(c,'delivery_forecasts'):
        c.delivery_forecasts = {}
    c.delivery_forecasts[epoch] = result
    return result
