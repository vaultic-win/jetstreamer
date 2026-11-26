"""Adopt native publication receipts under the already-locked status cadence."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from evidence import BASE, bound, checked, digest, durable, ensure_dir, need, syncdir
import status


ROOT = Path('/home/sol/.jetstreamer-private/horizon-completed-deliveries-20261126-v1')
TOOL = Path(__file__).resolve().with_name('jetstreamer-r2-ready-status')
RECEIPTS = {
    145: (BASE / 'epoch145-parallel-full-verification-20261126-v1/delivery-bind-v1/receipts',
          105610995833, 'df194137df5de51ae628160854cabafc9e180b4e7058cab3fba6aac4621a7b4d'),
    199: (BASE / 'epoch199-retained-full-verification-20261126-v1/publication-receipts',
          101011065678, '527810d1cf57ef410ba72e46c678cbd9bec196c63e2b36c177d4edb4f1ceca18'),
}


def selected_tool(seal):
    member, = (row for row in seal['members'] if row['name'] == TOOL.name)
    with TOOL.open('rb') as source:
        metadata = os.fstat(source.fileno())
        need(metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o555
             and metadata.st_size == member['bytes'] and member['mode'] == '0555'
             and hashlib.file_digest(source, 'sha256').hexdigest() == member['sha256'],
             'different native ready status deletion tool')
    return member['sha256']


def terminal(unit, invocation):
    manager = subprocess.check_output([
        '/usr/bin/systemctl', 'show', unit, '-p', 'ActiveState,InvocationID,MainPID,ControlPID,Job',
    ], text=True, timeout=10)
    state = dict(line.split('=', 1) for line in manager.splitlines())
    if state['ActiveState'] != 'inactive':
        return None
    need(state['InvocationID'] in ('', invocation) and not state['Job']
         and state['MainPID'] == state['ControlPID'] == '0', 'publisher still has an owner')
    result = subprocess.check_output([
        '/usr/bin/journalctl', '-b', '--no-pager', '-o', 'json', '_PID=1', '_UID=0',
        f'UNIT={unit}', f'INVOCATION_ID={invocation}',
        'MESSAGE_ID=7ad2d189f7e94e70a38c781354912448',
    ], text=True, timeout=10)
    event, = map(json.loads, result.splitlines())
    need(event['UNIT'] == unit and event['INVOCATION_ID'] == invocation,
         'publisher terminal journal names another invocation')
    return dict(unit=unit, invocation_id=invocation, journal_cursor=event['__CURSOR'])


def raw_receipt(path, payload):
    if not path.exists():
        with tempfile.NamedTemporaryFile(dir=path.parent) as stage:
            stage.write(payload)
            stage.flush()
            os.fsync(stage.fileno())
            os.link(stage.name, path)
        syncdir(path.parent)
    ref = bound(path)
    need(ref['sha256'] == digest(payload), 'different saved authenticated status bytes')
    return ref


def reconcile(c, store, snapshot, refs, publishers, tool_sha, external_event):
    statuses, ready, archives = snapshot
    completed = dict(c.fleet.get('retained_publication_completions', {}))
    for epoch in sorted(ready & publishers.keys()):
        key = str(epoch)
        directory, length, archive_sha = RECEIPTS[epoch]
        if key in completed:
            result = checked(completed[key])
            need(epoch not in statuses and archives.get(epoch) == (result['etag'], length)
                 and result['archive_sha256'] == archive_sha, 'accepted ready pair or status changed')
            continue
        archive = directory / f'epoch-{epoch}.r2.json'
        if not archive.exists():
            continue
        owner = terminal(*publishers[epoch])
        if owner is None:
            continue
        archive_ref = bound(archive)
        receipt = checked(archive_ref)
        need(receipt['schema'] == 'jetstreamer-horizon-r2-receipt-v1' and receipt['epoch'] == epoch
             and receipt['bucket'] == status.BUCKET and receipt['archive_sha256'] == archive_sha
             and receipt['archive_length'] == length and receipt['remote_sha256_readback']
             and receipt['current_reader_playback']
             and archives.get(epoch) == (receipt['archive_etag'], length), 'different native publisher receipt')
        ensure_dir(ROOT)
        work = ROOT / key
        ensure_dir(work)
        plan_path = work / 'plan.json'
        deletion = work / f'epoch-{epoch}.fallback-ready-status-deletion.json'
        if not plan_path.exists():
            need(epoch in statuses and key in refs, 'no status receipt for ready publication')
            etag, payload = store.get(epoch)
            previous = refs[key]
            prior = checked(previous)
            if prior['after_etag'] != etag or prior['after_sha256'] != digest(payload):
                previous, prior = external_event(epoch, previous, etag, payload)
            need(prior['epoch'] == epoch and prior['current_repair_owner'] == '/root'
                 and prior['after_status']['jet_size_bytes'] == length
                 and prior['authenticated_readback'] and prior['after_etag'] == etag
                 and prior['after_sha256'] == digest(payload) and status.body(prior['after_status']) == payload,
                 'status is outside the exact publisher handoff')
            raw = raw_receipt(work / f'status-{digest(payload)}.json', payload)
            durable(plan_path, dict(schema='jetstreamer-r2-anza-cadence-ready-status-plan-v1',
                bucket=status.BUCKET, epoch=epoch, status_delete_authorized=True,
                archive_or_sidecar_mutations=False, fallback_completion=previous,
                raw_status=raw, archive_receipt=archive_ref, deletion_receipt=str(deletion),
                deletion_intent=str(work / f'epoch-{epoch}.fallback-ready-status-delete-intent.json')))
        plan = bound(plan_path)
        need(checked(plan)['archive_receipt'] == archive_ref, 'publication changed after cleanup plan')
        argv = [str(TOOL), 'status-delete-fallback-ready', plan['path'], '--plan-sha256',
                plan['sha256'], '--self-sha256', tool_sha]
        probe = json.loads(subprocess.check_output([*argv, '--check-only'], timeout=60))
        need(probe['epoch'] == epoch and probe['authenticated_ready_pair'] and not probe['remote_mutations'],
             'native cleanup preflight did not authenticate the ready pair')
        subprocess.run(argv, check=True, timeout=60, stdout=subprocess.PIPE)
        result = checked(bound(deletion))
        need(result['binding']['archive_receipt'] == archive_ref and result['authenticated_ready_pair_before']
             and result['authenticated_ready_pair_after'] and result['authenticated_status_absent_after'],
             'native cleanup did not authenticate ready pair and status absence')
        inventory = json.loads(subprocess.check_output([
            str(TOOL), 'inventory', str(work), '--epochs', f'{epoch}-{epoch}',
        ], timeout=30))
        row, = inventory['entries']
        need(inventory['schema'] == 'jetstreamer-horizon-r2-inventory-v1' and not inventory['anomalies']
             and row['epoch'] == epoch and row['state'] == 'ready-pair'
             and row['archive_length'] == length and row['archive_etag'] == receipt['archive_etag']
             and row['sidecar_sha256'] == archive_sha, 'native inventory differs from the ready pair')
        done = work / 'completion.json'
        durable(done, dict(epoch=epoch, publisher=owner, archive=archive_ref,
            archive_sha256=archive_sha, etag=receipt['archive_etag'], length=length,
            deletion=bound(deletion), inventory_entry=row))
        completed[key] = bound(done)
    need(set(map(int, completed)) <= ready, 'accepted ready sidecar disappeared')
    return completed
