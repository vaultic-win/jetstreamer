"""Check the existing epoch 257 bootstrap against the sealed 266 workspace and price the return of 250/251."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).parent))
from funding import CG, D, M, V, bound, partition, price, ref
from owners import props
import funds


def pin(path, expected):
    r = ref(path)
    assert r['sha256'] == expected, path
    return r


def rotation(fit, remaining, version):
    timing = pin(D/'horizon250-measured-rotation-price-v206-a1/assessment.json',
                 '2e7df8f8b61b63325d85d817aec365c0fc17fa0fedb78f83ca09cc348b87d65b')
    old = bound(timing)
    sizes, deadlines = {}, {}
    for epoch in (250, 251):
        handoff = bound(fit['planning'])['possible_holding_relief'][str(epoch)]['handoff']
        archive = bound(handoff)['source']['archive']
        transfer = old['transfers'][str(epoch)]
        assert archive == transfer['source'] == bound(transfer['booking'])['original']
        ident = archive['identity']
        st = Path(archive['path']).lstat()
        assert (st.st_dev, st.st_ino, st.st_size, st.st_nlink, st.st_blocks * 512 >= st.st_size) == (
            ident['device'], ident['inode'], ident['length'], 1, True)
        sizes[epoch] = st.st_size
        status = ref(D/f'horizon-resumed-campaign-status-v{version}-a1/{epoch-1}/completion.json')
        receipt = bound(status)
        row = bound(receipt['readback'])
        assert receipt['authenticated_exact_byte_readback'] and row['epoch'] == epoch-1
        needed = datetime.fromisoformat(row['sampled_at_utc']) + timedelta(milliseconds=row['estimated_remaining_millis'])
        return_budget = 4 * transfer['refill_and_return_seconds']
        deadlines[epoch] = dict(predecessor_status=status, source_needed_forecast=needed.isoformat(),
            latest_modeled_refill_start=(needed - timedelta(seconds=return_budget)).isoformat(),
            return_seconds_budget=return_budget, handoff=handoff)
    both = remaining + sum(sizes.values())
    return dict(timing=timing, deadlines=deadlines, no_retirements=remaining,
                after_either_retirement={e: remaining + n for e, n in sizes.items()},
                after_both_retirements=both,
                while_restoring_one={e: both-n for e, n in sizes.items()},
                while_restoring_both=remaining, credited_holding_bytes=0)


def check(attempt):
    assert os.geteuid() == 0 and __debug__
    name = 'horizon257-after-closed266-v215-' + attempt
    dest = D / name
    release = pin(V/'horizon266-v210-closed-growth-v215/release.json',
                  'c2112c2cf4d97797dbf9d1d2c347c2e00c954c14eedba5572b621aa22e7588af')
    old_options = pin(D/'horizon-replacement-fit-v193-a1/assessment.json',
                      '4cd1e78fa92846ef0b48efbfd81cf55367b1371dc0679725e61d5269ab463e74')
    harness = pin(V/'horizon257-native-input-limited-20261120-v1/horizon257-native-input',
                  'b8f52e2de7bf4f6232ea66137bb148bb6fb5b3342ce354379f4c237c70c39fce')
    original = pin(D/'horizon257-post-first-close-v156-v1/completion.json',
                   'a1b701036ea7d63c853e3c9014639e8c53bd38c208e830032bab8f84d86178ef')
    with partition.take():
        fit = price(256*M, 4*M, 2*M)
        closed = bound(release)
        extent = fit['extent']
        assert closed['terminal'] == fit['closed266'] and closed['original'] == fit['issued']
        assert extent['identity'] == closed['current']['identity']
        assert extent['first']['blocks'] == extent['second']['blocks'] == closed['retained_backing_bytes']
        assert Path('/sys/block/loop18/ro').read_text().strip() == '1'
        floor = fit['protected_floor'] - extent['remaining'] + fit['disk'] + closed['qa_bytes']
        # A publication reservation carved out of this closed volume still needs its disk after the original growth is removed.
        if fit.get('closed265_delivery'):
            floor += bound(fit['closed265_delivery'])['disk']
        available = extent['free'] - floor
        option = bound(old_options)['candidate_options']['257']
        required_disk = option['disk']['bytes']
        required_ram = option['producer'] + option['guard_and_controller']
        assert (required_disk, required_ram) == (256000000000, 121342177280)
        assert bound(bound(original)['terminal'])['kernel_drained']
        production = 'horizon-257-native-input-20261120-v1.service'
        state = props(production, ['ActiveState','Job','MainPID'])
        assert state['ActiveState'] in ('failed','inactive') and not state['Job'] and state['MainPID']=='0' and not (CG/production).exists()
        version = Path(fit['fleet']['path']).parent.name.split('-v')[1].split('-')[0]
        full_disk = closed['full_workspace_required']
        phases = rotation(fit, available-full_disk, version)
        # Validate the sealed startup packet through the exact worker harness. This invocation
        # only reads input identities and rehashes the worker; it cannot restore or execute entries.
        unit = name + '-inputs.service'
        cmd = [harness['path'], '--validate-inputs']
        properties = ['Type=exec','User=ubuntu','Group=ubuntu','CPUQuota=100%','AllowedCPUs=8',
            'MemoryMax=128M','MemorySwapMax=0','TasksMax=8','RuntimeMaxSec=60','Restart=no',
            'NoNewPrivileges=yes','PrivateNetwork=yes','PrivateDevices=yes','ProtectSystem=strict',
            'ProtectHome=read-only','ReadOnlyPaths=/','CapabilityBoundingSet=']
        dest.mkdir(mode=0o700)
        ledger = D/('horizon-bounded265-residual-'+name)
        ledger.mkdir(mode=0o700)
        assigned = funds.put(ledger/'assignment.json',fit)
        book = funds.put(dest/'booking.json',dict(assignment=assigned,original=original,release=release,
            prior_candidate=old_options,argv=cmd,image=harness,properties=properties,unit=unit))
        p = subprocess.run(['systemd-run','--quiet','--pipe','--wait','--unit='+unit,
            *['--property='+v for v in properties],*cmd], capture_output=True, timeout=75)
        result = funds.put(dest/'process.json',dict(exit=p.returncode,stdout=p.stdout.decode(),stderr=p.stderr.decode()))
        assert p.returncode==0,p.stderr
        report = json.loads(p.stdout)
        assert report['bootstrap_slot']==111022755 and report['measured_identities_accepted'] and not report['worker_started']
        events = [json.loads(v) for v in subprocess.check_output(['journalctl','-b','-o','json','--no-pager','_PID=1','_UID=0','UNIT='+unit]).splitlines()]
        assert len([v for v in events if v.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' and v.get('UNIT_RESULT','success')=='success'])==1 and not (CG/unit).exists()
        print(funds.put(dest/'assessment.json',dict(booking=book,process=result,manager=funds.put(dest/'pid1.json',events),
            as_of_utc=datetime.now(timezone.utc).isoformat(),available_disk=available,protected_floor=floor,
            available_serial_ram=fit['serialized_phase_margin'],candidate_disk=required_disk,candidate_ram=required_ram,
            candidate_disk_margin=available-required_disk,candidate_memory_margin=fit['serialized_phase_margin']-required_ram,
            full266_rotation=phases,full266_while_257_reserved=phases['no_retirements']-required_disk,
            epoch257_cold_started=False,capacity_reassigned=False)),flush=True)


if __name__ == '__main__':
    check(sys.argv[1])
