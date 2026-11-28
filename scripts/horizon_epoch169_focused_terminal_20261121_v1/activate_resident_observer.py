"""Switch only the scheduled observer command and sleeping status consumer to the qualified build."""
import datetime as dt
import json
import os
from pathlib import Path
import select
import subprocess as sp
import sys
import time

R=Path('/var/lib/jetstreamer/horizon_runtime_data')
ROOT=R/'resident-observer-20261121-v1'
OLD=R/'host-census-clock-recovery-20261121-v1/cadence-tools'
mode = sys.argv[1] if len(sys.argv)>1 else ''
DEPLOYMENTS = {
    '--private140-status': ('prefix140-cadence-20261122-v1', 'prefix140-status-cadence-20261122-v1',
                            'zzzzzzzz-private140-status.conf', 'qualified-private140-status-cadence-v1'),
    '--prefix140-cadence': ('ready-idle-cpu-20261121-v1', 'prefix140-cadence-20261122-v1',
                            'zzzzzzz-prefix140-cadence.conf', 'qualified-prefix140-metered-cadence-v1'),
    '--ready-audit-retirement': ('resident-observer-20261121-v1', 'ready-audit-cadence-20261121-v1',
                                 'zzzz-ready-audit-retirement.conf', 'qualified-ready-audit-handoff-v1'),
    '--ready-audit-idle-clock': ('ready-audit-growth-20261121-v1', 'ready-idle-cpu-20261121-v1',
                                'zzzzzz-ready-idle-clock.conf', 'qualified-ready-idle-clock-handoff-v1'),
    '--ready-audit-growth': ('ready-audit-cadence-20261121-v1', 'ready-audit-growth-20261121-v1',
                             'zzzzz-ready-audit-growth.conf', 'qualified-ready-audit-growth-handoff-v1'),
}
drop_name = 'zzz-qualified-resident-census.conf'
schema = 'qualified-native-rss-clock-handoff-v1'
if mode in DEPLOYMENTS:
    sys.argv.pop(1)
    previous, successor, drop_name, schema = DEPLOYMENTS[mode]
    OLD = R / previous / 'cadence-tools'
    ROOT = R / successor
NEW=ROOT/'cadence-tools'
UNIT='horizon-archive-status-cadence-after172-20261120-v1.service'
PAID='horizon-holding-export145-20261121-v1.service'
sys.path.insert(0,str(OLD))
from evidence import bound, checked, durable, utc


def ctl(*args):
    return sp.check_output(['systemctl',*args],text=True,timeout=40).strip()


def show(unit,fields):
    return dict(l.split('=',1) for l in ctl('show',unit,'-p',','.join(fields)).splitlines())


def waiting():
    return [l.split()[0] for l in ctl('list-units','--type=timer','--state=waiting','--plain','--no-legend','horizon-observer-*.timer').splitlines()]


def current(package):
    state=show(UNIT,['ActiveState','SubState','Job','MainPID','InvocationID'])
    p=Path('/proc')/state['MainPID']
    assert state['ActiveState']=='active' and state['SubState']=='running' and not state['Job']
    assert (p/'fd/255').samefile(package/'consume') and (p/'fd/9').samefile(R/'stable-cadence-controller-20261120-v1/consumer.lock')
    assert ' FLOCK ' in (p/'fdinfo/9').read_text()
    children=(p/'task'/p.name/'children').read_text().split()
    assert children and all((Path('/proc')/child/'exe').resolve()==Path('/usr/bin/sleep') for child in children)
    return state


def fresh_paid_boundary():
    """Wait for an actual periodic full-fit child in the paid guard to finish.

    Its successful full-price refresh is cached by the active semantic verifier.
    PID1 already has both replacement commands loaded when this wait begins.
    """
    m=show(PAID,['ActiveState','MainPID','InvocationID'])
    if m['ActiveState'] in ('inactive','failed') and m['MainPID']=='0':
        return dict(manager=m,stage='stopped')
    assert m['ActiveState']=='active' and m['InvocationID']
    parent=Path('/proc')/m['MainPID']
    version,provider=('v5e','v16') if mode in ('--prefix140-cadence','--private140-status') else ('v5d','v14')
    assert (parent/'exe').resolve()==R/f'epoch145-semantic-continuity-20261121-v1/tools-{version}/export145'
    end=time.monotonic()+95
    while time.monotonic()<end:
        for row in (parent/'task'/parent.name/'children').read_text().split():
            child=Path('/proc')/row
            try:
                cmd=(child/'cmdline').read_bytes().split(b'\0')
                if str(R/f'incident-replay-fit-20261121-v1/tools-{provider}/post-stop-fit').encode() not in cmd:continue
                fd=os.pidfd_open(int(row))
            except ProcessLookupError:continue
            except FileNotFoundError:continue
            try:
                p=select.poll();p.register(fd,select.POLLIN)
                assert p.poll(60000)
            finally:os.close(fd)
            assert (parent/'exe').exists()
            prices=sp.run(['pgrep','-f','^/usr/bin/python3 -IB /var/lib/jetstreamer/horizon_runtime_data/[^ ]+/post-stop-fit '],stdout=sp.PIPE,check=False)
            if prices.returncode==0:
                continue
            assert prices.returncode==1
            return dict(manager=m,refresh_pid=int(row),refresh_exited_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        time.sleep(.05)
    raise ValueError('active paid verifier did not produce a full-fit handoff boundary')


def main():
    assert os.geteuid()==0 and __debug__ and sys.flags.isolated
    qp,expected,head_path=sys.argv[1:]
    qref=bound(Path(qp));assert qref['sha256']==expected
    q=checked(qref);assert checked(q['package_seal'])['destination']==str(NEW)
    head=bound(Path(head_path));f=checked(head)
    if mode=='--ready-audit-idle-clock':
        from cycle import load_fleet
        f,cfg,_=load_fleet(head)
    else:
        cfg=checked(f['sole_next_observer'])
    assert f['all_active_status_reports_authenticated_readback'] and f['authenticated_status_count']==19
    for pkg in (OLD,NEW):
        sp.run(['sha256sum','--check','--status','SHA256SUMS'],cwd=pkg,check=True)
        meta=json.loads(sp.check_output(['/usr/bin/python3','-B',pkg/'describe.py',head['path'],head['sha256']]))
        assert meta['sample']==cfg['output'] and meta['due']==cfg['not_before_utc'] and meta['timer']==f['sole_next_timer']
    timer=meta['timer'];service=timer.removesuffix('.timer')+'.service';before=current(OLD)
    keys=['ActiveState','SubState','InvocationID','TimersCalendar','NextElapseUSecRealtime']
    initial_timer=show(timer,keys)
    def window():
        assert waiting()==[timer] and not Path(meta['sample']).exists() and initial_timer==show(timer,keys)
        assert (utc(meta['due'])-dt.datetime.now(dt.timezone.utc)).total_seconds()>120
        o=show(service,['ActiveState','Job','MainPID'])
        assert o['ActiveState']=='inactive' and not o['Job'] and o['MainPID']=='0'
    window()
    commands={service:f"/usr/bin/python3 -B {NEW}/guard_stops.py {f['sole_next_observer']['path']}",
              UNIT:f"{NEW}/consume {head['path']} {head['sha256']}"}
    changes={}
    try:
        for u,command in commands.items():
            folder=Path('/run/systemd/system')/(u+'.d');folder.mkdir(mode=0o755,exist_ok=True)
            p=folder/drop_name
            with p.open('x') as out:
                os.fchmod(out.fileno(),0o644)
                if u==service:out.write('[Unit]\nDescription='+command+'\n')
                out.write('[Service]\nExecStart=\nExecStart='+command+'\n');out.flush();os.fsync(out.fileno())
            changes[p]=bound(p)
        ctl('daemon-reload');window()
        assert before==current(OLD)
        assert show(service,['Description'])['Description']==commands[service]
        assert all(argv in show(u,['ExecStart'])['ExecStart'] for u,argv in commands.items())
        boundary=fresh_paid_boundary()
        ctl('restart',UNIT)
        for _ in range(80):
            try:
                after=current(NEW)
                if after['InvocationID']!=before['InvocationID']:break
            except (AssertionError,FileNotFoundError,ProcessLookupError):pass
            time.sleep(.1)
        else:raise RuntimeError('current cadence did not reacquire original lock')
        window()
    except BaseException:
        for p,ref in changes.items():
            assert bound(p)==ref
            p.unlink()
        ctl('daemon-reload')
        try:current(OLD)
        except (AssertionError,FileNotFoundError,ProcessLookupError):ctl('restart',UNIT)
        raise
    receipt=ROOT/'ACTIVE.json'
    durable(receipt,dict(schema=schema,qualification=qref,head=head,
                         before=before,after=after,unchanged_timer=initial_timer,paid_boundary=boundary,
                         native_config=f['sole_next_observer'],dropins=list(changes.values()),new_observations=0))
    print(json.dumps(bound(receipt)))

if __name__=='__main__':
    main()
