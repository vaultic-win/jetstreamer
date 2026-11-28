"""Read the native ready queue workers across its original and parallel systemd units."""
from pathlib import Path
import re
from evidence import BASE, checked, need

READY = BASE/'ready-range-audit-20261121-v1'
CG = Path('/sys/fs/cgroup/horizonaudit.slice')
UNITS = ('horizon-r2-fast-ranges-256-20261121-v1.service',
         'horizon-r2-ready-ranges-101-300-20261121-v1.service',
         'horizon-r2-ready-parallel-regions-20261121-v1.service')

def native_jobs(scope_ref):
    ranges=checked(scope_ref)['eligible_ranges']; jobs=[]
    for unit in UNITS:
        group=CG/unit
        try: pids=(group/'cgroup.procs').read_text().split()
        except FileNotFoundError: continue
        for pid in pids:
            proc=Path('/proc')/pid
            try:
                exe=(proc/'exe').readlink()
                if exe.name!='horizon_pipeline':continue
                st=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
                argv=[v.decode() for v in (proc/'cmdline').read_bytes().split(b'\0') if v]
                actual=(proc/'cgroup').read_text().strip()
                same=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]==st
            except (FileNotFoundError,ProcessLookupError):continue
            if not same or actual!='0::/horizonaudit.slice/'+unit:continue
            need(len(argv)>3 and Path(argv[0])==exe and re.fullmatch(r'\d+:\d+',argv[1]),'unknown ready worker identity')
            region=list(map(int,argv[1].split(':')))
            need(region in ranges and all(flag in argv for flag in ('--verify-only','--slot-ranges','--archive-inventory','--threads')),
                 'worker outside strict ready scope')
            jobs.append(dict(unit=unit,pid=int(pid),start_ticks=int(st),range=region,reader=str(exe),
                             partitions=int(argv[argv.index('--threads')+1]),max_active_partitions=(
                                 int(argv[argv.index('--max-active-partitions')+1]) if '--max-active-partitions' in argv else None)))
    return sorted(jobs,key=lambda row:row['range'])
