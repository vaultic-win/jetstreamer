"""Verify the paid four-CPU audit ceiling or its exact top-level idle-only extension."""
import json
import os
from pathlib import Path
import stat

GROUP=Path('/sys/fs/cgroup/horizonaudit.slice')
ASSIGNMENT=Path('/var/lib/jetstreamer/horizon_runtime_data/public-stream-observer-continuity-20261120-v1/SHARED_CPU_ASSIGNMENT.json')
POLICY=dict(schema='public-ready-idle-cpu-assignment-v1',slice='horizonaudit.slice',previous_cpu_quota='4s',
            cpu_quota='12s',paid_cpu_quota_micros=4_000_000,additional_memory_bytes=0,
            required_cpu_idle=1,shared_memory_high_bytes=20<<30,shared_memory_max_bytes=24<<30,
            shared_swap_max_bytes=0,shared_tasks_max=512)

def read_assignment(path):
    if not path.exists(): return None
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        info=os.fstat(stream.fileno())
        if not (stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==0
                and info.st_mode&0o022==0 and info.st_size<=8192 and path.resolve()==path):
            raise ValueError('untrusted public CPU assignment')
        return json.loads(stream.read(8193))

def profile(group=GROUP,assignment=ASSIGNMENT):
    required={'memory.high':str(20<<30),'memory.max':str(24<<30),'memory.swap.max':'0','pids.max':'512'}
    if any((group/name).read_text().strip()!=v for name,v in required.items()):
        raise ValueError('changed audit memory, swap or task ceiling')
    quota=(group/'cpu.max').read_text().split();idle=(group/'cpu.idle').read_text().strip()
    if quota==['400000','100000'] and idle in ('0','1'):
        return 'paid-four'
    if quota==['1200000','100000'] and idle=='1' and read_assignment(assignment)==POLICY:
        return 'idle-twelve'
    raise ValueError('unexpected public audit CPU entitlement')
