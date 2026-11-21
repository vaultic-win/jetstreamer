"""Repeat a full native fit only after a positively observed controller-owned probe."""
import json
import os
import subprocess
import time
from pathlib import Path

UNIT = 'horizon-holding-export145-20261121-v1.service'
GROUP = '0::/system.slice/' + UNIT
MEMBERS = Path('/sys/fs/cgroup/system.slice') / UNIT / 'cgroup.procs'
IMAGE = Path('/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5c/export145')


def argv(proc):
    return [os.fsdecode(piece) for piece in (proc / 'cmdline').read_bytes().split(b'\0') if piece]


def self_probe(provider, fleet, digest, image_digest):
    # This observation can justify waiting. Only the unmodified full provider
    # can authenticate the final actor set, both lease sets and resource fit.
    if not MEMBERS.exists():
        return None
    for pid in MEMBERS.read_text().split():
        p = Path('/proc') / pid
        try:
            args = argv(p)
            if len(args) != 6 or args[:4] != ['/usr/bin/python3','-IB',str(provider),'145']:
                continue
            actual_fleet = Path(args[4])
            if actual_fleet.parent.parent != provider.parent.parent.parent or actual_fleet.name != 'ROOT_COMPLETE_OPERATIONAL_FLEET.json' or actual_fleet.resolve() != actual_fleet or __import__('hashlib').sha256(actual_fleet.read_bytes()).hexdigest() != args[5]:
                continue
            if not os.path.samefile(p / 'exe', '/usr/bin/python3') or (p / 'cgroup').read_text().strip() != GROUP:
                continue
            procstat = (p / 'stat').read_text().rsplit(')', 1)[1].split()
            parent = Path('/proc') / procstat[1]
            args = argv(parent)
            if (len(args) != 5 or args[:2] != [str(IMAGE), 'recover-full-output'] or args[4] != image_digest
                    or not os.path.samefile(parent / 'exe', IMAGE) or (parent / 'cgroup').read_text().strip() != GROUP):
                continue
            return int(pid), int(procstat[19])
        except (FileNotFoundError, ProcessLookupError):
            continue
    return None


def capture(provider, fleet, digest, image_digest):
    observed_provider = provider.parent.parent / 'tools-v10/post-stop-fit'
    assert __import__('hashlib').sha256(observed_provider.read_bytes()).hexdigest() == 'd5ed981b98ad6fc2c54843667852e9d3c3567c764398b644afac00231cd2940d'
    assert image_digest == '34d90f2a5ae8a821109b2bbf99c5527d43c3eb141f68cea212109fc876f28c8d'
    command = [str(provider), '145', fleet, digest]
    end = time.monotonic() + 100
    for attempt in range(3):
        observed = set()
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as child:
            try:
                while True:
                    if image_digest:
                        probe = self_probe(observed_provider, fleet, digest, image_digest)
                        if probe:
                            observed.add(probe)
                    if time.monotonic() >= end:
                        raise TimeoutError('complete maintenance fit timed out')
                    try:
                        out, err = child.communicate(timeout=0.35)
                        break
                    except subprocess.TimeoutExpired:
                        continue
            except BaseException:
                child.kill()
                child.wait()
                raise
        if child.returncode == 0:
            return json.loads(out)
        if (attempt == 2 or not observed or not err.rstrip().endswith('ValueError: foreign 145 descendants')):
            raise RuntimeError('complete maintenance fit refused: ' + err[-2000:] + ' ' + out[:160])
        while self_probe(observed_provider, fleet, digest, image_digest) in observed:
            if time.monotonic() >= end:
                raise TimeoutError('145 self-probe did not drain')
            time.sleep(0.15)
