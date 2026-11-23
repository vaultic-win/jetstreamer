"""Register the independent retry before its next coordinated observation."""
import os
from pathlib import Path

import retry265 as retry


IMPORT = "import lane265\n"
SELECT = """import lane265
import sys
sys.path.insert(0, '/var/lib/jetstreamer/horizon265-retry-tools-v216')
import retry265
if retry265.CLAIM.exists():
 lane265=retry265
"""


def replace(source, before, after):
    assert source.count(before) == 1, before
    return source.replace(before, after)


def cadence(source):
    source = replace(source, IMPORT, SELECT)
    return replace(source, "assert cfg.get('delivery265_claim') in (None,binding265)",
                   "assert cfg.get('delivery265_claim') in (None,binding265) or "
                   "(lane265 is retry265 and cfg.get('delivery265_claim') == retry265.retired_binding())")


def pricing(source):
    source = replace(source, " import lane265\n", " import lane265\n sys.path.insert(0,'/var/lib/jetstreamer/horizon265-retry-tools-v216')\n import retry265\n")
    source = replace(source, "  fixed.update(lane265.finite_owner())",
                   "  fixed.update(lane265.finite_owner())\n  fixed.update(retry265.finite_owner())")
    return reserve257(source)


def reserve257(source):
    # Raw pricing retains the full 266 booking. Its closed-donor consumers take
    # the assessment view before removing 266 growth or funding a successor.
    return replace(source, " return dict(closed265_delivery=", """ reservation257=None
 closed257=V/'horizon257-closed266-reservation-v217/assignment.json'
 if closed257.exists() and assessment_only:
  reservation257=ref(closed257)
  assert reservation257['sha256']=='c28b7b8e77ad679827338f883e5496c42f2d2de6a3a25cc44c7d3f38cf2862cb'
  award=bound(reservation257)
  assert award['schema']=='horizon-closed266-reservation-for257-v1' and award['epoch']==257
  assert award['donor']==bound(ref(lane265.BOOK))['donor'] and not award['automatic_release']
  assert (award['memory'],award['disk'])==(121342177280,256000000000)
  growth+=award['memory']
  floor+=award['disk']
 return dict(reservation257=reservation257,closed265_delivery=""")


def fleet(source):
    source = replace(source, IMPORT, SELECT)
    census = "added265=lane265.CLAIM.exists() and lane265.census(p,o,done)"
    return replace(source, census, census + """
if added265:
 _,claim,booking,_=lane265.registered()
 hand=b.checked(booking['handoff'])
 drain=b.checked(booking['drain'])
 assert hand['schema']=='horizon-singleton-delivery-handoff-v1' and hand['epoch']==265
 assert hand['producer']['unit']['Result']=='success' and hand['producer']['unit']['ExecMainStatus']=='0'
 assert drain['schema']=='horizon-singleton-terminal-drain-v1' and drain['epoch']==265
 assert drain['producer_cgroup_drained'] and drain['terminal_handoff']==booking['handoff']
 assert claim['phase']=='upload-readback' and claim in p['pipeline_claims']
 gate=p['gates']['265']
 assert gate['state'] in ('staged-admissible','post-replay-pipeline')
 b.include(gate,Path(booking['handoff']['path']),Path(booking['drain']['path']))
 gate['state']='post-replay-pipeline'""")


def status(source):
    source = replace(source, IMPORT, SELECT)
    return replace(source, " if lane:\n  for directory in", """ if lane is retry265 and not prior_marker.exists():
  previous=retry265.predecessor()
  assert bind(prior_marker.parent/'terminal-outcome.json')==bind(retry265.D/'horizon-resumed-campaign-status-v216-a1/265/terminal-outcome.json')
  prior_marker=Path(previous['path'])
 if lane:
  for directory in""")


def install():
    assert os.geteuid() == 0 and __debug__ and Path(__file__).resolve().parent == retry.TOOLS
    tools = Path("/run/horizon266-bounded-tools-v208")
    routine = Path("/tmp/horizon-main-v217")
    consumers = [
        (routine/"status.py", "dd3cad7248d42607b223099ca0b6e35e7bce4f78563ad9e60ef7abd8954f7ce7", status),
        (routine/"fleet.py", "225403ed716d7281d050bc01bd018c1b4a03d7543859bb170c83c859dc1e1fdb", fleet),
        (tools/"retry_fit.py", "c1acd9ebea996c8e540450c912569a0987948b3e652509a908074c6c21c0b28b", pricing),
        (tools/"retry_entry_cadence.py", "821d3504f3909c89f916214aac45ab82595a7775295fc297381d5b5a07b4f7b3", cadence),
        (Path("/run/horizon266-terminal-event-v211-a1/cadence.py"), "4b697d968c07026aeb2991bb284e1a976b9553a9eb503f45de9d3496b026aa66", cadence)]
    with retry.shared.partition.take():
        assert not (retry.D/"horizon-resume-observer-20261120-v217.json").exists()
        changes = []
        for path, digest, edit in consumers:
            backup = retry.TOOLS/(path.parent.name+"-"+path.name+".original")
            original = backup if backup.exists() else path
            assert retry.ref(original)["sha256"] == digest and path.stat().st_uid == 0
            old = original.read_text()
            new = edit(old)
            compile(new, str(path), "exec")
            assert path.read_text() in (old, new)
            changes.append((path, backup, old, new))
        for path, backup, old, new in changes:
            if not backup.exists():
                write(backup, old)
            if path.read_text() != new:
                temporary = path.with_suffix(".retry265")
                write(temporary, new)
                temporary.replace(path)


def write(path, source):
    with path.open("x") as output:
        output.write(source)
        output.flush()
        os.fchmod(output.fileno(), 0o400)
        os.fsync(output.fileno())


if __name__ == "__main__":
    install()
