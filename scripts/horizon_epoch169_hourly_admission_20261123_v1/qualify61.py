"""Exercise the V61 handoff and three 170 histories in an isolated mount namespace."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


def check(writer, route, ready, derive):
    fleet = writer.checked(ready["fleet"])
    cfg = writer.sealed(ready["config"])
    scope = route.interface()
    old = route.contract.stopped_owner(fleet)
    terminal = writer.checked(route.contract.STOP)
    drain = writer.checked(route.contract.DRAIN)
    assert old["phase"] == "terminal" and terminal["partial"] is terminal["last_logged_progress"] is None
    assert old["actor_ref"] == terminal["actor"] and old["release"] == terminal["release"] == drain["binding"]["release"]
    assert ready["terminal_private_invocations"][old["unit"]["Id"]] == route.contract.PREVIOUS
    assert ready["third_ram_gap170_interface"] == route.INTERFACE
    assert scope["previous_ram_terminal"] == ready["retained_170_second_ram_stop"] == route.contract.STOP
    assert scope["previous_ram_drain"] == ready["retained_170_second_ram_drain"] == route.contract.DRAIN
    assert ready["second162_retry_scope"] == writer.second162_route.SCOPE and ready["private169_retry4_scope"] == writer.retry169_status.SCOPE
    assert ready["second_ram_gap170_interface"] == writer.ram170_second_status.INTERFACE
    assert route.retained_population(fleet, cfg) is None and route.history_config(fleet,cfg) == cfg
    assert [name for name in ("ram170_second_status.py","fourth169_status.py","second162_retry_status.py","second162_retry_route.py",
                              "ram170_status.py") if (derive.NEW/name).read_bytes() != (derive.OLD/name).read_bytes()] == []
    cases=["complete handoff on the V60 clock","unchanged 169/162 and two 170 histories",
           "exact stopped bootstrap and native drain without progress or output", "absent third owner"]
    base = {"sha256":"a"*64,"path":"/fixture/actor"}
    grant = {"sha256":"b"*64,"path":"/fixture/release"}
    iid = "adc32e75c39643b0805b90ee25e815d3"
    act = {"producer_invocation_id":iid,"producer_pid":84208,"unit":route.UNIT}
    cfgrow = dict(range="170", producer_unit=route.UNIT, expected_producer_invocation_id=iid)
    def reject(func):
        try:
            func()
        except (ValueError, KeyError, AssertionError):
            return
        raise AssertionError("foreign third owner was accepted")
    for phase in ("held","bootstrap","worker","terminal"):
        row=dict(epoch=170,unit={"Id":route.UNIT},interface=route.INTERFACE,actor_ref=base,release=grant,
                 actor=act,observer=fleet["observer"],phase=phase,observer_config=cfgrow if phase=="worker" else None,
                 resource_credit_bytes=0,archive_publication_authorized=False,canonical_replay_claimed=False,transaction_replay_claimed=False)
        if phase=="terminal":
            row["native_terminal"]={"INVOCATION_ID":iid}
        sample=deepcopy(fleet)
        route.install(sample,row)
        assert sample[route.FIELD] == row and sample[writer.ram170_second_status.FIELD] == old
        assert sample["active_producer_count"] == fleet["active_producer_count"] + int(phase!="terminal")
        c=SimpleNamespace(next_cfg=deepcopy(cfg));route.project(c,row)
        with patch.object(route.gap,"bound",return_value=base), patch.object(writer.transition_v61,"bound",return_value=base):
            assert route.retained_population(sample,c.next_cfg)==row
            assert route.history_config(sample,c.next_cfg)==cfg
            # Other observers see precisely their historical assignment.
            assert writer.ram170_second_status.retained_population(sample,cfg)==old
            reject(lambda:route.retained_population(sample,dict(c.next_cfg,diagnostic_replays=[dict(cfgrow,producer_unit="foreign")])))
        assert route.active(row) == (phase!="terminal")
        fields=route.status_fields(row)
        assert fields["private170_third_ram_gap_phase"]==phase and not fields["private170_canonical_progress"]
        cases.append("third "+phase+" scope, counts and history")
    wrong = deepcopy(fleet)
    wrong[writer.ram170_second_status.FIELD]["native_terminal"]["INVOCATION_ID"]="0"*32
    reject(lambda:route.contract.stopped_owner(wrong))
    reject(lambda:route.enroll(writer.__dict__,ready["fleet"],ready["old_owner"]))
    cases += ["foreign predecessor refused", "predecessor writer cannot enroll the third actor"]
    return cases


def main():
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import derive61 as d
    from derive56 import verified
    os.umask(0o077)
    if len(sys.argv) == 1:
        fixture = Path(tempfile.mkdtemp(prefix="third170-v61-fixture-",dir=d.ROOT))
        print(str(fixture),flush=True)
        subprocess.run(["unshare","--mount","--propagation","private",sys.executable,"-IB",__file__,str(fixture)],check=True)
        return
    fixture = Path(sys.argv[1]).resolve(strict=True)
    root = d.OLD.parent
    assert len(sys.argv) == 2 and fixture.parent == d.ROOT and fixture.name.startswith("third170-v61-fixture-")
    assert not Path("/proc/self/ns/mnt").samefile("/proc/1/ns/mnt")
    assert subprocess.check_output(["findmnt","-n","-o","PROPAGATION","-T","/"],text=True).strip() == "private"
    upper,work = fixture/"upper",fixture/"work"
    upper.mkdir()
    work.mkdir()
    subprocess.run(["mount","-t","overlay","overlay","-o",f"lowerdir={root},upperdir={upper},workdir={work}",root],check=True)
    plan = d.stage(fixture/"input")
    def save(name,value):
        path = fixture/name
        with path.open("xb") as out:
            out.write((json.dumps(value,sort_keys=True,indent=2)+"\n").encode())
            out.flush()
            os.fchmod(out.fileno(),0o400)
            os.fsync(out.fileno())
        fd = os.open(fixture, os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return {"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    ref = save("plan.json",plan)
    sealer = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
    digest = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
    verified(sealer,digest)
    subprocess.run([sealer,ref["path"],"--plan-sha256",ref["sha256"],"--self-sha256",digest],stdout=subprocess.DEVNULL,check=True)
    args = [sys.executable,"-IB",d.NEW/"status_cycle.py"]
    package = json.loads(subprocess.check_output(args+["--check-entry"]))
    head = max(root.parent.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
    head_sha = hashlib.sha256(head.read_bytes()).hexdigest()
    ready = json.loads(subprocess.check_output(args+["--check-v61-handoff",head,head_sha]))
    assert ready["package"] == package and ready["old_owner"]["sha256"] == d.OWNER
    sys.path.insert(0,str(d.NEW))
    import status_cycle
    import ram170_third_status
    cases = check(status_cycle,ram170_third_status,ready,d)
    receipt = save("RESULT.json",dict(schema="horizon-cadence-v61-third170-private-qualification-v1",plan=ref,
        package=package,parent=ready["old_owner"],writer_handoff=save("ready.json",ready),
        fixture_fleet=ready["fleet"],cases=cases))
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
