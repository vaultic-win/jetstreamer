"""Retain the first journal block attributable to the third invocation and its guarded native worker."""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import subprocess
import time

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch162-third-replay-20261128-v1")
PIN = "0489c223b03c5bbc889a1cd28b4907fa237c11dd05e10c52bee3ba78615afdb3"
NAME = "THIRD162_FIRST_PROTECTED_BLOCK.json"
TRANSACTIONS = "THIRD162_FIRST_PROTECTED_TRANSACTIONS.json"
BLOCK = re.compile(r"\bblock slot ([0-9]+) total_txs=([0-9]+)")


def read_progress(layout, status, held, ref, grant, iid, row, match, previous=None):
    pid = held["producer_pid"]
    slot,tx = map(int,match.groups())
    layout.need(69_998_120 <= slot <= 70_004_937 and tx >= 0, "journal outside third interval")
    state = layout.manager(layout.UNIT)
    layout.need(state["ActiveState"] == "active" and state["InvocationID"] == iid and int(state["MainPID"]) == pid
                and layout.ticks(pid) == held["start_ticks"], "third producer changed")
    raw,guard,plan = status["last_guard"](layout,held)
    workers = raw["workers"]
    if not workers:
        return None
    layout.need(len(workers) == 1 and 0 < workers[0][1] <= 3_500_000, "third guard has a different worker census")
    worker = workers[0][0]
    exe = Path("/proc")/str(worker)/"exe"
    name = exe.readlink()
    ticks = layout.ticks(worker)
    layout.need(worker in map(int,(layout.CGROUP/"cgroup.procs").read_text().split())
                and name.is_relative_to(layout.RUN/"scratch") and name.name == "historical-worker"
                and layout.digest(exe) == layout.scope()["capped_worker"]["sha256"]
                and layout.ticks(worker) == ticks, "unguarded or foreign third worker")
    if int(row["__MONOTONIC_TIMESTAMP"]) < ticks*1_000_000//os.sysconf("SC_CLK_TCK"):
        return None
    keys = ("_BOOT_ID","_PID","_SYSTEMD_INVOCATION_ID","_SYSTEMD_UNIT","__CURSOR",
            "__MONOTONIC_TIMESTAMP","__REALTIME_TIMESTAMP","MESSAGE")
    name = TRANSACTIONS if previous else NAME
    data = dict(schema="horizon-private-162-third-first-protected-block-v1",
        scope=layout.pinned(ROOT/"SCOPE.json")[1],held=ref,grant=grant,guard=guard,
        actor=dict(unit=layout.UNIT,invocation=iid,pid=pid,start_ticks=held["start_ticks"],worker_pid=worker,
                   worker_start_ticks=ticks,worker_executable=str(name)),journal={k:row[k] for k in keys},
        slot=slot,cumulative_transactions=tx,guard_root_budget=plan["maximum_root_physical_bytes"],
        canonical_or_r2_writes=False)
    if previous:
        before,first_ref = previous
        layout.need(slot > before["slot"] and tx > before["cumulative_transactions"]
                    and int(row["__MONOTONIC_TIMESTAMP"]) > int(before["journal"]["__MONOTONIC_TIMESTAMP"]),
                    "no native third-162 slot or transaction advance")
        data.update(schema="horizon-private-162-third-first-protected-transaction-advance-v1",previous=first_ref,
                    slot_delta=slot-before["slot"],transaction_delta=tx-before["cumulative_transactions"])
    receipt = layout.save(ROOT/name,data,0o400)
    return dict(receipt=receipt,slot=slot,cumulative_transactions=tx,invocation_id=iid)


def first(iid, transactions=False):
    from hashlib import sha256
    interface = ROOT/"INTERFACE.json"
    data = interface.read_bytes()
    if sha256(data).hexdigest() != PIN or not re.fullmatch("[a-f0-9]{32}",iid):
        raise ValueError("different interface or invocation")
    info = json.loads(data)
    reader = ROOT/"operator-v1/status162.py"
    if info["reader"] != dict(path=str(reader),sha256=sha256(reader.read_bytes()).hexdigest()):
        raise ValueError("different native third reader")
    status = runpy.run_path(str(reader))
    layout = status["api"]()
    held,ref = layout.pinned(layout.DATA/"HELD_OWNER.json")
    g,grant = layout.pinned(layout.DATA/"GRANT.json")
    layout.need(layout.UNIT == info["unit"] and g["held"] == ref and g["iid"] == held["producer_invocation_id"] == iid
                and layout.ALLOW.read_bytes() == iid.encode() and layout.scope()["previous"] == info["previous"], "foreign private grant")
    previous = None
    if transactions:
        previous = layout.pinned(ROOT/NAME)
        before = previous[0]
        layout.need(before["held"] == ref and before["grant"] == grant and before["actor"]["invocation"] == iid,
                    "first block refers to a different producer")
    name = TRANSACTIONS if transactions else NAME
    if (ROOT/name).exists():
        rec,existing = layout.pinned(ROOT/name)
        layout.need(rec["held"] == ref and rec["grant"] == grant and rec["actor"]["invocation"] == iid,
                    "progress belongs to another producer")
        return dict(receipt=existing,slot=rec["slot"],cumulative_transactions=rec["cumulative_transactions"],invocation_id=iid)
    boot = held["boot_id"].replace("-","")
    sources = dict(_BOOT_ID=boot,_PID=str(held["producer_pid"]),_SYSTEMD_INVOCATION_ID=iid,_SYSTEMD_UNIT=layout.UNIT)
    args = ["/usr/bin/journalctl","-q","--no-pager","--no-tail","--follow","-o","json",
            "--grep=block slot [0-9]+ total_txs=|Deactivated successfully|Failed with result|Main process exited",
            *(k+"="+v for k,v in sources.items()),"+","_PID=1","_UID=0","_BOOT_ID="+boot,"UNIT="+layout.UNIT,"INVOCATION_ID="+iid]
    deadline = time.monotonic()+layout.scope()["profile"].get("runtime_seconds",6300)+45
    proc = subprocess.Popen(args,stdout=subprocess.PIPE,bufsize=0)
    try:
        with selectors.DefaultSelector() as reader_events:
            reader_events.register(proc.stdout,selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not reader_events.select(min(45,deadline-time.monotonic())):
                    layout.need(proc.poll() is None,"native journal reader closed")
                    continue
                line = proc.stdout.readline()
                layout.need(line,"native journal ended before protected progress")
                row = json.loads(line)
                if row.get("_PID") == "1":
                    raise ValueError("third producer reached PID 1 terminal before observed progress: "+row["MESSAGE"])
                m = BLOCK.search(row["MESSAGE"])
                if m and all(row.get(k) == v for k,v in sources.items()):
                    if previous and (int(m[1]) <= before["slot"] or int(m[2]) <= before["cumulative_transactions"]):
                        continue
                    result = read_progress(layout,status,held,ref,grant,iid,row,m,previous)
                    if result is not None:
                        return result
            raise TimeoutError("third producer timed out before a guarded block")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        proc.stdout.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("invocation")
    parser.add_argument("--transactions",action="store_true",help="capture the first later block with a positive transaction delta")
    args = parser.parse_args()
    print(json.dumps(first(args.invocation,args.transactions),sort_keys=True),flush=True)
