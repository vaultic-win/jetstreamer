"""Exercise the deployed classifier and original live refusal without modifying the producer."""
import copy
import json
from pathlib import Path
import runpy

def qualify():
    c=runpy.run_path(str(Path(__file__).resolve().with_name("closure169.py")))
    o=c["o"];w,wr=c["live"]()
    assert o["owner"]()==w
    try:c["settle"]()
    except ValueError as ex:assert "still occupied" in str(ex)
    else:raise ValueError("accepted active original")
    assert not c["TERM"].exists() and not c["DONE"].exists() and not c["guard"].intent_path.exists()
    source=Path("/home/sol/.jetstreamer-private/epoch169-standard-lane-20261109-v1/replacement-local3retry3-20261110-v1/producer.log")
    with source.open("rb") as f:
        f.seek(-8192,2);old=f.read().splitlines(keepends=True)
    warn,=[r for r in old if c["WARN"].fullmatch(r.rstrip(b"\n"))]
    error=old[-1];assert c["ERROR"].fullmatch(error.rstrip(b"\n"))
    bank=b"epoch169 diagnostic bank feature at slot 73239086 entry 164: per_byte_logging_cost active=false activated_slot=None\n"
    boot=w["boot_id"]
    base=dict(_PID="1",_BOOT_ID=boot.replace("-",""),UNIT=c["UNIT"],INVOCATION_ID=c["IID"],__REALTIME_TIMESTAMP="10")
    success=[dict(base,MESSAGE_ID=c["OK"])]
    failed=[dict(base,MESSAGE_ID=c["EXIT"],COMMAND="ExecStart",EXIT_CODE="exited",EXIT_STATUS="1"),dict(base,MESSAGE_ID=c["FAIL"],UNIT_RESULT="exit-code")]
    native=lambda rows:c["manager_events"](rows,boot)
    def fixture(lines,events,guard=None,artifact=None):
        return c["classify"](lines,native(events),guard,artifact)[0]
    diag=[bank,warn,error]
    assert fixture(diag,failed)==c["MISMATCH"]
    checkpoint=b"[2026-11-21T12:00:00.000Z INFO  jetstreamer_node::historical_replay] historical checkpoint slot=73245218 bank_hash="+b"A"*44+b" accounts_hash="+o["HASH"].encode()+b" last_blockhash="+b"A"*44+b" capitalization=1 transactions=1 tick_height=1 complete=true writes=1 next_write_version=1\n"
    archive=b"[2026-11-21T12:00:00.000Z INFO  jetstreamer_node::horizon] horizon archive complete: slots=237219 blocks=1 txs=1 tx_updates=1 orphan_updates=1 epochs=1 buckets=1 bytes=99999 (payload 100000 uncompressed)\n"
    manifest=b"[2026-11-21T12:00:00.000Z INFO  jetstreamer_node] published verified historical segment evidence "+str(o["MANIFEST"]).encode()+b"\n"
    complete=[bank,checkpoint,archive,manifest]
    assert fixture(complete,success,None,{"size":99999})==c["PRIVATE"]
    bfail=copy.deepcopy(failed);bfail[0]["EXIT_CODE"]="killed";bfail[1]["UNIT_RESULT"]="oom-kill"
    bad=[(diag,success,None,None),(diag,bfail,None,None),(diag,failed,{"intent":"present"},None),([warn,bank,error],failed,None,None),
         ([bank,warn,b"padding"+error],failed,None,None),([bank,warn,error+b"trailing\n"],failed,None,None),
         ([bank,warn,error.replace(b"transaction 205",b"transaction 206")],failed,None,None),
         ([bank,warn,error.replace(b"ComputationalBudgetExceeded",b"ProgramFailedToComplete")],failed,None,None),
         ([bank,bank,warn,error],failed,None,None),([bank,warn,error,b"error: interrupted\n"],failed,None,None),
         (complete,success,None,None),(complete,success,None,{"size":6}),(complete[:2]+complete[-1:],success,None,{"size":99999}),
         ([bank,checkpoint.replace(o["HASH"].encode(),b"B"*44),archive,manifest],success,None,{"size":99999}),
         (complete,[dict(base,MESSAGE_ID=c["STOPPING"]),*success],None,{"size":99999})]
    for lines,events,g,a in bad:assert fixture(lines,events,g,a)==c["INTERRUPTED"]
    for rows in ([],[failed[0]],failed*2,[dict(success[0],INVOCATION_ID="d228ed7687234bf1b83777a7c7a82d0f")],[dict(success[0],UNIT=o["GUARD"])],[dict(success[0],_PID="5")]):
        try:native(rows)
        except ValueError:pass
        else:raise ValueError("accepted foreign manager")
    for before in (dict(Id=c["TIMER"],ActiveState="active",InvocationID=c["TIMER_IID"],Triggers=o["GUARD"],Job="pending"),
                   dict(Id=c["TIMER"],ActiveState="active",InvocationID=c["IID"],Triggers=o["GUARD"],Job="")):
        try:c["guard"].expected_timer(before)
        except ValueError:pass
        else:raise ValueError("accepted foreign timer")
    return dict(live=wr,prior_failure_is_classifier_fixture_only=True,original_active_refused=True,dispositions=[c["MISMATCH"],c["PRIVATE"],c["INTERRUPTED"]],
                adverse_classifications=len(bad),independent_manager_refusals=6,foreign_timer_refusals=2,resource_credit_bytes=0)

if __name__=="__main__":print(json.dumps(qualify(),sort_keys=True))
