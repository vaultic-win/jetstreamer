"""Price every closed subset using the original admitted allowances and native held-pair fixtures."""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import runpy
import time


def trials(full, publication, measured, fleet):
    root = publication["R"]
    peers = full["peer_closures"]()
    terminals = {}
    prepaid = {}
    artifacts = {}
    for epoch in publication["FLEET_FIELDS"]:
        delivery = root / ("epoch166-retry10-delivery-20261121-v1" if epoch == 166 else f"epoch{epoch}-current-delivery-20261121-v1")
        marker = "READER_SUCCESSOR_QUALIFIED.json" if epoch in (166, 168) else "HELD_PUBLICATION_QUALIFIED.json"
        handoff = json.loads((delivery / marker).read_bytes())
        row = handoff["qualification"]
        native_dir = Path(row["path"]).parent
        assert hashlib.sha256(Path(row["path"]).read_bytes()).hexdigest() == row["sha256"]
        run = native_dir / "test-publisher"
        def read(name):
            path = run / name
            data = path.read_bytes()
            return json.loads(data), dict(path=str(path), sha256=hashlib.sha256(data).hexdigest())
        terminal, tr = read("authority/TERMINAL_SUCCESS.json")
        live, lr = read("authority/LIVE.json")
        batch, br = read("native-batch.json")
        result, _ = read("RESULT.json")
        assert result["native_batch"] == br and batch["epochs"] == [epoch] and result["receiver"]["canonical_writes"] == 0
        if epoch in (167, 170):
            guard = peers["authority"](epoch).guard
        elif epoch == 168:
            guard = full["terminal168_profile"]()[0]["guard"]
        else:
            guard = runpy.run_path(str(Path(full["CHILD"]).with_name("closure.py")))["ORIGINAL"]
        guard.validate_terminal(terminal, live, lr, live["admission"], live["first_protected_worker"])
        proof = dict(terminal=tr, admission=live["admission"], producer_invocation_id=guard.producer_id, resource_credit_bytes=0)
        terminals[epoch] = proof
        artifacts[epoch] = dict(native_qualification=row, terminal=tr, batch=br)
        if epoch in publication["PRESTART"]:
            book = measured["bookings"][str(epoch)]
            args = (measured["actual_original_stops"][str(epoch)], Path(book["root"]), Path(book["run"]), book["cap_bytes"], measured["epoch170_extension"])
            unused = full["closed_allowance"](epoch, proof, *args)
            assert unused == publication["PRESTART"][epoch] == measured["replacements"][str(epoch)]["prestart_remaining"]
            for bad in [dict(proof, producer_invocation_id="f"*32),dict(proof,admission=lr)]:
                try:full["closed_allowance"](epoch, bad, *args)
                except (ValueError, KeyError):pass
                else:raise ValueError("foreign original prestart accepted")
            prepaid[str(epoch)] = unused

    prices, rejected = [], []
    for count in range(1, 5):
        for group in itertools.combinations(publication["FLEET_FIELDS"], count):
            data, roster = copy.deepcopy(measured), copy.deepcopy(fleet)
            for epoch in group:
                key = str(epoch)
                original = next(v for v in roster["actual_executing_replays"] if v["epoch"] == epoch)
                roster["actual_executing_replays"].remove(original)
                data["population"].pop(original["unit"]["Id"])
                data["required_available_memory_bytes"] += data["joined_resident_lower_bounds"].pop(key)
                if epoch == 168:
                    data["normal168"], data["active168_guard_floor"] = None, 0
                else:
                    data["replacements"].pop(key)
                    roster["original_disk_guard_recovery_workers"].pop(key)
                    data["closed_prestart_remaining"][key] = prepaid[key]
                data["bookings"][key]["measurement"] = "two complete stopped-tree walks"
                data[publication["CLOSURES"][epoch]] = terminals[epoch]
                roster[publication["FLEET_FIELDS"][epoch]] = terminals[epoch]["terminal"]
            required, protected, deficit = full["disk_budget"](data["original_aggregate_HOME_bytes"], data["candidate136"],
                data["bookings"], 145, data["survivors"], data["replacements"], data["active168_guard_floor"], data["closed_prestart_remaining"])
            assert deficit == measured["historical_baseline_deficit_bytes"] and required == protected
            assert measured["complete_required_HOME_bytes"] >= required
            data["complete_required_HOME_bytes"] = required
            data["recorded_unix_seconds"] = int(time.time())
            floor = required + count * publication["BOOK"]
            data["available_HOME_bytes"] = max(floor,data["available_HOME_bytes"])
            data["available_memory_bytes"] = max(data["available_memory_bytes"],data["required_available_memory_bytes"])
            for publisher in group:
                tr=terminals[publisher]["terminal"]
                def validate(value,inventory=roster):
                    return publication["validate"](value,inventory,data["fleet"],tr,publisher)
                assert validate(data)==floor
                prices.append(dict(closed=group,publisher=publisher,protected=floor,fully_retained_cap=data["bookings"][str(publisher)]["cap_bytes"]))
                other=next(e for e in terminals if e!=publisher)
                bads=dict(disk_floor=dict(data,available_HOME_bytes=floor-1), credited_memory=dict(data,required_available_memory_bytes=data["required_available_memory_bytes"]-1),
                    population=dict(data,population={}),wrong_terminal=dict(data,**{publication["CLOSURES"][publisher]:terminals[other]}),
                    cap=copy.deepcopy(data),prepaid=dict(data,closed_prestart_remaining=dict(data["closed_prestart_remaining"],foreign=1)))
                bads["cap"]["bookings"][str(publisher)]["cap_bytes"]-=1
                for label,value in bads.items():
                    try:validate(value)
                    except (ValueError,KeyError):rejected.append([group,publisher,label])
                    else:raise ValueError("invalid price accepted: "+label)
    assert len(prices)==32 and len(rejected)==192
    return dict(native_fixtures=artifacts,original_prestart_remaining=prepaid,prices=prices,rejected=rejected,
                projected_closures=True,available_resources_for_positive_controls="raised to exact sufficient thresholds",r2_writes=0)
