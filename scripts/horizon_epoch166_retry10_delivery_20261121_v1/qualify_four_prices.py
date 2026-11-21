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
        result, rr = read("RESULT.json")
        qualified=json.loads(Path(row["path"]).read_bytes())
        claim=result["receiver"]["source"]
        assert qualified["fixture_checks"]["publisher"]==rr and claim["epoch"]==epoch and claim["terminal_sha256"]==tr["sha256"]
        assert claim["sha256"]==terminal["local_archive"]["sha256"] and claim["receipt_sha256"]==terminal["committed_receipt"]["sha256"]
        assert claim["transaction_id"]==terminal["transaction_id"]
        assert result["native_batch"] == br and batch["epochs"] == [epoch] and result["receiver"]["canonical_writes"] == 0
        if epoch == 172:
            guard = runpy.run_path(str(delivery / "closure-tools/closure172.py"))["guard"]
            original_live, _, admission, worker = guard.original()
            assert live["admission"] == admission and live["first_protected_worker"] == worker
            assert live["booked_tree"] == original_live["booked_tree"]
        elif epoch in (167, 170):
            guard = peers["authority"](epoch).guard
        elif epoch == 168:
            guard = full["terminal168_profile"]()[0]["guard"]
        else:
            guard = runpy.run_path(str(Path(full["CHILD"]).with_name("closure.py")))["ORIGINAL"]
        guard.validate_terminal(terminal, live, lr, live["admission"], live["first_protected_worker"])
        proof = dict(terminal=tr, admission=live["admission"], producer_invocation_id=guard.producer_id, resource_credit_bytes=0)
        if epoch == 172:
            # There is no production retirement yet. Use a fixture reference, separate
            # from the original live authority and its still-running timer.
            proof["guard_retirement"] = rr
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
    # Keep live 172 guard accounting on the original host equation as a comparator.
    cap172 = measured["survivors"]["172"]["guard"]
    evidence172 = terminals[172]
    tree168 = measured["bookings"]["168"]
    raw_tree168 = dict(cap=tree168["cap_bytes"],physical_bytes=tree168["physical_bytes"],root=tree168["root"])
    ledger=full["bound"](full["fit"].BOOK)
    for count in range(1, len(terminals)+1):
        for group in itertools.combinations(publication["FLEET_FIELDS"], count):
            data, roster = copy.deepcopy(measured), copy.deepcopy(fleet)
            for epoch in group:
                key = str(epoch)
                original = next(v for v in roster["actual_executing_replays"] if v["epoch"] == epoch)
                roster["actual_executing_replays"].remove(original)
                data["population"].pop(original["unit"]["Id"])
                if epoch == 172:
                    incumbent = data["survivors"].pop(key)
                    data["required_available_memory_bytes"] += incumbent["resident"]
                    book = dict(cap_bytes=cap172["cap"], physical_bytes=cap172["cap"]-cap172["remaining"],
                                remaining_bytes=cap172["remaining"], historical_realized_bytes=0,
                                plan=cap172["plan"],retired_guard_floor=cap172["floor"])
                    data["bookings"][key] = book
                    roster["full172_guard_retirement"] = evidence172["guard_retirement"]
                    _, eq = full["host_floor"](roster,ledger,raw_tree168,data["survivors"],book)
                    data["registered_host_equation"]=eq
                else:
                    data["required_available_memory_bytes"] += data["joined_resident_lower_bounds"].pop(key)
                if epoch == 168:
                    data["normal168"], data["active168_guard_floor"] = None, 0
                elif epoch != 172:
                    data["replacements"].pop(key)
                    roster["original_disk_guard_recovery_workers"].pop(key)
                    data["closed_prestart_remaining"][key] = prepaid[key]
                data["bookings"][key]["measurement"] = "two complete stopped-tree walks"
                data[publication["CLOSURES"][epoch]] = terminals[epoch]
                roster[publication["FLEET_FIELDS"][epoch]] = terminals[epoch]["terminal"]
            raw,eq=full["host_floor"](roster,ledger,raw_tree168,data["survivors"],data["bookings"].get("172"))
            extension=data["epoch170_extension"]
            native_raw=raw+(extension["extra_bytes"] if extension else 0)
            if 172 in group:
                retained_169=measured["survivors"]["169"]["guard"]
                # Reconstruct the unguarded 172 floor from each still-paid term.
                nested=max(eq["rebased_floor"],retained_169["floor"])+retained_169["remaining"]+(16<<30)
                assert raw==nested+cap172["remaining"]+(128<<20)
                assert measured["original_aggregate_HOME_bytes"]-native_raw==max(0,cap172["floor"]-nested)
            else:
                assert native_raw==measured["original_aggregate_HOME_bytes"]
            data["original_aggregate_HOME_bytes"]=native_raw
            assert eq==data["registered_host_equation"]
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
    assert len(prices)==80 and len(rejected)==480
    # After genuine closure, a retained physical byte replaces exactly one
    # corresponding future physical byte under the same full 172 cap.
    peers = dict(measured["survivors"])
    peers.pop("172")
    book = dict(cap_bytes=cap172["cap"],remaining_bytes=cap172["remaining"],plan=cap172["plan"],retired_guard_floor=cap172["floor"])
    a, _ = full["host_floor"](fleet,ledger,raw_tree168,peers,book)
    b, _ = full["host_floor"](fleet,ledger,raw_tree168,peers,dict(book,remaining_bytes=book["remaining_bytes"]-1))
    assert a == b+1
    try:full["host_floor"](fleet,ledger,raw_tree168,measured["survivors"],book)
    except ValueError:pass
    else:raise ValueError("a live and closed full 172 were both charged")
    return dict(native_fixtures=artifacts,original_prestart_remaining=prepaid,prices=prices,rejected=rejected,
                projected_closures=True,available_resources_for_positive_controls="raised to exact sufficient thresholds",r2_writes=0)
