"""Prepare the third bounded replay from the proven second-interval operator."""
import argparse
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import second_interval as second
from third_inputs import (
    BASE, INPUT, NAMES, PREVIOUS, PRIOR, PRIVATE, SCOPE_SHA, SLOTS, WITNESS,
    WITNESS_SHA, checkpoints, local_bootstrap,
)

need, reference, load, digest = second.need, second.reference, second.load, second.digest
OLD_OP = PRIOR / "operator-v1"
OLD_SEAL = "92c4b62dad822256ee92f0338661398a0a2449b3cffeff0146e16912053bc783"
STATIC = BASE / "static-v1"
VALIDATION = BASE / "static-proof-v1/NATIVE_GUARD_VALIDATED.json"
VALIDATION_SHA = "10a4cf4846c6153c2fea9518657d3acd27fea56fc74fa0579aa81dd89fb2f6bb"
NATIVE = "6aecfdacac92c7271eb7e530c70a323515ab5c33"
OLD_ALIAS = "/run/horizon-162-second-replay-v3"
ALIAS = "/run/horizon-162-third-replay-v1"
OLD_IID = "c64af2c83b994e299e375b44dee7ce21"
FIELD = "current_private162_third_hourly"


def native():
    proof = load(VALIDATION, VALIDATION_SHA)
    seal = second.bind(proof["seal"])
    need(proof["seal"] == reference(STATIC / "deployment-seal-receipt.json")
         and seal["destination"] == str(STATIC)
         and proof["guard"] == reference(STATIC / "guard") and proof["hold"] == reference(STATIC / "hold")
         and [(c["name"], c["exit"]) for c in proof["cases"]] ==
             [("exact", 0), ("foreign-unit", 1), ("other-root", 1), ("oversize", 1)],
         "different qualified gate or guard")
    return proof


def route(text):
    return (text.replace(PRIOR.name, BASE.name).replace("162-second-replay-20261128-v3", "162-third-replay-20261128-v1")
            .replace(OLD_ALIAS, ALIAS).replace("hold-162-second", "hold-162-third"))


def successor_profile(prior, names, snap, proof, slots, previous_base, next_base, alias, hashes_path, gate_name, relocate):
    previous_snap = Path(second.bind(prior["bootstrap"]["verified_local_custody"])["destination"])
    old = prior["profile"]
    def relocated(value):
        return relocate(value).replace(previous_snap.name, snap.name)
    rows = []
    for row in old["readonly_projections"]:
        view = relocated(row["readonly_view"])
        source = row["source"]
        if source == str(previous_snap) or view == alias + "/canonical-hashes.txt":
            p = snap if source == str(previous_snap) else hashes_path
            st = p.lstat()
            rows.append(dict(source=str(p), readonly_view=view,
                             identity=[st.st_dev, st.st_ino, st.st_size, st.st_ctime_ns, st.st_mtime_ns]))
        elif source == prior["first_hourly_gate"]["path"]:
            rows.append(dict(source=proof["hold"]["path"], readonly_view=view, sha256=proof["hold"]["sha256"]))
        elif source == str(previous_base / "barrier"):
            rows.append(dict(row, source=str(next_base / "barrier"), readonly_view=view))
        else:
            rows.append(dict(row, readonly_view=view))
    actual = [relocated(arg) for arg in old["actual_node_argv"]]
    need(actual[-1] == "--qualification-end-slot=" + str(slots[0]), "different native entry")
    actual[-1] = "--qualification-end-slot=" + str(slots[1])
    profile = dict(old, actual_node_argv=actual, main_argv=[relocated(v) for v in old["main_argv"]],
                   environment={k: relocated(v) for k,v in old["environment"].items()}, readonly_projections=rows)
    need(len(set(r["readonly_view"] for r in rows)) == len(rows)
         and profile["main_argv"] == [alias + "/" + gate_name]
         and actual[4] == "--snapshot-archive=" + alias + "/" + names[0], "ambiguous bootstrap or gate")
    return profile


def scope(revision, prior, pins, witnesses, names, proof):
    snap, custody = local_bootstrap(pins[0], witnesses[0])
    profile = successor_profile(prior, names, snap, proof, SLOTS, PRIOR, BASE, ALIAS, NAMES, "hold-162-third", route)
    inherited = ("capped_worker", "node", "producer_ram", "guard_ram", "producer_cpu_micros", "guard_cpu_micros",
                 "tmpfs_bytes", "control_bytes", "mutable_image_bytes", "unreleased_predecessor", "postguard_predecessor")
    return dict({k: prior[k] for k in inherited}, schema="horizon-private-162-third-native-contract-v1",
                first_slot=SLOTS[0]+1, last_slot=SLOTS[1], position_count=SLOTS[1]-SLOTS[0], profile=profile,
                bootstrap=dict(verified_local_custody=custody, witness=prior["terminal"]["terminal_witness"],
                               bank_hash=witnesses[0]["bank"]["bank_hash"], account_hash=witnesses[0]["accounts_hash"],
                               archive_sha256=witnesses[0]["raw_archive_readback"]["sha256"], generation=int(pins[0]["generation"])),
                terminal=dict(terminal_witness=reference(WITNESS), bank_hash=witnesses[1]["bank"]["bank_hash"],
                              accounts_hash=witnesses[1]["accounts_hash"], generation=int(pins[1]["generation"])),
                previous=reference(PREVIOUS), previous_interface=reference(PRIOR / "INTERFACE.json"),
                checkpoint_names=reference(NAMES), first_hourly_gate=proof["hold"], first_hourly_guard=proof["guard"],
                gate_deployment=proof["seal"], guard_deployment=proof["seal"], native_guard_validation=reference(VALIDATION),
                canonical_publication_authorized=False, source_commit=revision)


def adapt(name, text, scope_hash, guard):
    text = route(text).replace("second162_reserved_", "third162_")
    once = second.exact
    if name == "layout.py":
        text = once(text, SCOPE_SHA, scope_hash)
        text = once(text, "/static-v3/hold-162-third", "/static-v1/hold")
        text = once(text, "/static-v3/guard", "/static-v1/guard")
        return once(text, "c6049e1161b1a54b2d7193faac077242c24b2f52543e986dfb9c958d47698d72", guard)
    if name == "launch.py":
        return once(text, 'q["second_162_predecessor"] == l.scope()["previous"], "different first interval custody"',
                    'q["third_162_predecessor"] == l.scope()["previous"], "different second interval custody"')
    if name == "status162.py":
        text = once(text, 'FIELD = "current_private162_second_reserved"', f'FIELD = "{FIELD}"')
        anchor = '    registered = [r for r in fleet["actual_active_private_diagnostics"]'
        return once(text, anchor, '''    preceding = fleet.get("current_private162_second_reserved")
    end = l.bound(l.scope()["previous"])
    l.need(preceding and preceding["phase"] == "terminal"
           and preceding["producer_invocation_id"] == "c64af2c83b994e299e375b44dee7ce21"
           and preceding["terminal"] == end["pid1"] and preceding["held_owner"] == end["held"]
           and end["private_checkpoint_matched"], "second 162 replay or custody changed")
''' + anchor)
    if name == "terminal_bank.py":
        old = PRIVATE / "epoch162-second-hourly-20261128-v1/TERMINAL_BANK_WITNESS.json"
        text = once(text, str(old), str(WITNESS))
        text = once(text, "0ea17b4d98a2c70e88da101424d2829659e1f56dfb049eea210b607e9074965c", WITNESS_SHA)
        return text.replace("69998119", "70004937")
    need(name == "close.py", "unknown prior operator member")
    text = once(text, "(69991077,7043)", "(69998120,6818)")
    text = text.replace("69998119", "70004937").replace("69991076", "69998119")
    text = once(text, '["validated_derived_segment"]["derived_manifest"]', '["archive"]["typed_manifest"]')
    return text.replace("second interval", "third interval").replace("second manifest", "third manifest")


def members(scope_hash, proof):
    old = load(OLD_OP / "deployment-seal-receipt.json", OLD_SEAL)
    result = {}
    for member in old["members"]:
        name = member["name"]
        if name.endswith(".py"):
            p = OLD_OP / name
            need(p.parent == OLD_OP and digest(p) == member["sha256"], "changed predecessor operator " + name)
            text = adapt(name, p.read_text(), scope_hash, proof["guard"]["sha256"])
            compile(text, name, "exec")
            result[name] = text
    need(set(result) == {"layout.py", "launch.py", "close.py", "status162.py", "terminal_bank.py"},
         "incomplete operator")
    return result


def check():
    prior, pins, witnesses, names = checkpoints()
    proof = native()
    bundle = members("0"*64, proof)
    bank = {"__name__": "fixture"}
    exec(compile(bundle["terminal_bank.py"], "terminal_bank.py", "exec"), bank)
    fixture = bank["fixture"]()
    layout = {"__name__": "fixture"}
    exec(compile(bundle["layout.py"], "layout.py", "exec"), layout)
    need(layout["BASE"] == BASE and layout["GUARD"] == STATIC/"guard" and layout["GATE"] == STATIC/"hold"
         and layout["UNIT"] == "horizon-qualify-162-third-replay-20261128-v1.service" and fixture["negative"] == 7,
         "compiled operator disagrees with the guarded route")
    return dict(positions=SLOTS[1]-SLOTS[0], checkpoint_names=names, predecessor=reference(PREVIOUS),
                terminal_bank=reference(WITNESS), terminal_fixture=fixture, guard=reference(VALIDATION))


def prepare(revision):
    prior, pins, witnesses, names = checkpoints()
    proof = native()
    checkout = HERE.parents[1]
    git = ["git", "-c", "safe.directory="+str(checkout), "-C", str(checkout)]
    for commit in (revision, NATIVE):
        subprocess.run([*git, "merge-base", "--is-ancestor", commit, "origin/account-updates"], check=True)
    inputs = {}
    for filename in ("third_interval.py", "third_inputs.py", "second_interval.py"):
        path = HERE / filename
        relative = str(path.relative_to(checkout))
        need(subprocess.check_output([*git, "show", revision+":"+relative]) == path.read_bytes(), "unpublished " + relative)
        inputs[relative] = digest(path)
    receipt = load(OLD_OP/"deployment-seal-receipt.json", OLD_SEAL)
    layout = OLD_OP / "layout.py"
    need(digest(layout) == next(m["sha256"] for m in receipt["members"] if m["name"] == layout.name), "changed layout")
    save = runpy.run_path(str(layout))["save"]
    need(os.geteuid() == 0 and BASE.resolve() == BASE and BASE.stat().st_uid == 0
         and BASE.stat().st_dev == PRIVATE.stat().st_dev and BASE.stat().st_mode & 0o077 == 0, "unsafe control root")
    packet = scope(revision, prior, pins, witnesses, names, proof)
    sr = save(BASE/"SCOPE.json", packet, 0o400)
    src = BASE/"operator-source-v1"
    src.mkdir(mode=0o700, exist_ok=True)
    need(src.resolve() == src and src.stat().st_uid == 0 and src.stat().st_mode & 0o077 == 0, "unsafe staging")
    files = {}
    for name, text in members(sr["sha256"], proof).items():
        p = src/name
        save(p, text.encode(), 0o444)
        files[name] = (p, 0o444)
    origin = src/"ORIGIN.json"
    save(origin, dict(revision=revision, native=NATIVE, sources=inputs, previous_operator=reference(OLD_OP/"deployment-seal-receipt.json"),
                      scope=sr, native_guard=proof["seal"], input_custody=packet["bootstrap"]["verified_local_custody"]))
    files[origin.name] = (origin, 0o444)
    second.BASE = BASE
    op = second.seal(files, BASE/"operator-v1", save)
    return save(BASE/"INTERFACE.json", dict(unit="horizon-qualify-162-third-replay-20261128-v1.service",
                field=FIELD, provider=op, reader=reference(BASE/"operator-v1/status162.py"), scope=sr,
                first_slot=SLOTS[0]+1, last_slot=SLOTS[1], previous=reference(PREVIOUS), guard_validation=reference(VALIDATION),
                gate=proof["hold"], guard=proof["guard"], bootstrap=packet["bootstrap"], terminal=packet["terminal"]), 0o400)


if __name__ == "__main__":
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--prepare", metavar="SOURCE_COMMIT")
    parsed = args.parse_args()
    result = check()
    if parsed.prepare:
        result["interface"] = prepare(parsed.prepare)
    print(json.dumps(result, sort_keys=True))
