"""Bind interval four to its actual third terminal, local bootstrap, Bank witness and qualified native binaries."""
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
from third_inputs import PRIVATE, RT, local_bootstrap, validate_previous, validate_source
from third_interval import successor_profile

bind, digest, exact, load, need, reference = second.bind, second.digest, second.exact, second.load, second.need, second.reference
INPUT = PRIVATE / "epoch162-fourth-inputs-20261128.ujxTgbWe"
OLD = RT / "epoch162-third-replay-20261128-v1"
BASE = RT / "epoch162-fourth-replay-20261128-v1"
OLD_OP = OLD / "operator-v1"
PAIR = INPUT / "CHECKPOINT_PAIR.json"
PAIR_SHA = "4e915d6736636f79445ae5aa91345514e572f2e094423a5ce622574479cadfb7"
PRIOR = OLD / "split-v1/TERMINAL.json"
PRIOR_SHA = "33ee146f4690261da3159ef711f8843453a46aeff183b19fc538eeda690923e0"
OLD_SCOPE_SHA = "1ded1d0f3bdf930a1e07c8d83f6bddf4cb648cf18d344bb3a80c525f6f5bda77"
OLD_INTERFACE_SHA = "0489c223b03c5bbc889a1cd28b4907fa237c11dd05e10c52bee3ba78615afdb3"
OLD_OP_SHA = "15489f1bbffde4a9ae7723220089e76d88f107a54a98ce115de96dcfd88dbc3c"
OLD_IID = "fbac5918bc594780b255eeb22ce87187"
OLD_WITNESS_SHA = "7af0483755d00617ea91328de4b0f160311261427423f63f37c4a5a8c74fe377"
OLD_GUARD_SHA = "a954d3035ecc6c450c97212ec4a27f6676440c6c23a6bf579d0cc07a949c0ff9"
GUARD_REV = "f5741f3c8fb259311a068e98d5e7f6c497a6ad60"
STATIC = BASE / "static-v1"
VALIDATION = BASE / "static-proof-v1/NATIVE_GUARD_VALIDATED.json"
WITNESS = INPUT / "bank/TERMINAL_BANK_WITNESS.json"
NAMES = BASE / "checkpoints.txt"
NAMES_SHA = "41f96ab5b7efce332840cfeb320a53c8b1bc1feccc39ec25ad30d47e44db7c0d"
ALIAS = "/run/horizon-162-fourth-replay-v1"
FIELD = "current_private162_fourth_hourly"
UNIT = "horizon-qualify-162-fourth-replay-20261128-v1.service"
SLOTS = (70_004_937, 70_011_988)
GENERATIONS = (1634787254699764, 1634787215818603)
SIZES = (1_788_689_408, 1_796_040_910)


def source():
    pair = load(PAIR, PAIR_SHA)
    prior = load(OLD / "SCOPE.json", OLD_SCOPE_SHA)
    interface = load(OLD / "INTERFACE.json", OLD_INTERFACE_SHA)
    end = load(PRIOR, PRIOR_SHA)
    held = bind(end["held"])
    need(interface["scope"] == reference(OLD / "SCOPE.json") and end["grant"] == reference(OLD / "split-v1/GRANT.json")
         and held["producer_invocation_id"] == OLD_IID and held["producer_unit"] == interface["unit"]
         and end["archive"]["sha256"] == "ef72d591464effbab8122bde38214982f295eb32c954310e8c358a0dd5cc78ec"
         and not end["canonical_writes"], "third-interval custody changed")
    pins = (pair["bootstrap"], pair["terminal"])
    names = [Path(pin["name"]).name for pin in pins]
    text = ("\n".join(names) + "\n").encode()
    need((pair["first"], pair["last"], pair["positions"]) == (SLOTS[0] + 1, SLOTS[1], SLOTS[1] - SLOTS[0])
         and pair["prior_native_bank"] == prior["terminal"]["terminal_witness"]
         and pair["prior_native_bank"]["sha256"] == OLD_WITNESS_SHA, "different fourth checkpoint pair")
    initial = bind(pair["prior_native_bank"])
    validate_source(pins[0], initial, SLOTS[0], GENERATIONS[0], SIZES[0], names[0])
    validate_previous(end, initial, SLOTS[0])
    return prior, pins, names, text, initial


def input_receipt(name, expected_path, pin):
    summary = INPUT / (name.upper() + "_VERIFIED.json")
    record = load(summary, pin)
    expected = reference(expected_path)
    need(record["production_launch"] is False and record["receipt"] == expected["path"]
         and record["receipt_sha256"] == expected["sha256"], name + " verification receipt changed")
    return record, dict(path=str(summary), sha256=pin)


def native(validation_pin):
    result = load(VALIDATION, validation_pin)
    dep = bind(result["seal"])
    provenance = bind(reference(STATIC / "SOURCE.json"))
    need(result["production_started"] is False and result["seal"] == reference(STATIC / "deployment-seal-receipt.json")
         and dep["destination"] == str(STATIC) and provenance["source_commit"] == GUARD_REV
         and all(result[n] == reference(STATIC / n) for n in ("hold", "guard"))
         and [(r["name"], r["exit"]) for r in result["cases"]] ==
             [("exact", 0), ("foreign-unit", 1), ("other-root", 1), ("oversize", 1)], "fourth native guard not qualified")
    return result


def route(text):
    return text.replace("162-third-replay-", "162-fourth-replay-").replace("hold-162-third", "hold-162-fourth")


def programs(scope_pin, proof, witness_pin):
    sealed = load(OLD_OP / "deployment-seal-receipt.json", OLD_OP_SHA)
    files = {}
    for member in sealed["members"]:
        name = member["name"]
        if not name.endswith(".py"):
            continue
        p = OLD_OP / name
        need(p.parent == OLD_OP and digest(p) == member["sha256"], "third operator member changed")
        s = route(p.read_text()).replace("third162_", "fourth162_")
        if name == "layout.py":
            s = exact(exact(s, OLD_SCOPE_SHA, scope_pin), OLD_GUARD_SHA, proof["guard"]["sha256"])
        elif name == "launch.py":
            s = exact(s, 'q["third_162_predecessor"]', 'q["fourth_162_predecessor"]').replace(
                "different second interval custody", "different third interval custody")
        elif name == "status162.py":
            s = exact(s, 'FIELD = "current_private162_third_hourly"', 'FIELD = "' + FIELD + '"')
            s = exact(s, 'preceding = fleet.get("current_private162_second_reserved")',
                      'preceding = fleet.get("current_private162_third_hourly")')
            s = exact(s, 'preceding["producer_invocation_id"] == "c64af2c83b994e299e375b44dee7ce21"',
                      'preceding["producer_invocation_id"] == "' + OLD_IID + '"')
            s = s.replace("second 162 replay or custody changed", "third 162 replay or custody changed")
        elif name == "terminal_bank.py":
            s = exact(s, str(PRIVATE / "epoch162-next-input-20261128.j9SpisbY/TERMINAL_BANK_WITNESS.json"), str(WITNESS))
            s = exact(exact(s, OLD_WITNESS_SHA, witness_pin), "TARGET = 70004937", "TARGET = 70011988")
        elif name == "close.py":
            s = exact(s, "(69998120,6818)", "(70004938,7051)")
            s = s.replace("70004937", "70011988").replace("69998119", "70004937")
            s = s.replace("third interval", "fourth interval").replace("third manifest", "fourth manifest")
        else:
            raise ValueError("unrecognized previous operator " + name)
        compile(s, name, "exec")
        files[name] = s.encode()
    need(set(files) == {"layout.py", "launch.py", "close.py", "status162.py", "terminal_bank.py"}, "incomplete operator")
    return files


def qualify(bootstrap_pin, terminal_pin, guard_pin, revision=None):
    prior, pins, names, names_text, initial = source()
    proof = native(guard_pin)
    boot_verify, boot_summary = input_receipt("bootstrap", INPUT / "incoming/BOOTSTRAP_CUSTODY.json", bootstrap_pin)
    end_verify, end_summary = input_receipt("terminal", WITNESS, terminal_pin)
    witness = load(WITNESS, end_verify["receipt_sha256"])
    validate_source(pins[1], witness, SLOTS[1], GENERATIONS[1], SIZES[1], names[1])
    need(witness["invocation_id"] and witness["payload_stored"] is False and witness["reader_sha256"] == initial["reader_sha256"]
         and witness["schema"] == "horizon-162-fourth-independent-v156-bank-v1", "fourth terminal reader changed")
    snap, custody = local_bootstrap(pins[0], initial, inputs=INPUT, slot=SLOTS[0], generation=GENERATIONS[0], size=SIZES[0])
    need(custody["sha256"] == boot_verify["receipt_sha256"], "bootstrap custody was replaced")
    schema = programs("0" * 64, proof, end_verify["receipt_sha256"])
    bank = {"__name__":"fixture"}
    exec(compile(schema["terminal_bank.py"], "terminal_bank.py", "exec"), bank)
    fixture = bank["fixture"]()
    need(bank["TARGET"] == SLOTS[1] and bank["UNIT"] == UNIT and fixture["negative"] == 7, "wrong scoped Bank comparison")
    result = dict(first=SLOTS[0]+1, last=SLOTS[1], positions=SLOTS[1]-SLOTS[0], names=names, bank_fixture=fixture,
                  previous=reference(PRIOR), bootstrap=custody, terminal=reference(WITNESS), native=reference(VALIDATION))
    if revision is None:
        return result
    checkout = HERE.parents[1]
    git = ["git", "-c", "safe.directory="+str(checkout), "-C", str(checkout)]
    for commit in (revision, GUARD_REV):
        subprocess.run([*git, "merge-base", "--is-ancestor", commit, "origin/account-updates"], check=True)
    inputs = {}
    for filename in ("second_interval.py", "third_inputs.py", "third_interval.py", "fourth_interval.py"):
        p = HERE / filename
        spec = revision + ":" + str(p.relative_to(checkout))
        need(subprocess.check_output([*git, "show", spec]) == p.read_bytes(), "unpublished interval source " + filename)
        inputs[str(p.relative_to(checkout))] = digest(p)
    need(BASE.stat().st_uid == 0 and BASE.resolve() == BASE and not BASE.stat().st_mode & 0o077
         and BASE.stat().st_dev == PRIVATE.stat().st_dev and os.geteuid() == 0, "unsafe control root")
    save = runpy.run_path(str(OLD_OP/"layout.py"))["save"]
    names_ref = save(NAMES, names_text)
    need(names_ref["sha256"] == NAMES_SHA, "checkpoint order changed")
    profile = successor_profile(prior, names, snap, proof, SLOTS, OLD, BASE, ALIAS, NAMES, "hold-162-fourth", route)
    keep = ("capped_worker", "node", "producer_ram", "guard_ram", "producer_cpu_micros", "guard_cpu_micros",
            "tmpfs_bytes", "control_bytes", "mutable_image_bytes", "unreleased_predecessor", "postguard_predecessor")
    scope = dict({k: prior[k] for k in keep}, schema="horizon-private-162-fourth-native-contract-v1",
        first_slot=SLOTS[0]+1, last_slot=SLOTS[1], position_count=SLOTS[1]-SLOTS[0], profile=profile,
        bootstrap=dict(verified_local_custody=custody, witness=prior["terminal"]["terminal_witness"],
                       bank_hash=initial["bank"]["bank_hash"], account_hash=initial["accounts_hash"],
                       archive_sha256=initial["raw_archive_readback"]["sha256"], generation=GENERATIONS[0]),
        terminal=dict(terminal_witness=reference(WITNESS), bank_hash=witness["bank"]["bank_hash"],
                      accounts_hash=witness["accounts_hash"], generation=GENERATIONS[1]),
        previous=reference(PRIOR), previous_interface=reference(OLD/"INTERFACE.json"), checkpoint_names=names_ref,
        first_hourly_gate=proof["hold"], first_hourly_guard=proof["guard"], gate_deployment=proof["seal"],
        guard_deployment=proof["seal"], native_guard_validation=reference(VALIDATION), input_pair=reference(PAIR),
        input_verifications=[boot_summary,end_summary], source_commit=revision, canonical_publication_authorized=False)
    scope_ref = save(BASE/"SCOPE.json", scope, 0o400)
    staging = BASE/"operator-source-v1"
    staging.mkdir(mode=0o700, exist_ok=True)
    need(staging.resolve() == staging and staging.stat().st_uid == 0 and not staging.stat().st_mode & 0o077,
         "unsafe staging")
    provider = programs(scope_ref["sha256"], proof, end_verify["receipt_sha256"])
    files = {}
    for name, raw in provider.items():
        save(staging/name, raw)
        files[name] = (staging/name, 0o444)
    origin = staging/"ORIGIN.json"
    save(origin, dict(revision=revision, native=GUARD_REV, sources=inputs, previous_operator=reference(OLD_OP/"deployment-seal-receipt.json"),
                      scope=scope_ref, native_guard=proof["seal"], previous=reference(PRIOR), verified_inputs=[boot_summary,end_summary]))
    files[origin.name] = (origin, 0o444)
    package = second.seal(files, BASE/"operator-v1", save, plan_root=BASE)
    result["interface"] = save(BASE/"INTERFACE.json",dict(unit=UNIT, field=FIELD, provider=package, reader=reference(BASE/"operator-v1/status162.py"),
        scope=scope_ref, first_slot=SLOTS[0]+1,last_slot=SLOTS[1],previous=reference(PRIOR),guard_validation=reference(VALIDATION),
        gate=proof["hold"],guard=proof["guard"],bootstrap=scope["bootstrap"],terminal=scope["terminal"]),0o400)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bootstrap_verify_sha")
    parser.add_argument("terminal_verify_sha")
    parser.add_argument("guard_validation_sha")
    parser.add_argument("--prepare", metavar="COMMIT")
    args = parser.parse_args()
    print(json.dumps(qualify(args.bootstrap_verify_sha, args.terminal_verify_sha, args.guard_validation_sha, args.prepare), sort_keys=True))
