"""Admit the fourth private 169 gate against the complete fleet price and active cadence."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time


BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = BASE / "epoch169-hourly-retry-20261128-v4"
OP = ROOT / "operator-v1"
ISSUED = ROOT / "issuer-v1"
SHARED = BASE / "epoch162-first-hourly-completion-20261127-v2/issued-price-v13"
PREDECESSOR = BASE / "epoch169-hourly-retry-20261128-v2/issuer-v1"
PROGRESS = "f3b52be3ead4604505e854bd20c9fc1ec36d278c6f1fc15fc6eb54b3e78ea4ac"
GEOMETRY = "c92dcb9d238e1aff668adfcd5c4bb479bbe1d1458868058ac040326e81149788"
SCOPE = "f74d0b1dd33abe2b03705f3c69af3a74b27784bb293f69aff1f913fecf24ddb5"
OPERATOR = "c87a140777cc4e94cd3db1b60ac2ee5f022d2a4d24bfa5ffd2110c4a7b3c2148"
PEER = "6bbf689919cd0446f0621914257e3a86291e7ddd7abce7a0c4ac326cb2651ad1"
V12 = "df17ab9a76fe24273e807d32f49d3b8b5287e8be4885ac339d3370323652c302"
G = 1 << 30


def load():
    path = PREDECESSOR / "second_joint.py"
    if hashlib.sha256(path.read_bytes()).hexdigest() != GEOMETRY:
        raise ValueError("changed 169 operator loader or price geometry")
    template = runpy.run_path(str(path))
    template["load"].__globals__.update(OP=OP, OP_SHA=OPERATOR)
    return template["load"](), template["geometry"]


def verify_provider(owner, digest):
    c, quote = owner["c"], owner["quote"]
    result = quote.verified_provider(SHARED, digest)
    source, _ = c.read(SHARED / "SOURCE.json")
    c.stable(SHARED / "retry169_peer.py", expected=PEER, sealed=True)
    c.need(source["fourth_169_scope"] == SCOPE and source["fourth_169_peer"] == PEER
           and source["v12_provider"] == dict(path=str(SHARED.with_name("issued-price-v12") / "deployment-seal-receipt.json"), sha256=V12),
           "unrecognized fourth 169 shared roster")
    return result


def install(owner, digest, commit, observed):
    c = owner["c"]
    scope, scope_ref = c.read(ROOT / "SCOPE.json", SCOPE)
    provider = verify_provider(owner, digest)
    need = c.need
    need(not os.path.lexists(ISSUED) and not any(os.path.lexists(ROOT / n) for n in
         ("PRESTART.json", "HELD_GATE.json", "GUARD_PLAN.json", "START_INTENT.json", "GRANT.json")),
         "fourth 169 already issued")
    me = Path(__file__).resolve()
    key = "scripts/horizon_epoch169_hourly_retry/fourth_joint.py"
    body = me.read_bytes()
    for revision in (commit, observed):
        need(subprocess.check_output(["git", "show", revision + ":" + key], cwd=me.parent) == body, "unmerged fourth issuer")
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, observed], cwd=me.parent, check=True)
    stage = Path(tempfile.mkdtemp(prefix="fourth-issuer-source.", dir=ROOT))
    (stage / me.name).write_bytes(body)
    progress = c.stable(PREDECESSOR / "first_progress.py", expected=PROGRESS, sealed=True, keep_bytes=True)[1]
    (stage / "first_progress.py").write_bytes(progress)
    c.recorded(stage / "SOURCE.json", dict(scope=scope_ref, operator=scope["operator"],
               third_unreleased=scope["third_unreleased"], common_provider=provider, peer_sha256=PEER,
               source_commit=commit, remote_observed=observed, remote_contains_commit=True,
               canonical_publication_authorized=False))
    members = [dict(name=p.name, source=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest(), mode=0o444)
               for p in sorted(stage.iterdir())]
    ref = c.recorded(ROOT / f"ISSUER_PLAN_{time.time_ns()}.json", dict(schema="jetstreamer-sealed-deployment-plan-v1",
                     destination=str(ISSUED), members=members))
    sealer = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
    sha = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
    c.stable(sealer, expected=sha, sealed=True)
    subprocess.run([str(sealer), ref["path"], "--plan-sha256", ref["sha256"], "--self-sha256", sha], check=True)
    deployed, proof = c.read(ISSUED / "deployment-seal-receipt.json")
    need(deployed["plan_sha256"] == ref["sha256"] and deployed["destination"] == str(ISSUED), "different fourth issuer")
    return proof


def price(owner, geometry, scope, sr, preliminary=False):
    c, q = owner["c"], owner["quote"]
    registered, rr = c.read(ISSUED / "SOURCE.json")
    provider = verify_provider(owner, registered["common_provider"]["sha256"])
    c.need(registered["scope"] == sr == dict(path=str(ROOT / "SCOPE.json"), sha256=SCOPE)
           and registered["common_provider"] == provider and registered["operator"] == scope["operator"]
           and scope["operator"]["sha256"] == OPERATOR and registered["third_unreleased"] == scope["third_unreleased"]
           and registered["peer_sha256"] == PEER, "fourth 169 issuer scope or provider changed")
    prior = q.bound(scope["predecessor"])["retained_incomplete_archive"]
    path = Path(prior["path"])
    initial = c.identity(path.lstat())
    c.need(all(prior[k] == v for k, v in initial.items()), "retained original 169 archive changed")
    loan = q.returned_loan()
    whole = runpy.run_path(str(SHARED / "capacity.py"))["whole_roster"]()
    native = whole["base_169"]["native"]
    booked = native["planned_169_retry"]
    other, actor = native["ram_gap170"], native["independent_retry169"]
    owners = whole["base_169"]["observed_actors"]
    def actor_list(epoch, row):
        return [] if not row else [dict(epoch=epoch, unit=row["unit"], invocation_id=row["invocation"])]
    c.need(whole["package"] == provider and booked["fourth_scope"] == sr and booked["third_scope"] == scope["parent_scope"]
           and booked["third_unreleased"] == scope["third_unreleased"] and booked["second_guard_stop"] == scope["second_guard_stop"]
           and booked["first_unreleased_closure"] == scope["first_gate_closure"]
           and booked["additional_home"] == c.HOME_OUTPUT + c.CONTROL_BYTES and booked["additional_ram"] == 8 * G
           and booked["original_169_guard_retained"] and booked["original_170_guard_cpu_retained"]
           and native["stopped_169_compute_handoff"]["retained_159_ram"] + booked["additional_ram"] == c.RAM
           and native["independent_gap_funding"]["cpu_donor"] == loan["scope"] and not whole["resource_credit_bytes"]
           and (not actor or actor["unit"] == c.UNIT) and (not other or other["phase"] in ("held", "bootstrap", "worker"))
           and [r for r in owners if r["epoch"] == 169] == actor_list(169, actor)
           and [r for r in owners if r["epoch"] == 170] == actor_list(170, other)
           and q.returned_loan() == loan and c.identity(path.lstat()) == initial, "fourth 169 resource or custody lineage changed")
    if not preliminary:
        writer = owner["read_active_writer"](c, whole["writer"])
        ready = q.bound(writer["ready"])
        c.need(ready.get("private169_retry4_scope") == sr and ready.get("private169_retry4_cadence") == scope["cadence_source"]
               and not writer["producer_mutations"], "active writer has not enrolled fourth 169")
    floor, margin = geometry(whole, (other["floor"] or 0) if other else 0, c.HOME_OUTPUT)
    return dict(schema="horizon-169-fourth-guarded-price-v1", scope=sr, recorded_unix=time.time(),
                provider=provider, registration=rr, writer=whole["writer"], returned_159_loan=loan,
                predecessor_custody=scope["predecessor"], third_unreleased=scope["third_unreleased"], whole_roster=whole,
                stage="native-postguard" if actor else "native-prestart", guard_floor=floor, home_margin=margin,
                ram_margin=whole["ram_margin"], fits=bool(whole["fits"] and min(margin, whole["ram_margin"]) >= 0),
                preliminary=preliminary, resource_credit_bytes=0, canonical_publication_authorized=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "prepare-quote", "quote", "launch", "first-progress"))
    parser.add_argument("--provider-sha")
    parser.add_argument("--commit")
    parser.add_argument("--observed")
    args = parser.parse_args()
    owner, geometry = load()
    c = owner["c"]
    if args.action == "install":
        result = install(owner, args.provider_sha, args.commit, args.observed)
    else:
        c.need(Path(__file__).resolve() == ISSUED / "fourth_joint.py", "use the sealed fourth issuer")
        scope, sr = c.read(ROOT / "SCOPE.json", SCOPE)
        if args.action == "first-progress":
            result = runpy.run_path(str(ISSUED / "first_progress.py"))["follow"](owner, scope, sr)
        else:
            with owner["quote"].LOCK.open("rb") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                if args.action == "launch":
                    start = owner["launch"]
                    start.__globals__["funded"] = lambda s, r: price(owner, geometry, s, r)
                    result = start()
                else:
                    fresh = price(owner, geometry, scope, sr, preliminary=args.action == "prepare-quote")
                    result = c.recorded(ROOT / f"JOINT_{time.time_ns()}.json", fresh)
    print(json.dumps(result))
