"""Seal the guarded V13q build and its exact post-verification provider."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

runtime = Path("/var/lib/jetstreamer/horizon_runtime_data")
sys.path.insert(0, str(runtime / "prefix140-status-cadence-20261122-v1/cadence-tools"))
from evidence import SEALER, bound, checked, durable, need, raw, syncdir

sealer = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment"
need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode
     and (len(sys.argv) == 2 or sys.argv[2:] in (["--v7"], ["--v9"])),
     "run as root with python3 -IB seal-v13q.py STAGE [--v7|--v9]")
generation = sys.argv[2][2:] if len(sys.argv) == 3 else "v6"
retry5 = generation in ("v7", "v9")
stage = Path(sys.argv[1])
need(stage.is_absolute() and stage.resolve(strict=True) == stage and stage.is_dir(), "invalid V13q build stage")
checkout = stage.parent / "source"
continuity = runtime / "epoch145-semantic-continuity-20261121-v1"
worker = continuity / {"v6": "tools-v13q", "v7": "tools-v13r", "v9": "tools-v13s"}[generation]
fit = runtime / "incident-replay-fit-20261121-v1"
provider = fit / f"tools-homefloor-145-post-{generation}-current-v1"
original_provider = fit / f"tools-homefloor-145-post-{generation}-build-v1"
evidence = stage / "evidence"
source = stage / "source"
worker_source = Path("scripts/horizon_epoch145_guarded_export_20261121_v1")
fit_source = Path("scripts/horizon_incident_replay_fit_20261121_v1")
semantic_owner, semantic_package_name, semantic_handoff_name, semantic_seal = {
    "v6": ("a71285e56d674de3bf793692f93dfbb3", "tools-v6-guard-walk", "v6-guard-walk-name-handoff", None),
    "v7": ("f7043fd6595a4151b659d4b098bede11", "tools-v7-168-stop-v2", "v7-168-stop-name-handoff",
           "589d1da9f51c305be8699a9dc01e443c9ec2367d1f67e7905ba67fdeb0d35c7b"),
    "v9": ("ebdfc34db47c4e7699ea5ccbada5d604", "tools-v9-census-recovery", "v9-census-name-handoff",
           "8766c269034824f114eb1906e1913188f615309b51243e8e23ca111936efeebd"),
}[generation]
semantic_package = continuity / semantic_package_name
semantic_handoff = continuity / semantic_handoff_name
semantic_schema = ("horizon-epoch145-v8-census-successor-semantic-completion-v1" if generation == "v9"
                   else "horizon-epoch145-v5z-custody-successor-semantic-completion-v1")
reader_commit = "e15f71a2a84c9f256c6fc3d5da34e9354430e702"

def git(*args):
    return subprocess.check_output(["/usr/sbin/runuser", "-u", "sol", "--", "/usr/bin/git", "-C", str(checkout), *args])

def compiled_file(inputs, relative):
    path = source / relative
    need(bound(path)["sha256"] == inputs["native_source"][str(relative)], f"unbound post source {relative}")
    return path

def source_containment(inputs, closure, commit, fetched):
    git("merge-base", "--is-ancestor", commit, fetched)
    delta = git("diff", "--name-only", commit, fetched, "--", *map(str, closure)).decode().splitlines()
    provider_paths = {str(fit_source / name) for name in ("post-stop-fit", "retry4_status.py")}
    need(set(delta) <= provider_paths, "fetched branch changed a qualified verifier input")
    files = {}
    for path in closure:
        digest = hashlib.sha256(git("show", f"{commit}:{path}")).hexdigest()
        need(digest == bound(compiled_file(inputs, path))["sha256"], f"staged bytes differ from merged source {path}")
        files[str(path)] = digest
    return {"source_commit":commit, "fetched_tip":fetched, "files":files,
            "later_provider_source_paths":delta, "archive_publication_authorized":False}

def member(name, path, mode):
    return dict(name=name, source=str(path), sha256=bound(path)["sha256"], mode=mode)

def seal(label, destination, members):
    plan = stage / f"{label}-seal-plan.json"
    durable(plan, dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(destination), members=members))
    plan_ref = bound(plan)
    if not os.path.lexists(destination):
        subprocess.run([sealer, str(plan), "--plan-sha256", plan_ref["sha256"],
                        "--self-sha256", SEALER], check=True, timeout=60)
    ref = bound(destination / "deployment-seal-receipt.json")
    receipt = checked(ref)
    need(receipt["destination"] == str(destination) and receipt["sealer_sha256"] == SEALER
         and receipt["plan_sha256"] == plan_ref["sha256"]
         and receipt["remote_mutations"] is False and
         {row["name"]:(row["sha256"],row["mode"]) for row in receipt["members"]} ==
         {row["name"]:(row["sha256"],f'{row["mode"]:04o}') for row in members},
         "incomplete new deployment seal")
    for row in receipt["members"]:
        installed = destination / row["name"]
        need(bound(installed)["sha256"] == row["sha256"]
             and stat.S_IMODE(installed.lstat().st_mode) == int(row["mode"], 8),
             "sealed V13q member changed: " + row["name"])
    return ref

source_publication = git("rev-parse", "origin/account-updates").decode().strip()
qualified_build = bound(evidence / "BUILD_PROOF.json")
terminal = bound(evidence / "NATIVE_TERMINAL.json")
build = checked(qualified_build)
stopped = checked(terminal)
inputs = checked(build["inputs"])
quote = checked(build["capacity"])["quote"]
commit = build["source_commit"]
completion_ref = bound(semantic_handoff / "SEMANTIC_COMPLETION.json")
completion = checked(completion_ref)
checker_seal = bound(semantic_package / "deployment-seal-receipt.json") if retry5 else inputs["quote_program_seal"]
need(commit == inputs["source_commit"]
     and build["schema"] == "horizon-epoch145-v13q-guarded-build-v1"
     and build["actor"]["InvocationID"] == stopped["invocation_id"] and stopped["build"] == qualified_build
     and quote["fits"] is True and quote["resource_credit_bytes"] == 0 and not quote["replay_launch_authorized"]
     and quote["phase145"]["stage"] == f"{generation}-semantic-complete-drained"
     and quote["phase145"]["completed_invocation_id"] == completion["invocation_id"] == semantic_owner
     and quote["phase145"]["completion"] == completion["completion"]
     and quote["phase145"]["checker_seal"] == checker_seal
     and (not retry5 or (
          checker_seal["sha256"] == semantic_seal
          and quote["phase145"]["semantic_receipt"] == completion_ref
          and completion["native_success"]["INVOCATION_ID"] == semantic_owner
          and completion["native_success"]["_PID"] == "1"))
     and completion["schema"] == semantic_schema
     and completion["publication_authorized"] is completion["r2_mutations"] is False,
     "different native build provenance")
tracked = [worker_source / name for name in (
    "incident-post-phase.py", "run-incident-post.sh", "reader_bridge.py", "seal-v13q.py")]
tracked += [fit_source / name for name in ("post-stop-fit", "retry4_status.py")]
if retry5:
    tracked += [fit_source / name for name in ("retry5_fit.py", "cold168_actor.py")]
    tracked.append(worker_source / "build_159_price.py")
closure = sorted(set(map(Path, build["merged_source_closure"])) | set(tracked))
source_receipt = stage / "SOURCE_CONTAINMENT.json"
durable(source_receipt, source_containment(inputs, closure, commit, source_publication))
reader_bridge = compiled_file(inputs, worker_source / "reader_bridge.py")
fresh_reader = json.loads(subprocess.check_output(["/usr/bin/python3", "-IB", str(reader_bridge), "--guard-post-preflight"], timeout=45))
need(fresh_reader["qualified_reader_commit"] == reader_commit
   and fresh_reader["fetched_tip"] == source_publication
   and fresh_reader["publication_authorized"] is fresh_reader["r2_mutations"] is False,
   "paired reader equivalence differs from the current branch")
reader_preflight = stage / "READER_PREFLIGHT.json"
durable(reader_preflight, fresh_reader)
tests = Path(build["tests"]["path"])
phase_tests = Path(build["phase_tests"]["path"])
image = evidence / "export145"
need(build["worker"] == bound(image) and build["tests"] == bound(tests)
     and build["phase_tests"] == bound(phase_tests)
     and "test result: ok." in tests.read_text() and "0 failed;" in tests.read_text()
     and ("Ran 6 tests" in phase_tests.read_text() or
          generation != "v9" and "Ran 5 tests" in phase_tests.read_text() or
          generation == "v6" and "Ran 4 tests" in phase_tests.read_text())
     and phase_tests.read_text().endswith("OK\n"),
     "native or phase test results differ")
reader_test = evidence / "native-reader-test.log"
result = reader_test.read_text()
need(build["reader_test"] == bound(reader_test)
     and "post::tests::current_full_and_plugin_use_the_same_qualified_plan_as_delivery ... ok" in result
     and "test result: ok. 1 passed; 0 failed;" in result,
     "the linked verifier did not prove the qualified HTTP retry reader")
adapter = compiled_file(inputs, worker_source / "incident-post-phase.py")
wrapper = compiled_file(inputs, worker_source / "run-incident-post.sh")
post_fit = compiled_file(inputs, fit_source / "post-stop-fit")
status_adapter = compiled_file(inputs, fit_source / "retry4_status.py")
worker_proof = stage / "worker-build-proof.json"
image_hash = build["worker"]["sha256"]
helper = bound(semantic_package / "v5v_semantic_completion.py")
runtime_seal = bound(semantic_package / "deployment-seal-receipt.json")
if retry5:
    startup = completion["startup_evidence"]
    original = bound(semantic_package / "build-proof.json")
    proof = checked(original)
    need(runtime_seal == checker_seal == startup["worker_seal"]
         and startup["worker_build"] == original and proof["semantic_checker"] == helper
         and startup["predecessor_terminal"] == proof["guard_terminal"],
         f"the {generation} semantic deployment changed")
else:
    qualified = checked(bound(stage.parent / "v6-worker-seal-evidence/QUALIFIED_V6.json"))
    need(runtime_seal == qualified["worker"] == completion["startup_evidence"]["worker_seal"]
         and completion["startup_evidence"]["predecessor_terminal"] == qualified["predecessor"],
         "the V6 semantic deployment changed")
semantic_member, = (row for row in checked(runtime_seal)["members"]
                    if row["name"] == "v5v_semantic_completion.py" and row["mode"] == "0444")
need(helper["sha256"] == semantic_member["sha256"], "V6 semantic checker changed")
durable(worker_proof, {"schema":"horizon-145-v5j-post-build-v1",
    "source_commit":commit, "verifier_sha256":image_hash, "native_qualification":qualified_build,
    "native_terminal":terminal, "source_containment":bound(source_receipt),
    "tests":build["tests"], "phase_tests":build["phase_tests"], "build_price":build["capacity"],
    "reader_preflight":bound(reader_preflight), "reader_commit":fresh_reader["qualified_reader_commit"],
    "semantic_checker":helper, "semantic_completion":completion_ref,
    "resource_credit_bytes":0, "archive_body_verified_by_this_build":False})
run_post = stage / "run-post"
template = wrapper.read_text()
need(template.count("PINNED_POST_SHA") == 1, "invalid run-post template")
wrapper_bytes = template.replace("PINNED_POST_SHA", image_hash).encode()
if os.path.lexists(run_post):
    need(raw(run_post) == wrapper_bytes, "existing run-post wrapper differs")
else:
    with run_post.open("xb") as file:
        file.write(wrapper_bytes)
        file.flush()
        os.fchmod(file.fileno(), 0o400)
        os.fsync(file.fileno())
    syncdir(stage)
subprocess.run(["/bin/bash", "-n", str(run_post)], check=True, timeout=10)
worker_ref = seal("worker", worker, [member("export145", image, 0o555), member("run-post", run_post, 0o555),
    member("build-proof.json", worker_proof, 0o444), member(adapter.name, adapter, 0o444),
    member(reader_bridge.name, reader_bridge, 0o444)])
profile = stage / "profile145-v5j-post.json"
durable(profile, dict(image_sha256=image_hash, seal_sha256=worker_ref["sha256"],
                      build_sha256=bound(worker_proof)["sha256"], adapter_sha256=bound(adapter)["sha256"]))
prior_ref = bound(original_provider / "deployment-seal-receipt.json")
prior = checked(prior_ref)
need(prior_ref == inputs["quote_program_seal"] and prior["destination"] == str(original_provider)
     and prior["sealer_sha256"] == SEALER, "unknown predecessor provider")
members = []
for row in prior["members"]:
    name = row["name"]
    path = original_provider / name
    need(bound(path)["sha256"] == row["sha256"]
         and stat.S_IMODE(path.lstat().st_mode) == int(row["mode"], 8), "changed predecessor provider")
    if name not in (profile.name, post_fit.name, status_adapter.name, "incident-phase.py", "incident-post-phase.py"):
        members.append(member(name, path, int(row["mode"], 8)))
members.extend([member(profile.name, profile, 0o444), member(post_fit.name, post_fit, 0o555),
                member(status_adapter.name, status_adapter, 0o444)])
provider_ref = seal("provider", provider, members)
result = stage / {"v6": "SEALED_V13Q.json", "v7": "SEALED_V13R.json", "v9": "SEALED_V13S.json"}[generation]
durable(result, {"source_commit":commit, "native_qualification":qualified_build, "native_terminal":terminal,
                 "seal_operator":bound(Path(__file__).resolve()),
                 "source_containment":bound(source_receipt), "reader_preflight":bound(reader_preflight),
                 "semantic_completion":completion_ref,
                 "worker":worker_ref, "provider":provider_ref, "predecessor_provider":prior_ref,
                 "post_worker_started":False, "r2_mutations":False})
print(json.dumps(bound(result), sort_keys=True))
