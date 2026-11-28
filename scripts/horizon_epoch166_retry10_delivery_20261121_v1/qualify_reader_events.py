"""Join the four actual publisher profiles to the scheduled completion fixtures."""
import datetime as dt
import json
from pathlib import Path
import shutil

import retry10_event as publication
import terminal_event as event


def load(ref, mode):
    value, observed = event.document(Path(ref["path"]), mode)
    event.need(ref == observed, "qualification reference changed")
    return value


def qualify(cadence, capacity, work):
    profiles = {e: publication.current_reader(e) for e in event.PUBLICATION_EPOCHS}
    prices = load(capacity, 0o400)["epochs"]
    controllers = {}
    refusals = []
    for epoch, profile in profiles.items():
        filename = "READER_SUCCESSOR_QUALIFIED.json" if epoch in (166, 168) else "HELD_PUBLICATION_QUALIFIED.json"
        handoff, handoff_ref = event.document(profile.delivery / filename, 0o400)
        seal = load(handoff["controller"], 0o444)
        launch = event.member(profile.launch, 0o555)[1]
        event.need(handoff["epoch"] == epoch and handoff["r2_writes"] == 0
                   and Path(seal["destination"]) == profile.launch.parent
                   and any(m["name"] == profile.launch.name and m["sha256"] == launch["sha256"] for m in seal["members"]),
                   "different qualified controller")
        if epoch in (166, 168):
            event.need(Path(handoff["provider_path"]) == profile.fit and handoff["launcher"] == launch,
                       "unexpected publication successor")
        price = prices[str(epoch)]
        bindings = {profile.fit.name: price["executable"], profile.launch.name: launch}
        fit_sha = publication.bound_fit(profile, bindings)
        price_seal = load(price["seal"], 0o444)
        event.need(Path(price_seal["destination"]) == profile.fit.parent and any(
            m["name"] == profile.fit.name and m["sha256"] == fit_sha for m in price_seal["members"]),
            "different qualified price")
        controllers[epoch] = dict(handoff=handoff_ref, programs=bindings, unit=profile.unit)

    for epoch, current in controllers.items():
        for other_epoch, other in controllers.items():
            if other_epoch == epoch:
                continue
            for name, foreign in other["programs"].items():
                crossed = dict(current["programs"], **{name: foreign})
                try:
                    publication.bound_fit(profiles[epoch], crossed)
                except event.Rejected:
                    refusals.append(dict(epoch=epoch, crossed_with=other_epoch, program=name))
                else:
                    raise AssertionError(f"accepted epoch {other_epoch} {name} for {epoch}")

    source = load(cadence, 0o600)
    fleet = load(source["base_fleet"], 0o600)
    checks = []
    dispatches = []
    for index, case in enumerate(source["fixture_status_and_fleet_passes"]):
        group = case["closed"]
        runtime = work / str(index) / "runtime"
        reports = runtime.parent / "reports"
        original = Path(case["report"]["path"])
        report = load(case["report"], 0o600)
        clock = dt.datetime.fromisoformat(report["sampled_at_utc"])
        tag, day = clock.strftime("%H%M%S"), clock.strftime("%Y%m%d")
        directory = runtime / f"root{tag}-live166167170-{day}-v1"
        base = reports / f"cycle{tag}-live166167170-19-{day}-v1"
        folder = event.completion_report_dir(base, group)
        directory.mkdir(parents=True)
        folder.mkdir(parents=True)
        saved = folder / "COMPLETED.json"
        shutil.copyfile(original, saved)
        saved.chmod(0o600)
        _, report_ref = event.document(saved, 0o600)
        terminals = {}
        for epoch in group:
            field = event.report_labels()[epoch] + "_local_commit"
            receipt = load(report["receipts"][str(epoch)], 0o600)
            terminals[field] = receipt[field]
        candidate = dict(fleet, **terminals, authenticated_status_audit=report_ref,
                         effective_status_receipts=report["receipts"])
        path = directory / event.FLEET_NAME
        path.write_text(json.dumps(candidate))
        path.chmod(0o600)
        _, fleet_ref = event.document(path, 0o600)
        watcher = event.Changes()
        try:
            for epoch in (e for e in group if e in profiles):
                profile = profiles[epoch]
                field = profile.authority.FIELD
                terminal = terminals[field]
                archive = load(terminal, 0o600)["local_archive"]
                def status(fleet, report, terminal):
                    return publication.status_evidence(fleet, report, terminal, archive, profile)
                now = fleet["recorded_unix_seconds"]
                proof = event.accepted(runtime, reports, terminal, watcher, lambda ref: ref, now, field, status)
                expected = dict(fleet=fleet_ref, report=report_ref, status=report["receipts"][str(epoch)])
                event.need(proof == expected, "incomplete event proof")
                event.need(event.accepted(runtime, reports, terminal, watcher, lambda _: None, now, field, status) is None,
                           "superseded fleet accepted")
                checks.append(dict(epoch=epoch, report=case["report"], status=expected["status"]))
                if epoch not in [d["epoch"] for d in dispatches]:
                    state = work / f"submission-{epoch}"
                    state.mkdir()
                    launches = []
                    def launch(ref, socket):
                        launches.append(ref)
                        return {"unit": profile.unit}
                    def submit():
                        return event.submit(state, terminal, proof, "/fixture/agent", launch, lambda _: None,
                                            profile.unit, profile.launch, "a" * 64)
                    event.need(submit() == "submitted" and submit() == "already-submitted-or-uncertain"
                               and launches == [fleet_ref], "duplicate or missing fixture dispatch")
                    dispatches.append(dict(epoch=epoch, unit=profile.unit, submission=event.document(
                        state / "SUBMISSION.json", 0o400)[1]))
        finally:
            watcher.close()
    event.need({d["epoch"] for d in dispatches} == set(profiles) and len(checks) ==
               sum(len(set(c["closed"]) & set(profiles)) for c in source["fixture_status_and_fleet_passes"]), "missing publication profile")
    return dict(cadence=cadence, capacity=capacity, controllers=controllers, checked=checks,
                crossed_program_refusals=refusals, fixture_dispatches=dispatches,
                production_dispatches=0, r2_writes=0)
