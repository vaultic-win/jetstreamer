"""Check the five publication event profiles against the original archives and event history."""
import itertools
import json
from pathlib import Path
import sys

here = Path(__file__).resolve().parent
sys.path[:0] = [str(here), str(here.parent / "horizon_epoch166_delivery_20261121_v1")]
import publication_recovery as recovery
import qualify_full172_event as fixture
import retry10_event as publication
import terminal_event as event

EPOCHS = (166, 167, 168, 170, 172)
FAMILY = event.R / "incident-replay-fit-20261121-v1"


def checked(ref, mode):
    body, actual = event.document(Path(ref["path"]), mode)
    event.need(ref == actual, "changed qualification evidence")
    return body


def status_rows(profile_for=publication.paid145_reader):
    cadence, ref = event.document(fixture.CADENCE, 0o600)
    event.need(ref["sha256"] == "a5ff0f41a934b1eb8a1b53a5f378eb0f02e39a3384de8eb07940d5f9c22ba2a8",
               "different five-source cadence fixture")
    rows = {epoch: [] for epoch in EPOCHS}
    for case in cadence["fixture_status_and_fleet_passes"]:
        report = checked(case["report"], 0o600)
        fleet = dict(observer=report["observer"], effective_status_receipts=report["receipts"])
        for epoch in case["closed"]:
            profile = profile_for(epoch)
            original = checked(cadence["singleton_fixtures"][str(epoch)], 0o400)
            status = report["receipts"][str(epoch)]
            terminal = checked(status, 0o600)[profile.authority.FIELD]
            archive = original["local_archive"]
            event.need(checked(terminal, 0o600)["local_archive"] == archive, "different fixture archive")
            found = publication.status_evidence(fleet, report, terminal, archive, profile)
            event.need(found == status, "different status readback")
            rows[epoch].append(found)
    event.need(all(rows.values()), "missing epoch in status fixtures")
    return rows


def qualify(digest, work, *, bounded=False):
    if bounded:
        current_name = "BOUNDED_FIVE_PUBLICATION_CONTROLLERS.json"
        prior_name = "FIVE_PAID145_PUBLICATION_CONTROLLERS.json"
        prior_digest = "5eb7102ef2b71689e0d956b2e60ae31ae6d36284e9a80f3247a9c99a8e0bbbd3"
        profile_for = publication.bounded_reader
        predecessors = publication.bounded_predecessors
    else:
        current_name = "FIVE_PAID145_PUBLICATION_CONTROLLERS.json"
        prior_name = "FIVE_V13_PUBLICATION_CONTROLLERS.json"
        prior_digest = "105bf534a321a4ca11679ef6485048b34e5eb734436c2b7d3a4c5817aa341e9b"
        profile_for = publication.paid145_reader
        predecessors = publication.paid145_predecessors
    current, manifest = event.document(FAMILY / current_name, 0o400)
    old, prior = event.document(FAMILY / prior_name, 0o400)
    event.need(manifest["sha256"] == digest and prior["sha256"] == prior_digest
               and set(current["epochs"]) == set(map(str, EPOCHS)), "unregistered controller handoff")
    prices = checked(current["capacity"], 0o400)
    statuses = status_rows(profile_for)
    rows = {}
    for epoch in EPOCHS:
        label = str(epoch)
        profile = profile_for(epoch)
        item = current["epochs"][label]
        price = prices["epochs"][label]
        event.need(item["epoch"] == epoch and item["predecessor_controller"] == old["epochs"][label]["controller"]
                   and item["provider"] == price["executable"], "crossed epoch handoff")
        programs = {profile.launch.name: item["launcher"], profile.fit.name: item["provider"]}
        publication.bound_fit(profile, programs)
        for exe, seal in ((profile.fit, price["seal"]), (profile.launch, item["controller"])):
            record = checked(seal, 0o444)
            event.need(record["destination"] == str(exe.parent) and any(m["name"] == exe.name and
                       m["sha256"] == programs[exe.name]["sha256"] and m["mode"] == "0555"
                       for m in record["members"]), "unsealed program")
        registered = {}
        for old_profile, package in predecessors(epoch):
            previous, binding = event.document(old_profile.delivery / package / "programs.json", 0o444)
            old_fit = publication.bound_fit(old_profile, previous)
            event.need((profile.unit, profile.authority.FIELD, profile.authority.T) ==
                       (old_profile.unit, old_profile.authority.FIELD, old_profile.authority.T), "changed original owner")
            terminal = checked(statuses[epoch][-1], 0o600)[profile.authority.FIELD]
            state = work / f"{epoch}-{package}"
            state.mkdir(mode=0o700)
            event.once(state / "INTENT.json", dict(terminal=terminal, unit=profile.unit, prior=None, boot=recovery.boot(),
                       recovery_schema=recovery.VERSION, controller=str(old_profile.launch), provider_sha256=old_fit))
            registered[str(old_profile.launch)] = dict(programs=binding, fit=old_fit)
            allowed = {name: pair["fit"] for name, pair in registered.items()}
            attempts, known = recovery.chain(state, terminal, profile, allowed)
            event.need(len(attempts) == 1 and not known, "lost prior intent")
        rows[epoch] = dict(programs=programs, prior=registered, statuses=statuses[epoch])
    crossed = 0
    for a, b in itertools.permutations(EPOCHS, 2):
        for name in rows[b]["programs"]:
            try:
                publication.bound_fit(profile_for(a), {**rows[a]["programs"], name: rows[b]["programs"][name]})
            except event.Rejected:
                crossed += 1
    event.need(crossed == 40 and sum(len(row["prior"]) for row in rows.values()) == sum(len(predecessors(e)) for e in EPOCHS), "incomplete event coverage")
    return dict(manifest=manifest, prior=prior, epochs=rows, crossed_refused=crossed, production_dispatches=0)


if __name__ == "__main__":
    args = sys.argv[1:]
    bounded = args[:1] == ["--bounded"]
    if bounded:
        args = args[1:]
    digest, directory = args
    print(json.dumps(qualify(digest, Path(directory), bounded=bounded), sort_keys=True))
