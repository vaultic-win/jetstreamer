"""Start publication of a committed singleton after its authenticated fleet status."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import NamedTuple

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import closure
import terminal_event as event

D=event.R/"epoch166-retry10-delivery-20261121-v1"
LAUNCH=D/"capacity-tools-v2/run-committed.sh"
FIT=D/"capacity-tools-v2/publication-fit"
UNIT="horizon-publish-166-retry10-committed.service"
STATE=D/"event-state"

class Publication(NamedTuple):
    epoch: int
    delivery: Path
    launch: Path
    fit: Path
    unit: str
    authority: object


RECOVERED = Publication(166, D, LAUNCH, FIT, UNIT, closure)


def metered():
    import closure168

    delivery = closure168.T
    return Publication(168, delivery, delivery / "controller-tools/run-committed.sh",
                       delivery / "capacity-tools/publication-fit",
                       "horizon-publish-168-metered-committed.service", closure168)


def current_reader(epoch):
    if epoch in (166, 168):
        original = RECOVERED if epoch == 166 else metered()
        capacity = "capacity-tools-v3" if epoch == 166 else "capacity-tools-v2"
        return original._replace(launch=original.delivery / "controller-tools-v2/run-committed.sh",
                                 fit=original.delivery / capacity / "publication-fit")

    import peer_closures

    units = {167: "horizon-publish-167-source-index-committed.service",
             170: "horizon-publish-170-retry10-committed.service"}
    authority = peer_closures.authority(epoch)
    return Publication(epoch, authority.T, authority.T / "controller-tools/run-committed.sh",
                       authority.T / "capacity-tools/publication-fit", units[epoch], authority)


def versioned_reader(epoch, versions):
    prior = current_reader(epoch)
    launcher, capacity = versions[epoch]
    return prior._replace(launch=prior.delivery / f"controller-tools-v{launcher}" / "run-committed.sh",
                          fit=prior.delivery / f"capacity-tools-v{capacity}" / "publication-fit")


def five_source_reader(epoch):
    return versioned_reader(epoch, {166: (3, 4), 167: (2, 2), 168: (3, 3), 170: (2, 2)})


def focused169_reader(epoch):
    return versioned_reader(epoch, {166: (4, 5), 167: (3, 3), 168: (4, 4), 170: (3, 3)})


def paid145_predecessors(epoch):
    if epoch == 172:
        import focused169_full172_event
        import full172_event
        return [(full172_event.profile(), "event-tools-current"),
                (focused169_full172_event.profile(), "event-tools-focused169")]
    return [(current_reader(epoch), "event-tools-current"),
            (five_source_reader(epoch), "event-tools-five-v1"),
            (focused169_reader(epoch), "event-tools-focused169")]


def paid145_reader(epoch):
    prior = paid145_predecessors(epoch)[-1][0]
    return prior._replace(launch=prior.delivery/"controller-tools-paid145/run-committed.sh",
                          fit=prior.delivery/"capacity-tools-paid145/publication-fit")


def bounded_reader(epoch):
    prior = paid145_reader(epoch)
    return prior._replace(launch=prior.delivery/"controller-tools-bounded/run-committed.sh",
                          fit=prior.delivery/"capacity-tools-bounded/publication-fit")


def bounded_predecessors(epoch):
    previous = paid145_predecessors(epoch)
    paid = paid145_reader(epoch)
    # Some installations sealed the paid controller without installing its event handler.
    if (paid.delivery/"event-tools-paid145/programs.json").exists():
        previous.append((paid, "event-tools-paid145"))
    return previous


def status_evidence(fleet, report, terminal, archive, profile=RECOVERED):
    key = str(profile.epoch)
    ref = report["receipts"][key]
    row,actual=event.document(Path(ref["path"]),0o600)
    observed=fleet["observer"]
    predecessor,prior=event.document(Path(row["previous_receipt"]["path"]),0o600)
    raw=(json.dumps(row["after_status"],sort_keys=True,separators=(",",":"))+"\n").encode()
    event.need(actual==ref==fleet["effective_status_receipts"][key] and row["epoch"]==profile.epoch and
               row["key"]==f"epoch-{key}.epoch-status.json" and row["observer"]==observed and
               row["previous_receipt"]==prior and predecessor["authenticated_readback"] and
               row["before_etag"]==predecessor["after_etag"] and row["before_sha256"]==predecessor["after_sha256"] and
               row["before_status"]==predecessor["after_status"] and row["after_sha256"]==hashlib.sha256(raw).hexdigest() and
               row["authenticated_readback"] is True and row["conditional_header"]=="If-Match" and
               row["current_repair_owner"]=="/root" and row["producer_invocation_id"] is None and
               row[profile.authority.FIELD]==terminal and row["after_status"]["phase"]=="verification" and
               row["archive_sample"]==archive and
               row["after_status"]["jet_size_bytes"]==row["archive_sample"]["size"] and row["after_etag"],
               "cadence did not read back the committed local source")
    return ref

def head(fleet):
    current,_=event.document(Path(fleet["path"]),0o600)
    timer=current["sole_next_timer"];name=timer if isinstance(timer,str) else timer["unit"]
    mo=re.fullmatch(r"horizon-observer-(root[0-9]{6}-live166167170-[0-9]{8}-v1)\.timer",name)
    event.need(mo is not None,"foreign scheduled successor")
    if (event.R/mo.group(1)/event.FLEET_NAME).exists():return None
    return event.document(Path(fleet["path"]),0o600)[1]

def bound_fit(profile, bindings):
    programs = {p.name: event.member(p, 0o555)[1] for p in (profile.fit, profile.launch)}
    event.need(programs == bindings, "changed qualified publication programs")
    return programs[profile.fit.name]["sha256"]


def main(profile=RECOVERED, recover=False, predecessor=None, *, predecessors=()):
    if predecessor is not None:
        event.need(not predecessors, "conflicting predecessor registrations")
        predecessors = ((predecessor, "event-tools-current"),)
    authority = profile.authority
    state = profile.delivery / "event-state"
    def status(fleet, report, terminal):
        archive = event.document(authority.T / "TERMINAL_SUCCESS.json", 0o400)[0]["local_archive"]
        return status_evidence(fleet, report, terminal, archive, profile)

    event.need(os.geteuid()==0 and __debug__ and sys.flags.isolated,"isolated root required")
    bindings,_=event.document(HERE/"programs.json",0o444)
    fit_sha=bound_fit(profile, bindings)
    original=authority.retire()["terminal"]
    m=state.lstat()
    event.need(state.resolve(strict=True)==state and m.st_uid==m.st_gid==0 and stat.S_IMODE(m.st_mode)==0o700,"untrusted event state")
    with (state/"event.lock").open("a+b") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if recover:
            import publication_recovery
            changes = event.Changes()
            try:
                def accepted():
                    return event.accepted(event.R, event.REPORTS, original, changes, head, time.time(), authority.FIELD, status)
                allowed = {}
                for predecessor, package in predecessors:
                    previous, _ = event.document(profile.delivery / package / "programs.json", 0o444)
                    allowed[str(predecessor.launch)] = bound_fit(predecessor, previous)
                result = publication_recovery.service(profile, state, original, fit_sha, accepted, changes, allowed)
                print(json.dumps(result), flush=True)
            finally:
                changes.close()
            return
        if (state/"INTENT.json").exists():
            old,_=event.document(state/"INTENT.json",0o400)
            event.need(old["terminal"]==original and old["unit"]==profile.unit,"uncertain original submission differs")
            print(json.dumps(dict(disposition="existing-intent",manager=event.manager(profile.unit))))
            return
        changes=event.Changes()
        try:
            def accepted():
                return event.accepted(event.R,event.REPORTS,original,changes,head,time.time(),authority.FIELD,status)
            while True:
                proof=accepted()
                if proof:
                    socket=event.agents()
                    event.need(authority.inspect()["terminal"]==original,"terminal changed before submission")
                    if accepted()!=proof:continue
                    def launch(fleet,socket):
                        subprocess.run([profile.launch,"sync",fleet["path"],fleet["sha256"],socket,fit_sha],check=True,timeout=45)
                        return event.manager(profile.unit)
                    print(event.submit(state,original,proof,socket,launch,lambda t:event.previous(t,profile.delivery,profile.unit),profile.unit,profile.launch,fit_sha),flush=True)
                    return
                changes.wait()
        finally:
            changes.close()

if __name__ == "__main__":
    if sys.argv[1:] == ["--metered168"]:
        main(metered())
    elif len(sys.argv) == 3 and sys.argv[1] == "--current-reader" and sys.argv[2] in ("166", "167", "168", "170"):
        main(current_reader(int(sys.argv[2])), recover=True)
    elif len(sys.argv) == 3 and sys.argv[1] == "--five-source-reader" and sys.argv[2] in ("166", "167", "168", "170"):
        epoch = int(sys.argv[2])
        main(five_source_reader(epoch), recover=True, predecessor=current_reader(epoch))
    elif len(sys.argv) == 3 and sys.argv[1] == "--focused169-reader" and sys.argv[2] in ("166", "167", "168", "170"):
        epoch = int(sys.argv[2])
        main(focused169_reader(epoch), recover=True,
             predecessors=[(current_reader(epoch), "event-tools-current"), (five_source_reader(epoch), "event-tools-five-v1")])
    elif len(sys.argv) == 3 and sys.argv[1] == "--bounded-reader" and sys.argv[2] in ("166", "167", "168", "170", "172"):
        epoch = int(sys.argv[2])
        main(bounded_reader(epoch), recover=True, predecessors=bounded_predecessors(epoch))
    elif len(sys.argv) == 3 and sys.argv[1] == "--paid145-reader" and sys.argv[2] in ("166", "167", "168", "170", "172"):
        epoch = int(sys.argv[2])
        main(paid145_reader(epoch), recover=True, predecessors=paid145_predecessors(epoch))
    elif len(sys.argv) == 1:
        main()
    else:
        sys.exit("usage: retry10_event.py [--metered168 | (--current-reader | --five-source-reader | --focused169-reader) {166,167,168,170} | (--paid145-reader | --bounded-reader) {166,167,168,170,172}]")
