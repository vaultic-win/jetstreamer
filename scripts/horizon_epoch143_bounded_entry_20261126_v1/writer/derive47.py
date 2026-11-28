"""Derive the next writer from the sealed V46 package, reusing every unchanged member."""

import ast
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from derive41 import one

OLD = "tools-cold168-retry5-failed166-v46-entry146-r2"
NEW = "tools-cold168-retry5-failed166-v47-entry146"
PREVIOUS_SEAL = "4bb23953781c66d9d221d36525f0daae6243d8d667b41bc4388b36be17bc9ea4"
BOOKER_SEAL = "e432ebd05eafc6ad412a52772949408c73b04056345968bc06ad705748a1c9fd"


def cycle(text):
    text = text.replace(", 46)", ", 46, 47)")
    old = "            import rolling170_retry_status as successor170_status"
    text = one(
        text,
        old,
        old
        + """
        if FAILED166_VERSION == 47:
            import transition_v47
            import rolling170_fourth_status as successor170_status""",
    )
    old = "                            successor170_status.history.following, import_module('continuation170_contract')]"
    text = one(
        text,
        old,
        old
        + """
            if FAILED166_VERSION == 47:
                modules += [transition_v47, transition_v46, transition_v45, successor170_status.following,
                            successor170_status.contract, successor170_status.history,
                            successor170_status.history.retry, successor170_status.history.contract,
                            successor170_status.history.history, successor170_status.history.history.previous,
                            successor170_status.history.history.following, import_module('continuation170_contract')]""",
    )
    old = "    elif FAILED166_VERSION == 46:"
    text = one(
        text,
        old,
        """    elif FAILED166_VERSION == 47:
        transition_v47.validate(globals(), ready, receipt)
"""
        + old,
    )
    old = "                46: (transition_v46.V45_SHA, transition_v46.V45_SEAL),"
    text = one(
        text,
        old,
        old
        + "\n                47: (transition_v47.V46_SHA, transition_v47.V46_SEAL),",
    )
    old = "                    46: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"
    text = one(text, old, old + "\n" + old.replace("46:", "47:"))
    old = "    return dict(ready, config=recovered_config) if FAILED166_VERSION == 31 else ready"
    text = one(
        text,
        old,
        """    if FAILED166_VERSION == 47:
        print(json.dumps(dict(epoch143_writer_active=bound(ROOT/'FAILED166_CADENCE_V47_ACTIVE.json'))), flush=True)
"""
        + old,
    )
    old = "    if FAILED166_VERSION == 46 and len(sys.argv) == 4:"
    return one(
        text,
        old,
        """    if FAILED166_VERSION == 47 and len(sys.argv) == 4:
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        if sys.argv[1] == '--check-v47-handoff':
            print(json.dumps(transition_v47.ready(globals(), head, receipt)))
            return
        if sys.argv[1] == '--enroll-next-bounded-170':
            os.umask(0o077)
            writer_ref = bound(ROOT/'FAILED166_CADENCE_V47_ACTIVE.json')
            print(json.dumps(successor170_status.enroll(globals(), head, writer_ref)))
            return
"""
        + old,
    )


def sources(old, digest):
    raw = (old / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("different predecessor deployment")
    seal = json.loads(raw)
    if seal["destination"] != str(old):
        raise ValueError("different predecessor destination")
    for row in seal["members"]:
        path = old / row["name"]
        if (
            path.parent != old
            or path.resolve() != path
            or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]
        ):
            raise ValueError("changed sealed member " + str(path))
        if path.name != "SHA256SUMS":
            yield dict(
                name=path.name,
                source=str(path),
                sha256=row["sha256"],
                mode=int(row["mode"], 8),
            )


def stage(old, staging):
    members = {row["name"]: row for row in sources(old, PREVIOUS_SEAL)}
    staging.mkdir(mode=0o700)

    def add(name, data, mode=0o444):
        if name.endswith(".py"):
            ast.parse(data, filename=name)
        path = staging / name
        path.write_bytes(data)
        path.chmod(mode)
        members[name] = dict(
            name=name,
            source=str(path),
            sha256=hashlib.sha256(data).hexdigest(),
            mode=mode,
        )

    add("status_cycle.py", cycle((old / "status_cycle.py").read_text()).encode())
    for name in ("full170_status.py", "cold170_status.py", "joint168_status.py"):
        current = (old / name).read_text()
        marker = f"'{OLD}')"
        if marker not in current:
            raise ValueError("missing V46 receiver binding " + name)
        add(name, current.replace(marker, f"'{OLD}', '{NEW}')").encode())
    native = (old / "continuation170_retry_native.py").read_text()
    native = one(
        native,
        "from continuation170_retry_contract import",
        "from fourth170_contract import",
    )
    add("fourth170_native.py", native.replace("73746882", "73766969").encode())
    for name in (
        "fourth170_contract.py",
        "rolling170_fourth_status.py",
        "transition_v47.py",
        "watch143_versions.py",
        "watch143_reentry.py",
        "cutover47.py",
    ):
        add(name, (HERE / name).read_bytes())
    return dict(
        schema="jetstreamer-sealed-deployment-plan-v1",
        destination=str(old.with_name(NEW)),
        members=list(members.values()),
    )


def booker(old, staging):
    members = {row["name"]: row for row in sources(old, BOOKER_SEAL)}
    staging.mkdir(mode=0o700)
    for name in ("book141.py", "prepare143.py"):
        data = (HERE / name).read_bytes()
        ast.parse(data, filename=name)
        path = staging / name
        path.write_bytes(data)
        path.chmod(0o444)
        members[name] = dict(
            name=name,
            source=str(path),
            sha256=hashlib.sha256(data).hexdigest(),
            mode=0o444,
        )
    return dict(
        schema="jetstreamer-sealed-deployment-plan-v1",
        destination=str(old.with_name("booking-price-v47")),
        members=list(members.values()),
    )


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--booker":
        print(json.dumps(booker(*map(Path, sys.argv[2:])), indent=2))
    else:
        print(json.dumps(stage(*map(Path, sys.argv[1:])), indent=2))
