"""Resolve runnable consumers of an exact retained epoch 186 partial on Anza."""

from pathlib import Path
import hashlib, json, os, re, subprocess

DEFINITIONS = [
    "/etc/systemd/system",
    "/run/systemd/transient",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/home/sol/.config/systemd/user",
    "/etc/cron.d",
    "/var/spool/cron/crontabs",
]
PROPS = "Id,ActiveState,SubState,Job,MainPID,ControlPID,TriggeredBy,Triggers,FragmentPath,DropInPaths,WorkingDirectory,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,UnitFileState"


def system(*args):
    return subprocess.check_output(["systemctl", *args], text=True, timeout=90)


def states(units):
    if not units:
        return []
    return [
        dict(
            line.split("=", 1)
            for line in record.splitlines()
            if line.split("=", 1)[0] in PROPS.split(",")
        )
        for record in system("show", "--all", "-p", PROPS, *units).strip().split("\n\n")
    ]


def live_refs(row, allowed_cgroup=None):
    source = Path(row["source"])
    run = source.parent.parent
    keys = (source.parent, run)
    obj = {(path.stat().st_dev, path.stat().st_ino) for path in keys}
    dev, ino = row["identity"][:2]
    obj.add((dev, ino))
    refs = []
    allowed = []
    namespaces = set()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            cg = (proc / "cgroup").read_text().strip().removeprefix("0::")
            cmd = (proc / "cmdline").read_bytes()
            hits = []
            if os.fsencode(str(run)) in cmd:
                hits.append("command")
            for f in [proc / "cwd", proc / "root", *(proc / "fd").iterdir()]:
                try:
                    m = f.stat()
                except (ProcessLookupError, FileNotFoundError):
                    continue
                if (m.st_dev, m.st_ino) in obj:
                    hits.append(f.name)
            for line in (proc / "maps").read_bytes().splitlines():
                fields = line.split(maxsplit=5)
                if (
                    len(fields) > 4
                    and fields[4] == str(ino).encode()
                    and fields[3].decode().lower()
                    == f"{os.major(dev):02x}:{os.minor(dev):02x}"
                ):
                    hits.append("mapping")
                    break
            ns = (proc / "ns/mnt").stat().st_ino
            if ns not in namespaces:
                for entry in (proc / "mountinfo").read_text().splitlines():
                    fields = entry.split()
                    if len(fields) > 5 and any(
                        path == str(run)
                        or path.startswith(str(run) + "/")
                        or path.endswith(str(run).removeprefix("/home/sol"))
                        or str(run).removeprefix("/home/sol") + "/" in path
                        for path in fields[3:5]
                    ):
                        hits.append("mount")
                namespaces.add(ns)
            if hits:
                match = dict(pid=int(proc.name), cgroup=cg, kind=hits)
                if cg == allowed_cgroup:
                    allowed.append(match)
                else:
                    refs.append(match)
        except (ProcessLookupError, FileNotFoundError):
            continue
    return refs, allowed


def unit_census(rows, allowed_unit=None):
    names = [
        r.split()[0]
        for r in system(
            "list-units",
            "--all",
            "--no-pager",
            "--plain",
            "--no-legend",
            "--type=service,timer,path,socket",
        ).splitlines()
        if r.split()
    ]
    allunits = []
    for start in range(0, len(names), 180):
        allunits += states(names[start : start + 180])
    definitions = {}
    plans = {}
    for root in map(Path, DEFINITIONS):
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            b = p.read_bytes()
            definitions[str(p)] = b
    result = []
    for row in rows:
        src = Path(row["source"])
        r = src.parent.parent
        dest = r.parents[2].name
        lane = "lane-" + row["lane"]
        old = states([row["producer"]["unit"]])[0]
        assert (
            old["ActiveState"] == "inactive"
            and old["ControlPID"] == old["MainPID"] == "0"
            and not old["Job"]
            and not old["TriggeredBy"]
        )
        tokens = dict(
            source=str(src),
            run=str(r),
            run_leaf=r.name,
            destination=dest,
            lane_path=str(r.parents[4]),
            lane_option="--lane " + lane,
        )

        def terms(text):
            return [k for k, t in tokens.items() if t in text]

        def exact(t):
            return bool({"source", "run", "run_leaf"} & set(t))

        def distinctly_other(text):
            scopes = set(re.findall(r"root-cohort-(\d+)-(\d+)/", text))
            explicit = re.findall(
                r"--(?:first-epoch|last-epoch|epoch)[= ](\d+)\b", text
            )
            return (
                bool(scopes or explicit)
                and all(not (int(a) <= 186 <= int(b)) for a, b in scopes)
                and all(n != "186" for n in explicit)
            )

        blocks = []
        related = []
        for unit in allunits:
            if unit.get("Id") == allowed_unit:
                continue
            if not unit.get("Id", "").startswith(("horizon", "jetstreamer", "solana")):
                continue
            active = (
                unit["Job"]
                or unit["ActiveState"]
                in ("active", "activating", "deactivating", "reloading")
                or unit["TriggeredBy"]
                or unit["UnitFileState"]
                in ("enabled", "enabled-runtime", "linked", "linked-runtime")
            )
            if not active:
                continue
            texts = dict(
                (k, unit.get(k, ""))
                for k in (
                    "ExecStart",
                    "ExecStartPre",
                    "ExecStartPost",
                    "ExecCondition",
                    "WorkingDirectory",
                    "FragmentPath",
                    "DropInPaths",
                )
            )
            for text in list(texts.values()):
                for n in re.findall(
                    r"/(?:home/sol/|etc/systemd/|run/systemd/|usr/local/lib/|var/lib/)[^\s;{}\x22\x27]+",
                    text,
                ):
                    p = Path(n.rstrip(",)]"))
                    if p.suffix not in (
                        ".json",
                        ".sh",
                        ".py",
                        ".toml",
                        ".service",
                        ".conf",
                        ".path",
                        ".timer",
                    ) or any(
                        key in str(p).lower()
                        for key in (
                            "credential",
                            "secret",
                            ".env",
                            "/etc/jetstreamer",
                            "keychain",
                            "/logs/",
                        )
                    ):
                        continue
                    try:
                        if not p.is_file() or p.stat().st_size > (2 << 20):
                            continue
                        if p not in plans:
                            plans[p] = p.read_bytes()
                        texts[str(p)] = plans[p].decode(errors="replace")
                    except FileNotFoundError:
                        continue
            for label, text in texts.items():
                t = terms(text)
                if t:
                    hit = dict(
                        unit=unit["Id"],
                        context=label,
                        matched=t,
                        sha256=hashlib.sha256(text.encode()).hexdigest(),
                        different_epoch=distinctly_other(text),
                    )
                    related.append(hit)
                    if exact(t) or not hit["different_epoch"]:
                        blocks.append(hit)
        staged = []
        for p, b in definitions.items():
            text = b.decode(errors="replace")
            t = terms(text)
            if t:
                hit = dict(path=p, terms=t, sha256=hashlib.sha256(b).hexdigest())
                staged.append(hit)
                if (
                    p.startswith(("/etc/cron", "/var/spool/cron"))
                    or ".wants/" in p
                    or ".requires/" in p
                ) and (exact(t) or not distinctly_other(text)):
                    blocks.append(hit)
        result.append(
            dict(
                lane=row["lane"],
                source=str(src),
                stopped_producer=old,
                live_reference_hits=related,
                definition_hits=staged,
                unresolved_units=blocks,
            )
        )
    return dict(
        units_scanned=len(allunits),
        definition_files=len(definitions),
        resolved_plans=len(plans),
        rows=result,
    )
