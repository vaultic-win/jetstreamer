"""Rotate two closed Anza partials through node_02 with single-inode restoration."""

import argparse
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import consumers

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
OUT = RT / "epoch186-closed-partial-rotation-20261127-v1"
HOME = Path("/home/sol")
BASE = HOME / ".jetstreamer-private"
HOLD = BASE / "r2-holding-state-dev-samjohnson-v1"
SIX = RT / "epoch141-foundation-sixth-bootstrap-20261127-v1"
SEVEN = RT / "epoch141-foundation-seventh-bootstrap-20261127-v1"
PREVIOUS = RT / "epoch185-lanem-main-holding-20261127-v1"
OPLOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
TOOLS = Path(__file__).resolve().parent
FOLLOWON = OUT / "n-tools-v4"
MAPPING = Path(
    "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json"
)
SCOPE = RT / "root0145-zero-recovery-20261120-v1/PARK_SERIAL_ADMISSION.json"
PAID = RT / "epoch185-lanem-holding-20261127-v1/PARK_ADMISSION.json"
GENESIS = Path(
    "/usr/local/lib/jetstreamer/horizon-node02-holding-custody-20261023-v1/custody.json"
)
PROVIDER = BASE / "epoch185-lanem-replaced-20261127.lYN2hEG7/dispatch-park.py"
S3_HELPER = PREVIOUS / "retirement-tools-v1/holding_identity.py"
G = 1 << 30
M = 1 << 20
META = 16 * M
SLOT = 123350028052
PINNED = {
    "m": (
        103040006,
        42990072477,
        "696361c6abd81bc078929f4d8f4aee87105bd742e400aced529f5c900cface05",
    ),
    "n": (
        108396798,
        28562497681,
        "d233e92f868bd6d04bc47bbd3af0d9b0175510093ba4b9b602c9003b3c6386cd",
    ),
}
libc = ctypes.CDLL(None, use_errno=True)


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def ref(p):
    with p.open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    return dict(path=str(p), sha256=digest)


def fixed(p, digest):
    r = ref(p)
    need(r["sha256"] == digest, "changed " + str(p))
    return r


def read(p):
    return json.loads(p.read_bytes())


def bound(r):
    p = Path(r["path"])
    m = p.lstat()
    need(
        p.resolve() == p
        and m.st_uid == 0
        and m.st_nlink == 1
        and not m.st_mode & 0o022
        and m.st_size
        <= (64 * M if p.name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json" else 8 * M),
        "unsafe root evidence " + str(p),
    )
    fixed(p, r["sha256"])
    return read(p)


def save(p, doc):
    b = (json.dumps(doc, indent=2) + "\n").encode()
    need(len(b) < 2 * M, "oversize evidence")
    with anonymous(p.parent) as f:
        os.fchmod(f.fileno(), 0o400)
        f.write(b)
        f.flush()
        os.fsync(f.fileno())
        publish_fd(f, p)
    return ref(p)


def syncdir(p):
    fd = os.open(p, os.O_DIRECTORY | os.O_NOFOLLOW)
    os.fsync(fd)
    os.close(fd)


def idstat(m):
    return [
        m.st_dev,
        m.st_ino,
        m.st_mode,
        m.st_uid,
        m.st_gid,
        m.st_nlink,
        m.st_size,
        m.st_blocks,
        m.st_mtime_ns,
        m.st_ctime_ns,
    ]


def stamp(p):
    need(p.resolve() == p, "symlink in source")
    return idstat(p.lstat())


def avail(p):
    s = os.statvfs(p)
    return s.f_bavail * s.f_frsize


def source(lane):
    p = OUT / lane / "profile.json"
    row = bound(ref(p))
    ino, n, h = PINNED[lane]
    s = Path(row["source"])
    expected = BASE / "epochs175-200-20260922-v1" / ("lane-" + lane) / "private"
    need(
        s.is_relative_to(expected)
        and s.name == "epoch-186.jet"
        and s.parent.name == "archives"
        and s.parents[2].name == "root-cohort-186-186"
        and s.parents[4].name.startswith("destination-")
        and row["identity"][:7] == [64512, ino, 0o100600, 1001, 1003, 1, n]
        and row["sha256"] == h,
        "foreign epoch 186 profile",
    )
    return row


def s3():
    from urllib.parse import urlsplit

    url = urlsplit(os.environ["HORIZON_S3_ENDPOINT"])
    need(
        url.scheme == "https"
        and (url.hostname or "").endswith(".r2.cloudflarestorage.com")
        and not (url.username or url.password or url.query or url.fragment)
        and url.path.strip("/") == "solana-archive-with-accounts-data",
        "unexpected authenticated holding endpoint",
    )
    digest = next(
        item["sha256"]
        for item in read(PREVIOUS / "retirement-tools-v1/deployment-seal-receipt.json")[
            "members"
        ]
        if item["name"] == "holding_identity.py"
    )
    fixed(S3_HELPER, digest)
    return runpy.run_path(str(S3_HELPER))


def checked_remote(expected, accepted):
    shared = s3()
    c = shared["client"]()
    head = shared["head"]
    small = shared["small_body"]
    owner = head(c, shared["OWNER"])
    need(
        json.loads(small(c, owner))
        == {
            "schema": "jetstreamer-horizon-holding-owner-v2",
            "host": "dev-samjohnson",
            "prefix": "node_02/",
        },
        "foreign holding owner",
    )
    pin = None
    custody = None
    if accepted:
        path = Path(expected["custody_path"])
        need(path.parent == HOLD / "receipts", "foreign custody")
        custody = bound(ref(path))
        need(
            all(
                custody[k] == expected[k]
                for k in (
                    "source",
                    "object_key",
                    "manifest_key",
                    "sha256",
                    "length",
                    "manifest_sha256",
                    "manifest",
                )
            )
            and custody["remote_sha256_readback"]
            and custody["local_source_revalidated"]
            and custody["local_retirement_authorized"] is False
            and custody["canonical_publication_authorized"] is False,
            "incomplete custody",
        )
        pin = '"' + custody["object_etag"].strip('"') + '"'
    blob = head(c, expected["object_key"], pin)
    man = head(c, expected["manifest_key"])
    if blob["status"] == 200:
        need(
            blob["length"] == expected["length"]
            and blob["metadata"].get("sha256") == expected["sha256"],
            "wrong remote object",
        )
    if man["status"] == 200:
        b = small(c, man)
        need(
            sha(b) == expected["manifest_sha256"]
            and json.loads(b) == expected["manifest"],
            "wrong remote manifest",
        )
    if accepted:
        need(
            blob["status"] == man["status"] == 200 and blob["etag"] == pin,
            "remote custody lost",
        )
    return c, dict(
        owner=owner,
        blob=blob,
        manifest=man,
        custody=ref(Path(expected["custody_path"])) if custody else None,
    )


def locked(p, identity=None):
    f = p.open("rb")
    m = os.fstat(f.fileno())
    need(
        p.resolve() == p
        and m.st_nlink == 1
        and (identity is None or idstat(m)[:7] == identity[:7]),
        "changed lock " + str(p),
    )
    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return f


def deployment(phase, lane):
    if TOOLS == FOLLOWON:
        need(
            lane == "n" and phase in ("park", "retire", "restore"),
            "this follow-on holds only the lane N serial rotation",
        )
    else:
        need(TOOLS == OUT / "tools", "use the deployed rotation operator")


def recent_price():
    if TOOLS == FOLLOWON:
        import n_admission

        return n_admission.price()
    fixed(PROVIDER, "a8d2139c524f06d38329cb9c7ab00ab036f26f1adbba3b3b501b365511fed471")
    q = runpy.run_path(str(PROVIDER))["price"]()
    live = q["live_quote"]
    need(0 <= time.time() - live["observed"] <= 15, "stale price")
    need(read(PAID)["restore_overlap_bytes"] == SLOT, "serial overlap changed")
    fleet = bound(live["fleet"])
    aux = fleet["retry9_auxiliary_commitments"]
    need(
        aux["holding_serial"]
        and aux["build_memory_bytes"] == 2 * G
        and aux["holding_memory_bytes"] == 2 * G,
        "changed serial slot",
    )
    six = read(SIX / "ANZA_SERIAL_HANDBACK.json")
    fifth = read(
        RT / "epoch141-foundation-fifth-bootstrap-20261127-v1/PARK_ADMISSION.json"
    )
    seven = SEVEN / "ANZA_SERIAL_HANDBACK.json"
    seventh = max(
        2588354467 + 4096, read(seven)["local_occupied_bytes"] if seven.exists() else 0
    )
    extra = (
        Path(six["local_copy"]).stat().st_blocks * 512
        + fifth["retained_disk_source"]
        + seventh
        + 4 * G
        + META
        + 512 * M
    )
    room = q["phase_margin_home_bytes"] - extra
    ram = q["phase_margin_ram_bytes"] - 2 * G - 256 * M
    return dict(
        basis=q,
        fleet=live["fleet"],
        utc=time.time(),
        available_home=live["home"],
        additional_holding_disk=extra,
        remaining_home=room,
        absolute_guard_floor=live["max_guard_floor"],
        floor=max(live["max_guard_floor"], live["home"] - room),
        remaining_ram=ram,
        serial_slot=SLOT,
        charged_parallel_control=2 * G,
        holding_ram_available_from_serial=2 * G,
        resource_credit_bytes=0,
    )


def owners(quote):
    if TOOLS == FOLLOWON:
        import n_admission

        return n_admission.owners(quote)
    fleet = bound(quote["fleet"])
    rows = list(fleet["actual_executing_replays"])
    for key, v in fleet.items():
        if (
            key.startswith("actual_separate_")
            and key.endswith("_executing_replay")
            and isinstance(v, dict)
        ):
            rows.append(v)
    expected = {
        row["unit"]["Id"]: row["unit"]["InvocationID"] for row in rows if "unit" in row
    }
    # The complete five-owner quote also binds separately enrolled workers.
    q = quote["basis"]["live_quote"]
    for k in ("owner141", "owner167", "owner170"):
        path = Path(q[k]["cgroup"])
        unit = path.name
        doc = bound(q[k]["actor"])
        actor = doc.get("actor", doc)
        iid = actor["producer_invocation_id"]
        expected[unit] = iid
    units = set(
        line.split()[0]
        for line in consumers.system(
            "list-units",
            "--plain",
            "--no-legend",
            "--type=service",
            "--state=running,activating,deactivating",
            "horizon-qualify-*",
        ).splitlines()
        if line.split()
    )
    need(units == set(expected), "replay roster changed")
    for unit, iid in expected.items():
        need(
            consumers.system("show", "--value", "-p", "InvocationID", unit).strip()
            == iid,
            "replay invocation changed",
        )


@contextlib.contextmanager
def anonymous(directory):
    need(
        directory.resolve() == directory
        and directory.stat().st_dev == HOME.stat().st_dev,
        "wrong restore filesystem",
    )
    fd = os.open(directory, os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w+b") as f:
        yield f


def publish_fd(f, p):
    if libc.linkat(f.fileno(), b"", -100, os.fsencode(p), 0x1000) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(p))
    syncdir(p.parent)


def move(src, dst):
    if libc.renameat2(-100, os.fsencode(src), -100, os.fsencode(dst), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(src))
    syncdir(dst.parent)


def receive(c, blob, digest, f, guard):
    shared = s3()
    n = blob["length"]
    response = c.get_object(
        Bucket=shared["BUCKET"], Key=blob["key"], IfMatch=blob["etag"]
    )
    need(
        response["ETag"] == blob["etag"] and response["ContentLength"] == n,
        "GET identity differs",
    )
    h = hashlib.sha256()
    written = 0
    with contextlib.closing(response["Body"]) as body:
        while b := body.read(8 * M):
            need(written + len(b) <= n, "oversize holding object")
            guard(n - written)
            f.write(b)
            written += len(b)
            h.update(b)
    need(written == n and h.hexdigest() == digest, "stream hash mismatch")
    f.flush()
    os.fsync(f.fileno())
    f.seek(0)
    need(
        hashlib.file_digest(f, "sha256").hexdigest() == digest,
        "local file readback mismatch",
    )
    guard(0)


def fixture():
    fixed(GENESIS, "749435d6a63400446a85ef1b39062077f682311b796135c058af8cf465b64629")
    fixture = read(GENESIS)
    s = s3()
    c = s["client"]()
    blob = s["head"](c, fixture["object_key"])
    need(
        blob["length"] == 20144
        and blob["etag"].strip('"') == fixture["object_etag"].strip('"'),
        "fixture pin",
    )
    m = s["head"](c, fixture["manifest_key"])
    need(sha(s["small_body"](c, m)) == fixture["manifest_sha256"], "fixture manifest")
    bad = False
    try:
        c.get_object(
            Bucket=s["BUCKET"], Key=blob["key"], IfMatch='"changed-fixture-etag"'
        )
    except s["ClientError"] as error:
        bad = error.response["ResponseMetadata"]["HTTPStatusCode"] == 412
    need(bad, "ETag fixture failed")
    d = OUT / "fixture"
    dest = d / ("receipt-" + os.environ["INVOCATION_ID"])
    before = list(d.iterdir())
    with anonymous(d) as f:
        f.write(b"interrupted")
        f.flush()
    need(list(d.iterdir()) == before, "interrupted file remained")
    with anonymous(d) as f:
        receive(
            c,
            blob,
            fixture["sha256"],
            f,
            lambda remaining: need(avail(d) > remaining + META, "fixture floor"),
        )
        os.fchmod(f.fileno(), 0o600)
        publish_fd(f, dest)
        try:
            publish_fd(f, dest)
        except FileExistsError:
            pass
        else:
            raise ValueError("no-clobber fixture failed")
    need(
        ref(dest)["sha256"] == fixture["sha256"] and dest.stat().st_nlink == 1,
        "fixture readback",
    )
    return dict(
        object=blob,
        manifest=m,
        source_qualification=ref(GENESIS),
        destination=ref(dest),
        whole_disk_readback=True,
        changed_etag_status=412,
        atomic_noclobber=True,
        one_inode=True,
        interrupted_no_named_partial=True,
    )


def native_scope(phase, lane):
    unit = (
        "horizon-closed186-"
        + phase
        + "-"
        + lane
        + "-"
        + os.environ["HORIZON186_RUN_ID"]
        + ".service"
    )
    iid = os.environ["INVOCATION_ID"]
    need(
        re.fullmatch("[0-9a-f]{32}", iid)
        and Path("/proc/self/cgroup").read_text().strip() == "0::/system.slice/" + unit,
        "outside assigned native unit",
    )
    p = Path("/sys/fs/cgroup/system.slice") / unit
    hard, cpus = {
        "fixture": (256 * M, 250000),
        "precheck": (256 * M, 250000),
        "park": (2 * G, 2000000),
        "retire": (G, 1000000),
        "restore": (2 * G, 1000000),
    }[phase]
    a, b = map(int, (p / "cpu.max").read_text().split())
    need(
        int((p / "memory.max").read_text()) == hard
        and int((p / "memory.swap.max").read_text()) == 0
        and a * 1000000 == b * cpus,
        "native hard limits differ",
    )
    return unit, iid


def serial_handoff():
    prior = bound(ref(PREVIOUS / "SERIAL_RETURN.json"))
    ret = bound(prior["reclamation"])
    need(
        prior["return_to"] == "campaign controller"
        and prior["verified_no_active_holding_or_mutation"]
        and prior["local_source_absent"]
        and ret["allocated_bytes_removed"] == 54996418560,
        "185 serial has not returned",
    )
    handoff = bound(ref(SEVEN / "ANZA_SERIAL_HANDBACK.json"))
    need(
        handoff["scope"] == "epoch 141 seventh bootstrap"
        and handoff["return_to"] == "campaign controller"
        and handoff["temporary_payloads"] == handoff["retained_tmpfs_bytes"] == 0
        and Path(handoff["local_copy"]).stat().st_blocks * 512
        == handoff["local_occupied_bytes"],
        "seventh serial has not returned",
    )
    receipts = [
        ref(PREVIOUS / "SERIAL_RETURN.json"),
        ref(SEVEN / "ANZA_SERIAL_HANDBACK.json"),
    ]
    if TOOLS == FOLLOWON:
        import n_admission

        receipts.append(n_admission.m_return())
    return receipts


def census(row, cgroup):
    result = consumers.unit_census([row], Path(cgroup).name)
    q = result["rows"][0]
    live, own = consumers.live_refs(row, cgroup)
    need(
        not q["unresolved_units"] and not live,
        "disk source has an unresolved consumer: "
        + str((q["unresolved_units"], live))[:300],
    )
    return dict(staged=result, kernel_refs=live, own=own)


def verify_artifact(path, row, original=True):
    m = stamp(path)
    ident = row["identity"]
    need((m == ident if original else m[:9] == ident[:9]), "epoch 186 identity changed")
    with os.fdopen(
        os.open(path, os.O_NOFOLLOW | os.O_RDONLY | os.O_NOATIME), "rb"
    ) as f:
        need(
            os.path.samestat(os.fstat(f.fileno()), path.lstat()), "source substitution"
        )
        h = hashlib.file_digest(f, "sha256").hexdigest()
        need(h == row["sha256"] and stamp(path) == m, "epoch 186 private bytes changed")


def retire(row, a, d, active, iid):
    src = Path(row["source"])
    quarantine = src.with_name(".epoch186-retiring-" + row["sha256"])
    intent = d / "MOVE_INTENT.json"
    unlink = d / "UNLINK_INTENT.json"
    operator = consumers.system("show", "-p", "ControlGroup", "--value", active).strip()
    retired = d / "RETIRED.json"
    if retired.exists():
        return bound(ref(retired))
    if intent.exists():
        old = bound(ref(intent))
        need(
            old["source"] == str(src)
            and old["sha256"] == row["sha256"]
            and old["quarantine"] == str(quarantine),
            "foreign pending retirement",
        )
        before = old["available_before"]
    else:
        need(
            src.exists() and not quarantine.exists() and not unlink.exists(),
            "retirement did not start on the original name",
        )
        before = avail(src.parent)
        save(
            intent,
            dict(
                source=str(src),
                sha256=row["sha256"],
                quarantine=str(quarantine),
                available_before=before,
                admission=a,
                invocation=iid,
            ),
        )
    if src.exists():
        need(
            not quarantine.exists() and not unlink.exists(),
            "ambiguous local retirement",
        )
        verify_artifact(src, row)
        census(row, operator)
        move(src, quarantine)
    if quarantine.exists():
        verify_artifact(quarantine, row, False)
        census(row, operator)
        if not unlink.exists():
            save(
                unlink,
                dict(
                    intent=ref(intent),
                    source=str(src),
                    quarantine=str(quarantine),
                    sha256=row["sha256"],
                    confirmed_armed_native=active,
                ),
            )
        u = bound(ref(unlink))
        need(
            u["intent"] == ref(intent) and u["sha256"] == row["sha256"],
            "foreign unlink intent",
        )
        guard = quarantine.lstat()
        need(
            idstat(guard)[:9] == row["identity"][:9] and not src.exists(),
            "quarantine changed",
        )
        quarantine.unlink()
        syncdir(src.parent)
    need(
        not src.exists()
        and not quarantine.exists()
        and unlink.exists()
        and bound(ref(unlink))["intent"] == ref(intent),
        "ambiguous terminal retirement",
    )
    after = avail(src.parent)
    return dict(
        epoch=186,
        source=str(src),
        sha256=row["sha256"],
        invocation=iid,
        admission=a,
        move=ref(intent),
        unlink=ref(unlink),
        available_before=before,
        available_after=after,
        allocated_bytes_removed=row["allocated"],
        measured_net_free_bytes=after - before,
        conservative_capacity_bytes=max(0, min(row["allocated"], after - before)),
        canonical_publication=False,
    )


def restore(row, expected, remote, client, q):
    src = Path(row["source"])
    n = expected["length"]
    pins = PINNED[row["lane"]]
    need(pins[1:] == (n, expected["sha256"]), "restore profile changed")
    last = [0.0]

    def guard(remaining):
        need(
            avail(src.parent) >= q["floor"] + remaining + META,
            "insufficient space above accepted fleet floor",
        )
        now = time.monotonic()
        if now - last[0] >= 20 or remaining == 0:
            owners(q)
            last[0] = now

    if src.exists():
        m = stamp(src)
        need(
            m[0] == row["identity"][0]
            and m[2:7] == row["identity"][2:7]
            and m[8] == row["identity"][8]
            and ref(src)["sha256"] == expected["sha256"],
            "original name occupied by another object",
        )
        return dict(
            path=str(src), sha256=expected["sha256"], already_restored=True, identity=m
        )
    guard(n)
    with anonymous(src.parent) as f:
        receive(client, remote["blob"], expected["sha256"], f, guard)
        fd = f.fileno()
        m = row["identity"]
        os.fchown(fd, m[3], m[4])
        os.fchmod(fd, stat.S_IMODE(m[2]))
        os.utime(fd, ns=(m[8], m[8]))
        os.fsync(fd)
        need(os.fstat(fd).st_nlink == 0, "temporary copy gained a name")
        publish_fd(f, src)
        need(
            os.path.samestat(src.lstat(), os.fstat(fd)) and src.stat().st_nlink == 1,
            "wrong installed inode",
        )
    return dict(
        path=str(src),
        identity=stamp(src),
        sha256=expected["sha256"],
        authenticated_get=True,
        single_inode=True,
        fsynced=True,
        independent_disk_readback=True,
    )


def execute(phase, lane):
    need(
        os.geteuid() == 0 and not sys.flags.optimize,
        "run in the bounded root service without Python optimize",
    )
    deployment(phase, lane)
    unit, iid = native_scope(phase, lane)
    stamp_id = os.environ["HORIZON186_RUN_ID"]
    hard = {
        "fixture": 256 * M,
        "precheck": 256 * M,
        "park": 2 * G,
        "retire": G,
        "restore": 2 * G,
    }[phase]
    row = source(lane)
    d = OUT / lane
    expected = bound(ref(d / "expected.json"))
    need(
        expected["source"] == row["source"]
        and expected["sha256"] == row["sha256"]
        and expected["length"] == row["identity"][6],
        "foreign expected",
    )
    original = Path(row["source"])
    members = read(TOOLS / "deployment-seal-receipt.json")["members"]
    for member in members:
        fixed(TOOLS / member["name"], member["sha256"])
    if phase == "fixture":
        return fixture()
    if phase == "precheck":
        return checked_remote(expected, False)[1]
    with contextlib.ExitStack() as locks:
        locks.enter_context(locked(OUT / "rotation.lock"))
        handoff = serial_handoff()
        locks.enter_context(locked(Path(row["epoch_lock"]), row["lock_identity"]))
        if phase != "park":
            locks.enter_context(
                locked(
                    HOLD / "transition.lock", [64512, 95818311, 0o100600, 0, 0, 1, 0]
                )
            )
        current = census(row, "/system.slice/" + unit)
        proof = ref(OUT / "RESTORE_FIXTURE_ACCEPTED.json")
        bound(proof)
        with locked(OPLOCK):
            fleet_price = recent_price()
            owners(fleet_price)
            disk = (
                expected["single_copy_peak"]
                if phase == "restore" and not original.exists()
                else 16 * M
            )
            need(
                fleet_price["remaining_home"] >= disk
                and fleet_price["remaining_ram"] >= hard,
                "fresh complete fleet cannot fit phase",
            )
            now = time.time()
            need(now - fleet_price["utc"] <= 15, "quote exceeded admission window")
            a = save(
                d / ("ADMISSION_" + phase + "_" + stamp_id + ".json"),
                dict(
                    unit=unit,
                    invocation=iid,
                    utc=now,
                    phase=phase,
                    profile=ref(d / "profile.json"),
                    expected=ref(d / "expected.json"),
                    handoff=handoff,
                    census=current,
                    price=fleet_price,
                    required_incremental_home=disk,
                    ram=hard,
                    swap=0,
                    restore_slot=SLOT,
                    restore_peak=expected["single_copy_peak"],
                    restore_fixture=proof,
                    canonical_publication=False,
                ),
            )
        if phase == "park":
            need(
                stamp(original) == row["identity"], "source changed before native park"
            )
            # Recover a completed native upload if a prior dispatch lost its final receipt.
            if Path(expected["custody_path"]).exists():
                remote = checked_remote(expected, True)[1]
                verify_artifact(original, row)
                return dict(
                    admission=a,
                    remote=remote,
                    source=str(original),
                    native_custody=remote["custody"],
                    source_identity=row["identity"],
                    invocation=iid,
                    capacity_credit=0,
                    recovered_prior_native=True,
                )
            checked_remote(expected, False)
            plan = ref(d / "plan.json")
            binary = read(SCOPE)["qualified_image"]
            fixed(
                Path(binary["path"]),
                "909248d8e4c1db4c3cd89e1a4f15205b4a59d442494f35b7635038152025bb7e",
            )
            subprocess.run(
                [
                    binary["path"],
                    "holding-park",
                    plan["path"],
                    "--spec-sha256",
                    plan["sha256"],
                    "--self-sha256",
                    binary["sha256"],
                ],
                check=True,
            )
            remote = checked_remote(expected, True)[1]
            need(
                stamp(original) == row["identity"], "source identity changed after park"
            )
            return dict(
                admission=a,
                remote=remote,
                source=str(original),
                native_custody=remote["custody"],
                source_identity=row["identity"],
                invocation=iid,
                capacity_credit=0,
            )
        previous = bound(ref(d / "PARK_ACCEPTED.json"))
        need(
            previous["output"]["sha256"]
            == ref(Path(previous["output"]["path"]))["sha256"]
            and previous["success"],
            "native park not accepted",
        )
        client, remote = checked_remote(expected, True)
        need(
            previous["native_custody"] == remote["custody"],
            "changed whole readback custody",
        )
        if phase == "retire":
            return retire(row, a, d, unit, iid)
        terminal = bound(ref(d / "RETIRED.json"))
        need(
            terminal["sha256"] == row["sha256"]
            and terminal["source"] == row["source"]
            and terminal["allocated_bytes_removed"] == row["allocated"],
            "foreign retirement",
        )
        return dict(
            admission=a,
            remote=remote,
            retirement=ref(d / "RETIRED.json"),
            restored=restore(row, expected, remote, client, fleet_price),
            invocation=iid,
        )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument(
        "phase", choices=["fixture", "precheck", "park", "retire", "restore"]
    )
    p.add_argument("lane", choices=["m", "n"])
    args = p.parse_args()
    print(json.dumps(execute(args.phase, args.lane), sort_keys=True), flush=True)
