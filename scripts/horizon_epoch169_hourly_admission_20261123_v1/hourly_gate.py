"""Wait for the root-held immutable grant in the fixed hourly producer namespace."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

BASE = Path("/home/sol/.jetstreamer-private/epoch169-hourly-source-20261123-v1")
DEST = BASE / "v158"
RUN = BASE / "hourly-run"
BIND = Path("/run/horizon-169-hourly")
UNIT = "horizon-qualify-169-focused-hourly-20261123-v1.service"
START = "snapshot-73238440-GDXFwepRMYKGWDv947uUN9cfoMpunPFDLJHn4cgJx5A5.tar.zst"
SNAP = BASE / "inputs" / START
TERMINAL = "snapshot-73245218-5aXCD1ZXBe3fPYtrxvFkDvSvz8x68XiRmWfoEnLVLPif.tar.zst"
NODE = BIND / "jetstreamer-node"
WORKER = BIND / "v158-worker"
NODE_SHA = "b22fe558888143543594ddaf1bf7de0584a69448f7d27fde6803f8ae95d5bd92"
WORKER_SHA = "9665351525b7a6a8b67e985fc35ad896a5adbcb7aeda0cab379be16cf693796a"
G = 1 << 30


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sealed(path, size_limit):
    m = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(m.st_mode) and m.st_uid == 0 and
         stat.S_IMODE(m.st_mode) == 0o444 and m.st_nlink == 1 and m.st_size <= size_limit, f"unsafe {path}")
    with path.open("rb") as fd:
        need(os.path.samestat(m,os.fstat(fd.fileno())), f"changed {path}")
        value = fd.read(size_limit+1)
    need(len(value) == m.st_size and m.st_ctime_ns == path.lstat().st_ctime_ns, f"unstable {path}")
    return value


def sha(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data,"sha256").hexdigest()


def verify_grant(grant, iid, pid, ticks, boot, now):
    need(grant["schema"] == "epoch169-hourly-private-postguard-release-v1" and grant["unit"] == UNIT and
         grant["invocation_id"] == iid and re.fullmatch("[0-9a-f]{32}",iid) and int(iid,16) and
         grant["pid"] == pid > 1 and grant["start_ticks"] == ticks and grant["boot_id"] == boot and
         0 <= now-grant["issued_unix_seconds"] <= 90, "wrong or expired grant owner")
    for field in ("first_guard_sha256","native_post_guard_price_sha256","registered_watcher_sha256",
                  "verified_source_receipt_sha256","guard_plan_sha256","snapshot_sha256"):
        value = grant[field]
        need(re.fullmatch("[0-9a-f]{64}",value) and int(value,16), f"missing {field}")
    need(grant["producer_cpu_micros"] == 3_000_000 and grant["guard_cpu_micros"] == 1_000_000 and
         grant["memory_max"] == 68*G and grant["guard_memory_max"] == G and
         grant["canonical_publication_authorized"] is False, "different resource or publication grant")


def command():
    out = DEST/"epoch-169-through-73245218.jet"
    return list(map(str,[NODE,"169",DEST,"--verify","--qualification-end-slot=73245218",
                         f"--snapshot-archive={SNAP}",f"--epoch-hashes={DEST}/epoch-hashes-169-focused.txt",
                         f"--horizon-output={out}",f"--replay-scratch={DEST}/scratch"]))


def main():
    iid = os.environ["INVOCATION_ID"]
    cgroup = "/system.slice/"+UNIT
    need((os.geteuid(),os.getegid()) == (1001,1003) and
         Path("/proc/self/cgroup").read_text().strip() == "0::"+cgroup, "wrong gated service")
    cg = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
    need((cg/"cpu.max").read_text().split() == ["300000","100000"] and
         int((cg/"memory.max").read_text()) == 68*G and int((cg/"memory.high").read_text()) == 64*G and
         int((cg/"memory.swap.max").read_text()) == 0, "wrong native controller limits")
    need(sha(NODE) == NODE_SHA and sha(WORKER) == WORKER_SHA, "changed native execution pair")
    deadline = time.monotonic()+90
    while time.monotonic() < deadline:
        try:
            grant = json.loads(sealed(BIND/"allow.json",16<<10))
            break
        except FileNotFoundError:
            time.sleep(.1)
    else:
        raise TimeoutError("expired before the first guard and postguard grant")
    ticks = int(Path("/proc/self/stat").read_text().rsplit(")",1)[1].split()[19])
    verify_grant(grant,iid,os.getpid(),ticks,Path("/proc/sys/kernel/random/boot_id").read_text().strip(),time.time())
    if os.environ.get("HORIZON169_REQUIRE_SPLIT_SCRATCH") == "1":
        need("private_scratch_mount" in grant, "split service requires the invocation-bound tmpfs")
    if "private_scratch_mount" in grant:
        import runpy
        mount_check = runpy.run_path(str(BIND / "scratch_mount.py"))
        need(grant["private_scratch_mount"] == mount_check["native"](os.getpid()),
             "private scratch does not match the held ancestor")
    st = SNAP.lstat()
    need(SNAP.resolve(strict=True) == SNAP and stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
         st.st_uid == 1001 and not st.st_mode & 0o077 and
         [st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns] == grant["snapshot_identity"]
         and st.st_size == 2_096_111_519, "hourly Bank changed after root checksum proof")
    need((DEST/"epoch-hashes-169-focused.txt").read_bytes() == (START+"\n"+TERMINAL+"\n").encode() and
         sha(DEST/"genesis.tar.bz2") == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
         "checkpoint manifest or mainnet genesis mismatch")
    for p in (DEST/"scratch",RUN/"tmp",RUN/"private"):
        st = p.lstat()
        need(p.resolve(strict=True)==p and stat.S_ISDIR(st.st_mode) and st.st_uid==1001 and
             stat.S_IMODE(st.st_mode)==0o700 and not any(p.iterdir()), "unclean private output root")
    archive = DEST/"epoch-169-through-73245218.jet"
    for p in (archive,archive.with_suffix(".jet.segment.json")):
        need(not os.path.lexists(p), "existing private output")
    env = dict(PATH="/usr/bin:/bin",HOME="/home/sol",LANG="C",INVOCATION_ID=iid,
               TMPDIR=str(RUN/"tmp"),JETSTREAMER_PRIVATE_RUN_ROOT=str(RUN/"private"),
               JETSTREAMER_HISTORICAL_WORKER_V1_5_8=str(WORKER),JETSTREAMER_ALLOW_CANDIDATE_RUNTIME="1",
               SOLANA_RAYON_THREADS="3",RAYON_NUM_THREADS="3",JETSTREAMER_HISTORICAL_POH_THREADS="3",
               JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS="600",JETSTREAMER_ARCHIVE_BACKEND="http",
               JETSTREAMER_HTTP_BASE_URL="https://files.old-faithful.net/",
               JETSTREAMER_COMPACT_INDEX_BASE_URL="https://files.old-faithful.net/",
               JETSTREAMER_NETWORK_CAPACITY_MB="1024",JETSTREAMER_THREADS="12",JETSTREAMER_RIPGET_THREADS="12",
               JETSTREAMER_VERIFY_SNAPSHOTS="1",JETSTREAMER_SKIP_SNAPSHOT_VERIFY="0",
               JETSTREAMER_LOAD_FROM_DIR="0",JETSTREAMER_ENFORCE_ARCHIVE_HASH="1",
               JETSTREAMER_PRUNE_EPOCH_SNAPSHOTS="0",
               RUST_LOG="info,solana_metrics=off,solana_runtime::bank=warn,solana_runtime::accounts_db=warn")
    os.chdir(DEST)
    os.execve(NODE,command(),env)


if __name__ == "__main__":
    main()
