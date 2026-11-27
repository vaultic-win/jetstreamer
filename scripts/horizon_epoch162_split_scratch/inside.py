"""Exercise only the fixture's two private mounts and the genuine node/worker entry."""
import errno
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def require(value, reason):
    if not value:
        raise ValueError(reason)


def mount(path):
    raw = subprocess.check_output(["findmnt", "--json", "--kernel", "-T", path, "-o",
                                   "TARGET,SOURCE,FSTYPE,OPTIONS"], text=True)
    return json.loads(raw)["filesystems"][0]


def small_write(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(data).hexdigest()


def pressure(path, max_bytes):
    # Each pressure fixture has only 2 or 16 MiB to fill.
    block = b"A" * (256 << 10)
    written = 0
    try:
        with path.open("xb", buffering=0) as f:
            while written < max_bytes:
                written += f.write(block)
            os.fsync(f.fileno())
    except OSError as error:
        require(error.errno == errno.ENOSPC, f"unexpected pressure failure {error!r}")
    else:
        raise ValueError("fixture wrote past its physical cap")
    return dict(bytes=written, errno=errno.ENOSPC)


def main():
    phase, config = sys.argv[1:]
    cfg = json.loads(Path(config).read_bytes())
    root = Path(cfg["view"])
    scratch = root / "scratch"
    ledger = root / "ledger"
    proof = root / "ledger/fixture-retained-evidence"
    home = mount(root)
    mem = mount(scratch) if phase != "readback" else {}
    marker = ("epoch 162 split scratch qualification " + cfg["token"] + "\n").encode()
    cg = Path("/sys/fs/cgroup" + Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1])
    require((cg/"memory.max").read_text().strip() == str(512 << 20)
            and (cg/"memory.swap.max").read_text().strip() == "0"
            and (cg/"cpu.max").read_text().split() == ["25000", "100000"], "unexpected fixture limits")
    require(os.getuid() == 1001 and os.getgid() == 1003 and home["fstype"] == "ext4"
            and os.major(root.stat().st_dev) == 7 and home["target"] == str(root),
            "unexpected UID, GID or image mount")
    loop = Path(f"/sys/dev/block/{os.major(root.stat().st_dev)}:{os.minor(root.stat().st_dev)}/loop/backing_file")
    reported = Path(loop.read_text().strip())
    backing = Path(cfg["backing_image"])
    candidates = [reported, Path("/home/sol") / reported.relative_to("/")]
    require(any(p.is_file() and p.samefile(backing) for p in candidates) and backing.stat().st_dev == Path("/home/sol").stat().st_dev,
            "different HOME backing inode")
    if phase == "readback":
        require("ro" in home["options"].split(",") and proof.read_bytes() == marker,
                "retained data missing on post-exit read-only image")
        print(json.dumps(dict(phase=phase, iid=os.environ["INVOCATION_ID"], label=cfg["token"],
                              checksum=hashlib.sha256(marker).hexdigest(), home=home)), flush=True)
        return
    home_vfs, mem_vfs = os.statvfs(ledger), os.statvfs(scratch)
    actual_home = home_vfs.f_blocks * home_vfs.f_frsize
    actual_scratch = mem_vfs.f_blocks * mem_vfs.f_frsize
    require("rw" in home["options"].split(",") and 0 < actual_home <= cfg["image_bytes"]
            and mem["target"] == str(scratch) and mem["fstype"] == "tmpfs"
            and set(("rw", "noswap")).issubset(mem["options"].split(","))
            and "noexec" not in mem["options"].split(",") and actual_scratch == cfg["scratch_bytes"]
            and ledger.stat().st_dev == (root/"private").stat().st_dev != scratch.stat().st_dev,
            "incorrect physical, HOME or noswap mount")
    checksum = small_write(proof, marker)
    result = dict(phase=phase, iid=os.environ["INVOCATION_ID"], uid=os.getuid(), gid=os.getgid(),
                  home=home, scratch=mem, home_filesystem_capacity=actual_home, home_inode_capacity=home_vfs.f_files, kernel_backing=str(reported),
                  image_inode=[backing.stat().st_dev,backing.stat().st_ino],
                  scratch_capacity=actual_scratch, scratch_inodes=mem_vfs.f_files, checksum=checksum)
    if phase == "pressure":
        result["scratch_pressure"] = pressure(scratch/"fixture-full", 4 << 20)
        result["home_pressure"] = pressure(ledger/"fixture-full", 20 << 20)
        require(proof.read_bytes() == marker, "retained marker changed on pressure")
        print(json.dumps(result), flush=True)
        return
    require(phase in ("native36", "native32") and actual_scratch == int(phase[6:]) << 30 and mem_vfs.f_files >= 1 << 20,
            "incorrect native fixture geometry")
    identities = []
    for item in cfg["bindings"]:
        dst = Path(item["view"]); st = dst.stat()
        actual = [st.st_dev, st.st_ino, st.st_size, st.st_ctime_ns, st.st_mtime_ns]
        require(actual == item["identity"] and "ro" in mount(dst)["options"].split(","), "changed bound " + str(dst))
        if "rehash_inside" in item:
            with dst.open("rb") as f:
                require(hashlib.file_digest(f, "sha256").hexdigest() == item["rehash_inside"], "changed " + str(dst))
        identities.append(dict(path=str(dst), identity=actual))
    real, fixture = Path(cfg["real_bootstrap"]), Path(cfg["mock_bootstrap"])
    require(real.name == fixture.name and real.stat().st_size == 1801022208 and
            fixture.stat().st_size < 32768 and not fixture.samefile(real), "native fixture selected the real payload")
    require(len([x for x in identities if "/compact-indexes/" in x["path"]]) == 3, "wrong readonly indexes")
    trace = Path(cfg["trace"])
    args = ["strace", "-f", "-qq", "-s", "640", "-e", "trace=mkdir,mkdirat,execve", "-o", str(trace), "--"] + cfg["argv"]
    run = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=105, text=True)
    print(run.stdout, flush=True)
    require(run.returncode != 0 and "block slot " not in run.stdout and "progress slot " not in run.stdout
            and "69983761..=69991076" in run.stdout and "SourceExact" in run.stdout
            and "starting isolated solana-v1.5.6 worker" in run.stdout, "unexpected native route or replay")
    # The tiny snapshot stops at Bank decoding after the genuine worker created its AccountsDB paths.
    native = trace.read_text()
    rx = re.compile(r'"(' + re.escape(str(scratch)) + r'/\.historical-runtime/jetstreamer-historical-parent-[^"/]+/jetstreamer-historical-v1\.5\.6-[^"/]+/accounts-state/([0-3]))"[^\n]*= 0')
    accounts = {int(index): path for path, index in rx.findall(native)}
    require(set(accounts) == {0, 1, 2, 3} and len({str(Path(path).parent) for path in accounts.values()}) == 1,
            "expected four genuine worker account path creations; see retained syscall trace")
    require(re.search(r'execve\("[^"]*historical-worker[^"]*"', native) or
            re.search(r'execve\("/proc/self/fd/[0-9]+"', native), "missing native worker execution")
    result.update(node_exit=run.returncode, node_expected_error=run.stdout.strip().splitlines()[-1],
                  actual_accounts=accounts, trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),
                  projected_source_inodes=identities, synthetic_bootstrap=str(fixture), original_bootstrap=str(real),
                  initialized_real_bank=False, production_slots_replayed=0)
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
