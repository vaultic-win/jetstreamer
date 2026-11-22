"""Cross the retry decision and native probe identity without starting a producer."""
import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
from unittest.mock import patch

def main(image):
    q = runpy.run_path(str(image))
    check = q["probe_identity"]
    fleet = dict(path="/example/FLEET", sha256="a" * 64)
    args = [q["PYTHON"], "-IB", str(q["NATIVE"]), "145", fleet["path"], fleet["sha256"]]
    info = [q["PARENT"], 10, args, "0::" + q["CGROUP"]]
    assert check(info, True, fleet)
    crossed = []
    for field, value in ((0, 10), (1, 0), (3, "/other")):
        new = copy.deepcopy(info)
        new[field] = value
        assert not check(new, True, fleet)
        crossed.append(["ppid", "ticks", None, "cgroup"][field])
    for index in range(len(args)):
        new = copy.deepcopy(info)
        new[2][index] += "-different"
        assert not check(new, True, fleet)
        crossed.append("argv" + str(index))
    assert not check(info, False, fleet)
    assert not check([*info[:2], args + ["extra"], info[3]], True, fleet)
    crossed += ["executable", "extra_argument"]
    # Use the actual original stderr to prove the full traceback fingerprint.
    original = subprocess.check_output(["/usr/bin/journalctl", "--no-pager", "-o", "cat",
                                        "-u", "horizon-bounded142-active-mirror-061010.service"])
    begin = original.index(b"Traceback (most recent call last):\n")
    end = original.index(b"'/proc/4011654/stat'\n", begin) + len(b"'/proc/4011654/stat'\n")
    stderr = original[begin:end]
    retry = q["retryable"]
    probe = (99, 10, 3)
    assert retry(1, b"", stderr, probe)
    for name, fields in [
        ("success", (0, b"", stderr, probe)),
        ("partial_stdout", (1, b"{}", stderr, probe)),
        ("unattested", (1, b"", stderr, None)),
        ("different_pid", (1, b"", stderr.replace(b"4011654", b"4011655"), probe)),
        ("negative_fit", (1, b"", b"negative fit", probe)),
        ("foreign_census", (1, b"", b"foreign 145 descendants", probe)),
        ("additional_failure", (1, b"", stderr + b"error", probe)),
    ]:
        assert not retry(*fields)
        crossed.append(name)
    fn = q["window"]
    with patch.dict(fn.__globals__, {"pid1_and_owners": lambda _: None, "witness": lambda _: None,
                                     "members": lambda: q["OWNERS"] | {999}}):
        try:
            fn(None, fleet, 0)
        except ValueError as error:
            assert "foreign V5f cgroup" in str(error)
        else:
            raise AssertionError("foreign member accepted")
    crossed.append("foreign_remaining_member")
    print(json.dumps(dict(crossed=crossed, accepted=["original-probe-shape", "original-overlap-traceback"])))

if __name__ == "__main__":
    main(Path(sys.argv[1]))
