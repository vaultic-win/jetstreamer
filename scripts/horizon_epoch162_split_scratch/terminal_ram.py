"""Reconcile two concluded one-shot RAM charges; preserve every retained file and serial slot."""
import json
from pathlib import Path
import subprocess


def terminal(row, allowed, quiet, require):
    unit = row["Id"]
    invocation = row["InvocationID"]
    now = quiet(unit)
    require(len(invocation) == 32 and now["InvocationID"] in ("", invocation), unit)
    rows = subprocess.run([
        "journalctl", "--no-pager", "--since", "2026-11-27 19:40 UTC", "-o", "json",
        "UNIT=" + unit, "INVOCATION_ID=" + invocation, "_PID=1",
        "--output-fields=MESSAGE_ID,MESSAGE,UNIT_RESULT,INVOCATION_ID,UNIT",
    ], capture_output=True, text=True, check=True, timeout=25).stdout.splitlines()
    events = [json.loads(line) for line in rows]
    starts = [j for j in events if j.get("MESSAGE_ID") == "39f53479d3a045ac8e11786248231fbf"]
    ends = [j for j in events if j.get("MESSAGE_ID") in allowed]
    require(len(starts) == len(ends) == 1 and
            int(starts[0]["__REALTIME_TIMESTAMP"]) < int(ends[0]["__REALTIME_TIMESTAMP"]), unit)
    return {"unit": unit, "invocation": invocation, "native": now, "start": starts[0], "terminal": ends[0]}


def reconcile(rt, old, room, doc, quiet, require):
    gib = 1 << 30
    ok = {"7ad2d189f7e94e70a38c781354912448"}
    failed = {"d9b373ed55a64feb8242e02dbe79a49c"}
    compiler = Path("/home/sol/.jetstreamer-private/epoch168-anza-reader-build-20261127.jMydZnTw")
    events = []
    v2 = old["compiler_recovery"]
    require(v2["maximum_memory"] == 3*gib and room["rooms"]["build_ram"] == 2*gib and
            room["rooms"]["holding_ram_available_from_serial"] == 2*gib, "build or holding budgets changed")
    intent = doc(v2["intent"]["path"], v2["intent"]["sha256"])
    launched = doc(v2["native"]["path"], v2["native"]["sha256"])
    require(launched["intent"] == v2["intent"] and "--property=MemoryMax=3G" in intent["command"], "compiler limit")
    events.append(terminal(launched["native"], failed, quiet, require))
    require(events[-1]["terminal"].get("UNIT_RESULT") == "exit-code", "unexpected recovery terminal")
    pack = doc(rt/"epoch168-current-anza-reader-20261127-v1/PACKAGE.json",
               "62b7dd8b88c1210f685932c0dfe2d727ea0686af56953b55132f94bcb92ca7ba")
    for name in ["v3-20261127/BUILD_LAUNCH.json", "native-qualification-v1/QUALIFICATION_LAUNCH.json",
                 "v4-20261127/BUILD_LAUNCH.json", "native-qualification-v2/QUALIFICATION_LAUNCH.json"]:
        launch = doc(compiler / name)
        events.append(terminal(launch["native"], ok | failed, quiet, require))
    require(events[-1]["invocation"] == pack["qualification_exit"]["invocation"] and pack["qualified"] and
            events[-1]["terminal"]["MESSAGE_ID"] in ok, "serial successor chain incomplete")
    patterns = ["horizon-168-anza-reader-recovery-*", "horizon-168-anza-uploader-*",
                "horizon-168-anza-reader-qualification-*", "horizon-input-170-73766969-*"]
    current = subprocess.check_output(["systemctl", "list-units", "--state=active,activating,deactivating,reloading",
                                      "--plain","--no-legend","--no-pager", *patterns], text=True,timeout=15)
    require(not current.strip(), "a serial successor or input copier is active")

    intake = room["input170"]
    package = doc(rt/"epoch170-from-73766969-20261127-v1/package/following-input.json",
                  "91c694b955490a1cca74cd4c9323f25b74b2272aa54214d9ca0d1d95ccb92943")
    require(not intake["active"] and intake["additional_ram"] == gib and len(intake["bookings"]) == 1 and
            intake["additional_home"] >= 2149673902 and intake["custody"] == package["custody"], "copier charge")
    custody = doc(intake["custody"]["path"], intake["custody"]["sha256"])
    require(custody["start"] == intake["bookings"][0] and custody["receipt"] == package["native"], "intake chain")
    start = doc(custody["start"]["path"], custody["start"]["sha256"])
    payload = Path(package["destination"])
    native = json.loads(Path(package["native"]["path"]).read_bytes())
    from hashlib import sha256
    require(sha256(Path(package["native"]["path"]).read_bytes()).hexdigest() == package["native"]["sha256"] and
            native["file"]["sha256"] == package["archive_sha256"] == custody["actual_sha256"], "private custody")
    st = payload.lstat()
    require(payload.resolve() == payload and st.st_nlink == 1 and
            [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns] == package["file_identity"] and
            "MemoryMax=1073741824" in start["argv"] and package["single_copy"], "input identity or copier cap")
    copied = terminal(dict(Id=start["unit"], InvocationID="e1a53cfef3964bf5a4414d80f940adc7"), ok, quiet, require)
    require(copied["start"]["__REALTIME_TIMESTAMP"] <= copied["terminal"]["__REALTIME_TIMESTAMP"] and
            float(copied["start"]["__REALTIME_TIMESTAMP"])/1e6 >= start["observed"] - 2 and
            float(copied["terminal"]["__REALTIME_TIMESTAMP"])/1e6 <= custody["time"] + 2,
            "transfer invocation interval")
    return dict(compiler_excess_ram=3*gib-room["rooms"]["build_ram"], concluded_copier_ram=intake["additional_ram"],
                retained_build_ram=2*gib, retained_holding_ram=2*gib, retained_input_home=intake["additional_home"],
                compiler_image=room["compiled_baseline"]["image_physically_funded_bytes"],
                compiler_terminals=events, input_terminal=copied, issued_input=intake["custody"], ending_disk_bytes=0)
