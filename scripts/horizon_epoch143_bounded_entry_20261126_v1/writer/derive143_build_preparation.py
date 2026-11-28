"""Derive the guarded native build from the successful closed-allocation copy gate."""

import json
from pathlib import Path
import sys

from derive143_bootstrap_retry import change, read_package
from derive143_v53 import member_plan

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-second-hourly-20261128-v1")
COPY = BASE/"preparation-tools-v2"
COPY_SEAL = "c5ed0f0ef7dc9c86936023ed686ff8f9ddfec23c05b2d4489557231e1eb3f3ed"
BUILD = BASE/"preparation-build-v2"
WORKTREE = Path("/home/sol/.jetstreamer-private/epoch143-hourly-closure-20261128.BYOcX2fH/source")
CUSTODY_SHA = "29bae456ca9d5e7c14a0b96a6ba4709556da62079028b6a8b5687fc315d3134c"
COPY_UNIT = "horizon-prepare-143-hourly-copy-20261128-v2.service"


def derive(work, revision, price_version, price_sha):
    package = read_package(COPY, COPY_SEAL)
    src, mode = package["dispatch143_second_copy.py"]
    s = src.decode()
    s = s.replace("preparation-tools-v2", BUILD.name)
    s = s.replace("horizon-prepare-143-hourly-copy-20261128-v2","horizon-prepare-143-hourly-build-20261128-v1")
    s = s.replace("horizon-guard-143-hourly-copy-20261128-v2","horizon-guard-143-hourly-build-20261128-v1")
    s = s.replace('"copy-guard-v2"','"build-guard-v1"').replace('"COPY_ADMISSION_V2.json"','"BUILD_ADMISSION_V2.json"')
    s = change(s,'INPUT = RUN / "input"', 'INPUT = RUN / "build"')
    s = s.replace("issued-price-v18",f"issued-price-v{price_version}")
    s = s.replace("8c326db152e86c7723771501a225607de66012c6cc6f619e9da452335c627e4a",price_sha)
    s = change(s, "MAX_BYTES = BYTES + 64*M\nMEM = 512*M\nRUNTIME = 720",
               "MAX_BYTES = 32<<30\nMEM = 32<<30\nRUNTIME = 3600")
    s = change(s, '        pinned = json.loads((RT/"epoch143-bootstrap-custody-20261126-v1/GENERATION_CUSTODY.json").read_bytes())',
               f'''        need(ref(BASE / "INPUT_CUSTODY.json")["sha256"] == "{CUSTODY_SHA}", "build has no completed bootstrap custody")
        copy = native("{COPY_UNIT}", "Id,ActiveState,MainPID,ControlPID,Job",not_found=True)
        need(copy["ActiveState"] == "inactive" and copy["MainPID"] == copy["ControlPID"] == "0"
             and not copy["Job"], "GCS copy still uses the 143 build allocation")
        checkout = Path("{WORKTREE}")
        need(run("/usr/bin/git","-C",str(checkout),"rev-parse","HEAD").strip() == "{revision}"
             and not run("/usr/bin/git","-C",str(checkout),"status","--short").strip(),
             "build source differs from the merged revision")''')
    # This read-only root checkout uses the sol-owned shared Git directory.
    s = s.replace('"/usr/bin/git","-C",str(checkout)',
                  '"/usr/sbin/runuser","-u","sol","--","/usr/bin/git","-C",str(checkout)')
    s = change(s, '"--property=CPUQuota=50%"', '"--property=CPUQuota=200%"')
    s = change(s, '"--property=TasksMax=128"', '"--property=TasksMax=512"')
    a = s.index('                f"--property=ReadWritePaths=')
    b = s.index('            active = True',a)
    s = s[:a] + f'''                f"--property=ReadWritePaths={{INPUT}} /home/sol/.cargo",
                f"--property=WorkingDirectory={WORKTREE}",
                "--setenv=RUSTUP_HOME=/home/sol/.rustup","--setenv=CARGO_HOME=/home/sol/.cargo",
                f"--setenv=CARGO_TARGET_DIR={{INPUT}}/target",f"--setenv=TMPDIR={{INPUT}}",
                "--setenv=CARGO_INCREMENTAL=0","--setenv=CARGO_PROFILE_RELEASE_LTO=thin",
                "--setenv=CARGO_PROFILE_RELEASE_CODEGEN_UNITS=8","--setenv=RUST_MIN_STACK=67108864",
                f"--property=BindReadOnlyPaths={{PACKAGE}}:/run/horizon143-prep-tools {{BASE / 'permits'}}:/run/horizon143-preparation-permits",
                "--property=ExecStartPre=/usr/bin/python3 -IB /run/horizon143-prep-tools/prepare143_second_gate.py build",
                "--","/home/sol/.cargo/bin/cargo","build","--locked","--offline","--release","-j","2",
                "--package","jetstreamer-node","--bin","jetstreamer-node",
                "--features","epoch143-hourly-continuation-diagnostic")
''' + s[b:]
    s = s.replace('"--expected-tasks-max","128"', '"--expected-tasks-max","512"')
    s = s.replace('"--expected-cpu-quota-usec","500000"', '"--expected-cpu-quota-usec","2000000"')
    s = s.replace('"--on-unit-inactive=4s"', '"--on-unit-inactive=10s"')
    s = s.replace('f"copy-v2-{iid}.json"', 'f"build-{iid}.json"')
    s = change(s,'schema="horizon-143-guarded-copy-admission-v1",source=SOURCE,snapshot_bytes=BYTES,',
               f'schema="horizon-143-guarded-build-admission-v1",source_revision="{revision}",')
    # The build tree is drawn from the existing 64 GiB, so price only its
    # unspent collateral. GCS custody is already physically charged.
    s = change(s, 'quote["home_margin"] >= MAX_BYTES', 'quote["home_margin"] >= 8*M')
    s = change(s, 'floor = quote["required_home"]', 'floor = quote["required_home"] - MAX_BYTES')
    files = {name: package[name] for name in ("guard-preparation","prepare143_second_gate.py")}
    files["dispatch143_second_build.py"] = (s.encode(),mode)
    files["SOURCE.json"] = ((json.dumps(dict(branch="account-updates",revision=revision,
        copied_tools_seal=COPY_SEAL,provider_seal=price_sha),indent=2)+"\n").encode(),0o444)
    return member_plan(files,work,BUILD)


if __name__ == "__main__":
    print(json.dumps(derive(Path(sys.argv[1]),sys.argv[2],int(sys.argv[3]),sys.argv[4]),indent=2))
