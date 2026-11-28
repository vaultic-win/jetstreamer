"""Bind the serial owner and the separate 16 MiB reclamation sublease to their native processes."""
from hashlib import file_digest
import json
from pathlib import Path
import re
import stat

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch157-lanej-rotation-20261128-v1")
DIRECTORY = BASE / "turnover-tools-v5"
IMAGE = DIRECTORY / "rotation"
SEAL = dict(path=str(DIRECTORY / "deployment-seal-receipt.json"),
            sha256="409008cf366a5cc28c41088b3b1a9dd7cd89cb0a273b8162ecbe24b4ce70fe60")
IMAGE_SHA = "7205d260bddd40612b5ecd2f004491c02f6d3d2e895aeca207ee020b20b8a56b"
FAMILY = re.compile(r"horizon-closed157-(retire|restore)-lanej-([0-9]+)\.service")
AUX = re.compile(r"horizon-157-lanej-(fixture|census|custody)-([0-9]+)\.service")
META = 16 << 20
LIMITS = {"fixture":(256 << 20,250000), "census":(512 << 20,500000),
          "custody":(256 << 20,250000), "retire":(1 << 30,1000000), "restore":(2 << 30,2000000)}


def registered(core):
    pack = core.bound(SEAL)
    member, = (m for m in pack["members"] if m["name"] == "rotation")
    st = IMAGE.lstat()
    core.need(pack["destination"] == str(DIRECTORY) and member["sha256"] == IMAGE_SHA
              and IMAGE.resolve(strict=True) == IMAGE and stat.S_ISREG(st.st_mode)
              and st.st_uid == st.st_gid == 0 and st.st_nlink == 1 and not st.st_mode & 0o222
              and st.st_size == member["bytes"], "different 157 reclamation operator")
    with IMAGE.open("rb") as f:
        core.need(file_digest(f,"sha256").hexdigest() == IMAGE_SHA, "changed 157 reclamation image")
    return SEAL


def confirm(core, name, pattern):
    match = pattern.fullmatch(name)
    core.need(match is not None, "unknown 157 admission " + name)
    phase = match[1]
    checked = json.loads(core.cmd(str(IMAGE),"live-holder",name))
    admission = core.bound(checked["admission"])
    start = core.bound(checked["start"])
    ram, cpu = LIMITS[phase]
    core.need(checked["phase"] == phase and checked["native"]["Id"] == name
              and start["invocation"] == checked["native"]["InvocationID"]
              and start["admission"] == checked["admission"] and admission["operator_seal"] == SEAL
              and admission["phase"] == phase and admission["unit"] == name
              and admission["serial_holding_slot"] == (pattern is FAMILY)
              and admission["memory_max"] == ram and admission["cpu_micros"] == cpu
              and admission["maximum_evidence"] == META and not admission["swap"]
              and checked["resource_credit_bytes"] == 0, "different paid 157 phase")
    if phase != "restore":
        whole = core.bound(admission["whole_roster"])
        scope = whole["epoch157_scoped_candidate"]
        core.need(scope["fits"] and scope["phase"] == phase and scope["provider"] == admission["provider"]
                  and scope["fleet"] == whole["fleet"] and scope["writer"] == whole["writer"]
                  and scope["ram_bytes"] == ram and scope["cpu_micros"] == cpu and scope["home_bytes"] == META
                  and scope["source_terminal"]["sha256"] == "71141c7de11f90d96733a7dcdfc948369dc20ed97f6962e5fe355bc91e3ff34b"
                  and not scope["resource_credit_bytes"] and not scope["planned_retirement_credit_bytes"]
                  and not scope["general_admission"], "unbound 157 sublease")
    return checked


def holder(core, units):
    registered(core)
    core.need(len(units) == 1, "several actors claim the shared holding slot")
    return confirm(core, next(iter(units)), FAMILY)


def account(whole, core):
    core.need("epoch157_lanej_rotation" not in whole and not whole["resource_credit_bytes"], "duplicate 157 price")
    registered(core)
    paid = whole["base_169"]["accounting"]
    core.need(paid["serial"]["repeated_serial_bytes"] == 2 << 30, "serial RAM reservation changed")
    current = paid["holding"]
    holding = current if current and FAMILY.fullmatch(current.get("native",{}).get("Id","")) else None
    text = core.cmd("/usr/bin/systemctl", "list-units", "--no-pager", "--plain", "--no-legend", "--type=service",
                    "--state=running,activating,deactivating,reloading", "horizon-157-lanej-*")
    aux = [line.split()[0] for line in text.splitlines() if line.strip()]
    core.need(len(aux) <= 1 and not (aux and holding), "several actors claim the 157 reclamation sublease")
    metadata = confirm(core, aux[0], AUX) if aux else None
    active = metadata or (holding if holding and holding["phase"] == "retire" else None)
    charge = dict(home_bytes=0, ram_bytes=0, cpu_micros_per_second=0)
    if active:
        core.need(whole["epoch167_private_assembly"]["phase"] == "unbooked", "unreleased 157 sublease at 167 assembly")
        charge["home_bytes"] = META
        if metadata:
            charge["ram_bytes"], charge["cpu_micros_per_second"] = LIMITS[metadata["phase"]]
        unused = whole["closed_167_suballocations"]["unassigned"]
        core.need(all(unused[k] >= n for k,n in charge.items()), "157 sublease exceeds its 167 reservation")
        whole["closed_167_suballocations"]["unassigned"] = {k:n-charge[k] for k,n in unused.items()}
    whole["epoch157_lanej_rotation"] = dict(operator_seal=SEAL, holder=holding, metadata=metadata,
            serial_slot_bytes=123350028052, sublease=charge, resource_credit_bytes=0)
    return whole
