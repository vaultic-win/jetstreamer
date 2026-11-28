"""Common PID1 launch flags for V5e dispatcher and its nonmutating qualification."""
from pathlib import Path

R=Path("/var/lib/jetstreamer/horizon_runtime_data")
DIR=R/"epoch145-phase-dispatch-20261122-v1"
OLD_DIR=R/"epoch145-v5e-delivery-handoff-20261121-v1"
BASE=Path("/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1")
STATUS=Path("/home/sol/.jetstreamer-private/r2-status-receipts")
PARENT=R/"epoch136-parent-handoff-20261121-v1"
CONTROLLER=OLD_DIR/"state/controller.lock"
OP=Path("/run/horizon-epoch171-to136-g1.operation.lock")
MASKS=Path("/run/systemd/system.control")
REG=Path("/run/horizon-epoch171-exclusive-to136-g1")
CRED=Path("/etc/jetstreamer/horizon-r2.env")
INCIDENT=R/"epoch145-guarded-export-20261121-v1/state/a99ed8b51e8a482b805b8a36a11b2700"
NEW="horizon-145-phase-dispatch-20261122-v1.service"
OLD="horizon-145-v5e-delivery-follow-20261121-v1.service"
SEM="horizon-holding-export145-20261121-v1.service"
IID="a99ed8b51e8a482b805b8a36a11b2700"
IMAGE=DIR/"tools-v2/follow145"
# Native release unlinks an owned registry beneath /run itself. Protect the installed
# controller and all other currently existing runtime directories except the mask parent.
# Existing individual lock files must track replacement, so do not inode-bind them.
def props(*, state=DIR/"state", previous=OLD_DIR/"state"):
    ro={str(BASE/"controller"),str(BASE/"tools"),"/run/systemd"}
    ro.update(str(p) for p in Path("/run").iterdir() if p.is_dir() and not p.is_symlink() and p!=REG)
    writes=([previous] if previous is not None else [])+[state,BASE,STATUS,PARENT,Path("/run"),MASKS]
    return ["Type=exec","CPUQuota=25%","CPUWeight=10","Nice=15","MemoryMax=134217728",
            "MemorySwapMax=0","TasksMax=64","Restart=no","KillMode=control-group","UMask=0077",
            "NoNewPrivileges=yes","ProtectSystem=strict","ProtectHome=read-only","PrivateTmp=no",
            "EnvironmentFile="+str(CRED),"ReadWritePaths="+" ".join(map(str,writes)),
            "ReadOnlyPaths="+" ".join(sorted(ro)),"StandardOutput=journal","StandardError=journal"]

def cmd(unit,exe,args=(),extra=(),slice_name="system.slice",*,state=DIR/"state",previous=OLD_DIR/"state"):
    opts=[v for p in [*props(state=state,previous=previous),*extra] for v in ("-p",p)]
    return ["/usr/bin/systemd-run","--quiet","--unit="+unit,"--slice="+slice_name,*opts,"--",str(exe),*map(str,args)]
