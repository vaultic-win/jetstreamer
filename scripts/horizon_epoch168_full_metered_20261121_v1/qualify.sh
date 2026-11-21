#!/bin/bash
# Root, in an already admitted bounded helper with a private mount namespace
# and PrivateNetwork=yes. All persistent data uses the home-backed runtime.
set -euo pipefail
umask 077
src=$(cd "$(dirname "$0")" && pwd -P)
state=/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1
root=/home/sol/.jetstreamer-private/full168-offline-qualification-20261121-v1
attempt="$state/qa-$INVOCATION_ID"
mkdir -p -m0700 "$state" "$attempt"
stage="$attempt/sources"
mkdir -m0700 "$stage"
for item in payload.py offline.py; do install -m0444 "$src/$item" "$stage/$item"; done
/usr/bin/python3 -IB "$stage/payload.py" > "$attempt/payload.json"
# Existing production files cannot be modified by the fixture. A subsequent
# attempt reuses the exact sealed package and starts with an empty fixture tree.
seal=/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment
self=e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3
test "$(sha256sum "$seal" | cut -d' ' -f1)" = "$self"
python3 -IB - "$attempt" "$state" <<'PY'
from pathlib import Path
import json,hashlib,sys
q,r=map(Path,sys.argv[1:])
j=json.loads((q/'payload.json').read_bytes())
members=[]
for name,(path,digest) in j['members'].items():
    if name.endswith('.json'):
        members.append(dict(name=name,source=path,sha256=digest,mode=0o444))
for name,path in [('payload.json',q/'payload.json'),('offline.py',q/'sources/offline.py')]:
    members.append(dict(name=name,source=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),mode=0o444))
(q/'plan.json').write_text(json.dumps(dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(r/'inputs-v1'),members=members)))
PY
if [[ ! -d "$state/inputs-v1" ]]; then
    "$seal" "$attempt/plan.json" --plan-sha256 "$(sha256sum "$attempt/plan.json" | cut -d' ' -f1)" --self-sha256 "$self"
fi
(cd "$state/inputs-v1" && sha256sum --check --status SHA256SUMS)
cmp "$attempt/payload.json" "$state/inputs-v1/payload.json"
cmp "$stage/offline.py" "$state/inputs-v1/offline.py"
test ! -L "$root"
install -d -o root -g root -m0711 "$root"
# This fresh mount hides all fixture paths from host services and is destroyed
# with the transient unit. The native binary inodes come from the installed normal seals.
mount -t tmpfs -o size=32m,uid=1001,gid=1003,mode=0700,nodev,nosuid tmpfs "$root"
install -d -m0700 -o sol -g horizon "$root/ledger" "$root/private"
mkdir -m0755 "$root/runtime"
# Build the actual projection from three normal sealed sources. The two large
# executables remain in their original sealed packages throughout.
mount -t tmpfs -o size=1m,mode=0755,nodev,nosuid tmpfs "$root/runtime"
for srcfile in "$state/inputs-v1"/*; do
    name=${srcfile##*/}
    touch "$root/runtime/$name"
    mount --bind "$srcfile" "$root/runtime/$name"
    mount -o remount,bind,ro "$root/runtime/$name"
done
while IFS=$'\t' read -r name source; do
    touch "$root/runtime/$name"
    mount --bind "$source" "$root/runtime/$name"
    mount -o remount,bind,ro "$root/runtime/$name"
done < <(jq -r '.members|to_entries[]|select(.key|endswith(".json")|not)|[.key,.value[0]]|@tsv' "$attempt/payload.json")
mount -o remount,ro "$root/runtime"
# The original cohort importer needs ledger and private on the same device.
# Source snapshots and retained indexes can remain exact read-only mount points.
python3 -IB - "$root" "$attempt/payload.json" <<'PY'
import json,subprocess,sys,os
from pathlib import Path
root=Path(sys.argv[1]);p=json.loads(Path(sys.argv[2]).read_bytes())
def bind(source,target):
    if source!=target:
        target.parent.mkdir(parents=True,exist_ok=True)
        for ancestor in target.parents:
            if ancestor == root/'ledger':
                break
            os.chown(ancestor,1001,1003)
            os.chmod(ancestor,0o700)
        target.touch(exist_ok=False)
    subprocess.run(['mount','--bind',source,target],check=True)
    subprocess.run(['mount','-o','remount,bind,ro,noatime',target],check=True)
boot=Path(p['bootstrap_file']['path']);bind(boot,boot)
genesis=Path(p['genesis']['path']);bind(genesis,genesis);bind(genesis,root/'ledger/genesis.tar.bz2')
for pair in p['indexes']:
    for name in ['source','independent_trace_copy']:
        f=Path(pair[name]['path']);bind(f,f)
    f=Path(pair['source']['path']);bind(f,root/'ledger/compact-indexes'/f.parent.name/f.name)
PY
setpriv --reuid=sol --regid=horizon --init-groups --no-new-privs /usr/bin/python3 -IB "$root/runtime/offline.py" "$root" > "$attempt/RESULT.json"
(cd "$attempt" && sha256sum RESULT.json payload.json plan.json sources/*) > "$attempt/SHA256SUMS"
