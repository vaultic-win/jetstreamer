#!/usr/bin/env bash
# Offline argv/namespace contract only. All files created by the node are in the disposable HOME fixture.
set -euo pipefail
umask 077
[[ $# == 1 ]] || { echo "usage: native-path-test.sh FOCUSED169_TEST_EXECUTABLE" >&2; exit 2; }
exe=$(realpath -- "$1")
[[ -x $exe ]]
here=/home/sol/.jetstreamer-private
[[ $(id -u) == 1001 ]]
node=/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-replay-20261120-g1/node-v1/jetstreamer-node
expected=7cd290140ae1097fb8caa573a4afcffd55d4a279dc07fefe6e9299936d39c71e
[[ $(sudo -n sha256sum "$node" | cut -d' ' -f1) == "$expected" ]]
for layout in enclosed sibling preworker; do
    fixture=$(mktemp -d "$here/epoch169-offline-path.XXXXXXXX")
    mkdir -m 700 "$fixture"/{v158,attempt-g4} "$fixture"/v158/scratch "$fixture"/attempt-g4/{tmp,private}
    printf '%s' native-node-path-fixture > "$fixture/attempt-g4/OFFLINE_FIXTURE"
    sudo -n unshare --mount --net --propagation private -- /bin/bash -euo pipefail -c '
      src=$1; node=$2; exe=$3; layout=$4
      lane=/home/sol/.jetstreamer-private/epoch169-focused-diagnostic-20261117-v1
      [[ $(readlink /proc/self/ns/mnt) != "$(readlink /proc/1/ns/mnt)" ]]
      [[ $(readlink /proc/self/ns/net) != "$(readlink /proc/1/ns/net)" ]]
      snap=snapshot-73007829-AgJkU9ZTLnhbCHK54yWFCG4N9sxbtLPRgkCZqwpdWF9R.tar.zst
      if [[ $layout == preworker ]]; then
          for name in "$snap" genesis.tar.bz2 epoch-hashes-169-focused.txt; do
              file=$src/v158/$name
              touch "$file"
              mount --bind "$lane/v158/$name" "$file"
              mount -o remount,bind,ro "$file"
              [[ $(stat -c %i "$file") == "$(stat -c %i "$lane/v158/$name")" ]]
          done
      fi
      mount --rbind "$src" "$lane"
      [[ $(stat -c %i "$lane") == "$(stat -c %i "$src")" ]]
      mount -t tmpfs -o nosuid,nodev,size=1M tmpfs /run
      touch /run/horizon-169-focused-node
      mount --bind "$node" /run/horizon-169-focused-node
      mount -o remount,bind,ro /run/horizon-169-focused-node
      timeout 20s setpriv --reuid=1001 --regid=1003 --clear-groups --no-new-privs env FIXTURE_RECEIPTS="$layout" "$exe" --exact tests::native_node_path_control --ignored --nocapture
    ' _ "$fixture" "$node" "$exe" "$layout"
    rm -r --one-file-system -- "$fixture"
done
