#!/bin/sh
set -eu
test "$(/usr/bin/id -u)" = 1000
test "$(/usr/bin/id -g)" = 1000
/usr/bin/id
/usr/bin/cat /proc/self/mountinfo
for p in /home/ubuntu/.jetstreamer-private/qualification-233-general-target1-fsize-repair-v1/output /home/ubuntu/horizon /home/ubuntu/.jetstreamer-private/destination-cc16e4ac982549c49990203164025f5c92247f275e6530e0654ed82c45a07519 /home/ubuntu/.jetstreamer-private/epoch233-delivery-logs-v4/import-v2; do
 test -d "$p"
 test -w "$p"
 /usr/bin/findmnt --noheadings --output ID,TARGET,VFS-OPTIONS --target "$p"
done
for p in /home/ubuntu/workspace /home/ubuntu/.config /home/ubuntu/.codex /home/ubuntu/.cargo /home/ubuntu/.rustup /home/ubuntu/.cache /home/ubuntu/.jetstreamer-private/qualification-233-general-target1-fsize-repair-v1/state; do
 test ! -w "$p"
 /usr/bin/findmnt --noheadings --output ID,TARGET,VFS-OPTIONS --target "$p"
done
/usr/bin/cat /proc/self/status
/usr/bin/cat /proc/self/limits
