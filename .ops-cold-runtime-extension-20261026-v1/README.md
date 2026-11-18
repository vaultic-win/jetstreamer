The existing cold park is healthy, but measured whole-object readback may exceed
its original four-hour service limit. Its readback allocates no archive copy or
new growth claim, and its two GiB cap remains inside the standing native pool.

Systemd rejected live RuntimeMaxSec through set-property in a disposable sleep
service; the actual park was not changed. Qualify an immutable runtime drop-in
and daemon reload on a second disposable service first. Verify unchanged native
identity, survival beyond the old deadline, termination at the new finite bound,
and unchanged replay identities and pending monitor deadlines after reload.
Only then prepare a separately bound six-hour extension for the exact live park.
Preserve every original launch/funding/deployment record and resource limit.
