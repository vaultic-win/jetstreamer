# Chronological R2 audit deployment

The persistent service `horizon-r2-chronological-plugin-audit-20261118-v1.service`
was enabled and started at 2026-11-18 21:46:22 UTC. Its initial invocation is
`9273f20a0025480bb12809beb52dea82`, controller PID 1534775. It fetched
`account-updates` and began compiling the reader at 21:46:39 UTC before epoch 0.
This records startup, not a successful archive playback.

The authenticated inventory contains 225 canonical archives, 16,504,898,595,724
bytes total, spanning epochs 0–960 with gaps. The runner processes its frozen
inventory in numeric order. It saves each result before deleting its own scratch
copy; source archives and R2 objects remain intact. A successful result requires
whole authenticated readback, complete current-plugin playback, actual boundary
observations, matching structured report/log counters and a clean exit.

Inspect it without a model or agent:

```sh
sudo /usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261118-v1/audit status /usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261118-v1/config.json
sudo journalctl -u horizon-r2-chronological-plugin-audit-20261118-v1.service -n 30 --no-pager
```

State, progress, child activity, inventory, results and attempt logs live under
`/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1`. The installed
runner SHA-256 is `df419d9a398f3dd777e996c5a11d1fbc3cff8f5e9f11603c981aded906494954`.
Its source was published as `c8755794cd267a2843b480ed5d9c6aa740c0aad9`;
15 tests and strict Clippy passed before deployment. Reader generations are
separately sealed beneath `/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1`.

The service uses the root filesystem, preserving 32 GiB free, with a 16 GiB
archive cap and 16 GiB working budget. It has CPU quota 400%, memory limit 32 GiB,
two build jobs and four plugin workers. These are audit resources, not replay
lanes, and must be included in subsequent whole-host admission accounting.
The first archive exceeding this cap is epoch 74; qualify larger scratch capacity
or a state migration before reaching it. The script waits rather than skipping
an epoch or consuming replay reservations. The largest queued archive is epoch
941 at 385,290,386,716 bytes. Restart recovery is independent of conversation
state and retains completed results.

Campaign continuity at startup: epoch 166 remains the only observed replay lane.
The accepted 21:19:25 UTC sample shows slot 71,730,174, 2.2812 slots/sec and zero
restarts. All 19 active status JSONs were refreshed with authenticated readback.
The sole next replay observer is armed for 21:49:25 UTC. Epoch 141 holding is
still running; no newly parked bytes have been credited or locally retired.
The next epoch 167 admission remains dependent on actual reclaimed space.
