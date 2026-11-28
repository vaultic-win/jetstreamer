# Epoch 257 protective stop under a private systemd manager

The ignored Rust test holds the sealed native harness before its release token, arms its actual guard with a forced filesystem floor and checks the original owner, sample, stop intent, stop request, PID 1 journal entries, SIGTERM and cgroup drainage. The fixture has no snapshot, worker or input packet. Its result carries `host_protective_stop_qualification=false`. Production qualification still requires a fresh full-fit host admission.

## Stage a booked invocation

Use a new root-owned stage named `/run/horizon257-exact-stop-sandbox-v<cycle>-v<attempt>`. The outer service name is the stage basename followed by `.service`. Install `boot` at the stage root and the remaining fixture files beside the compiled Rust test executable under `src/`. Name the test executable `sandbox-tests`. Its fully qualified test name appears in `driver.service`.

Copy both hash-pinned images from the measured deployments identified by `native257.rs` into `src/` as `horizon257-native-input` and `horizon257-native-guard`. Copy the four sealed bodies for the `takeover-guard-v1` attempt into `src/units/` using their real service, target and timer names. Verify each original digest. In the fixture copy, bind the guard service’s ExecStart to the selected guard executable and its SHA-256. Bind the producer’s CPUAffinity to the booked CPU. Include those exact unit bytes in the fixture manifest. Make the stage and its source root-owned and read-only. Write a sorted, stage-relative `source.sha256` from inside `src/` that covers every file in that directory. The boot script rechecks this manifest.

The controller books one eligible CPU with a quota of one CPU, 1 GiB maximum memory, zero swap, 192 tasks, a 150-second runtime and a five-second stop timeout. The outer service uses `Type=exec`, root, no restart, `KillMode=control-group`, CPU/memory/PID controller delegation, `ProtectControlGroups=no`, `PrivateNetwork=yes`, `PrivateDevices=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, and an executable, private 224 MiB tmpfs on `/tmp`. It gives the result directory write access and limits each file to 16 MiB. The measured outer unit used `UMask=0022`, `Nice=10`, `IOWeight=10`, `NoNewPrivileges=no` and this capability bounding set.

```text
CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_KILL CAP_CHOWN CAP_FOWNER CAP_SETPCAP CAP_SYS_RESOURCE CAP_MKNOD CAP_AUDIT_WRITE CAP_SYS_NICE CAP_FSETID
```

Clear Horizon and AWS service credentials from the unit environment. Check the exact properties, CPU and capability set against the current booking.

Once booked, mount a distinct 32 MiB tmpfs on the empty `result/` directory with `mode=0700,uid=0,gid=0,nosuid,nodev,noexec`. Execute the staged `boot` as that service. The guest has its own namespace root, private PID 1, manager bus and delegated cgroup subtree. Its only writable bind to host files is the retained result mount.

## Inspect the result

Require outer exit status zero, the Rust test's pass in `driver.stdout`, and `sandbox-comparison.json`. The original guest files under `guest-files/` retain the exact bytes and names referenced by `protective-stop-capture.json`. Paths beginning with `/evidence/` resolve at the result mount. The original source and terminal evidence can be hashed after the outer service drains. Retain the booking, invocation ID, source hashes, captured journals and separate outcomes for failed attempts.

The private manager can report that per-service network namespace creation is unavailable inside the already network-isolated guest. The receipt establishes the pretoken guard stop inside that guest. Host admission and host service restrictions require their own evidence.
