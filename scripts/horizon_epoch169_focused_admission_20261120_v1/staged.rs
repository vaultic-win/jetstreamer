//! Accept staged bytes only after the genuine payload verified the copy and exec'd the
//! original node in the same guarded systemd invocation. No bank restoration is implied.
use super::*;
const NODE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-replay-20261120-g1/node-v1/jetstreamer-node";
const SNAP: &str = "snapshot-73007829-AgJkU9ZTLnhbCHK54yWFCG4N9sxbtLPRgkCZqwpdWF9R.tar.zst";
// These native log lines precede worker initialization. They prove that this invocation
// passed batch recovery and resolved its actual worker, not that any bank was replayed.
fn native_route(log: &[u8]) -> bool {
    let text = String::from_utf8_lossy(log);
    let Some((_, rest)) = text.split_once("acquired 1 epoch publication lease(s) for 169-169")
    else {
        return false;
    };
    let Some((_, rest))=rest.split_once("epoch 169: selected execution profile solana-v1.5.8 (Candidate) from slots 73008000..73245219") else { return false };
    rest.contains("starting isolated solana-v1.5.8 worker /run/horizon-169-focused-worker")
}
pub(super) fn capture(id: &str, pid: u64, timer_id: &str) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(240);
    let dir = Path::new(DEST);
    let attempt = Path::new(ATTEMPT);
    let file = attempt.join("inputs.json");
    let baseline = fs::metadata(NODE)?;
    while Instant::now() < deadline {
        let native = show(UNIT)?;
        ensure!(
            native["InvocationID"] == id
                && native["MainPID"]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    == Some(pid)
                && native["ActiveState"] == "active"
                && native["NRestarts"] == "0",
            "producer lost during staging"
        );
        let t = show(TIMER)?;
        ensure!(
            t["InvocationID"] == timer_id
                && t["ActiveState"] == "active"
                && !Path::new(RECEIPTS).join("stop-intent.json").try_exists()?,
            "guard lost during staging"
        );
        let exe = fs::metadata(format!("/proc/{pid}/exe"))?;
        if (exe.dev(), exe.ino()) != (baseline.dev(), baseline.ino()) {
            thread::sleep(Duration::from_millis(500));
            continue;
        }
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&file)?;
        let m = input.metadata()?;
        let dev = fs::metadata("/home/sol")?.dev();
        ensure!(
            m.is_file()
                && m.dev() == dev
                && m.mode() & 0o7777 == 0o400
                && m.uid() == 1001
                && m.gid() == 1003
                && m.nlink() == 1
                && m.len() <= 8192,
            "invalid staged inputs receipt"
        );
        let mut b = Vec::new();
        input.read_to_end(&mut b)?;
        let v: Value = serde_json::from_slice(&b)?;
        ensure!(
            v["schema"] == "epoch169-private-trace-inputs-v1"
                && v["invocation_id"] == id
                && v["node_sha256"]
                    == "7cd290140ae1097fb8caa573a4afcffd55d4a279dc07fefe6e9299936d39c71e"
                && v["worker_sha256"]
                    == "44f39109586d7e2cabdb03e3b781949d64ed0c2a3591067b382a6eb590f77cf4"
                && v["bootstrap_sha256"]
                    == "6e48d311c0f3b5e95f40968d46aac3919d6b7f84f5b63ad0d2a81c0b0ee51ab0"
                && v["bootstrap_bytes"] == 2_109_034_648u64
                && v["target_slot"] == 73_239_086
                && v["target_entry"] == 164
                && v["target_transaction"] == 205
                && v["terminal_checkpoint"] == 73_245_218
                && v["publication_authorized"] == false
                && v["private_run_root"] == format!("{ATTEMPT}/private")
                && v["reused_staging"] == true,
            "wrong staging provenance"
        );
        let mut inputs = json!({});
        for (n, len) in [(SNAP, 2_109_034_648u64), ("genesis.tar.bz2", 20_144)] {
            let p = dir.join(n);
            let m = fs::symlink_metadata(&p)?;
            ensure!(
                p.canonicalize()? == p
                    && m.is_file()
                    && m.dev() == dev
                    && m.uid() == 1001
                    && m.gid() == 1003
                    && m.nlink() == 1
                    && m.mode() & 0o7777 == 0o400
                    && m.len() == len,
                "staged object identity {}",
                p.display()
            );
            inputs[n] = json!({"device":dev,"inode":m.ino(),"size":len});
        }
        let log_path = attempt.join("producer.log");
        let log = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&log_path)?;
        let sinks = log.metadata()?;
        ensure!(
            sinks.is_file()
                && sinks.dev() == dev
                && sinks.nlink() == 1
                && sinks.uid() == 1001
                && sinks.gid() == 1003
                && sinks.mode() & 0o7777 == 0o600,
            "changed private log custody"
        );
        for fd in ["1", "2"] {
            let x = fs::metadata(format!("/proc/{pid}/fd/{fd}"))?;
            let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))?;
            let flags = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:"))
                .context("missing fd flags")?;
            let flags = i32::from_str_radix(flags.trim(), 8)?;
            ensure!(
                flags & libc::O_APPEND != 0,
                "private log descriptor is not append-only"
            );
            ensure!(
                x.dev() == sinks.dev() && x.ino() == sinks.ino(),
                "changed private output binding"
            );
        }
        let mut prefix = Vec::new();
        log.take(256 << 10).read_to_end(&mut prefix)?;
        if !native_route(&prefix) {
            ensure!(
                prefix.len() < 256 << 10,
                "native worker route missing from first 256 KiB"
            );
            thread::sleep(Duration::from_millis(250));
            continue;
        }
        let current = show(UNIT)?;
        let final_timer = show(TIMER)?;
        let final_exe = fs::metadata(format!("/proc/{pid}/exe"))?;
        ensure!(
            (final_exe.dev(), final_exe.ino()) == (exe.dev(), exe.ino())
                && final_timer["InvocationID"] == timer_id
                && final_timer["ActiveState"] == "active"
                && !Path::new(RECEIPTS).join("stop-intent.json").try_exists()?,
            "changed node or guard during native observation"
        );
        ensure!(
            current["InvocationID"] == id
                && current["MainPID"] == native["MainPID"]
                && current["ActiveState"] == "active",
            "changed staging owner"
        );
        return Ok(
            json!({"actual_native":current,"verified_by_sealed_payload":binding(&file,&digest(&b)),"private_input_files":inputs,"protected_timer":t,"node_device":exe.dev(),"node_inode":exe.ino(),"native_preworker_log":{"path":log_path,"device":sinks.dev(),"inode":sinks.ino(),"prefix_bytes":prefix.len(),"prefix_sha256":digest(&prefix)},"bank_restoration_proven":false,"transaction_replay_claimed":false}),
        );
    }
    bail!("verified snapshot staging and node exec exceeded 240s")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_three_ordered_native_log_records() {
        let lease = "acquired 1 epoch publication lease(s) for 169-169";
        let profile = "epoch 169: selected execution profile solana-v1.5.8 (Candidate) from slots 73008000..73245219";
        let worker = "starting isolated solana-v1.5.8 worker /run/horizon-169-focused-worker";
        assert!(native_route(
            format!("{lease}\n{profile}\n{worker}").as_bytes()
        ));
        assert!(!native_route(
            format!("{lease}\n{worker}\n{profile}").as_bytes()
        ));
        assert!(!native_route(
            format!("{lease}\narchive batch state remains closed").as_bytes()
        ));
    }
}
