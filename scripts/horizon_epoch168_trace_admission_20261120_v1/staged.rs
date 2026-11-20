//! Accept staged bytes only after the genuine payload verified the copy and exec'd the
//! original node in the same guarded systemd invocation. No bank restoration is implied.
use super::*;
const NODE: &str = "/usr/local/lib/jetstreamer/horizon-independent168-singleton-package-20261109-v1/jetstreamer-node";
const SNAP: &str = "snapshot-72575704-Grdro3ninCQfmShQL6ypGv2y1gUzhPPB7xbj9M4UHJnx.tar.zst";
pub(super) fn capture(id: &str, pid: u64, timer_id: &str) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(240);
    let dir = Path::new(DEST);
    let file = dir.join("inputs.json");
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
            v["schema"] == "epoch168-private-trace-inputs-v1"
                && v["invocation_id"] == id
                && v["node_sha256"]
                    == "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65"
                && v["worker_sha256"]
                    == "97f6bd75e7d9a7ec44931172d2e7ce8e585ecd4434372c57b2dce44a770bfda6"
                && v["bootstrap_sha256"]
                    == "f1a8902dcb00eb59266a2f688d05f7d406af1999eb78956bfd0c46056571ad04"
                && v["bootstrap_bytes"] == 2_029_219_745u64
                && v["target_slot"] == 72_728_191
                && v["target_entry"] == 433
                && v["target_transaction"] == 532
                && v["terminal_checkpoint"] == 73_007_829
                && v["publication_authorized"] == false,
            "wrong staging provenance"
        );
        let mut inputs = json!({});
        for (n, len) in [(SNAP, 2_029_219_745u64), ("ledger/genesis.tar.bz2", 20_144)] {
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
        let sinks = fs::metadata(dir.join("producer.log"))?;
        for fd in ["1", "2"] {
            let x = fs::metadata(format!("/proc/{pid}/fd/{fd}"))?;
            ensure!(
                x.dev() == sinks.dev() && x.ino() == sinks.ino(),
                "changed private output binding"
            );
        }
        let current = show(UNIT)?;
        ensure!(
            current["InvocationID"] == id
                && current["MainPID"] == native["MainPID"]
                && current["ActiveState"] == "active",
            "changed staging owner"
        );
        return Ok(
            json!({"actual_native":current,"verified_by_sealed_payload":binding(&file,&digest(&b)),"private_input_files":inputs,"protected_timer":t,"node_device":exe.dev(),"node_inode":exe.ino(),"bank_restoration_proven":false,"transaction_replay_claimed":false}),
        );
    }
    bail!("verified snapshot staging and node exec exceeded 240s")
}
