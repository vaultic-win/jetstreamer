//! Check the accepted signed transaction and immutable node/worker bytes independently of the producer.
use super::*;
use std::collections::BTreeSet;
const INPUT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-replay-20261120-g1/inputs-v1";
const NODE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-replay-20261120-g1/node-v1";
const INPUT_SEAL: &str = "2fe7d2fb8ca707b4b122662622587a1d00bf6981781609a2989a7ac7f6f42e69";
const NODE_SEAL: &str = "1f8f198a0fd613379281cb12c867d4de64ab7b4659522ff3947351bf0e9c04b7";
const NODE_SHA: &str = "7cd290140ae1097fb8caa573a4afcffd55d4a279dc07fefe6e9299936d39c71e";
const WORKER_SHA: &str = "44f39109586d7e2cabdb03e3b781949d64ed0c2a3591067b382a6eb590f77cf4";
const CHECK: &str = "epoch-hashes-169-focused.txt";
const HASHES_SHA: &str = "ff65bad30840b3f6d8a8ab0882081e1856d9d8c7923378c46da85a69f131600f";
const WORKER: &str = "jetstreamer-historical-worker-v1-5-8";
const GENESIS: &str =
    "/home/sol/.jetstreamer-private/epoch169-standard-lane-20261109-v1/output/genesis.tar.bz2";
const SNAPSHOT: &str = "/home/sol/.jetstreamer-private/epoch169-standard-lane-20261109-v1/private/destination-d5071eb14bc459360668014134a7a0f1cec90ee78c9360cf175ef3cdd7fab573/work/root-cohort-169-169/run-50818-1794254430868327931/inputs/snapshot-73007829-AgJkU9ZTLnhbCHK54yWFCG4N9sxbtLPRgkCZqwpdWF9R.tar.zst";
fn existing_names(names: &BTreeSet<String>, with_log: bool) -> bool {
    let mut expected = BTreeSet::from([CHECK.to_string()]);
    if with_log {
        expected.insert("producer.log".into());
    }
    names == &expected
}
pub(super) fn existing_destination(p: &Path, log: bool) -> Result<()> {
    let names = fs::read_dir(p)?
        .map(|e| e.map(|i| i.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    ensure!(
        existing_names(&names, log),
        "foreign files in private destination"
    );
    let path = p.join(CHECK);
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let m = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.nlink() == 1
            && m.ino() == 111744589
            && m.len() == 142
            && m.mode() & 0o7777 == 0o600
            && m.uid() == 1001
            && m.gid() == 1003,
        "checkpoint custody"
    );
    let mut b = Vec::new();
    std::io::Read::by_ref(&mut f)
        .take(143)
        .read_to_end(&mut b)?;
    ensure!(digest(&b) == HASHES_SHA, "existing checkpoint digest");
    Ok(())
}
fn sealed(dir: &str, seal_sha: &str, files: &[&str]) -> Result<Value> {
    let directory = Path::new(dir);
    let s = json_pin(&directory.join("deployment-seal-receipt.json"), seal_sha)?;
    ensure!(
        s["destination"] == dir && s["remote_mutations"] == false,
        "wrong input seal"
    );
    let members = s["members"].as_array().context("members")?;
    let mut index = json!({});
    for name in files {
        let mut rows = members.iter().filter(|m| m["name"] == *name);
        let row = rows.next().context("missing sealed member")?;
        ensure!(rows.next().is_none(), "duplicate sealed name");
        let p = directory.join(name);
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            m.mode() & 0o222 == 0 && m.len() == row["bytes"].as_u64().context("member length")?,
            "mutable or truncated member"
        );
        let sha = at(row, "sha256")?;
        pinned(&p, sha)?;
        index[*name] = json!(sha);
    }
    Ok(index)
}
pub(super) fn verify(proof: &Value) -> Result<Value> {
    let nod = sealed(NODE, NODE_SEAL, &["jetstreamer-node", "node-proof.json"])?;
    let inp = sealed(
        INPUT,
        INPUT_SEAL,
        &[
            WORKER,
            CHECK,
            "input-proof.json",
            "production-binding.json",
            "source-lineage.json",
            "request.json",
            "response.json",
            "prior-finalized.json",
            "bootstrap-gcs.json",
            "terminal-gcs.json",
        ],
    )?;
    let nr = json_pin(
        &Path::new(NODE).join("node-proof.json"),
        at(&nod, "node-proof.json")?,
    )?;
    let ir = json_pin(
        &Path::new(INPUT).join("input-proof.json"),
        at(&inp, "input-proof.json")?,
    )?;
    let rr = json_pin(
        &Path::new(INPUT).join("response.json"),
        at(&inp, "response.json")?,
    )?;
    ensure!(
        nr["node_sha256"] == NODE_SHA
            && nod["jetstreamer-node"] == NODE_SHA
            && nr["worker_and_inputs"]["sha256"] == INPUT_SEAL
            && nr["source_commit"] == "dead395c32e6c46d3f600eaffda9554b16123ec4"
            && nr["features"] == json!(["default", "epoch169-v1-5-8-diagnostic"])
            && nr["native_cli_controls"] == json!(["wrong-root", "missing-optin"]),
        "node provenance"
    );
    ensure!(
        ir["worker_sha256"] == WORKER_SHA
            && inp[WORKER] == WORKER_SHA
            && inp[CHECK] == HASHES_SHA
            && ir["worker_commit"] == "061b47a6447c733771a12160ea52ee5f044e20a8"
            && ir["start_slot"] == 73007830
            && ir["failure_slot"] == 73239086
            && ir["terminal_slot"] == 73245218
            && ir["signed_transaction_message_sha256"]
                == "5afa6b1fb68043e3dc4342e6bc12d9b195b7bc3afe5700620122555a8758a22b"
            && ir["verified_ed25519_signatures"]
                .as_array()
                .is_some_and(|v| v.len() == 2)
            && rr["result"]["slot"] == 73239086
            && rr["result"]["meta"]["err"]
                == json!({"InstructionError":[2,"ProgramFailedToComplete"]})
            && ir["worker_tests_passed"] == 44
            && ir["worker_tests_failed"] == 0,
        "signed worker provenance"
    );
    ensure!(
        ir["bootstrap"]["path"] == SNAPSHOT
            && ir["genesis"]["path"] == GENESIS
            && ir["bootstrap"]["generation"] == "1634787450103391"
            && ir["terminal_generation"] == "1634787429412044",
        "bootstrap/terminal lineage"
    );
    let m = fs::symlink_metadata(SNAPSHOT)?;
    ensure!(
        Path::new(SNAPSHOT).canonicalize()? == Path::new(SNAPSHOT)
            && m.is_file()
            && m.dev() == 64512
            && m.ino() == 105595455
            && m.nlink() == 1
            && m.len() == 2_109_034_648,
        "bootstrap identity"
    );
    ensure!(
        proof["node_seal_sha256"] == NODE_SEAL && proof["worker_seal_sha256"] == INPUT_SEAL,
        "controller did not bind upstream seals"
    );
    Ok(
        json!({"input_seal":INPUT_SEAL,"node_seal":NODE_SEAL,"members":[nod,inp],"bootstrap":ir["bootstrap"],"worker_commit":ir["worker_commit"],"node_commit":nr["source_commit"]}),
    )
}
fn flags(line: &str, flag: &str) -> bool {
    line.split(',').any(|s| s == flag)
}
fn mount<'a>(table: &'a str, p: &str) -> Result<&'a str> {
    table
        .lines()
        .filter_map(|l| {
            let words = l.split_whitespace().collect::<Vec<_>>();
            if words.len() > 6 && words[4] == p {
                Some(words[5])
            } else {
                None
            }
        })
        .next_back()
        .context("missing expected mount")
}
pub(super) fn sandbox(pid: u64) -> Result<()> {
    ensure!(pid > 1, "invalid gate PID");
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let root = proc.join("root");
    let mt = fs::read_to_string(proc.join("mountinfo"))?;
    let ps = fs::read_to_string(proc.join("status"))?;
    ensure!(
        ps.lines()
            .any(|l| l.split_whitespace().eq(["NoNewPrivs:", "1"]))
            && ps
                .lines()
                .any(|l| l.split_whitespace().eq(["CapBnd:", "0000000000000000"]))
            && ps.lines().any(|l| l
                .split_whitespace()
                .eq(["Uid:", "1001", "1001", "1001", "1001"])),
        "gate privilege/sandbox mismatch"
    );
    ensure!(
        flags(mount(&mt, DEST)?, "rw") && !flags(mount(&mt, DEST)?, "noexec"),
        "private destination is not writable/executable"
    );
    for (host, alias, executable) in [
        (
            format!("{NODE}/jetstreamer-node"),
            "/run/horizon-169-focused-node",
            true,
        ),
        (
            format!("{INPUT}/{WORKER}"),
            "/run/horizon-169-focused-worker",
            true,
        ),
        (SNAPSHOT.into(), "/run/horizon-169-incident-snapshot", false),
        (GENESIS.into(), "/run/horizon-169-genesis", false),
        (
            format!("{PACKAGE}/gate169"),
            "/run/horizon-169-focused-gate",
            true,
        ),
        (PAYLOAD.into(), "/run/horizon-169-focused-payload", true),
    ] {
        let m = fs::metadata(host)?;
        let a = fs::metadata(root.join(alias.trim_start_matches('/')))?;
        let options = mount(&mt, alias)?;
        ensure!(
            (m.dev(), m.ino()) == (a.dev(), a.ino())
                && flags(options, "ro")
                && (!executable || !flags(options, "noexec")),
            "sandbox bind mismatch at {alias}"
        );
    }
    let b = fs::metadata(format!("{BASE}/barrier"))?;
    let a = fs::metadata(root.join("run/horizon-169-focused-barrier"))?;
    ensure!(
        (b.dev(), b.ino()) == (a.dev(), a.ino())
            && flags(mount(&mt, "/run/horizon-169-focused-barrier")?, "ro"),
        "barrier is not sealed read-only"
    );
    let exe = fs::metadata(proc.join("exe"))?;
    let gate = fs::metadata(Path::new(PACKAGE).join("gate169"))?;
    ensure!(
        (exe.dev(), exe.ino()) == (gate.dev(), gate.ino()),
        "unexpected pre-payload executable"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destination_admits_exact_preexisting_checkpoint() {
        let mut names = BTreeSet::from([CHECK.into()]);
        assert!(existing_names(&names, false));
        names.insert("producer.log".into());
        assert!(existing_names(&names, true));
        assert!(!existing_names(&names, false));
        names.insert("scratch".into());
        assert!(!existing_names(&names, true));
    }
    #[test]
    fn exact_mount_flags() {
        assert!(flags("ro,nosuid", "ro"));
        assert!(!flags("rw,errors=remount-ro", "ro"));
        assert!(mount("1 2 1:0 / /tmp/other ro - ext4 /abc rw", "/tmp").is_err());
    }
}

#[cfg(test)]
mod sealed_inputs_test {
    use super::*;
    #[test]
    #[ignore = "read-only fixture on the campaign host; requires root"]
    fn genuine_sealed_inputs_and_existing_epoch169_tree() {
        verify(&json!({"node_seal_sha256":NODE_SEAL,"worker_seal_sha256":INPUT_SEAL})).unwrap();
        existing_destination(Path::new(DEST), false).unwrap();
        let result = crate::peers::root169().unwrap();
        assert_eq!(result["focused_root_cap"], CAP);
    }
}
