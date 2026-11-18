//! Dormant epoch 251 source packet; preserves the exact 250 service protection.
use super::*;
use std::process::Command;

const BASE251: &str = "/var/lib/jetstreamer/horizon250-reboot-20261117-static-v2";
const ROOT251: &str = "/home/ubuntu/.jetstreamer-private/qualification-251-replacement-20261118-v1";
const PREFIX251: &str = "/var/lib/jetstreamer/horizon251-replacement-20261118";
const CACHE251: &str = "/var/lib/jetstreamer/horizon251-index-cache-20261118-v1";
const INPUT251: &str = "/var/lib/jetstreamer/horizon251-native-input-20261118-v1";
const SNAP251: &str = "snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst";
const MANIFEST251: &str = "/var/lib/jetstreamer/horizon251-single-epoch-manifest-20261118-v1/preflight-251-single-epoch.json";
const FINGERPRINT251: &str =
    "sha256:e214b640c55cc6ec0e431c66f9cbd0076c4620578c2dea1e6c2324e7f616789e";
const PROBE251: &str =
    "/home/ubuntu/.codex/diagnostics/horizon251-index-cache-20261118-v1/successor-probe.stdout";
const PROBE_UNIT: &str = "horizon251-successor-source-probe-20261118-v1.service";
const PROBE_IID: &str = "7ecc4812120d446dadce99b3a01d63fb";
const PROBE_NODE: &str =
    "/var/lib/jetstreamer/horizon250-successor-boundary-probe-20261117-v1/jetstreamer-node";
const UNIT251: &str = "horizon-qualify-251-replacement-20261118-v1.service";
const GUARD251: &str = "horizon-251-replacement-20261118-protective-v1.service";
const TIMER251: &str = "horizon-251-replacement-20261118-protective-v1.timer";

pub(super) fn read_bound(path: &str, sha: &str) -> Result<Vec<u8>> {
    let p = Path::new(path);
    let before = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == p
            && before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() < 4 * 1024 * 1024,
        "unsafe metadata: {path}"
    );
    let bytes = fs::read(p)?;
    let after = fs::symlink_metadata(p)?;
    ensure!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec()
        ) == (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        ),
        "changed metadata: {path}"
    );
    ensure!(digest(&bytes) == sha, "metadata digest mismatch: {path}");
    Ok(bytes)
}

pub(super) fn bound_value(path: &str, sha: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&read_bound(path, sha)?)?)
}

fn template(name: &str, sha: &str) -> Result<String> {
    Ok(String::from_utf8(read_bound(
        &format!("{BASE251}/{name}"),
        sha,
    )?)?)
}

fn producer_from(mut s: String) -> Result<String> {
    replace_all(&mut s, ROOT, ROOT251)?;
    replace_all(&mut s, TOKENS, &format!("{PREFIX251}-tokens-v1"))?;
    replace_all(&mut s, CACHE, CACHE251)?;
    replace_one(
        &mut s,
        "Description=General full epoch 250 replay",
        "Description=General full epoch 251 replay",
    )?;
    replace_one(&mut s, "jetstreamer-node 250 ", "jetstreamer-node 251 ")?;
    replace_one(&mut s, MANIFEST, MANIFEST251)?;
    replace_one(&mut s, FINGERPRINT, FINGERPRINT251)?;
    replace_one(
        &mut s,
        &BOOTSTRAP.replace(ROOT, ROOT251),
        &format!("{INPUT251}/{SNAP251}"),
    )?;
    replace_one(
        &mut s,
        &format!(" {ROOT251}/input\n"),
        &format!(" {INPUT251}\n"),
    )?;
    let old_binds = format!(
        "BindReadOnlyPaths={CACHE251}:{ROOT251}/output/compact-indexes/249 {CACHE251}:{ROOT251}/output/compact-indexes/250"
    );
    let new_binds = format!(
        "BindReadOnlyPaths={CACHE251}:{ROOT251}/output/compact-indexes/250 {CACHE251}:{ROOT251}/output/compact-indexes/251 {INPUT251}/genesis.tar.bz2:{ROOT251}/output/genesis.tar.bz2"
    );
    replace_one(&mut s, &old_binds, &new_binds)?;
    // This packet targets a released 247 claim; it cannot be installed over 247.
    replace_one(&mut s, "AllowedCPUs=64-79", "AllowedCPUs=0-15")?;
    replace_one(&mut s, "CPUAffinity=64-79", "CPUAffinity=0-15")?;
    for required in [
        "Restart=no",
        "MemoryMax=251041591296",
        "MemoryHigh=167361060864",
        "MemorySwapMax=0",
        "CPUQuota=800%",
        "RuntimeMaxSec=259200",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ExecStartPre=/usr/bin/test -f",
        "ExecStartPre=/usr/bin/test ! -L",
        "${INVOCATION_ID}/guard-admission.json",
        "--verify --root-checkpoint-cohort",
        "JETSTREAMER_SKIP_SNAPSHOT_VERIFY=0",
        "JETSTREAMER_VERIFY_SNAPSHOTS=1",
    ] {
        ensure!(s.contains(required), "producer lost protection: {required}");
    }
    ensure!(
        !s.contains("horizon250-")
            && !s.contains("qualification-250")
            && !s.contains("/compact-indexes/249"),
        "stale predecessor binding"
    );
    Ok(s)
}

fn validate_probe(output: &Value) -> Result<()> {
    ensure!(
        output["schema"] == "jetstreamer-successor-boundary-source-probe-v1"
            && output["epoch"] == 252
            && output["requested_slot"] == 108864000
            && output["first_block_slot"] == 108864012
            && output["parent_slot"] == 108863995
            && output["production_boundary_reader"] == true,
        "wrong successor boundary"
    );
    for field in [
        "publication_authorized",
        "replay_launch_authorized",
        "r2_mutations",
        "remote_mutations",
    ] {
        ensure!(
            output[field] == false,
            "source probe must not grant {field}"
        );
    }
    Ok(())
}

fn validate_journal(rows: &[Value]) -> Result<()> {
    ensure!(rows.len() == 2, "unexpected probe journal census");
    for r in rows {
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["_COMM"] == "systemd"
                && r["UNIT"] == PROBE_UNIT
                && r["INVOCATION_ID"] == PROBE_IID
                && r["_BOOT_ID"] == "3b17d0055c3a4a0e8841da097e0957b5",
            "foreign probe journal identity"
        );
    }
    ensure!(
        rows[0]["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
            && rows[0]["JOB_RESULT"] == "done"
            && rows[0]["JOB_TYPE"] == "start"
            && rows[0]["MESSAGE"]
                == format!(
                    "Started {PROBE_UNIT} - [systemd-run] {PROBE_NODE} --probe-successor-boundary=108864000."
                )
            && rows[1]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && rows[1]["MESSAGE"] == format!("{PROBE_UNIT}: Deactivated successfully."),
        "probe lacks exact successful lifecycle"
    );
    let time = |v: &Value| -> Result<u64> {
        Ok(v["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("journal time")?
            .parse()?)
    };
    ensure!(
        time(&rows[0])? == 1795028585799964 && time(&rows[1])? == 1795028587290957,
        "probe journal time changed"
    );
    Ok(())
}

pub(super) fn save251(out: &Path, name: &str, bytes: &[u8]) -> Result<Value> {
    ensure!(!name.contains('/'), "unsafe member");
    let path = out.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(json!({"path":path,"sha256":digest(bytes),"bytes":bytes.len()}))
}

pub(super) fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 3,
        "usage: horizon250-replacement-source prepare-251 OUTPUT_DIRECTORY"
    );
    let out = PathBuf::from(&args[2]);
    ensure!(
        out.is_absolute()
            && out.parent().context("output parent")?.canonicalize()? == out.parent().unwrap()
            && fs::symlink_metadata(&out).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "output must be new and canonical"
    );
    let native_path = "/home/ubuntu/.codex/diagnostics/horizon251-native-small-terminal-20261118-v1/terminal-receipt.json";
    let native_sha = "f0e1235e880ec1f8c9a2137256db9ef568f34aef9b0218b3447ad5a0be8da0b3";
    let native = bound_value(native_path, native_sha)?;
    ensure!(
        native["one_exact_test_passed"] == true
            && native["manager_success"] == true
            && native["guard_trips"] == 0
            && native["replay_launch_authorized"] == false,
        "native input test rejected"
    );
    let structure_path =
        "/home/ubuntu/.codex/diagnostics/horizon251-index-cache-20261118-v1/structure-receipt.json";
    let structure_sha = "2336057d7fe4cef0ccbad433027e872a178f173c60630b15c836fb6cf6a23676";
    let structure = bound_value(structure_path, structure_sha)?;
    ensure!(
        structure["epoch"] == 251
            && structure["structure_accepted"] == true
            && structure["native_replay_probe_passed"] == false
            && structure["replay_launch_authorized"] == false,
        "index structural evidence rejected"
    );
    let input_seal_path = format!("{INPUT251}/deployment-seal-receipt.json");
    let input_seal_sha = "1478564db113a40f8870c54f3c9b0c2cc91abd3943e34b823018994f40cafd7c";
    let input = bound_value(&input_seal_path, input_seal_sha)?;
    ensure!(
        input["destination"] == INPUT251 && input["members"][0]["name"] == SNAP251,
        "input seal changed"
    );
    let manifest_sha = "e40e8d0341440d29cff7cd35e79e5f713d7908ce42f3a1c4995e1b2924551f14";
    let manifest = bound_value(MANIFEST251, manifest_sha)?;
    ensure!(
        manifest["manifest_fingerprint"] == FINGERPRINT251
            && manifest["manifest"]["first_epoch"] == 251
            && manifest["manifest"]["last_epoch"] == 251,
        "manifest scope changed"
    );
    let probe_bytes = read_bound(
        PROBE251,
        "e25e942cd3d9fad1f4ace77b4316ea57218718232c3b77585889c1df0273beb1",
    )?;
    let probe: Value = serde_json::from_slice(&probe_bytes)?;
    validate_probe(&probe)?;
    let probe_seal_path = "/var/lib/jetstreamer/horizon250-successor-boundary-probe-20261117-v1/deployment-seal-receipt.json";
    let probe_seal_sha = "85829367cf816da5bd5884d7f35c87dd35aaec80b0ed5124be731f9353b4006d";
    bound_value(probe_seal_path, probe_seal_sha)?;
    let captured = Command::new("/usr/bin/journalctl")
        .args(["-u", PROBE_UNIT, "--no-pager", "--all", "-o", "json"])
        .output()?;
    ensure!(
        captured.status.success() && captured.stderr.is_empty(),
        "journal capture failed"
    );
    let rows = captured
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    validate_journal(&rows)?;
    let producer = producer_from(template(
        UNIT,
        "9ef783df5862a605cbdea70e8297b90189d2861c35e51bb9715f3c09a9ad2462",
    )?)?;
    let mut guard = template(
        GUARD,
        "fee203fbdc165f3e95e4618cc586589caa4f2aef452e0b9e43535d4191e54e83",
    )?;
    replace_one(&mut guard, "epoch 250 v1", "epoch 251 v1")?;
    replace_all(&mut guard, RECEIPTS, &format!("{PREFIX251}-receipts-v1"))?;
    replace_all(&mut guard, BOUND, &format!("{PREFIX251}-guard-v1"))?;
    let mut timer = template(
        TIMER,
        "8fd1463f68f37b1ca4f8e671bb526c8fcd73495c96df543eb29b6edcf41c54a6",
    )?;
    replace_one(&mut timer, "epoch 250 v1", "epoch 251 v1")?;
    replace_one(&mut timer, GUARD, GUARD251)?;
    fs::create_dir(&out)?;
    let journal = save251(&out, "successor-probe.journal.jsonl", &captured.stdout)?;
    let probe_receipt = json!({"schema":"horizon251-successor-source-terminal-v1","unit":PROBE_UNIT,"invocation_id":PROBE_IID,"journal":journal,"manager_success":true,"output":{"path":PROBE251,"sha256":digest(&probe_bytes)},"decoded_output":probe,"source_node":{"path":PROBE_NODE,"sha256":"8e82375e588b46413118ad198fefba618c8db3cbe5f070bbac50fa5d94fc97c3"},"source_node_seal":{"path":probe_seal_path,"sha256":probe_seal_sha},"deployed_replay_node_qualified":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false});
    let probe_receipt = save251(
        &out,
        "successor-probe-receipt.json",
        &serde_json::to_vec_pretty(&probe_receipt)?,
    )?;
    let files = vec![
        save251(&out, UNIT251, producer.as_bytes())?,
        save251(&out, GUARD251, guard.as_bytes())?,
        save251(&out, TIMER251, timer.as_bytes())?,
    ];
    let plan = json!({"schema":"horizon251-replacement-source-plan-v1","epoch":251,"producer_unit":UNIT251,"guard_unit":GUARD251,"timer_unit":TIMER251,"worker_root":ROOT251,"index_cache":CACHE251,"files":files,"native_input_test":{"path":native_path,"sha256":native_sha},"index_structure":{"path":structure_path,"sha256":structure_sha},"input_seal":{"path":input_seal_path,"sha256":input_seal_sha},"manifest":{"path":MANIFEST251,"sha256":manifest_sha},"successor_source_probe":probe_receipt,"snapshot_reused_without_copy":true,"final_root_snapshot_copy_required":false,"candidate_memory_max_bytes":251041591296u64,"candidate_memory_high_bytes":167361060864u64,"candidate_root_cap_bytes":506191984640u64,"scheduling_reservation_ceiling_bytes":223779342336u64,"replacement_claim_epoch":247,"preserve_live_epochs":[248,249,250],"remaining_gates":["exact deployed-node cached-input and service-effective namespace qualification","source/runtime seal and invocation-bound launcher qualification","fresh replacement admission after authenticated claim release or separate capacity transition","first genuine guard fire and exact invocation token before replay"],"fresh_main_admission_accepted":false,"native_replay_qualified":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,"remote_mutations":false});
    let source_plan = save251(&out, "source-plan.json", &serde_json::to_vec_pretty(&plan)?)?;
    let mut members = files;
    members.extend([journal, probe_receipt, source_plan]);
    let members: Vec<_> = members.iter().map(|m| json!({"source":m["path"],"name":Path::new(m["path"].as_str().unwrap()).file_name().unwrap().to_string_lossy(),"sha256":m["sha256"],"mode":292})).collect();
    let seal = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":format!("{PREFIX251}-static-v1"),"members":members});
    save251(
        &out,
        "deployment-plan.json",
        &serde_json::to_vec_pretty(&seal)?,
    )?;
    File::open(&out)?.sync_all()?;
    File::open(out.parent().unwrap())?.sync_all()?;
    println!("{}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn producer_preserves_guard_and_uses_sealed_inputs() {
        let base = include_str!("../packet-v2/horizon-qualify-250-reboot-20261117-v1.service");
        let p = producer_from(base.to_string()).unwrap();
        assert!(p.contains(&format!("--snapshot-archive={INPUT251}/{SNAP251}")));
        assert!(p.contains(&format!(
            "{INPUT251}/genesis.tar.bz2:{ROOT251}/output/genesis.tar.bz2"
        )));
        assert!(p.contains("AllowedCPUs=0-15") && p.contains("/compact-indexes/251"));
        assert!(
            producer_from(base.replace("MemoryMax=251041591296", "MemoryMax=infinity")).is_err()
        );
        assert!(
            producer_from(base.replace(
                "ExecStartPre=/usr/bin/test -f",
                "ExecStartPre=/usr/bin/true"
            ))
            .is_err()
        );
    }
    #[test]
    fn boundary_and_authority_cannot_be_substituted() {
        let p = json!({"schema":"jetstreamer-successor-boundary-source-probe-v1","epoch":252,"requested_slot":108864000,"first_block_slot":108864012,"parent_slot":108863995,"production_boundary_reader":true,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false,"remote_mutations":false});
        validate_probe(&p).unwrap();
        for (field, value) in [
            ("parent_slot", json!(108863999)),
            ("epoch", json!(251)),
            ("replay_launch_authorized", json!(true)),
        ] {
            let mut changed = p.clone();
            changed[field] = value;
            assert!(validate_probe(&changed).is_err());
        }
        assert!(validate_journal(&[]).is_err());
    }
    #[test]
    fn journal_requires_exact_success_and_owner() {
        let common = json!({"_PID":"1","_UID":"0","_COMM":"systemd","UNIT":PROBE_UNIT,"INVOCATION_ID":PROBE_IID,"_BOOT_ID":"3b17d0055c3a4a0e8841da097e0957b5"});
        let mut start = common.clone();
        for (k, v) in [
            ("MESSAGE_ID", json!("39f53479d3a045ac8e11786248231fbf")),
            ("JOB_RESULT", json!("done")),
            ("JOB_TYPE", json!("start")),
            (
                "MESSAGE",
                json!(format!(
                    "Started {PROBE_UNIT} - [systemd-run] {PROBE_NODE} --probe-successor-boundary=108864000."
                )),
            ),
            ("__REALTIME_TIMESTAMP", json!("1795028585799964")),
        ] {
            start[k] = v;
        }
        let mut end = common;
        end["MESSAGE_ID"] = json!("7ad2d189f7e94e70a38c781354912448");
        end["MESSAGE"] = json!(format!("{PROBE_UNIT}: Deactivated successfully."));
        end["__REALTIME_TIMESTAMP"] = json!("1795028587290957");
        let rows = vec![start, end];
        validate_journal(&rows).unwrap();
        for (k, v) in [
            ("INVOCATION_ID", json!("foreign")),
            ("MESSAGE_ID", json!("failure")),
            ("_PID", json!("2")),
            ("__REALTIME_TIMESTAMP", json!("1795028585799963")),
        ] {
            let mut changed = rows.clone();
            changed[1][k] = v;
            assert!(validate_journal(&changed).is_err());
        }
        let mut extra = rows.clone();
        extra.push(rows[1].clone());
        assert!(validate_journal(&extra).is_err());
    }
}
