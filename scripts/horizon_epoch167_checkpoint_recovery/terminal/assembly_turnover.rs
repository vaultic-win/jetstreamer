//! Reuse the native epoch 167 source qualification and dispatch its private V3 merger.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};
#[allow(dead_code)]
#[path = "../../horizon_epoch170_checkpoint_suffix/evidence.rs"]
mod evidence;
use evidence::{
    available, bound, command, digest, idle, member, now, num, props, receipt, reference, stamp,
    trusted, word,
};
mod assembly_booking;
const RT: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch167-assembly-20261127-v1";
const SCOPE: &str = "qualifier-run-1795847372426869765";
const BOOT: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
const QID: &str = "ab8147b379d144a696b1d210127ea866";
const QUAL: &str = "horizon-167-private-source-qualification-20261127-v1.service";
const UNIT: &str = "horizon-167-private-v3-assembly-20261127-v1.service";
const OUT: &str = "/home/sol/.jetstreamer-private/epoch167-private-assembly-20261127-v1/output";
const LOCK: &str = "/run/horizon-epoch171-to136-g1.operation.lock";
const REPO: &str = "/home/sol/workspace/jetstreamer";
const OK: &str = "7ad2d189f7e94e70a38c781354912448";
const TAIL_SHA: &str = "f8c9f54e7ca433002441ff3a345447d147792222975a5c3c80bc630187b3ea7c";
const PLAN_SHA: &str = "1c9114468b92c80a3eea903911c73d68f71849cd5150ce836fee79828d1d4d9b";
const IMAGE: &str = "2f0c6202872d2c3abe3853ca368f477aa62ff94fa452f0443327c74c32721207";
const MEMORY: u64 = 8 << 30;
const CPU: u64 = 1_000_000;
const OUTPUT_CAP: u64 = 128 << 30;
const EVIDENCE_CAP: u64 = 64 << 20;
const BUDGET: u64 = OUTPUT_CAP + EVIDENCE_CAP;
fn rt(file: &str) -> PathBuf {
    Path::new(ROOT).join(file)
}
fn state(file: &str) -> PathBuf {
    rt("assembly-turnover-v1").join(file)
}
fn fixed(path: PathBuf, sha: &str) -> Value {
    json!({"path":path,"sha256":sha})
}
fn assembler_seal() -> Value {
    fixed(
        rt("tools/deployment-seal-receipt.json"),
        "462354b776e1097269080a3f5c602b89839a603d66c90729236efcac476cb23c",
    )
}
fn stable(path: &Path, doc: &Value) -> Result<Value> {
    if path.try_exists()? {
        let r = reference(path)?;
        ensure!(bound(&r)? == *doc, "different existing {}", path.display());
        Ok(r)
    } else {
        receipt(path, doc)
    }
}
fn private_dir(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        fs::DirBuilder::new().mode(0o700).create(path)?;
        File::open(path.parent().context("directory parent")?)?.sync_all()?;
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o777 == 0o700
            && m.dev() == fs::metadata("/home/sol")?.dev(),
        "untrusted HOME directory {}",
        path.display()
    );
    Ok(())
}
fn lock() -> Result<File> {
    ensure!(unsafe { libc::geteuid() } == 0, "root scope");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(LOCK)?;
    ensure!(
        f.metadata()?.uid() == 0
            && f.metadata()?.ino() == fs::symlink_metadata(LOCK)?.ino()
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "operation lock busy or changed"
    );
    Ok(f)
}
fn git(args: &[&str]) -> Result<String> {
    let mut settings = vec![
        "-c",
        "safe.directory=/home/sol/workspace/jetstreamer",
        "-C",
        REPO,
    ];
    settings.extend_from_slice(args);
    command("/usr/bin/git", &settings)
}
fn qualified_source(tip: &str) -> Result<Value> {
    let build = bound(&reference(&member(&assembler_seal(), "BUILD.json")?)?)?;
    ensure!(
        tip.len() == 40
            && tip.bytes().all(|b| b.is_ascii_hexdigit())
            && git(&["rev-parse", "refs/remotes/origin/account-updates"])?.trim() == tip,
        "fetched branch advanced"
    );
    let own_seal = assembly_booking::our_seal()?;
    let own = bound(&reference(&member(&own_seal, "SOURCE.json")?)?)?;
    let mut later_assembler_changes = serde_json::Map::new();
    for (proof, label) in [(&build, "assembler"), (&own, "turnover operator")] {
        let rev = word(proof, "source_commit")?;
        git(&["merge-base", "--is-ancestor", rev, tip])?;
        let inputs = proof["source_files"]
            .as_object()
            .context("compiled sources")?;
        ensure!(!inputs.is_empty(), "empty compiled inputs for {label}");
        for (name, want) in inputs {
            let actual = git(&["show", &format!("{rev}:{name}")])?;
            ensure!(
                digest(actual.as_bytes()) == *want,
                "original {label} input changed {name}"
            );
            let latest = digest(git(&["show", &format!("{tip}:{name}")])?.as_bytes());
            if *want != latest {
                ensure!(label == "assembler", "newer turnover operator input {name}");
                later_assembler_changes
                    .insert(name.to_string(), json!({"compiled":want,"fetched":latest}));
            }
        }
    }
    let original = word(&build, "source_commit")?;
    let image = member(&assembler_seal(), "horizon-167-assembly")?;
    ensure!(reference(&image)?["sha256"] == IMAGE, "different assembler");
    Ok(
        json!({"origin_account_updates":tip,"assembler_source":original,"subsequent_assembler_input_changes":later_assembler_changes,"turnover_operator_source":own["source_commit"],"turnover_seal":own_seal,"build":reference(&rt("tools/BUILD.json"))?,"assembler":reference(&image)?}),
    )
}
fn query_terminal(unit: &str, iid: &str) -> Result<Value> {
    ensure!(
        iid.len() == 32
            && iid.bytes().all(|b| b.is_ascii_hexdigit())
            && fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .replace('-', "")
                == BOOT,
        "boot or invocation mismatch"
    );
    idle(unit)?;
    ensure!(
        !Path::new("/sys/fs/cgroup/system.slice")
            .join(unit)
            .try_exists()?,
        "cgroup still present"
    );
    let rows = command(
        "/usr/bin/journalctl",
        &[
            "-q",
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={unit}"),
            &format!("_BOOT_ID={BOOT}"),
            &format!("INVOCATION_ID={iid}"),
            &format!("MESSAGE_ID={OK}"),
            "MESSAGE_ID=be02cf6855d2428ba40df7e9d022f03d",
        ],
    )?;
    let events = rows
        .lines()
        .map(serde_json::from_str)
        .collect::<serde_json::Result<Vec<Value>>>()?;
    ensure!(
        events.len() == 1
            && events[0]["MESSAGE_ID"] == OK
            && events[0]["INVOCATION_ID"] == iid
            && events[0]["UNIT"] == unit
            && events[0]["_BOOT_ID"] == BOOT,
        "missing exact native success {unit}"
    );
    Ok(events[0].clone())
}
fn original() -> Result<(Value, Value, Value)> {
    let r = fixed(
        rt(SCOPE).join("DISPATCH_RESULT.json"),
        "05f86476ac682d00e31a1267f38b5434b47d89cc814979b858d2d0ac46dab3bf",
    );
    let launch = bound(&r)?;
    let intent = bound(&launch["intent"])?;
    let plan = bound(&intent["plan"])?;
    let bind = fixed(
        rt(SCOPE).join("NATIVE_STREAMS.json"),
        "7fd0d90a9002df1869646a5ded79aba9a8f180f15a855489ee57251c3d577201",
    );
    let s = bound(&bind)?;
    ensure!(
        s["dispatch"] == r
            && s["invocation"] == QID
            && s["producer"] == QUAL
            && launch["unit"]["InvocationID"] == QID
            && intent["plan"]["sha256"] == PLAN_SHA
            && plan["tool_seal"] == assembler_seal(),
        "source invocation bindings changed"
    );
    Ok((s, intent, plan))
}
fn validate_report(q: &Value, plan: &Value) -> Result<()> {
    ensure!(
        q["schema"] == "horizon-167-qualified-mixed-worker-sources-v1"
            && q["unit"] == QUAL
            && q["invocation"] == QID
            && q["boot"] == BOOT
            && q["tool_sha256"] == IMAGE
            && q["tool_seal"] == plan["tool_seal"]
            && q["tail_manifest"] == plan["tail_manifest"]
            && q["prefix_result"] == plan["prefix_result"]
            && q["publication_authorized"] == false
            && q["source_epoch_last"] == 72_575_999u64
            && q["post_epoch_slots_excluded"] == 6855
            && q["full_tail_bytes"] == 20_279_360_388u64
            && q["full_tail_sha256"] == TAIL_SHA
            && q["epoch_last_blockhash"] == "76NscCJt2diYHF8a7vxwiMHMK9A2Tr3wDaMY42WjzVFs"
            && q["selected_raw_start"] == 52_892_210_899u64
            && num(q, "selected_raw_end_exclusive")? > num(q, "selected_raw_start")?,
        "wrong private source result"
    );
    for key in [
        "selected_tail_sha256",
        "selected_tail_semantic",
        "v3_sha256",
    ] {
        let v = word(q, key)?;
        ensure!(
            v.len() == 64 && v.bytes().all(|c| c.is_ascii_hexdigit()),
            "absent digest {key}"
        );
    }
    Ok(())
}
fn capture() -> Result<Value> {
    let (streams, _, plan) = original()?;
    let exit = query_terminal(QUAL, QID)?;
    for key in ["stdout", "stderr"] {
        let src = &streams["streams"][key];
        let p = rt(SCOPE).join(format!("RESULT.{key}"));
        let info = fs::symlink_metadata(&p)?;
        ensure!(
            Path::new(word(src, "path")?) == p
                && info.dev() == num(src, "dev")?
                && info.ino() == num(src, "ino")?
                && info.len() <= 2 << 20
                && info.uid() == 0
                && info.nlink() == 1,
            "different qualified {key}"
        );
    }
    let stdout = rt(SCOPE).join("RESULT.stdout");
    let written = fs::symlink_metadata(&stdout)?;
    let stream_bound = fs::metadata(rt(SCOPE).join("NATIVE_STREAMS.json"))?;
    let last = word(&exit, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
    let micros = |m: &fs::Metadata| (m.mtime() as u64) * 1_000_000 + (m.mtime_nsec() as u64) / 1000;
    ensure!(
        micros(&stream_bound) <= micros(&written)
            && micros(&written) <= last
            && written.ctime() as u64 * 1_000_000 + written.ctime_nsec() as u64 / 1000 <= last,
        "source report modified outside the original qualification window"
    );
    let raw = trusted(&stdout)?;
    let q: Value = serde_json::from_slice(&raw)?;
    validate_report(&q, &plan)?;
    let dest = state("QUALIFIED.json");
    if dest.try_exists()? {
        ensure!(trusted(&dest)? == raw, "conflicting source qualification");
    } else {
        evidence::publish(&dest, &raw, 0o400)?;
    }
    ensure!(
        reference(&dest)?["sha256"] == digest(&raw)
            && trusted(&stdout)? == raw
            && query_terminal(QUAL, QID)? == exit,
        "qualification changed during readback"
    );
    let native = json!({"original_stream_bindings":reference(&rt(SCOPE).join("NATIVE_STREAMS.json"))?,"original_stdout":reference(&stdout)?,"qualification":reference(&dest)?,"terminal":exit,"private_only":true});
    stable(&state("SOURCE_TERMINAL.json"), &native)
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [mode] if mode == "account" => {
            let v: Value = serde_json::from_reader(std::io::stdin().take(8 << 20))?;
            assembly_booking::account(v)?
        }
        [mode] if mode == "capture" => {
            let _l = lock()?;
            private_dir(&state(""))?;
            capture()?
        }
        _ => assembly_booking::entry(&args)?,
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn require_the_original_tail_at_the_epoch_boundary() {
        let plan = json!({"tool_seal":{"sha256":"sealed"},"tail_manifest":{"sha256":"tail"},"prefix_result":{"sha256":"prefix"}});
        let mut q = json!({"schema":"horizon-167-qualified-mixed-worker-sources-v1","unit":QUAL,
            "invocation":QID,"boot":BOOT,"tool_sha256":IMAGE,"tool_seal":plan["tool_seal"],"tail_manifest":plan["tail_manifest"],
            "prefix_result":plan["prefix_result"],"publication_authorized":false,"source_epoch_last":72_575_999,"post_epoch_slots_excluded":6855,
            "full_tail_bytes":20_279_360_388u64,"full_tail_sha256":TAIL_SHA,"epoch_last_blockhash":"76NscCJt2diYHF8a7vxwiMHMK9A2Tr3wDaMY42WjzVFs",
            "selected_raw_start":52_892_210_899u64,"selected_raw_end_exclusive":52_892_210_900u64,
            "selected_tail_sha256":TAIL_SHA,"selected_tail_semantic":TAIL_SHA,"v3_sha256":TAIL_SHA});
        assert!(validate_report(&q, &plan).is_ok());
        q["source_epoch_last"] = json!(72_582_854);
        assert!(validate_report(&q, &plan).is_err());
        q["source_epoch_last"] = json!(72_575_999);
        q["selected_raw_start"] = json!(52_892_210_900u64);
        assert!(validate_report(&q, &plan).is_err());
    }
}
