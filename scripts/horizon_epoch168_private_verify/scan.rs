use crate::custody::{Bound, Opened, bound, num, save, string};
use crate::scope::{Inputs, branch};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub fn terminal(unit: &str, iid: &str) -> Result<Value> {
    ensure!(
        unit.ends_with(".service") && iid.len() == 32 && iid.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid service identity"
    );
    let native = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "--all",
            "-p",
            "Id,InvocationID,MainPID,ControlPID,ControlGroup,Job,ActiveState",
            unit,
        ])
        .output()?;
    ensure!(
        matches!(native.status.code(), Some(0 | 4)),
        "cannot inspect service"
    );
    let props = String::from_utf8(native.stdout)?;
    let properties: BTreeMap<_, _> = props.lines().filter_map(|s| s.split_once('=')).collect();
    let get = |k| properties.get(k).copied().unwrap_or("?");
    ensure!(
        get("Id") == unit
            && get("MainPID") == "0"
            && get("ControlPID") == "0"
            && get("ControlGroup").is_empty()
            && get("Job").is_empty()
            && get("ActiveState") == "inactive"
            && (get("InvocationID").is_empty() || get("InvocationID") == iid),
        "service has an active or unclean successor: {unit}"
    );
    let res = Command::new("/usr/bin/journalctl")
        .args([
            "-q",
            "-b",
            "--no-pager",
            "-o",
            "json",
            "_UID=0",
            "_PID=1",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={iid}"),
            "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
        ])
        .output()?;
    ensure!(
        res.status.success() && res.stdout.len() < 64 * 1024,
        "cannot read the source terminal"
    );
    let rows = String::from_utf8(res.stdout)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let [event] = rows.as_slice() else {
        anyhow::bail!("missing exact successful PID1 event for {unit}/{iid}")
    };
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(
        event["UNIT"] == unit
            && event["INVOCATION_ID"] == iid
            && event["_BOOT_ID"] == boot
            && event["MESSAGE"] == format!("{unit}: Deactivated successfully."),
        "wrong manager terminal"
    );
    Ok(
        json!({"unit":unit,"invocation":iid,"boot":boot,"manager_message_id":event["MESSAGE_ID"],"realtime_usec":event["__REALTIME_TIMESTAMP"]}),
    )
}

fn output(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?)
}

// The native PoH verifier reports progress twice per second. Drain the pipe to EOF
// even when the retained head and tail fill. Hash every original stderr byte.
fn retain_stderr(
    name: &str,
    mut stream: impl Read,
    mut dest: impl Write,
    keep: usize,
) -> Result<Value> {
    let mut left = keep;
    let mut tail: VecDeque<u8> = VecDeque::with_capacity(keep);
    let mut total = 0u64;
    let mut hasher = Sha256::new();
    let mut buf = [0; 32 * 1024];
    let mut pulse = Instant::now();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total
            .checked_add(n as u64)
            .context("diagnostic byte count")?;
        let head = n.min(left);
        dest.write_all(&buf[..head])?;
        left -= head;
        let remaining = &buf[head..n];
        if remaining.len() >= keep {
            tail.clear();
            tail.extend(&remaining[remaining.len() - keep..]);
        } else {
            let discard = (tail.len() + remaining.len()).saturating_sub(keep);
            tail.drain(..discard);
            tail.extend(remaining);
        }
        if pulse.elapsed() >= Duration::from_secs(1800) {
            if let Some(line) = String::from_utf8_lossy(&buf[..n]).lines().rev().find(|s| {
                s.len() <= 1024 && (s.starts_with("[verify]") || s.contains("horizon_tps "))
            }) {
                eprintln!("{name}: {line}");
            }
            pulse = Instant::now();
        }
    }
    let head = keep - left;
    let omitted = total - head as u64 - tail.len() as u64;
    if omitted > 0 {
        writeln!(
            dest,
            "\n[private verifier retained head and tail; {omitted} intervening bytes]"
        )?;
    }
    let (front, back) = tail.as_slices();
    dest.write_all(front)?;
    dest.write_all(back)?;
    dest.flush()?;
    Ok(
        json!({"raw_bytes":total,"raw_sha256":format!("{:x}",hasher.finalize()),
              "head_bytes":head,"tail_bytes":tail.len(),"omitted_bytes":omitted}),
    )
}

fn job(name: &str, exe: &Bound, args: &[String], root: &Path) -> Result<Value> {
    exe.binary()?;
    let out = root.join(format!("{name}.stdout"));
    let err = root.join(format!("{name}.stderr"));
    let retained = output(&err)?;
    let mut child = Command::new(&exe.path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(output(&out)?)
        .stderr(Stdio::piped())
        .spawn()?;
    let capture = retain_stderr(
        name,
        child.stderr.take().context("native stderr")?,
        retained,
        128 * 1024,
    );
    if capture.is_err() {
        let _ = child.kill();
    }
    let result = child.wait()?;
    let diagnostic = capture?;
    File::open(&out)?.sync_all()?;
    File::open(&err)?.sync_all()?;
    ensure!(
        result.success(),
        "{name} exited {result}. See {}",
        err.display()
    );
    exe.binary()?;
    Ok(
        json!({"program":exe,"argv":args,"exit":0,"stdout":bound(&out)?,"stderr":bound(&err)?,
              "stderr_original":diagnostic}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_keep_both_ends_and_hash_the_entire_stream() {
        let input: Vec<u8> = (0..2_000_000).map(|n| (n % 251) as u8).collect();
        for len in [0, 2, 127, 256, 257, input.len()] {
            let original = &input[..len];
            let mut out = Vec::new();
            let report = retain_stderr("fixture", original, &mut out, 128).unwrap();
            assert_eq!(report["raw_bytes"], len);
            assert_eq!(report["raw_sha256"], crate::custody::digest(original));
            assert_eq!(report["omitted_bytes"], len.saturating_sub(256));
            if len <= 256 {
                assert_eq!(&out, original);
            } else {
                assert!(out.starts_with(&original[..128]) && out.ends_with(&original[len - 128..]));
                assert!(out.len() < 400);
            }
        }
    }
}

fn count(text: &str, label: &str) -> Result<u64> {
    let mut numbers = text.lines().filter_map(|line| {
        let (k, v) = line.trim().split_once(':')?;
        (k == label).then_some(v.trim())
    });
    let value = numbers.next().with_context(|| format!("missing {label}"))?;
    ensure!(numbers.next().is_none(), "duplicate {label}");
    let cleaned = value.replace(',', "");
    ensure!(
        !cleaned.is_empty() && cleaned.bytes().all(|c| c.is_ascii_digit()),
        "invalid {label}"
    );
    Ok(cleaned.parse()?)
}

fn validate_semantics(
    a: &Value,
    s: &Inputs,
    full: &str,
    report: &Value,
    argv: &[String],
) -> Result<()> {
    let e = &s.expectation;
    let parent = num(e, "parent_slot")?;
    let tip = num(e, "terminal_slot")?;
    let p = string(e, "parent_blockhash")?;
    let t = string(e, "terminal_blockhash")?;
    ensure!(
        full.lines().any(|l| l.starts_with(&format!(
            "archive provenance V4: structurally valid; sha256={} ",
            string(e, "provenance_sha256").unwrap_or("")
        )))
            && full
                .lines()
                .any(|l| l.trim()
                    == format!("chain anchor:        slot={parent} blockhash={p}").trim())
            && full.lines().any(|l| l.starts_with("RESULT: OK:"))
            && full.lines().any(|l| l.starts_with(&format!(
                "CANONICAL TERMINAL OK: expected slot={tip} blockhash={t},"
            ))),
        "full verifier did not accept V4 and both independent boundaries"
    );
    let r = &report["report"];
    let first = s.scope.epoch * 432000;
    let last = first + 431999;
    let mut expected = vec![s.pipeline.path.display().to_string()];
    expected.extend_from_slice(argv);
    ensure!(
        report["schema"] == "jetstreamer-horizon-plugin-playback-v1"
            && report["source"] == json!(s.scope.assembly_dir)
            && report["invocation"] == json!(expected)
            && report["full_epoch_verified"] == true
            && report["expected_first_slot"] == first
            && report["expected_last_slot"] == last
            && r["slots"] == 432000
            && r["first_slot"] == first
            && r["last_slot"] == last
            && r["epoch"] == s.scope.epoch
            && r["worker_count"] == s.scope.threads
            && num(r, "blocks")?.checked_add(num(r, "skipped")?) == Some(432000),
        "incomplete native plugin coverage"
    );
    let orphan = num(r, "orphan_updates")?
        .checked_add(num(r, "epoch_updates")?)
        .context("orphan counter overflow")?;
    let writes = orphan
        .checked_add(num(r, "transaction_updates")?)
        .context("account update overflow")?;
    ensure!(
        a["blocks"] == r["blocks"]
            && a["transactions"] == r["transactions"]
            && a["normalized_writes"] == writes,
        "assembly and plugin account, transaction or block totals differ"
    );
    for (label, expected) in [
        ("slots (blk+skipped)", 432000),
        ("slot frames visited", 432000),
        ("blocks", num(r, "blocks")?),
        ("skipped slots", num(r, "skipped")?),
        ("transactions", num(r, "transactions")?),
        ("entries", num(r, "entries")?),
        ("tx account updates", num(r, "transaction_updates")?),
        ("orphan updates", orphan),
    ] {
        ensure!(
            count(full, label)? == expected,
            "full verifier and plugin disagree on {label}"
        );
    }
    ensure!(
        r["stream_digest"].as_array().is_some_and(
            |v| v.len() == 32 && v.iter().all(|b| b.as_u64().is_some_and(|n| n <= 255))
        ),
        "missing plugin stream digest"
    );
    Ok(())
}

fn admit(inputs: &Inputs, control: &Bound, root: &Path) -> Result<Value> {
    let a = control.json()?;
    let s = &inputs.scope;
    let iid = std::env::var("INVOCATION_ID")?;
    let c = fs::read_to_string("/proc/self/cgroup")?;
    let cg =
        Path::new("/sys/fs/cgroup").join(c.trim().strip_prefix("0::/").context("unified cgroup")?);
    ensure!(
        a["schema"] == "horizon-168-private-native-scan-admission-v1"
            && a["fits"] == true
            && a["canonical_writes"] == false
            && a["output"] == json!(root)
            && iid.len() == 32
            && a["scan_unit"]
                == cg
                    .file_name()
                    .context("native unit")?
                    .to_string_lossy()
                    .as_ref()
            && c.trim().starts_with("0::/horizonaudit.slice/")
            && std::env::var("RUST_MIN_STACK")? == "67108864"
            && fs::read_link("/proc/self/ns/net")? != fs::read_link("/proc/1/ns/net")?
            && fs::read_link("/proc/self/ns/mnt")? != fs::read_link("/proc/1/ns/mnt")?,
        "invalid verification controls"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let until = num(&a, "valid_until")?;
    let accepted = num(&a, "issued_at")?;
    ensure!(
        accepted <= now && now <= until && until - accepted <= 180,
        "expired private scan admission"
    );
    for (key, expected) in [
        ("cpu.max", "100000 100000".to_owned()),
        ("memory.max", num(&a, "ram_bytes")?.to_string()),
        ("memory.swap.max", "0".to_owned()),
        ("pids.max", "96".to_owned()),
    ] {
        ensure!(
            fs::read_to_string(cg.join(key))?.trim() == expected,
            "incorrect scan unit {key}"
        );
    }
    ensure!(
        a["assembly_terminal"] == terminal(&s.unit, &s.invocation)?,
        "producer terminal mismatch"
    );
    Ok(a)
}

pub fn run(scope: &Bound, control: &Bound, root: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let serial = File::open("/run/lock/horizon-epoch140-suffix-compiler.lock")?;
    ensure!(
        unsafe { libc::flock(serial.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "shared native verification slot occupied"
    );
    let inputs = Inputs::load(scope)?;
    let s = &inputs.scope;
    let ad = admit(&inputs, control, root)?;
    ensure!(
        ad["scope"] == json!(scope),
        "admission for different verification"
    );
    let initial = branch(&s.reader_equivalence)?;
    ensure!(
        initial == ad["reader_branch"],
        "branch changed since admission"
    );
    let assembly = bound(&s.assembly_dir.join("assembly.json"))?;
    ensure!(
        ad["assembly"] == json!(assembly),
        "assembly receipt changed since admission"
    );
    let assembled = assembly.json()?;
    inputs.assembly(&assembled)?;
    save(
        &root.join("STARTED.json"),
        &json!({"scope":scope,"admission":control,"assembly":assembly,
        "scan_unit":ad["scan_unit"],"invocation":std::env::var("INVOCATION_ID")?,
        "pid":std::process::id(),"ram_bytes":ad["ram_bytes"],"exclusive_serial_lock":true}),
    )?;
    let archive = s.assembly_dir.join(format!("epoch-{}.jet", s.epoch));
    let mut file = Opened::open(&archive)?;
    ensure!(
        file.start.len == num(&assembled, "archive_bytes")?
            && file.hash()? == string(&assembled, "archive_sha256")?,
        "independent archive length or SHA-256 mismatch"
    );
    let exp = &inputs.expectation;
    let epoch = s.epoch.to_string();
    let threads = s.threads.to_string();
    let full_args = vec![
        archive.display().to_string(),
        "--full".into(),
        "--threads".into(),
        threads.clone(),
        "--anchor".into(),
        num(exp, "parent_slot")?.to_string(),
        string(exp, "parent_blockhash")?.into(),
        "--expected-terminal".into(),
        num(exp, "terminal_slot")?.to_string(),
        string(exp, "terminal_blockhash")?.into(),
        "--expected-provenance-sha256".into(),
        string(exp, "provenance_sha256")?.into(),
    ];
    eprintln!("epoch {epoch} passed independent archive SHA-256, starting full PoH verification");
    let full = job("full", &inputs.verifier, &full_args, root)?;
    file.unchanged()?;
    let plugin_path = root.join("plugin.json");
    let args = vec![
        epoch.clone(),
        s.assembly_dir.display().to_string(),
        "--verify-only".into(),
        "--threads".into(),
        threads,
        "--verification-report".into(),
        plugin_path.display().to_string(),
    ];
    eprintln!("epoch {epoch} passed full PoH verification, starting local plugin playback");
    let playback = job("playback", &inputs.pipeline, &args, root)?;
    fs::set_permissions(&plugin_path, fs::Permissions::from_mode(0o400))?;
    File::open(&plugin_path)?.sync_all()?;
    let plugin = bound(&plugin_path)?;
    let report = plugin.json()?;
    validate_semantics(
        &assembled,
        &inputs,
        &fs::read_to_string(root.join("full.stdout"))?,
        &report,
        &args,
    )?;
    ensure!(assembly.json()? == assembled, "assembly receipt changed");
    file.unchanged()?;
    let closing = branch(&s.reader_equivalence)?;
    let rec = save(
        &root.join("SCAN.json"),
        &json!({"schema":"horizon-private-v4-archive-scan-v1","epoch":s.epoch,"fixture":s.fixture,"scan_invocation":std::env::var("INVOCATION_ID")?,
        "scope":scope,"admission":control,"assembly":assembly,"archive_path":archive,"archive_stamp":file.start,"verified_archive_sha256":assembled["archive_sha256"],
        "assembly_terminal":ad["assembly_terminal"],"package":s.package,"main":inputs.main,"expectation":s.expectation,"selected":s.selected,"selected_native":s.selected_native,
        "lineage":s.lineage,"terminal_edge":s.terminal_edge,"provenance_sha256":exp["provenance_sha256"],"reader_branch_at_entry":initial,"reader_branch_at_end":closing,
        "full":full,"playback":playback,"local_plugin":plugin,"counters":report["report"],"canonical_writes":false,"publication_authorized":false}),
    )?;
    println!("{}", serde_json::to_string(&rec)?);
    Ok(())
}

pub fn finish(scope: &Bound, control: &Bound, root: &Path, terminal_ref: &Bound) -> Result<Bound> {
    let inputs = Inputs::load(scope)?;
    let s = &inputs.scope;
    let ad = control.json()?;
    let scan = bound(&root.join("SCAN.json"))?;
    let d = scan.json()?;
    ensure!(
        d["scope"] == json!(scope)
            && d["admission"] == json!(control)
            && d["fixture"] == s.fixture
            && d["epoch"] == s.epoch
            && ad["output"] == json!(root),
        "different scan"
    );
    let end = terminal(string(&ad, "scan_unit")?, string(&d, "scan_invocation")?)?;
    ensure!(terminal_ref.json()? == end, "wrong managed scan exit");
    let assembly = bound(&s.assembly_dir.join("assembly.json"))?;
    ensure!(d["assembly"] == json!(assembly), "source report changed");
    let a = assembly.json()?;
    inputs.assembly(&a)?;
    let file = Opened::open(Path::new(string(&a, "archive_path")?))?;
    ensure!(
        json!(file.start) == d["archive_stamp"]
            && a["archive_sha256"] == d["verified_archive_sha256"],
        "archive changed after scan"
    );
    let plugin: Bound = serde_json::from_value(d["local_plugin"].clone())?;
    let full = crate::custody::reference(&d["full"], "stdout")?;
    ensure!(
        bound(&full.path)? == full && d["counters"] == plugin.json()?["report"],
        "native evidence changed after scan"
    );
    let fresh = branch(&s.reader_equivalence)?;
    save(
        &root.join("ACCEPTANCE.json"),
        &json!({"schema":"horizon-private-v4-archive-acceptance-v1","epoch":s.epoch,"fixture":s.fixture,
        "native_terminal":terminal_ref,"scan":scan,"admission":control,"scope":scope,"assembly":assembly,"archive":a["archive_path"],"archive_bytes":a["archive_bytes"],
        "archive_sha256":a["archive_sha256"],"provenance_sha256":a["provenance_sha256"],"reader_branch":fresh,"full":d["full"],"local_plugin":plugin,"counters":d["counters"],
        "canonical_writes":false,"publication_authorized":false}),
    )
}
