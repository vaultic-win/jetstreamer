//! Bind the retained epoch 145 candidate to its guarded successor and completion.
use super::*;

const HANDOFF: &str = "epoch145-semantic-continuity-20261121-v1/v5r-name-handoff";
const STAGE: &str = "epoch145-encoded-prefix-stage-20261124-v1";
const PREDECESSOR: &str = "cbacb5a17e6347509640846eccb95cb0";
const SELECTOR: &str = "horizon-145-v5q-136-dispatch-20261124-v1.service";
const STATE: &str = "epoch145-guarded-export-20261121-v1/state";
const IMAGE_DIR: &str = "epoch145-semantic-continuity-20261121-v1/tools-v5r";
const PAID: &str =
    "/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1/.tmp36MvkN";
const PROMOTED: &str =
    "/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1/epoch-145.jet";
const VIEW: &str = "/home/sol/.jetstreamer-private/epoch145-prefix-extract-materialized-view-20261121-v1/epoch-145.jet";
const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch145-cached-b2a09f57de39c384/work/diagnostic/epoch-145-through-63072070.jet";
const BYTES: u64 = 105_610_995_833;
#[cfg(feature = "v5r-136-post")]
const SELECTOR_CUSTODY: &str = "1343de96384e52ff061262a2d80c217d187a1fc8b0ce0e07e32940ee88e89b3b";

fn load(reference: &Value, path: &Path) -> Result<Value> {
    ensure!(aspath(reference)? == path, "unexpected {}", path.display());
    from_ref(reference)
}

struct Semantic {
    iid: String,
    state: PathBuf,
    custody: Value,
    submission: Value,
    candidate: Value,
    old_stop: Value,
}

impl Semantic {
    fn load(custody_sha: &str) -> Result<Self> {
        let handoff = rt(HANDOFF);
        let custody = pinned(
            &handoff.join("ACTUAL_ADVANCING_AND_136_CUSTODY.json"),
            custody_sha,
        )?;
        let submission = load(
            &custody["submission"],
            &handoff.join("submission-result.json"),
        )?;
        let iid = text(&submission["invocation_id"])?;
        ensure!(
            custody["schema"] == "horizon-145-encoded-prefix-live-custody-v1"
                && custody["publication_authorized"] == false
                && custody["donor_reservation_released"] == false
                && submission["schema"] == "horizon-145-encoded-prefix-submission-v1"
                && submission["publication_authorized"] == false
                && submission["r2_mutations"] == false
                && valid_iid(iid)
                && iid != PREDECESSOR
                && custody["manager"]["InvocationID"] == iid
                && custody["manager"]["MainPID"] == submission["manager"]["MainPID"],
            "foreign epoch 145 successor custody"
        );
        let state = rt(STATE).join(iid);
        let started = load(
            &custody["verifier_start"],
            &state.join("recovery-started.json"),
        )?;
        let intent = load(
            &submission["intent"],
            &handoff.join("submission-intent.json"),
        )?;
        let old_stop = load(
            &submission["predecessor_stop"],
            &handoff.join("PREDECESSOR_STOP.json"),
        )?;
        let selector_stop = load(
            &custody["displaced_selector"],
            &handoff.join("SELECTOR_STOP.json"),
        )?;
        let stage = load(&intent["staging"], &rt(STAGE).join("STAGED.json"))?;
        let image = check_member(
            &rt(IMAGE_DIR),
            text(&stage["worker"]["sha256"])?,
            "export145",
        )?;
        let witness = &submission["native_successor"];
        let start_event = &witness["records"]["successor_started"];
        let startup = &started["fresh_fit"]["phase145"];
        let candidate = &intent["frozen_candidate"];
        let args = submission["argv"]
            .as_array()
            .context("missing native arguments")?;
        let tail = args
            .len()
            .checked_sub(5)
            .context("missing verifier command")?;
        let image_sha = &intent["images"]["worker"]["sha256"];
        ensure!(
            intent["successor_argv"] == submission["argv"]
                && args[tail] == json!(image)
                && args[tail + 1] == "recover-full-output"
                && args[tail + 4] == *image_sha
                && intent["images"]["worker"] == bound(&image)?
                && stage["native_profile"]["image"] == *image_sha
                && submission["previous_136_selector_stop"] == custody["displaced_selector"]
                && selector_stop["unit"] == SELECTOR
                && selector_stop["records"]["stop_finished"]["JOB_RESULT"] == "done"
                && old_stop["invocation_id"] == PREDECESSOR
                && old_stop["unit"] == E
                && old_stop["boot_id"] == witness["boot_id"]
                && old_stop["records"]["stop_finished"] == witness["records"]["stop_finished"]
                && start_event["INVOCATION_ID"] == iid
                && witness["successor_invocation_id"] == iid
                && started["iid"] == iid
                && started["image"] == *image_sha
                && started["file"] == PAID
                && started["r2_mutations"] == false
                && started["fresh_fit"]["fits"] == true
                && started["fresh_fit"]["provider_seal"] == stage["provider"]
                && startup["stage"] == "controller"
                && startup["invocation_id"] == iid
                && startup["window"]["encoded_prefix_predecessor_stop"]
                    == submission["predecessor_stop"]
                && startup["window"]["native_parent"]["pid"].as_i64()
                    == text(&submission["manager"]["MainPID"])?.parse::<i64>().ok()
                && candidate["path"] == PAID
                && candidate["bytes"] == BYTES,
            "different verifier restart, guarded startup, or retained candidate"
        );
        ensure!(
            !state.join("failed.json").try_exists()?,
            "epoch 145 verifier failed"
        );
        Ok(Self {
            iid: iid.to_owned(),
            state,
            custody,
            submission,
            candidate: candidate.clone(),
            old_stop,
        })
    }

    fn live(&self) -> Result<Value> {
        let (pid, iid) = stable(&native(E)?, E)?;
        let [_, worker] = self.custody["worker_samples"]
            .as_array()
            .context("missing guarded worker samples")?
            .as_slice()
        else {
            bail!("expected two samples of the guarded worker");
        };
        let child = i32::try_from(worker["pid"].as_i64().context("worker PID")?)?;
        let image = rt(IMAGE_DIR).join("export145");
        let argv = fs::read(format!("/proc/{child}/cmdline"))?;
        let parent = text(&self.submission["manager"]["MainPID"])?;
        let image_sha = self.submission["argv"]
            .as_array()
            .and_then(|v| v.last())
            .context("worker image digest")?;
        let expected = [
            platform::string_path(&image)?,
            "recover-worker",
            parent,
            text(image_sha)?,
            "",
        ]
        .join("\0");
        ensure!(
            iid == self.iid
                && pid == parent.parse::<i32>()?
                && platform::proc_exe(pid)? == image
                && platform::proc_exe(child)? == image
                && platform::ticks(child)? == worker["ticks"]
                && platform::group_members(&format!("/system.slice/{E}"))?.contains(&child)
                && argv == expected.as_bytes(),
            "guarded epoch 145 worker changed"
        );
        let observed = events::inspect_native_stop(
            E,
            PREDECESSOR,
            self.old_stop["not_before_monotonic_usec"]
                .as_u64()
                .context("stop clock")?,
            Some(&iid),
        )?;
        ensure!(
            observed == self.submission["native_successor"],
            "native epoch 145 owner changed"
        );
        Ok(
            json!({"invocation_id":iid,"stage":"leased-worker","manager":observed["manager"],
                  "window":{"recovery":self.custody["verifier_start"],
                            "native_parent":{"pid":pid,"start_ticks":platform::ticks(pid)?},
                            "native_child":{"pid":child,"start_ticks":worker["ticks"]}},
                  "displaced_selector":self.custody["displaced_selector"],
                  "donor_lock":self.custody["donor_lock"],"publication_authorized":false}),
        )
    }

    fn complete(&self) -> Result<Option<Value>> {
        if !self.state.join("complete.json").try_exists()? {
            return Ok(None);
        }
        let done_ref = bound(&self.state.join("complete.json"))?;
        let done = from_ref(&done_ref)?;
        let extraction_ref = &done["receipt"];
        let extraction = load(extraction_ref, &self.state.join("extraction-complete.json"))?;
        let verified_ref = &extraction["verified_frozen"];
        let verified = load(verified_ref, &self.state.join("verified-frozen.json"))?;
        let current = fs::symlink_metadata(PROMOTED)?;
        let retained_parent = text(&self.submission["manager"]["MainPID"])?.parse::<i32>()?;
        let e = validate_extraction(
            &self.iid,
            retained_parent,
            &self.custody["verifier_start"],
            &self.candidate,
            &verified,
            &extraction,
            &done,
        )?;
        ensure!(
            Path::new(PROMOTED).canonicalize()? == Path::new(PROMOTED)
                && !Path::new(PAID).try_exists()?
                && !self.state.join("failed.json").try_exists()?
                && current.is_file()
                && current.uid() == 0
                && current.gid() == 0
                && current.nlink() == 1
                && current.mode() & 0o7777 == 0o400
                && current.dev() == self.candidate["device"]
                && current.ino() == self.candidate["inode"]
                && current.len() == BYTES
                && current.mtime() * 1_000_000_000 + current.mtime_nsec()
                    == self.candidate["mtime_ns"],
            "different promoted epoch 145 inode"
        );
        let success = events::observed_success(
            E,
            &self.submission["native_successor"]["records"]["successor_started"],
        )?;
        Ok(Some(
            json!({"schema":"horizon-145-v5j-semantic-completion-v1","invocation_id":self.iid,
            "start":self.custody["verifier_start"],"verified":verified_ref,"extraction":extraction_ref,
            "completion":done_ref,"pid1_success":success["__CURSOR"],"archive":PROMOTED,"archive_bytes":BYTES,
            "archive_sha256":e["archive_sha256"],"provenance_sha256":e["expected_output_provenance_sha256"]}),
        ))
    }
}

fn validate_extraction<'a>(
    iid: &str,
    parent: i32,
    start: &Value,
    candidate: &Value,
    verified: &Value,
    extraction: &'a Value,
    done: &Value,
) -> Result<&'a Value> {
    let e = &extraction["extraction"];
    let mut projected = e.clone();
    projected["archive"] = json!(VIEW);
    let sha = |value: &Value| {
        value.as_str().is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    };
    ensure!(
        verified["iid"] == iid
            && verified["parent"] == parent
            && verified["paid_source"] == PAID
            && verified["private_projection"] == VIEW
            && ["device", "inode", "bytes", "mtime_ns", "ctime_ns"]
                .iter()
                .all(|k| verified["before"][*k] == candidate[*k])
            && verified["original_export"] == ORIGINAL
            && verified["extraction"] == projected
            && extraction["schema"] == "horizon-epoch145-guarded-private-prefix-completion-v1"
            && extraction["actor_iid"] == iid
            && extraction["original_export"] == ORIGINAL
            && extraction["archive_publication_authorized"] == false
            && extraction["recovery_evidence"] == *start
            && done["iid"] == iid
            && done["recovered_from"] == ORIGINAL
            && [verified, extraction, done]
                .iter()
                .all(|r| r["r2_mutations"] == false)
            && e["schema"] == "jetstreamer-private-epoch145-canonical-prefix-extraction-v1"
            && e["archive"] == PROMOTED
            && e["epoch"] == 145
            && e["archive_bytes"] == BYTES
            && e["output_slot_start"] == 62_640_000
            && e["output_slot_count"] == 432_000
            && e["source_archive"] == SOURCE
            && e["source_archive_sha256"]
                == "cb8ac0bc47919c22dc7898e068fb43ffac80aceadcacac3ff8f24ef32d3b3353"
            && e["source_manifest_sha256"]
                == "a101b885c5d60a13b8567d3968acd0e5177ec4f04669b91333cb9b3c5ca4b96a"
            && e["worker_sha256"]
                == "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"
            && e["source_canonical_checkpoint_slot"] == 63_072_070
            && e["source_canonical_accounts_hash"]
                == "DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p"
            && e["retained_verification_tail_slots"] == 71
            && e["source_must_be_retained"] == true
            && e["independent_output_reread_passed"] == true
            && [
                "current_plugin_verification_passed",
                "canonical_sidecar_authorized",
                "publication_authorized",
                "retirement_authorized",
                "r2_mutations"
            ]
            .iter()
            .all(|k| e[*k] == false)
            && [
                "archive_sha256",
                "output_semantic_sha256",
                "expected_output_provenance_sha256"
            ]
            .iter()
            .all(|k| sha(&e[*k])),
        "invalid guarded epoch 145 extraction or provenance"
    );
    Ok(e)
}

fn capture(custody_sha: &str) -> Result<Value> {
    let dir = rt(HANDOFF);
    let _lock = guard_instance(&dir)?;
    let done = Semantic::load(custody_sha)?
        .complete()?
        .context("waiting for epoch 145 semantic completion")?;
    let out = dir.join("semantic-completion.json");
    if out.try_exists()? {
        ensure!(
            from_ref(&bound(&out)?)? == done,
            "existing completion belongs to another generation"
        );
    } else {
        platform::save(&out, &done)?;
    }
    Ok(done)
}

#[cfg(feature = "v5r-136-post")]
pub(super) fn selector_origin() -> Result<Value> {
    let scope = Semantic::load(SELECTOR_CUSTODY)?;
    let start = &scope.custody["verifier_start"];
    let receipt = from_ref(start)?;
    Ok(json!({"start":start,"result":scope.submission,
        "parent":receipt["fresh_fit"]["phase145"]["window"]["native_parent"]}))
}

#[cfg(feature = "v5r-136-post")]
pub(super) fn wait_for_capture(iid: &str) -> Result<()> {
    let path = rt(HANDOFF);
    let receipt = pinned(
        &path.join("SEMANTIC_WATCH_STARTED.json"),
        "77193f986740740c15125df7ef6926cb472579a292954451f2fad670b089faca",
    )?;
    let unit = "horizon-145-v5r-semantic-capture-20261124-v1.service";
    ensure!(
        receipt["watching_invocation"] == iid && receipt["manager"]["Id"] == unit,
        "different epoch 145 completion watcher"
    );
    let watcher = text(&receipt["manager"]["InvocationID"])?;
    events::manager(unit, watcher)?;
    Ok(())
}

pub(super) fn run(mode: &str, custody_sha: &str) -> Result<Option<Value>> {
    let report = match mode {
        "inspect-encoded-prefix-live" => Semantic::load(custody_sha)?.live()?,
        "inspect-encoded-prefix-semantic" => Semantic::load(custody_sha)?
            .complete()?
            .unwrap_or(Value::Null),
        "capture-encoded-prefix-semantic" => capture(custody_sha)?,
        "follow-encoded-prefix-semantic" => {
            let scope = Semantic::load(custody_sha)?;
            events::manager(E, &scope.iid)?;
            capture(custody_sha)?
        }
        _ => return Ok(None),
    };
    Ok(Some(report))
}
