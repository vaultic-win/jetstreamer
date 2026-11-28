//! Binds the replacement to the proved instruction writer and the admitted 228 peer.
use super::*;

pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon266-instructions-2789f821-v169-control";
pub(super) const CONTROLLER: &str = "horizon266-instructions-2789f821-v169-control.service";
pub(super) const NODE: &str =
    "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node";
const NODE_SHA: &str = "2789f8211dafc4230a084910867db99699e6470b4a08a6fd8cc6dc00bf080f32";
const ORIGINAL: &str = "09dcaaddbbc34f3eb5f81c0a4f8a909e";
const PEER_IID: &str = "5566869f329b46309aa8a2ea8f46047a";
pub(super) const WORKER_SHA: &str =
    "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae";
pub(super) const MEMORY: u64 = 176_000_000_000;
pub(super) fn allocation() -> Value {
    json!({"from_original_invocation":ORIGINAL,"assigned_to":"horizon-qualify-266-instructions-2789f821-v169.service",
        "producer_bytes":MEMORY,"new_guard_bytes":GUARD_MEM,"new_controller_bytes":CONTROL_MEM,"old_guard_retained":GUARD_MEM,
        "old_controller_retained":CONTROL_MEM,"original_cold_residual":64u64<<20,"disk_credit":0})
}
fn qualification() -> Bound {
    Bound::new(
        "/home/ubuntu/.codex/diagnostics/horizon266-selected-producer-capability-v167-a2/qualification.json",
        "18c0e334c7c0c6861344b07c34d2fb982325f0d2605c640b55d72b4f31fb3618",
    )
}
fn handoff() -> Bound {
    Bound::new(
        "/var/lib/jetstreamer/horizon228-native-root-tail-v166-a1/pilot/handoff.json",
        "da3fdea0fa6f6682daa741e4c72d5f3a81d6bd420743d5df70c46d40b6319752",
    )
}
pub(super) fn selected(review: &Value) -> Result<()> {
    let qual = qualification();
    ensure!(
        review["selected_producer"] == json!(qual)
            && review["epoch228_handoff"] == json!(handoff())
            && review["epoch266_reassignment"] == allocation(),
        "explicit bounded-generation review"
    );
    writer(review)
}
pub(super) fn writer(review: &Value) -> Result<()> {
    let qual = qualification();
    ensure!(
        review["selected_producer"] == json!(qual),
        "different selected writer"
    );
    let q = qual.json()?;
    let node = Bound::new(NODE, NODE_SHA);
    node.artifact()?;
    let signed = binding(&q["signed_fixture"])?.json()?;
    let a = binding(&q["records"]["attempt2.json"])?.json()?;
    let worker = binding(&q["worker"])?;
    worker.artifact()?;
    ensure!(
        q["producer"] == json!(node)
            && a["node"] == json!(node)
            && a["worker"] == json!(worker)
            && worker.sha256 == "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae"
            && q["compiled_instruction_count_bound"] == 410
            && q["production_replay_admitted"] == false
            && signed["original_slot"] == 114912038
            && signed["original_block_index"] == 1274
            && signed["signed_message_instructions"] == 200
            && signed["old_producer_first_rejected_append"] == 65
            && signed["signed_transaction_sha256"]
                == "fa3d08b33be4c1f6dd4302845e12ba9625358447f5d9b313f8cdf7cb4e2ef61e",
        "selected production writer or original signed transaction changed"
    );
    Ok(())
}
pub(super) fn payload(p: &Profile, spec: &Value) -> Result<()> {
    let src = gate::inputs()?;
    let files = rows(&src, "files")?;
    let node = Bound::new(NODE, NODE_SHA);
    node.artifact()?;
    let manifest = Bound::new(
        Path::new(SNAPROOT).join("preflight-233-301-target4-publish300-46b4b4a.json"),
        "3c32a5d78e764cb982b246ab123eadf4fddb5eb51b6377f7afbb196aef714b81",
    );
    let manifest_body = manifest.sealed()?;
    let worker = Bound::new(
        text(&files[2], "path")?,
        "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae",
    );
    worker.artifact()?;
    let expected = json!([
        NODE,
        "266",
        p.root.join("output"),
        "--verify",
        "--root-checkpoint-cohort",
        format!("--cohort-manifest={}", manifest.path.display()),
        format!(
            "--cohort-manifest-fingerprint={}",
            text(&manifest_body, "manifest_fingerprint")?
        ),
        format!("--snapshot-archive={}", text(&files[0], "path")?)
    ]);
    ensure!(
        spec["argv"] == expected
            && spec["worker"] == json!(worker.path)
            && spec["manifest"] == json!(manifest)
            && spec["root"] == json!(p.root),
        "different successor replay command"
    );
    Ok(())
}
pub(super) fn peer(n: &mut Native) -> Result<(Value, u64)> {
    let binding_ref = handoff();
    let h = binding_ref.sealed()?;
    let p = Profile::new(Lane::Epoch228, "pilot")?;
    let prior = binding(&h["held_fit"])?.sealed()?;
    let spec = binding(&h["spec"])?.sealed()?;
    let g = binding(&h["guard"])?.sealed()?;
    let token = binding(&h["token"])?.sealed()?;
    let m = n.show(&p.unit)?;
    ensure!(
        h["unit"] == p.unit
            && h["iid"] == PEER_IID
            && h["pid"] == 2819393
            && token["iid"] == PEER_IID
            && token["pid"] == 2819393
            && token["held_fit"] == h["held_fit"]
            && token["guard"] == h["guard"]
            && token["spec"] == h["spec"]
            && g["invocation_id"] == PEER_IID
            && h["timer"] == "4e5c9b39e5e04d4f90eba4a8aea05296"
            && m["MainPID"] == "2819393"
            && m["InvocationID"] == PEER_IID
            && prior["epoch251_assignment"]["disk_credit"] == 0
            && prior["concurrent_266"]["iid"] == ORIGINAL
            && prior["concurrent_266"]["memory_credit_for_228"] == 0
            && num(&prior["winner"], "hard")? == 1_211_435_323_392
            && num(&prior["winner"], "root")? == epoch228::ROOT_BYTES
            && num(&prior["winner"], "memory")? == epoch228::MEMORY
            && prior["cpus"] == json!([40, 41, 42, 43, 44, 45, 46, 47]),
        "actual 228 booking or manager differs"
    );
    let timer = n.show(&p.timer)?;
    ensure!(
        timer["Id"] == p.timer
            && timer["InvocationID"] == h["timer"]
            && timer["ActiveState"] == "active"
            && timer["Unit"] == p.guard,
        "228 live guard lineage"
    );
    for name in [&p.unit, &p.timer, &p.guard] {
        let state = n.show(name)?;
        ensure!(
            state["DropInPaths"] == ""
                && Path::new(text(&state, "FragmentPath")?).canonicalize()? == p.state.join(name),
            "228 fragment changed"
        );
    }
    epoch228::mapped_command(&m, &spec)?;
    epoch228::kernel(&p, &m, &prior)?;
    let loopname = Path::new(text(&spec, "loop")?)
        .file_name()
        .context("228 loop")?
        .to_str()
        .context("228 loop name")?;
    let backing = p.state.join("private.ext4");
    let meta = fs::metadata(&backing)?;
    ensure!(
        loopname == "loop6"
            && fs::read_to_string("/sys/block/loop6/loop/backing_file")?.trim()
                == backing.to_str().context("228 backing")?
            && meta.len() == epoch228::ROOT_BYTES
            && meta.uid() == 0
            && fs::metadata(&p.root)?.dev() == num(&spec, "root_device")?,
        "228 scratch differs"
    );
    for name in ["stop-intent.json", "pressure-stop.json"] {
        absent(&p.state.join("receipts").join(name))?;
    }
    let current = live::kernel_memory(&m, &p.unit, epoch228::MEMORY)?;
    let value = json!({"handoff":binding_ref,"held_fit":h["held_fit"],"guard":h["guard"],"iid":PEER_IID,"pid":2819393,"unit":p.unit,"guard_service":p.guard,"cpus":prior["cpus"],"original_floor":num(&g,"minimum_free_bytes")?,"original_required_free":num(&prior["winner"],"required_free")?,"root":prior["winner"]["root"],"scratch_reassignment":prior["epoch228_scratch_assignment"],"retained_251":prior["epoch251_assignment"]});
    Ok((value, current))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_failure_and_admitted_peer_cannot_share_the_successor_namespace() {
        let new = Profile::new(Lane::Instructions266, "pilot").unwrap();
        assert_eq!(
            new.unit,
            "horizon-qualify-266-instructions-2789f821-v169.service"
        );
        for previous in [Lane::Epoch228, Lane::Epoch266] {
            let p = Profile::new(previous, "pilot").unwrap();
            assert_ne!(p.root, new.root);
            assert_ne!(p.guard, new.guard);
            assert_ne!(p.timer, new.timer);
            assert_ne!(p.state, new.state);
        }
        let a = allocation();
        assert_eq!(a["old_guard_retained"], GUARD_MEM);
        assert_eq!(a["assigned_to"], new.unit);
        assert_eq!(a["from_original_invocation"], ORIGINAL);
        assert_eq!(a["disk_credit"], 0);
    }
}

/// A retired 247 delivery can create real host free space. Authenticate the original
/// manager's end without releasing its old booking or treating it as a publication receipt.
pub(super) fn drained247(n: &mut Native) -> Result<Value> {
    let (unit, iid, _) = funding::OWNERS[2];
    let state=Command::new("/usr/bin/systemctl").args(["show",unit,"-p","Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,ControlPID,Job,Restart"]).output()?;
    let m = std::str::from_utf8(&state.stdout)?
        .lines()
        .map(|l| l.split_once('=').context("247 property"))
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        state.status.success()
            || (state.status.code() == Some(4) && m.get("LoadState") == Some(&"not-found")),
        "invalid 247 manager result"
    );
    ensure!(
        m["Id"] == unit
            && (m["InvocationID"] == iid || m["InvocationID"].is_empty())
            && m["MainPID"] == "0"
            && m["NRestarts"] == "0"
            && matches!(
                (m["ActiveState"], m["SubState"]),
                ("inactive", "dead") | ("failed", "failed")
            ),
        "different terminal 247 owner"
    );
    ensure!(
        m["ControlPID"] == "0" && m["Job"].is_empty() && m["Restart"] == "no",
        "247 still has a manager job"
    );
    live::verify_drained_group(unit)?;
    match fs::read_to_string("/proc/2774321/stat") {
        Ok(stat) => ensure!(
            stat.rsplit_once(')')
                .context("247 stat")?
                .1
                .split_whitespace()
                .nth(19)
                != Some("44413482"),
            "original 247 process survives"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    };
    let raw = n.run(
        "/usr/bin/journalctl",
        &[
            "--boot=0",
            "--no-pager",
            "--output=json",
            "--output-fields=_UID,_PID,MESSAGE_ID,UNIT_RESULT,UNIT,INVOCATION_ID,MESSAGE",
            "--lines=64",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={iid}"),
        ],
    )?;
    let events = std::str::from_utf8(&raw)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut end = events.iter().filter(|r| {
        matches!(
            r["MESSAGE_ID"].as_str(),
            Some("d9b373ed55a64feb8242e02dbe79a49c" | "7ad2d189f7e94e70a38c781354912448")
        )
    });
    let event = end.next().context("247 lacks an original PID1 terminal")?;
    ensure!(
        end.next().is_none()
            && event["_BOOT_ID"] == BOOT.replace('-', "")
            && event["UNIT"] == unit
            && event["INVOCATION_ID"] == iid
            && event["_PID"] == "1"
            && event["_UID"] == "0",
        "foreign 247 terminal"
    );
    if event["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448" {
        ensure!(
            event["MESSAGE"] == format!("{unit}: Deactivated successfully."),
            "247 success message"
        );
    } else {
        ensure!(
            matches!(
                event["UNIT_RESULT"].as_str(),
                Some(
                    "exit-code"
                        | "signal"
                        | "core-dump"
                        | "timeout"
                        | "oom-kill"
                        | "watchdog"
                        | "resources"
                        | "protocol"
                )
            ),
            "247 failure result"
        );
    }
    Ok(event.clone())
}
