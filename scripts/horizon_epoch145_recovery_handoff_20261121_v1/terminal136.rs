//! Close the selected 136 donation before admitting the epoch 145 post worker.
use super::*;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::process::Stdio;
use std::time::Duration;

const BASE: &str = "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1";
const ACTOR: &str = "horizon-qualify-136-actual-20261120-g1.service";
const GUARD: &str = "horizon-guard-136-actual-20261120-g1.service";
const TIMER: &str = "horizon-guard-136-actual-20261120-g1.timer";
const GUARD_IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/guard-v1/guard";
const GUARD_SHA: &str = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016";

fn local(name: &str) -> PathBuf {
    Path::new(BASE).join(name)
}

pub(super) fn unit_state(unit: &str) -> Result<Value> {
    let fields =
        "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID,ExecStart,Unit";
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "-p", fields])
        .output()?;
    let mut row = json!({});
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("unit property")?;
        row[key] = value.into();
    }
    ensure!(
        row["Id"] == unit
            && (out.status.success()
                || (out.status.code() == Some(4) && row["LoadState"] == "not-found")),
        "cannot identify {unit}"
    );
    Ok(row)
}

fn closed(row: &Value) -> bool {
    matches!(row["ActiveState"].as_str(), Some("inactive" | "failed"))
        && row["Job"] == ""
        && ["MainPID", "ControlPID"]
            .iter()
            .all(|key| row[*key].is_null() || row[*key] == "0")
}

fn empty_cgroup(unit: &str) -> Result<()> {
    let group = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    let path = group.join("cgroup.events");
    let mut file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                !group.try_exists()? && closed(&unit_state(unit)?),
                "{unit} changed while draining"
            );
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    // A manager exit may precede the last descendant leaving. cgroup.events
    // notifies on the populated transition without polling the processes.
    loop {
        if !group.try_exists()? {
            break;
        }
        let mut events = String::new();
        if let Err(e) = file
            .seek(SeekFrom::Start(0))
            .and_then(|_| file.read_to_string(&mut events))
        {
            if !group.try_exists()? {
                break;
            }
            return Err(e.into());
        }
        if events.lines().any(|s| s == "populated 0") {
            break;
        }
        ensure!(
            events.lines().any(|s| s == "populated 1") && closed(&unit_state(unit)?),
            "{unit} changed before physical drain"
        );
        let mut fd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLPRI | libc::POLLERR,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut fd, 1, -1) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        ensure!(
            n > 0 && fd.revents & libc::POLLNVAL == 0,
            "lost {unit} cgroup notification"
        );
    }
    if group.try_exists()? {
        let latest = fs::metadata(&path)?;
        let original = file.metadata()?;
        ensure!(
            (latest.dev(), latest.ino()) == (original.dev(), original.ino()),
            "replaced {unit} cgroup"
        );
    }
    ensure!(
        closed(&unit_state(unit)?),
        "new {unit} generation after physical drain"
    );
    Ok(())
}

fn admission_expiry(a: &Value, intent: &Value) -> Result<u64> {
    let issued = a["recorded_unix_seconds"]
        .as_u64()
        .context("admission issuance")?;
    let expiry = a["launch_expires_unix_seconds"]
        .as_u64()
        .context("admission expiry")?;
    ensure!(
        a["schema"] == "horizon-epoch136-actual-admission-v1"
            && a["writer"] == intent["writer"]
            && a["writer_invocation_id"] == intent["writer_invocation_id"]
            && issued.checked_add(900) == Some(expiry),
        "foreign or invalid 136 admission"
    );
    Ok(expiry)
}

fn launch(admission: &Value) -> Result<Value> {
    let path = local("reproduction/receipts/launch.json");
    let row = from_ref(&bound(&path)?)?;
    let a = from_ref(admission)?;
    ensure!(
        row["schema"] == "jetstreamer-epoch136-actual-20261120-launch-v1"
            && row["unit"] == ACTOR
            && row["plan"] == a["plan"]
            && row["admission"] == *admission
            && valid_iid(text(&row["invocation_id"])?)
            && row["publication_authorized"] == false,
        "foreign original 136 launch"
    );
    Ok(row)
}

fn candidate(unit: &Value, admission: &Value) -> Result<()> {
    let iid = text(&unit["InvocationID"])?;
    ensure!(valid_iid(iid), "unknown 136 actor generation");
    if local("reproduction/receipts/launch.json").try_exists()? {
        ensure!(
            launch(admission)?["invocation_id"] == iid,
            "crossed 136 actor"
        );
        return Ok(());
    }
    // A failed writer can leave its original helper still staging before launch.json.
    let a = from_ref(admission)?;
    let pid = text(&unit["MainPID"])?.parse::<i32>()?;
    ensure!(pid > 1, "no original pre-launch helper");
    let helper = &a["helper"];
    let plan = &a["plan"];
    let argv = [
        text(&helper["path"])?,
        text(&plan["path"])?,
        "--plan-sha256",
        text(&plan["sha256"])?,
        "--self-sha256",
        text(&helper["sha256"])?,
        "--admission",
        text(&admission["path"])?,
        "--admission-sha256",
        text(&admission["sha256"])?,
        "",
    ]
    .join("\0");
    let live = fs::metadata(format!("/proc/{pid}/exe"))?;
    let target = fs::metadata(aspath(helper)?)?;
    ensure!(
        aspath(helper)? == local("tools/epoch136-actual-payload")
            && bound(aspath(helper)?)? == *helper
            && (live.dev(), live.ino()) == (target.dev(), target.ino())
            && fs::read(format!("/proc/{pid}/cmdline"))? == argv.as_bytes()
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::/system.slice/{ACTOR}"),
        "foreign 136 staging helper"
    );
    Ok(())
}

fn guard_identity(unit: &str, row: &Value, admission: &Value) -> Result<()> {
    let actor = launch(admission)?;
    let path = local("reproduction/receipts/guard-plan.json");
    let binding = bound(&path)?;
    let g = from_ref(&binding)?;
    ensure!(
        g["unit"] == ACTOR
            && g["invocation_id"] == actor["invocation_id"]
            && g["worker_root"] == json!(local("reproduction"))
            && g["maximum_root_physical_bytes"] == 64u64 << 30,
        "foreign 136 guard plan"
    );
    let service = if unit == TIMER {
        ensure!(row["Unit"] == GUARD, "foreign 136 timer target");
        unit_state(GUARD)?
    } else {
        row.clone()
    };
    let command = text(&service["ExecStart"])?;
    let start = format!(
        "{{ path={GUARD_IMAGE} ; argv[]={GUARD_IMAGE} {} --plan-sha256 {} --self-sha256 {GUARD_SHA} ; ignore_errors=no ; start_time=",
        path.display(),
        text(&binding["sha256"])?
    );
    ensure!(
        command.starts_with(&start) && command.matches(" ; argv[]=").count() == 1,
        "foreign 136 guard command"
    );
    Ok(())
}

// Take a boot-local journal cursor before reading PID 1, then wait only for a
// subsequent manager event for this unit. An event is a wakeup, never proof.
fn cursor() -> Result<String> {
    let raw = platform::output(
        "/usr/bin/journalctl",
        &[
            "-b",
            "-n",
            "1",
            "-o",
            "json",
            "--no-pager",
            "--output-fields=MESSAGE_ID",
        ],
    )?;
    let last: Value = serde_json::from_str(raw.trim())?;
    Ok(text(&last["__CURSOR"])?.to_owned())
}

fn wait_unit_event(unit: &str, after: &str) -> Result<()> {
    let mut child = Command::new("/usr/bin/journalctl")
        .args([
            "-b",
            "--follow",
            "-n",
            "all",
            "--no-pager",
            "-o",
            "json",
            "--output-fields=_PID,UNIT,MESSAGE_ID",
            "--after-cursor",
            after,
            "_PID=1",
            &format!("UNIT={unit}"),
        ])
        .stdout(Stdio::piped())
        .spawn()?;
    let result = (|| -> Result<()> {
        let out = child.stdout.take().context("PID 1 event stream")?;
        let mut line = String::new();
        ensure!(
            BufReader::new(out).read_line(&mut line)? != 0,
            "PID 1 event stream ended for {unit}"
        );
        let event: Value = serde_json::from_str(&line)?;
        ensure!(
            event["_PID"] == "1" && event["UNIT"] == unit,
            "foreign manager wakeup"
        );
        Ok(())
    })();
    let _ = child.kill();
    child.wait()?;
    result
}

fn drain(unit: &str, intent: &Value, admission: Option<&Value>) -> Result<()> {
    loop {
        let after = cursor()?;
        let row = unit_state(unit)?;
        if closed(&row) {
            return empty_cgroup(unit);
        }
        let check = if unit == W {
            ensure!(
                row["InvocationID"] == intent["writer_invocation_id"],
                "another 136 writer is active"
            );
            Ok(())
        } else {
            let a = admission.context("live 136 unit without a selected admission")?;
            if unit == ACTOR {
                candidate(&row, a)
            } else {
                guard_identity(unit, &row, a)
            }
        };
        if let Err(error) = check {
            let next = unit_state(unit)?;
            if closed(&next) {
                return empty_cgroup(unit);
            }
            return Err(error);
        }
        wait_unit_event(unit, &after)?;
    }
}

fn fleet_contains_136(fleet: &Value, iid: Option<&str>) -> Result<bool> {
    let mut found = false;
    for kind in [
        "actual_active_private_diagnostics",
        "actual_executing_replays",
        "actual_active_bootstraps",
    ] {
        for row in fleet[kind].as_array().context("missing fleet roster")? {
            if row["epoch"] == 136 {
                ensure!(
                    !found
                        && kind == "actual_active_private_diagnostics"
                        && row["unit"]["Id"] == ACTOR
                        && iid.is_some()
                        && row["unit"]["InvocationID"].as_str() == iid,
                    "another or duplicated 136 in accepted fleet"
                );
                found = true;
            }
        }
    }
    Ok(found)
}

/// expected_intent is the decoded original prestart-intent.json. The caller
/// owns the selector's controller lock and has released the donor operation lock.
pub(super) fn release_before_post(
    planref: &Value,
    image: &Path,
    expected_intent: &Value,
) -> Result<()> {
    let base = local("prestart-intent.json");
    let intent_ref = bound(&base)?;
    let intent = from_ref(&intent_ref)?;
    let plan = from_ref(planref)?;
    ensure!(
        intent == *expected_intent
            && intent["schema"] == "horizon-136-incident-donor-intent-v1"
            && intent["writer_plan"] == *planref
            && intent["writer"] == plan["controller"]
            && intent["selector"] == plan["holding145_prestart_ready"]
            && intent["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
            && valid_iid(text(&intent["writer_invocation_id"])?),
        "foreign selected 136 intent"
    );
    use boundary::profile::{WRITER_DIR, WRITER_SEAL};
    let package = rt(WRITER_DIR).join("controller");
    let exact = check_member(&package, WRITER_SEAL, "admit136")?;
    ensure!(
        image == exact && bound(image)?["sha256"] == intent["writer"]["sha256"],
        "foreign release controller"
    );

    drain(W, &intent, None)?;
    let admission_path = local("admission.json");
    let admission = admission_path
        .try_exists()?
        .then(|| bound(&admission_path))
        .transpose()?;
    if let Some(reference) = &admission {
        let expiry = admission_expiry(&from_ref(reference)?, &intent)?;
        while platform::now() < expiry {
            std::thread::sleep(Duration::from_secs(expiry.saturating_sub(platform::now())));
        }
    }
    for unit in [ACTOR, TIMER, GUARD, W] {
        drain(unit, &intent, admission.as_ref())?;
    }
    let actual_admission = admission_path
        .try_exists()?
        .then(|| bound(&admission_path))
        .transpose()?;
    ensure!(
        bound(&base)? == intent_ref && actual_admission == admission,
        "136 custody changed before release"
    );
    let release_path = local("prestart-released.json");
    let result = if release_path.try_exists()? {
        bound(&release_path)?
    } else {
        // The sealed selected controller alone acquires the original operation flock,
        // unmasks the exact recorded donor and emits the durable release receipt.
        serde_json::from_slice(&command(image, &["release"])?)?
    };
    let verified: Value = serde_json::from_slice(&command(
        image,
        &[
            "verify-release",
            text(&planref["path"])?,
            text(&planref["sha256"])?,
        ],
    )?)?;
    ensure!(
        result == bound(&release_path)? && verified == result,
        "unverified 136 release"
    );
    let closed = from_ref(&result)?;
    ensure!(
        closed["intent"] == intent_ref
            && closed["admission"] == json!(admission)
            && closed["donor_restored"] == true
            && closed["candidate_physically_drained"] == true
            && closed["all_physical_outputs_retained"] == true
            && closed["resource_credit_bytes"] == 0,
        "incomplete terminal custody"
    );

    let original = if local("reproduction/receipts/launch.json").try_exists()? {
        Some(launch(
            admission
                .as_ref()
                .context("136 launch without its admission")?,
        )?)
    } else {
        None
    };
    loop {
        let head = incident::fleet()?;
        let fleet = from_ref(&head)?;
        if !fleet_contains_136(
            &fleet,
            original.as_ref().and_then(|l| l["invocation_id"].as_str()),
        )? {
            return Ok(());
        }
        outcome::wait_file(&outcome::next(&fleet)?)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_136_requires_its_original_expiry_and_fleet_generation() {
        let intent = json!({"writer":{"sha256":"a"},"writer_invocation_id":"x"});
        let mut a = json!({"schema":"horizon-epoch136-actual-admission-v1","writer":intent["writer"],
            "writer_invocation_id":"x","recorded_unix_seconds":500,"launch_expires_unix_seconds":1400});
        assert_eq!(admission_expiry(&a, &intent).unwrap(), 1400);
        a["writer_invocation_id"] = json!("other");
        assert!(admission_expiry(&a, &intent).is_err());
        let mut f = json!({"actual_active_private_diagnostics":[],"actual_active_bootstraps":[],"actual_executing_replays":[]});
        assert!(!fleet_contains_136(&f, None).unwrap());
        let row = json!({"epoch":136,"unit":{"Id":ACTOR,"InvocationID":"x"}});
        f["actual_active_private_diagnostics"] = json!([row]);
        assert!(fleet_contains_136(&f, Some("x")).unwrap());
        assert!(fleet_contains_136(&f, Some("other")).is_err());
        f["actual_executing_replays"] = json!([row]);
        assert!(fleet_contains_136(&f, Some("x")).is_err());
        assert!(closed(
            &json!({"ActiveState":"failed","MainPID":"0","ControlPID":"0","Job":""})
        ));
        assert!(!closed(
            &json!({"ActiveState":"inactive","MainPID":"0","ControlPID":"2","Job":""})
        ));
    }
}
