//! Networked handoff of the one completed epoch to the ordinary Rust R2
//! publisher. All archive, public playback and readiness operations stay in it.
use super::*;

const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1";
const REPOSITORY: &str = "/home/sol/workspace/jetstreamer";
const ORIGIN: &str = "git@github-matt-vaultic:vaultic-win/jetstreamer.git";
pub(super) const UPLOADER: &str =
    "eb448ede557144f04446dbe00a2d2ec7ad88c934a7a227797d0569a15307a904";
use post::{PIPELINE, VERIFIER};

fn bound(path: PathBuf, sha: &str) -> Bound {
    Bound {
        path,
        sha256: sha.into(),
    }
}

pub(super) fn frozen_json(path: &Path) -> Result<(Bound, Value)> {
    let m = custody::frozen_identity(path)?;
    ensure!(m.bytes <= 8 << 20, "oversized receipt");
    let b = bound(path.into(), &custody::sha(&fs::read(path)?));
    let v = custody::json(&b, true)?;
    Ok((b, v))
}

fn uploader(root: &Path) -> Result<PathBuf> {
    let exe = root.join("uploader-tools/jetstreamer-r2");
    let seal = frozen_json(&root.join("uploader-tools/deployment-seal-receipt.json"))?.1;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == exe.parent().unwrap().to_str().unwrap()
            && seal["members"].as_array().is_some_and(|a| a
                .iter()
                .any(|m| m["name"] == "jetstreamer-r2"
                    && m["sha256"] == UPLOADER
                    && m["mode"] == "0555")),
        "ordinary uploader deployment changed"
    );
    let qa = custody::evidence(&bound(
        root.join("route-39b88e91a2904751a5be211d4f5f58fe/route.json"),
        "ab5dc9610ae71789183efec7de7dcf711e87932075d27d0427754c62f7f5f970",
    ))?;
    ensure!(
        qa["artifact_sha256"] == UPLOADER
            && qa["authenticated_read_only_inventory"] == true
            && qa["remote_mutations"] == false,
        "native route qualification changed"
    );
    custody::bytes(&bound(exe.clone(), UPLOADER), 64 << 20, true)?;
    Ok(exe)
}

fn local(full: &Path, iid: &str, archive: &Path) -> Result<(Bound, String)> {
    let (_, v) = frozen_json(&full.join("verified.json"))?;
    let (_, p) = frozen_json(&full.join("verified-plugin.json"))?;
    #[cfg(incident_fixture_post145_only)]
    {
        let exporter = materialized::completion_owner()?;
        post::fixture_semantic_owner(&exporter)?;
        let extraction = Path::new(BASE)
            .join("state")
            .join(exporter)
            .join("extraction-complete.json");
        ensure!(
            v["export_completion"] == json!(custody::binding(&extraction)?),
            "local verification used a different semantic promotion"
        );
    }
    let id = custody::frozen_identity(archive)?;
    let hash = v["archive_sha256"].as_str().context("local digest")?;
    let plan: Bound = serde_json::from_value(v["delivery_plan"].clone())?;
    ensure!(
        id.device == 64512
            && id.inode == 103237059
            && id.bytes == BYTES
            && v["schema"] == "horizon-145-current-native-full-acceptance-v1"
            && p["schema"] == "horizon-145-current-native-plugin-acceptance-v1"
            && [&v, &p].iter().all(|r| r["epoch"] == 145
                && r["invocation"] == iid
                && r["archive"] == archive.to_str().unwrap()
                && r["archive_identity"] == json!(id)
                && r["archive_sha256"] == hash
                && r["exit_code"] == 0
                && r["r2_mutations"] == false)
            && custody::hex(hash, 64)
            && v["expected_slot_count"] == 432000
            && v["incoming_slot"] == 62639999
            && v["terminal_slot"] == 63071999
            && v["independent_pre_post_hashes_match"] == true
            && v["verifier"]["sha256"] == VERIFIER
            && p["pipeline"]["sha256"] == PIPELINE
            && plan.path == full.join("delivery-plan.json"),
        "independent local receipts, range, payload or plan changed"
    );
    let b: Bound = serde_json::from_value(p["report"].clone())?;
    ensure!(
        b.path == full.join("plugin-report.json"),
        "wrong local report binding"
    );
    let argv: Vec<String> = serde_json::from_value(p["argv"].clone())?;
    post::plugin_counts(&custody::evidence(&b)?, &argv)?;
    let body = custody::json(&plan, true)?;
    #[cfg(incident_v5z_post145_only)]
    ensure!(
        body["reader_commit"] == post::GUARD_READER_COMMIT
            && body["qualification"]["sha256"] == post::GUARD_QUALIFICATION_SHA
            && p["current_branch_qualification"] == post::GUARD_QUALIFICATION_SHA,
        "epoch 145 verification did not use the qualified HTTP retry reader"
    );
    ensure!(
        body["threads"] == 1
            && body["origin_url"] == ORIGIN
            && body["repository"] == REPOSITORY
            && body["pipeline"] == p["pipeline"]
            && body["full_verifier"] == v["verifier"]
            && body["epoch_expectations"]["145"] == v["expectation"]
            && body["scratch_directory"] == full.join("delivery").to_str().unwrap(),
        "incorrect epoch-specific ordinary plan"
    );
    let sidecar = archive.with_extension("jet.sha256");
    let expected = format!("{hash}  epoch-145.jet\n");
    custody::bytes(
        &bound(sidecar, &custody::sha(expected.as_bytes())),
        128,
        true,
    )?;
    Ok((plan, hash.into()))
}

fn output(path: &Path) -> Result<Stdio> {
    Ok(Stdio::from(
        OpenOptions::new()
            .write(true)
            .mode(0o600)
            .create_new(true)
            .open(path)?,
    ))
}

fn entry(v: &Value) -> Result<&Value> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-r2-inventory-v1"
            && v["first_epoch"] == 145
            && v["last_epoch"] == 145
            && v["requested_epochs"] == 1
            && v["anomalies"] == 0
            && v["entries"]
                .as_array()
                .is_some_and(|a| a.len() == 1 && a[0]["epoch"] == 145),
        "unexpected authenticated inventory"
    );
    Ok(&v["entries"][0])
}

fn missing(v: &Value) -> Result<()> {
    let row = entry(v)?;
    ensure!(
        row["state"] == "missing"
            && v["missing"] == 1
            && v["ready_pairs"] == 0
            && ["archive_length", "archive_etag", "sidecar_sha256"]
                .iter()
                .all(|key| row.get(key).is_some_and(Value::is_null)),
        "archive or sidecar already present"
    );
    Ok(())
}

fn owner_command() -> Result<Command> {
    let m = fs::metadata(REPOSITORY)?;
    ensure!(
        m.uid() == 1001 && m.gid() == 1001 && std::env::var("HOME")? == "/home/sol",
        "repository owner or SSH home changed"
    );
    let socket = std::env::var("SSH_AUTH_SOCK")?;
    use std::os::unix::fs::FileTypeExt;
    let s = fs::symlink_metadata(&socket)?;
    ensure!(
        s.file_type().is_socket() && s.uid() == m.uid(),
        "agent socket owner changed"
    );
    let mut c = Command::new("/usr/bin/setpriv");
    c.env_clear()
        .env("HOME", "/home/sol")
        .env("SSH_AUTH_SOCK", socket)
        .env("PATH", "/usr/bin:/bin")
        .args(["--reuid=1001", "--regid=1001", "--clear-groups", "--"]);
    Ok(c)
}

pub(super) fn publish(fleet: Bound, full_iid: &str, sha: &str, joint: bool) -> Result<()> {
    let root = Path::new(ROOT);
    let image = if cfg!(incident_post145_only) {
        PathBuf::from(post::INCIDENT_POST_IMAGE)
    } else if joint {
        joint::IMAGE.into()
    } else if cfg!(materialized145_only) {
        PathBuf::from(materialized::IMAGE)
    } else {
        root.join("network-tools/export145")
    };
    check_image(sha, &image)?;
    if joint {
        joint::route(sha)?;
    }
    let iid = verify_cgroup()?;
    ensure!(
        custody::hex(full_iid, 32) && full_iid != iid,
        "invalid completed verification identity"
    );
    let _exclusive = lock()?;
    pending()?;
    source_identity()?;
    post::terminal(full_iid)?;
    let full = root.join(format!("full-{full_iid}"));
    let archive = Path::new(OUTPUT).join("epoch-145.jet");
    let (plan, hash) = local(&full, full_iid, &archive)?;
    let exe = uploader(root)?;
    #[cfg(not(incident_post145_only))]
    let (fit, first) = {
        let fit = capacity::capture_phase(&fleet, joint || cfg!(continuity145_only))?;
        fit.await_topology()?;
        let first = fit.await_current(0)?;
        (fit, first)
    };
    source_lease::arm_break_signal()?;
    let acquire =
        |p: &Path| source_lease::ReadLease::acquire(p, (&fs::symlink_metadata(p)?).into());
    let archive_lease = acquire(&archive)?;
    let checksum_lease = acquire(&archive.with_extension("jet.sha256"))?;
    #[cfg(incident_post145_only)]
    let (fit, first) = {
        let fit = incident_fit::Fit::capture(&fleet)?;
        fit.await_topology()?;
        let first = fit.await_current(0)?;
        (fit, first)
    };
    let tree = publication_tree::Tree::create()?;
    let run = |cmd: &mut Command| tree.run(cmd, &fit, &archive_lease, &checksum_lease);
    let state = root.join(format!("network-{iid}"));
    fs::DirBuilder::new().mode(0o700).create(&state)?;
    let receipts = state.join("receipts");
    fs::DirBuilder::new().mode(0o700).create(&receipts)?;
    custody::write_new(
        &state.join("started.json"),
        &json!({"invocation":iid,"local_verification":full_iid,
        "archive_sha256":hash,"reader_plan":plan,"fleet":fleet,"fit":fit.evidence,"initial":first,
        "uploader":UPLOADER,"holding_lock":HOLDING_LOCK}),
    )?;
    run(owner_command()?
        .args(["/usr/bin/ssh-add", "-l"])
        .stdout(Stdio::null()))?;
    let git = |args: &[&str], label: &str| -> Result<String> {
        let path = state.join(label);
        run(owner_command()?
            .args(["/usr/bin/git", "-C", REPOSITORY])
            .args(args)
            .stdout(output(&path)?))?;
        Ok(fs::read_to_string(path)?.trim().to_owned())
    };
    ensure!(
        git(&["remote", "get-url", "origin"], "origin.txt")? == ORIGIN,
        "repository origin changed"
    );
    let remote = git(
        &[
            "ls-remote",
            "--exit-code",
            "origin",
            "refs/heads/account-updates",
        ],
        "ls-remote.txt",
    )?;
    let (tip, name) = remote.split_once('\t').context("missing branch ref")?;
    ensure!(
        custody::hex(tip, 40) && name == "refs/heads/account-updates",
        "invalid SSH branch result"
    );
    git(
        &[
            "fetch",
            "origin",
            "refs/heads/account-updates:refs/remotes/origin/account-updates",
        ],
        "fetch.txt",
    )?;
    let inventory = |label: &str| -> Result<Value> {
        let path = state.join(label);
        run(Command::new(&exe)
            .arg("inventory")
            .arg(OUTPUT)
            .args(["--epochs", "145-145"])
            .stdout(output(&path)?))?;
        custody::evidence(&custody::binding(&path)?)
    };
    missing(&inventory("before.json")?)?;
    run(Command::new(&exe)
        .arg("sync")
        .arg(OUTPUT)
        .args(["--epochs", "145-145", "--receipt-directory"])
        .arg(&receipts)
        .arg("--current-reader-plan")
        .arg(&plan.path)
        .arg("--current-reader-plan-sha256")
        .arg(&plan.sha256)
        .args(["--concurrency", "1", "--part-size-mib", "64"]))?;
    let delivered = custody::binding(&receipts.join("epoch-145.r2.json"))?;
    let receipt = custody::evidence(&delivered)?;
    let after = inventory("after.json")?;
    let row = entry(&after)?;
    ensure!(
        receipt["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && receipt["bucket"] == "solana-archive-with-accounts-data"
            && receipt["epoch"] == 145
            && receipt["archive_key"] == "epoch-145.jet"
            && receipt["checksum_key"] == "epoch-145.jet.sha256"
            && receipt["archive_length"] == BYTES
            && receipt["archive_sha256"] == hash
            && receipt["remote_sha256_readback"] == true
            && row["state"] == "ready-pair"
            && row["archive_etag"] == receipt["archive_etag"]
            && row["archive_length"] == BYTES
            && row["sidecar_sha256"] == hash
            && row["archive_metadata_sha256"] == hash,
        "durable receipt and authenticated inventory disagree"
    );
    let playback: Bound = serde_json::from_value(receipt["current_reader_playback"].clone())?;
    ensure!(
        playback.path.starts_with(full.join("delivery"))
            && playback
                .path
                .file_name()
                .is_some_and(|n| n == "remote-playback-acceptance.json"),
        "wrong public playback receipt"
    );
    let played = custody::json(&playback, true)?;
    ensure!(
        played["epoch"] == 145
            && played["reader_plan"] == json!(plan)
            && played["remote_playback"]["object"]["sha256"] == hash
            && played["remote_playback"]["object"]["etag"] == receipt["archive_etag"],
        "public playback does not bind ready object"
    );
    checksum_lease.check()?;
    archive_lease.check()?;
    custody::write_new(
        &state.join("complete.json"),
        &json!({"invocation":iid,"verified_pair":delivered,
        "public_playback":playback,"authenticated_inventory":custody::binding(&state.join("after.json"))?,
        "original_source_retained":true,"canonical_output_retained":true}),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the final owner, agent socket, writable Git and service mounts"]
    fn native_service_owner_fetch() {
        let invoke = |args: &[&str]| -> String {
            let o = owner_command().unwrap().args(args).output().unwrap();
            assert!(
                o.status.success(),
                "owner command failed: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            String::from_utf8(o.stdout).unwrap().trim().to_owned()
        };
        assert!(!invoke(&["/usr/bin/ssh-add", "-l"]).is_empty());
        assert_eq!(
            invoke(&[
                "/usr/bin/git",
                "-C",
                REPOSITORY,
                "remote",
                "get-url",
                "origin"
            ]),
            ORIGIN
        );
        let git = |args: &[&str]| invoke(&[&["/usr/bin/git", "-C", REPOSITORY][..], args].concat());
        let output = git(&[
            "ls-remote",
            "--exit-code",
            "origin",
            "refs/heads/account-updates",
        ]);
        let (hash, name) = output.split_once('\t').unwrap();
        assert!(custody::hex(hash, 40) && name == "refs/heads/account-updates");
        git(&[
            "fetch",
            "origin",
            "refs/heads/account-updates:refs/remotes/origin/account-updates",
        ]);
        assert!(custody::hex(
            &git(&["rev-parse", "refs/remotes/origin/account-updates^{commit}"]),
            40
        ));
        println!("owning user authenticated configured SSH origin at {hash}");
    }

    #[test]
    fn authenticated_singleton_must_have_neither_archive_nor_sidecar() {
        let v = json!({"schema":"jetstreamer-horizon-r2-inventory-v1","first_epoch":145,"last_epoch":145,
            "requested_epochs":1,"anomalies":0,"missing":1,"ready_pairs":0,"entries":[{"epoch":145,"state":"missing",
            "archive_length":null,"archive_etag":null,"sidecar_sha256":null}]});
        missing(&v).unwrap();
        for (key, value) in [
            ("archive_length", json!(BYTES)),
            ("archive_etag", json!("changed")),
            ("sidecar_sha256", json!("existing")),
        ] {
            let mut changed = v.clone();
            changed["entries"][0][key] = value;
            assert!(missing(&changed).is_err());
        }
    }
}
