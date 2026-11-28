//! Positive evidence for the running full/plugin/boundary readers and uploader.
//! A watcher covering 130 is a real consumer even while its canonical input is absent.
use crate::{SHA, SOURCE, closure, raw, s, sha};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, os::unix::fs::MetadataExt, path::Path};

const DIR: &str = "/var/lib/jetstreamer/horizon_runtime_data/cold130-boot-lineage-20261121-v1";
const DECLARATION: &str = "a883ba29ffdc1c41fc1c2ce896d4d2d3b1aee2ba7eab0b65660e7a2d03180d8e";
const READERS: &str = "a12535f32a2c6a63d43a6390fd2a9b25610f2c04a94c7911e99bd808e9345e5c";
const CANONICAL: &str = "/home/sol/horizon";

pub(super) fn binding() -> Value {
    json!({"path":format!("{DIR}/CANONICAL_READER_DECLARATIONS.json"),"sha256":READERS})
}
fn fixed(name: &str, digest: &str) -> Result<Value> {
    crate::bound_with_limit(
        &json!({"path":format!("{DIR}/{name}"),"sha256":digest}),
        1 << 20,
        true,
    )
}

pub(super) fn controller() -> Result<()> {
    let d = fixed("ROOT_CURRENT_HANDOFF_DECLARATION.json", DECLARATION)?;
    ensure!(
        d["owner"] == "/root"
            && d["source"] == SOURCE
            && d["sha256"] == SHA
            && d["known_staged_producer_or_consumer_of_this_local_body"].is_null()
            && s(&d, "boot_id")? == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "different controller, boot or source in historical handoff"
    );
    for b in d["covered_handoffs"]
        .as_array()
        .context("reviewed controller scope")?
    {
        let path = Path::new(s(b, "path")?);
        let bytes = fs::read(path)?;
        let size = usize::try_from(b["size"].as_u64().context("bound handoff length")?)?;
        let reviewed = bytes.get(..size).context("controller handoff truncated")?;
        ensure!(
            sha(reviewed) == s(b, "sha256_at_review")?,
            "controller handoff rewritten"
        );
        // Handoffs are append-only. A later 130 instruction must be independently reconciled.
        let extra = bytes.get(size..).context("handoff suffix")?;
        ensure!(
            ![
                SOURCE.as_bytes(),
                SHA.as_bytes(),
                b"cold130",
                b"epoch130",
                b"epoch 130"
            ]
            .iter()
            .any(|key| extra.windows(key.len()).any(|w| w == *key)),
            "candidate-specific assignment added after handoff {}",
            path.display()
        );
    }
    Ok(())
}
fn directory(pid: u32) -> Result<()> {
    let real = fs::symlink_metadata(CANONICAL)?;
    ensure!(
        real.is_dir() && (real.dev(), real.ino()) == (64512, 290586625),
        "canonical directory changed"
    );
    let view = Path::new("/proc")
        .join(pid.to_string())
        .join("root/home/sol/horizon");
    let world = fs::metadata(&view)?;
    ensure!(
        (world.dev(), world.ino()) == (real.dev(), real.ino()),
        "reader has alternate archive mount"
    );
    for name in ["epoch-130.jet", "epoch-130.jet.sha256"] {
        match fs::symlink_metadata(view.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(m) => {
                ensure!(
                    m.is_file() && m.nlink() == 1 && (m.dev(), m.ino()) != (64512, 100794422),
                    "canonical reader aliases old body"
                );
                if name.ends_with(".sha256") {
                    ensure!(m.len() < 1024, "unexpected canonical sidecar size");
                    let bytes = fs::read(view.join(name))?;
                    ensure!(
                        std::str::from_utf8(&bytes)?.split_whitespace().next()
                            == Some(crate::CANONICAL_SHA),
                        "canonical ready sidecar digest differs"
                    );
                } else {
                    ensure!(m.len() == 83_405_061_082, "canonical body length differs");
                }
            }
        }
    }
    Ok(())
}
pub(super) fn canonical_classes() -> Result<BTreeSet<String>> {
    let d = fixed("CANONICAL_READER_DECLARATIONS.json", READERS)?;
    let mut classes = BTreeSet::new();
    for r in d["readers"].as_array().context("declared native cohorts")? {
        let n = s(r, "unit")?;
        let current = closure::native(n)?;
        ensure!(
            current["ActiveState"] == "active"
                && current["SubState"] == "running"
                && current["InvocationID"] == r["invocation"],
            "running canonical cohort changed: {n}"
        );
        let pid = s(&current, "MainPID")?.parse::<u32>()?;
        let cmd = fs::read(format!("/proc/{pid}/cmdline"))?;
        ensure!(
            sha(&cmd) == r["actual_argv_sha256"],
            "canonical reader actual command changed: {n}"
        );
        let args: Vec<_> = cmd.split(|b| *b == 0).collect();
        let index = usize::try_from(
            r["canonical_argument_index"]
                .as_u64()
                .context("canonical argument index")?,
        )?;
        ensure!(
            args.get(index) == Some(&CANONICAL.as_bytes()),
            "reader is not bound to its canonical argument"
        );
        if r["reader_class"] == "import-publication" {
            ensure!(
                args.contains(&b"--defer-epochs=129-132".as_slice()),
                "progressive publisher no longer defers 130"
            );
        }
        directory(pid)?;
        for k in ["actually_loaded_fragments", "reviewed_wrappers"] {
            for b in r[k].as_array().context("actual archive selection code")? {
                let declared = Path::new(s(b, "path")?);
                let resolved = declared.canonicalize()?;
                if declared != resolved {
                    let permitted = match declared.to_str() {
                        Some(
                            "/etc/systemd/system/horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service.d/50-native198-receipts.conf",
                        ) => {
                            "/usr/local/lib/jetstreamer/horizon-epoch198-uploader-transition-20261021-v1/50-native198-receipts.conf"
                        }
                        Some(
                            "/etc/systemd/system/horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service.d/60-native183-receipts.conf",
                        ) => {
                            "/usr/local/lib/jetstreamer/horizon-cohort183-uploader-transition-20261029-v2/60-native183-receipts.conf"
                        }
                        _ => anyhow::bail!(
                            "unknown canonical watcher configuration alias: {}",
                            declared.display()
                        ),
                    };
                    ensure!(
                        resolved == Path::new(permitted)
                            && fs::symlink_metadata(declared)?.uid() == 0,
                        "canonical watcher drop-in alias changed"
                    );
                }
                let bytes = raw(&resolved, 16 << 20, true)?;
                ensure!(
                    declared.canonicalize()? == resolved,
                    "canonical watcher drop-in changed"
                );
                ensure!(
                    sha(&bytes) == b["sha256"],
                    "loaded input or root selector changed: {}",
                    b["path"]
                );
            }
        }
        let after = closure::native(n)?;
        ensure!(
            after["MainPID"] == current["MainPID"]
                && after["InvocationID"] == current["InvocationID"],
            "reader changed during inspection"
        );
        ensure!(
            classes.insert(s(r, "reader_class")?.to_owned()),
            "duplicate reader class"
        );
    }
    Ok(classes)
}

pub(super) fn inert_probe(path: &Path, target: &Path, bytes: &[u8]) -> Result<bool> {
    const UNIT: &str = "horizon-cold130-holding-capability-20261110-v1.service";
    const SPEC: &str =
        "/usr/local/lib/jetstreamer/horizon-cold130-holding-plan-20261110-v1/plan.json";
    if path != Path::new("/run/systemd/transient").join(UNIT) || target != Path::new(SPEC) {
        return Ok(false);
    }
    ensure!(
        sha(bytes) == "baa5a9fd576317ba33a65332495f29ca8afee690732ca05a870ba992019d0f56",
        "dormant probe unit changed"
    );
    let d = closure::native(UNIT)?;
    closure::terminal(UNIT, &d)?;
    let evidence = raw(
        Path::new("/var/lib/jetstreamer/cold130-holding-20261110-v1/probe.stderr"),
        1 << 16,
        true,
    )?;
    ensure!(d["InvocationID"]=="d2efb2081e754736a905a9161701c46e" && d["ActiveState"]=="failed" && evidence==b"Error: holding evidence digest differs: path=/usr/local/lib/jetstreamer/horizon-cold130-holding-plan-20261110-v1/plan.json actual_bytes=815 allowed_bytes=1048576\n", "probe is no longer the original terminal digest rejection");
    Ok(true)
}

fn exact_write_mounts(bytes: &[u8], parent: &Path) -> Result<bool> {
    let source = parent.to_str().context("nonunicode source parent")?;
    let permitted = BTreeSet::from([
        source,
        "/var/lib/jetstreamer/horizon_runtime_data/cold130-boot-lineage-20261121-v1/retirement",
        "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock",
    ]);
    let mut seen = BTreeSet::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        if let Some(list) = line.strip_prefix("ReadWritePaths=") {
            for item in list.split_ascii_whitespace() {
                let item = item
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(item);
                if !permitted.contains(item) || !seen.insert(item) {
                    return Ok(false);
                }
            }
        } else if crate::process_references::encoded_reference(
            line.as_bytes(),
            source.as_bytes(),
            true,
        ) {
            return Ok(false);
        }
    }
    Ok(seen == permitted)
}
pub(super) fn own_sandbox(path: &Path, target: &Path, bytes: &[u8]) -> Result<bool> {
    if Some(target) != Path::new(SOURCE).parent() {
        return Ok(false);
    }
    let mode = match path.to_str() {
        Some("/run/systemd/transient/horizon-cold130-backed-retire-check-20261110-v2.service") => {
            false
        }
        Some(
            "/run/systemd/transient/horizon-cold130-backed-retire-execute-20261110-v2.service",
        ) => true,
        _ => return Ok(false),
    };
    if !exact_write_mounts(bytes, target)? {
        return Ok(false);
    }
    ensure!(
        fs::symlink_metadata(path)?.uid() == 0
            && crate::prior_boot::is_image(&fs::read_link("/proc/self/exe")?),
        "untrusted native sandbox exception"
    );
    crate::own(mode)?;
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_three_projected_write_mounts_can_name_the_paid_caller_source_parent() {
        let p = Path::new("/private/source/archives");
        let allowed = "ReadWritePaths=\"/var/lib/jetstreamer/horizon_runtime_data/cold130-boot-lineage-20261121-v1/retirement\" \"/private/source/archives\" \"/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock\"\n";
        assert!(exact_write_mounts(allowed.as_bytes(), p).unwrap());
        for extra in [
            "ExecStart=/reader /private/source/archives/epoch-130.jet\n",
            "ReadWritePaths=/home/sol/foreign\n",
            "ReadWritePaths=/private/source/archives\n",
        ] {
            assert!(!exact_write_mounts(format!("{allowed}{extra}").as_bytes(), p).unwrap());
        }
    }
}
