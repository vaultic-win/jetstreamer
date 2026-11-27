use crate::custody::{Bound, digest, is_digest, num, reference, string};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

const PACKAGE_SHA: &str = "62b7dd8b88c1210f685932c0dfe2d727ea0686af56953b55132f94bcb92ca7ba";
const READER_SCOPE: &str = "c11f9e060b518ef772379975e3008b0f630f21929230dc61c3980ddc0868f67f";
const REPO: &str = "/home/sol/workspace/jetstreamer";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub schema: String,
    pub fixture: bool,
    pub epoch: u64,
    pub threads: u64,
    pub assembly_dir: PathBuf,
    pub unit: String,
    pub invocation: String,
    pub package: Bound,
    pub reader_equivalence: Bound,
    pub plan: Bound,
    pub native_launch: Bound,
    pub expectation: Bound,
    pub preparation: Bound,
    pub selected: Bound,
    pub selected_native: Bound,
    pub lineage: Bound,
    pub terminal_edge: Bound,
}

pub struct Inputs {
    pub scope: Scope,
    pub expectation: Value,
    pub plan: Value,
    pub pipeline: Bound,
    pub verifier: Bound,
    pub main: Bound,
}

fn required_declared(path: &Value, name: &str, exact: &Bound) -> Result<()> {
    ensure!(
        reference(path, name)? == *exact,
        "different binding for {name}"
    );
    Ok(())
}

pub fn git_status(words: &[&str]) -> Result<String> {
    let out = Command::new("/usr/bin/git")
        .args([
            "-c",
            "safe.directory=/home/sol/workspace/jetstreamer",
            "-C",
            REPO,
        ])
        .args(words)
        .output()?;
    ensure!(
        out.status.success(),
        "Git {} failed: {}",
        words[0],
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

pub fn branch(eq: &Bound) -> Result<Value> {
    ensure!(
        eq.sha256 == READER_SCOPE,
        "reader compiler comparison changed"
    );
    let doc = eq.json()?;
    let from = string(&doc, "original_commit")?;
    ensure!(
        doc["compiled_file_count"] == 175
            && doc["targets"]
                == json!([
                    "horizon_pipeline",
                    "reader_playback_qualification",
                    "verify_archive"
                ]),
        "invalid target graph"
    );
    let to = git_status(&["rev-parse", "refs/remotes/origin/account-updates"])?;
    git_status(&["merge-base", "--is-ancestor", from, &to])?;
    let paths = doc["compared_paths"]
        .as_array()
        .context("compiled inputs")?;
    for chunk in paths.chunks(100) {
        let mut args = vec!["diff", "--quiet", from, &to, "--"];
        for p in chunk {
            args.push(p.as_str().context("input path")?);
        }
        git_status(&args)?;
    }
    ensure!(
        git_status(&["rev-parse", "refs/remotes/origin/account-updates"])? == to,
        "published branch moved during comparison"
    );
    Ok(
        json!({"reader_comparison":eq,"compiled_from":from,"fetched_commit":to,"compiled_inputs":175}),
    )
}

impl Inputs {
    pub fn load(binding: &Bound) -> Result<Self> {
        let s: Scope = serde_json::from_value(binding.json()?)?;
        ensure!(
            s.schema == "horizon-private-assembly-verification-scope-v1"
                && s.threads == 2
                && s.package.sha256 == PACKAGE_SHA
                && s.reader_equivalence.sha256 == READER_SCOPE
                && s.invocation.len() == 32
                && s.invocation.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid scope"
        );
        if s.fixture {
            ensure!(
                s.epoch == 251
                    && s.unit.starts_with("horizon-168-verifier-fixture-")
                    && s.assembly_dir.starts_with("/home/sol/.jetstreamer-private"),
                "invalid synthetic source"
            );
        } else {
            ensure!(
                s.epoch == 168
                    && s.unit == "horizon-assemble-168-private-20261127-v1.service"
                    && s.invocation == "f097aed2a8f647398854fa6139f02d32"
                    && s.assembly_dir
                        == Path::new(
                            "/home/sol/.jetstreamer-private/epoch168-private-assembly-20261127-v1/output"
                        )
                    && s.plan.sha256
                        == "7d22db1ba666caa553b73b89aaa2c40f82e95aa1badb09c420742a6e7e77372a"
                    && s.native_launch.sha256
                        == "3da3b3af56ae50a30787e0f924f0cf61d7a55fba76067298b19195fa678fcf28"
                    && s.expectation.sha256
                        == "2cd07c9bc75622b5b4407f0894b6c1e2b350057df8a7ab2d01231c143e22b187"
                    && s.preparation.sha256
                        == "0eea7441adfca3d0e1e50935c1816a8a65c9c5ea96fc54c0a95d23cb87c88164"
                    && s.selected.sha256
                        == "1fdbd34bc1edee4db9781f5ba27b3f9d5b6443c717a07ce6fd08ea3f7940bd3b"
                    && s.selected_native.sha256
                        == "63067817b1dfb2bd11b4c184dd089aec8cb58d9b19ab1bc93112a7171cae7044"
                    && s.lineage.sha256
                        == "4c5d0946e0f37e8695411e9859152682aea85c1d05221df7434183e00d96c65f"
                    && s.terminal_edge.sha256
                        == "7cb87c2d84b9ab53987e6cab9db776e119ff7aa1715606f223e60a10316165d4",
                "different epoch 168 producer or evidence"
            );
        }
        let package = s.package.json()?;
        let main = reference(&package, "main")?;
        let proof = main.json()?;
        let pipeline = reference(&proof, "pipeline")?;
        let verifier = reference(&proof, "full_verifier")?;
        required_declared(&package["binaries"], "horizon_pipeline", &pipeline)?;
        required_declared(&package["binaries"], "verify_archive", &verifier)?;
        ensure!(
            proof["minimum_thread_stack_bytes"] == 67108864
                && proof["full_and_plugin_capabilities_accepted"] == true
                && proof["source_artifact_correspondence_accepted"] == true
                && proof["reader_commit"] == "0bf0b2ad901b9e05b559f3feb7d02a6faf0f6ebe",
            "wrong reader qualification"
        );
        let plan = s.plan.json()?;
        let launch = s.native_launch.json()?;
        ensure!(
            plan["unit"] == s.unit
                && launch["Id"] == s.unit
                && launch["InvocationID"] == s.invocation
                && plan["output_directory"] == json!(s.assembly_dir)
                && plan["publication_authorized"] == false,
            "different assembly plan or native process"
        );
        for (key, b) in [
            ("lineage", &s.lineage),
            ("qualification", &s.selected),
            ("qualification_native", &s.selected_native),
        ] {
            required_declared(&plan, key, b)?;
        }
        let prep = s.preparation.json()?;
        let expected = s.expectation.json()?;
        let first = s.epoch.checked_mul(432000).context("slot overflow")?;
        let last = first + 431999;
        ensure!(
            prep["epoch"] == s.epoch
                && prep["expected_result"]["sha256"] == s.expectation.sha256
                && prep["slot_range"] == json!([first, last])
                && prep["slots"] == 432000
                && prep["expected_assembly_report"] == json!(s.assembly_dir.join("assembly.json"))
                && prep["publication_authorized"] == false
                && expected["schema"] == "horizon-current-reader-epoch-expectation-v1"
                && expected["epoch"] == s.epoch
                && num(&expected, "parent_slot")? < first
                && num(&expected, "terminal_slot")? <= last
                && num(&expected, "terminal_slot")? >= first
                && is_digest(string(&expected, "provenance_sha256")?),
            "invalid independent expectation"
        );
        for (key, b) in [
            ("selected_source_qualification", &s.selected),
            ("selected_source_native_acceptance", &s.selected_native),
            ("terminal_finalized_crosscheck", &s.terminal_edge),
        ] {
            required_declared(&prep, key, b)?;
        }
        let independent = expected["independent_evidence"]
            .as_array()
            .context("independent boundaries")?;
        ensure!(!independent.is_empty(), "absent independent evidence");
        for b in independent {
            serde_json::from_value::<Bound>(b.clone())?.json()?;
        }
        let src = s.selected.json()?;
        let native = s.selected_native.json()?;
        let edge = s.terminal_edge.json()?;
        let lineage = s.lineage.json()?;
        required_declared(&src, "lineage", &s.lineage)?;
        required_declared(&native, "qualified_report", &s.selected)?;
        required_declared(&native, "lineage", &s.lineage)?;
        ensure!(
            src["epoch"] == s.epoch
                && src["boundary_decoder_run"] == true
                && src["publication_authorized"] == false
                && native["native_terminal"]["success"] == true
                && native["invocation_id"] == native["native_terminal"]["invocation_id"]
                && native["publication_authorized"] == false
                && native["archive_bytes_written"] == 0
                && lineage["epoch"] == s.epoch
                && lineage["seam"] == src["seam"]
                && src["prefix_range"]["start"] == first
                && src["prefix_range"]["end_exclusive"] == src["suffix_range"]["start"]
                && src["suffix_range"]["end_exclusive"] == last + 1
                && num(&src, "seam")?.checked_add(1) == src["suffix_range"]["start"].as_u64(),
            "inconsistent selected sources"
        );
        let selected = &src["selection"];
        ensure!(
            selected["v4_provenance_sha256"] == expected["provenance_sha256"]
                && selected["retry6_last_block_slot"] == expected["terminal_slot"]
                && selected["retry6_last_blockhash"] == expected["terminal_blockhash"]
                && edge["commitment"] == if s.fixture { "synthetic" } else { "finalized" }
                && edge["slot"] == expected["terminal_slot"]
                && edge["get_block"]["result"]["blockhash"] == expected["terminal_blockhash"],
            "independent terminal or provenance mismatch"
        );
        if !s.fixture {
            let hex = string(selected, "v4_provenance_hex")?.as_bytes();
            ensure!(hex.len().is_multiple_of(2), "malformed selected provenance");
            let raw = hex
                .chunks_exact(2)
                .map(|s| {
                    u8::from_str_radix(std::str::from_utf8(s)?, 16).map_err(anyhow::Error::from)
                })
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                digest(&raw) == string(&expected, "provenance_sha256")?,
                "unbound source V4 provenance bytes"
            );
        }
        Ok(Self {
            scope: s,
            expectation: expected,
            plan,
            pipeline,
            verifier,
            main,
        })
    }

    pub fn assembly(&self, doc: &Value) -> Result<()> {
        let s = &self.scope;
        let archive = s.assembly_dir.join(format!("epoch-{}.jet", s.epoch));
        ensure!(
            doc["schema"] == "horizon-epoch168-private-v4-assembly-v1"
                && doc["epoch"] == s.epoch
                && doc["unit"] == s.unit
                && doc["invocation_id"] == s.invocation
                && doc["archive_path"] == json!(archive)
                && doc["slots"] == 432000
                && doc["publication_authorized"] == false
                && doc["independent_verification_pending"] == true
                && is_digest(string(doc, "archive_sha256")?)
                && num(doc, "archive_bytes")? > 0
                && num(doc, "archive_bytes")? <= num(&self.plan, "maximum_archive_bytes")?
                && doc["maximum_archive_bytes"] == self.plan["maximum_archive_bytes"]
                && doc["minimum_home_free_bytes"] == self.plan["minimum_home_free_bytes"]
                && doc["provenance_sha256"] == self.expectation["provenance_sha256"],
            "assembly identity, width, or provenance mismatch"
        );
        for (field, b) in [
            ("plan", &s.plan),
            ("lineage", &s.lineage),
            ("qualification", &s.selected),
            ("qualification_native", &s.selected_native),
        ] {
            required_declared(doc, field, b)?;
        }
        let admission = reference(&self.plan, "admission")?;
        required_declared(doc, "admission", &admission)?;
        let ad = admission.json()?;
        ensure!(
            ad["fits"] == true && ad["unit"] == s.unit && ad["publication_authorized"] == false,
            "different assembly admission"
        );
        Ok(())
    }
}
