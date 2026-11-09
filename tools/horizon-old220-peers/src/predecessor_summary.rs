// Typed replay of the previous raw native envelopes against the current opaque
// five-peer capture. Raw input is retained; only four typed command timestamps
// are ignored for comparison AFTER ordered path/argv/ignore checks pass.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeRecord {
    program: String,
    argv: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SummaryRow {
    unit: String,
    original_invocation_id: String,
    actual_terminal: BTreeMap<String, String>,
    native_query_sha256: BTreeMap<String, String>,
    native_raw_evidence: Vec<NativeRecord>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerSummary {
    schema: String,
    review_sha256: String,
    source_specs_sha256: String,
    selected_owner: String,
    selected_epoch: u64,
    selected_inodes: Vec<u64>,
    inputs: Vec<ReadWitness>,
    rows: Vec<SummaryRow>,
    data_retirement_authorized: bool,
    global_alias_closure_qualified: bool,
    capacity_credit_bytes: u64,
}
struct RecordedNative {
    records: std::collections::VecDeque<NativeRecord>,
}
impl Backend for RecordedNative {
    fn read(&mut self, _: &Pin) -> Result<ReadFile> {
        anyhow::bail!("native replay cannot read source")
    }
    fn directory_names(&mut self, _: &str) -> Result<Option<Vec<String>>> {
        anyhow::bail!("native replay cannot read directories")
    }
    fn query(&mut self, q: &Request) -> Result<Reply> {
        let r = self
            .records
            .pop_front()
            .context("predecessor missing native request")?;
        ensure!(
            r.program == q.program && r.argv == q.argv,
            "predecessor native request/order differs"
        );
        Ok(Reply {
            code: r.exit_code,
            stdout: r.stdout,
            stderr: r.stderr,
        })
    }
}
fn command_display(raw: &str) -> Result<Value> {
    commands(raw)?; // validates ALL tuple types, including PID/code/status
    let mut v: Value = serde_json::from_str(raw)?;
    for row in v["data"].as_array_mut().context("command data")? {
        let a = row.as_array_mut().context("command tuple")?;
        for stamp in &mut a[3..7] {
            *stamp = json!(0);
        }
    }
    Ok(v)
}
fn validate_summary_against(current: &ValidatedPeers, value: &Value) -> Result<()> {
    let p: PeerSummary = serde_json::from_value(value.clone())?;
    ensure!(
        p.schema == "horizon-old220-peers1016-exact-five-current-v2"
            && p.review_sha256 == current.review_sha256
            && p.source_specs_sha256 == digest(SPEC_BYTES)
            && p.selected_owner == OWNER
            && p.selected_epoch == 220
            && p.selected_inodes == vec![20581075, 20582466]
            && p.inputs == current.reads
            && p.rows.len() == 5
            && !p.data_retirement_authorized
            && !p.global_alias_closure_qualified
            && p.capacity_credit_bytes == 0,
        "predecessor peer review/spec/selection/input binding differs"
    );
    for (raw, row) in p.rows.iter().enumerate() {
        let now: SummaryRow = serde_json::from_value(current.rows[raw].clone())?;
        ensure!(
            row.unit == now.unit
                && row.original_invocation_id == now.original_invocation_id
                && row.actual_terminal == now.actual_terminal,
            "predecessor peer role/history/terminal differs"
        );
        let encoded = serde_json::to_value(row)?;
        let records: Vec<NativeRecord> =
            serde_json::from_value(encoded["native_raw_evidence"].clone())?;
        let mut replay = RecordedNative {
            records: records.into(),
        };
        let verified = check_native(&mut replay, &current.specs[raw], &current.origins[raw], "")?;
        ensure!(
            replay.records.is_empty() && verified == encoded,
            "predecessor native envelope/hash/terminal incomplete or altered"
        );
        ensure!(row.native_raw_evidence.len() == now.native_raw_evidence.len());
        for (old, new) in row.native_raw_evidence.iter().zip(&now.native_raw_evidence) {
            ensure!(
                old.program == new.program
                    && old.argv == new.argv
                    && old.exit_code == new.exit_code
                    && old.stderr == new.stderr
            );
            let property = old.argv.last().map(String::as_str).unwrap_or("");
            if old.program == "/usr/bin/busctl" && COMMANDS.contains(&property) {
                // check_native above independently proved exact ordered command vectors.
                ensure!(
                    command_display(&old.stdout)? == command_display(&new.stdout)?,
                    "predecessor command identity/PID/code/status differs"
                );
            } else {
                ensure!(
                    old.stdout == new.stdout,
                    "predecessor non-timestamp native capture differs"
                );
            }
        }
    }
    Ok(())
}
