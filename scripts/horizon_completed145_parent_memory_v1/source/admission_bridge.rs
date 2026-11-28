//! Only explicit, newly qualified callers may select the new view.
//! Hook after unchanged complete raw builder and current141/failed4 typed baseline.
use crate::{
    VerifiedParentMemory, fsutil as f,
    model::{Current, Request},
    preserve_baseline, select,
};
use anyhow::{Result, ensure};
use jetstreamer_typed_memory::VerifiedPeerMemory;
use serde_json::Value;
pub fn point_of_use(
    request: Option<&Request>,
    current: &Current,
    unchanged_raw_accounting: &Value,
    baseline: VerifiedPeerMemory,
    now: u64,
) -> Result<VerifiedParentMemory> {
    let Some(request) = request else {
        return Ok(preserve_baseline(baseline));
    };
    ensure!(
        request.current == *current,
        "new selector caller current tuple crossed"
    );
    let result = select(request, now)?;
    ensure!(
        result.raw_total_bytes() == baseline.raw_total_bytes()
            && result.raw_peer_bytes() == baseline.raw_peer_bytes()
            && result.evidence()["baseline_effective_total_bytes"]
                == baseline.effective_total_bytes()
            && result.evidence()["baseline_effective_peer_bytes"]
                == baseline.effective_peer_bytes()
            && result.evidence()["raw_accounting_serde_json_sha256"]
                == f::sha(&serde_json::to_vec(unchanged_raw_accounting)?),
        "caller raw builder/baseline differs; existing141/failed4 or199 deduction would repeat"
    );
    Ok(result)
}

/// Concrete standalone caller: rebuild the existing opaque baseline from the
/// successful original reader, then enter the same point-of-use hook expected
/// by the full admission consumer. It grants no CPU/DATA/VMA/launch authority.
pub fn from_current_reader(request: &Request, now: u64) -> Result<VerifiedParentMemory> {
    let (reader, _, before, after) = crate::reader(
        &request.current,
        &request.current_reader,
        &request.reader_program,
        &request.current_reader_acceptance,
        now,
    )?;
    let (base, _) = crate::baseline(request, &reader, &before, &after, now)?;
    point_of_use(Some(request), &request.current, &after, base, now)
}
