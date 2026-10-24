//! Compatibility wrapper preserving the Foundation holding receipt schema.
use super::*;

pub(super) fn check(value: &Value, additional: u64) -> Result<Value> {
    let mut capacity = maintenance_capacity::check(value, additional)?;
    capacity["schema"] = json!("jetstreamer-foundation-holding-capacity-v1");
    let fields = capacity
        .as_object_mut()
        .context("maintenance capacity object")?;
    let additional = fields
        .remove("additional_bytes")
        .context("maintenance bytes")?;
    fields.insert("additional_restore_bytes".into(), additional);
    fields.remove("maintenance_only");
    fields.insert("restore_only".into(), json!(true));
    Ok(capacity)
}
