//! GET-only inspection for comparing dashboard reports; never remote proof.
use super::*;

pub(super) async fn run() -> Result<()> {
    let args = env::args().skip(2).collect::<Vec<_>>();
    ensure!(
        !args.is_empty() && args.len() <= 16,
        "status-inspect EPOCH [EPOCH ...] (at most16)"
    );
    let epochs = args
        .iter()
        .map(|arg| arg.parse::<u64>().context("invalid status epoch"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        epochs.iter().all(|n| *n <= 1_000_000),
        "status epoch outside inspection bound"
    );
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    let mut objects = Vec::new();
    for epoch in epochs {
        let key = format!("epoch-{epoch}.epoch-status.json");
        let object = get_mutable_object(&s3, &r2.bucket, &key).await?;
        objects.push(match object {
            Some(object) => serde_json::json!({"key":key,"etag":object.etag,"payload":serde_json::from_slice::<Value>(&object.bytes)?}),
            None => serde_json::json!({"key":key,"payload":null}),
        });
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"bucket":r2.bucket,"objects":objects,"r2_mutations":false})
        )?
    );
    Ok(())
}
