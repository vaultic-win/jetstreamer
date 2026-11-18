//! Read-only staged consumer inspection; no retirement or replay authority.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::path::Path::new("/home/sol/.jetstreamer-private/epoch141-ledger-source-20261020-v1/download/rocksdb.tar.bz2");
    println!("{}", jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(target)?);
    Ok(())
}
