#[path = "build_support/clickhouse_embed.rs"]
mod clickhouse_embed;

fn main() {
    for name in [
        "JETSTREAMER_CLICKHOUSE_BINARY",
        "JETSTREAMER_CLICKHOUSE_SHA256",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support/clickhouse_embed.rs");
    let source = std::env::var_os("JETSTREAMER_CLICKHOUSE_BINARY");
    let digest = std::env::var_os("JETSTREAMER_CLICKHOUSE_SHA256");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    clickhouse_embed::generate(source.as_deref(), digest.as_deref(), &out)
        .unwrap_or_else(|error| panic!("ClickHouse embedding rejected: {error}"));
    if let Some(source) = source {
        println!(
            "cargo:rerun-if-changed={}",
            source.to_str().expect("validated UTF-8 source")
        );
    }
}
