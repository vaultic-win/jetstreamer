mod build_support;

use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=JETSTREAMER_CLICKHOUSE_ARTIFACT");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let embed_clickhouse_rs = out_dir.join("embed_clickhouse.rs");

    if env::var_os("DOCS_RS").is_some() {
        println!("cargo:warning=Skipping ClickHouse download while building documentation");
        fs::write(
            &embed_clickhouse_rs,
            "/// ClickHouse binary bytes are not bundled in documentation builds.\n\
             pub const CLICKHOUSE_BINARY: &[u8] = &[];\n",
        )
        .unwrap();
        return;
    }

    let target = env::var("TARGET").expect("Cargo did not set TARGET");
    let artifact =
        build_support::artifact_for_target(&target).unwrap_or_else(|error| panic!("{error}"));
    let supplied = env::var_os("JETSTREAMER_CLICKHOUSE_ARTIFACT").map(PathBuf::from);
    let (source, artifact_path) =
        build_support::acquire(&out_dir, artifact, supplied.as_deref(), |destination| {
            build_support::download(artifact, destination)
        })
        .unwrap_or_else(|error| panic!("Could not acquire verified ClickHouse: {error}"));
    println!("cargo:rerun-if-changed={}", artifact_path.display());

    let clickhouse_binary = out_dir.join("clickhouse");
    // Regenerate even a cached executable from its verified source. Watching both
    // outputs makes Cargo revalidate after either is modified between builds.
    build_support::materialize(source, artifact, &clickhouse_binary)
        .unwrap_or_else(|error| panic!("Could not extract verified ClickHouse: {error}"));
    println!("cargo:rerun-if-changed={}", clickhouse_binary.display());

    // Debug string formatting escapes unusual path characters as a Rust literal.
    let path = Path::new(&clickhouse_binary)
        .to_str()
        .expect("ClickHouse output path is not valid UTF-8");
    fs::write(
        &embed_clickhouse_rs,
        format!(
            "/// Verified ClickHouse {} bytes for {}.\n\
             pub const CLICKHOUSE_BINARY: &[u8] = include_bytes!({path:?});\n",
            build_support::VERSION,
            target,
        ),
    )
    .unwrap();
}
