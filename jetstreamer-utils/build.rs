use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

#[path = "build_support/clickhouse_input.rs"]
mod clickhouse_input;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let embed_clickhouse_rs = Path::new(&out_dir).join("embed_clickhouse.rs");

    for name in [
        "JETSTREAMER_CLICKHOUSE_BINARY",
        "JETSTREAMER_CLICKHOUSE_SHA256",
        "DOCS_RS",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let explicit = clickhouse_input::selected_input(
        env::var_os("JETSTREAMER_CLICKHOUSE_BINARY"),
        env::var_os("JETSTREAMER_CLICKHOUSE_SHA256"),
    )
    .unwrap_or_else(|error| panic!("Invalid explicit ClickHouse build input: {error}"));
    if let Some((path, digest)) = explicit {
        clickhouse_input::verify(&path, &digest)
            .unwrap_or_else(|error| panic!("Invalid explicit ClickHouse build input: {error}"));
        let path = path.to_str().expect("ClickHouse input path must be UTF-8");
        println!("cargo:rerun-if-changed={path}");
        println!("cargo:warning=Embedding pinned offline ClickHouse input, SHA-256 {digest}");
        fs::write(
            &embed_clickhouse_rs,
            format!(
                "/// ClickHouse binary from a verified immutable offline input.\n\
             pub const CLICKHOUSE_BINARY: &[u8] = include_bytes!({path:?});\n"
            ),
        )
        .unwrap();
        return;
    }

    if env::var("DOCS_RS").is_ok() {
        println!("cargo:warning=Skipping ClickHouse download while building on docs.rs");
        fs::write(
            &embed_clickhouse_rs,
            "/// ClickHouse binary bytes are not bundled when building on docs.rs.\n\
             pub const CLICKHOUSE_BINARY: &[u8] = &[];\n",
        )
        .unwrap();
        return;
    }

    let clickhouse_binary = out_dir.join("clickhouse");

    // Check if the ClickHouse binary exists
    if !clickhouse_binary.exists() {
        println!("ClickHouse binary not found. Downloading ClickHouse...");

        // Run the curl command to download and install ClickHouse
        let status = Command::new("sh")
            .arg("-c")
            .arg("curl https://clickhouse.com/ | sh")
            .current_dir(&out_dir)
            .status()
            .expect("Failed to download and install ClickHouse");

        if !status.success() {
            panic!("ClickHouse installation failed with status: {}", status);
        }

        // Mark the ClickHouse binary as executable
        if clickhouse_binary.exists() {
            println!("Setting ClickHouse binary as executable...");
            let mut permissions = fs::metadata(&clickhouse_binary)
                .expect("Failed to get ClickHouse binary metadata")
                .permissions();
            permissions.set_mode(0o755); // rwxr-xr-x
            fs::set_permissions(&clickhouse_binary, permissions)
                .expect("Failed to set ClickHouse binary as executable");
        } else {
            panic!("ClickHouse binary was not downloaded correctly.");
        }
    } else {
        println!("ClickHouse binary already exists. Skipping installation.");
    }

    fs::write(
        &embed_clickhouse_rs,
        format!(
            "/// Raw bytes of clickhouse binary ({} bytes)\n\
             pub const CLICKHOUSE_BINARY: &[u8] = include_bytes!(r#\"{}\"#);\n",
            fs::metadata(&clickhouse_binary).unwrap().len(),
            clickhouse_binary.display()
        ),
    )
    .unwrap();
}
