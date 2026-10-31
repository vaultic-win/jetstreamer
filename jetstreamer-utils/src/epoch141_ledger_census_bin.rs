//! Private census-only profile; no decompressed files are retained.
mod epoch141_ledger_inspect;

fn main() {
    if let Err(error) = epoch141_ledger_inspect::run(false) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
