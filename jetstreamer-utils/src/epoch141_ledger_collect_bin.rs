//! Separate private full-retention profile. Never selects native/replay/publication.
// Share exact source, admission and receipt gates with the census profile;
// runtime mode is fixed by the executable, never selectable on the command line.
mod epoch141_ledger_inspect;

fn main() {
    if let Err(error) = epoch141_ledger_inspect::run(true) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
