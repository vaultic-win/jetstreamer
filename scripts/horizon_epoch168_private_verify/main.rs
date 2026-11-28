mod custody;
mod scan;
mod scope;

use anyhow::{Result, ensure};
use custody::{Bound, Opened, bound, num};
use scope::{Inputs, branch};
use serde_json::json;
use std::{
    env,
    path::{Path, PathBuf},
};

fn binding(p: &str, d: &str) -> Bound {
    Bound {
        path: PathBuf::from(p),
        sha256: d.to_owned(),
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let strings: Vec<_> = args.iter().map(|s| s.as_str()).collect();
    let row = match strings.as_slice() {
        ["scope", p, d] => {
            let b = binding(p, d);
            let input = Inputs::load(&b)?;
            let eq = branch(&input.scope.reader_equivalence)?;
            json!({"scope":b,"epoch":input.scope.epoch,"fixture":input.scope.fixture,"reader_branch":eq,"canonical_writes":false})
        }
        ["ready", p, d] => {
            let b = binding(p, d);
            let input = Inputs::load(&b)?;
            let s = &input.scope;
            let terminal = scan::terminal(&s.unit, &s.invocation)?;
            let assembly = bound(&s.assembly_dir.join("assembly.json"))?;
            let a = assembly.json()?;
            input.assembly(&a)?;
            let file = Opened::open(&s.assembly_dir.join(format!("epoch-{}.jet", s.epoch)))?;
            ensure!(
                file.start.len == num(&a, "archive_bytes")?,
                "completed archive length differs"
            );
            json!({"scope":b,"epoch":s.epoch,"fixture":s.fixture,"reader_branch":branch(&s.reader_equivalence)?,"assembly":assembly,"assembly_terminal":terminal,"archive_stamp":file.start})
        }
        ["terminal", unit, iid] => scan::terminal(unit, iid)?,
        ["run", p, d, a, asum, root] => {
            return scan::run(&binding(p, d), &binding(a, asum), Path::new(root));
        }
        ["finish", p, d, a, asum, root, t, tsum] => json!(scan::finish(
            &binding(p, d),
            &binding(a, asum),
            Path::new(root),
            &binding(t, tsum)
        )?),
        _ => anyhow::bail!("expected scope, ready, terminal, run or finish"),
    };
    println!("{}", serde_json::to_string(&row)?);
    Ok(())
}
