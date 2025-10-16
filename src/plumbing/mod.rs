use crate::errors::*;
use crate::{args::Plumbing, srcinfo};
use tokio::fs;

pub async fn run(cmd: Plumbing) -> Result<()> {
    match cmd {
        Plumbing::Srcinfo { path } => {
            let buf = fs::read_to_string(&path)
                .await
                .with_context(|| format!("Failed to read the file: {path:?}"))?;
            let pkg = srcinfo::parse(&buf)?;
            println!("pkg={pkg:#?}");
        }
    }

    Ok(())
}
