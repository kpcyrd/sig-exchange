use crate::{args::Plumbing, srcinfo};
use crate::{debian, errors::*};
use tokio::fs;

pub async fn run(cmd: Plumbing) -> Result<()> {
    match cmd {
        Plumbing::Srcinfo { path } => {
            let buf = fs::read_to_string(&path)
                .await
                .with_context(|| format!("Failed to read file: {path:?}"))?;
            let pkg = srcinfo::parse(&buf)?;
            println!("pkg={pkg:#?}");
        }
        Plumbing::DebSrc { path } => {
            let buf = fs::read(&path)
                .await
                .with_context(|| format!("Failed to read file: {path:?}"))?;

            let list = debian::parse(&buf)?;
            for pkg in list {
                println!("pkg={pkg:#?}");
            }
        }
    }

    Ok(())
}
