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
            let file = fs::File::open(&path)
                .await
                .with_context(|| format!("Failed to open file: {path:?}"))?;
            let list = debian::parse_source_index(file).await?;
            for pkg in list {
                println!("pkg={pkg:#?}");
            }
        }
        Plumbing::DebianTar { path } => {
            let file = fs::File::open(&path)
                .await
                .with_context(|| format!("Failed to open file: {path:?}"))?;
            let key = debian::parse_source_tar(file).await?;
            println!("key={key:#?}");
        }
    }

    Ok(())
}
