use crate::{archlinux, db, debian, errors::*, pgp};
use crate::{args::Plumbing, srcinfo};
use tokio::fs;

pub async fn run(cmd: Plumbing) -> Result<()> {
    match cmd {
        Plumbing::ArchlinuxTar { path } => {
            let file = fs::File::open(&path)
                .await
                .with_context(|| format!("Failed to open file: {path:?}"))?;
            let key = archlinux::parse(file).await?;
            println!("key={key:#?}");
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
        Plumbing::Migrate => {
            let _db = db::Client::create().await?;
            info!("All migrations have been applied");
        }
        Plumbing::PgpSigs { path } => {
            let buf = fs::read_to_string(&path)
                .await
                .with_context(|| format!("Failed to read file: {path:?}"))?;
            pgp::parse(&buf)?;
        }
        Plumbing::PingDb => {
            let db = db::Client::create_no_migrations().await?;
            let version = db.ping().await?;
            println!("Database connected: {version:?}");
        }
        Plumbing::Srcinfo { path } => {
            let buf = fs::read_to_string(&path)
                .await
                .with_context(|| format!("Failed to read file: {path:?}"))?;
            let pkg = srcinfo::parse(&buf)?;
            println!("pkg={pkg:#?}");
        }
    }

    Ok(())
}
