use crate::{archlinux, args::Import, db, debian, errors::*, issuer::Issuer, pgp};
use tokio::fs;

pub async fn run(cmd: &Import) -> Result<()> {
    let db = db::Client::create().await?;

    match cmd {
        Import::ArchlinuxTar { path } => {
            let file = fs::File::open(&path)
                .await
                .with_context(|| format!("Failed to open file: {path:?}"))?;

            archlinux::import_pkg(&db, file).await?;
        }
        Import::ArchlinuxTree => archlinux::import_tree(db).await?,
        Import::DebianSources => debian::import_sources(db).await?,
        Import::PgpSigs { path } => {
            let buf = tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("Failed to read file: {path:?}"))?;
            for sig in pgp::parse(&buf)? {
                debug!("Signature: {sig:?}");
                info!("Inserting sig with chksum {}", sig.chksum);
                db.insert_issuer(&Issuer {
                    fingerprint: sig.issuer.clone(),
                    family: sig.family.clone(),
                })
                .await?;
                db.insert_sig(&sig).await?;
            }
        }
    }

    Ok(())
}
