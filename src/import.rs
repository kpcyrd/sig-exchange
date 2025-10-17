use crate::{args::Import, db, errors::*, issuer::Issuer, pgp};

pub async fn run(cmd: &Import) -> Result<()> {
    let db = db::Client::create().await?;

    match cmd {
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
