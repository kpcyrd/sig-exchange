use crate::{
    archlinux,
    args::Import,
    db,
    errors::*,
    issuer::Issuer,
    pgp,
    pkg::{Pkg, Upstream},
};
use alpm_types::OpenPGPIdentifier;
use tokio::fs;

pub async fn run(cmd: &Import) -> Result<()> {
    let db = db::Client::create().await?;

    match cmd {
        Import::ArchlinuxTar { path } => {
            let file = fs::File::open(&path)
                .await
                .with_context(|| format!("Failed to open file: {path:?}"))?;
            let (pkg, release_datetime, _keys) = archlinux::parse(file).await?;

            if let Some(pkg) = pkg {
                if pkg.signing_keys.is_empty() {
                    return Ok(());
                }

                db.insert_pkg(&Pkg {
                    os: "archlinux".to_string(),
                    name: pkg.name.clone(),
                    version: pkg.version,
                    release_datetime,
                })
                .await?;

                for key in pkg.signing_keys {
                    let OpenPGPIdentifier::OpenPGPv4Fingerprint(fp) = key else {
                        continue;
                    };
                    let issuer = fp.to_string().to_ascii_lowercase();

                    db.insert_issuer(&Issuer {
                        fingerprint: issuer.clone(),
                        family: "pgp".to_string(),
                    })
                    .await?;

                    db.insert_upstream(&Upstream {
                        os: "archlinux".to_string(),
                        name: pkg.name.clone(),
                        issuer,
                        last_observed: release_datetime,
                    })
                    .await?;
                }
            }
        }
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
