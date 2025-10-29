use crate::archlinux;
use crate::args::Import;
use crate::db;
use crate::debian;
use crate::errors::*;
use crate::fetch;
use crate::issuer::Issuer;
use crate::pgp;
use crate::sig::Sig;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::fs;

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct SigQueueItem {
    pub url: String,
    pub family: String,
    pub next_fetch: DateTime<Utc>,
    pub attempts: i32,
    pub sigs: Option<Vec<String>>,
    pub artifact_chksums: Vec<String>,
    pub os: String,
    pub pkg: String,
    pub version: String,
}

impl SigQueueItem {
    pub fn next_retry(&self) -> DateTime<Utc> {
        let delay = match self.attempts {
            0 => 10,
            1 => 30,
            2 => 90,
            3 => 24 * 60,
            i => (3 * 60) * 2_i64.pow(i as u32),
        };
        Utc::now() + chrono::Duration::minutes(delay)
    }

    async fn attempt(&self, db: &db::Client, http: &fetch::Client) -> Result<Vec<String>> {
        if self.family != "pgp" {
            bail!("Unsupported sig family: {:?}", self.family);
        }

        let (_, body) = http.fetch_no_cache(&self.url).await?;

        let mut sigs = Vec::new();
        for sig in pgp::parse_sigs(&body)? {
            db.insert_issuer(&Issuer {
                fingerprint: sig.issuer.clone(),
                family: sig.family.clone(),
                key: None,
            })
            .await?;

            let sig = Sig::from(sig);
            db.insert_sig(&sig).await?;
            sigs.push(sig.chksum);
        }

        Ok(sigs)
    }

    pub async fn fetch_and_store(&mut self, db: &db::Client, http: &fetch::Client) -> Result<()> {
        match self.attempt(db, http).await {
            Ok(sigs) => {
                for sig in &sigs {
                    for artifact_chksum in &self.artifact_chksums {
                        db.insert_sig_link(
                            sig,
                            artifact_chksum,
                            &self.os,
                            &self.pkg,
                            &self.version,
                        )
                        .await?;
                    }
                }

                self.sigs = Some(sigs);
                db.solve_remote_sig_queue_item(self).await?;
            }
            Err(err) => {
                error!("Failed to fetch sig from {:?}: {err:#}", self.url);
                db.retry_remote_sig_queue_item(self).await?;
            }
        }

        Ok(())
    }
}

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
            let buf = tokio::fs::read(&path)
                .await
                .with_context(|| format!("Failed to read file: {path:?}"))?;
            for sig in pgp::parse_sigs(&buf)? {
                debug!("Signature: {sig:?}");
                info!("Inserting sig with chksum {}", sig.chksum);
                db.insert_issuer(&Issuer {
                    fingerprint: sig.issuer.clone(),
                    family: sig.family.clone(),
                    key: None,
                })
                .await?;
                let sig = Sig::from(sig);
                db.insert_sig(&sig).await?;
            }
        }
    }

    Ok(())
}
