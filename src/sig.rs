use crate::db;
use crate::errors::*;
use crate::pkg::{Artifact, Pkg};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct Sig {
    pub chksum: String,
    pub family: String,
    pub issuer: String,
    pub bytes: Vec<u8>,
    pub hash_algo: Option<String>,
    pub creation_time: Option<DateTime<Utc>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RemoteSig {
    pub sig_url: String,
    pub artifact_url: String,
    pub artifact_hashes: BTreeMap<&'static str, String>,
}

pub async fn insert_remote_sigs(db: &db::Client, sigs: &[RemoteSig], pkg: &Pkg) -> Result<()> {
    for sig in sigs {
        let mut hashes = Vec::new();

        for (algo, hash) in &sig.artifact_hashes {
            let artifact = Artifact {
                chksum: format!("{algo}:{hash}"),
                url: sig.artifact_url.clone(),
                os: pkg.os.to_string(),
                pkg: pkg.name.clone(),
                version: pkg.version.clone(),
            };
            db.insert_artifact(&artifact).await?;
            hashes.push(artifact.chksum);
        }

        db.insert_remote_sig(&sig.sig_url, &hashes, pkg).await?;
    }

    Ok(())
}

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct SigLink {
    pub sig_chksum: String,
    pub artifact_chksum: String,
    pub os: String,
    pub verified: Option<bool>,
}

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct SigQueueItem {
    pub url: String,
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
}

pub fn db_id(sig: &[u8]) -> String {
    let chksum = blake3::hash(sig);
    let mut chksum = format!("{chksum}");
    chksum.truncate(32);
    chksum
}
