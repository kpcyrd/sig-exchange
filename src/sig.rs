use serde::Serialize;
use std::collections::BTreeMap;

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct Sig {
    pub chksum: String,
    pub family: String,
    pub issuer: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RemoteSig {
    pub sig_url: String,
    pub artifact_url: String,
    pub artifact_hashes: BTreeMap<&'static str, String>,
}

pub fn db_id(sig: &[u8]) -> String {
    let chksum = blake3::hash(sig);
    let mut chksum = format!("{chksum}");
    chksum.truncate(32);
    chksum
}
