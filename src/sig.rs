use std::collections::BTreeMap;

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
