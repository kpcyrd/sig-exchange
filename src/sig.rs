use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub struct RemoteSig {
    pub location: String,
    pub for_hash: BTreeMap<&'static str, String>,
}

pub fn db_id(sig: &[u8]) -> String {
    let chksum = blake3::hash(sig);
    let mut chksum = format!("{chksum}");
    chksum.truncate(32);
    chksum
}
