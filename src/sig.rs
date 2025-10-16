use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub struct RemoteSig {
    pub location: String,
    pub for_hash: BTreeMap<&'static str, String>,
}
