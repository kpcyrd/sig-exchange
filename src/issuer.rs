use serde::Serialize;

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct Issuer {
    pub fingerprint: String,
    pub family: String,
    pub key: Option<Vec<u8>>,
}
