use serde::Serialize;

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct Issuer {
    pub fingerprint: String,
    pub family: String,
}
