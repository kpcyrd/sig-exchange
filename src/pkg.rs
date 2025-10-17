use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct Upstream {
    pub os: String,
    pub name: String,
    pub issuer: String,
    pub last_observed: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct Pkg {
    pub os: String,
    pub name: String,
    pub version: String,
    pub release_datetime: DateTime<Utc>,
}
