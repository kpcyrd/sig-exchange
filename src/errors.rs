#![allow(unused_imports)]
pub use anyhow::{Context as _, Result, anyhow, bail};
pub use log::{debug, error, info, trace, warn};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error(transparent)]
    RenderError(#[from] handlebars::RenderError),
    #[error(transparent)]
    MigrateError(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    SqlxError(#[from] sqlx::Error),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
    #[error(transparent)]
    Uri(#[from] warp::http::uri::InvalidUri)
}

// TODO: not sure if this is correct
impl warp::reject::Reject for ApiError {}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
