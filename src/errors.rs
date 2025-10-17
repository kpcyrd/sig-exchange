#![allow(unused_imports)]
pub use anyhow::{Context as _, Result, anyhow, bail};
pub use log::{debug, error, info, trace, warn};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error(transparent)]
    RenderError(#[from] handlebars::RenderError),
}

// TODO: not sure if this is correct
impl warp::reject::Reject for ApiError {}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
