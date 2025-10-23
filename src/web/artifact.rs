use crate::db;
use crate::errors::*;
use crate::web::Handlebars;
use crate::web::search_not_found;
use serde::{Deserialize, Serialize};
use std::result;
use std::sync::Arc;
use warp::http::Uri;

pub(super) async fn get(
    hbs: Arc<Handlebars>,
    db: db::Client,
    chksum: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let artifacts = db.count_by_artifact_chksum(&chksum).await?;

    if artifacts == 0 {
        return Err(warp::reject::not_found());
    }

    // TODO: add more data
    let html = hbs.render(
        "artifact.html.hbs",
        &serde_json::json!({
            "chksum": chksum,
        }),
    )?;
    Ok(Box::new(warp::reply::html(html)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ArtifactSearch {
    pub chksum: String,
}

pub(super) async fn search(
    db: db::Client,
    search: ArtifactSearch,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let chksum = &search.chksum;
    let artifacts = db.count_by_artifact_chksum(chksum).await?;

    if artifacts == 0 {
        Ok(search_not_found())
    } else {
        let uri = format!("/artifact/{chksum}");
        let uri = uri.parse::<Uri>().map_err(ApiError::from)?;
        Ok(Box::new(warp::redirect::found(uri)))
    }
}
