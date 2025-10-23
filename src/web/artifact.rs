use crate::db;
use crate::errors::*;
use crate::web::{CACHE_CONTROL_DEFAULT, Handlebars, cache_control, search_not_found};
use serde::{Deserialize, Serialize};
use std::result;
use std::sync::Arc;
use warp::{Filter, http::Uri};

pub(super) fn endpoints(
    hbs: Arc<Handlebars>,
    db: db::Client,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let hbs = warp::any().map(move || hbs.clone());
    let db = warp::any().map(move || db.clone());

    let get = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(get)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let search = warp::get()
        .and(db.clone())
        .and(warp::path::end())
        .and(warp::query::<ArtifactSearch>())
        .and_then(search)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    get.or(search)
}

async fn get(
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
struct ArtifactSearch {
    pub chksum: String,
}

async fn search(
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
