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
    fingerprint: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let Some(issuer) = db.get_issuer(&fingerprint).await? else {
        return Err(warp::reject::not_found());
    };
    let upstreams = db.list_upstreams_for_issuer(&fingerprint).await?;
    let sigs = db.list_sigs_for_issuer(&fingerprint).await?;

    let html = hbs.render(
        "issuer.html.hbs",
        &serde_json::json!({
            "issuer": issuer,
            "upstreams": upstreams,
            "sigs": sigs,
        }),
    )?;
    Ok(Box::new(warp::reply::html(html)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct IssuerSearch {
    pub fingerprint: String,
}

pub(super) async fn search(
    db: db::Client,
    search: IssuerSearch,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let fingerprint = search.fingerprint.to_ascii_lowercase();

    if let Some(issuer) = db.get_issuer(&fingerprint).await? {
        let uri = format!("/issuer/{}", issuer.fingerprint);
        let uri = uri.parse::<Uri>().map_err(ApiError::from)?;
        Ok(Box::new(warp::redirect::found(uri)))
    } else {
        Ok(search_not_found())
    }
}
