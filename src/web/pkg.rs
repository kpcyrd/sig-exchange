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
    os: String,
    name: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let pkgs = db.list_pkgs(&os, &name).await?;
    if pkgs.is_empty() {
        return Err(warp::reject::not_found());
    };

    let html = hbs.render(
        "pkg.html.hbs",
        &serde_json::json!({
            "db_version": db.ping().await.unwrap_or_else(|_| "unknown".to_string()),
            "os": os,
            "name": name,
            "pkgs": pkgs,
        }),
    )?;
    Ok(Box::new(warp::reply::html(html)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PkgSearch {
    pub name: String,
}

pub(super) async fn search(
    hbs: Arc<Handlebars>,
    db: db::Client,
    search: PkgSearch,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let pkgs = db.search_pkgs_by_name(&search.name).await?;

    let Some(first) = pkgs.first() else {
        return Ok(search_not_found());
    };

    if pkgs.len() == 1 {
        let (os, name) = first;
        let uri = format!("/pkg/{os}/{name}");
        let uri = uri.parse::<Uri>().map_err(ApiError::from)?;
        return Ok(Box::new(warp::redirect::found(uri)));
    }

    let html = hbs.render(
        "pkg_search.html.hbs",
        &serde_json::json!({
            "db_version": db.ping().await.unwrap_or_else(|_| "unknown".to_string()),
            "name": search.name,
            "pkgs": pkgs,
        }),
    )?;

    Ok(Box::new(warp::reply::html(html)))
}
