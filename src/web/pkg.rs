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
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(get)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let list_for_os = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(list_for_os)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let search = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path::end())
        .and(warp::query::<PkgSearch>())
        .and_then(search)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    get.or(list_for_os).or(search)
}

async fn get(
    hbs: Arc<Handlebars>,
    db: db::Client,
    os: String,
    name: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let pkgs = db.list_pkgs(&os, &name).await?;

    let Some(latest) = pkgs.iter().map(|p| p.release_datetime).max() else {
        return Err(warp::reject::not_found());
    };

    let upstreams = db.list_upstreams_for_pkg(&os, &name, latest).await?;

    let html = hbs.render(
        "pkg.html.hbs",
        &serde_json::json!({
            "os": os,
            "name": name,
            "upstreams": upstreams,
            "pkgs": pkgs,
        }),
    )?;
    Ok(Box::new(warp::reply::html(html)))
}

async fn list_for_os(
    hbs: Arc<Handlebars>,
    db: db::Client,
    os: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let pkgs = db.list_os_pkgs(&os).await?;
    if pkgs.is_empty() {
        return Err(warp::reject::not_found());
    };

    let html = hbs.render(
        "pkg_os.html.hbs",
        &serde_json::json!({
            "os": os,
            "pkgs": pkgs,
        }),
    )?;
    Ok(Box::new(warp::reply::html(html)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PkgSearch {
    pub name: String,
}

async fn search(
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
            "name": search.name,
            "pkgs": pkgs,
        }),
    )?;

    Ok(Box::new(warp::reply::html(html)))
}
