use crate::db;
use crate::web::{CACHE_CONTROL_DEFAULT, cache_control};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::result;
use warp::Filter;

pub(super) fn endpoints(
    db: db::Client,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let db = warp::any().map(move || db.clone());

    warp::any()
        .and(db.clone())
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(search)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Search {
    pub query: String,
}

async fn search(
    _db: db::Client,
    search: Search,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    Ok(Box::new(warp::reply::json(&json!({
        "status": "ok",
        "req": search
    }))))
}
