use crate::db;
use crate::web::{CACHE_CONTROL_DEFAULT, cache_control};
use std::result;
use warp::{Filter, http::StatusCode};

pub(super) fn endpoints(
    db: db::Client,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let db = warp::any().map(move || db.clone());

    warp::get()
        .and(db.clone())
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(get)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT))
}

async fn get(
    db: db::Client,
    filename: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let Some(content) = db.get_cache_by_filename(&filename).await? else {
        return Err(warp::reject::not_found());
    };

    Ok(Box::new(warp::reply::with_header(
        warp::reply::with_status(content, StatusCode::OK),
        "Content-Disposition",
        "attachment",
    )))
}
