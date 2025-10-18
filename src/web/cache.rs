use crate::db;
use std::result;
use warp::http::StatusCode;

pub(super) async fn get(
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
