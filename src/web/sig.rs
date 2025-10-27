use crate::db;
use crate::errors::*;
use crate::pgp::PgpSig;
use crate::web::{CACHE_CONTROL_DEFAULT, Handlebars, cache_control};
use std::result;
use std::sync::Arc;
use warp::{Filter, http::StatusCode};

pub(super) fn endpoints(
    hbs: Arc<Handlebars>,
    db: db::Client,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let hbs = warp::any().map(move || hbs.clone());
    let db = warp::any().map(move || db.clone());

    warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("-"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(get)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT))
}

async fn get(
    hbs: Arc<Handlebars>,
    db: db::Client,
    chksum: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let (chksum, download) = chksum
        .strip_suffix(".asc")
        .map(|c| (c, true))
        .unwrap_or((&chksum, false));
    let sig = db.get_sig(chksum).await?;

    // this is always "family = pgp" at this point
    let sig = PgpSig::try_from(&sig).map_err(ApiError::Anyhow)?;
    let armored = sig.to_ascii_armored().map_err(ApiError::from)?;

    if download {
        let response = warp::reply::with_status(armored, StatusCode::OK);
        Ok(Box::new(response))
    } else {
        let html = hbs.render(
            "sig.html.hbs",
            &serde_json::json!({
                "sig": sig,
                "armored": armored,
            }),
        )?;
        Ok(Box::new(warp::reply::html(html)))
    }
}
