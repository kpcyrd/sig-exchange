use crate::db;
use crate::errors::*;
use crate::web::Handlebars;
use std::result;
use std::sync::Arc;
use warp::http::StatusCode;

pub(super) async fn get(
    hbs: Arc<Handlebars>,
    db: db::Client,
    chksum: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let (chksum, download) = chksum
        .strip_suffix(".asc")
        .map(|c| (c, true))
        .unwrap_or((&chksum, false));
    let sig = db.get_sig(chksum).await?;
    let armored = sig.to_ascii_armored().map_err(ApiError::from)?;

    if download {
        let response = warp::reply::with_status(armored, StatusCode::OK);
        Ok(Box::new(response))
    } else {
        let html = hbs.render(
            "sig.html.hbs",
            &serde_json::json!({
                "db_version": db.ping().await.unwrap_or_else(|_| "unknown".to_string()),
                "sig": sig,
                "armored": armored,
            }),
        )?;
        Ok(Box::new(warp::reply::html(html)))
    }
}
