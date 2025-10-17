use crate::args;
use crate::db;
use crate::errors::*;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::convert::Infallible;
use std::result;
use std::sync::Arc;
use warp::{Filter, http::StatusCode, reject::MethodNotAllowed, reply::Response};

#[derive(RustEmbed)]
#[folder = "templates"]
#[include = "*.hbs"]
#[include = "*.css"]
struct Assets;

struct Handlebars {
    hbs: handlebars::Handlebars<'static>,
}

impl Handlebars {
    fn new() -> Result<Handlebars> {
        let mut hbs = handlebars::Handlebars::new();
        hbs.set_prevent_indent(true);
        hbs.register_embed_templates::<Assets>()?;
        Ok(Self { hbs })
    }

    fn render<T>(&self, name: &str, data: &T) -> ApiResult<String>
    where
        T: serde::Serialize,
    {
        let out = self.hbs.render(name, data)?;
        Ok(out)
    }
}

async fn index(
    hbs: Arc<Handlebars>,
    db: db::Client,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let html = hbs.render(
        "index.html.hbs",
        &serde_json::json!({
            "db_version": db.ping().await.unwrap_or_else(|_| "unknown".to_string()),
        }),
    )?;
    Ok(Box::new(warp::reply::html(html)))
}

async fn style() -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let style = Assets::get("style.css").unwrap();

    // TODO: avoid allocation if possible
    let response = Response::new(style.data.to_vec().into());

    Ok(Box::new(response))
}

async fn get_sig(
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

async fn get_issuer(
    hbs: Arc<Handlebars>,
    db: db::Client,
    fingerprint: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let issuer = db.get_issuer(&fingerprint).await?;
    let sigs = db.get_sigs_for_issuer(&fingerprint).await?;

    let html = hbs.render(
        "issuer.html.hbs",
        &serde_json::json!({
            "db_version": db.ping().await.unwrap_or_else(|_| "unknown".to_string()),
            "issuer": issuer,
            "sigs": sigs,
        }),
    )?;
    Ok(Box::new(warp::reply::html(html)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Search {
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

async fn rejection(err: warp::Rejection) -> result::Result<impl warp::Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "404 - file not found\n";
    } else if let Some(_err) = err.find::<ApiError>() {
        error!("api error: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "server error\n";
    } else if let Some(_err) = err.find::<MethodNotAllowed>() {
        code = StatusCode::BAD_REQUEST;
        message = "400 - bad request\n";
    } else {
        error!("unhandled rejection: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "server error\n";
    }

    Ok(warp::reply::with_status(message, code))
}

pub async fn run(args: &args::Web) -> Result<()> {
    let hbs = Arc::new(Handlebars::new()?);
    let hbs = warp::any().map(move || hbs.clone());

    let db = db::Client::create().await?;
    let db = warp::any().map(move || db.clone());

    let log = warp::log("web");

    let index = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path::end())
        .and_then(index);

    let style = warp::get()
        .and(warp::path("assets"))
        .and(warp::path("style.css"))
        .and(warp::path::end())
        .and_then(style);

    let search = warp::any()
        .and(db.clone())
        .and(warp::path("search"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(search);

    let get_sig = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("sig"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(get_sig);

    let get_issuer = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("issuer"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(get_issuer);

    let routes = warp::any()
        .and(index.or(style).or(search).or(get_sig).or(get_issuer))
        .recover(rejection)
        .with(log);

    info!("Starting web server on {}", args.bind_addr);
    warp::serve(routes).run(args.bind_addr).await;

    Ok(())
}
