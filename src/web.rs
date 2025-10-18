mod cache;
mod issuer;
mod pkg;
mod sig;

use crate::args;
use crate::db;
use crate::errors::*;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::convert::Infallible;
use std::result;
use std::sync::Arc;
use warp::reply::Reply;
use warp::{
    Filter,
    http::{HeaderValue, StatusCode, header},
    reject::MethodNotAllowed,
    reply::Response,
};

const CACHE_CONTROL_DEFAULT: HeaderValue =
    HeaderValue::from_static("public, max-age=600, stale-while-revalidate=300, stale-if-error=300");

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

fn cache_control(reply: impl warp::Reply, value: HeaderValue) -> impl warp::Reply {
    warp::reply::with_header(reply, header::CACHE_CONTROL, value)
}

async fn index(hbs: Arc<Handlebars>) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let html = hbs.render("index.html.hbs", &serde_json::json!({}))?;
    Ok(Box::new(warp::reply::html(html)))
}

async fn style(filename: String) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    if filename.ends_with(".css")
        && let Some(style) = Assets::get(&filename)
    {
        // TODO: avoid allocation if possible
        let response = Response::new(style.data.to_vec().into());
        Ok(Box::new(response))
    } else {
        Err(warp::reject::not_found())
    }
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

fn search_not_found() -> Box<dyn warp::Reply> {
    let reply = warp::reply::with_header(
        warp::reply::with_status("", StatusCode::FOUND),
        "Location",
        "/#not-found",
    )
    .into_response();
    Box::new(reply)
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
        .and(warp::path::end())
        .and_then(index)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let style = warp::get()
        .and(warp::path("assets"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(style)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let search = warp::any()
        .and(db.clone())
        .and(warp::path("search"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(search)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let get_sig = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("-"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(sig::get)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let get_issuer = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("issuer"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(issuer::get)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let search_issuer = warp::get()
        .and(db.clone())
        .and(warp::path("issuer"))
        .and(warp::path::end())
        .and(warp::query::<issuer::IssuerSearch>())
        .and_then(issuer::search)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let get_pkg = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("pkg"))
        .and(warp::path::param())
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(pkg::get)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let list_os_pkgs = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("pkg"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(pkg::list_for_os)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let search_pkg = warp::get()
        .and(hbs.clone())
        .and(db.clone())
        .and(warp::path("pkg"))
        .and(warp::path::end())
        .and(warp::query::<pkg::PkgSearch>())
        .and_then(pkg::search)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let cache = warp::get()
        .and(db.clone())
        .and(warp::path("cache"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and_then(cache::get)
        .map(|r| cache_control(r, CACHE_CONTROL_DEFAULT));

    let routes = warp::any()
        .and(
            index
                .or(style)
                .or(get_sig)
                .or(get_issuer)
                .or(search_issuer)
                .or(get_pkg)
                .or(list_os_pkgs)
                .or(search_pkg)
                .or(search)
                .or(cache),
        )
        .recover(rejection)
        .with(log);

    info!("Starting web server on {}", args.bind_addr);
    warp::serve(routes).run(args.bind_addr).await;

    Ok(())
}
