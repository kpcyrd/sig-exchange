mod artifact;
mod cache;
mod index;
mod issuer;
mod pkg;
mod search;
mod sig;

use crate::args;
use crate::db;
use crate::errors::*;
use rust_embed::RustEmbed;
use std::convert::Infallible;
use std::result;
use std::sync::Arc;
use warp::reply::Reply;
use warp::{
    Filter,
    http::{HeaderValue, StatusCode, header},
    reject::MethodNotAllowed,
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
    let db = db::Client::create().await?;

    let log = warp::log("web");

    let index = index::endpoints(hbs.clone());
    let search = warp::path("search").and(search::endpoints(db.clone()));
    let sigs = sig::endpoints(hbs.clone(), db.clone());
    let issuers = warp::path("issuer").and(issuer::endpoints(hbs.clone(), db.clone()));
    let pkgs = warp::path("pkg").and(pkg::endpoints(hbs.clone(), db.clone()));
    let artifacts = warp::path("artifact").and(artifact::endpoints(hbs.clone(), db.clone()));
    let cache = warp::path("cache").and(cache::endpoints(db.clone()));

    let routes = warp::any()
        .and(
            index
                .or(sigs)
                .or(issuers)
                .or(pkgs)
                .or(artifacts)
                .or(search)
                .or(cache),
        )
        .recover(rejection)
        .with(log);

    info!("Starting web server on {}", args.bind_addr);
    warp::serve(routes).run(args.bind_addr).await;

    Ok(())
}
