use crate::args;
use crate::db;
use crate::errors::*;
use rust_embed::RustEmbed;
use std::convert::Infallible;
use std::result;
use std::sync::Arc;
use warp::{Filter, http::StatusCode, reply::Response};

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

async fn rejection(err: warp::Rejection) -> result::Result<impl warp::Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "404 - file not found\n";
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

    let routes = warp::any()
        .and(index.or(style))
        .recover(rejection)
        .with(log);

    info!("Starting web server on {}", args.bind_addr);
    warp::serve(routes).run(args.bind_addr).await;

    Ok(())
}
