use crate::web::{Assets, CACHE_CONTROL_DEFAULT, Handlebars, cache_control};
use std::result;
use std::sync::Arc;
use warp::{Filter, reply::Response};

pub(super) fn endpoints(
    hbs: Arc<Handlebars>,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let hbs = warp::any().map(move || hbs.clone());

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

    index.or(style)
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
