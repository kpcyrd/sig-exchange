use crate::db;
use crate::errors::*;
use crate::web::Handlebars;
use crate::web::search_not_found;
use sequoia_openpgp::{Packet, PacketPile, parse::Parse};
use serde::{Deserialize, Serialize};
use std::result;
use std::sync::Arc;
use warp::http::{StatusCode, Uri};

fn pgp_mpis(bytes: &[u8]) -> Option<String> {
    let pile = PacketPile::from_reader(bytes).ok()?;

    for packet in pile.descendants() {
        let mpis = match packet {
            Packet::PublicKey(key) => key.mpis(),
            Packet::PublicSubkey(key) => key.mpis(),
            _ => continue,
        };
        return Some(format!("{mpis:#?}"));
    }

    None
}

pub(super) async fn get(
    hbs: Arc<Handlebars>,
    db: db::Client,
    fingerprint: String,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let (fingerprint, download) = fingerprint
        .strip_suffix(".asc")
        .map(|c| (c, true))
        .unwrap_or((&fingerprint, false));

    let Some(mut issuer) = db.get_issuer(fingerprint).await? else {
        return Err(warp::reject::not_found());
    };

    if download {
        let armored = issuer.to_ascii_armored().map_err(ApiError::from)?;
        let response = warp::reply::with_status(armored, StatusCode::OK);
        return Ok(Box::new(response));
    }

    let upstreams = db.list_upstreams_for_issuer(fingerprint).await?;
    let sigs = db.list_sigs_for_issuer(fingerprint).await?;

    let mpis = match (issuer.family.as_str(), issuer.key.take()) {
        ("pgp", Some(key)) => pgp_mpis(&key),
        _ => None,
    };

    let html = hbs.render(
        "issuer.html.hbs",
        &serde_json::json!({
            "issuer": issuer,
            "upstreams": upstreams,
            "sigs": sigs,
            "mpis": mpis,
        }),
    )?;
    Ok(Box::new(warp::reply::html(html)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct IssuerSearch {
    pub fingerprint: String,
}

pub(super) async fn search(
    db: db::Client,
    search: IssuerSearch,
) -> result::Result<Box<dyn warp::Reply>, warp::Rejection> {
    let fingerprint = search.fingerprint.to_ascii_lowercase();

    if let Some(issuer) = db.get_issuer(&fingerprint).await? {
        let uri = format!("/issuer/{}", issuer.fingerprint);
        let uri = uri.parse::<Uri>().map_err(ApiError::from)?;
        Ok(Box::new(warp::redirect::found(uri)))
    } else {
        Ok(search_not_found())
    }
}
