use crate::db;
use crate::errors::*;
use crate::fetch;
use crate::issuer::Issuer;
use crate::pgp;
use crate::pkg::{Pkg, Upstream};
use crate::sig;
use crate::srcinfo;
use alpm_types::OpenPGPIdentifier;
use async_compression::tokio::bufread::BzDecoder;
use chrono::{DateTime, Utc};
use std::{cmp, collections::VecDeque, path::Path};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio_stream::StreamExt;

const OS: &str = "archlinux";
const REPOS: &[&str] = &["core-x86_64", "extra-x86_64", "multilib-x86_64"];

fn matches_repo(path: &Path) -> bool {
    let Ok(path) = path.strip_prefix("state-main") else {
        return false;
    };
    REPOS.iter().any(|repo| path.starts_with(repo))
}

fn normalize_archlinux_gitlab_names(package: &str) -> String {
    if package == "tree" {
        return "unix-tree".to_string();
    }

    let mut iter = package.chars();
    let mut out = String::new();
    while let Some(ch) = iter.next() {
        if ch != '+' {
            out.push(ch);
        } else if iter.clone().any(|c| c != '+') {
            out.push('-');
        } else {
            out.push_str("plus");
        }
    }
    out
}

pub async fn import_tree(db: &db::Client) -> Result<()> {
    let client = fetch::Client::new(db.clone())?;

    let state_url =
        "https://gitlab.archlinux.org/archlinux/packaging/state/-/archive/main/state-main.tar.bz2";
    let stream = client.stream(state_url).await?;
    let reader = tokio_util::io::StreamReader::new(stream);
    let reader = BufReader::new(reader);
    let reader = BzDecoder::new(reader);

    let mut tar = tokio_tar::Archive::new(reader);
    let mut entries = tar.entries()?;

    let mut queue = VecDeque::new();
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;

        let header = entry.header();
        if header.entry_type() != tokio_tar::EntryType::Regular {
            continue;
        }

        let path = entry.path()?;
        if !matches_repo(&path) {
            debug!("Skipping package: {path:?}");
            continue;
        }
        info!("Processing archlinux tree path: {path:?}");

        let mut buf = String::new();
        entry.read_to_string(&mut buf).await?;

        let mut chunker = buf.split(' ');
        let Some(pkgbase) = chunker.next() else {
            continue;
        };
        let Some(version) = chunker.next() else {
            continue;
        };
        let Some(tag) = chunker.next() else { continue };

        queue.push_back((pkgbase.to_string(), version.to_string(), tag.to_string()));
    }

    for (pkgbase, _version, tag) in queue {
        let repo = normalize_archlinux_gitlab_names(&pkgbase);
        let url = format!(
            "https://gitlab.archlinux.org/archlinux/packaging/packages/{repo}/-/archive/{tag}/{repo}-{tag}.tar.bz2"
        );

        let data = client.fetch(&url).await?;
        debug!("Fetched {} bytes", data.len());

        if let Err(err) = import_pkg(&db, &data[..]).await {
            error!("Failed to import package {pkgbase} from archlinux tree: {err:#}");
        }
    }

    Ok(())
}

pub async fn import_pkg<R: AsyncRead + Unpin>(db: &db::Client, reader: R) -> Result<()> {
    let (pkg, release_datetime, signing_keys) = parse(reader).await?;

    if let Some(pkg) = pkg {
        if pkg.signing_keys.is_empty() {
            return Ok(());
        }

        db.insert_pkg(&Pkg {
            os: OS.to_string(),
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            release_datetime,
        })
        .await?;

        for key in pkg.signing_keys {
            let OpenPGPIdentifier::OpenPGPv4Fingerprint(fp) = key else {
                continue;
            };
            let issuer = fp.to_string().to_ascii_lowercase();

            db.insert_issuer(&Issuer {
                fingerprint: issuer.clone(),
                family: "pgp".to_string(),
                key: None,
            })
            .await?;

            db.insert_upstream(&Upstream {
                os: OS.to_string(),
                name: pkg.name.clone(),
                issuer,
                last_observed: release_datetime,
            })
            .await?;
        }

        if let Some(signing_keys) = signing_keys {
            let keys = pgp::parse_keys(signing_keys.as_bytes())
                .with_context(|| format!("Failed to parse PGP keys for package {:?}", pkg.name))?;

            // We only add the bytes to the database, these files don't imply trust on their own
            for key in keys {
                db.insert_issuer(&Issuer {
                    fingerprint: key.fingerprint,
                    family: "pgp".to_string(),
                    key: Some(key.bytes),
                })
                .await?;
            }

            sig::insert_remote_sigs(
                db,
                &pkg.sigs,
                &Pkg {
                    os: OS.to_string(),
                    name: pkg.name,
                    version: pkg.version,
                    release_datetime,
                },
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn parse<R: AsyncRead + Unpin>(
    reader: R,
) -> Result<(Option<srcinfo::Pkg>, DateTime<Utc>, Option<String>)> {
    let reader = BufReader::new(reader);
    let reader = BzDecoder::new(reader);
    let mut tar = tokio_tar::Archive::new(reader);
    let mut entries = tar.entries()?;

    let mut srcinfo = None;

    let mut release_time = None;
    let mut signing_keys = String::new();
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        let mtime = entry.header().mtime()?;
        let mtime = DateTime::from_timestamp_secs(mtime as i64);
        release_time = cmp::max(release_time, mtime);

        let path = entry.path()?;
        let Some(path) = path.to_str() else {
            continue;
        };

        debug!("Found file in archlinux tar: {path:?}");

        if path.ends_with("/.SRCINFO") {
            debug!("Parsing .SRCINFO file from archlinux tar");

            let mut buf = String::new();
            entry.read_to_string(&mut buf).await?;

            srcinfo = Some(srcinfo::parse(&buf)?);
        } else if path.contains("/keys/pgp/") && path.ends_with(".asc") {
            info!("Reading public key from archlinux tar: {path:?}");

            entry.read_to_string(&mut signing_keys).await?;
            if !signing_keys.ends_with('\n') {
                signing_keys.push('\n');
            }
        }
    }

    let release_time = release_time.context("Failed to determine release datetime")?;

    let signing_keys = Some(signing_keys);
    let signing_keys = signing_keys.filter(|s| !s.is_empty());

    Ok((srcinfo, release_time, signing_keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sig::RemoteSig, srcinfo::Pkg};

    #[tokio::test]
    async fn test_parse() {
        let data = include_bytes!(
            "../test_data/rebuilderd-1a3fed9ab0e3828a968047735f752c171838724f.tar.bz2"
        );

        let (srcinfo, release_time, keys) = parse(&data[..]).await.unwrap();
        assert_eq!(srcinfo,
           Some(Pkg {
            name: "rebuilderd".to_string(),
            version: "0.25.0-1".to_string(),
            signing_keys: vec!["64B13F7117D6E07D661BBCE0FE763A64F5E54FD6".parse().unwrap()],
            sigs: vec![RemoteSig {
                sig_url: "https://github.com/kpcyrd/rebuilderd/releases/download/v0.25.0/rebuilderd-0.25.0.tar.gz.asc".to_string(),
                family: "pgp".to_string(),
                artifact_url: "https://github.com/kpcyrd/rebuilderd/archive/refs/tags/v0.25.0.tar.gz".to_string(),
                artifact_hashes: [
                    ("blake2b", "d8700167849f09eb2667e198f5c91f4a910566f3b1a7100a4f835181b9aff17892d9c976665e5dc60c6bec74ac9262d673c9add3cbe62470f90cc5fd4912d2dc".to_string()),
                    ("sha512", "b1cb36f3d9b416aac208a32e0c76041f04b975c9ea04c4f49f4c8a46856ecd960577e05a40d1278fa2feb326623af816a1dae1e8ad64d72745643f99101ac286".to_string()),
                ].into_iter().collect(),
            }],
        }
        ));
        assert_eq!(
            release_time,
            DateTime::parse_from_rfc3339("2025-08-29T11:43:50Z").unwrap(),
        );
        assert_eq!(
            keys.as_deref(),
            Some(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBFvFw/oBEADXsERfKaqjSXZLVQ1bUzkdxViCQ1Tploywx6cHzj3Dl+ZpymAW\nC8RyKn9SFAqBqKuO0zt2kvq+mUlihvL9ChrEGemhnTQ3WbkNKS3RjVANjhNNGFXe\nDneqEE7HVFWKD1qaOrrOLyJVvNJnvaUd3WcS6u+OqHg5S5ldFl5c40VnJ2NCl7aD\noOjcYOIzQUEmTkO6B+nIP34amI9M4C6LWIIokSMVOW7vlkKkAA3j2ct9g9FGBKnz\nF/tHVxlNYj6pd7+j7LCQQVtMFqPlyhiVKavfhONqN4QGbq+Ef2TVcgiq3Lbgcopm\nt+zjMgvwP70h+ztnDQ8uOIrH3q6mAhvQK/zzRDC/P92hcZycXgaa+v3jQrf4sLq4\nxGFRhJimoAgZCYGdIWesBkpXAJ4gtfenkR7HYUn0mj3xcEoGJLwUlzuK8be3RbWv\nqnL4TLK3VZwLma9fRDqoy1ChggtnnThZyO9DKMprE1O32VGBC4LWg+LSecOl74EP\n6uYRiBTjjEzUvSiHn34oIHWwpsyYEtdilENGZE/IM5b4B/yxUndcLa0QIqmXw7Xw\nTyeSrZcF/zKfYK/tCAxDSbOjb5ZQuqg+BjYb4peP6gQ2i4ig30zznLq3iPwNwjYR\nDsxnS9rq3+gChQwTu+XXnnFw+dNmq5SRYglPmpaXyEbSg7NlJt2AbQ6GhQARAQAB\ntBNrcGN5cmQgPGdpdEByeHYuY2M+iQJXBBMBCgBBAhsDBQsJCAcDBRUKCQgLBRYC\nAwEAAh4BAheAAhkBFiEEZLE/cRfW4H1mG7zg/nY6ZPXlT9YFAl2l8qQFCQeDySoA\nCgkQ/nY6ZPXlT9ZRYBAAmbgLwveE0rd78KRuebn/SpxgrZB2rO1N4Sox+GFTlxMs\nXtU5AUXdmDrNZWxZGxgatKv4geFS9RO1jrlUBpwKV2pRby8b+51ZOWspgzf3aObU\nGJ5Nm8DpBUH6tmJAvshYcjjZku5VySo/p2xPdW3Scl8FHVaNsrH+BZBsECznAFD0\nQeqe2wHFIJSa6KWocuvUs18K7ZIpD8n+zl2vcrvJwT8A3qdpnEzyAffhqI+dVv7n\nYxRGHM7h4fwF1wjWq+G0mZDdYJEDkbsHIv97vd2xSPgWXnQX9GtEyDTUUZkfNg+z\nnOk3vXFnTWyTm2TMZyeJb1dTDYvI+zfWpgWW1HYPsumePb/NMfkBU2CQo0AYo+Th\nZ3612Wf19pEc85gffVphS6y5gAvnW2C1yLR5dx96h2smAZKi2tPxRu5uXQfVMXUc\nokv4p4Okk8TpqolfMiC+HgF4tgNYYhti1InX/60jyKVxq+po0QaGnZCHvYeB/n2U\nb4b5Ziy1o5yDmyb5rm59W4WdP0qocw04pfb9LWsc/dPPZvZJjdsg6Pr8hbsSAh4S\nmIpQjLdCdVvKrrtdLQW+NnpKE4AlVP9NuNHl0ntiytqvh0H2cf7BoBzWsmlRnwGJ\nzFwdyZrYKokrCDnsrPSxGuoze2x9oihCfUYyl5eJ7pzWFrQq+4p1ro5RC5i9YOK0\nHWtwY3lyZCA8a3BjeXJkQGFyY2hsaW51eC5vcmc+iQJUBBMBCgA+AhsDBQsJCAcD\nBRUKCQgLBRYCAwEAAh4BAheAFiEEZLE/cRfW4H1mG7zg/nY6ZPXlT9YFAl2l8qQF\nCQeDySoACgkQ/nY6ZPXlT9ZTyRAAxAPCTB4tyoCJPrxvw7ELdgSC+ZV5IBnonKSl\n4g60/d2fsGhjJVn15iV3g8bp/znAVM1DLuFwHQZju/hNxrHOqK2V1FK3YMCzQcGJ\nnZhoF7iSTmwQwXJJBYn/YuUx2pnl/onr/kWBVhjEcehgNJCL1tDfOmbOL5yy2KgC\nJZkfo4dMO9uKagmIH8WE43lQ9J/GKpCq7wqcTHsAlEwWGRmFcassx2X0luk5IqBx\nTrj87Uu2sTJs2QLx4pX3fyEJMZLTOeAHvDnyonOZPAItWrUGSo/mfqk9K0EidrTc\nDLgEewi0Jb/b0f366SQenEd5IaVBxzkKBEpfzgNtZUj8h1pGiAWc1+5bEATgAThU\nA+vu7P/50hQ+0an4zdQTuYh37b8sppP56WmIGO4YM6YXgp4aV9EdlO39nHknCtBJ\n3I40Q4Rn5EAN+8gGZCZPgpJ4ojzJ7GfAmTCYUMBHiEGKmGefZl6+uK9ge3G1PRrv\nt3iO7fEQIb6LxFHzusoYLj3I+QH306282HhQM628a96W7/RnKMIUAbMVFLt24Wo5\nY5raeeduJhLEkrpSZ+YAV74WzP2nIkIEtLeqRpFULB135OdpsrHouWodV8IYpsHt\nxH6ORw0PbPdxEwQF8Kljklguk1Le0v7Ihk91BfTFLCGB9GM4gC5J+oIaVthYHdtI\nj+QnNyi5Ag0EXFyH/AEQAJpW7r63imLm0w4nncEsOAJe5WWRRLWicNcIY6rFKHul\nAUHTXynwRaV9cL9YPnSNM/Q9ba5e50B/QhL57OAzH7m9lDihho4ByKbSEz05CCLC\nZUIbu9tP/BkflksrbH7fU7zuNbiZz69ynwHGsf5WmHmxB9IajcbEPpBwGof2EP7A\nqktXtrJp27zSLG3s+phAL7H2bASmO+/2pW/sh7Nqt8qJJ8zWj64kbDDi69K4judz\nEjPDIqD1BelKMmEVs8dduvj1qKgY90PiLxCJsIicIIsMe1tl76U4hlHGrCoJkSsZ\no8t0PQqkYrbHjO2LIohQXhMc2bg4S0Cf7LxRzj65kZNhoL68nl0y63sEe84CvG9o\n422gjzMX8vvojC4vPdmTznRM4boDArMiJi4uKpwXf2NLcYrIAXLIKk2FyjM+FcIT\n796OYPOpC1CAdhFqT4c8us5D7h61Bmy4vrsHGVXKmHpIpVMIWgtSxcShoKuLRx1M\nMv7ymcv7C377n+zCIKXu+JYB1ckF/FF39o5//o5WCQM1p/ozQxQtRFa3LtbYZmT0\nUMAeoP3oms6tpe5LereBkhrwhOF8qL+xoCKGinLxVXZjq/a90e2ZmEBuABWymXyz\n8HZfRn80Ak+3zz3ImGn+dRaN3vkmBksS5P15HJXntduUTbzNt+vVJgNEBl8H3bNr\nABEBAAGJBHIEGAEKACYCGwIWIQRksT9xF9bgfWYbvOD+djpk9eVP1gUCXaXzDQUJ\nBu0FkQJACRD+djpk9eVP1sF0IAQZAQoAHRYhBDPruKjhxWU2RbEjKkWmUOJjjFNt\nBQJcXIf8AAoJEEWmUOJjjFNtLdwP/2bAKtpXFukBVmFpnF8pNRpM4YH9RvUgPTd/\nn3W7uPHwgXCzkhJF6MbNtxdKLS8TqxUV4GcTxN1MQihhn+kY8ANeSM0H3RJti+cV\nc5UkC6vKU+KqlwBZz67E9kAiP0WEfCRZSlkPuQNYFe4Rqs3kzeN/Ge64Xg2WC/ma\nJ3itlGuiUlz1VLCYleBv79B91GA20DSEPpJH9S97f8aWfjM/jI+83P92KLFgRs87\nR2UPv4ztY65ephLyjIOwR01eRZdXHWOqUnQGs+UbPmMt7bYkA0YPmFFnwU+rIj+0\nxnoTWaIQtdIE6UHhXIpN7yQAizySUmxJM+DpqM7sTYKJJNVOUKGP999fBdl70kH+\n+ajwaCckhZPPELr7slauB58nN4AVbryVNOsJoyDk0c2RHUtIqojhwx/aw6ysk/Qf\nXYVnzxM79OOSqIUNEeL5A7PEcSKlm5CqhHWUOJbsLz4PdEEOcp+Y5k2kYRZpJStG\niCAFUFcpWN2eiajks8O1AkznfeMNr4eZmMNfPfRouqVWmfZK+YYogpapK+wnGOXa\nnnNnBosk6KmB+D7PN0xy6y1s57CTRWK15XTXorDJHMaj4jd5eDp1aN2GFr2sUfOX\nmBTA/Rm8dski6xtsaPY7+zSVmrFbRmTH6bmRzTG4h5n4Et2jcDYZt1PRmN0F/adG\n5hdnwQGebiMQALyE9pdXKu9jYdwxq9uhuuAewNtbeomNvDEHLNERw12ZqWsBrNLY\noevBiU/6L/tFRfhaPDBkb3yciqDVJih5p05C+K3vNjGThEi0R56WsYjmUm6+6WLV\nwbvDyJV12h9r4RYUy1cWU+1RGzEmSLT6oHeelEpH5K2Rk/9I5BIL+3B0ERj3iv3R\npBSgXQCYpjxt0SavGxE7akxZS0hl19hSkuKKGDmt9moQQagVZJAB7gMFe6t0+D7+\nF+6OABgbpIT9Egh3QmPo4DA1BORuvSFRrbi6Lsoe8LJTtCASMSkbnF6ifGAP1mwF\noB/CR7aNeeJvFEs8VdUwsdNCnbY8p9V8syQ3pKbM0QvtziTbuZWNpCqQAgWtBVfP\nqXTw8C8taWYQy0ZuwBcYgZN2UL8uSPsw76ghkwq6JBsjrgj3vy1StbwNPMDRPe+A\n3ySiZ3v2B11of897G4+pMC6Lo9z3LY3fZI0bk6j/SZNbYKJbB2uhji6S46cDXw9w\nRhDzipLUUXLS7QpkJnQ3qimA+tLCJyrDLfyb47r3akyHnyruqBe34fJ7h/4fMszu\nKU1YOcDbyki/1WJub9lgaLoYVm9bs8ahxPpozuijQW5af9qWeRiLSrXjMryDJjTU\nt0QWU4lcugzGOYS6Mam2YcNe3P2V3hHZYEf7g1uagHN2oWYgpP8nG7QquQINBFvF\nw/oBEADgzYDfg0L6g0MknECMcVD0Vf8M0W2uEkqUunPd94RRaOBa+AYYBxmTf/w4\ncdyfcKb3UC+5QzY/BHt5LrFewwSKNOoyTrdCnO4buiffzS5gxPpcgLCad7VeeV5T\nss8NXVcggBWHnilmCfBahPM97V1OemNEdN33VNeghQ8JN4cUQj4/9E7ydzJnUX8D\nIF+E90fVMt4k+YSBBL1tQbkXH9Wg2PicfoHXlPu6NoqyMJm7M+2emM8UMGQNvoPC\n9OyNqRuIzk4e7rT6gvTpm0ycLfeR5mpqxIAyCTDvXc9muqX0WMlyoqANTfNFDUy8\nh/0Y7bwnSmwyjzCrAIB8W5zs2bBs10S9giQzF+2T4XbLp3k1g8vugwMVNfO6jJKT\npj4eVZVSw75hTx85DC5veC0Q0pLscQ/ZsP35EiXSgCMFO8P/vKQVozZYenc3TNTE\nqBSe6vhlXs0QH7I5YEyZu8r0kl6ry7AY8xNiMgf4aYB/trM4XZt7tuVGb/K6t3Vy\nyTpGthPZ8TbFL1BRktCzRsT6kGI46QB3vv2tDSpyVxuzLylKKlSQ3B+QKx9jZ6Ev\nuScxH3OKLDyGrSoa5CnEQ3kBl107F+4n9P7ixRlMt6RGqOoivmlSUT8ZxkH/ib9i\nt/Aj26HSAhrHdS2A6RiTdjYn1G2BCAnnAlDTAvhKuwh0Ga05NwARAQABiQI8BBgB\nCgAmAhsMFiEEZLE/cRfW4H1mG7zg/nY6ZPXlT9YFAl2l8w0FCQeDyZMACgkQ/nY6\nZPXlT9aXvQ/+NpjKTZO2x+vRWAjtjg38kSY9lCkzHYrpiGg36BY4QqVT7aZCkrvZ\nASwKNACdH2jMeNesHbYvYMLFQat6x8MBp6geGm+E3JqC/Ow8HXl7jIJQFa6a5lCj\ntqpVG3gGx552iRp4u4N7NZdO1nuCj6/xYKgiKANbxf5I734TdXQWbTNPt4T1BWNx\njyHDkneuEWkpmWLbGtUUM+Mk668e9Uf7KIyUtf9DkWIHc7huTxHN491f09wiD1pc\nHskihANuWLV4sokghbaNXTPfvk1zNG+aU2n8h0W8PHFN1kn55PGngmTT0E8VlV7t\nzv9GlZRe3TmHpOw0Ujg6BAtQPx6RbzPh+cRU8vk9o/BgXjW3YsjM3sPJM3AxXFbQ\nc+Ad6s/IxGrhpFVDIemZdnjiT9bWq2P3oe7eiitc3p7xp7X6AM91Ei9/ihgjGvAI\nFvo7nDoo7g7Tvh2jNow0RF2/9JPg0fubTn3ZHtDVOy7h/Qnq4uab/0+f+rXIvvQW\neFOx4EL5W1K5oTVh0pAThw139cHEipTaE63bqTe3hXujZ6M+4K0CpuYSCfLPYGTI\npLNWkPbQkrIlOO/9cYJRJlO1vhV11Ej+GRrdd+DA9yMFG4sf6witjT+AvasjaJgo\nnUyWyRksKl6DGnMMx7Gu5LfqwHykcp90j/sRszg9x52ilxZNx1TG//U=\n=fJBy\n-----END PGP PUBLIC KEY BLOCK-----\n"
            )
        );
    }
}
