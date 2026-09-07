use crate::{errors::*, sig::RemoteSig};
use alpm_srcinfo::source_info::v1::SourceInfoV1;
use alpm_types::{Digest, OpenPGPIdentifier, SkippableChecksum, Source as AlpmSource};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    pub signing_keys: Vec<OpenPGPIdentifier>,
    pub sigs: Vec<RemoteSig>,
}

fn filename(src: &AlpmSource) -> Result<String> {
    match src {
        AlpmSource::SourceUrl {
            filename,
            source_url,
        } => {
            if let Some(filename) = filename {
                let filename = filename.to_str().context("Filename is invalid utf8")?;
                Ok(filename.to_string())
            } else {
                let url = source_url.url.inner();
                let filename = url
                    .path_segments()
                    .and_then(|mut segments| segments.next_back())
                    .filter(|s| !s.is_empty())
                    .with_context(|| anyhow!("Failed to extract filename from URL: {url}"))?;
                Ok(filename.to_string())
            }
        }
        AlpmSource::File { filename, location } => {
            if let Some(filename) = filename {
                let filename = filename.to_str().context("Filename is invalid utf8")?;
                Ok(filename.to_string())
            } else {
                let filename = location
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("Failed to get filename from path")?;
                Ok(filename.to_string())
            }
        }
    }
}

fn is_signature(filename: &str) -> Option<&str> {
    for suffix in &[".sig", ".sign", ".asc"] {
        if let Some(filename) = filename.strip_suffix(suffix) {
            return Some(filename);
        }
    }
    None
}

fn location(src: &AlpmSource) -> Option<&str> {
    match src {
        AlpmSource::SourceUrl { source_url, .. } => Some(source_url.url.as_str()),
        AlpmSource::File { location, .. } => location.to_str(),
    }
}

fn checksum(
    hashes: &mut BTreeMap<&'static str, String>,
    name: &'static str,
    chksum: Option<&SkippableChecksum<impl Digest + Clone>>,
) {
    if let Some(SkippableChecksum::Checksum { digest }) = chksum {
        hashes.insert(name, digest.to_string());
    }
}

pub fn parse(srcinfo: &str) -> Result<Pkg> {
    let srcinfo = SourceInfoV1::from_string(srcinfo).context("Failed to parse srcinfo")?;
    let pkgbase = srcinfo.base;

    let mut pkg = Pkg {
        name: pkgbase.name.to_string(),
        version: pkgbase.version.to_string(),
        signing_keys: pkgbase.pgp_fingerprints,
        sigs: Vec::new(),
    };

    let mut map = BTreeMap::new();
    for (idx, src) in pkgbase.sources.into_iter().enumerate() {
        debug!("Parsed source #{idx}: {src:?}");
        let Ok(filename) = filename(&src) else {
            continue;
        };
        debug!("Parsed filename for source #{idx}: {:?}", filename);
        map.insert(filename, (idx, src));
    }

    for (sig_filename, (_, sig_src)) in &map {
        let Some(filename) = is_signature(sig_filename) else {
            continue;
        };

        info!("Looking up hash data for {sig_filename:?} -> {filename:?}");
        let Some(&(idx, ref artifact_src)) = map.get(filename) else {
            continue;
        };

        let mut hashes = BTreeMap::new();
        checksum(&mut hashes, "blake2b", pkgbase.b2_checksums.get(idx));
        checksum(&mut hashes, "sha224", pkgbase.sha224_checksums.get(idx));
        checksum(&mut hashes, "sha256", pkgbase.sha256_checksums.get(idx));
        checksum(&mut hashes, "sha384", pkgbase.sha384_checksums.get(idx));
        checksum(&mut hashes, "sha512", pkgbase.sha512_checksums.get(idx));

        pkg.sigs.push(RemoteSig {
            sig_url: location(sig_src)
                .with_context(|| anyhow!("Failed to get location for source #{idx}"))?
                .to_string(),
            family: "pgp".to_string(),
            artifact_url: location(artifact_src)
                .with_context(|| anyhow!("Failed to get location for source #{idx}"))?
                .to_string(),
            artifact_hashes: hashes,
        });
    }

    Ok(pkg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_srcinfo() {
        let srcinfo = include_str!("../test_data/rebuilderd-SRCINFO");
        let pkg = parse(srcinfo).unwrap();
        assert_eq!(
            pkg,
            Pkg {
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
                    ]
                        .into_iter()
                        .collect(),
                }],
            }
        );
    }
}
