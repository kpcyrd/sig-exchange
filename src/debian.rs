use crate::errors::*;
use crate::sig::RemoteSig;
use async_compression::tokio::bufread::XzDecoder;
use chrono::{DateTime, Utc};
use debian_changelog::ChangeLog;
use std::io::Read;
use std::{cmp, collections::BTreeMap};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio_stream::StreamExt;

#[derive(Debug, PartialEq, Eq)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    pub sigs: Vec<RemoteSig>,
}

pub async fn parse_source_index<R: AsyncRead + Unpin>(reader: R) -> Result<Vec<Pkg>> {
    let reader = BufReader::new(reader);
    let mut reader = XzDecoder::new(reader);

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await?;

    parse_decompressed_reader_source_index(&buf[..])
}

fn is_signature(filename: &str) -> Option<&str> {
    filename.strip_suffix(".asc")
}

pub fn parse_decompressed_reader_source_index<R: Read>(reader: R) -> Result<Vec<Pkg>> {
    let deb822 = deb822_fast::Deb822::from_reader(reader)
        .map_err(|err| anyhow!("Failed to parse deb822: {err:#}"))?;

    let mut pkgs = Vec::new();
    for paragraph in deb822.iter() {
        trace!("Paragraph: {paragraph:#?}");

        let name = paragraph
            .get("Package")
            .ok_or_else(|| anyhow!("No 'Package' field in paragraph"))?;

        let version = paragraph
            .get("Version")
            .ok_or_else(|| anyhow!("No 'Version' field in paragraph"))?;

        let checksums_sha256 = paragraph
            .get("Checksums-Sha256")
            .ok_or_else(|| anyhow!("No 'Checksums-Sha256' field in paragraph"))?;

        let directory = paragraph
            .get("Directory")
            .ok_or_else(|| anyhow!("No 'Directory' field in paragraph"))?;

        let mut map = BTreeMap::new();
        for line in checksums_sha256.lines() {
            let mut chunks = line.split(' ');
            let Some(sha256) = chunks.next() else {
                continue;
            };
            let Some(_size) = chunks.next() else { continue };
            let Some(filename) = chunks.next() else {
                continue;
            };
            if let Some(trailing) = chunks.next() {
                bail!("Unexpected trailing data in Checksums-Sha256: {trailing:?}");
            }

            map.insert(filename.to_string(), sha256.to_string());
        }

        let mut pkg = Pkg {
            name: name.to_string(),
            version: version.to_string(),
            sigs: Vec::new(),
        };

        // check if there's any signatures
        if map.keys().any(|f| is_signature(f).is_some()) {
            info!("Found package with signatures: name={name:?} version={version:?}");
        }

        for sig_filename in map.keys() {
            let Some(filename) = is_signature(sig_filename) else {
                continue;
            };

            info!("Looking up hash data for {sig_filename:?} -> {filename:?}");
            let Some(sha256) = map.get(filename) else {
                continue;
            };

            pkg.sigs.push(RemoteSig {
                location: format!("https://deb.debian.org/debian/{directory}/{sig_filename}"),
                for_hash: [("sha256", sha256.to_string())].into_iter().collect(),
            });
        }

        if !pkg.sigs.is_empty() {
            pkgs.push(pkg);
        }
    }

    Ok(pkgs)
}

pub async fn parse_source_tar<R: AsyncRead + Unpin>(
    reader: R,
) -> Result<(DateTime<Utc>, Option<String>)> {
    let reader = BufReader::new(reader);
    let reader = XzDecoder::new(reader);

    let mut tar = tokio_tar::Archive::new(reader);
    let mut entries = tar.entries()?;

    let mut release_time = None;
    let mut signing_keys = String::new();
    while let Some(entry) = entries.next().await {
        let mut entry = entry?;
        let path = entry.path()?;

        match path.to_str() {
            Some("debian/changelog") => {
                info!("Found file in debian tar: {path:?}");

                let mut buf = Vec::new();
                entry.read_to_end(&mut buf).await?;

                let changelog = ChangeLog::read(&buf[..])?;
                for entry in changelog.iter() {
                    let Some(datetime) = entry.datetime() else {
                        continue;
                    };
                    let datetime = datetime.with_timezone(&Utc);
                    release_time = cmp::max(release_time, Some(datetime));
                }
            }
            Some("debian/upstream/signing-key.asc") => {
                info!("Found file in debian tar: {path:?}");
                entry.read_to_string(&mut signing_keys).await?;
                if !signing_keys.ends_with('\n') {
                    signing_keys.push('\n');
                }
            }
            _ => {
                debug!("Found file in debian tar: {path:?}");
            }
        }
    }

    let release_time = release_time.context("Failed to determine release datetime")?;

    let signing_keys = Some(signing_keys);
    let signing_keys = signing_keys.filter(|s| !s.is_empty());

    Ok((release_time, signing_keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_debsrc() {
        let data = r#"Package: 2ping
Binary: 2ping
Version: 4.5-1.2
Maintainer: Ryan Finnie <ryan@finnie.org>
Build-Depends: debhelper, debhelper-compat (= 13), dpkg-dev (>= 1.16.1~), python3-pytest, python3-setuptools, python3-all, dh-python, bash-completion
Architecture: all
Standards-Version: 4.5.0
Format: 3.0 (quilt)
Files:
 ae82f5d73aca504b36e750efb6b0f2d0 2280 2ping_4.5-1.2.dsc
 80889d373d3ef6a50221cc62ca09fa7d 77771 2ping_4.5.orig.tar.gz
 27a98b9e4e6a18cb3526f7dec5e69671 833 2ping_4.5.orig.tar.gz.asc
 f31e9ed60784e6471515cc36ee808f80 6712 2ping_4.5-1.2.debian.tar.xz
Vcs-Browser: https://salsa.debian.org/rfinnie/2ping-pkg-debian
Vcs-Git: https://salsa.debian.org/rfinnie/2ping-pkg-debian.git
Checksums-Sha256:
 3ec60e903f5a11dca07fc0ead98e6a3460844cafa93fa0123f5b3ce6e880c541 2280 2ping_4.5-1.2.dsc
 867009928bf767d36279f90ff8f891855804c0004849f9554ac77fcd7f0fdb7b 77771 2ping_4.5.orig.tar.gz
 90c76b504b4ae472e8a69aa450349805d0fccc5735873070a79a87dc76eff79a 833 2ping_4.5.orig.tar.gz.asc
 5a47df75ede3413aa52e543c0ba24fbd507dd704f1814a3e38174961a166cf5f 6712 2ping_4.5-1.2.debian.tar.xz
Homepage: https://www.finnie.org/software/2ping/
Package-List: 
 2ping deb net optional arch=all
Testsuite: autopkgtest
Testsuite-Triggers: python3-distro, python3-dnspython, python3-netifaces, python3-pycryptodome, python3-systemd
Directory: pool/main/2/2ping
Priority: source
Section: net

"#;
        let list = parse_decompressed_reader_source_index(data.as_bytes()).unwrap();
        assert_eq!(
            list,
            vec![Pkg {
                name: "2ping".to_string(),
                version: "4.5-1.2".to_string(),
                sigs: vec![RemoteSig {
                    location:
                        "https://deb.debian.org/debian/pool/main/2/2ping/2ping_4.5.orig.tar.gz.asc"
                            .to_string(),
                    for_hash: [(
                        "sha256",
                        "867009928bf767d36279f90ff8f891855804c0004849f9554ac77fcd7f0fdb7b"
                            .to_string()
                    )]
                    .into_iter()
                    .collect(),
                }]
            }]
        );
    }

    #[tokio::test]
    async fn test_parse_debian_tar() {
        let data = include_bytes!("../test_data/2ping_4.5-1.2.debian.tar.xz");
        let (release_time, signing_key) = parse_source_tar(&data[..]).await.unwrap();
        assert_eq!(
            release_time,
            DateTime::parse_from_rfc3339("2023-11-27T11:51:56Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert_eq!(signing_key.map(|s| s.len()), Some(3912));
    }
}
