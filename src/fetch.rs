use crate::db;
use crate::errors::*;
use async_compression::tokio::bufread::{BzDecoder, GzipDecoder, XzDecoder};
use bytes::Bytes;
use std::env;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{self, AsyncBufRead, AsyncRead};
use tokio_stream::{Stream, StreamExt};

fn filename_from_url(url: &reqwest::Url) -> Result<String> {
    let segments = url
        .path_segments()
        .with_context(|| format!("Failed to extract path segments from URL: {:?}", url))?;
    let filename = segments
        .filter(|s| !s.is_empty())
        .next_back()
        .with_context(|| {
            format!(
                "Failed to extract filename from URL path segments: {:?}",
                url
            )
        })?;
    Ok(filename.to_string())
}

pub enum Decompress<R> {
    Bz2(BzDecoder<R>),
    Xz(XzDecoder<R>),
    Gz(GzipDecoder<R>),
    Plain(R),
}

impl<R> Decompress<R> {
    pub fn new(url: &str, reader: R) -> Self
    where
        R: AsyncBufRead + Unpin,
    {
        match url.split('.').next_back() {
            Some("bz2" | "bzip2") => Decompress::Bz2(BzDecoder::new(reader)),
            Some("xz") => Decompress::Xz(XzDecoder::new(reader)),
            Some("gz") => Decompress::Gz(GzipDecoder::new(reader)),
            _ => Decompress::Plain(reader),
        }
    }
}

impl<R: AsyncBufRead + Unpin> AsyncRead for Decompress<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Decompress::Bz2(decoder) => Pin::new(decoder).poll_read(cx, buf),
            Decompress::Xz(decoder) => Pin::new(decoder).poll_read(cx, buf),
            Decompress::Gz(decoder) => Pin::new(decoder).poll_read(cx, buf),
            Decompress::Plain(reader) => Pin::new(reader).poll_read(cx, buf),
        }
    }
}

pub struct Client {
    client: reqwest::Client,
    db: db::Client,
}

impl Client {
    pub fn new(db: db::Client) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(80));

        if let Ok(proxy) = env::var("PROXY") {
            // PROXY=socks5h://127.0.0.1:1080
            builder = builder.proxy(reqwest::Proxy::all(&proxy)?);
        }

        let client = builder.build()?;

        Ok(Self { client, db })
    }

    pub async fn fetch(&self, url: &str) -> Result<Vec<u8>> {
        if let Some(cached) = self.db.get_cache_by_url(url).await? {
            return Ok(cached);
        }

        let (filename, bytes) = self.fetch_no_cache(url).await?;

        debug!("Caching fetched URL: {:?}", url);
        self.db.put_cache(url, filename.as_deref(), &bytes).await?;

        Ok(bytes.to_vec())
    }

    pub async fn fetch_no_cache(&self, url: &str) -> Result<(Option<String>, Vec<u8>)> {
        info!("Fetching URL: {:?}", url);
        let url = url
            .parse::<reqwest::Url>()
            .with_context(|| "Failed to parse URL: {url:?}")?;
        let filename = filename_from_url(&url).ok();

        let resp = self.client.get(url).send().await?.error_for_status()?;
        let bytes = resp.bytes().await?.to_vec();

        Ok((filename, bytes.to_vec()))
    }

    pub async fn stream(
        &self,
        url: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = io::Result<Bytes>>>>> {
        info!("Streaming URL: {:?}", url);
        let resp = self.client.get(url).send().await?.error_for_status()?;
        let stream = resp.bytes_stream().map(|b| b.map_err(io::Error::other));
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filename_from_url() {
        let url = "https://example.com/path/to/file.txt";
        let filename = filename_from_url(&url.parse().unwrap()).unwrap();
        assert_eq!(filename, "file.txt");

        let url = "https://example.com/path/to/";
        let result = filename_from_url(&url.parse().unwrap()).unwrap();
        assert_eq!(result, "to".to_string());

        let url = "https://example.com/";
        let result = filename_from_url(&url.parse().unwrap());
        assert!(result.is_err());

        let url = "https://gitlab.archlinux.org/archlinux/packaging/packages/curl-rustls/-/archive/main/curl-rustls-main.tar.bz2?ref_type=heads";
        let filename = filename_from_url(&url.parse().unwrap()).unwrap();
        assert_eq!(filename, "curl-rustls-main.tar.bz2");
    }
}
