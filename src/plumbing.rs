use crate::{archlinux, args::Plumbing, db, debian, errors::*, fetch, pgp, srcinfo};
use tokio::fs;
use tokio::io::{self, BufReader};

pub async fn run(cmd: Plumbing) -> Result<()> {
    match cmd {
        Plumbing::ArchlinuxTar { path } => {
            let file = fs::File::open(&path)
                .await
                .with_context(|| format!("Failed to open file: {path:?}"))?;
            let parsed = archlinux::parse(file).await?;
            println!("parsed={parsed:#?}");
        }
        Plumbing::DebSrc { path } => {
            let file = fs::File::open(&path)
                .await
                .with_context(|| format!("Failed to open file: {path:?}"))?;

            let reader = fetch::Decompress::new(&path.to_string_lossy(), BufReader::new(file));
            let list = debian::parse_source_index(reader).await?;
            for pkg in list {
                println!("pkg={pkg:#?}");
            }
        }
        Plumbing::DebianTar { path } => {
            let file = fs::File::open(&path)
                .await
                .with_context(|| format!("Failed to open file: {path:?}"))?;
            let parsed = debian::parse_source_tar(file).await?;
            println!("parsed={parsed:#?}");
        }
        Plumbing::FetchCache { url } => {
            let db = db::Client::create().await?;
            let client = fetch::Client::new(db)?;
            let bytes = client
                .fetch(&url)
                .await
                .with_context(|| format!("Failed to fetch URL: {url}"))?;
            info!("Fetched {} bytes", bytes.len());
        }
        Plumbing::Fetch { url } => {
            let client = fetch::HttpClient::new()?;
            let stream = client
                .stream(&url)
                .await
                .with_context(|| format!("Failed to fetch URL: {url}"))?;
            let mut reader = tokio_util::io::StreamReader::new(stream);
            io::copy(&mut reader, &mut io::stdout()).await?;
        }
        Plumbing::FetchSigQueue => {
            let db = db::Client::create().await?;
            let http = fetch::Client::new(db.clone())?;
            for mut item in db.next_remote_sig_queue_items().await? {
                info!(
                    "Fetching sigs for artifact {:?} from {} (attempts={})",
                    item.artifact_chksums, item.url, item.attempts
                );
                item.fetch_and_store(&db, &http).await?;
            }
        }
        Plumbing::Migrate => {
            let _db = db::Client::create().await?;
            info!("All migrations have been applied");
        }
        Plumbing::PgpKeys { path } => {
            let buf = fs::read(&path)
                .await
                .with_context(|| format!("Failed to read file: {path:?}"))?;
            pgp::parse_keys(&buf)?;
        }
        Plumbing::PgpSigs { path } => {
            let buf = fs::read(&path)
                .await
                .with_context(|| format!("Failed to read file: {path:?}"))?;
            pgp::parse_sigs(&buf)?;
        }
        Plumbing::PingDb => {
            let db = db::Client::create_no_migrations().await?;
            let version = db.ping().await?;
            println!("Database connected: {version:?}");
        }
        Plumbing::Srcinfo { path } => {
            let buf = fs::read_to_string(&path)
                .await
                .with_context(|| format!("Failed to read file: {path:?}"))?;
            let pkg = srcinfo::parse(&buf)?;
            println!("pkg={pkg:#?}");
        }
    }

    Ok(())
}
