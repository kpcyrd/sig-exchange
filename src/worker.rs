use crate::archlinux;
use crate::db;
use crate::debian;
use crate::errors::*;
use crate::fetch;
use tokio::time;

pub async fn run() -> Result<()> {
    let db = db::Client::create().await?;
    let http = fetch::Client::new(db.clone())?;

    let mut interval = time::interval(time::Duration::from_secs(3 * 60 * 60));

    loop {
        if let Err(err) = archlinux::import_tree(&db).await {
            error!("Arch Linux import failed: {err:#}");
        }

        if let Err(err) = debian::import_sources(&db).await {
            error!("Debian import failed: {err:#}");
        }

        loop {
            let batch = db.next_remote_sig_queue_items().await?;

            if batch.is_empty() {
                break;
            }

            for mut item in batch {
                info!(
                    "Fetching sigs for artifact {:?} from {} (attempts={})",
                    item.artifact_chksums, item.url, item.attempts
                );
                item.fetch_and_store(&db, &http).await?;
            }

            time::sleep(time::Duration::from_secs(10)).await;
        }

        interval.tick().await;
    }
}
