use crate::{
    errors::{ApiResult as Result, *},
    issuer::Issuer,
    pgp::PgpSig,
};
use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use std::env;

#[derive(Debug, Clone)]
pub struct Client {
    pool: Pool<Postgres>,
}

impl Client {
    pub async fn create() -> Result<Self> {
        let client = Self::create_no_migrations().await?;

        sqlx::migrate!("./migrations").run(&client.pool).await?;
        debug!("Database has been setup");

        Ok(client)
    }

    pub async fn create_no_migrations() -> Result<Self> {
        let database_url = env::var("DATABASE_URL").unwrap();

        info!("Connecting to database...");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await?;

        Ok(Client { pool })
    }

    pub async fn ping(&self) -> Result<String> {
        let row: (String,) = sqlx::query_as("SELECT version()")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    pub async fn insert_issuer(&self, issuer: &Issuer) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO issuers (fingerprint, family)
            VALUES ($1, $2)
            ON CONFLICT (fingerprint) DO NOTHING
            ",
        )
        .bind(&issuer.fingerprint)
        .bind(&issuer.family)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_issuer(&self, fingerprint: &str) -> Result<Issuer> {
        let issuer = sqlx::query_as::<_, Issuer>("SELECT * FROM issuers WHERE fingerprint = $1")
            .bind(fingerprint)
            .fetch_one(&self.pool)
            .await?;
        Ok(issuer)
    }

    pub async fn insert_sig(&self, sig: &PgpSig) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO sigs (chksum, family, issuer, sig_type, sig_version, hash_algo, sig_algo, creation_time, digest_prefix, bytes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (chksum) DO NOTHING
            ",
        )
        .bind(&sig.chksum)
        .bind(&sig.family)
        .bind(&sig.issuer)
        .bind(sig.sig_type)
        .bind(sig.sig_version)
        .bind(&sig.hash_algo)
        .bind(&sig.sig_algo)
        .bind(sig.creation_time)
        .bind(&sig.digest_prefix)
        .bind(&sig.bytes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_sig(&self, chksum: &str) -> Result<PgpSig> {
        let sig = sqlx::query_as::<_, PgpSig>(
            "SELECT * FROM sigs
            WHERE chksum = $1",
        )
        .bind(chksum)
        .fetch_one(&self.pool)
        .await?;
        Ok(sig)
    }

    pub async fn get_sigs_for_issuer(&self, issuer: &str) -> Result<Vec<PgpSig>> {
        let sigs = sqlx::query_as::<_, PgpSig>(
            "SELECT * FROM sigs
            WHERE issuer = $1
            ORDER BY creation_time DESC, chksum ASC",
        )
        .bind(issuer)
        .fetch_all(&self.pool)
        .await?;
        Ok(sigs)
    }
}
