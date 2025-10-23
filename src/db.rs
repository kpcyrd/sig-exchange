use crate::{
    errors::{ApiResult as Result, *},
    issuer::Issuer,
    pgp::PgpSig,
    pkg::{Artifact, Pkg, Upstream},
};
use chrono::{DateTime, Utc};
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
        debug!("Inserting issuer: {issuer:?}");
        let _result = sqlx::query(
            "INSERT INTO issuers (fingerprint, family, key)
            VALUES ($1, $2, $3)
            ON CONFLICT (fingerprint) DO UPDATE SET
            key = COALESCE(EXCLUDED.key, issuers.key)
            ",
        )
        .bind(&issuer.fingerprint)
        .bind(&issuer.family)
        .bind(&issuer.key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_issuer(&self, fingerprint: &str) -> Result<Option<Issuer>> {
        let issuer = sqlx::query_as::<_, Issuer>("SELECT * FROM issuers WHERE fingerprint = $1")
            .bind(fingerprint)
            .fetch_optional(&self.pool)
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

    pub async fn list_sigs_for_issuer(&self, issuer: &str) -> Result<Vec<PgpSig>> {
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

    pub async fn insert_upstream(&self, upstream: &Upstream) -> Result<()> {
        info!("Inserting upstream: {upstream:?}");
        let _result = sqlx::query(
            "INSERT INTO upstreams (os, name, issuer, last_observed)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (os, name, issuer) DO UPDATE SET
            last_observed = GREATEST(upstreams.last_observed, EXCLUDED.last_observed)
            ",
        )
        .bind(&upstream.os)
        .bind(&upstream.name)
        .bind(&upstream.issuer)
        .bind(upstream.last_observed)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_upstreams_for_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<(Upstream, DateTime<Utc>)>> {
        #[derive(sqlx::FromRow)]
        struct UpstreamWithExtra {
            os: String,
            name: String,
            issuer: String,
            last_observed: DateTime<Utc>,
            latest_release: DateTime<Utc>,
        }

        let upstreams = sqlx::query_as::<_, UpstreamWithExtra>(
            "SELECT u.*, (
                SELECT MAX(release_datetime) FROM pkgs as p
                WHERE p.os = u.os AND p.name = u.name
            ) as latest_release FROM upstreams as u
            WHERE issuer = $1
            ORDER BY name ASC",
        )
        .bind(issuer)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|upstream| {
            (
                Upstream {
                    os: upstream.os,
                    name: upstream.name,
                    issuer: upstream.issuer,
                    last_observed: upstream.last_observed,
                },
                upstream.latest_release,
            )
        })
        .collect();

        Ok(upstreams)
    }

    pub async fn list_upstreams_for_pkg(
        &self,
        os: &str,
        name: &str,
        latest: DateTime<Utc>,
    ) -> Result<Vec<(Upstream, u64)>> {
        #[derive(sqlx::FromRow)]
        struct UpstreamWithExtra {
            os: String,
            name: String,
            issuer: String,
            last_observed: DateTime<Utc>,
            pkgs: i64,
        }

        let upstreams = sqlx::query_as::<_, UpstreamWithExtra>(
            "SELECT u.*, (
                SELECT COUNT(*) FROM upstreams as u2
                WHERE u2.issuer = u.issuer AND u2.last_observed = (
                    SELECT MAX(release_datetime) FROM pkgs as p
                    WHERE p.os = u2.os AND p.name = u2.name
                )
            ) as pkgs FROM upstreams as u
            WHERE os = $1 AND name = $2 AND last_observed = $3
            ORDER BY u.issuer ASC",
        )
        .bind(os)
        .bind(name)
        .bind(latest)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|upstream| {
            (
                Upstream {
                    os: upstream.os,
                    name: upstream.name,
                    issuer: upstream.issuer,
                    last_observed: upstream.last_observed,
                },
                upstream.pkgs as u64,
            )
        })
        .collect();

        Ok(upstreams)
    }

    pub async fn insert_pkg(&self, pkg: &Pkg) -> Result<()> {
        info!("Inserting pkg: {pkg:?}");
        let _result = sqlx::query(
            "INSERT INTO pkgs (os, name, version, release_datetime)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (os, name, version) DO UPDATE SET
            release_datetime = GREATEST(pkgs.release_datetime, EXCLUDED.release_datetime)
            ",
        )
        .bind(&pkg.os)
        .bind(&pkg.name)
        .bind(&pkg.version)
        .bind(pkg.release_datetime)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_pkgs(&self, os: &str, name: &str) -> Result<Vec<Pkg>> {
        let pkgs = sqlx::query_as::<_, Pkg>(
            "SELECT * FROM pkgs
            WHERE os = $1 AND name = $2
            ORDER BY name ASC, release_datetime DESC",
        )
        .bind(os)
        .bind(name)
        .fetch_all(&self.pool)
        .await?;
        Ok(pkgs)
    }

    pub async fn list_os_pkgs(&self, os: &str) -> Result<Vec<String>> {
        let pkgs = sqlx::query_as::<_, (String,)>(
            "SELECT DISTINCT name FROM pkgs
            WHERE os = $1
            ORDER BY name ASC",
        )
        .bind(os)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|(name,)| name)
        .collect();

        Ok(pkgs)
    }

    pub async fn search_pkgs_by_name(&self, name: &str) -> Result<Vec<(String, String)>> {
        let pkgs = sqlx::query_as::<_, (String, String)>(
            "SELECT DISTINCT os, name FROM pkgs
            WHERE name = $1
            ORDER BY os ASC, name ASC",
        )
        .bind(name)
        .fetch_all(&self.pool)
        .await?;
        Ok(pkgs)
    }

    pub async fn get_cache_by_url(&self, url: &str) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query_as(
            "SELECT content FROM cache
                WHERE url = $1
                ",
        )
        .bind(url)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((content,)) = row {
            Ok(Some(content))
        } else {
            Ok(None)
        }
    }

    pub async fn get_cache_by_filename(&self, filename: &str) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query_as(
            "SELECT content FROM cache
                WHERE filename = $1
                ORDER BY url ASC
                LIMIT 1",
        )
        .bind(filename)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((content,)) = row {
            Ok(Some(content))
        } else {
            Ok(None)
        }
    }

    pub async fn put_cache(&self, url: &str, filename: Option<&str>, content: &[u8]) -> Result<()> {
        let _result = sqlx::query(
            "INSERT INTO cache (url, filename, content)
            VALUES ($1, $2, $3)
            ON CONFLICT (url) DO UPDATE SET
            filename = EXCLUDED.filename,
            content = EXCLUDED.content
            ",
        )
        .bind(url)
        .bind(filename)
        .bind(content)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_artifact(&self, artifact: &Artifact) -> Result<()> {
        info!("Inserting artifact: {artifact:?}");
        let _result = sqlx::query(
            "INSERT INTO artifacts (chksum, url, os, pkg, version)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (chksum, url, os, pkg, version) DO NOTHING
            ",
        )
        .bind(&artifact.chksum)
        .bind(&artifact.url)
        .bind(&artifact.os)
        .bind(&artifact.pkg)
        .bind(&artifact.version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn count_by_artifact_chksum(&self, chksum: &str) -> Result<u64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM artifacts
            WHERE chksum = $1",
        )
        .bind(chksum)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 as u64)
    }
}
