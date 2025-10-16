use crate::errors::*;
use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use std::env;

#[derive(Debug)]
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

        debug!("Connecting to database...");
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
}
