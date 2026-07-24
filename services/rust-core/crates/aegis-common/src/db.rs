//! PostgreSQL connection pool (sqlx) with search_path set to the aegis schema.

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::ConnectOptions;
use std::str::FromStr;
use std::time::Duration;

pub type Pool = sqlx::PgPool;

/// Build a connection pool. `after_connect` pins the search_path so all queries
/// resolve against the `aegis` schema without qualifying every identifier.
pub async fn connect(database_url: &str, max_conns: u32) -> anyhow::Result<Pool> {
    let opts = PgConnectOptions::from_str(database_url)?
        .application_name("aegis-rust")
        .log_statements(tracing::log::LevelFilter::Debug);

    let pool = PgPoolOptions::new()
        .max_connections(max_conns)
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("SET search_path TO aegis, public")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with(opts)
        .await?;

    Ok(pool)
}
