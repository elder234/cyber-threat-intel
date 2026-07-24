//! Durable job queue client. Wraps the `aegis.dequeue_jobs / complete_job /
//! fail_job / enqueue_job` stored procedures so workers get atomic,
//! SKIP-LOCKED claims without hand-writing SQL everywhere.

use crate::db::Pool;
use serde_json::Value;
use uuid::Uuid;

/// A claimed unit of work.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Job {
    pub id: i64,
    pub queue: String,
    pub kind: String,
    pub payload: Value,
    pub attempts: i32,
    pub max_attempts: i32,
}

#[derive(Clone)]
pub struct JobQueue {
    pool: Pool,
    /// Stable worker identity for observability + claim ownership.
    worker_id: String,
}

impl JobQueue {
    pub fn new(pool: Pool) -> Self {
        let worker_id = format!(
            "{}-{}",
            hostname(),
            Uuid::new_v4().simple().to_string().get(0..8).unwrap_or("00000000")
        );
        Self { pool, worker_id }
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// Atomically claim up to `limit` pending jobs from `queue`.
    pub async fn claim(&self, queue: &str, limit: i32) -> anyhow::Result<Vec<Job>> {
        let jobs = sqlx::query_as::<_, Job>(
            "SELECT id, queue, kind, payload, attempts, max_attempts
               FROM aegis.dequeue_jobs($1, $2, $3)",
        )
        .bind(queue)
        .bind(&self.worker_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(jobs)
    }

    /// Mark a job succeeded.
    pub async fn complete(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("SELECT aegis.complete_job($1)")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Mark a job failed; the SP handles retry/backoff or moves it to `dead`.
    pub async fn fail(&self, id: i64, err: &str) -> anyhow::Result<()> {
        sqlx::query("SELECT aegis.fail_job($1, $2)")
            .bind(id)
            .bind(err)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Enqueue a new job (used by collectors to spawn follow-up work).
    pub async fn enqueue(
        &self,
        kind: &str,
        payload: Value,
        queue: &str,
        priority: i32,
    ) -> anyhow::Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "SELECT aegis.enqueue_job($1, $2, $3, $4)",
        )
        .bind(kind)
        .bind(payload)
        .bind(queue)
        .bind(priority)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "worker".to_string())
}
