//! Shared primitives for all Aegis Rust services: config, DB pool, telemetry,
//! the durable job model, and the job-queue helper functions that map to the
//! `aegis.*` stored procedures.

pub mod config;
pub mod db;
pub mod jobs;
pub mod telemetry;

pub use config::Config;
pub use db::{connect, Pool};
pub use jobs::{Job, JobQueue};

/// Common result alias.
pub type Result<T> = anyhow::Result<T>;
