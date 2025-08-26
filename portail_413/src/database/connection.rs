use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

use crate::config::DatabaseConfig;
use crate::errors::{AppError, Result};

pub struct Database {
    pub pool: PgPool,
}

impl Database {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.connect_timeout))
            .idle_timeout(Duration::from_secs(config.idle_timeout))
            .connect(&config.url)
            .await
            .map_err(AppError::Database)?;

        // Test de la connexion
        sqlx::query("SELECT 1")
            .execute(&pool)
            .await
            .map_err(AppError::Database)?;

        tracing::info!("Database connection established successfully");

        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> Result<()> {
        // Migrations désactivées - la base de données est déjà initialisée
        // sqlx::migrate!("./migrations")
        //     .run(&self.pool)
        //     .await
        //     .map_err(|e| AppError::Internal(format!("Migration failed: {}", e)))?;

        tracing::info!("Database migrations skipped - database already initialized");
        Ok(())
    }

    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(AppError::Database)?;

        Ok(())
    }
}
