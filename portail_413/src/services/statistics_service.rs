use chrono::{DateTime, Utc, Duration};
use serde_json::{json, Value};
use sqlx::PgPool;
use bigdecimal::ToPrimitive;

use crate::errors::{AppError, Result};

#[derive(Clone)]
pub struct StatisticsService {
    pool: PgPool,
}

impl StatisticsService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_dashboard_stats(&self) -> Result<Value> {
        let now = Utc::now();
        let today_start = now.date_naive().and_hms_opt(0, 0, 0)
            .ok_or_else(|| AppError::Internal("Failed to create start of day".to_string()))?
            .and_utc();
        let week_start = now - Duration::days(7);
        let month_start = now - Duration::days(30);

        // Statistiques des visiteurs
        let total_visitors = self.count_total_visitors().await?;
        let visitors_today = self.count_visitors_since(today_start).await?;
        let visitors_this_week = self.count_visitors_since(week_start).await?;
        let visitors_this_month = self.count_visitors_since(month_start).await?;

        // Statistiques des visites
        let total_visits = self.count_total_visits().await?;
        let visits_today = self.count_visits_since(today_start).await?;
        let visits_this_week = self.count_visits_since(week_start).await?;
        let visits_this_month = self.count_visits_since(month_start).await?;

        // Visites actives
        let active_visits = self.count_active_visits().await?;
        let pending_visits = self.count_pending_visits().await?;

        // Statistiques par statut
        let visit_stats_by_status = self.get_visit_stats_by_status().await?;

        // Top départements
        let top_departments = self.get_top_departments().await?;

        Ok(json!({
            "visitors": {
                "total": total_visitors,
                "today": visitors_today,
                "this_week": visitors_this_week,
                "this_month": visitors_this_month
            },
            "visits": {
                "total": total_visits,
                "today": visits_today,
                "this_week": visits_this_week,
                "this_month": visits_this_month,
                "active": active_visits,
                "pending": pending_visits
            },
            "visit_status": visit_stats_by_status,
            "top_departments": top_departments,
            "last_updated": now
        }))
    }

    pub async fn get_hourly_stats(&self, date: DateTime<Utc>) -> Result<Value> {
        let day_start = date.date_naive().and_hms_opt(0, 0, 0)
            .ok_or_else(|| AppError::Internal("Failed to create start of day".to_string()))?
            .and_utc();
        let day_end = day_start + Duration::days(1);

        let hourly_data = sqlx::query!(
            r#"
            SELECT 
                EXTRACT(HOUR FROM created_at) as hour,
                COUNT(*) as visit_count
            FROM visits 
            WHERE created_at >= $1 AND created_at < $2
            GROUP BY EXTRACT(HOUR FROM created_at)
            ORDER BY hour
            "#,
            day_start,
            day_end
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::Database)?;

        let mut hours = Vec::new();
        for i in 0..24 {
            let count = hourly_data
                .iter()
                .find(|row| {
                    if let Some(hour_bd) = &row.hour {
                        hour_bd.to_f64().map(|h| h as i32) == Some(i)
                    } else {
                        false
                    }
                })
                .map(|row| row.visit_count.unwrap_or(0))
                .unwrap_or(0);

            hours.push(json!({
                "hour": i,
                "visits": count
            }));
        }

        Ok(json!({
            "date": date.date_naive(),
            "hourly_data": hours
        }))
    }

    pub async fn get_weekly_stats(&self) -> Result<Value> {
        let now = Utc::now();
        let week_start = now - Duration::days(7);

        let daily_data = sqlx::query!(
            r#"
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as visit_count
            FROM visits 
            WHERE created_at >= $1
            GROUP BY DATE(created_at)
            ORDER BY date
            "#,
            week_start
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(json!({
            "period": "last_7_days",
            "daily_data": daily_data.into_iter().map(|row| json!({
                "date": row.date,
                "visits": row.visit_count
            })).collect::<Vec<_>>()
        }))
    }

    async fn count_total_visitors(&self) -> Result<i64> {
        let count = sqlx::query_scalar!("SELECT COUNT(*) FROM visitors")
            .fetch_one(&self.pool)
            .await
            .map_err(AppError::Database)?;
        Ok(count.unwrap_or(0))
    }

    async fn count_visitors_since(&self, since: DateTime<Utc>) -> Result<i64> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM visitors WHERE created_at >= $1",
            since
        )
        .fetch_one(&self.pool)
        .await
        .map_err(AppError::Database)?;
        Ok(count.unwrap_or(0))
    }

    async fn count_total_visits(&self) -> Result<i64> {
        let count = sqlx::query_scalar!("SELECT COUNT(*) FROM visits")
            .fetch_one(&self.pool)
            .await
            .map_err(AppError::Database)?;
        Ok(count.unwrap_or(0))
    }

    async fn count_visits_since(&self, since: DateTime<Utc>) -> Result<i64> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM visits WHERE created_at >= $1",
            since
        )
        .fetch_one(&self.pool)
        .await
        .map_err(AppError::Database)?;
        Ok(count.unwrap_or(0))
    }

    async fn count_active_visits(&self) -> Result<i64> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM visits WHERE status = 'inprogress'"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(AppError::Database)?;
        Ok(count.unwrap_or(0))
    }

    async fn count_pending_visits(&self) -> Result<i64> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM visits WHERE status = 'pending'"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(AppError::Database)?;
        Ok(count.unwrap_or(0))
    }

    async fn get_visit_stats_by_status(&self) -> Result<Value> {
        let stats = sqlx::query!(
            r#"
            SELECT 
                status::text as status,
                COUNT(*) as count
            FROM visits 
            GROUP BY status
            ORDER BY count DESC
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(json!(stats.into_iter().map(|row| json!({
            "status": row.status,
            "count": row.count
        })).collect::<Vec<_>>()))
    }

    async fn get_top_departments(&self) -> Result<Value> {
        let departments = sqlx::query!(
            r#"
            SELECT 
                department,
                COUNT(*) as visit_count
            FROM visits 
            GROUP BY department
            ORDER BY visit_count DESC
            LIMIT 10
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(json!(departments.into_iter().map(|row| json!({
            "department": row.department,
            "visits": row.visit_count
        })).collect::<Vec<_>>()))
    }
}
