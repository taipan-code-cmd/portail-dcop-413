use actix_web::{
    web::{Data, Path, Query},
    HttpResponse,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::errors::{AppError, Result};
use crate::middleware::AuthenticatedUser;
use crate::models::{AuditSearchQuery, UserRole};
use crate::services::{AuditService, StatisticsService};

#[derive(Debug, Deserialize)]
pub struct StatisticsQuery {
    pub date: Option<DateTime<Utc>>,
    pub period: Option<String>, // "hourly", "daily", "weekly"
}

pub struct AdminHandler;

impl AdminHandler {
    pub async fn get_dashboard_stats(
        stats_service: Data<StatisticsService>,
        authenticated_user: AuthenticatedUser,
    ) -> Result<HttpResponse> {
        // Vérifier les permissions admin
        match authenticated_user.user.role {
            UserRole::Admin | UserRole::Director => {},
            _ => return Err(AppError::Authorization("Admin access required".to_string())),
        }

        let stats = stats_service.get_dashboard_stats().await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": stats
        })))
    }

    pub async fn get_hourly_stats(
        stats_service: Data<StatisticsService>,
        authenticated_user: AuthenticatedUser,
        query: Query<StatisticsQuery>,
    ) -> Result<HttpResponse> {
        // Vérifier les permissions admin
        match authenticated_user.user.role {
            UserRole::Admin | UserRole::Director => {},
            _ => return Err(AppError::Authorization("Admin access required".to_string())),
        }

        let query_data = query.into_inner();
        let date = query_data.date.unwrap_or_else(Utc::now);
        let stats = stats_service.get_hourly_stats(date).await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": stats
        })))
    }

    pub async fn get_weekly_stats(
        stats_service: Data<StatisticsService>,
        authenticated_user: AuthenticatedUser,
    ) -> Result<HttpResponse> {
        // Vérifier les permissions admin
        match authenticated_user.user.role {
            UserRole::Admin | UserRole::Director => {},
            _ => return Err(AppError::Authorization("Admin access required".to_string())),
        }

        let stats = stats_service.get_weekly_stats().await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": stats
        })))
    }

    pub async fn get_audit_logs(
        audit_service: Data<AuditService>,
        authenticated_user: AuthenticatedUser,
        query: Query<AuditSearchQuery>,
    ) -> Result<HttpResponse> {
        // Vérifier les permissions admin
        match authenticated_user.user.role {
            UserRole::Admin | UserRole::Director => {},
            _ => return Err(AppError::Authorization("Admin access required".to_string())),
        }

        let logs = audit_service.search_audit_logs(query.into_inner()).await?;
        let total = logs.len() as u32;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": {
                "logs": logs,
                "total": total,
                "page": 1,
                "limit": total,
                "total_pages": 1
            }
        })))
    }

    pub async fn get_audit_log(
        audit_service: Data<AuditService>,
        authenticated_user: AuthenticatedUser,
        audit_id: Path<Uuid>,
    ) -> Result<HttpResponse> {
        // Vérifier les permissions admin
        match authenticated_user.user.role {
            UserRole::Admin | UserRole::Director => {},
            _ => return Err(AppError::Authorization("Admin access required".to_string())),
        }

        let log = audit_service.get_audit_log(*audit_id).await?;

        match log {
            Some(log) => Ok(HttpResponse::Ok().json(json!({
                "success": true,
                "data": log
            }))),
            None => Err(AppError::NotFound("Audit log not found".to_string())),
        }
    }

    pub async fn get_system_health(
        authenticated_user: AuthenticatedUser,
    ) -> Result<HttpResponse> {
        // Vérifier les permissions admin
        match authenticated_user.user.role {
            UserRole::Admin | UserRole::Director => {},
            _ => return Err(AppError::Authorization("Admin access required".to_string())),
        }

        // Informations de santé du système
        let health_info = json!({
            "status": "healthy",
            "timestamp": Utc::now(),
            "version": env!("CARGO_PKG_VERSION"),
            "uptime": "N/A", // À implémenter avec un compteur global
            "database": "connected",
            "memory_usage": "N/A", // À implémenter avec des métriques système
            "active_connections": "N/A"
        });

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": health_info
        })))
    }

    pub async fn export_data(
        audit_service: Data<AuditService>,
        authenticated_user: AuthenticatedUser,
        query: Query<AuditSearchQuery>,
    ) -> Result<HttpResponse> {
        // Vérifier les permissions directeur uniquement
        match authenticated_user.user.role {
            UserRole::Director => {},
            _ => return Err(AppError::Authorization("Director access required for data export".to_string())),
        }

        // Récupérer les données d'audit pour export
        let logs = audit_service.search_audit_logs(query.into_inner()).await?;

        // En production, ceci devrait générer un fichier CSV/PDF
        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "message": "Export initiated",
            "data": {
                "export_id": Uuid::new_v4(),
                "status": "processing",
                "record_count": logs.len(),
                "estimated_completion": Utc::now() + chrono::Duration::minutes(5)
            }
        })))
    }
}
