use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use chrono::{DateTime, Utc};

use crate::{
    AppState,
    middleware::AuthenticatedUser,
};

// ===== STRUCTURES POUR LES STATISTIQUES =====

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardStats {
    pub active_visits: i32,
    pub total_visitors: i32,
    pub today_visits: i32,
    pub pending_approvals: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VisitStatistics {
    pub total_visits: i64,
    pub completed_visits: i64,
    pub cancelled_visits: i64,
    pub average_duration_minutes: i32,
    pub visits_by_status: Vec<StatusCount>,
    pub visits_by_day: Vec<DayCount>,
    pub visits_by_hour: Vec<HourCount>,
    pub top_departments: Vec<DepartmentCount>,
    pub peak_hours: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VisitorStatistics {
    pub total_unique_visitors: i64,
    pub new_visitors_this_month: i64,
    pub returning_visitors: i64,
    pub average_visits_per_visitor: f64,
    pub top_companies: Vec<CompanyCount>,
    pub visitor_origin_countries: Vec<CountryCount>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityChartData {
    pub hourly_visits: Vec<ChartPoint>,
    pub daily_visits: Vec<ChartPoint>,
    pub weekly_visits: Vec<ChartPoint>,
    pub monthly_visits: Vec<ChartPoint>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportStatistics {
    pub total_exports_this_month: i32,
    pub total_data_exported_mb: f64,
    pub most_exported_format: String,
    pub last_export_date: Option<DateTime<Utc>>,
    pub exports_by_type: Vec<ExportTypeCount>,
}

// Types auxiliaires
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StatusCount {
    pub status: String,
    pub count: i64,
    pub percentage: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DayCount {
    pub day: String,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HourCount {
    pub hour: i32,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepartmentCount {
    pub department: String,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompanyCount {
    pub company: String,
    pub visitor_count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CountryCount {
    pub country: String,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChartPoint {
    pub label: String,
    pub value: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportTypeCount {
    pub export_type: String,
    pub count: i32,
}

// ===== HANDLERS STATISTIQUES =====

/// Récupère les statistiques générales du tableau de bord
pub async fn get_dashboard_stats(
    app_state: web::Data<AppState>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse> {
    info!("Getting dashboard statistics");

    match app_state.statistics_repository.get_dashboard_stats().await {
        Ok(stats) => {
            info!("Dashboard statistics retrieved successfully");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": stats
            })))
        }
        Err(e) => {
            error!("Failed to get dashboard statistics: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve dashboard statistics"
            })))
        }
    }
}

/// Récupère les statistiques des visites par période
pub async fn get_visit_statistics(
    app_state: web::Data<AppState>,
    query: web::Query<serde_json::Value>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse> {
    let period = query.get("period")
        .and_then(|p| p.as_str())
        .unwrap_or("week");

    info!("Getting visit statistics for period: {}", period);

    match app_state.statistics_repository.get_visit_statistics(period).await {
        Ok(stats) => {
            info!("Visit statistics retrieved successfully");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": stats
            })))
        }
        Err(e) => {
            error!("Failed to get visit statistics: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve visit statistics"
            })))
        }
    }
}

/// Récupère les statistiques des visiteurs
pub async fn get_visitor_statistics(
    app_state: web::Data<AppState>,
    _user: AuthenticatedUser,
    
) -> Result<HttpResponse> {
    info!("Getting visitor statistics");

    match app_state.statistics_repository.get_visitor_statistics().await {
        Ok(stats) => {
            info!("Visitor statistics retrieved successfully");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": stats
            })))
        }
        Err(e) => {
            error!("Failed to get visitor statistics: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve visitor statistics"
            })))
        }
    }
}

/// Récupère les données des graphiques d'activité
pub async fn get_activity_chart_data(
    app_state: web::Data<AppState>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse> {
    info!("Getting activity chart data");

    match app_state.statistics_repository.get_activity_chart_data().await {
        Ok(data) => {
            info!("Activity chart data retrieved successfully");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": data
            })))
        }
        Err(e) => {
            error!("Failed to get activity chart data: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve activity chart data"
            })))
        }
    }
}

/// Récupère les statistiques d'export
pub async fn get_export_statistics(
    app_state: web::Data<AppState>,
    _user: AuthenticatedUser,
    
) -> Result<HttpResponse> {
    info!("Getting export statistics");

    match app_state.statistics_repository.get_export_statistics().await {
        Ok(stats) => {
            info!("Export statistics retrieved successfully");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": stats
            })))
        }
        Err(e) => {
            error!("Failed to get export statistics: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve export statistics"
            })))
        }
    }
}

/// Récupère le nombre de visites actives
pub async fn get_active_visits_count(
    app_state: web::Data<AppState>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse> {
    info!("Getting active visits count");

    match app_state.statistics_repository.get_active_visits_count().await {
        Ok(count) => {
            info!("Active visits count: {}", count);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": count
            })))
        }
        Err(e) => {
            error!("Failed to get active visits count: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve active visits count"
            })))
        }
    }
}

/// Récupère le nombre de visites aujourd'hui
pub async fn get_today_visits_count(
    app_state: web::Data<AppState>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse> {
    info!("Getting today's visits count");

    match app_state.statistics_repository.get_today_visits_count().await {
        Ok(count) => {
            info!("Today's visits count: {}", count);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": count
            })))
        }
        Err(e) => {
            error!("Failed to get today's visits count: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve today's visits count"
            })))
        }
    }
}

/// Récupère le nombre de visites en attente d'approbation
pub async fn get_pending_approvals_count(
    app_state: web::Data<AppState>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse> {
    info!("Getting pending approvals count");

    match app_state.statistics_repository.get_pending_approvals_count().await {
        Ok(count) => {
            info!("Pending approvals count: {}", count);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": count
            })))
        }
        Err(e) => {
            error!("Failed to get pending approvals count: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve pending approvals count"
            })))
        }
    }
}

/// Récupère le nombre total de visiteurs uniques
pub async fn get_total_visitors_count(
    app_state: web::Data<AppState>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse> {
    info!("Getting total visitors count");

    match app_state.statistics_repository.get_total_visitors_count().await {
        Ok(count) => {
            info!("Total visitors count: {}", count);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": count
            })))
        }
        Err(e) => {
            error!("Failed to get total visitors count: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve total visitors count"
            })))
        }
    }
}

// ===== VERSIONS PUBLIQUES DES HANDLERS (SANS AUTHENTIFICATION) =====

/// Version publique des statistiques du dashboard
pub async fn get_dashboard_stats_public(
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    info!("Getting dashboard statistics (public)");

    match app_state.statistics_repository.get_dashboard_stats().await {
        Ok(stats) => {
            info!("Dashboard statistics retrieved successfully (public)");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": stats
            })))
        }
        Err(e) => {
            error!("Failed to get dashboard statistics (public): {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve dashboard statistics"
            })))
        }
    }
}

/// Version publique des statistiques de visite
pub async fn get_visit_statistics_public(
    app_state: web::Data<AppState>,
    query: web::Query<serde_json::Value>,
) -> Result<HttpResponse> {
    let period = query.get("period")
        .and_then(|p| p.as_str())
        .unwrap_or("week");

    info!("Getting visit statistics for period: {} (public)", period);

    match app_state.statistics_repository.get_visit_statistics(period).await {
        Ok(stats) => {
            info!("Visit statistics retrieved successfully (public)");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": stats
            })))
        }
        Err(e) => {
            error!("Failed to get visit statistics (public): {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve visit statistics"
            })))
        }
    }
}

/// Version publique des statistiques de visiteurs
pub async fn get_visitor_statistics_public(
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    info!("Getting visitor statistics (public)");

    match app_state.statistics_repository.get_visitor_statistics().await {
        Ok(stats) => {
            info!("Visitor statistics retrieved successfully (public)");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": stats
            })))
        }
        Err(e) => {
            error!("Failed to get visitor statistics (public): {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve visitor statistics"
            })))
        }
    }
}

/// Version publique des données de graphiques d'activité
pub async fn get_activity_chart_data_public(
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    info!("Getting activity chart data (public)");

    match app_state.statistics_repository.get_activity_chart_data().await {
        Ok(data) => {
            info!("Activity chart data retrieved successfully (public)");
            Ok(HttpResponse::Ok().json(data))
        }
        Err(e) => {
            error!("Failed to get activity chart data (public): {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve activity chart data"
            })))
        }
    }
}

/// Endpoint pour les statistiques temps réel du dashboard admin
pub async fn get_real_time_statistics(
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    info!("Getting real-time dashboard statistics");

    match app_state.statistics_repository.get_dashboard_stats().await {
        Ok(stats) => {
            info!("Real-time dashboard statistics retrieved successfully");
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": stats
            })))
        }
        Err(e) => {
            error!("Failed to get real-time dashboard statistics: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve real-time dashboard statistics"
            })))
        }
    }
}
