use actix_web::{
    web::{Data, Json, Path, Query},
    HttpRequest, HttpResponse,
};
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

use crate::errors::{AppError, Result};
use crate::middleware::AuthenticatedUser;
use crate::models::{CreateVisitRequest, UpdateVisitStatusRequest, VisitSearchQuery};
use crate::AppState;
use crate::utils::extract_user_agent;

pub struct VisitHandler;

impl VisitHandler {
    pub async fn create_visit(
        app_state: Data<AppState>,
        authenticated_user: AuthenticatedUser,
        req: HttpRequest,
        Json(request): Json<CreateVisitRequest>,
    ) -> Result<HttpResponse> {
        // Valider la requête
        request.validate().map_err(|e| AppError::Validation(e.to_string()))?;

        let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_string());
        let user_agent = extract_user_agent(&req);
        let user_id = Some(authenticated_user.user.id);

    let visit = app_state.visit_service
            .create_visit(request, user_id, ip_address, user_agent)
            .await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visit
        })))
    }

    pub async fn get_visit(
        app_state: Data<AppState>,
        visit_id: Path<Uuid>,
        _authenticated_user: AuthenticatedUser,
    ) -> Result<HttpResponse> {
        let visit = app_state.visit_service.get_visit(*visit_id).await?;

        match visit {
            Some(visit) => Ok(HttpResponse::Ok().json(json!({
                "success": true,
                "data": visit
            }))),
            None => Err(AppError::NotFound("Visit not found".to_string())),
        }
    }

    pub async fn search_visits(
        app_state: Data<AppState>,
        query: Query<VisitSearchQuery>,
        _authenticated_user: AuthenticatedUser,
    ) -> Result<HttpResponse> {
        let visits = app_state.visit_service.search_visits(query.into_inner()).await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visits,
            "count": visits.len()
        })))
    }

    pub async fn list_visits(
        app_state: Data<AppState>,
        query: Query<VisitSearchQuery>,
        _authenticated_user: AuthenticatedUser,
    ) -> Result<HttpResponse> {
        let visits = app_state.visit_service.search_visits(query.into_inner()).await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visits,
            "count": visits.len()
        })))
    }

    pub async fn update_visit_status(
        app_state: Data<AppState>,
        req: HttpRequest,
        authenticated_user: AuthenticatedUser,
        visit_id: Path<Uuid>,
        Json(request): Json<UpdateVisitStatusRequest>,
    ) -> Result<HttpResponse> {
        let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_string());
        let user_agent = extract_user_agent(&req);

    let visit = app_state.visit_service
            .update_visit_status(*visit_id, request, authenticated_user.user.id, ip_address, user_agent)
            .await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visit
        })))
    }

    pub async fn start_visit(
        app_state: Data<AppState>,
        req: HttpRequest,
        authenticated_user: AuthenticatedUser,
        visit_id: Path<Uuid>,
    ) -> Result<HttpResponse> {
        let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_string());
        let user_agent = extract_user_agent(&req);

    let visit = app_state.visit_service
            .start_visit(*visit_id, authenticated_user.user.id, ip_address, user_agent)
            .await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visit,
            "message": "Visit started successfully"
        })))
    }

    pub async fn end_visit(
        app_state: Data<AppState>,
        req: HttpRequest,
        authenticated_user: AuthenticatedUser,
        visit_id: Path<Uuid>,
    ) -> Result<HttpResponse> {
        let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_string());
        let user_agent = extract_user_agent(&req);

    let visit = app_state.visit_service
            .end_visit(*visit_id, authenticated_user.user.id, ip_address, user_agent)
            .await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visit,
            "message": "Visit ended successfully"
        })))
    }

    pub async fn get_active_visits(
        app_state: Data<AppState>,
        _authenticated_user: AuthenticatedUser,
    ) -> Result<HttpResponse> {
        let visits = app_state.visit_service.get_active_visits().await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visits,
            "count": visits.len()
        })))
    }
}

