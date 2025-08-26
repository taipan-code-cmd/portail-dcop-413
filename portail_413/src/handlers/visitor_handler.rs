use actix_web::{
    web::{Data, Json, Path, Query},
    HttpRequest, HttpResponse,
};
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

use crate::errors::{AppError, Result};
use crate::middleware::AuthenticatedUser;
use crate::models::{CreateVisitorRequest, VisitorSearchQuery};
use crate::AppState;
use crate::utils::extract_user_agent;

pub struct VisitorHandler;

impl VisitorHandler {
    pub async fn create_visitor(
        app_state: Data<AppState>,
        authenticated_user: AuthenticatedUser,
        req: HttpRequest,
        Json(request): Json<CreateVisitorRequest>,
    ) -> Result<HttpResponse> {
        // Valider la requête (basique + stricte)
        request.validate().map_err(|e| AppError::Validation(e.to_string()))?;

        // Validation stricte de sécurité
        request.validate_strict()?;

        let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_string());
        let user_agent = extract_user_agent(&req);
        let user_id = Some(authenticated_user.user.id);

    let visitor = app_state.visitor_service
            .create_visitor(request, user_id, ip_address, user_agent)
            .await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visitor
        })))
    }

    pub async fn get_visitor(
        app_state: Data<AppState>,
        _authenticated_user: AuthenticatedUser,
        visitor_id: Path<Uuid>,
    ) -> Result<HttpResponse> {
        let visitor = app_state.visitor_service.get_visitor(*visitor_id).await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visitor
        })))
    }

    pub async fn list_visitors(
        app_state: Data<AppState>,
        _authenticated_user: AuthenticatedUser,
        query: Query<VisitorSearchQuery>,
    ) -> Result<HttpResponse> {
        let visitors = app_state.visitor_service
            .search_visitors(query.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visitors
        })))
    }

    pub async fn search_visitors(
        app_state: Data<AppState>,
        _authenticated_user: AuthenticatedUser,
        query: Query<VisitorSearchQuery>,
    ) -> Result<HttpResponse> {
        let visitors = app_state.visitor_service.search_visitors(query.into_inner()).await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visitors,
            "count": visitors.len()
        })))
    }

    pub async fn update_visitor(
        app_state: Data<AppState>,
        authenticated_user: AuthenticatedUser,
        req: HttpRequest,
        visitor_id: Path<Uuid>,
        Json(request): Json<CreateVisitorRequest>,
    ) -> Result<HttpResponse> {
        // Valider la requête
        request.validate().map_err(|e| AppError::Validation(e.to_string()))?;

        let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_string());
        let user_agent = extract_user_agent(&req);

    let visitor = app_state.visitor_service
            .update_visitor(*visitor_id, request, Some(authenticated_user.user.id), ip_address, user_agent)
            .await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visitor
        })))
    }

    pub async fn delete_visitor(
        app_state: Data<AppState>,
        authenticated_user: AuthenticatedUser,
        req: HttpRequest,
        visitor_id: Path<Uuid>,
    ) -> Result<HttpResponse> {
        let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_string());
        let user_agent = extract_user_agent(&req);

    app_state.visitor_service
            .delete_visitor(*visitor_id, Some(authenticated_user.user.id), ip_address, user_agent)
            .await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "message": "Visitor deleted successfully"
        })))
    }
}
