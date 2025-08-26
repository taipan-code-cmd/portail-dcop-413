use actix_web::{web::{Data, Json, Path, Query}, HttpResponse};
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState,
    errors::{AppError, Result},
    middleware::AuthenticatedUser,
    models::{CreateUserRequest, UserRole},
};

fn map_user_to_ui(user: &crate::models::User) -> serde_json::Value {
    serde_json::json!({
        "id": user.id,
        "username": user.username,
        "email": serde_json::Value::Null,
        "first_name": serde_json::Value::Null,
        "last_name": serde_json::Value::Null,
        "role": user.role, // serde will serialize enum as lowercase due to sqlx type
        "status": if user.is_active { "active" } else { "inactive" },
        "is_active": user.is_active,
        "last_login": user.last_login,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    })
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct UserStatusRequestBody {
    pub active: bool,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct UserRoleRequestBody {
    pub role: UserRole,
}

pub struct UserHandler;

impl UserHandler {
    pub async fn list_users(
        app_state: Data<AppState>,
        _user: AuthenticatedUser,
        query: Query<ListQuery>,
    ) -> Result<HttpResponse> {
        let page = query.page.unwrap_or(1).max(1);
        let limit = query.limit.unwrap_or(25).clamp(1, 100);
        let offset = (page - 1) * limit;

    let users = app_state.auth_service.list_users(limit, offset).await?;

        let users_json: Vec<_> = users.iter().map(map_user_to_ui).collect();
        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": {
                "users": users_json,
                "total": users_json.len(),
                "page": page,
                "limit": limit,
                "total_pages": 1
            }
        })))
    }

    pub async fn create_user(
        app_state: Data<AppState>,
        user: AuthenticatedUser,
        Json(payload): Json<CreateUserRequest>,
    ) -> Result<HttpResponse> {
        // RESTRICTION : Seuls les administrateurs peuvent créer des utilisateurs
        if !matches!(user.user.role, UserRole::Admin) {
            return Err(AppError::Authorization("Seuls les administrateurs peuvent créer des comptes utilisateur".to_string()));
        }

        let created = app_state.auth_service.register_user(payload, Some(user.user.id)).await?;
        // Fetch full user to include all fields
        let full = app_state
            .auth_service
            .find_user_by_id(created.id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
        Ok(HttpResponse::Ok().json(json!({ "success": true, "data": map_user_to_ui(&full) })))
    }

    pub async fn delete_user(
        _app_state: Data<AppState>,
        _user: AuthenticatedUser,
        _user_id: Path<Uuid>,
    ) -> Result<HttpResponse> {
    // Not implemented in repositories yet
    Err(AppError::Internal("Delete user not implemented".to_string()))
    }

    pub async fn change_status(
        app_state: Data<AppState>,
        user: AuthenticatedUser,
        user_id: Path<Uuid>,
        Json(body): Json<UserStatusRequestBody>,
    ) -> Result<HttpResponse> {
        if !matches!(user.user.role, UserRole::Admin | UserRole::Director) {
            return Err(AppError::Authorization("Admin access required".to_string()));
        }

    let updated = app_state.auth_service.set_user_active(*user_id, body.active).await?;

    Ok(HttpResponse::Ok().json(json!({ "success": true, "data": map_user_to_ui(&updated) })))
    }

    pub async fn change_role(
        app_state: Data<AppState>,
        user: AuthenticatedUser,
        user_id: Path<Uuid>,
        Json(body): Json<UserRoleRequestBody>,
    ) -> Result<HttpResponse> {
        if !matches!(user.user.role, UserRole::Admin | UserRole::Director) {
            return Err(AppError::Authorization("Admin access required".to_string()));
        }

    let updated = app_state.auth_service.set_user_role(*user_id, body.role).await?;

    Ok(HttpResponse::Ok().json(json!({ "success": true, "data": map_user_to_ui(&updated) })))
    }

    pub async fn current_profile(
        app_state: Data<AppState>,
        user: AuthenticatedUser,
    ) -> Result<HttpResponse> {
        let u = app_state
            .auth_service
            .find_user_by_id(user.user.id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
        let perms = match u.role {
            UserRole::Admin => vec!["manage_users", "view_audit", "export_data", "manage_visits", "manage_visitors"],
            UserRole::Director => vec!["view_audit", "export_data", "manage_visits", "manage_visitors"],
            UserRole::User => vec!["manage_visits", "manage_visitors"],
        };
        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": {
                "user": map_user_to_ui(&u),
                "permissions": perms
            }
        })))
    }

    pub async fn current_permissions(
        _app_state: Data<AppState>,
        user: AuthenticatedUser,
    ) -> Result<HttpResponse> {
        // Basic permissions based on role
        let perms = match user.user.role {
            UserRole::Admin => vec!["manage_users", "view_audit", "export_data", "manage_visits", "manage_visitors"],
            UserRole::Director => vec!["view_audit", "export_data", "manage_visits", "manage_visitors"],
            UserRole::User => vec!["manage_visits", "manage_visitors"],
        };
        Ok(HttpResponse::Ok().json(json!({ "success": true, "data": perms })))
    }
}
