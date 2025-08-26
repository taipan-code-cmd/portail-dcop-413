use actix_web::{
    web::{Data, Json},
    HttpRequest, HttpResponse,
};
use serde_json::json;

use crate::errors::{AppError, Result};
use crate::middleware::AuthenticatedUser;
use crate::security::{CsrfProtectionService};
use crate::security::csrf_protection::{DoubleSubmitCookieService, DoubleSubmitCookieConfig};

pub struct CsrfHandler;

impl CsrfHandler {
    /// Génère un nouveau token CSRF
    pub async fn generate_token(
        csrf_service: Data<CsrfProtectionService>,
        authenticated_user: Option<AuthenticatedUser>,
    ) -> Result<HttpResponse> {
        let user_id = authenticated_user.map(|u| u.user.id);
        
        let token_response = csrf_service.generate_token(user_id)?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": {
                "csrf_token": token_response.token,
                "expires_at": token_response.expires_at
            }
        })))
    }

    /// Génère un token Double Submit Cookie
    pub async fn generate_double_submit_token(
        _req: HttpRequest,
    ) -> Result<HttpResponse> {
        let config = DoubleSubmitCookieConfig::default();
        let service = DoubleSubmitCookieService::new(config);
        
        let token = service.generate_double_submit_token()?;
        let cookie = service.create_csrf_cookie(&token);

        Ok(HttpResponse::Ok()
            .append_header(("Set-Cookie", cookie))
            .json(json!({
                "success": true,
                "data": {
                    "csrf_token": token
                }
            })))
    }

    /// Valide un token CSRF (endpoint de test)
    pub async fn validate_token(
        csrf_service: Data<CsrfProtectionService>,
        authenticated_user: Option<AuthenticatedUser>,
        Json(payload): Json<ValidateTokenRequest>,
    ) -> Result<HttpResponse> {
        let user_id = authenticated_user.map(|u| u.user.id);
        
        match csrf_service.validate_token(&payload.token, user_id) {
            Ok(_) => Ok(HttpResponse::Ok().json(json!({
                "success": true,
                "message": "CSRF token is valid"
            }))),
            Err(e) => Ok(HttpResponse::BadRequest().json(json!({
                "success": false,
                "error": e.to_string()
            })))
        }
    }

    /// Obtient les statistiques des tokens CSRF
    pub async fn get_token_stats(
        csrf_service: Data<CsrfProtectionService>,
        authenticated_user: AuthenticatedUser,
    ) -> Result<HttpResponse> {
        // Vérifier les permissions admin
        match authenticated_user.user.role {
            crate::models::UserRole::Admin | crate::models::UserRole::Director => {},
            _ => return Err(AppError::Authorization("Admin access required".to_string())),
        }

        let stats = csrf_service.get_token_stats()?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": stats
        })))
    }

    /// Endpoint pour tester la protection CSRF
    pub async fn test_csrf_protection(
        req: HttpRequest,
        authenticated_user: Option<AuthenticatedUser>,
    ) -> Result<HttpResponse> {
        // Vérifier la présence du token CSRF dans les headers
        let csrf_token = req.headers()
            .get("X-CSRF-Token")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Authentication("Missing CSRF token".to_string()))?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "message": "CSRF protection is working",
            "data": {
                "received_token": csrf_token,
                "user_id": authenticated_user.map(|u| u.user.id)
            }
        })))
    }
}

#[derive(serde::Deserialize)]
pub struct ValidateTokenRequest {
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_generate_token_endpoint() {
        let csrf_service = CsrfProtectionService::new(30, true);
        
        let app = test::init_service(
            App::new()
                .app_data(Data::new(csrf_service))
                .route("/csrf/token", web::get().to(CsrfHandler::generate_token))
        ).await;

        let req = test::TestRequest::get()
            .uri("/csrf/token")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
