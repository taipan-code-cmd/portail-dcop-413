use actix_web::{
    dev::ServiceRequest, 
    HttpRequest, FromRequest,
    error::ErrorUnauthorized,
    web::Data,
};
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::Future;

use crate::errors::AppError;
use crate::models::{User, UserRole};
use crate::services::AuthService;
use crate::AppState;

#[derive(Clone)]
pub struct AuthenticatedUser {
    pub user: User,
}

// Future pour l'extraction asynchrone de l'utilisateur authentifié
pub struct AuthenticatedUserFuture {
    inner: Pin<Box<dyn Future<Output = Result<AuthenticatedUser, actix_web::Error>> + 'static>>,
}

impl Future for AuthenticatedUserFuture {
    type Output = Result<AuthenticatedUser, actix_web::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

// Implémentation de FromRequest pour AuthenticatedUser
impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = AuthenticatedUserFuture;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let req = req.clone();
        
        AuthenticatedUserFuture {
            inner: Box::pin(async move {
                // Récupérer AppState depuis les données de l'app
                let app_state = req
                    .app_data::<Data<AppState>>()
                    .ok_or_else(|| ErrorUnauthorized("Requested application data is not configured correctly. View/enable debug logs for more details"))?;

                // Extraire le header d'autorisation
                let auth_header = req
                    .headers()
                    .get("authorization")
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(|| ErrorUnauthorized("Missing authorization header"))?;

                // Extraire le token
                let token = crate::security::SecureSessionManager::extract_token_from_header(auth_header)
                    .map_err(|_| ErrorUnauthorized("Invalid authorization header"))?;

                // Valider le token
                let user = app_state.auth_service
                    .validate_token(&token)
                    .await
                    .map_err(|e| ErrorUnauthorized(format!("Invalid token: {}", e)))?;

                Ok(AuthenticatedUser { user })
            }),
        }
    }
}

// Fonction utilitaire pour extraire l'utilisateur authentifié depuis HttpRequest et AppState
pub async fn extract_authenticated_user_from_request(
    req: &HttpRequest,
    app_state: &AppState,
) -> Result<AuthenticatedUser, AppError> {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Authentication("Missing authorization header".to_string()))?;

    let token = crate::security::SecureSessionManager::extract_token_from_header(auth_header)?;
    let user = app_state.auth_service.validate_token(token).await?;

    Ok(AuthenticatedUser { user })
}

// Pour Actix-web, nous utilisons des extractors plutôt que des middlewares pour l'authentification
// Ces fonctions peuvent être utilisées dans les handlers individuels

pub async fn extract_authenticated_user(
    req: &ServiceRequest,
    auth_service: &AuthService,
) -> Result<AuthenticatedUser, AppError> {
    let headers = req.headers();

    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Authentication("Missing authorization header".to_string()))?;

    let token = crate::security::SecureSessionManager::extract_token_from_header(auth_header)?;
    let user = auth_service.validate_token(token).await?;

    Ok(AuthenticatedUser { user })
}

pub fn require_admin(user: &AuthenticatedUser) -> Result<(), AppError> {
    match user.user.role {
        UserRole::Admin | UserRole::Director => Ok(()),
        _ => Err(AppError::Authorization("Admin access required".to_string())),
    }
}

pub fn require_director(user: &AuthenticatedUser) -> Result<(), AppError> {
    match user.user.role {
        UserRole::Director => Ok(()),
        _ => Err(AppError::Authorization("Director access required".to_string())),
    }
}





