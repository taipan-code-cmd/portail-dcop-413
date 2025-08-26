use actix_web::HttpResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Service de gestion d'erreurs sécurisé conforme OWASP A09:2021
/// Affiche des messages neutres côté client, logs détaillés côté serveur
pub struct SecureErrorHandler {
    error_codes: HashMap<String, ErrorCodeInfo>,
    log_sensitive_details: bool,
    generic_error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorCodeInfo {
    pub code: String,
    pub public_message: String,
    pub log_level: LogLevel,
    pub should_alert: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

#[derive(Debug, Serialize)]
pub struct StandardErrorResponse {
    pub success: bool,
    pub error: ErrorDetails,
    pub request_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetails {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl SecureErrorHandler {
    /// Crée un nouveau gestionnaire d'erreurs sécurisé
    pub fn new(log_sensitive_details: bool) -> Self {
        let mut error_codes = HashMap::new();

        // Codes d'erreur standardisés conformes OWASP A09:2021
        // Messages neutres pour éviter l'exposition d'informations sensibles
        error_codes.insert("AUTH_001".to_string(), ErrorCodeInfo {
            code: "AUTH_001".to_string(),
            public_message: "Authentification requise".to_string(),
            log_level: LogLevel::Warn,
            should_alert: false,
        });

        error_codes.insert("AUTH_002".to_string(), ErrorCodeInfo {
            code: "AUTH_002".to_string(),
            public_message: "Identifiants invalides".to_string(), // Message neutre
            log_level: LogLevel::Warn,
            should_alert: true, // Tentative d'intrusion potentielle
        });

        error_codes.insert("AUTH_003".to_string(), ErrorCodeInfo {
            code: "AUTH_003".to_string(),
            public_message: "Accès non autorisé".to_string(),
            log_level: LogLevel::Warn,
            should_alert: true,
        });

        error_codes.insert("VAL_001".to_string(), ErrorCodeInfo {
            code: "VAL_001".to_string(),
            public_message: "Invalid input data".to_string(),
            log_level: LogLevel::Info,
            should_alert: false,
        });

        error_codes.insert("VAL_002".to_string(), ErrorCodeInfo {
            code: "VAL_002".to_string(),
            public_message: "File upload error".to_string(),
            log_level: LogLevel::Warn,
            should_alert: false,
        });

        error_codes.insert("DB_001".to_string(), ErrorCodeInfo {
            code: "DB_001".to_string(),
            public_message: "Data processing error".to_string(),
            log_level: LogLevel::Error,
            should_alert: true,
        });

        error_codes.insert("SYS_001".to_string(), ErrorCodeInfo {
            code: "SYS_001".to_string(),
            public_message: "Internal server error".to_string(),
            log_level: LogLevel::Critical,
            should_alert: true,
        });

        error_codes.insert("RATE_001".to_string(), ErrorCodeInfo {
            code: "RATE_001".to_string(),
            public_message: "Too many requests".to_string(),
            log_level: LogLevel::Warn,
            should_alert: true,
        });

        error_codes.insert("CSRF_001".to_string(), ErrorCodeInfo {
            code: "CSRF_001".to_string(),
            public_message: "Validation de sécurité échouée".to_string(), // Message neutre
            log_level: LogLevel::Error,
            should_alert: true,
        });

        // Code d'erreur générique pour masquer tous les détails sensibles
        error_codes.insert("ERR_GENERIC".to_string(), ErrorCodeInfo {
            code: "ERR_GENERIC".to_string(),
            public_message: "Une erreur s'est produite. Veuillez réessayer plus tard.".to_string(),
            log_level: LogLevel::Error,
            should_alert: false,
        });

        Self {
            error_codes,
            log_sensitive_details,
            generic_error_message: "Une erreur s'est produite. Veuillez réessayer plus tard.".to_string(),
        }
    }

    /// Traite une erreur et retourne une réponse standardisée
    pub fn handle_error(
        &self,
        error: &crate::errors::AppError,
        request_id: Option<String>,
        context: Option<&str>,
    ) -> StandardErrorResponse {
        let request_id = request_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let error_code = self.map_error_to_code(error);
        let error_info = self.error_codes.get(&error_code).cloned()
            .unwrap_or_else(|| ErrorCodeInfo {
                code: "SYS_001".to_string(),
                public_message: "Internal server error".to_string(),
                log_level: LogLevel::Critical,
                should_alert: true,
            });

        // Logger les détails sensibles côté serveur
        self.log_error(error, &error_info, &request_id, context);

        // Créer la réponse publique (sans détails sensibles)
        StandardErrorResponse {
            success: false,
            error: ErrorDetails {
                code: error_info.code,
                message: error_info.public_message,
                details: if self.log_sensitive_details {
                    Some(serde_json::json!({
                        "context": context,
                        "internal_error": error.to_string()
                    }))
                } else {
                    None
                },
            },
            request_id,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Retourne un message d'erreur générique pour masquer les détails sensibles
    /// Conforme aux recommandations OWASP A09:2021
    pub fn get_generic_error_response(&self, request_id: Option<String>) -> StandardErrorResponse {
        let request_id = request_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        StandardErrorResponse {
            success: false,
            error: ErrorDetails {
                code: "ERR_GENERIC".to_string(),
                message: self.generic_error_message.clone(),
                details: None,
            },
            request_id,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Traite une erreur avec masquage automatique des détails sensibles
    pub fn handle_error_secure(
        &self,
        error: &crate::errors::AppError,
        request_id: Option<String>,
        context: Option<&str>,
        mask_sensitive: bool,
    ) -> StandardErrorResponse {
        // Log détaillé côté serveur
        self.log_detailed_error(error, &request_id, context);

        if mask_sensitive {
            // Retourner un message générique pour masquer les détails
            self.get_generic_error_response(request_id)
        } else {
            // Retourner l'erreur normale (pour développement/debug)
            self.handle_error(error, request_id, context)
        }
    }

    /// Log détaillé côté serveur uniquement - ne jamais exposer au client
    fn log_detailed_error(
        &self,
        error: &crate::errors::AppError,
        request_id: &Option<String>,
        context: Option<&str>,
    ) {
        let request_id = request_id.as_deref().unwrap_or("unknown");
        let context = context.unwrap_or("unknown");

        match error {
            crate::errors::AppError::Authentication(msg) => {
                tracing::warn!("AUTH_ERROR [{}] in {}: {}", request_id, context, msg);
            },
            crate::errors::AppError::Authorization(msg) => {
                tracing::warn!("AUTHZ_ERROR [{}] in {}: {}", request_id, context, msg);
            },
            crate::errors::AppError::Validation(msg) => {
                tracing::info!("VALIDATION_ERROR [{}] in {}: {}", request_id, context, msg);
            },
            crate::errors::AppError::Database(msg) => {
                tracing::error!("DB_ERROR [{}] in {}: {}", request_id, context, msg);
            },
            crate::errors::AppError::Internal(msg) => {
                tracing::error!("INTERNAL_ERROR [{}] in {}: {}", request_id, context, msg);
            },
            crate::errors::AppError::NotFound(msg) => {
                tracing::info!("NOT_FOUND [{}] in {}: {}", request_id, context, msg);
            },
            _ => {
                tracing::error!("UNKNOWN_ERROR [{}] in {}: {:?}", request_id, context, error);
            }
        }
    }

    /// Mappe une erreur interne vers un code d'erreur public
    fn map_error_to_code(&self, error: &crate::errors::AppError) -> String {
        match error {
            crate::errors::AppError::Authentication(_) => "AUTH_002".to_string(),
            crate::errors::AppError::Authorization(_) => "AUTH_003".to_string(),
            crate::errors::AppError::Validation(_) => "VAL_001".to_string(),
            crate::errors::AppError::Database(_) => "DB_001".to_string(),
            crate::errors::AppError::NotFound(_) => "VAL_001".to_string(), // Ne pas révéler l'existence
            crate::errors::AppError::Internal(_) => "SYS_001".to_string(),
            crate::errors::AppError::RateLimit => "RATE_001".to_string(),
            crate::errors::AppError::Encryption(_) => "SYS_001".to_string(),
            crate::errors::AppError::Configuration(_) => "SYS_001".to_string(),
            crate::errors::AppError::Conflict(_) => "VAL_001".to_string(),
            crate::errors::AppError::BadRequest(_) => "VAL_001".to_string(),
            crate::errors::AppError::ServiceUnavailable => "SYS_001".to_string(),
        }
    }

    /// Enregistre l'erreur avec les détails complets
    fn log_error(
        &self,
        error: &crate::errors::AppError,
        error_info: &ErrorCodeInfo,
        request_id: &str,
        context: Option<&str>,
    ) {
        let log_message = format!(
            "Error [{}] - Request ID: {} - Context: {} - Details: {}",
            error_info.code,
            request_id,
            context.unwrap_or("unknown"),
            error
        );

        match error_info.log_level {
            LogLevel::Debug => tracing::debug!("{}", log_message),
            LogLevel::Info => tracing::info!("{}", log_message),
            LogLevel::Warn => tracing::warn!("{}", log_message),
            LogLevel::Error => tracing::error!("{}", log_message),
            LogLevel::Critical => {
                tracing::error!("CRITICAL: {}", log_message);
                // Ici, vous pourriez déclencher des alertes supplémentaires
                if error_info.should_alert {
                    self.send_alert(&log_message, error_info);
                }
            }
        }
    }

    /// Envoie une alerte pour les erreurs critiques
    fn send_alert(&self, message: &str, error_info: &ErrorCodeInfo) {
        // Implémentation d'alerte (email, Slack, PagerDuty, etc.)
        tracing::error!("ALERT: {} - {}", error_info.code, message);
        
        // Exemple : écrire dans un fichier d'alerte
        if let Err(e) = std::fs::write(
            "/tmp/security_alerts.log",
            format!("{}: {}\n", chrono::Utc::now().to_rfc3339(), message)
        ) {
            tracing::error!("Failed to write security alert: {}", e);
        }
    }

    /// Crée une réponse HTTP à partir d'une erreur
    pub fn create_http_response(&self, error: &crate::errors::AppError, request_id: Option<String>) -> HttpResponse {
        let error_response = self.handle_error(error, request_id, None);
        
        let status_code = match error {
            crate::errors::AppError::Authentication(_) => actix_web::http::StatusCode::UNAUTHORIZED,
            crate::errors::AppError::Authorization(_) => actix_web::http::StatusCode::FORBIDDEN,
            crate::errors::AppError::Validation(_) => actix_web::http::StatusCode::BAD_REQUEST,
            crate::errors::AppError::NotFound(_) => actix_web::http::StatusCode::NOT_FOUND,
            crate::errors::AppError::RateLimit => actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            crate::errors::AppError::Database(_) | crate::errors::AppError::Internal(_) => {
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
            }
            crate::errors::AppError::Encryption(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            crate::errors::AppError::Configuration(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            crate::errors::AppError::Conflict(_) => actix_web::http::StatusCode::CONFLICT,
            crate::errors::AppError::BadRequest(_) => actix_web::http::StatusCode::BAD_REQUEST,
            crate::errors::AppError::ServiceUnavailable => actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
        };

        HttpResponse::build(status_code)
            .append_header(("X-Request-ID", error_response.request_id.clone()))
            .json(error_response)
    }
}

impl Default for SecureErrorHandler {
    fn default() -> Self {
        Self::new(false) // Par défaut, ne pas exposer les détails sensibles
    }
}

/// Middleware pour la gestion d'erreurs sécurisée
pub struct SecureErrorMiddleware {
    handler: SecureErrorHandler,
}

impl SecureErrorMiddleware {
    pub fn new(handler: SecureErrorHandler) -> Self {
        Self { handler }
    }

    /// Traite une erreur dans le contexte d'une requête
    pub fn handle_request_error(
        &self,
        error: &crate::errors::AppError,
        request_id: Option<String>,
        path: &str,
        method: &str,
    ) -> HttpResponse {
        let context = format!("{} {}", method, path);
        let error_response = self.handler.handle_error(error, request_id, Some(&context));
        
        let status_code = match error {
            crate::errors::AppError::Authentication(_) => actix_web::http::StatusCode::UNAUTHORIZED,
            crate::errors::AppError::Authorization(_) => actix_web::http::StatusCode::FORBIDDEN,
            crate::errors::AppError::Validation(_) => actix_web::http::StatusCode::BAD_REQUEST,
            crate::errors::AppError::NotFound(_) => actix_web::http::StatusCode::NOT_FOUND,
            crate::errors::AppError::RateLimit => actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            crate::errors::AppError::Database(_) | crate::errors::AppError::Internal(_) => {
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
            }
            crate::errors::AppError::Encryption(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            crate::errors::AppError::Configuration(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            crate::errors::AppError::Conflict(_) => actix_web::http::StatusCode::CONFLICT,
            crate::errors::AppError::BadRequest(_) => actix_web::http::StatusCode::BAD_REQUEST,
            crate::errors::AppError::ServiceUnavailable => actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
        };

        HttpResponse::build(status_code)
            .append_header(("X-Request-ID", error_response.request_id.clone()))
            .append_header(("X-Content-Type-Options", "nosniff"))
            .append_header(("X-Frame-Options", "DENY"))
            .json(error_response)
    }
}

/// Extracteur pour l'ID de requête
pub struct RequestId(pub String);

impl actix_web::FromRequest for RequestId {
    type Error = actix_web::Error;
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let request_id = req.headers()
            .get("X-Request-ID")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        std::future::ready(Ok(RequestId(request_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_handler_creation() {
        let handler = SecureErrorHandler::new(false);
        assert!(!handler.log_sensitive_details);
        assert!(!handler.error_codes.is_empty());
    }

    #[test]
    fn test_error_mapping() {
        let handler = SecureErrorHandler::new(false);
        let auth_error = crate::errors::AppError::Authentication("test".to_string());
        let code = handler.map_error_to_code(&auth_error);
        assert_eq!(code, "AUTH_002");
    }

    #[test]
    fn test_error_response_structure() {
        let handler = SecureErrorHandler::new(false);
        let error = crate::errors::AppError::Validation("test validation error".to_string());
        let response = handler.handle_error(&error, None, Some("test context"));
        
        assert!(!response.success);
        assert_eq!(response.error.code, "VAL_001");
        assert_eq!(response.error.message, "Invalid input data");
        assert!(response.error.details.is_none()); // Pas de détails sensibles
    }
}
