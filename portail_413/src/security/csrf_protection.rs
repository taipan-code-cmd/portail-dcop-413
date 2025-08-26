use actix_web::{
    dev::ServiceRequest,
    http::{header, Method},
    HttpMessage, HttpRequest,
};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::errors::{AppError, Result};

/// Service de protection CSRF avec tokens synchronisés et vérification Origin/Referer
/// Conforme aux recommandations OWASP A01:2021 et CWE-352
#[derive(Clone)]
pub struct CsrfProtectionService {
    tokens: Arc<Mutex<HashMap<String, InternalCsrfToken>>>,
    token_lifetime: Duration,
    strict_origin_check: bool,
    allowed_origins: HashSet<String>,
    double_submit_cookie: bool,
}

#[derive(Debug, Clone)]
struct InternalCsrfToken {
    #[allow(dead_code)]
    value: String,
    user_id: Option<Uuid>,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CsrfTokenResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

impl CsrfProtectionService {
    /// Crée un nouveau service de protection CSRF avec toutes les protections OWASP
    pub fn new(token_lifetime_minutes: i64, strict_origin_check: bool) -> Self {
        let mut allowed_origins = HashSet::new();
        allowed_origins.insert("https://localhost".to_string());
        allowed_origins.insert("https://127.0.0.1".to_string());

        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            token_lifetime: Duration::minutes(token_lifetime_minutes),
            strict_origin_check,
            allowed_origins,
            double_submit_cookie: true, // Activé par défaut pour sécurité maximale
        }
    }

    /// Crée un service CSRF avec origines personnalisées
    pub fn with_allowed_origins(
        token_lifetime_minutes: i64,
        strict_origin_check: bool,
        allowed_origins: Vec<String>,
        double_submit_cookie: bool
    ) -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            token_lifetime: Duration::minutes(token_lifetime_minutes),
            strict_origin_check,
            allowed_origins: allowed_origins.into_iter().collect(),
            double_submit_cookie,
        }
    }

    /// Génère un nouveau token CSRF avec CSPRNG sécurisé (256 bits)
    /// Conforme aux recommandations OWASP pour la génération de tokens
    pub fn generate_token(&self, user_id: Option<Uuid>) -> Result<CsrfTokenResponse> {
        let rng = SystemRandom::new();
        let mut token_bytes = [0u8; 32]; // 256 bits

        rng.fill(&mut token_bytes)
            .map_err(|_| AppError::Encryption("Failed to generate CSRF token".to_string()))?;

        let token_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);

        let now = Utc::now();
        let expires_at = now + self.token_lifetime;

        let csrf_token = InternalCsrfToken {
            value: token_value.clone(),
            user_id,
            created_at: now,
            expires_at,
            used: false,
        };

        let mut tokens = self.tokens.lock()
            .map_err(|_| AppError::Internal("Failed to acquire CSRF tokens lock".to_string()))?;

        tokens.insert(token_value.clone(), csrf_token);

        // Nettoyer les tokens expirés
        self.cleanup_expired_tokens(&mut tokens);

        Ok(CsrfTokenResponse {
            token: token_value,
            expires_at,
        })
    }

    /// Valide un token CSRF
    pub fn validate_token(&self, token: &str, user_id: Option<Uuid>) -> Result<()> {
        let mut tokens = self.tokens.lock()
            .map_err(|_| AppError::Internal("Failed to acquire CSRF tokens lock".to_string()))?;

        let csrf_token = tokens.get_mut(token)
            .ok_or_else(|| AppError::Authentication("Invalid CSRF token".to_string()))?;

        // Vérifier l'expiration
        if Utc::now() > csrf_token.expires_at {
            tokens.remove(token);
            return Err(AppError::Authentication("CSRF token expired".to_string()));
        }

        // Vérifier si le token a déjà été utilisé (protection contre replay)
        if csrf_token.used {
            tokens.remove(token);
            return Err(AppError::Authentication("CSRF token already used".to_string()));
        }

        // Vérifier l'association utilisateur
        if csrf_token.user_id != user_id {
            return Err(AppError::Authentication("CSRF token user mismatch".to_string()));
        }

        // Marquer le token comme utilisé
        csrf_token.used = true;

        tracing::info!("CSRF token validated successfully for user: {:?}", user_id);
        Ok(())
    }

    /// Vérifie l'origine de la requête
    pub fn verify_origin(&self, request: &HttpRequest) -> Result<()> {
        if !self.strict_origin_check {
            return Ok(());
        }

        let origin = request.headers()
            .get(header::ORIGIN)
            .or_else(|| request.headers().get(header::REFERER))
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Authentication("Missing Origin/Referer header".to_string()))?;

        let host = request.headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Authentication("Missing Host header".to_string()))?;

        // Extraire le domaine de l'origine
        let origin_domain = if origin.starts_with("https://") {
            &origin[8..]
        } else if origin.starts_with("http://") {
            &origin[7..]
        } else {
            origin
        };

        // Vérifier que l'origine correspond à l'hôte
        if origin_domain.split('/').next().unwrap_or("") != host {
            tracing::warn!("CSRF origin mismatch: origin={}, host={}", origin, host);
            return Err(AppError::Authentication("Origin verification failed".to_string()));
        }

        Ok(())
    }

    /// Nettoie les tokens expirés
    fn cleanup_expired_tokens(&self, tokens: &mut HashMap<String, InternalCsrfToken>) {
        let now = Utc::now();
        tokens.retain(|_, token| now <= token.expires_at);
    }

    /// Obtient les statistiques des tokens
    pub fn get_token_stats(&self) -> Result<CsrfTokenStats> {
        let tokens = self.tokens.lock()
            .map_err(|_| AppError::Internal("Failed to acquire CSRF tokens lock".to_string()))?;

        let now = Utc::now();
        let total_tokens = tokens.len();
        let expired_tokens = tokens.values().filter(|t| now > t.expires_at).count();
        let used_tokens = tokens.values().filter(|t| t.used).count();
        let active_tokens = total_tokens - expired_tokens - used_tokens;

        Ok(CsrfTokenStats {
            total_tokens,
            active_tokens,
            expired_tokens,
            used_tokens,
        })
    }

    /// Vérifie les headers Origin et Referer selon OWASP A01:2021
    /// Protection contre les attaques CSRF cross-origin
    pub fn validate_origin_and_referer(&self, request: &HttpRequest) -> Result<()> {
        if !self.strict_origin_check {
            return Ok(());
        }

        // Vérification de l'header Origin (priorité)
        if let Some(origin) = request.headers().get(header::ORIGIN) {
            let origin_str = origin.to_str()
                .map_err(|_| AppError::Validation("Invalid Origin header".to_string()))?;

            if !self.allowed_origins.contains(origin_str) {
                tracing::warn!("CSRF: Rejected request from unauthorized origin: {}", origin_str);
                return Err(AppError::Validation(format!("Origin '{}' not allowed", origin_str)));
            }

            tracing::debug!("CSRF: Origin validation passed: {}", origin_str);
            return Ok(());
        }

        // Fallback sur l'header Referer si Origin absent
        if let Some(referer) = request.headers().get(header::REFERER) {
            let referer_str = referer.to_str()
                .map_err(|_| AppError::Validation("Invalid Referer header".to_string()))?;

            // Extraire l'origine du referer (parsing simple)
            let referer_origin = if referer_str.starts_with("https://") {
                if let Some(path_start) = referer_str[8..].find('/') {
                    referer_str[..8 + path_start].to_string()
                } else {
                    referer_str.to_string()
                }
            } else if referer_str.starts_with("http://") {
                if let Some(path_start) = referer_str[7..].find('/') {
                    referer_str[..7 + path_start].to_string()
                } else {
                    referer_str.to_string()
                }
            } else {
                return Err(AppError::Validation("Invalid Referer protocol".to_string()));
            };

            if !self.allowed_origins.contains(&referer_origin) {
                tracing::warn!("CSRF: Rejected request from unauthorized referer: {}", referer_origin);
                return Err(AppError::Validation(format!("Referer origin '{}' not allowed", referer_origin)));
            }

            tracing::debug!("CSRF: Referer validation passed: {}", referer_origin);
            return Ok(());
        }

        // Aucun header Origin ou Referer trouvé
        tracing::warn!("CSRF: Request missing both Origin and Referer headers");
        Err(AppError::Validation("Missing Origin or Referer header for CSRF protection".to_string()))
    }

    /// Validation complète CSRF avec toutes les protections OWASP
    pub fn validate_request_comprehensive(&self, request: &HttpRequest, token: &str, user_id: Option<Uuid>) -> Result<()> {
        // 1. Vérification Origin/Referer
        self.validate_origin_and_referer(request)?;

        // 2. Validation du token CSRF
        self.validate_token(token, user_id)?;

        // 3. Si Double Submit Cookie activé, vérifier le cookie
        if self.double_submit_cookie {
            if let Some(cookie_value) = request.cookie("csrf_token") {
                if cookie_value.value() != token {
                    tracing::warn!("CSRF: Double Submit Cookie mismatch");
                    return Err(AppError::Validation("CSRF token mismatch with cookie".to_string()));
                }
            } else {
                tracing::warn!("CSRF: Missing CSRF cookie for Double Submit validation");
                return Err(AppError::Validation("Missing CSRF cookie".to_string()));
            }
        }

        tracing::info!("CSRF: Comprehensive validation passed");
        Ok(())
    }

    /// Ajoute une origine autorisée pour les vérifications CSRF
    pub fn add_allowed_origin(&mut self, origin: String) {
        self.allowed_origins.insert(origin);
    }

    /// Génère un token Double Submit Cookie sécurisé
    pub fn generate_double_submit_token(&self) -> Result<String> {
        let rng = SystemRandom::new();
        let mut token_bytes = [0u8; 32]; // 256 bits

        rng.fill(&mut token_bytes)
            .map_err(|_| AppError::Encryption("Failed to generate double submit token".to_string()))?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes))
    }
}

#[derive(Debug, Serialize)]
pub struct CsrfTokenStats {
    pub total_tokens: usize,
    pub active_tokens: usize,
    pub expired_tokens: usize,
    pub used_tokens: usize,
}

/// Middleware de protection CSRF
pub struct CsrfProtectionMiddleware {
    service: CsrfProtectionService,
    exempt_paths: Vec<String>,
}

impl CsrfProtectionMiddleware {
    pub fn new(service: CsrfProtectionService, exempt_paths: Vec<String>) -> Self {
        Self {
            service,
            exempt_paths,
        }
    }

    /// Vérifie si un chemin est exempté de la protection CSRF
    fn is_exempt_path(&self, path: &str) -> bool {
        self.exempt_paths.iter().any(|exempt| {
            path.starts_with(exempt) || path.matches(exempt).count() > 0
        })
    }

    /// Vérifie la protection CSRF pour une requête
    pub fn verify_request(&self, req: &ServiceRequest) -> Result<()> {
        let path = req.path();
        let method = req.method();

        // Ignorer les méthodes sûres (GET, HEAD, OPTIONS)
        if matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS) {
            return Ok(());
        }

        // Ignorer les chemins exemptés
        if self.is_exempt_path(path) {
            return Ok(());
        }

        // Vérifier l'origine
        self.service.verify_origin(req.request())?;

        // Extraire le token CSRF
        let csrf_token = self.extract_csrf_token(req)?;

        // Extraire l'ID utilisateur (si disponible)
        let user_id = req.extensions().get::<Uuid>().copied();

        // Valider le token
        self.service.validate_token(&csrf_token, user_id)?;

        Ok(())
    }

    /// Extrait le token CSRF de la requête
    fn extract_csrf_token(&self, req: &ServiceRequest) -> Result<String> {
        // Essayer d'abord le header X-CSRF-Token
        if let Some(header_value) = req.headers().get("X-CSRF-Token") {
            if let Ok(token) = header_value.to_str() {
                return Ok(token.to_string());
            }
        }

        // Essayer ensuite le cookie CSRF
        if let Some(cookie_header) = req.headers().get(header::COOKIE) {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if cookie.starts_with("csrf_token=") {
                        return Ok(cookie[11..].to_string());
                    }
                }
            }
        }

        Err(AppError::Authentication("CSRF token not found".to_string()))
    }
}

/// Extracteur de token CSRF pour les handlers
pub struct CsrfToken(pub String);

impl actix_web::FromRequest for CsrfToken {
    type Error = actix_web::Error;
    type Future = std::future::Ready<std::result::Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        // Extraire le token du header
        let token = req.headers()
            .get("X-CSRF-Token")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();

        std::future::ready(Ok(CsrfToken(token)))
    }
}

/// Configuration Double Submit Cookie
#[derive(Debug, Clone)]
pub struct DoubleSubmitCookieConfig {
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: String,
}

impl Default for DoubleSubmitCookieConfig {
    fn default() -> Self {
        Self {
            cookie_name: "csrf_token".to_string(),
            cookie_secure: true,
            cookie_http_only: false, // Doit être accessible en JavaScript
            cookie_same_site: "Strict".to_string(),
        }
    }
}

/// Implémentation du pattern Double Submit Cookie
pub struct DoubleSubmitCookieService {
    config: DoubleSubmitCookieConfig,
}

impl DoubleSubmitCookieService {
    pub fn new(config: DoubleSubmitCookieConfig) -> Self {
        Self { config }
    }

    /// Génère un token pour Double Submit Cookie avec CSPRNG sécurisé
    /// Conforme aux recommandations OWASP pour Double Submit Cookie Pattern
    pub fn generate_double_submit_token(&self) -> Result<String> {
        let rng = SystemRandom::new();
        let mut token_bytes = [0u8; 32]; // 256 bits

        rng.fill(&mut token_bytes)
            .map_err(|_| AppError::Encryption("Failed to generate double submit token".to_string()))?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes))
    }

    /// Crée un cookie CSRF
    pub fn create_csrf_cookie(&self, token: &str) -> String {
        format!(
            "{}={}; Secure={}; HttpOnly={}; SameSite={}; Path=/",
            self.config.cookie_name,
            token,
            self.config.cookie_secure,
            self.config.cookie_http_only,
            self.config.cookie_same_site
        )
    }

    /// Valide le Double Submit Cookie
    pub fn validate_double_submit(&self, req: &HttpRequest) -> Result<()> {
        let header_token = req.headers()
            .get("X-CSRF-Token")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Authentication("Missing CSRF header token".to_string()))?;

        let cookie_token = self.extract_cookie_token(req)?;

        if header_token != cookie_token {
            return Err(AppError::Authentication("CSRF token mismatch".to_string()));
        }

        Ok(())
    }

    /// Extrait le token du cookie
    fn extract_cookie_token(&self, req: &HttpRequest) -> Result<String> {
        let cookie_header = req.headers()
            .get(header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Authentication("Missing cookie header".to_string()))?;

        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(token) = cookie.strip_prefix(&format!("{}=", self.config.cookie_name)) {
                return Ok(token.to_string());
            }
        }

        Err(AppError::Authentication("CSRF cookie not found".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_token_generation() {
        let service = CsrfProtectionService::new(30, true);
        let token_response = service.generate_token(None).expect("Checked operation");
        
        assert!(!token_response.token.is_empty());
        assert!(token_response.expires_at > Utc::now());
    }

    #[test]
    fn test_csrf_token_validation() {
        let service = CsrfProtectionService::new(30, true);
        let token_response = service.generate_token(None).expect("Checked operation");
        
        // Validation réussie
        assert!(service.validate_token(&token_response.token, None).is_ok());
        
        // Le token ne peut pas être réutilisé
        assert!(service.validate_token(&token_response.token, None).is_err());
    }

    #[test]
    fn test_double_submit_cookie() {
        let config = DoubleSubmitCookieConfig::default();
        let service = DoubleSubmitCookieService::new(config);

        let token = service.generate_double_submit_token().expect("Checked operation");
        assert!(!token.is_empty());

        let cookie = service.create_csrf_cookie(&token);
        assert!(cookie.contains(&token));
        assert!(cookie.contains("Secure=true"));
    }
}
