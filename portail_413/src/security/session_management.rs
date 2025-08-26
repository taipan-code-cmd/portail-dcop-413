use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::errors::{AppError, Result};
use crate::models::UserRole;

/// Service de gestion des sessions JWT sécurisé avec refresh tokens
#[derive(Clone)]
pub struct SecureSessionManager {
    access_token_secret: String,
    refresh_token_secret: String,
    access_token_lifetime: Duration,
    refresh_token_lifetime: Duration,
    revoked_tokens: Arc<Mutex<HashSet<String>>>,
    active_sessions: Arc<Mutex<HashMap<Uuid, SessionInfo>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: Uuid,           // User ID
    pub username: String,
    pub role: UserRole,
    pub exp: i64,           // Expiration timestamp
    pub iat: i64,           // Issued at timestamp
    pub jti: String,        // JWT ID (pour révocation)
    pub session_id: Uuid,   // ID de session
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: Uuid,          // User ID
    pub session_id: Uuid,   // ID de session
    pub exp: i64,           // Expiration timestamp
    pub iat: i64,           // Issued at timestamp
    pub jti: String,        // JWT ID (pour révocation)
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub is_active: bool,
}

#[derive(Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_expires_at: DateTime<Utc>,
    pub refresh_token_expires_at: DateTime<Utc>,
    pub session_id: Uuid,
}

impl SecureSessionManager {
    /// Crée un nouveau gestionnaire de sessions sécurisé
    /// Les secrets doivent être d'au moins 256 bits (32 caractères) selon OWASP
    pub fn new(
        access_token_secret: String,
        refresh_token_secret: String,
        access_token_lifetime_minutes: i64,
        refresh_token_lifetime_days: i64,
    ) -> Self {
        // Validation de la force des secrets selon OWASP
        if access_token_secret.len() < 32 {
            tracing::error!("Access token secret is too weak (< 256 bits) - SECURITY RISK");
        }
        if refresh_token_secret.len() < 32 {
            tracing::error!("Refresh token secret is too weak (< 256 bits) - SECURITY RISK");
        }

        Self {
            access_token_secret,
            refresh_token_secret,
            access_token_lifetime: Duration::minutes(access_token_lifetime_minutes),
            refresh_token_lifetime: Duration::days(refresh_token_lifetime_days),
            revoked_tokens: Arc::new(Mutex::new(HashSet::new())),
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Crée un gestionnaire depuis les variables d'environnement sécurisées
    /// Conforme aux principes Secure-by-Design
    pub fn from_env() -> crate::errors::Result<Self> {
        use crate::config::read_secret_or_env;

        let access_secret = read_secret_or_env("JWT_SECRET_FILE", "JWT_SECRET")
            .map_err(|e| crate::errors::AppError::Configuration(format!("JWT secret not found: {}", e)))?;

        let refresh_secret = read_secret_or_env("JWT_REFRESH_SECRET_FILE", "JWT_REFRESH_SECRET")
            .unwrap_or_else(|_| {
                tracing::warn!("JWT_REFRESH_SECRET not found, using JWT_SECRET (not recommended)");
                access_secret.clone()
            });

        // Durées conformes aux recommandations OWASP
        let access_lifetime = std::env::var("JWT_ACCESS_LIFETIME_MINUTES")
            .unwrap_or_else(|_| "15".to_string()) // 15 minutes par défaut
            .parse::<i64>()
            .unwrap_or(15);

        let refresh_lifetime = std::env::var("JWT_REFRESH_LIFETIME_DAYS")
            .unwrap_or_else(|_| "7".to_string()) // 7 jours par défaut
            .parse::<i64>()
            .unwrap_or(7);

        Ok(Self::new(access_secret, refresh_secret, access_lifetime, refresh_lifetime))
    }

    /// Crée une nouvelle session avec tokens d'accès et de rafraîchissement
    pub fn create_session(
        &self,
        user_id: Uuid,
        username: String,
        role: UserRole,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<TokenPair> {
        let now = Utc::now();
        let session_id = Uuid::new_v4();
        let access_jti = Uuid::new_v4().to_string();
        let refresh_jti = Uuid::new_v4().to_string();

        let access_expires_at = now + self.access_token_lifetime;
        let refresh_expires_at = now + self.refresh_token_lifetime;

        // Créer les claims pour l'access token
        let access_claims = AccessTokenClaims {
            sub: user_id,
            username,
            role,
            exp: access_expires_at.timestamp(),
            iat: now.timestamp(),
            jti: access_jti,
            session_id,
        };

        // Créer les claims pour le refresh token
        let refresh_claims = RefreshTokenClaims {
            sub: user_id,
            session_id,
            exp: refresh_expires_at.timestamp(),
            iat: now.timestamp(),
            jti: refresh_jti,
        };

        // Encoder les tokens
        let access_token = encode(
            &Header::default(),
            &access_claims,
            &EncodingKey::from_secret(self.access_token_secret.as_ref()),
        ).map_err(|e| AppError::Internal(format!("Failed to create access token: {}", e)))?;

        let refresh_token = encode(
            &Header::default(),
            &refresh_claims,
            &EncodingKey::from_secret(self.refresh_token_secret.as_ref()),
        ).map_err(|e| AppError::Internal(format!("Failed to create refresh token: {}", e)))?;

        // Enregistrer la session
        let session_info = SessionInfo {
            user_id,
            session_id,
            created_at: now,
            last_activity: now,
            ip_address,
            user_agent,
            is_active: true,
        };

        let mut sessions = self.active_sessions.lock()
            .map_err(|_| AppError::Internal("Failed to acquire sessions lock".to_string()))?;

        // Limiter le nombre de sessions par utilisateur (max 5)
        self.cleanup_user_sessions(&mut sessions, user_id, 5);

        sessions.insert(session_id, session_info);

        tracing::info!("New session created for user {} with session ID {}", user_id, session_id);

        Ok(TokenPair {
            access_token,
            refresh_token,
            access_token_expires_at: access_expires_at,
            refresh_token_expires_at: refresh_expires_at,
            session_id,
        })
    }

    /// Valide un access token
    pub fn validate_access_token(&self, token: &str) -> Result<AccessTokenClaims> {
        // Vérifier si le token est révoqué
        let revoked_tokens = self.revoked_tokens.lock()
            .map_err(|_| AppError::Internal("Failed to acquire revoked tokens lock".to_string()))?;

        let validation = Validation::default();
        let token_data = decode::<AccessTokenClaims>(
            token,
            &DecodingKey::from_secret(self.access_token_secret.as_ref()),
            &validation,
        ).map_err(|e| AppError::Authentication(format!("Invalid access token: {}", e)))?;

        // Vérifier si le token est révoqué
        if revoked_tokens.contains(&token_data.claims.jti) {
            return Err(AppError::Authentication("Token has been revoked".to_string()));
        }

        // Vérifier si la session est active
        let sessions = self.active_sessions.lock()
            .map_err(|_| AppError::Internal("Failed to acquire sessions lock".to_string()))?;

        if let Some(session) = sessions.get(&token_data.claims.session_id) {
            if !session.is_active {
                return Err(AppError::Authentication("Session is not active".to_string()));
            }
        } else {
            return Err(AppError::Authentication("Session not found".to_string()));
        }

        Ok(token_data.claims)
    }

    /// Rafraîchit un access token en utilisant un refresh token
    pub fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair> {
        let validation = Validation::default();
        let token_data = decode::<RefreshTokenClaims>(
            refresh_token,
            &DecodingKey::from_secret(self.refresh_token_secret.as_ref()),
            &validation,
        ).map_err(|e| AppError::Authentication(format!("Invalid refresh token: {}", e)))?;

        // Vérifier si le refresh token est révoqué
        let revoked_tokens = self.revoked_tokens.lock()
            .map_err(|_| AppError::Internal("Failed to acquire revoked tokens lock".to_string()))?;

        if revoked_tokens.contains(&token_data.claims.jti) {
            return Err(AppError::Authentication("Refresh token has been revoked".to_string()));
        }
        drop(revoked_tokens);

        // Récupérer les informations de session
        let mut sessions = self.active_sessions.lock()
            .map_err(|_| AppError::Internal("Failed to acquire sessions lock".to_string()))?;

        let session = sessions.get_mut(&token_data.claims.session_id)
            .ok_or_else(|| AppError::Authentication("Session not found".to_string()))?;

        if !session.is_active {
            return Err(AppError::Authentication("Session is not active".to_string()));
        }

        // Mettre à jour l'activité de la session
        session.last_activity = Utc::now();

        // Récupérer les informations utilisateur (vous devrez adapter selon votre implémentation)
        let user_id = session.user_id;
        let username = format!("user_{}", user_id); // À adapter selon votre base de données
        let role = UserRole::User; // À adapter selon votre base de données
        let ip_address = session.ip_address.clone();
        let user_agent = session.user_agent.clone();

        drop(sessions);

        // Créer de nouveaux tokens
        self.create_session(
            user_id,
            username,
            role,
            ip_address,
            user_agent,
        )
    }

    /// Révoque un token spécifique
    pub fn revoke_token(&self, jti: &str) -> Result<()> {
        let mut revoked_tokens = self.revoked_tokens.lock()
            .map_err(|_| AppError::Internal("Failed to acquire revoked tokens lock".to_string()))?;

        revoked_tokens.insert(jti.to_string());
        tracing::info!("Token revoked: {}", jti);

        Ok(())
    }

    /// Nettoie les tokens révoqués expirés pour optimiser la mémoire
    /// Conforme aux bonnes pratiques de gestion de session OWASP
    pub fn cleanup_expired_revoked_tokens(&self) -> Result<usize> {
        let mut revoked_tokens = self.revoked_tokens.lock()
            .map_err(|_| AppError::Internal("Failed to acquire revoked tokens lock".to_string()))?;

        let initial_count = revoked_tokens.len();

        // Pour une implémentation complète, nous aurions besoin de stocker les timestamps
        // des tokens révoqués. Pour l'instant, nous gardons une limite de taille
        const MAX_REVOKED_TOKENS: usize = 10000;

        if revoked_tokens.len() > MAX_REVOKED_TOKENS {
            // Garder seulement les tokens les plus récents (approximation)
            let tokens_to_keep: HashSet<String> = revoked_tokens
                .iter()
                .take(MAX_REVOKED_TOKENS / 2)
                .cloned()
                .collect();

            *revoked_tokens = tokens_to_keep;

            let cleaned_count = initial_count - revoked_tokens.len();
            tracing::info!("Cleaned {} expired revoked tokens", cleaned_count);

            Ok(cleaned_count)
        } else {
            Ok(0)
        }
    }

    /// Révoque toutes les sessions d'un utilisateur
    pub fn revoke_user_sessions(&self, user_id: Uuid) -> Result<()> {
        let mut sessions = self.active_sessions.lock()
            .map_err(|_| AppError::Internal("Failed to acquire sessions lock".to_string()))?;

        let mut revoked_count = 0;
        for session in sessions.values_mut() {
            if session.user_id == user_id && session.is_active {
                session.is_active = false;
                revoked_count += 1;
            }
        }

        tracing::info!("Revoked {} sessions for user {}", revoked_count, user_id);
        Ok(())
    }

    /// Révoque une session spécifique
    pub fn revoke_session(&self, session_id: Uuid) -> Result<()> {
        let mut sessions = self.active_sessions.lock()
            .map_err(|_| AppError::Internal("Failed to acquire sessions lock".to_string()))?;

        if let Some(session) = sessions.get_mut(&session_id) {
            session.is_active = false;
            tracing::info!("Session revoked: {}", session_id);
        }

        Ok(())
    }

    /// Force l'expiration immédiate de toutes les sessions d'un utilisateur
    /// Utile en cas de compromission de compte - Conforme OWASP
    pub fn force_expire_user_sessions(&self, user_id: Uuid) -> Result<usize> {
        let mut sessions = self.active_sessions.lock()
            .map_err(|_| AppError::Internal("Failed to acquire sessions lock".to_string()))?;

        let mut expired_count = 0;

        // Marquer toutes les sessions de l'utilisateur comme inactives
        for (session_id, session) in sessions.iter_mut() {
            if session.user_id == user_id && session.is_active {
                session.is_active = false;
                expired_count += 1;
                tracing::warn!("Force expired session {} for user {}", session_id, user_id);
            }
        }

        tracing::warn!("Force expired {} sessions for user {}", expired_count, user_id);
        Ok(expired_count)
    }

    /// Limite le nombre de sessions par utilisateur
    fn cleanup_user_sessions(&self, sessions: &mut HashMap<Uuid, SessionInfo>, user_id: Uuid, max_sessions: usize) {
        let user_sessions: Vec<_> = sessions
            .iter()
            .filter(|(_, session)| session.user_id == user_id && session.is_active)
            .map(|(session_id, session)| (*session_id, session.created_at))
            .collect();

        if user_sessions.len() >= max_sessions {
            // Trier par date de création (plus ancien en premier)
            let mut sorted_sessions = user_sessions;
            sorted_sessions.sort_by(|a, b| a.1.cmp(&b.1));

            // Supprimer les sessions les plus anciennes
            let sessions_to_remove = sorted_sessions.len() - max_sessions + 1;
            for (session_id, _) in sorted_sessions.iter().take(sessions_to_remove) {
                if let Some(session) = sessions.get_mut(session_id) {
                    session.is_active = false;
                    tracing::info!("Deactivated old session {} for user {} (session limit reached)", session_id, user_id);
                }
            }
        }
    }

    /// Nettoie les sessions expirées
    pub fn cleanup_expired_sessions(&self) -> Result<usize> {
        let now = Utc::now();
        let mut sessions = self.active_sessions.lock()
            .map_err(|_| AppError::Internal("Failed to acquire sessions lock".to_string()))?;

        let initial_count = sessions.len();
        
        // Supprimer les sessions expirées (inactives depuis plus de 7 jours)
        let cutoff_time = now - Duration::days(7);
        sessions.retain(|_, session| {
            session.last_activity > cutoff_time && session.is_active
        });

        let cleaned_count = initial_count - sessions.len();
        
        if cleaned_count > 0 {
            tracing::info!("Cleaned up {} expired sessions", cleaned_count);
        }

        Ok(cleaned_count)
    }

    /// Extrait le token JWT de l'en-tête Authorization
    pub fn extract_token_from_header(auth_header: &str) -> Result<&str> {
        if !auth_header.starts_with("Bearer ") {
            return Err(AppError::Authentication("Invalid authorization header format".to_string()));
        }

        let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
        if token.is_empty() {
            return Err(AppError::Authentication("Empty token in authorization header".to_string()));
        }

        Ok(token)
    }

    /// Obtient les statistiques des sessions
    pub fn get_session_stats(&self) -> Result<SessionStats> {
        let sessions = self.active_sessions.lock()
            .map_err(|_| AppError::Internal("Failed to acquire sessions lock".to_string()))?;

        let revoked_tokens = self.revoked_tokens.lock()
            .map_err(|_| AppError::Internal("Failed to acquire revoked tokens lock".to_string()))?;

        let total_sessions = sessions.len();
        let active_sessions = sessions.values().filter(|s| s.is_active).count();
        let inactive_sessions = total_sessions - active_sessions;
        let revoked_tokens_count = revoked_tokens.len();

        Ok(SessionStats {
            total_sessions,
            active_sessions,
            inactive_sessions,
            revoked_tokens_count,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct SessionStats {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub inactive_sessions: usize,
    pub revoked_tokens_count: usize,
}

impl Default for SecureSessionManager {
    fn default() -> Self {
        // ⚠️ ATTENTION: Default uniquement pour les tests
        // En production, utilisez SecureSessionManager::from_env() ou new() avec des secrets forts
        tracing::warn!("Using default SecureSessionManager - NOT FOR PRODUCTION");

        Self::new(
            "dev_access_secret_minimum_256_bits_for_development_only_change_in_production".to_string(),
            "dev_refresh_secret_minimum_256_bits_for_development_only_change_in_production".to_string(),
            15, // 15 minutes pour l'access token (conforme OWASP)
            7,  // 7 jours pour le refresh token
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let manager = SecureSessionManager::default();
        let user_id = Uuid::new_v4();
        
        let token_pair = manager.create_session(
            user_id,
            "test_user".to_string(),
            UserRole::User,
            Some("127.0.0.1".to_string()),
            Some("test-agent".to_string()),
        ).expect("Checked operation");

        assert!(!token_pair.access_token.is_empty());
        assert!(!token_pair.refresh_token.is_empty());
        assert!(token_pair.access_token_expires_at > Utc::now());
    }

    #[test]
    fn test_token_validation() {
        let manager = SecureSessionManager::default();
        let user_id = Uuid::new_v4();
        
        let token_pair = manager.create_session(
            user_id,
            "test_user".to_string(),
            UserRole::User,
            None,
            None,
        ).expect("Checked operation");

        let claims = manager.validate_access_token(&token_pair.access_token).expect("Checked operation");
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.username, "test_user");
    }

    #[test]
    fn test_token_revocation() {
        let manager = SecureSessionManager::default();
        let user_id = Uuid::new_v4();
        
        let token_pair = manager.create_session(
            user_id,
            "test_user".to_string(),
            UserRole::User,
            None,
            None,
        ).expect("Checked operation");

        let claims = manager.validate_access_token(&token_pair.access_token).expect("Checked operation");
        manager.revoke_token(&claims.jti).expect("Checked operation");

        // Le token devrait maintenant être invalide
        assert!(manager.validate_access_token(&token_pair.access_token).is_err());
    }
}
