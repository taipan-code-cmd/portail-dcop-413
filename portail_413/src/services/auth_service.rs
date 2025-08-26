use chrono::{Duration, Utc};
use uuid::Uuid;
use std::net::IpAddr;

use crate::database::UserRepository;
use crate::errors::{AppError, Result};
use crate::models::{CreateUserRequest, LoginRequest, LoginResponse, User, UserResponse, UserRole};
use crate::security::{SecureSessionManager, PasswordService, SecurityLogger, SecurityEventType, SecuritySeverity};
use crate::services::{AuditService, LoginAttemptService};

#[derive(Clone)]
pub struct AuthService {
    user_repository: UserRepository,
    session_manager: SecureSessionManager,
    audit_service: AuditService,
    login_attempt_service: LoginAttemptService,
    max_login_attempts: u32,
    lockout_duration: Duration,
    security_logger: SecurityLogger,
}

impl AuthService {
    pub fn new(
        user_repository: UserRepository,
        session_manager: SecureSessionManager,
        audit_service: AuditService,
        max_login_attempts: u32,
        lockout_duration_seconds: u64,
    ) -> Self {
        Self {
            user_repository,
            session_manager,
            audit_service,
            login_attempt_service: LoginAttemptService::new(
                max_login_attempts,
                max_login_attempts * 2, // Plus strict pour les IPs
                24, // Nettoyage toutes les 24h
            ),
            max_login_attempts,
            lockout_duration: Duration::seconds(lockout_duration_seconds as i64),
            security_logger: SecurityLogger::new(true), // Alertes temps réel activées
        }
    }

    // === Public user management helpers for handlers ===
    pub async fn list_users(&self, limit: i64, offset: i64) -> Result<Vec<User>> {
        self.user_repository.list_users(limit, offset).await
    }

    pub async fn find_user_by_id(&self, id: Uuid) -> Result<Option<User>> {
        self.user_repository.find_by_id(id).await
    }

    pub async fn set_user_active(&self, user_id: Uuid, active: bool) -> Result<User> {
        // Utiliser query_as au lieu de sqlx::query! pour éviter les problèmes SQLX_OFFLINE
        let result = sqlx::query("UPDATE users SET is_active = $1, updated_at = $2 WHERE id = $3")
            .bind(active)
            .bind(chrono::Utc::now())
            .bind(user_id)
            .execute(self.user_repository.get_pool())
            .await
            .map_err(AppError::Database)?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        self.user_repository
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found after update".to_string()))
    }

    pub async fn set_user_role(&self, user_id: Uuid, role: UserRole) -> Result<User> {
        // Utiliser query au lieu de sqlx::query! pour éviter les problèmes SQLX_OFFLINE
        let result = sqlx::query("UPDATE users SET role = $1, updated_at = $2 WHERE id = $3")
            .bind(role as UserRole)
            .bind(chrono::Utc::now())
            .bind(user_id)
            .execute(self.user_repository.get_pool())
            .await
            .map_err(AppError::Database)?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        self.user_repository
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))
    }

    /// Crée un utilisateur admin par défaut s'il n'existe pas
    pub async fn ensure_default_admin(&self) -> Result<()> {
        // Vérifier si un admin existe déjà
        let admin_count = self
            .user_repository
            .find_by_username("admin")
            .await?;

        if admin_count.is_none() {
            // Créer l'utilisateur admin par défaut avec un mot de passe sécurisé
            let admin_request = CreateUserRequest {
                username: "admin".to_string(),
                password: "AdminDCOP2025!@#$".to_string(), // 16 caractères, majuscules, minuscules, chiffres, spéciaux
                role: crate::models::UserRole::Admin,
            };

            self.user_repository.create_user(admin_request).await?;
            tracing::info!("Utilisateur admin par défaut créé avec succès");
        }

        Ok(())
    }

    pub async fn register_user(
        &self,
        request: CreateUserRequest,
        admin_user_id: Option<Uuid>,
    ) -> Result<UserResponse> {
        // Validation complète avec règles de sécurité renforcées
        if let Err(validation_errors) = request.validate_with_security_rules() {
            let error_messages: Vec<String> = validation_errors.iter()
                .map(|e| e.message.clone())
                .collect();
            
            log::info!("SECURITY: Échec de validation du mot de passe: {}", error_messages.join(", "));
            
            return Err(AppError::Validation(format!(
                "Mot de passe non conforme aux règles de sécurité: {}", 
                error_messages.join("; ")
            )));
        }

        // Calculer et logger le score de force du mot de passe
        let password_strength = request.calculate_password_strength();
        tracing::info!("Score de force du mot de passe: {}/100", password_strength);
        
        if password_strength < 70 {
            return Err(AppError::Validation(
                "Le mot de passe est trop faible (score < 70/100). Veuillez utiliser un mot de passe plus robuste.".to_string()
            ));
        }

        // Créer l'utilisateur
        let user = self.user_repository.create_user(request).await?;

        // Enregistrer l'audit
        self.audit_service
            .log_action(
                admin_user_id,
                "CREATE_USER".to_string(),
                "User".to_string(),
                Some(user.id),
                None,
                Some(serde_json::json!({
                    "username": user.username,
                    "role": user.role
                })),
                None,
                None,
                true,
                None,
            )
            .await?;

        Ok(UserResponse::from(user))
    }

    pub async fn login(
        &self,
        request: LoginRequest,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<LoginResponse> {
        // 1. Parser l'IP pour la validation
        let client_ip = ip_address.as_ref()
            .and_then(|ip_str| ip_str.parse::<IpAddr>().ok())
            .unwrap_or_else(|| "127.0.0.1".parse().expect("Failed to parse default IP"));

        // 2. Vérifier si les tentatives sont autorisées (protection brute force)
        if !self.login_attempt_service.can_attempt_login(&request.username, client_ip).await? {
            // Log de sécurité pour tentative bloquée
            self.security_logger.log_security_event(
                SecurityEventType::SuspiciousActivity,
                SecuritySeverity::High,
                None,
                ip_address.clone(),
                user_agent.clone(),
                format!("Login attempt blocked due to too many failures for user '{}' from IP {}", 
                       request.username, client_ip),
                Some("brute_force_blocked".to_string()),
                None,
            )?;

            return Err(AppError::Authentication(
                "Compte temporairement verrouillé en raison de trop de tentatives de connexion. Veuillez réessayer plus tard.".to_string()
            ));
        }

        // 3. Rechercher l'utilisateur
        let user = self
            .user_repository
            .find_by_username(&request.username)
            .await?
            .ok_or_else(|| {
                // Enregistrer la tentative d'accès avec username inexistant
                tokio::spawn({
                    let login_attempt_service = self.login_attempt_service.clone();
                    let username = request.username.clone();
                    let user_agent_clone = user_agent.clone();
                    async move {
                        let _ = login_attempt_service.record_failed_attempt(
                            None, 
                            &username, 
                            client_ip, 
                            user_agent_clone
                        ).await;
                    }
                });
                AppError::Authentication("Identifiants invalides".to_string())
            })?;

        // 4. Vérifier si l'utilisateur est actif
        if !user.is_active {
            // Enregistrer la tentative sur compte inactif
            self.login_attempt_service.record_failed_attempt(
                Some(user.id), 
                &request.username, 
                client_ip, 
                user_agent.clone()
            ).await?;

            // Log de sécurité pour compte désactivé
            self.security_logger.log_security_event(
                SecurityEventType::AuthenticationFailure,
                SecuritySeverity::Medium,
                Some(user.id),
                ip_address.clone(),
                user_agent.clone(),
                format!("Login attempt on disabled account: {}", request.username),
                Some("account_disabled".to_string()),
                None,
            )?;

            return Err(AppError::Authentication("Compte désactivé".to_string()));
        }

        // 5. Vérifier si l'utilisateur est verrouillé (ancien système + nouveau)
        if let Some(locked_until) = user.locked_until {
            if Utc::now() < locked_until {
                // Log de sécurité pour compte verrouillé
                self.security_logger.log_security_event(
                    SecurityEventType::AuthenticationFailure,
                    SecuritySeverity::High,
                    Some(user.id),
                    ip_address.clone(),
                    user_agent.clone(),
                    format!("Login attempt on locked account: {} (locked until {})", request.username, locked_until),
                    Some("account_locked".to_string()),
                    None,
                )?;

                self.audit_service
                    .log_action(
                        Some(user.id),
                        "LOGIN_ATTEMPT".to_string(),
                        "User".to_string(),
                        Some(user.id),
                        None,
                        None,
                        ip_address.clone(),
                        user_agent.clone(),
                        false,
                        Some("Account locked".to_string()),
                    )
                    .await?;

                return Err(AppError::Authentication(
                    format!("Compte verrouillé jusqu'à {}. Contactez un administrateur si nécessaire.", 
                           locked_until.format("%d/%m/%Y %H:%M:%S"))
                ));
            }
        }

        // 6. Vérifier le mot de passe
        let password_valid = PasswordService::verify_password(&request.password, &user.password_hash)?;

        if !password_valid {
            // Enregistrer la tentative échouée avec le nouveau service
            self.login_attempt_service.record_failed_attempt(
                Some(user.id), 
                &request.username, 
                client_ip, 
                user_agent.clone()
            ).await?;

            // Log de sécurité pour mot de passe invalide
            let severity = if user.failed_login_attempts >= (self.max_login_attempts as i32 - 1) {
                SecuritySeverity::High // Proche du verrouillage
            } else {
                SecuritySeverity::Medium
            };

            self.security_logger.log_security_event(
                SecurityEventType::AuthenticationFailure,
                severity,
                Some(user.id),
                ip_address.clone(),
                user_agent.clone(),
                format!("Invalid password for user: {} (attempt {}/{})",
                       request.username,
                       user.failed_login_attempts + 1,
                       self.max_login_attempts),
                Some("invalid_password".to_string()),
                None,
            )?;

            // Incrémenter les tentatives échouées (ancien système)
            self.user_repository.increment_failed_login(user.id).await?;

            // Vérifier si l'utilisateur doit être verrouillé (ancien système)
            if user.failed_login_attempts + 1 >= self.max_login_attempts as i32 {
                let locked_until = Utc::now() + self.lockout_duration;
                self.user_repository.lock_user(user.id, locked_until).await?;

                // Log de sécurité pour verrouillage automatique
                self.security_logger.log_security_event(
                    SecurityEventType::AccountLocked,
                    SecuritySeverity::High,
                    Some(user.id),
                    ip_address.clone(),
                    user_agent.clone(),
                    format!("Account automatically locked after {} failed attempts: {}",
                           self.max_login_attempts, request.username),
                    Some("auto_lock".to_string()),
                    None,
                )?;
            }

            self.audit_service
                .log_action(
                    Some(user.id),
                    "LOGIN_ATTEMPT".to_string(),
                    "User".to_string(),
                    Some(user.id),
                    None,
                    None,
                    ip_address,
                    user_agent,
                    false,
                    Some("Invalid password".to_string()),
                )
                .await?;

            return Err(AppError::Authentication("Identifiants invalides".to_string()));
        }

        // 7. Connexion réussie - Reset des compteurs de tentatives
        self.login_attempt_service.record_successful_login(
            user.id, 
            &request.username, 
            client_ip
        ).await?;

        // Mettre à jour la dernière connexion (ancien système)
        self.user_repository.update_last_login(user.id).await?;

        // Log de sécurité pour connexion réussie
        self.security_logger.log_security_event(
            SecurityEventType::AuthenticationSuccess,
            SecuritySeverity::Low,
            Some(user.id),
            ip_address.clone(),
            user_agent.clone(),
            format!("Successful login for user: {} from IP {}", request.username, client_ip),
            Some("login_success".to_string()),
            None,
        )?;

        // Créer une session sécurisée avec tokens
        let session_result = self.session_manager.create_session(
            user.id,
            user.username.clone(),
            user.role.clone(),
            ip_address.clone(),
            user_agent.clone(),
        )?;

        let token = session_result.access_token;
        let expires_at = session_result.access_token_expires_at;

        // Log de sécurité pour création de session
        self.security_logger.log_security_event(
            SecurityEventType::SessionCreated,
            SecuritySeverity::Low,
            Some(user.id),
            ip_address.clone(),
            user_agent.clone(),
            format!("Session created for user: {} (expires: {})", request.username, expires_at),
            Some("session_created".to_string()),
            None,
        )?;

        // Enregistrer l'audit
        self.audit_service
            .log_action(
                Some(user.id),
                "LOGIN_SUCCESS".to_string(),
                "User".to_string(),
                Some(user.id),
                None,
                None,
                ip_address,
                user_agent,
                true,
                None,
            )
            .await?;

        Ok(LoginResponse {
            token,
            user: UserResponse::from(user),
            expires_at,
        })
    }

    pub async fn validate_token(&self, token: &str) -> Result<User> {
        let claims = self.session_manager.validate_access_token(token)?;

        let user = self
            .user_repository
            .find_by_id(claims.sub)
            .await?
            .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

        if !user.is_active {
            return Err(AppError::Authentication("Account disabled".to_string()));
        }

        // Vérifier si l'utilisateur est verrouillé
        if let Some(locked_until) = user.locked_until {
            if Utc::now() < locked_until {
                return Err(AppError::Authentication("Account temporarily locked".to_string()));
            }
        }

        Ok(user)
    }

    pub async fn logout(
        &self,
        user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<()> {
        // Enregistrer l'audit
        self.audit_service
            .log_action(
                Some(user_id),
                "LOGOUT".to_string(),
                "User".to_string(),
                Some(user_id),
                None,
                None,
                ip_address,
                user_agent,
                true,
                None,
            )
            .await?;

        Ok(())
    }

    /// Débloquer manuellement un utilisateur (pour les administrateurs)
    pub async fn unlock_user(&self, username: &str, admin_user_id: Uuid) -> Result<bool> {
        // Débloquer dans le nouveau système
        let unlocked_new = self.login_attempt_service.unlock_user(username, admin_user_id).await?;
        
        // Débloquer dans l'ancien système (base de données)
        let unlocked_old = self.user_repository.unlock_user_by_username(username).await?;
        
        Ok(unlocked_new || unlocked_old)
    }

    /// Débloquer manuellement une IP (pour les administrateurs)
    pub async fn unlock_ip(&self, ip_str: &str, admin_user_id: Uuid) -> Result<bool> {
        let ip: IpAddr = ip_str.parse()
            .map_err(|_| AppError::Validation("Invalid IP address format".to_string()))?;
        
        self.login_attempt_service.unlock_ip(ip, admin_user_id).await
    }

    /// Obtenir les statistiques des tentatives de connexion
    pub async fn get_login_attempt_statistics(&self) -> std::collections::HashMap<String, serde_json::Value> {
        self.login_attempt_service.get_attempt_statistics().await
    }

    /// Nettoyer les tentatives expirées (à appeler périodiquement)
    pub async fn cleanup_expired_attempts(&self) -> Result<usize> {
        self.login_attempt_service.cleanup_expired_attempts().await
    }

    /// Obtenir la politique de mot de passe actuelle
    pub fn get_password_policy() -> std::collections::HashMap<String, serde_json::Value> {
        let mut policy = std::collections::HashMap::new();
        
        policy.insert("min_length".to_string(), serde_json::json!(12));
        policy.insert("max_length".to_string(), serde_json::json!(128));
        policy.insert("require_uppercase".to_string(), serde_json::json!(true));
        policy.insert("require_lowercase".to_string(), serde_json::json!(true));
        policy.insert("require_digits".to_string(), serde_json::json!(true));
        policy.insert("require_special_chars".to_string(), serde_json::json!(true));
        policy.insert("check_compromised_passwords".to_string(), serde_json::json!(true));
        policy.insert("prevent_keyboard_sequences".to_string(), serde_json::json!(true));
        policy.insert("prevent_repetitive_patterns".to_string(), serde_json::json!(true));
        policy.insert("min_complexity_score".to_string(), serde_json::json!(60));
        
        policy
    }

    /// Valider un mot de passe selon les politiques strictes
    pub fn validate_password_policy(password: &str) -> Result<std::collections::HashMap<String, serde_json::Value>> {
        // Utiliser le service de validation des mots de passe
        match PasswordService::validate_password_strength(password) {
            Ok(_) => {
                let mut result = std::collections::HashMap::new();
                result.insert("valid".to_string(), serde_json::json!(true));
                result.insert("score".to_string(), serde_json::json!(
                    PasswordService::calculate_complexity_score(password)
                ));
                result.insert("message".to_string(), serde_json::json!(
                    "Mot de passe conforme aux politiques de sécurité"
                ));
                Ok(result)
            },
            Err(e) => {
                let mut result = std::collections::HashMap::new();
                result.insert("valid".to_string(), serde_json::json!(false));
                result.insert("score".to_string(), serde_json::json!(
                    PasswordService::calculate_complexity_score(password)
                ));
                result.insert("message".to_string(), serde_json::json!(e.to_string()));
                Ok(result)
            }
        }
    }
}
