use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use crate::security::password_validation::{PasswordValidator, PasswordValidationError};

// Suppression de Debug pour éviter l'exposition de données sensibles (password_hash)
#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String, // Sensible - ne pas logger
    pub role: UserRole,
    pub is_active: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub integrity_hash: String, // Sensible - ne pas logger
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "director")]
    Director,
    #[serde(rename = "user")]
    User,
}

// Suppression de Debug pour éviter l'exposition de mots de passe en logs
#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String, // Sensible - ne pas logger
    pub role: UserRole,
}

impl CreateUserRequest {
    /// Validation complète avec règles de sécurité renforcées
    pub fn validate_with_security_rules(&self) -> Result<(), Vec<PasswordValidationError>> {
        let mut errors = Vec::new();
        
        // Validation du nom d'utilisateur
        if self.username.trim().is_empty() {
            errors.push(PasswordValidationError {
                message: "Le nom d'utilisateur ne peut pas être vide".to_string(),
                code: "EMPTY_USERNAME".to_string(),
            });
        } else if self.username.len() < 3 {
            errors.push(PasswordValidationError {
                message: "Le nom d'utilisateur doit contenir au moins 3 caractères".to_string(),
                code: "USERNAME_TOO_SHORT".to_string(),
            });
        } else if self.username.len() > 50 {
            errors.push(PasswordValidationError {
                message: "Le nom d'utilisateur ne peut pas dépasser 50 caractères".to_string(),
                code: "USERNAME_TOO_LONG".to_string(),
            });
        }
        
        // Valider le mot de passe avec les règles de sécurité
        if let Err(password_errors) = PasswordValidator::validate_user_password(&self.password, &self.username) {
            errors.extend(password_errors);
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
    
    /// Calcule le score de force du mot de passe
    pub fn calculate_password_strength(&self) -> u8 {
        PasswordValidator::calculate_strength_score(&self.password)
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String, // Sensible - ne pas logger
}

impl LoginRequest {
    pub fn validate(&self) -> Result<(), Vec<PasswordValidationError>> {
        let mut errors = Vec::new();
        
        if self.username.trim().is_empty() {
            errors.push(PasswordValidationError {
                message: "Le nom d'utilisateur ne peut pas être vide".to_string(),
                code: "EMPTY_USERNAME".to_string(),
            });
        }
        
        if self.password.is_empty() {
            errors.push(PasswordValidationError {
                message: "Le mot de passe ne peut pas être vide".to_string(),
                code: "EMPTY_PASSWORD".to_string(),
            });
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub role: UserRole,
    pub status: String, // "Active", "Inactive", ou "Locked"
    pub is_active: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserResponse,
    pub expires_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        let status = if user.locked_until.is_some() && user.locked_until.expect("Checked operation") > Utc::now() {
            "Locked".to_string()
        } else if user.is_active {
            "Active".to_string()
        } else {
            "Inactive".to_string()
        };

        Self {
            id: user.id,
            username: user.username,
            role: user.role,
            status,
            is_active: user.is_active,
            last_login: user.last_login,
            created_at: user.created_at,
        }
    }
}
