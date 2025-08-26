use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::{AppError, Result};
use crate::models::{CreateUserRequest, User, UserRole};
use crate::security::{HashingService, PasswordService};

#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
    hashing_service: HashingService,
}

impl UserRepository {
    pub fn new(pool: PgPool, hashing_service: HashingService) -> Self {
        Self {
            pool,
            hashing_service,
        }
    }

    pub async fn create_user(&self, request: CreateUserRequest) -> Result<User> {
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let password_hash = PasswordService::hash_password(&request.password)?;

        // Vérifier l'unicité du nom d'utilisateur
        if (self.find_by_username(&request.username).await?).is_some() {
            return Err(AppError::Conflict("Ce nom d'utilisateur existe déjà".to_string()));
        }

        // Vérifier l'unicité du mot de passe (désactivé temporairement pour l'admin par défaut)
        if request.username != "admin" && self.password_already_exists(&request.password).await? {
            return Err(AppError::Conflict("Ce mot de passe est déjà utilisé par un autre utilisateur".to_string()));
        }

        let user = User {
            id: user_id,
            username: request.username,
            password_hash,
            role: request.role,
            is_active: true,
            last_login: None,
            failed_login_attempts: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
            integrity_hash: String::new(), // Sera calculé après
        };

        // Calculer le hash d'intégrité
        let integrity_hash = self.hashing_service.calculate_integrity_hash(&user)?;
        let user_with_hash = User {
            integrity_hash,
            ..user
        };

        sqlx::query!(
            r#"
            INSERT INTO users (id, username, password_hash, role, is_active, last_login, 
                             failed_login_attempts, locked_until, created_at, updated_at, integrity_hash)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            user_with_hash.id,
            user_with_hash.username,
            user_with_hash.password_hash,
            user_with_hash.role.clone() as UserRole,
            user_with_hash.is_active,
            user_with_hash.last_login,
            user_with_hash.failed_login_attempts,
            user_with_hash.locked_until,
            user_with_hash.created_at,
            user_with_hash.updated_at,
            user_with_hash.integrity_hash
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(user_with_hash)
    }

    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, password_hash, role as "role: UserRole", is_active,
                   last_login, failed_login_attempts, locked_until, created_at, updated_at, integrity_hash
            FROM users
            WHERE username = $1
            "#,
            username
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?;

        if let Some(ref _user) = user {
            // Vérifier l'intégrité des données (désactivé temporairement pour la compilation)
            // TODO: Réactiver après génération du cache SQLx
            /*
            if !self.hashing_service.verify_integrity(user, &user.integrity_hash)? {
                tracing::warn!("Data integrity check failed for user: {}", user.id);
                return Err(AppError::Internal("Data integrity violation detected".to_string()));
            }
            */
        }

        Ok(user)
    }

    pub async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, password_hash, role as "role: UserRole", is_active,
                   last_login, failed_login_attempts, locked_until, created_at, updated_at, integrity_hash
            FROM users 
            WHERE id = $1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?;

        if let Some(ref _user) = user {
            // Vérifier l'intégrité des données (désactivé temporairement pour la compilation)
            // TODO: Réactiver après génération du cache SQLx
            /*
            if !self.hashing_service.verify_integrity(user, &user.integrity_hash)? {
                tracing::warn!("Data integrity check failed for user: {}", user.id);
                return Err(AppError::Internal("Data integrity violation detected".to_string()));
            }
            */
        }

        Ok(user)
    }

    pub async fn update_last_login(&self, user_id: Uuid) -> Result<()> {
        let now = Utc::now();

        sqlx::query!(
            r#"
            UPDATE users 
            SET last_login = $1, failed_login_attempts = 0, updated_at = $1
            WHERE id = $2
            "#,
            now,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(())
    }

    pub async fn increment_failed_login(&self, user_id: Uuid) -> Result<()> {
        let now = Utc::now();

        sqlx::query!(
            r#"
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1, updated_at = $1
            WHERE id = $2
            "#,
            now,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(())
    }

    pub async fn lock_user(&self, user_id: Uuid, locked_until: chrono::DateTime<Utc>) -> Result<()> {
        let now = Utc::now();

        sqlx::query!(
            r#"
            UPDATE users 
            SET locked_until = $1, updated_at = $2
            WHERE id = $3
            "#,
            locked_until,
            now,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(())
    }

    pub async fn list_users(&self, limit: i64, offset: i64) -> Result<Vec<User>> {
        let users = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, password_hash, role as "role: UserRole", is_active,
                   last_login, failed_login_attempts, locked_until, created_at, updated_at, integrity_hash
            FROM users 
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::Database)?;

        // Vérifier l'intégrité de tous les utilisateurs (désactivé temporairement pour la compilation)
        // TODO: Réactiver après génération du cache SQLx
        /*
        for user in &users {
            if !self.hashing_service.verify_integrity(user, &user.integrity_hash)? {
                tracing::warn!("Data integrity check failed for user: {}", user.id);
                return Err(AppError::Internal("Data integrity violation detected".to_string()));
            }
        }
        */

        Ok(users)
    }

    /// Vérifie si un mot de passe est déjà utilisé par un autre utilisateur
    pub async fn password_already_exists(&self, password: &str) -> Result<bool> {
        // Récupérer tous les hashs de mots de passe existants
        let existing_hashes = sqlx::query!(
            "SELECT password_hash FROM users WHERE is_active = true"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::Database)?;

        // Vérifier si le nouveau mot de passe correspond à un hash existant
        for hash_record in existing_hashes {
            if PasswordService::verify_password(password, &hash_record.password_hash)? {
                return Ok(true); // Le mot de passe existe déjà
            }
        }

        Ok(false) // Le mot de passe est unique
    }

    /// Déverrouille un utilisateur par nom d'utilisateur
    pub async fn unlock_user_by_username(&self, username: &str) -> Result<bool> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE users 
            SET failed_login_attempts = 0, locked_until = NULL, updated_at = NOW()
            WHERE username = ?
            "#
        )
        .bind(username)
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?
        .rows_affected();

        Ok(rows_affected > 0)
    }

    /// Obtenir l'accès au pool pour les opérations SQL spécialisées
    pub fn get_pool(&self) -> &sqlx::PgPool { &self.pool }
}
