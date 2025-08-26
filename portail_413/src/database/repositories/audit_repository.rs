use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;
use sqlx::types::ipnetwork::IpNetwork;

use crate::{
    errors::{AppError, Result},
    models::{AuditLog, AuditSearchQuery, CreateAuditRequest},
};

#[derive(Clone)]
pub struct AuditRepository {
    pool: PgPool,
}

impl AuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_audit_log(
        &self,
        request: CreateAuditRequest,
    ) -> Result<AuditLog> {
        let audit_id = Uuid::new_v4();
        let timestamp = Utc::now();

        let ip_addr: Option<IpNetwork> = request.ip_address
            .as_ref()
            .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
            .map(IpNetwork::from);

        let audit_log = AuditLog {
            id: audit_id,
            user_id: request.user_id,
            action: request.action.clone(),
            resource_type: request.resource_type.clone(),
            resource_id: request.resource_id,
            old_values: request.old_values.clone(),
            new_values: request.new_values.clone(),
            ip_address: ip_addr,
            user_agent: request.user_agent.clone(),
            timestamp,
            success: request.success,
            error_message: request.error_message.clone(),
        };

        sqlx::query!(
            r#"
            INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, 
                                  old_values, new_values, ip_address, user_agent, 
                                  timestamp, success, error_message)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
            audit_id,
            request.user_id,
            request.action,
            request.resource_type,
            request.resource_id,
            request.old_values,
            request.new_values,
            ip_addr,
            request.user_agent,
            timestamp,
            request.success,
            request.error_message
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(audit_log)
    }

    /// ✅ FONCTION SÉCURISÉE - CORRECTION VULNÉRABILITÉ SQL INJECTION
    /// Utilise exclusivement des requêtes préparées pour éviter les injections SQL
    /// Conforme aux recommandations OWASP et standards de sécurité
    pub async fn search_audit_logs(&self, query: AuditSearchQuery) -> Result<Vec<AuditLog>> {
        let limit = query.limit.unwrap_or(50).min(1000); // Max 1000 résultats
        let offset = query.offset.unwrap_or(0);

        // Utilisation de requêtes préparées spécifiques selon les critères de recherche
        // Aucune construction SQL dynamique pour éliminer le risque d'injection
        
        match (query.user_id, query.action.as_deref(), query.resource_type.as_deref(), query.success) {
            // Cas 1: Recherche par utilisateur uniquement
            (Some(user_id), None, None, None) => {
                sqlx::query_as!(
                    AuditLog,
                    r#"
                    SELECT id, user_id, action, resource_type, resource_id,
                           old_values, new_values, ip_address, user_agent,
                           timestamp, success, error_message
                    FROM audit_logs
                    WHERE user_id = $1
                    ORDER BY timestamp DESC
                    LIMIT $2 OFFSET $3
                    "#,
                    user_id,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(Into::into)
            },
            
            // Cas 2: Recherche par action uniquement
            (None, Some(action), None, None) => {
                sqlx::query_as!(
                    AuditLog,
                    r#"
                    SELECT id, user_id, action, resource_type, resource_id,
                           old_values, new_values, ip_address, user_agent,
                           timestamp, success, error_message
                    FROM audit_logs
                    WHERE action = $1
                    ORDER BY timestamp DESC
                    LIMIT $2 OFFSET $3
                    "#,
                    action,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(Into::into)
            },
            
            // Cas 3: Recherche par resource_type uniquement
            (None, None, Some(resource_type), None) => {
                sqlx::query_as!(
                    AuditLog,
                    r#"
                    SELECT id, user_id, action, resource_type, resource_id,
                           old_values, new_values, ip_address, user_agent,
                           timestamp, success, error_message
                    FROM audit_logs
                    WHERE resource_type = $1
                    ORDER BY timestamp DESC
                    LIMIT $2 OFFSET $3
                    "#,
                    resource_type,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(Into::into)
            },
            
            // Cas 4: Recherche combinée (user_id + action)
            (Some(user_id), Some(action), None, None) => {
                sqlx::query_as!(
                    AuditLog,
                    r#"
                    SELECT id, user_id, action, resource_type, resource_id,
                           old_values, new_values, ip_address, user_agent,
                           timestamp, success, error_message
                    FROM audit_logs
                    WHERE user_id = $1 AND action = $2
                    ORDER BY timestamp DESC
                    LIMIT $3 OFFSET $4
                    "#,
                    user_id,
                    action,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(Into::into)
            },
            
            // Cas 5: Recherche combinée avec filtre succès
            (Some(user_id), Some(action), Some(resource_type), Some(success)) => {
                sqlx::query_as!(
                    AuditLog,
                    r#"
                    SELECT id, user_id, action, resource_type, resource_id,
                           old_values, new_values, ip_address, user_agent,
                           timestamp, success, error_message
                    FROM audit_logs
                    WHERE user_id = $1 AND action = $2 AND resource_type = $3 AND success = $4
                    ORDER BY timestamp DESC
                    LIMIT $5 OFFSET $6
                    "#,
                    user_id,
                    action,
                    resource_type,
                    success,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(Into::into)
            },
            
            // Cas 6: Recherche combinée complète (sans filtre succès)
            (Some(user_id), Some(action), Some(resource_type), None) => {
                sqlx::query_as!(
                    AuditLog,
                    r#"
                    SELECT id, user_id, action, resource_type, resource_id,
                           old_values, new_values, ip_address, user_agent,
                           timestamp, success, error_message
                    FROM audit_logs
                    WHERE user_id = $1 AND action = $2 AND resource_type = $3
                    ORDER BY timestamp DESC
                    LIMIT $4 OFFSET $5
                    "#,
                    user_id,
                    action,
                    resource_type,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(Into::into)
            },
            
            // Cas 7: Recherche par succès uniquement
            (None, None, None, Some(success)) => {
                sqlx::query_as!(
                    AuditLog,
                    r#"
                    SELECT id, user_id, action, resource_type, resource_id,
                           old_values, new_values, ip_address, user_agent,
                           timestamp, success, error_message
                    FROM audit_logs
                    WHERE success = $1
                    ORDER BY timestamp DESC
                    LIMIT $2 OFFSET $3
                    "#,
                    success,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(Into::into)
            },
            
            // Cas par défaut: tous les logs (aucun filtre spécifique)
            _ => {
                sqlx::query_as!(
                    AuditLog,
                    r#"
                    SELECT id, user_id, action, resource_type, resource_id,
                           old_values, new_values, ip_address, user_agent,
                           timestamp, success, error_message
                    FROM audit_logs
                    ORDER BY timestamp DESC
                    LIMIT $1 OFFSET $2
                    "#,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await
                .map_err(Into::into)
            }
        }
    }

    pub async fn get_audit_log_by_id(&self, audit_id: Uuid) -> Result<Option<AuditLog>> {
        let audit_log = sqlx::query_as!(
            AuditLog,
            r#"
            SELECT id, user_id, action, resource_type, resource_id, 
                   old_values, new_values, ip_address, user_agent, 
                   timestamp, success, error_message
            FROM audit_logs
            WHERE id = $1
            "#,
            audit_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(audit_log)
    }

    pub async fn count_audit_logs(&self) -> Result<i64> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM audit_logs"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(count.unwrap_or(0))
    }
}
