use uuid::Uuid;

use crate::{
    database::repositories::{AuditRepository},
    errors::Result,
    models::{AuditLog, AuditLogResponse, AuditSearchQuery, CreateAuditRequest},
};

#[derive(Clone)]
pub struct AuditService {
    audit_repository: AuditRepository,
}

impl AuditService {
    pub fn new(audit_repository: AuditRepository) -> Self {
        Self { audit_repository }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn log_action(
        &self,
        user_id: Option<Uuid>,
        action: String,
        resource_type: String,
        resource_id: Option<Uuid>,
        old_values: Option<serde_json::Value>,
        new_values: Option<serde_json::Value>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        success: bool,
        error_message: Option<String>,
    ) -> Result<AuditLog> {
        let request = CreateAuditRequest {
            user_id,
            action,
            resource_type,
            resource_id,
            old_values,
            new_values,
            ip_address,
            user_agent,
            success,
            error_message,
        };
        
        self.log_action_with_request(request).await
    }

    /// Version optimisée prenant directement une requête structurée
    pub async fn log_action_with_request(
        &self,
        request: CreateAuditRequest,
    ) -> Result<AuditLog> {
        self.audit_repository
            .create_audit_log(request)
            .await
    }

    pub async fn search_audit_logs(&self, query: AuditSearchQuery) -> Result<Vec<AuditLogResponse>> {
        let audit_logs = self.audit_repository.search_audit_logs(query).await?;
        
        Ok(audit_logs
            .into_iter()
            .map(AuditLogResponse::from)
            .collect())
    }

    pub async fn get_audit_log(&self, audit_id: Uuid) -> Result<Option<AuditLogResponse>> {
        let audit_log = self.audit_repository.get_audit_log_by_id(audit_id).await?;
        
        Ok(audit_log.map(AuditLogResponse::from))
    }

    pub async fn get_audit_stats(&self) -> Result<serde_json::Value> {
        let total_logs = self.audit_repository.count_audit_logs().await?;
        
        Ok(serde_json::json!({
            "total_logs": total_logs,
            "last_updated": chrono::Utc::now()
        }))
    }
}
