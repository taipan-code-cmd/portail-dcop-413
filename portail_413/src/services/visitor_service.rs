use uuid::Uuid;

use crate::database::VisitorRepository;
use crate::errors::Result;
use crate::models::{CreateVisitorRequest, VisitorResponse, VisitorSearchQuery};
use crate::services::AuditService;
use crate::security::get_validation_service;

#[derive(Clone)]
pub struct VisitorService {
    visitor_repository: VisitorRepository,
    audit_service: AuditService,
}

impl VisitorService {
    pub fn new(visitor_repository: VisitorRepository, audit_service: AuditService) -> Self {
        Self {
            visitor_repository,
            audit_service,
        }
    }

    pub async fn create_visitor(
        &self,
        request: CreateVisitorRequest,
        user_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<VisitorResponse> {
        // Valider les données de l'image si présente
        if let Some(ref photo_data) = request.photo_data {
            get_validation_service()?.validate_image_data(photo_data)?;
        }

        // Créer le visiteur
        let visitor = self.visitor_repository.create_visitor(request).await?;

        // Enregistrer l'audit
        self.audit_service
            .log_action(
                user_id,
                "CREATE_VISITOR".to_string(),
                "Visitor".to_string(),
                Some(visitor.id),
                None,
                Some(serde_json::json!({
                    "organization": visitor.organization,
                    "has_photo": visitor.photo_data.is_some()
                })),
                ip_address,
                user_agent,
                true,
                None,
            )
            .await?;

        // Déchiffrer et retourner les données
        self.visitor_repository.find_by_id(visitor.id).await?
            .ok_or_else(|| crate::errors::AppError::Internal("Visitor not found after creation".to_string()))
    }

    pub async fn get_visitor(&self, visitor_id: Uuid) -> Result<Option<VisitorResponse>> {
        self.visitor_repository.find_by_id(visitor_id).await
    }

    pub async fn search_visitors(&self, query: VisitorSearchQuery) -> Result<Vec<VisitorResponse>> {
        self.visitor_repository.search_visitors(query).await
    }

    pub async fn update_visitor(
        &self,
        visitor_id: Uuid,
        request: CreateVisitorRequest,
        user_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<VisitorResponse> {
        // Valider les données de l'image si présente
        if let Some(ref photo_data) = request.photo_data {
            get_validation_service()?.validate_image_data(photo_data)?;
        }

        // Récupérer l'ancien visiteur pour l'audit
        let old_visitor = self.visitor_repository.find_by_id(visitor_id).await?;

        // Mettre à jour le visiteur
        let updated_visitor = self.visitor_repository.update_visitor(visitor_id, request).await?;

        // Enregistrer l'audit
        self.audit_service
            .log_action(
                user_id,
                "UPDATE_VISITOR".to_string(),
                "Visitor".to_string(),
                Some(visitor_id),
                old_visitor.map(|v| serde_json::json!({
                    "organization": v.organization,
                    "has_photo": v.photo_data.is_some()
                })),
                Some(serde_json::json!({
                    "organization": updated_visitor.organization,
                    "has_photo": updated_visitor.photo_data.is_some()
                })),
                ip_address,
                user_agent,
                true,
                None,
            )
            .await?;

        Ok(updated_visitor)
    }

    pub async fn delete_visitor(
        &self,
        visitor_id: Uuid,
        user_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<()> {
        // Récupérer le visiteur pour l'audit
        let visitor = self.visitor_repository.find_by_id(visitor_id).await?;

        // Supprimer le visiteur
        self.visitor_repository.delete_visitor(visitor_id).await?;

        // Enregistrer l'audit
        self.audit_service
            .log_action(
                user_id,
                "DELETE_VISITOR".to_string(),
                "Visitor".to_string(),
                Some(visitor_id),
                visitor.map(|v| serde_json::json!({
                    "organization": v.organization,
                    "has_photo": v.photo_data.is_some()
                })),
                None,
                ip_address,
                user_agent,
                true,
                None,
            )
            .await?;

        Ok(())
    }
}
