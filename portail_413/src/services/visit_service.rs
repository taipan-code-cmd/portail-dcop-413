use uuid::Uuid;

use crate::database::VisitRepository;
use crate::errors::Result;
use crate::models::{CreateVisitRequest, VisitResponse, VisitSearchQuery, UpdateVisitStatusRequest};
use crate::services::AuditService;

#[derive(Clone)]
pub struct VisitService {
    visit_repository: VisitRepository,
    audit_service: AuditService,
}

impl VisitService {
    pub fn new(visit_repository: VisitRepository, audit_service: AuditService) -> Self {
        Self {
            visit_repository,
            audit_service,
        }
    }

    pub async fn create_visit(
        &self,
        request: CreateVisitRequest,
        user_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<VisitResponse> {
        // Créer la visite
        let visit = self.visit_repository.create_visit(request).await?;

        // Enregistrer l'audit
        self.audit_service
            .log_action(
                user_id,
                "CREATE_VISIT".to_string(),
                "Visit".to_string(),
                Some(visit.id),
                None,
                Some(serde_json::json!({
                    "visitor_id": visit.visitor_id,
                    "purpose": visit.purpose,
                    "department": visit.department,
                    "status": visit.status
                })),
                ip_address,
                user_agent,
                true,
                None,
            )
            .await?;

        Ok(VisitResponse::from(visit))
    }

    pub async fn get_visit(&self, visit_id: Uuid) -> Result<Option<VisitResponse>> {
        let visit = self.visit_repository.find_by_id(visit_id).await?;
        Ok(visit.map(VisitResponse::from))
    }

    pub async fn search_visits(&self, query: VisitSearchQuery) -> Result<Vec<VisitResponse>> {
        let visits = self.visit_repository.search_visits(query).await?;
        Ok(visits.into_iter().map(VisitResponse::from).collect())
    }

    pub async fn update_visit_status(
        &self,
        visit_id: Uuid,
        request: UpdateVisitStatusRequest,
        user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<VisitResponse> {
        // Récupérer l'ancienne visite pour l'audit
        let old_visit = self.visit_repository.find_by_id(visit_id).await?;

        // Mettre à jour le statut
        let updated_visit = self.visit_repository
            .update_visit_status(visit_id, request.clone(), Some(user_id))
            .await?;

        // Enregistrer l'audit
        self.audit_service
            .log_action(
                Some(user_id),
                "UPDATE_VISIT_STATUS".to_string(),
                "Visit".to_string(),
                Some(visit_id),
                old_visit.map(|v| serde_json::json!({
                    "status": v.status,
                    "notes": v.notes
                })),
                Some(serde_json::json!({
                    "status": updated_visit.status,
                    "notes": updated_visit.notes
                })),
                ip_address,
                user_agent,
                true,
                None,
            )
            .await?;

        Ok(VisitResponse::from(updated_visit))
    }

    pub async fn start_visit(
        &self,
        visit_id: Uuid,
        user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<VisitResponse> {
        // Démarrer la visite
        let visit = self.visit_repository.start_visit(visit_id).await?;

        // Enregistrer l'audit
        self.audit_service
            .log_action(
                Some(user_id),
                "START_VISIT".to_string(),
                "Visit".to_string(),
                Some(visit_id),
                None,
                Some(serde_json::json!({
                    "actual_start": visit.actual_start,
                    "status": visit.status
                })),
                ip_address,
                user_agent,
                true,
                None,
            )
            .await?;

        Ok(VisitResponse::from(visit))
    }

    pub async fn end_visit(
        &self,
        visit_id: Uuid,
        user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<VisitResponse> {
        // Terminer la visite
        let visit = self.visit_repository.end_visit(visit_id).await?;

        // Enregistrer l'audit
        self.audit_service
            .log_action(
                Some(user_id),
                "END_VISIT".to_string(),
                "Visit".to_string(),
                Some(visit_id),
                None,
                Some(serde_json::json!({
                    "actual_end": visit.actual_end,
                    "status": visit.status
                })),
                ip_address,
                user_agent,
                true,
                None,
            )
            .await?;

        Ok(VisitResponse::from(visit))
    }

    pub async fn get_active_visits(&self) -> Result<Vec<VisitResponse>> {
        let visits = self.visit_repository.get_active_visits().await?;
        Ok(visits.into_iter().map(VisitResponse::from).collect())
    }
}
