use crate::services::{AuthService, VisitorService, VisitService, StatisticsService, AuditService};
use crate::database::repositories::StatisticsRepository;

#[derive(Clone)]
pub struct AppState {
    pub auth_service: AuthService,
    pub visitor_service: VisitorService,
    pub visit_service: VisitService,
    pub statistics_service: StatisticsService,
    pub audit_service: AuditService,
    pub statistics_repository: StatisticsRepository,
}

impl AppState {
    pub fn new(
        auth_service: AuthService,
        visitor_service: VisitorService,
        visit_service: VisitService,
        statistics_service: StatisticsService,
        audit_service: AuditService,
        statistics_repository: StatisticsRepository,
    ) -> Self {
        Self {
            auth_service,
            visitor_service,
            visit_service,
            statistics_service,
            audit_service,
            statistics_repository,
        }
    }
}
