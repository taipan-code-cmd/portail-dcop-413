use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Visit {
    pub id: Uuid,
    pub visitor_id: Uuid,
    pub purpose: String,
    pub host_name: String,
    pub department: String,
    pub scheduled_start: DateTime<Utc>,
    pub scheduled_end: DateTime<Utc>,
    pub actual_start: Option<DateTime<Utc>>,
    pub actual_end: Option<DateTime<Utc>>,
    pub status: VisitStatus,
    pub badge_number: Option<String>,
    pub notes: Option<String>,
    pub approved_by: Option<Uuid>,
    pub approved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub integrity_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "visit_status", rename_all = "lowercase")]
pub enum VisitStatus {
    Pending,
    Approved,
    Rejected,
    InProgress,
    Completed,
    Cancelled,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateVisitRequest {
    pub visitor_id: Uuid,
    
    #[validate(length(min = 1, max = 500))]
    pub purpose: String,
    
    #[validate(length(min = 1, max = 100))]
    pub host_name: String,
    
    #[validate(length(min = 1, max = 100))]
    pub department: String,
    
    pub scheduled_start: DateTime<Utc>,
    pub scheduled_end: DateTime<Utc>,
    
    #[validate(length(max = 1000))]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VisitResponse {
    pub id: Uuid,
    pub visitor_id: Uuid,
    pub purpose: String,
    pub host_name: String,
    pub department: String,
    pub scheduled_start: DateTime<Utc>,
    pub scheduled_end: DateTime<Utc>,
    pub actual_start: Option<DateTime<Utc>>,
    pub actual_end: Option<DateTime<Utc>>,
    pub status: VisitStatus,
    pub badge_number: Option<String>,
    pub notes: Option<String>,
    pub approved_by: Option<Uuid>,
    pub approved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct VisitSearchQuery {
    pub visitor_id: Option<Uuid>,
    pub status: Option<VisitStatus>,
    pub department: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateVisitStatusRequest {
    pub status: VisitStatus,
    pub notes: Option<String>,
}

impl From<Visit> for VisitResponse {
    fn from(visit: Visit) -> Self {
        Self {
            id: visit.id,
            visitor_id: visit.visitor_id,
            purpose: visit.purpose,
            host_name: visit.host_name,
            department: visit.department,
            scheduled_start: visit.scheduled_start,
            scheduled_end: visit.scheduled_end,
            actual_start: visit.actual_start,
            actual_end: visit.actual_end,
            status: visit.status,
            badge_number: visit.badge_number,
            notes: visit.notes,
            approved_by: visit.approved_by,
            approved_at: visit.approved_at,
            created_at: visit.created_at,
        }
    }
}
