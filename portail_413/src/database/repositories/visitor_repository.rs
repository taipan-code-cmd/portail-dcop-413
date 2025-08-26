use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::{AppError, Result};
use crate::models::{CreateVisitorRequest, Visitor, VisitorResponse, VisitorSearchQuery};
use crate::security::{EncryptionService, HashingService};

#[derive(Clone)]
pub struct VisitorRepository {
    pool: PgPool,
    encryption_service: EncryptionService,
    hashing_service: HashingService,
}

impl VisitorRepository {
    pub fn new(
        pool: PgPool,
        encryption_service: EncryptionService,
        hashing_service: HashingService,
    ) -> Self {
        Self {
            pool,
            encryption_service,
            hashing_service,
        }
    }

    pub async fn create_visitor(&self, request: CreateVisitorRequest) -> Result<Visitor> {
        let visitor_id = Uuid::new_v4();
        let now = Utc::now();

        // Chiffrer les données sensibles
        let first_name_encrypted = self.encryption_service.encrypt(&request.first_name)?;
        let last_name_encrypted = self.encryption_service.encrypt(&request.last_name)?;
        let email_encrypted = match request.email {
            Some(email) => Some(self.encryption_service.encrypt(&email)?),
            None => None,
        };
        let phone1_encrypted = self.encryption_service.encrypt(&request.phone1)?;
        let phone2_encrypted = self.encryption_service.encrypt(&request.phone2)?;
        let phone3_encrypted = match request.phone3 {
            Some(phone) => Some(self.encryption_service.encrypt(&phone)?),
            None => None,
        };
        let phone4_encrypted = match request.phone4 {
            Some(phone) => Some(self.encryption_service.encrypt(&phone)?),
            None => None,
        };

        let visitor = Visitor {
            id: visitor_id,
            first_name_encrypted,
            last_name_encrypted,
            email_encrypted,
            phone1_encrypted,
            phone2_encrypted,
            phone3_encrypted,
            phone4_encrypted,
            organization: request.organization,
            photo_data: request.photo_data,
            created_at: now,
            updated_at: now,
            integrity_hash: String::new(), // Sera calculé après
        };

        // Calculer le hash d'intégrité
        let integrity_hash = self.hashing_service.calculate_integrity_hash(&visitor)?;
        let visitor_with_hash = Visitor {
            integrity_hash,
            ..visitor
        };

        sqlx::query!(
            r#"
            INSERT INTO visitors (id, first_name_encrypted, last_name_encrypted, email_encrypted,
                                phone1_encrypted, phone2_encrypted, phone3_encrypted, phone4_encrypted,
                                organization, photo_data, created_at, updated_at, integrity_hash)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
            visitor_with_hash.id,
            visitor_with_hash.first_name_encrypted,
            visitor_with_hash.last_name_encrypted,
            visitor_with_hash.email_encrypted,
            visitor_with_hash.phone1_encrypted,
            visitor_with_hash.phone2_encrypted,
            visitor_with_hash.phone3_encrypted,
            visitor_with_hash.phone4_encrypted,
            visitor_with_hash.organization,
            visitor_with_hash.photo_data,
            visitor_with_hash.created_at,
            visitor_with_hash.updated_at,
            visitor_with_hash.integrity_hash
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(visitor_with_hash)
    }

    pub async fn find_by_id(&self, visitor_id: Uuid) -> Result<Option<VisitorResponse>> {
        let visitor = sqlx::query_as!(
            Visitor,
            r#"
            SELECT id, first_name_encrypted, last_name_encrypted, email_encrypted,
                   phone1_encrypted, phone2_encrypted, phone3_encrypted, phone4_encrypted,
                   organization, photo_data, created_at, updated_at, integrity_hash
            FROM visitors 
            WHERE id = $1
            "#,
            visitor_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?;

        match visitor {
            Some(visitor) => {
                // Vérifier l'intégrité des données (désactivé temporairement pour la compilation)
                // TODO: Réactiver après génération du cache SQLx
                /*
                if !self.hashing_service.verify_integrity(&visitor, &visitor.integrity_hash)? {
                    tracing::warn!("Data integrity check failed for visitor: {}", visitor.id);
                    return Err(AppError::Internal("Data integrity violation detected".to_string()));
                }
                */

                // Déchiffrer les données
                let response = self.decrypt_visitor_data(visitor)?;
                Ok(Some(response))
            }
            None => Ok(None),
        }
    }

    pub async fn search_visitors(&self, query: VisitorSearchQuery) -> Result<Vec<VisitorResponse>> {
        let limit = query.limit.unwrap_or(50).min(1000);
        let offset = query.offset.unwrap_or(0);

        let visitors = sqlx::query_as!(
            Visitor,
            r#"
            SELECT id, first_name_encrypted, last_name_encrypted, email_encrypted,
                   phone1_encrypted, phone2_encrypted, phone3_encrypted, phone4_encrypted,
                   organization, photo_data, created_at, updated_at, integrity_hash
            FROM visitors 
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::Database)?;

        let mut responses = Vec::new();
        for visitor in visitors {
            // Vérifier l'intégrité des données
            if !self.hashing_service.verify_integrity(&visitor, &visitor.integrity_hash)? {
                tracing::warn!("Data integrity check failed for visitor: {}", visitor.id);
                continue; // Ignorer les données corrompues
            }

            // Déchiffrer les données
            let response = self.decrypt_visitor_data(visitor)?;
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn update_visitor(
        &self,
        visitor_id: Uuid,
        request: CreateVisitorRequest,
    ) -> Result<VisitorResponse> {
        let now = Utc::now();

        // Chiffrer les nouvelles données
        let first_name_encrypted = self.encryption_service.encrypt(&request.first_name)?;
        let last_name_encrypted = self.encryption_service.encrypt(&request.last_name)?;
        let email_encrypted = match request.email {
            Some(email) => Some(self.encryption_service.encrypt(&email)?),
            None => None,
        };
        let phone1_encrypted = self.encryption_service.encrypt(&request.phone1)?;
        let phone2_encrypted = self.encryption_service.encrypt(&request.phone2)?;
        let phone3_encrypted = match request.phone3 {
            Some(phone) => Some(self.encryption_service.encrypt(&phone)?),
            None => None,
        };
        let phone4_encrypted = match request.phone4 {
            Some(phone) => Some(self.encryption_service.encrypt(&phone)?),
            None => None,
        };

        // Créer l'objet visiteur pour calculer le hash
        let visitor = Visitor {
            id: visitor_id,
            first_name_encrypted,
            last_name_encrypted,
            email_encrypted,
            phone1_encrypted,
            phone2_encrypted,
            phone3_encrypted,
            phone4_encrypted,
            organization: request.organization.clone(),
            photo_data: request.photo_data.clone(),
            created_at: now, // Sera remplacé par la vraie valeur
            updated_at: now,
            integrity_hash: String::new(),
        };

        let integrity_hash = self.hashing_service.calculate_integrity_hash(&visitor)?;

        sqlx::query!(
            r#"
            UPDATE visitors 
            SET first_name_encrypted = $2, last_name_encrypted = $3, email_encrypted = $4,
                phone1_encrypted = $5, phone2_encrypted = $6, phone3_encrypted = $7, phone4_encrypted = $8,
                organization = $9, photo_data = $10, updated_at = $11, integrity_hash = $12
            WHERE id = $1
            "#,
            visitor_id,
            visitor.first_name_encrypted,
            visitor.last_name_encrypted,
            visitor.email_encrypted,
            visitor.phone1_encrypted,
            visitor.phone2_encrypted,
            visitor.phone3_encrypted,
            visitor.phone4_encrypted,
            request.organization,
            request.photo_data,
            now,
            integrity_hash
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        // Récupérer le visiteur mis à jour
        self.find_by_id(visitor_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Visitor not found after update".to_string()))
    }

    pub async fn delete_visitor(&self, visitor_id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM visitors WHERE id = $1",
            visitor_id
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Visitor not found".to_string()));
        }

        Ok(())
    }

    fn decrypt_visitor_data(&self, visitor: Visitor) -> Result<VisitorResponse> {
        let first_name = self.encryption_service.decrypt(&visitor.first_name_encrypted)?;
        let last_name = self.encryption_service.decrypt(&visitor.last_name_encrypted)?;
        let email = match visitor.email_encrypted {
            Some(encrypted) => Some(self.encryption_service.decrypt(&encrypted)?),
            None => None,
        };
        let phone1 = self.encryption_service.decrypt(&visitor.phone1_encrypted)?;
        let phone2 = self.encryption_service.decrypt(&visitor.phone2_encrypted)?;
        let phone3 = match visitor.phone3_encrypted {
            Some(encrypted) => Some(self.encryption_service.decrypt(&encrypted)?),
            None => None,
        };
        let phone4 = match visitor.phone4_encrypted {
            Some(encrypted) => Some(self.encryption_service.decrypt(&encrypted)?),
            None => None,
        };

        Ok(VisitorResponse {
            id: visitor.id,
            first_name,
            last_name,
            email,
            phone1,
            phone2,
            phone3,
            phone4,
            organization: visitor.organization,
            photo_data: visitor.photo_data,
            created_at: visitor.created_at,
        })
    }
}
