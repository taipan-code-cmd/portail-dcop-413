use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;
use crate::security::get_validation_service;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Visitor {
    pub id: Uuid,
    pub first_name_encrypted: String,
    pub last_name_encrypted: String,
    pub email_encrypted: Option<String>,
    pub phone1_encrypted: String,        // Téléphone principal (obligatoire)
    pub phone2_encrypted: String,        // Téléphone secondaire (obligatoire)
    pub phone3_encrypted: Option<String>, // Téléphone tertiaire (optionnel)
    pub phone4_encrypted: Option<String>, // Téléphone quaternaire (optionnel)
    pub organization: String,
    pub photo_data: Option<String>, // Base64 encoded photo
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub integrity_hash: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateVisitorRequest {
    #[validate(length(min = 1, max = 100))]
    pub first_name: String,

    #[validate(length(min = 1, max = 100))]
    pub last_name: String,

    #[validate(email)]
    pub email: Option<String>,

    #[validate(length(min = 10, max = 15))]
    pub phone1: String, // Téléphone principal (obligatoire)

    #[validate(length(min = 10, max = 20))]
    pub phone2: String, // Téléphone secondaire (obligatoire)

    #[validate(length(min = 10, max = 20))]
    pub phone3: Option<String>, // Téléphone tertiaire (optionnel)

    #[validate(length(min = 10, max = 20))]
    pub phone4: Option<String>, // Téléphone quaternaire (optionnel)

    #[validate(length(min = 1, max = 200))]
    pub organization: String,

    pub photo_data: Option<String>, // Base64 encoded photo

    // Nouveaux champs ajoutés selon le formulaire (temporairement ignorés pour la DB)
    pub function: Option<String>, // Fonction du visiteur

    #[validate(length(min = 1, max = 200))]
    pub visit_purpose: String, // Objectif de la visite (obligatoire)
    pub host_name: Option<String>, // Nom de la personne à visiter
    pub visit_date: Option<String>, // Date de la visite
    pub visit_time: Option<String>, // Heure prévue
    pub visit_details: Option<String>, // Détails supplémentaires
    pub security_agreement: Option<bool>, // Accord consignes de sécurité
    pub electronic_devices: Option<bool>, // Interdiction appareils électroniques
    pub confidentiality: Option<bool>, // Engagement confidentialité
    pub signature_date: Option<String>, // Date de signature
    pub signature: Option<String>, // Signature numérique (base64)
}

#[derive(Debug, Serialize)]
pub struct VisitorResponse {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub email: Option<String>,
    pub phone1: String,
    pub phone2: String,
    pub phone3: Option<String>,
    pub phone4: Option<String>,
    pub organization: String,
    pub photo_data: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct VisitorSearchQuery {
    pub name: Option<String>,
    pub organization: Option<String>,
    pub email: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl CreateVisitorRequest {
    /// Validation stricte avec le service de sécurité
    pub fn validate_strict(&self) -> crate::errors::Result<()> {
        let validation_service = get_validation_service()?;

        // Validation du nom
        validation_service.validate_name(&self.first_name)?;
        validation_service.validate_name(&self.last_name)?;

        // Validation de l'email
        if let Some(ref email) = self.email {
            validation_service.validate_email(email)?;
        }

        // Validation des téléphones
        validation_service.validate_phone(&self.phone1)?;
        validation_service.validate_phone(&self.phone2)?;

        if let Some(ref phone3) = self.phone3 {
            validation_service.validate_phone(phone3)?;
        }

        if let Some(ref phone4) = self.phone4 {
            validation_service.validate_phone(phone4)?;
        }

        // Validation de l'organisation
        validation_service.validate_organization(&self.organization)?;

        // Validation des données d'image
        if let Some(ref photo_data) = self.photo_data {
            validation_service.validate_image_data(photo_data)?;
        }

        // Validation des nouveaux champs (optionnels pour l'instant)
        if let Some(ref function) = self.function {
            validation_service.validate_name(function)?;
        }

        // Validation de l'objectif de la visite (obligatoire)
        validation_service.validate_name(&self.visit_purpose)?;

        if let Some(ref host_name) = self.host_name {
            validation_service.validate_name(host_name)?;
        }

        if let Some(ref visit_details) = self.visit_details {
            if visit_details.len() > 1000 {
                return Err(crate::errors::AppError::Validation(
                    "Les détails de la visite ne peuvent pas dépasser 1000 caractères".to_string()
                ));
            }
        }

        // Validation des données de signature
        if let Some(ref signature) = self.signature {
            validation_service.validate_image_data(signature)?;
        }

        Ok(())
    }
}
