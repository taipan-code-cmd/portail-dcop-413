use sha2::{Digest, Sha512};
use serde::Serialize;

use crate::errors::{AppError, Result};

#[derive(Clone)]
pub struct HashingService {
    salt: String,
}

impl HashingService {
    pub fn new(salt: String) -> Self {
        Self { salt }
    }

    /// Calcule le hash d'intégrité SHA-512 pour un objet sérialisable
    pub fn calculate_integrity_hash<T: Serialize>(&self, data: &T) -> Result<String> {
        // Sérialiser l'objet en JSON de manière déterministe
        let json_data = serde_json::to_string(data)
            .map_err(|e| AppError::Internal(format!("Serialization failed: {e}")))?;

        // Normaliser les données (supprimer les espaces, trier les clés)
        let normalized_data = self.normalize_json(&json_data)?;

        // Ajouter le sel privé
        let data_with_salt = format!("{}{}", normalized_data, self.salt);

        // Calculer le hash SHA-512
        let mut hasher = Sha512::new();
        hasher.update(data_with_salt.as_bytes());
        let result = hasher.finalize();

        // Convertir en hexadécimal
        Ok(format!("{result:x}"))
    }

    /// Vérifie l'intégrité d'un objet en comparant son hash
    pub fn verify_integrity<T: Serialize>(&self, data: &T, expected_hash: &str) -> Result<bool> {
        let calculated_hash = self.calculate_integrity_hash(data)?;
        Ok(calculated_hash == expected_hash)
    }

    /// Normalise une chaîne JSON pour assurer la cohérence du hachage
    fn normalize_json(&self, json: &str) -> Result<String> {
        let value: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| AppError::Internal(format!("JSON parsing failed: {e}")))?;

        // Sérialiser de nouveau sans espaces et avec les clés triées
        serde_json::to_string(&value)
            .map_err(|e| AppError::Internal(format!("JSON normalization failed: {e}")))
    }

    /// Calcule un hash simple pour les données non-structurées
    pub fn hash_data(&self, data: &str) -> String {
        let data_with_salt = format!("{}{}", data, self.salt);
        let mut hasher = Sha512::new();
        hasher.update(data_with_salt.as_bytes());
        let result = hasher.finalize();
        format!("{result:x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_integrity_hash_consistency() {
        let service = HashingService::new("test-salt".to_string());
        let data = json!({
            "name": "John Doe",
            "age": 30,
            "email": "john@example.com"
        });

        let hash1 = service.calculate_integrity_hash(&data).expect("Checked operation");
        let hash2 = service.calculate_integrity_hash(&data).expect("Checked operation");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_integrity_verification() {
        let service = HashingService::new("test-salt".to_string());
        let data = json!({
            "name": "John Doe",
            "age": 30
        });

        let hash = service.calculate_integrity_hash(&data).expect("Checked operation");
        assert!(service.verify_integrity(&data, &hash).expect("Checked operation"));

        // Modifier les données
        let modified_data = json!({
            "name": "Jane Doe",
            "age": 30
        });

        assert!(!service.verify_integrity(&modified_data, &hash).expect("Checked operation"));
    }

    #[test]
    fn test_hash_data() {
        let service = HashingService::new("test-salt".to_string());
        let data = "sensitive information";

        let hash1 = service.hash_data(data);
        let hash2 = service.hash_data(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 128); // SHA-512 en hex = 128 caractères
    }
}
