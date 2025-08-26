use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::time::{interval, Duration as TokioDuration};
use uuid::Uuid;

use crate::errors::{AppError, Result};

/// Service de rotation automatique des secrets
#[derive(Clone)]
pub struct SecretRotationService {
    secrets: HashMap<String, RotatableSecret>,
    rotation_interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotatableSecret {
    pub id: Uuid,
    pub name: String,
    pub current_value: String,
    pub previous_value: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub rotation_count: u32,
}

#[derive(Debug, Clone)]
pub struct SecretRotationConfig {
    pub rotation_interval_hours: i64,
    pub grace_period_hours: i64,
    pub max_rotation_count: u32,
}

impl Default for SecretRotationConfig {
    fn default() -> Self {
        Self {
            rotation_interval_hours: 24 * 7, // 7 jours
            grace_period_hours: 24,          // 1 jour de grâce
            max_rotation_count: 1000,        // Limite de rotations
        }
    }
}

impl SecretRotationService {
    pub fn new(config: SecretRotationConfig) -> Self {
        Self {
            secrets: HashMap::new(),
            rotation_interval: Duration::hours(config.rotation_interval_hours),
        }
    }

    /// Génère un nouveau secret cryptographiquement fort avec CSPRNG 256 bits minimum
    /// Utilise ring::rand::SystemRandom pour une sécurité maximale
    pub fn generate_secret(length: usize) -> Result<String> {
        if length < 32 {
            return Err(AppError::Validation("Secret length must be at least 32 bytes (256 bits)".to_string()));
        }

        let rng = SystemRandom::new();
        let mut secret_bytes = vec![0u8; length];

        rng.fill(&mut secret_bytes)
            .map_err(|_| AppError::Encryption("Failed to generate cryptographically secure random bytes".to_string()))?;

        Ok(base64::engine::general_purpose::STANDARD.encode(secret_bytes))
    }

    /// Génère un secret JWT de 512 bits (64 bytes) selon les recommandations OWASP
    pub fn generate_jwt_secret() -> Result<String> {
        Self::generate_secret(64) // 512 bits
    }

    /// Génère une clé de chiffrement de 256 bits (32 bytes)
    pub fn generate_encryption_key() -> Result<String> {
        Self::generate_secret(32) // 256 bits
    }

    /// Génère un sel de sécurité de 384 bits (48 bytes)
    pub fn generate_security_salt() -> Result<String> {
        Self::generate_secret(48) // 384 bits
    }

    /// Génère un mot de passe PostgreSQL de 256 bits (32 bytes)
    pub fn generate_postgres_password() -> Result<String> {
        Self::generate_secret(32) // 256 bits
    }

    /// Génère et sauvegarde tous les secrets dans le répertoire secrets/
    /// Conforme aux exigences OWASP et Secure-by-Design
    pub fn generate_and_save_all_secrets<P: AsRef<Path>>(secrets_dir: P) -> Result<()> {
        let secrets_path = secrets_dir.as_ref();

        // Créer le répertoire secrets s'il n'existe pas
        fs::create_dir_all(secrets_path)
            .map_err(|e| AppError::Internal(format!("Failed to create secrets directory: {e}")))?;

        // Générer et sauvegarder chaque secret
        let secrets = [
            ("postgres_password.txt", Self::generate_postgres_password()?),
            ("jwt_secret.txt", Self::generate_jwt_secret()?),
            ("encryption_key.txt", Self::generate_encryption_key()?),
            ("security_salt.txt", Self::generate_security_salt()?),
        ];

        for (filename, secret) in secrets.iter() {
            let file_path = secrets_path.join(filename);
            fs::write(&file_path, secret)
                .map_err(|e| AppError::Internal(format!("Failed to write {filename}: {e}")))?;

            // Définir les permissions restrictives (600 = rw-------)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&file_path)
                    .map_err(|e| AppError::Internal(format!("Failed to get metadata for {filename}: {e}")))?
                    .permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&file_path, perms)
                    .map_err(|e| AppError::Internal(format!("Failed to set permissions for {filename}: {e}")))?;
            }

            tracing::info!("Generated and saved secure secret: {}", filename);
        }

        tracing::info!("All secrets generated successfully with CSPRNG 256+ bits");
        Ok(())
    }

    /// Ajoute un secret à la rotation automatique
    pub fn add_secret(&mut self, name: String, current_value: String) -> Result<Uuid> {
        let secret_id = Uuid::new_v4();
        let now = Utc::now();
        
        let secret = RotatableSecret {
            id: secret_id,
            name: name.clone(),
            current_value,
            previous_value: None,
            created_at: now,
            expires_at: now + self.rotation_interval,
            rotation_count: 0,
        };

        tracing::info!("Secret '{}' added to rotation service", name);
        self.secrets.insert(name, secret);
        
        Ok(secret_id)
    }

    /// Effectue la rotation d'un secret spécifique
    pub fn rotate_secret(&mut self, name: &str) -> Result<String> {
        let secret = self.secrets.get_mut(name)
            .ok_or_else(|| AppError::NotFound(format!("Secret '{}' not found", name)))?;

        // Générer le nouveau secret
        let new_secret = Self::generate_jwt_secret()?; // 512 bits pour JWT
        
        // Sauvegarder l'ancien secret pour la période de grâce
        secret.previous_value = Some(secret.current_value.clone());
        secret.current_value = new_secret.clone();
        secret.expires_at = Utc::now() + self.rotation_interval;
        secret.rotation_count += 1;

        tracing::info!(
            "Secret '{}' rotated (count: {})", 
            name, 
            secret.rotation_count
        );

        Ok(new_secret)
    }

    /// Vérifie si un secret doit être renouvelé
    pub fn needs_rotation(&self, name: &str) -> bool {
        if let Some(secret) = self.secrets.get(name) {
            Utc::now() >= secret.expires_at
        } else {
            false
        }
    }

    /// Obtient un secret valide (actuel ou précédent pendant la période de grâce)
    pub fn get_valid_secret(&self, name: &str, value: &str) -> Option<&RotatableSecret> {
        if let Some(secret) = self.secrets.get(name) {
            // Vérifier le secret actuel
            if secret.current_value == value {
                return Some(secret);
            }
            
            // Vérifier le secret précédent (période de grâce)
            if let Some(ref previous) = secret.previous_value {
                if previous == value {
                    return Some(secret);
                }
            }
        }
        None
    }

    /// Lance la rotation automatique en arrière-plan
    pub async fn start_automatic_rotation(&mut self) -> Result<()> {
        let mut interval = interval(TokioDuration::from_secs(3600)); // Vérification toutes les heures
        
        loop {
            interval.tick().await;
            
            let secrets_to_rotate: Vec<String> = self.secrets
                .iter()
                .filter(|(_, secret)| Utc::now() >= secret.expires_at)
                .map(|(name, _)| name.clone())
                .collect();

            for secret_name in secrets_to_rotate {
                match self.rotate_secret(&secret_name) {
                    Ok(new_secret) => {
                        tracing::info!("Auto-rotated secret: {}", secret_name);
                        // Ici, vous pourriez notifier les services dépendants
                        self.notify_secret_rotation(&secret_name, &new_secret).await?;
                    }
                    Err(e) => {
                        tracing::error!("Failed to rotate secret '{}': {}", secret_name, e);
                    }
                }
            }
        }
    }

    /// Notifie les services de la rotation d'un secret
    async fn notify_secret_rotation(&self, name: &str, _new_value: &str) -> Result<()> {
        // Implémentation de notification (webhook, message queue, etc.)
        tracing::info!("Notifying services of secret rotation for: {}", name);
        
        // Exemple : écrire dans un fichier de notification
        let notification = format!(
            "SECRET_ROTATED: {} at {}\n", 
            name, 
            Utc::now().to_rfc3339()
        );
        
        tokio::fs::write(
            format!("/tmp/secret_rotation_{}.log", name),
            notification
        ).await
        .map_err(|e| AppError::Internal(format!("Failed to write rotation log: {}", e)))?;

        Ok(())
    }

    /// Nettoie les anciens secrets expirés
    pub fn cleanup_expired_secrets(&mut self, grace_period: Duration) {
        let cutoff_time = Utc::now() - grace_period;
        
        for secret in self.secrets.values_mut() {
            if let Some(ref _previous) = secret.previous_value {
                if secret.created_at < cutoff_time {
                    secret.previous_value = None;
                    tracing::info!("Cleaned up expired previous secret for: {}", secret.name);
                }
            }
        }
    }

    /// Exporte les métadonnées des secrets (sans les valeurs)
    pub fn export_metadata(&self) -> Vec<SecretMetadata> {
        self.secrets
            .values()
            .map(|secret| SecretMetadata {
                id: secret.id,
                name: secret.name.clone(),
                created_at: secret.created_at,
                expires_at: secret.expires_at,
                rotation_count: secret.rotation_count,
                has_previous: secret.previous_value.is_some(),
            })
            .collect()
    }
}

#[derive(Debug, Serialize)]
pub struct SecretMetadata {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub rotation_count: u32,
    pub has_previous: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_generation() {
        let secret = SecretRotationService::generate_secret(32).expect("Checked operation");
        assert!(secret.len() > 40); // Base64 encoding increases length
        
        let secret2 = SecretRotationService::generate_secret(32).expect("Checked operation");
        assert_ne!(secret, secret2); // Should be different
    }

    #[tokio::test]
    async fn test_secret_rotation() {
        let mut service = SecretRotationService::new(SecretRotationConfig::default());
        
        let initial_secret = "initial_secret_value".to_string();
        service.add_secret("test_secret".to_string(), initial_secret.clone()).expect("Checked operation");
        
        let new_secret = service.rotate_secret("test_secret").expect("Checked operation");
        assert_ne!(initial_secret, new_secret);
        
        // L'ancien secret devrait encore être valide pendant la période de grâce
        assert!(service.get_valid_secret("test_secret", &initial_secret).is_some());
        assert!(service.get_valid_secret("test_secret", &new_secret).is_some());
    }
}
