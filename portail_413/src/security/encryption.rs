use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use base64::{engine::general_purpose, Engine as _};

use crate::errors::{AppError, Result};

#[derive(Clone)]
pub struct EncryptionService {
    key: LessSafeKey,
}

impl EncryptionService {
    pub fn new(key: &str) -> Result<Self> {
        // Validation de la clé d'entrée
        if key.is_empty() {
            return Err(AppError::Encryption("Encryption key cannot be empty".to_string()));
        }
        if key.len() < 16 {
            return Err(AppError::Encryption("Encryption key must be at least 16 characters".to_string()));
        }

        // Dériver une clé de 32 bytes à partir de la clé fournie
        let key_bytes = Self::derive_key(key)?;
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|_| AppError::Encryption("Failed to create encryption key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        Ok(Self { key })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        // Générer un nonce aléatoire
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut nonce_bytes)
            .map_err(|_| AppError::Encryption("Failed to generate nonce".to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Préparer les données à chiffrer
        let mut in_out = plaintext.as_bytes().to_vec();

        // Chiffrer les données
        self.key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| AppError::Encryption("Encryption failed".to_string()))?;

        // Combiner nonce + ciphertext et encoder en base64
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);

        Ok(general_purpose::STANDARD.encode(result))
    }

    pub fn decrypt(&self, encrypted_data: &str) -> Result<String> {
        // Décoder de base64
        let data = general_purpose::STANDARD
            .decode(encrypted_data)
            .map_err(|e| AppError::Encryption(format!("Base64 decode failed: {e}")))?;

        if data.len() < NONCE_LEN {
            return Err(AppError::Encryption("Invalid encrypted data length".to_string()));
        }

        // Séparer nonce et ciphertext
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let mut nonce_array = [0u8; NONCE_LEN];
        nonce_array.copy_from_slice(nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_array);

        // Préparer les données pour le déchiffrement
        let mut in_out = ciphertext.to_vec();

        // Déchiffrer
        let plaintext = self.key.open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| AppError::Encryption("Decryption failed".to_string()))?;

        String::from_utf8(plaintext.to_vec())
            .map_err(|e| AppError::Encryption(format!("UTF-8 conversion failed: {e}")))
    }

    fn derive_key(input: &str) -> Result<[u8; 32]> {
        use ring::pbkdf2;
        use std::num::NonZeroU32;

        // Sel fixe pour la dérivation (en production, devrait être configurable)
        // Note: En production, utiliser un sel unique par application
        const SALT: &[u8] = b"DCOP_PORTAIL_413_ENCRYPTION_SALT_V1";

        // 100,000 itérations pour la sécurité (ajustable selon performance)
        let iterations = NonZeroU32::new(100_000).expect("Checked operation");

        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            SALT,
            input.as_bytes(),
            &mut key,
        );

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let service = EncryptionService::new("test-key-123456789").expect("Checked operation");
        let plaintext = "Données sensibles à chiffrer";
        
        let encrypted = service.encrypt(plaintext).expect("Checked operation");
        let decrypted = service.decrypt(&encrypted).expect("Checked operation");
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_different_encryptions() {
        let service = EncryptionService::new("test-key-123456789").expect("Checked operation");
        let plaintext = "Test data";

        let encrypted1 = service.encrypt(plaintext).expect("Checked operation");
        let encrypted2 = service.encrypt(plaintext).expect("Checked operation");

        // Les chiffrements doivent être différents (nonce aléatoire)
        assert_ne!(encrypted1, encrypted2);

        // Mais le déchiffrement doit donner le même résultat
        assert_eq!(service.decrypt(&encrypted1).expect("Checked operation"), plaintext);
        assert_eq!(service.decrypt(&encrypted2).expect("Checked operation"), plaintext);
    }

    #[test]
    fn test_key_validation() {
        // Clé vide
        assert!(EncryptionService::new("").is_err());

        // Clé trop courte
        assert!(EncryptionService::new("short").is_err());

        // Clé valide
        assert!(EncryptionService::new("valid-encryption-key-123").is_ok());
    }

    #[test]
    fn test_invalid_encrypted_data() {
        let service = EncryptionService::new("test-key-123456789").expect("Checked operation");

        // Données invalides
        assert!(service.decrypt("invalid-base64!").is_err());
        assert!(service.decrypt("dGVzdA==").is_err()); // Trop court
    }
}
