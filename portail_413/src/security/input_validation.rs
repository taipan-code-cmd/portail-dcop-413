use base64::Engine;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::errors::{AppError, Result};

/// Service de validation stricte des entrées utilisateur conforme OWASP A03:2021
pub struct InputValidationService {
    patterns: HashMap<String, Regex>,
    max_file_size: usize,
    allowed_mime_types: Vec<String>,
    forbidden_patterns: Vec<Regex>,
    dangerous_keywords: HashSet<String>,
}

impl InputValidationService {
    /// Crée un nouveau service de validation avec des règles strictes
    pub fn new() -> Result<Self> {
        let mut patterns = HashMap::new();

        // Patterns de validation strictes
        patterns.insert(
            "username".to_string(),
            Regex::new(r"^[a-zA-Z0-9_.-]{3,50}$")
                .map_err(|e| AppError::Internal(format!("Invalid username regex: {}", e)))?
        );

        patterns.insert(
            "email".to_string(),
            Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
                .map_err(|e| AppError::Internal(format!("Invalid email regex: {}", e)))?
        );

        patterns.insert(
            "phone_international".to_string(),
            Regex::new(r"^\+[1-9]\d{1,14}$")
                .map_err(|e| AppError::Internal(format!("Invalid phone regex: {}", e)))?
        );

        patterns.insert(
            "phone_local".to_string(),
            Regex::new(r"^0[1-9]\d{8,9}$")
                .map_err(|e| AppError::Internal(format!("Invalid local phone regex: {}", e)))?
        );

        patterns.insert(
            "name".to_string(),
            Regex::new(r"^[a-zA-ZÀ-ÿ\s'-]{1,100}$")
                .map_err(|e| AppError::Internal(format!("Invalid name regex: {}", e)))?
        );

        patterns.insert(
            "organization".to_string(),
            Regex::new(r"^[a-zA-Z0-9À-ÿ\s.,-]{2,200}$")
                .map_err(|e| AppError::Internal(format!("Invalid organization regex: {}", e)))?
        );

        patterns.insert(
            "alphanumeric".to_string(),
            Regex::new(r"^[a-zA-Z0-9]+$")
                .map_err(|e| AppError::Internal(format!("Invalid alphanumeric regex: {}", e)))?
        );

        patterns.insert(
            "uuid".to_string(),
            Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
                .map_err(|e| AppError::Internal(format!("Invalid UUID regex: {}", e)))?
        );

        patterns.insert(
            "safe_text".to_string(),
            Regex::new(r"^[a-zA-Z0-9À-ÿ\s.,:;!?'-]{1,1000}$")
                .map_err(|e| AppError::Internal(format!("Invalid safe text regex: {}", e)))?
        );

        // Patterns interdits pour détecter les attaques
        let mut forbidden_patterns = Vec::new();

        // Détection XSS
        forbidden_patterns.push(
            Regex::new(r"(?i)<script[^>]*>.*?</script>")
                .map_err(|e| AppError::Internal(format!("Invalid XSS regex: {}", e)))?
        );

        // Détection SQL Injection
        forbidden_patterns.push(
            Regex::new(r"(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into|update\s+set)")
                .map_err(|e| AppError::Internal(format!("Invalid SQL injection regex: {}", e)))?
        );

        // Détection LDAP Injection
        forbidden_patterns.push(
            Regex::new(r"[()&|!*]")
                .map_err(|e| AppError::Internal(format!("Invalid LDAP injection regex: {}", e)))?
        );

        // Mots-clés dangereux
        let mut dangerous_keywords = HashSet::new();
        dangerous_keywords.insert("javascript:".to_string());
        dangerous_keywords.insert("vbscript:".to_string());
        dangerous_keywords.insert("data:text/html".to_string());
        dangerous_keywords.insert("eval(".to_string());
        dangerous_keywords.insert("expression(".to_string());
        dangerous_keywords.insert("onload=".to_string());
        dangerous_keywords.insert("onerror=".to_string());
        dangerous_keywords.insert("onclick=".to_string());
        dangerous_keywords.insert("onmouseover=".to_string());

        Ok(Self {
            patterns,
            max_file_size: 10 * 1024 * 1024, // 10 MB
            allowed_mime_types: vec![
                "image/jpeg".to_string(),
                "image/png".to_string(),
                "image/gif".to_string(),
                "image/webp".to_string(),
                "application/pdf".to_string(),
            ],
            forbidden_patterns,
            dangerous_keywords,
        })
    }

    /// Valide une chaîne selon un pattern spécifique
    pub fn validate_string(&self, input: &str, pattern_name: &str) -> Result<()> {
        let pattern = self.patterns.get(pattern_name)
            .ok_or_else(|| AppError::Validation(format!("Unknown validation pattern: {}", pattern_name)))?;

        if !pattern.is_match(input) {
            return Err(AppError::Validation(
                format!("Input does not match required pattern: {}", pattern_name)
            ));
        }

        Ok(())
    }

    /// Valide un nom d'utilisateur
    pub fn validate_username(&self, username: &str) -> Result<()> {
        self.validate_string(username, "username")?;
        
        // Vérifications supplémentaires
        if username.starts_with('.') || username.ends_with('.') {
            return Err(AppError::Validation("Username cannot start or end with a dot".to_string()));
        }

        if username.contains("..") {
            return Err(AppError::Validation("Username cannot contain consecutive dots".to_string()));
        }

        Ok(())
    }

    /// Valide une adresse email
    pub fn validate_email(&self, email: &str) -> Result<()> {
        self.validate_string(email, "email")?;

        // Vérifications supplémentaires
        if email.len() > 254 {
            return Err(AppError::Validation("Email address too long".to_string()));
        }

        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return Err(AppError::Validation("Invalid email format".to_string()));
        }

        let local_part = parts[0];
        let domain_part = parts[1];

        if local_part.len() > 64 {
            return Err(AppError::Validation("Email local part too long".to_string()));
        }

        if domain_part.len() > 253 {
            return Err(AppError::Validation("Email domain part too long".to_string()));
        }

        Ok(())
    }

    /// Valide un numéro de téléphone
    pub fn validate_phone(&self, phone: &str) -> Result<()> {
        // Nettoyer le numéro (supprimer espaces, tirets, parenthèses)
        let cleaned_phone = phone.chars()
            .filter(|c| c.is_ascii_digit() || *c == '+')
            .collect::<String>();

        if cleaned_phone.starts_with('+') {
            self.validate_string(&cleaned_phone, "phone_international")
        } else {
            self.validate_string(&cleaned_phone, "phone_local")
        }
    }

    /// Valide un nom (prénom/nom de famille)
    pub fn validate_name(&self, name: &str) -> Result<()> {
        self.validate_string(name, "name")?;

        // Vérifications supplémentaires
        if name.trim().is_empty() {
            return Err(AppError::Validation("Name cannot be empty".to_string()));
        }

        if name.chars().all(|c| c.is_whitespace()) {
            return Err(AppError::Validation("Name cannot contain only whitespace".to_string()));
        }

        Ok(())
    }

    /// Valide une organisation
    pub fn validate_organization(&self, organization: &str) -> Result<()> {
        self.validate_string(organization, "organization")?;

        if organization.trim().len() < 2 {
            return Err(AppError::Validation("Organization name too short".to_string()));
        }

        Ok(())
    }

    /// Valide des données d'image en base64 avec vérifications OWASP strictes
    pub fn validate_image_data(&self, base64_data: &str) -> Result<()> {
        // 1. Validation de la longueur base64
        if base64_data.len() > (self.max_file_size * 4 / 3 + 4) {
            return Err(AppError::Validation("Base64 data too long".to_string()));
        }

        // 2. Décoder les données base64
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|_| AppError::Validation("Invalid base64 image data".to_string()))?;

        // 3. Vérifier la taille décodée
        if decoded.len() > self.max_file_size {
            return Err(AppError::Validation(
                format!("Image too large (max {} bytes)", self.max_file_size)
            ));
        }

        // 4. Vérifier le type MIME par signature (magic numbers)
        let mime_type = self.detect_mime_type(&decoded)?;
        if !self.allowed_mime_types.contains(&mime_type) {
            return Err(AppError::Validation(
                format!("Unsupported image type: {}", mime_type)
            ));
        }

        // 5. Vérifications de sécurité supplémentaires
        self.validate_image_security(&decoded)?;

        // 6. Détection de contenu malveillant dans les métadonnées
        self.detect_malicious_content(&String::from_utf8_lossy(&decoded))?;

        tracing::info!("Image validation passed: {} bytes, type: {}", decoded.len(), mime_type);
        Ok(())
    }

    /// Détecte le type MIME d'un fichier
    fn detect_mime_type(&self, data: &[u8]) -> Result<String> {
        if data.len() < 8 {
            return Err(AppError::Validation("File too small to determine type".to_string()));
        }

        // Signatures de fichiers (magic numbers)
        match &data[0..8] {
            [0xFF, 0xD8, 0xFF, ..] => Ok("image/jpeg".to_string()),
            [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] => Ok("image/png".to_string()),
            [0x47, 0x49, 0x46, 0x38, 0x37, 0x61, ..] | [0x47, 0x49, 0x46, 0x38, 0x39, 0x61, ..] => Ok("image/gif".to_string()),
            [0x52, 0x49, 0x46, 0x46, _, _, _, _] if &data[8..12] == b"WEBP" => Ok("image/webp".to_string()),
            [0x25, 0x50, 0x44, 0x46, ..] => Ok("application/pdf".to_string()),
            _ => Err(AppError::Validation("Unknown or unsupported file type".to_string())),
        }
    }

    /// Valide la sécurité d'une image
    fn validate_image_security(&self, data: &[u8]) -> Result<()> {
        // Vérifier la présence de scripts ou de contenu malveillant
        let data_str = String::from_utf8_lossy(data);
        
        let dangerous_patterns = [
            "<script", "</script>", "javascript:", "vbscript:",
            "onload=", "onerror=", "onclick=", "onmouseover=",
            "<?php", "<%", "%>", "eval(", "exec(",
        ];

        for pattern in &dangerous_patterns {
            if data_str.to_lowercase().contains(pattern) {
                return Err(AppError::Validation(
                    "Image contains potentially malicious content".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Sanitise une chaîne de caractères
    pub fn sanitize_string(&self, input: &str) -> String {
        input
            .chars()
            .filter(|c| !c.is_control() || c.is_whitespace())
            .collect::<String>()
            .trim()
            .to_string()
    }

    /// Valide et sanitise du texte libre
    pub fn validate_and_sanitize_text(&self, text: &str, max_length: usize) -> Result<String> {
        if text.len() > max_length {
            return Err(AppError::Validation(
                format!("Text too long (max {} characters)", max_length)
            ));
        }

        let sanitized = self.sanitize_string(text);
        
        if sanitized.is_empty() && !text.trim().is_empty() {
            return Err(AppError::Validation("Text contains only invalid characters".to_string()));
        }

        self.validate_string(&sanitized, "safe_text")?;
        Ok(sanitized)
    }

    /// Valide un UUID
    pub fn validate_uuid(&self, uuid_str: &str) -> Result<()> {
        self.validate_string(uuid_str, "uuid")
    }

    /// Valide une URL
    pub fn validate_url(&self, url: &str) -> Result<()> {
        if url.len() > 2048 {
            return Err(AppError::Validation("URL too long".to_string()));
        }

        // Vérifier le schéma
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return Err(AppError::Validation("URL must use HTTP or HTTPS scheme".to_string()));
        }

        // Vérifier les caractères dangereux
        let dangerous_chars = ['<', '>', '"', '\'', '`', '{', '}', '|', '\\', '^', '[', ']'];
        if url.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(AppError::Validation("URL contains dangerous characters".to_string()));
        }

        Ok(())
    }

    /// Détecte les tentatives d'injection et attaques XSS selon OWASP A03:2021
    pub fn detect_malicious_content(&self, input: &str) -> Result<()> {
        let input_lower = input.to_lowercase();

        // Vérifier les mots-clés dangereux
        for keyword in &self.dangerous_keywords {
            if input_lower.contains(keyword) {
                tracing::warn!("Malicious keyword detected: {}", keyword);
                return Err(AppError::Validation(format!("Input contains dangerous content: {}", keyword)));
            }
        }

        // Vérifier les patterns interdits
        for pattern in &self.forbidden_patterns {
            if pattern.is_match(input) {
                tracing::warn!("Malicious pattern detected in input");
                return Err(AppError::Validation("Input contains potentially malicious patterns".to_string()));
            }
        }

        Ok(())
    }

    /// Validation complète avec détection de contenu malveillant
    pub fn validate_string_comprehensive(&self, input: &str, pattern_name: &str) -> Result<()> {
        // 1. Détection de contenu malveillant
        self.detect_malicious_content(input)?;

        // 2. Validation du format
        self.validate_string(input, pattern_name)?;

        tracing::debug!("Comprehensive validation passed for pattern: {}", pattern_name);
        Ok(())
    }

    /// Rejette les données inattendues selon les principes OWASP
    pub fn reject_unexpected_data(&self, input: &str, expected_type: &str) -> Result<()> {
        match expected_type {
            "numeric" => {
                if !input.chars().all(|c| c.is_ascii_digit()) {
                    return Err(AppError::Validation("Expected numeric data only".to_string()));
                }
            },
            "alpha" => {
                if !input.chars().all(|c| c.is_ascii_alphabetic()) {
                    return Err(AppError::Validation("Expected alphabetic data only".to_string()));
                }
            },
            "alphanumeric" => {
                if !input.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err(AppError::Validation("Expected alphanumeric data only".to_string()));
                }
            },
            _ => {
                return Err(AppError::Validation(format!("Unknown expected type: {}", expected_type)));
            }
        }

        Ok(())
    }
}

impl Default for InputValidationService {
    fn default() -> Self {
        Self::new().expect("Failed to create default InputValidationService")
    }
}

/// Instance globale du service de validation
static VALIDATION_SERVICE: OnceLock<InputValidationService> = OnceLock::new();

/// Obtient l'instance globale du service de validation
pub fn get_validation_service() -> &'static InputValidationService {
    VALIDATION_SERVICE.get_or_init(|| {
        InputValidationService::new().expect("Failed to initialize validation service")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_validation() {
        let service = InputValidationService::new().expect("Checked operation");
        
        assert!(service.validate_username("valid_user123").is_ok());
        assert!(service.validate_username("user.name").is_ok());
        assert!(service.validate_username("user-name").is_ok());
        
        assert!(service.validate_username("us").is_err()); // Trop court
        assert!(service.validate_username("user@name").is_err()); // Caractère invalide
        assert!(service.validate_username(".username").is_err()); // Commence par un point
        assert!(service.validate_username("user..name").is_err()); // Points consécutifs
    }

    #[test]
    fn test_email_validation() {
        let service = InputValidationService::new().expect("Checked operation");
        
        assert!(service.validate_email("user@example.com").is_ok());
        assert!(service.validate_email("test.email+tag@domain.co.uk").is_ok());
        
        assert!(service.validate_email("invalid-email").is_err());
        assert!(service.validate_email("@domain.com").is_err());
        assert!(service.validate_email("user@").is_err());
    }

    #[test]
    fn test_phone_validation() {
        let service = InputValidationService::new().expect("Checked operation");
        
        assert!(service.validate_phone("+33123456789").is_ok());
        assert!(service.validate_phone("0123456789").is_ok());
        assert!(service.validate_phone("+1 (555) 123-4567").is_ok()); // Sera nettoyé
        
        assert!(service.validate_phone("123").is_err()); // Trop court
        assert!(service.validate_phone("abc123").is_err()); // Lettres
    }

    #[test]
    fn test_image_validation() {
        let service = InputValidationService::new().expect("Checked operation");
        
        // PNG valide (signature)
        let png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let png_base64 = base64::engine::general_purpose::STANDARD.encode(&png_data);
        assert!(service.validate_image_data(&png_base64).is_ok());
        
        // Données invalides
        assert!(service.validate_image_data("invalid_base64").is_err());
    }

    #[test]
    fn test_text_sanitization() {
        let service = InputValidationService::new().expect("Checked operation");
        
        let input = "  Hello\x00World\t  ";
        let sanitized = service.sanitize_string(input);
        assert_eq!(sanitized, "HelloWorld");
        
        let result = service.validate_and_sanitize_text("Valid text content", 100);
        assert!(result.is_ok());
        assert_eq!(result.expect("Checked operation"), "Valid text content");
    }

    #[test]
    fn test_malicious_content_detection() {
        let service = InputValidationService::new().expect("Checked operation");

        // Test XSS
        assert!(service.detect_malicious_content("<script>alert('xss')</script>").is_err());
        assert!(service.detect_malicious_content("javascript:alert(1)").is_err());
        assert!(service.detect_malicious_content("onload=malicious()").is_err());

        // Test SQL Injection
        assert!(service.detect_malicious_content("'; DROP TABLE users; --").is_err());
        assert!(service.detect_malicious_content("UNION SELECT * FROM passwords").is_err());

        // Test contenu sain
        assert!(service.detect_malicious_content("Hello world").is_ok());
        assert!(service.detect_malicious_content("user@example.com").is_ok());
    }

    #[test]
    fn test_comprehensive_validation() {
        let service = InputValidationService::new().expect("Checked operation");

        // Test validation complète avec contenu sain
        assert!(service.validate_string_comprehensive("user123", "username").is_ok());
        assert!(service.validate_string_comprehensive("test@example.com", "email").is_ok());

        // Test validation complète avec contenu malveillant
        assert!(service.validate_string_comprehensive("<script>alert(1)</script>", "safe_text").is_err());
        assert!(service.validate_string_comprehensive("javascript:alert(1)", "safe_text").is_err());
    }

    #[test]
    fn test_unexpected_data_rejection() {
        let service = InputValidationService::new().expect("Checked operation");

        // Test données numériques
        assert!(service.reject_unexpected_data("12345", "numeric").is_ok());
        assert!(service.reject_unexpected_data("123abc", "numeric").is_err());

        // Test données alphabétiques
        assert!(service.reject_unexpected_data("abcdef", "alpha").is_ok());
        assert!(service.reject_unexpected_data("abc123", "alpha").is_err());

        // Test données alphanumériques
        assert!(service.reject_unexpected_data("abc123", "alphanumeric").is_ok());
        assert!(service.reject_unexpected_data("abc-123", "alphanumeric").is_err());
    }
}
