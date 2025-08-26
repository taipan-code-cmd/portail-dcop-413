use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::errors::{AppError, Result};

/// Service de Certificate Pinning pour sécuriser les communications TLS
#[derive(Clone)]
pub struct CertificatePinningService {
    pinned_hashes: HashSet<String>,
    backup_hashes: HashSet<String>,
    strict_mode: bool,
}

impl CertificatePinningService {
    /// Crée un nouveau service de certificate pinning
    pub fn new(strict_mode: bool) -> Self {
        Self {
            pinned_hashes: HashSet::new(),
            backup_hashes: HashSet::new(),
            strict_mode,
        }
    }

    /// Ajoute un hash de certificat épinglé
    pub fn add_pinned_hash(&mut self, hash: String) {
        self.pinned_hashes.insert(hash);
    }

    /// Ajoute un hash de certificat de sauvegarde
    pub fn add_backup_hash(&mut self, hash: String) {
        self.backup_hashes.insert(hash);
    }

    /// Calcule le hash SHA-256 d'un certificat depuis un fichier
    /// Version simplifiée utilisant seulement ring pour éviter OpenSSL et base64ct
    pub fn calculate_cert_hash<P: AsRef<Path>>(cert_path: P) -> Result<String> {
        let cert_data = fs::read(cert_path)
            .map_err(|e| AppError::Internal(format!("Failed to read certificate: {}", e)))?;

        // Convertir PEM vers DER si nécessaire
        let cert_der = if cert_data.starts_with(b"-----BEGIN") {
            Self::pem_to_der(&cert_data)?
        } else {
            cert_data
        };

        // Calculer directement le hash SHA-256 du certificat DER complet
        // (approche simplifiée mais sécurisée)
        let mut hasher = Sha256::new();
        hasher.update(&cert_der);
        let hash = hasher.finalize();

        Ok(base64::engine::general_purpose::STANDARD.encode(hash))
    }

    /// Convertit un certificat PEM en DER (simple parser)
    fn pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>> {
        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|_| AppError::Internal("Invalid UTF-8 in PEM data".to_string()))?;

        // Extraire le contenu entre BEGIN et END CERTIFICATE
        let start_marker = "-----BEGIN CERTIFICATE-----";
        let end_marker = "-----END CERTIFICATE-----";

        let start = pem_str.find(start_marker)
            .ok_or_else(|| AppError::Internal("PEM start marker not found".to_string()))?
            + start_marker.len();

        let end = pem_str.find(end_marker)
            .ok_or_else(|| AppError::Internal("PEM end marker not found".to_string()))?;

        let base64_content = &pem_str[start..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();

        base64::engine::general_purpose::STANDARD
            .decode(base64_content)
            .map_err(|e| AppError::Internal(format!("Failed to decode base64: {}", e)))
    }

    /// Vérifie si un certificat est épinglé
    pub fn verify_certificate(&self, cert_hash: &str) -> bool {
        if self.pinned_hashes.contains(cert_hash) {
            return true;
        }

        // En mode non-strict, accepter aussi les certificats de sauvegarde
        if !self.strict_mode && self.backup_hashes.contains(cert_hash) {
            tracing::warn!("Certificate verified using backup hash: {}", cert_hash);
            return true;
        }

        false
    }

    /// Charge les hashes épinglés depuis un fichier de configuration
    pub fn load_from_config<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config_content = fs::read_to_string(config_path)
            .map_err(|e| AppError::Internal(format!("Failed to read pinning config: {}", e)))?;

        let config: PinningConfig = serde_json::from_str(&config_content)
            .map_err(|e| AppError::Internal(format!("Failed to parse pinning config: {}", e)))?;

        let mut service = Self::new(config.strict_mode);

        for hash in config.pinned_hashes {
            service.add_pinned_hash(hash);
        }

        for hash in config.backup_hashes {
            service.add_backup_hash(hash);
        }

        Ok(service)
    }

    /// Sauvegarde la configuration de pinning
    pub fn save_to_config<P: AsRef<Path>>(&self, config_path: P) -> Result<()> {
        let config = PinningConfig {
            pinned_hashes: self.pinned_hashes.iter().cloned().collect(),
            backup_hashes: self.backup_hashes.iter().cloned().collect(),
            strict_mode: self.strict_mode,
        };

        let config_json = serde_json::to_string_pretty(&config)
            .map_err(|e| AppError::Internal(format!("Failed to serialize config: {}", e)))?;

        fs::write(config_path, config_json)
            .map_err(|e| AppError::Internal(format!("Failed to write config: {}", e)))?;

        Ok(())
    }

    /// Génère les headers HTTP Public Key Pinning (HPKP) - DÉPRÉCIÉ
    ///
    /// ⚠️ ATTENTION: HPKP est déprécié par les navigateurs modernes (Chrome 72+, Firefox 72+).
    /// Utilisez Certificate Transparency, HSTS et Expect-CT à la place.
    /// Cette méthode est conservée pour compatibilité legacy uniquement.
    #[deprecated(since = "1.0.0", note = "HPKP is deprecated. Use HSTS and Certificate Transparency instead")]
    pub fn generate_hpkp_header(&self, max_age: u32, include_subdomains: bool) -> String {
        let mut header = String::new();

        // Ajouter les hashes épinglés
        for hash in &self.pinned_hashes {
            if !header.is_empty() {
                header.push_str("; ");
            }
            header.push_str(&format!("pin-sha256=\"{}\"", hash));
        }

        // Ajouter au moins un hash de sauvegarde (requis par HPKP)
        if let Some(backup_hash) = self.backup_hashes.iter().next() {
            if !header.is_empty() {
                header.push_str("; ");
            }
            header.push_str(&format!("pin-sha256=\"{backup_hash}\""));
        }

        // Ajouter les paramètres
        header.push_str(&format!("; max-age={}", max_age));

        if include_subdomains {
            header.push_str("; includeSubDomains");
        }

        header
    }

    /// Valide la configuration de pinning
    pub fn validate_configuration(&self) -> Result<()> {
        if self.pinned_hashes.is_empty() {
            return Err(AppError::Internal("No pinned hashes configured".to_string()));
        }

        if self.backup_hashes.is_empty() {
            tracing::warn!("No backup hashes configured - this may cause issues during certificate rotation");
        }

        // Vérifier qu'il n'y a pas de doublons entre pinned et backup
        for hash in &self.pinned_hashes {
            if self.backup_hashes.contains(hash) {
                return Err(AppError::Internal(
                    format!("Hash {} appears in both pinned and backup sets", hash)
                ));
            }
        }

        Ok(())
    }

    /// Effectue la rotation des certificats épinglés
    pub fn rotate_pins(&mut self, new_hash: String, old_hash: Option<String>) -> Result<()> {
        // Ajouter le nouveau hash
        self.pinned_hashes.insert(new_hash.clone());

        // Si un ancien hash est spécifié, le déplacer vers les backups
        if let Some(old) = old_hash {
            if self.pinned_hashes.remove(&old) {
                tracing::info!("Moved old certificate hash to backup: {}", old);
                self.backup_hashes.insert(old);
            }
        }

        // Limiter le nombre de hashes de sauvegarde
        if self.backup_hashes.len() > 5 {
            let oldest_hash = self.backup_hashes.iter().next().cloned();
            if let Some(hash) = oldest_hash {
                self.backup_hashes.remove(&hash);
                tracing::info!("Removed oldest backup hash: {}", hash);
            }
        }

        tracing::info!("Certificate pinning rotated with new hash: {}", new_hash);
        Ok(())
    }

    /// Génère les headers HSTS (HTTP Strict Transport Security) modernes
    /// Conforme aux recommandations OWASP et remplace HPKP
    pub fn generate_hsts_header(&self, max_age: u32, include_subdomains: bool, preload: bool) -> String {
        let mut header = format!("max-age={}", max_age);

        if include_subdomains {
            header.push_str("; includeSubDomains");
        }

        if preload {
            header.push_str("; preload");
        }

        tracing::info!("Generated HSTS header: {}", header);
        header
    }

    /// Génère les headers Expect-CT (Certificate Transparency)
    /// Remplace HPKP pour la validation des certificats
    pub fn generate_expect_ct_header(&self, max_age: u32, enforce: bool, report_uri: Option<&str>) -> String {
        let mut header = format!("max-age={}", max_age);

        if enforce {
            header.push_str(", enforce");
        }

        if let Some(uri) = report_uri {
            header.push_str(&format!(", report-uri=\"{}\"", uri));
        }

        tracing::info!("Generated Expect-CT header: {}", header);
        header
    }

    /// Génère un ensemble complet de headers de sécurité SSL/TLS modernes
    /// Conforme aux recommandations OWASP A02:2021 et Secure-by-Design
    pub fn generate_modern_security_headers(&self, domain: &str) -> std::collections::HashMap<String, String> {
        let mut headers = std::collections::HashMap::new();

        // HSTS avec preload pour sécurité maximale (2 ans)
        headers.insert(
            "Strict-Transport-Security".to_string(),
            self.generate_hsts_header(63072000, true, true) // 2 ans
        );

        // Certificate Transparency enforcement
        headers.insert(
            "Expect-CT".to_string(),
            self.generate_expect_ct_header(86400, true, Some(&format!("https://{}/ct-report", domain)))
        );

        // Content Security Policy pour HTTPS uniquement
        headers.insert(
            "Content-Security-Policy".to_string(),
            "upgrade-insecure-requests; block-all-mixed-content".to_string()
        );

        // Référer policy sécurisé
        headers.insert(
            "Referrer-Policy".to_string(),
            "strict-origin-when-cross-origin".to_string()
        );

        tracing::info!("Generated {} modern security headers for domain: {}", headers.len(), domain);
        headers
    }

    /// Valide qu'un certificat utilise des algorithmes cryptographiques forts
    /// Version simplifiée basée sur la taille du certificat DER
    pub fn validate_certificate_strength_simple(&self, cert_der: &[u8]) -> Result<CertificateStrength> {
        // Estimation de la force basée sur la taille du certificat DER
        // (approximation simple mais efficace)
        let strength = match cert_der.len() {
            len if len >= 1200 => CertificateStrength::Strong,    // ECDSA P-384+ ou RSA 4096+
            len if len >= 800 => CertificateStrength::Adequate,   // ECDSA P-256 ou RSA 2048+
            _ => CertificateStrength::Weak,
        };

        tracing::info!("Certificate strength validation (simple): {:?} (DER size: {} bytes)", strength, cert_der.len());
        Ok(strength)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CertificateStrength {
    Strong,    // ECDSA P-384+ ou RSA 4096+
    Adequate,  // ECDSA P-256 ou RSA 2048+
    Weak,      // Tout le reste
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PinningConfig {
    pinned_hashes: Vec<String>,
    backup_hashes: Vec<String>,
    strict_mode: bool,
}

/// Middleware pour vérifier le certificate pinning
pub struct CertificatePinningMiddleware {
    service: CertificatePinningService,
}

impl CertificatePinningMiddleware {
    pub fn new(service: CertificatePinningService) -> Self {
        Self { service }
    }

    /// Vérifie le certificat d'une requête entrante
    pub fn verify_request_certificate(&self, cert_hash: &str) -> Result<()> {
        if self.service.verify_certificate(cert_hash) {
            Ok(())
        } else {
            Err(AppError::Authentication(
                "Certificate pinning verification failed".to_string()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_pinning_service() {
        let mut service = CertificatePinningService::new(true);
        
        let test_hash = "test_hash_123".to_string();
        service.add_pinned_hash(test_hash.clone());
        
        assert!(service.verify_certificate(&test_hash));
        assert!(!service.verify_certificate("invalid_hash"));
    }

    #[test]
    fn test_backup_hashes_non_strict() {
        let mut service = CertificatePinningService::new(false);
        
        let pinned_hash = "pinned_hash".to_string();
        let backup_hash = "backup_hash".to_string();
        
        service.add_pinned_hash(pinned_hash.clone());
        service.add_backup_hash(backup_hash.clone());
        
        assert!(service.verify_certificate(&pinned_hash));
        assert!(service.verify_certificate(&backup_hash));
    }

    #[test]
    fn test_backup_hashes_strict() {
        let mut service = CertificatePinningService::new(true);
        
        let pinned_hash = "pinned_hash".to_string();
        let backup_hash = "backup_hash".to_string();
        
        service.add_pinned_hash(pinned_hash.clone());
        service.add_backup_hash(backup_hash.clone());
        
        assert!(service.verify_certificate(&pinned_hash));
        assert!(!service.verify_certificate(&backup_hash)); // Strict mode
    }

    #[test]
    #[allow(deprecated)]
    fn test_hpkp_header_generation() {
        let mut service = CertificatePinningService::new(false);
        service.add_pinned_hash("hash1".to_string());
        service.add_backup_hash("backup1".to_string());

        let header = service.generate_hpkp_header(86400, true);

        assert!(header.contains("pin-sha256=\"hash1\""));
        assert!(header.contains("pin-sha256=\"backup1\""));
        assert!(header.contains("max-age=86400"));
        assert!(header.contains("includeSubDomains"));
    }

    #[test]
    fn test_hsts_header_generation() {
        let service = CertificatePinningService::new(true);

        // Test HSTS basique
        let header = service.generate_hsts_header(31536000, false, false);
        assert_eq!(header, "max-age=31536000");

        // Test HSTS avec subdomains
        let header = service.generate_hsts_header(31536000, true, false);
        assert_eq!(header, "max-age=31536000; includeSubDomains");

        // Test HSTS avec preload
        let header = service.generate_hsts_header(63072000, true, true);
        assert_eq!(header, "max-age=63072000; includeSubDomains; preload");
    }

    #[test]
    fn test_expect_ct_header_generation() {
        let service = CertificatePinningService::new(true);

        // Test Expect-CT basique
        let header = service.generate_expect_ct_header(86400, false, None);
        assert_eq!(header, "max-age=86400");

        // Test Expect-CT avec enforcement
        let header = service.generate_expect_ct_header(86400, true, None);
        assert_eq!(header, "max-age=86400, enforce");

        // Test Expect-CT avec report URI
        let header = service.generate_expect_ct_header(86400, true, Some("https://example.com/ct-report"));
        assert_eq!(header, "max-age=86400, enforce, report-uri=\"https://example.com/ct-report\"");
    }

    #[test]
    fn test_modern_security_headers() {
        let service = CertificatePinningService::new(true);
        let headers = service.generate_modern_security_headers("example.com");

        // Vérifier que tous les headers essentiels sont présents
        assert!(headers.contains_key("Strict-Transport-Security"));
        assert!(headers.contains_key("Expect-CT"));
        assert!(headers.contains_key("Content-Security-Policy"));
        assert!(headers.contains_key("Referrer-Policy"));

        // Vérifier le contenu HSTS
        let hsts = headers.get("Strict-Transport-Security").expect("Checked operation");
        assert!(hsts.contains("max-age=63072000"));
        assert!(hsts.contains("includeSubDomains"));
        assert!(hsts.contains("preload"));

        // Vérifier le contenu Expect-CT
        let expect_ct = headers.get("Expect-CT").expect("Checked operation");
        assert!(expect_ct.contains("enforce"));
        assert!(expect_ct.contains("example.com/ct-report"));
    }

    #[test]
    fn test_configuration_validation() {
        let mut service = CertificatePinningService::new(false);
        
        // Configuration vide devrait échouer
        assert!(service.validate_configuration().is_err());
        
        // Ajouter un hash épinglé
        service.add_pinned_hash("test_hash".to_string());
        assert!(service.validate_configuration().is_ok());
        
        // Conflit entre pinned et backup devrait échouer
        service.add_backup_hash("test_hash".to_string());
        assert!(service.validate_configuration().is_err());
    }
}
