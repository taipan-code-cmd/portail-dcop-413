// DCOP (413) - Configuration de Sécurité Moderne
// Gestion centralisée des paramètres de sécurité selon les standards OWASP et NIST

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::security::secrets_manager::SecretsManager;

/// Configuration de la sécurité de l'authentification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSecurityConfig {
    /// Durée de vie des tokens JWT
    pub jwt_expiration: Duration,
    /// Durée de grâce pour le refresh des tokens
    pub jwt_refresh_window: Duration,
    /// Algorithme de signature JWT
    pub jwt_algorithm: String,
    /// Nombre maximum de tentatives de connexion
    pub max_login_attempts: u32,
    /// Durée de blocage après échec
    pub lockout_duration: Duration,
    /// Durée de session
    pub session_timeout: Duration,
    /// Activation de la double authentification
    pub require_mfa: bool,
    /// Longueur minimum des mots de passe
    pub min_password_length: usize,
    /// Complexité requise des mots de passe
    pub password_complexity: PasswordComplexity,
}

/// Règles de complexité des mots de passe selon NIST SP 800-63B
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordComplexity {
    pub min_length: usize,
    pub max_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digits: bool,
    pub require_special_chars: bool,
    pub forbidden_patterns: Vec<String>,
    pub check_common_passwords: bool,
    pub check_breach_databases: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Limites par endpoint
    pub endpoint_limits: HashMap<String, EndpointRateLimit>,
    /// Configuration Valkey pour le stockage distribué
    pub valkey_config: Option<ValkeyConfig>,
    /// Algorithme de limitation (token bucket, sliding window, etc.)
    pub algorithm: RateLimitAlgorithm,
    /// Exemptions par IP
    pub ip_exemptions: Vec<IpNetwork>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRateLimit {
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub requests_per_day: u32,
    pub burst_capacity: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RateLimitAlgorithm {
    TokenBucket,
    SlidingWindow,
    FixedWindow,
    LeakyBucket,
}

/// Configuration Valkey pour la mise en cache et le rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValkeyConfig {
    pub url: String,
    pub pool_size: u32,
    pub timeout: Duration,
    pub retry_attempts: u32,
    pub cluster_mode: bool,
}

/// Configuration de chiffrement selon les standards modernes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Algorithme de chiffrement symétrique
    pub symmetric_algorithm: SymmetricAlgorithm,
    /// Algorithme de hachage
    pub hash_algorithm: HashAlgorithm,
    /// Configuration Argon2
    pub argon2_config: Argon2Config,
    /// Rotation automatique des clés
    pub key_rotation_interval: Duration,
    /// Taille des clés en bits
    pub key_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymmetricAlgorithm {
    AesGcm256,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Blake3,
    Sha3_256,
    Sha2_256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Config {
    pub memory_cost: u32,     // En KiB
    pub time_cost: u32,       // Nombre d'itérations
    pub parallelism: u32,     // Nombre de threads
    pub output_length: usize, // Longueur en bytes
}

/// Configuration de sécurité réseau
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    /// IPs autorisées (whitelist)
    pub allowed_ips: Vec<IpNetwork>,
    /// IPs bloquées (blacklist)
    pub blocked_ips: Vec<IpNetwork>,
    /// Protection contre les attaques DDoS
    pub ddos_protection: DdosProtectionConfig,
    /// Configuration TLS/SSL
    pub tls_config: TlsConfig,
    /// Headers de sécurité HTTP
    pub security_headers: SecurityHeaders,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosProtectionConfig {
    pub enabled: bool,
    pub threshold_requests_per_second: u32,
    pub threshold_requests_per_minute: u32,
    pub block_duration: Duration,
    pub challenge_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub min_version: String,
    pub max_version: String,
    pub cipher_suites: Vec<String>,
    pub prefer_server_cipher_order: bool,
    pub certificate_transparency: bool,
    pub hsts_max_age: Duration,
    pub require_sni: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaders {
    pub content_security_policy: String,
    pub x_frame_options: String,
    pub x_content_type_options: String,
    pub x_xss_protection: String,
    pub referrer_policy: String,
    pub permissions_policy: String,
    pub strict_transport_security: String,
    pub expect_ct: String,
}

/// Configuration d'audit et de logging de sécurité
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Niveau de logging
    pub log_level: String,
    /// Events à auditer
    pub audit_events: Vec<AuditEventType>,
    /// Rétention des logs
    pub log_retention: Duration,
    /// Destination des logs
    pub log_destination: LogDestination,
    /// Chiffrement des logs
    pub encrypt_logs: bool,
    /// Intégrité des logs
    pub log_integrity_check: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    SystemChanges,
    SecurityEvents,
    Errors,
    PerformanceIssues,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogDestination {
    File { path: PathBuf },
    Syslog { facility: String },
    Database { connection_string: String },
    Remote { url: String, token: Option<String> },
    Multiple(Vec<LogDestination>),
}

/// Configuration principale de sécurité
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Mode de développement/production
    pub development_mode: bool,
    /// Configuration de l'authentification
    pub auth: AuthSecurityConfig,
    /// Configuration de la limitation de débit
    pub rate_limiting: RateLimitConfig,
    /// Configuration du chiffrement
    pub encryption: EncryptionConfig,
    /// Configuration réseau
    pub network: NetworkSecurityConfig,
    /// Configuration d'audit
    pub audit: AuditConfig,
    /// Environnements de déploiement
    pub environments: HashMap<String, EnvironmentConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    pub name: String,
    pub debug: bool,
    pub log_level: String,
    pub allowed_origins: Vec<String>,
    pub database_encryption: bool,
    pub backup_encryption: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self::production_defaults()
    }
}

impl SecurityConfig {
    /// Configuration sécurisée pour la production
    pub fn production_defaults() -> Self {
        Self {
            development_mode: false,
            auth: AuthSecurityConfig::production_defaults(),
            rate_limiting: RateLimitConfig::production_defaults(),
            encryption: EncryptionConfig::production_defaults(),
            network: NetworkSecurityConfig::production_defaults(),
            audit: AuditConfig::production_defaults(),
            environments: Self::default_environments(),
        }
    }

    /// Configuration pour le développement (moins restrictive)
    pub fn development_defaults() -> Self {
        let mut config = Self::production_defaults();
        config.development_mode = true;
        config.auth.lockout_duration = Duration::from_secs(60); // 1 minute au lieu de 15
        config.auth.max_login_attempts = 10; // Plus permissif
        config.rate_limiting.endpoint_limits.get_mut("/api/auth/login")
            .map(|limit| limit.requests_per_minute = 100); // Plus permissif
        config.audit.log_level = "debug".to_string();
        config
    }

    /// Charge la configuration depuis les variables d'environnement et secrets
    pub async fn load_from_environment(_secrets_manager: &SecretsManager) -> Result<Self> {
        info!("Loading security configuration from environment");

        let env_type = std::env::var("DEPLOYMENT_ENV").unwrap_or_else(|_| "development".to_string());
        
        let mut config = match env_type.as_str() {
            "production" => Self::production_defaults(),
            "staging" => {
                let mut config = Self::production_defaults();
                config.development_mode = false;
                config.audit.log_level = "info".to_string();
                config
            }
            _ => Self::development_defaults(),
        };

        // Personnaliser avec les variables d'environnement
        config.customize_from_env().await?;

        // Valider la configuration
        config.validate()?;

        info!("Security configuration loaded successfully for environment: {}", env_type);
        Ok(config)
    }

    /// Personnalise la configuration avec les variables d'environnement
    async fn customize_from_env(&mut self) -> Result<()> {
        // JWT Configuration
        if let Ok(jwt_exp) = std::env::var("JWT_EXPIRATION_HOURS") {
            if let Ok(hours) = jwt_exp.parse::<u64>() {
                self.auth.jwt_expiration = Duration::from_secs(hours * 3600);
            }
        }

        // Session timeout
        if let Ok(session_timeout) = std::env::var("SESSION_TIMEOUT_MINUTES") {
            if let Ok(minutes) = session_timeout.parse::<u64>() {
                self.auth.session_timeout = Duration::from_secs(minutes * 60);
            }
        }

        // Max login attempts
        if let Ok(max_attempts) = std::env::var("MAX_LOGIN_ATTEMPTS") {
            if let Ok(attempts) = max_attempts.parse::<u32>() {
                self.auth.max_login_attempts = attempts;
            }
        }

        // Lockout duration
        if let Ok(lockout) = std::env::var("LOCKOUT_DURATION_MINUTES") {
            if let Ok(minutes) = lockout.parse::<u64>() {
                self.auth.lockout_duration = Duration::from_secs(minutes * 60);
            }
        }

        // Log level
        if let Ok(log_level) = std::env::var("SECURITY_LOG_LEVEL") {
            self.audit.log_level = log_level;
        }

        debug!("Security configuration customized from environment variables");
        Ok(())
    }

    /// Valide la configuration de sécurité
    pub fn validate(&self) -> Result<()> {
        // Validation de l'authentification
        if self.auth.jwt_expiration < Duration::from_secs(300) {
            return Err(anyhow::anyhow!("JWT expiration too short (minimum 5 minutes)"));
        }

        if self.auth.jwt_expiration > Duration::from_secs(24 * 3600) {
            warn!("JWT expiration longer than 24 hours - consider shorter expiration");
        }

        if self.auth.max_login_attempts < 3 {
            return Err(anyhow::anyhow!("Max login attempts too low (minimum 3)"));
        }

        if self.auth.max_login_attempts > 20 {
            warn!("Max login attempts very high - consider lowering for better security");
        }

        // Validation du chiffrement
        if self.encryption.key_size < 256 {
            return Err(anyhow::anyhow!("Encryption key size too small (minimum 256 bits)"));
        }

        if self.encryption.argon2_config.memory_cost < 32768 {
            warn!("Argon2 memory cost might be too low for production");
        }

        // Validation de la limitation de débit
        for (endpoint, limit) in &self.rate_limiting.endpoint_limits {
            if limit.requests_per_minute == 0 {
                return Err(anyhow::anyhow!("Rate limit for {} cannot be zero", endpoint));
            }
        }

        info!("Security configuration validation passed");
        Ok(())
    }

    fn default_environments() -> HashMap<String, EnvironmentConfig> {
        let mut envs = HashMap::new();

        envs.insert("development".to_string(), EnvironmentConfig {
            name: "development".to_string(),
            debug: true,
            log_level: "debug".to_string(),
            allowed_origins: vec!["http://localhost:8443".to_string()],
            database_encryption: false,
            backup_encryption: true,
        });

        envs.insert("staging".to_string(), EnvironmentConfig {
            name: "staging".to_string(),
            debug: false,
            log_level: "info".to_string(),
            allowed_origins: vec!["https://staging.dcop413.fr".to_string()],
            database_encryption: true,
            backup_encryption: true,
        });

        envs.insert("production".to_string(), EnvironmentConfig {
            name: "production".to_string(),
            debug: false,
            log_level: "warn".to_string(),
            allowed_origins: vec!["https://dcop413.fr".to_string()],
            database_encryption: true,
            backup_encryption: true,
        });

        envs
    }

    /// Retourne la configuration de l'environnement actuel
    pub fn current_environment(&self) -> &EnvironmentConfig {
        let env_name = std::env::var("DEPLOYMENT_ENV").unwrap_or_else(|_| "development".to_string());
        self.environments.get(&env_name).unwrap_or_else(|| {
            warn!("Environment {} not found, using development defaults", env_name);
            self.environments.get("development").expect("Checked operation")
        })
    }
}

impl AuthSecurityConfig {
    fn production_defaults() -> Self {
        Self {
            jwt_expiration: Duration::from_secs(15 * 60), // 15 minutes
            jwt_refresh_window: Duration::from_secs(5 * 60), // 5 minutes
            jwt_algorithm: "HS512".to_string(),
            max_login_attempts: 5,
            lockout_duration: Duration::from_secs(15 * 60), // 15 minutes
            session_timeout: Duration::from_secs(30 * 60), // 30 minutes
            require_mfa: false, // À activer progressivement
            min_password_length: 12,
            password_complexity: PasswordComplexity::nist_standards(),
        }
    }
}

impl PasswordComplexity {
    fn nist_standards() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_digits: true,
            require_special_chars: true,
            forbidden_patterns: vec![
                "password".to_string(),
                "123456".to_string(),
                "qwerty".to_string(),
                "admin".to_string(),
                "root".to_string(),
            ],
            check_common_passwords: true,
            check_breach_databases: false, // Nécessite une API externe
        }
    }
}

impl RateLimitConfig {
    fn production_defaults() -> Self {
        let mut endpoint_limits = HashMap::new();

        endpoint_limits.insert("/api/auth/login".to_string(), EndpointRateLimit {
            requests_per_minute: 10,
            requests_per_hour: 100,
            requests_per_day: 1000,
            burst_capacity: 5,
        });

        endpoint_limits.insert("/api/auth/register".to_string(), EndpointRateLimit {
            requests_per_minute: 5,
            requests_per_hour: 20,
            requests_per_day: 50,
            burst_capacity: 2,
        });

        endpoint_limits.insert("/api/*".to_string(), EndpointRateLimit {
            requests_per_minute: 100,
            requests_per_hour: 1000,
            requests_per_day: 10000,
            burst_capacity: 20,
        });

        Self {
            endpoint_limits,
            valkey_config: None, // À configurer si Valkey est disponible
            algorithm: RateLimitAlgorithm::TokenBucket,
            ip_exemptions: vec![], // À configurer avec les IPs internes
        }
    }
}

impl EncryptionConfig {
    fn production_defaults() -> Self {
        Self {
            symmetric_algorithm: SymmetricAlgorithm::AesGcm256,
            hash_algorithm: HashAlgorithm::Blake3,
            argon2_config: Argon2Config {
                memory_cost: 65536, // 64 MiB
                time_cost: 3,
                parallelism: 4,
                output_length: 32,
            },
            key_rotation_interval: Duration::from_secs(30 * 24 * 3600), // 30 jours
            key_size: 256,
        }
    }
}

impl NetworkSecurityConfig {
    fn production_defaults() -> Self {
        Self {
            allowed_ips: vec![], // À configurer selon les besoins
            blocked_ips: vec![], // À maintenir avec les IPs malveillantes
            ddos_protection: DdosProtectionConfig {
                enabled: true,
                threshold_requests_per_second: 100,
                threshold_requests_per_minute: 1000,
                block_duration: Duration::from_secs(300), // 5 minutes
                challenge_mode: false,
            },
            tls_config: TlsConfig {
                min_version: "1.2".to_string(),
                max_version: "1.3".to_string(),
                cipher_suites: vec![
                    "TLS_AES_256_GCM_SHA384".to_string(),
                    "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                    "TLS_AES_128_GCM_SHA256".to_string(),
                ],
                prefer_server_cipher_order: true,
                certificate_transparency: true,
                hsts_max_age: Duration::from_secs(365 * 24 * 3600), // 1 an
                require_sni: true,
            },
            security_headers: SecurityHeaders::strict_defaults(),
        }
    }
}

impl SecurityHeaders {
    fn strict_defaults() -> Self {
        Self {
            content_security_policy: "default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self' 'nonce-{random}'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content".to_string(),
            x_frame_options: "DENY".to_string(),
            x_content_type_options: "nosniff".to_string(),
            x_xss_protection: "1; mode=block".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: "geolocation=(), microphone=(), camera=()".to_string(),
            strict_transport_security: "max-age=31536000; includeSubDomains; preload".to_string(),
            expect_ct: "enforce, max-age=86400".to_string(),
        }
    }
}

impl AuditConfig {
    fn production_defaults() -> Self {
        Self {
            log_level: "info".to_string(),
            audit_events: vec![
                AuditEventType::Authentication,
                AuditEventType::Authorization,
                AuditEventType::DataAccess,
                AuditEventType::DataModification,
                AuditEventType::SecurityEvents,
                AuditEventType::Errors,
            ],
            log_retention: Duration::from_secs(90 * 24 * 3600), // 90 jours
            log_destination: LogDestination::Multiple(vec![
                LogDestination::File { path: PathBuf::from("/app/logs/security.log") },
                LogDestination::Syslog { facility: "local0".to_string() },
            ]),
            encrypt_logs: true,
            log_integrity_check: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_config_validation() {
        let config = SecurityConfig::production_defaults();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_development_config_validation() {
        let config = SecurityConfig::development_defaults();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_password_complexity_nist() {
        let complexity = PasswordComplexity::nist_standards();
        assert!(complexity.min_length >= 8);
        assert!(complexity.require_uppercase);
        assert!(complexity.check_common_passwords);
    }

    #[test]
    fn test_rate_limit_config() {
        let config = RateLimitConfig::production_defaults();
        assert!(!config.endpoint_limits.is_empty());
        
        let login_limit = config.endpoint_limits.get("/api/auth/login").expect("Checked operation");
        assert!(login_limit.requests_per_minute > 0);
    }
}
