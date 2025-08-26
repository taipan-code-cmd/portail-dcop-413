use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

// Fonction helper pour lire les secrets Docker de manière sécurisée
// Conforme aux principes Secure-by-Design et OWASP
pub fn read_secret_or_env(file_env: &str, direct_env: &str) -> anyhow::Result<String> {
    // Priorité 1: Lire depuis le fichier secret Docker (production)
    if let Ok(file_path) = env::var(file_env) {
        match fs::read_to_string(&file_path) {
            Ok(content) => {
                let secret = content.trim().to_string();

                // Validation de la force du secret selon OWASP
                if secret.len() < 32 {
                    tracing::warn!("Secret from {} is weak (< 256 bits) - SECURITY RISK", file_env);
                }

                tracing::debug!("Loaded secret from file: {}", file_env);
                return Ok(secret);
            },
            Err(e) => {
                tracing::warn!("Failed to read secret file {}: {}", file_path, e);
            }
        }
    }

    // Priorité 2: Fallback sur la variable d'environnement directe (développement)
    match env::var(direct_env) {
        Ok(secret) => {
            if secret.len() < 32 {
                tracing::warn!("Secret from {} is weak (< 256 bits) - SECURITY RISK", direct_env);
            }

            // Vérifier si c'est un secret de développement
            if secret.contains("dev_") || secret.contains("development") {
                tracing::warn!("Using development secret from {} - NOT FOR PRODUCTION", direct_env);
            }

            tracing::debug!("Loaded secret from environment: {}", direct_env);
            Ok(secret)
        },
        Err(_) => {
            Err(anyhow::anyhow!(
                "Secret not found: neither {} (file) nor {} (env) are set. Use generate-secrets.sh to create secure secrets.",
                file_env,
                direct_env
            ))
        }
    }
}

/// Valide qu'un secret respecte les exigences de sécurité OWASP
pub fn validate_secret_strength(secret: &str, name: &str) -> bool {
    let is_strong = secret.len() >= 32 &&
                   !secret.contains("dev_") &&
                   !secret.contains("development") &&
                   !secret.contains("default") &&
                   !secret.contains("example");

    if !is_strong {
        tracing::error!("Secret '{}' does not meet OWASP security requirements", name);
    }

    is_strong
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: u64,
    pub idle_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub encryption_key: String,
    pub salt: String,
    pub session_timeout: u64,
    pub max_login_attempts: u32,
    pub lockout_duration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: Option<String>,
}

impl Config {
    /// Construit l'URL de base de données en utilisant les secrets Docker
    fn build_database_url() -> anyhow::Result<String> {
        // Essayer d'abord DATABASE_URL directe (pour développement)
        if let Ok(url) = env::var("DATABASE_URL") {
            return Ok(url);
        }

        // Construire depuis les variables séparées (Docker)
        if let (Ok(host), Ok(port), Ok(db), Ok(user)) = (
            env::var("POSTGRES_HOST"),
            env::var("POSTGRES_PORT"), 
            env::var("POSTGRES_DB"),
            env::var("POSTGRES_USER")
        ) {
            let password = if let Ok(password_file) = env::var("POSTGRES_PASSWORD_FILE") {
                std::fs::read_to_string(&password_file)
                    .map_err(|e| anyhow::anyhow!("Failed to read password file {}: {}", password_file, e))?
                    .trim()
                    .to_string()
            } else {
                env::var("POSTGRES_PASSWORD")
                    .map_err(|_| anyhow::anyhow!("Neither POSTGRES_PASSWORD_FILE nor POSTGRES_PASSWORD is set"))?
            };

            // Encoder le mot de passe pour l'URL (sécurise les caractères spéciaux)
            let encoded_password = utf8_percent_encode(&password, NON_ALPHANUMERIC).to_string();
            let url = format!("postgresql://{user}:{encoded_password}@{host}:{port}/{db}");
            return Ok(url);
        }

        // Sinon, construire à partir du template et du fichier de secret (legacy)
        let template = env::var("DATABASE_URL_TEMPLATE")
            .unwrap_or_else(|_| "postgresql://dcop_user:__PASSWORD__@postgres:5432/dcop_413".to_string());

        let password = if let Ok(password_file) = env::var("POSTGRES_PASSWORD_FILE") {
            std::fs::read_to_string(&password_file)
                .map_err(|e| anyhow::anyhow!("Failed to read password file {}: {}", password_file, e))?
                .trim()
                .to_string()
        } else {
            env::var("POSTGRES_PASSWORD")
                .map_err(|_| anyhow::anyhow!("Neither POSTGRES_PASSWORD_FILE nor POSTGRES_PASSWORD is set"))?
        };

        // Encoder le mot de passe pour l'URL (sécurise les caractères spéciaux)
        let encoded_password = utf8_percent_encode(&password, NON_ALPHANUMERIC).to_string();
        let url = template.replace("__PASSWORD__", &encoded_password);
        Ok(url)
    }

    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();

        let config = Config {
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8443".to_string())
                    .parse()
                    .unwrap_or(8443),
                tls_cert_path: env::var("TLS_CERT_PATH").ok(),
                tls_key_path: env::var("TLS_KEY_PATH").ok(),
            },
            database: DatabaseConfig {
                url: Self::build_database_url()?,
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .unwrap_or(10),
                min_connections: env::var("DB_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "1".to_string())
                    .parse()
                    .unwrap_or(1),
                connect_timeout: env::var("DB_CONNECT_TIMEOUT")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()
                    .unwrap_or(30),
                idle_timeout: env::var("DB_IDLE_TIMEOUT")
                    .unwrap_or_else(|_| "600".to_string())
                    .parse()
                    .unwrap_or(600),
            },
            security: SecurityConfig {
                jwt_secret: read_secret_or_env("JWT_SECRET_FILE", "JWT_SECRET")?,
                encryption_key: read_secret_or_env("ENCRYPTION_KEY_FILE", "ENCRYPTION_KEY")?,
                salt: read_secret_or_env("SECURITY_SALT_FILE", "SECURITY_SALT")?,
                session_timeout: env::var("SESSION_TIMEOUT")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()
                    .unwrap_or(3600),
                max_login_attempts: env::var("MAX_LOGIN_ATTEMPTS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()
                    .unwrap_or(5),
                lockout_duration: env::var("LOCKOUT_DURATION")
                    .unwrap_or_else(|_| "900".to_string())
                    .parse()
                    .unwrap_or(900),
            },
            logging: LoggingConfig {
                level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
                file_path: env::var("LOG_FILE_PATH").ok(),
            },
        };

        Ok(config)
    }
}
