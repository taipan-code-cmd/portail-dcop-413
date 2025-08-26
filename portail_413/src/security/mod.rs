pub mod encryption;
pub mod hashing;
pub mod password;
pub mod password_validation;
pub mod secure_password_parser;
pub mod secret_rotation;
pub mod certificate_pinning;
pub mod csrf_protection;
pub mod input_validation;
pub mod error_handling;
pub mod session_management;
pub mod rate_limiting;
pub mod security_logger;
pub mod secrets_manager;
pub mod security_config;
pub mod rate_limiting_advanced;
pub mod security_audit;
pub mod valkey_rate_limiting;
pub mod centralized_security_logger;

// Re-export des types principaux
pub use encryption::EncryptionService;
pub use hashing::HashingService;
pub use password::PasswordService;
pub use secret_rotation::SecretRotationService;
pub use certificate_pinning::CertificatePinningService;
pub use csrf_protection::CsrfProtectionService;
pub use input_validation::InputValidationService;
pub use session_management::SecureSessionManager;
pub use rate_limiting::RateLimitingService;
pub use security_logger::{SecurityLogger, SecurityEventType, SecuritySeverity};
pub use secrets_manager::SecretsManager;
pub use security_config::SecurityConfig;
pub use centralized_security_logger::{CentralizedSecurityLogger, SecurityEvent, SecurityResult};
pub use password_validation::{PasswordValidator, PasswordValidationError};
pub use secure_password_parser::{SecurePassword, SecurePasswordParser, SecureLoginRequest, SecureCreateUserRequest};

// Service factory function for validation
pub fn get_validation_service() -> Result<InputValidationService, crate::errors::AppError> {
    InputValidationService::new()
}
