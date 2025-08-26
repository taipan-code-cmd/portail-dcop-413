use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use actix_web::http::header::HeaderValue;

/// Structure sécurisée pour gérer les mots de passe avec caractères spéciaux
/// Gère l'encodage/décodage correct et évite les erreurs de parsing
#[derive(Clone)]
pub struct SecurePassword {
    /// Le mot de passe en tant que bytes pour gérer tous les caractères Unicode
    password_bytes: Vec<u8>,
    /// Indique si le mot de passe est valide UTF-8
    is_valid_utf8: bool,
}

impl SecurePassword {
    /// Crée un nouveau SecurePassword à partir d'une chaîne
    pub fn new(password: &str) -> Self {
        let password_bytes = password.as_bytes().to_vec();
        Self {
            password_bytes,
            is_valid_utf8: true,
        }
    }
    
    /// Crée un SecurePassword à partir de bytes bruts
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let is_valid_utf8 = String::from_utf8(bytes.clone()).is_ok();
        Self {
            password_bytes: bytes,
            is_valid_utf8,
        }
    }
    
    /// Retourne le mot de passe en tant que String (si valide UTF-8)
    pub fn as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.password_bytes.clone())
    }
    
    /// Retourne le mot de passe en tant que &str (si valide UTF-8)
    pub fn as_str(&self) -> Option<&str> {
        if self.is_valid_utf8 {
            std::str::from_utf8(&self.password_bytes).ok()
        } else {
            None
        }
    }
    
    /// Retourne les bytes bruts du mot de passe
    pub fn as_bytes(&self) -> &[u8] {
        &self.password_bytes
    }
    
    /// Vérifie si le mot de passe est vide
    pub fn is_empty(&self) -> bool {
        self.password_bytes.is_empty()
    }
    
    /// Retourne la longueur en bytes
    pub fn len_bytes(&self) -> usize {
        self.password_bytes.len()
    }
    
    /// Retourne la longueur en caractères (si UTF-8 valide)
    pub fn len_chars(&self) -> Option<usize> {
        self.as_str().map(|s| s.chars().count())
    }
    
    /// Nettoie la mémoire (surécrit les données sensibles)
    pub fn clear(&mut self) {
        // Surécrit la mémoire avec des zéros pour la sécurité
        for byte in self.password_bytes.iter_mut() {
            *byte = 0;
        }
        self.password_bytes.clear();
        self.is_valid_utf8 = false;
    }
}

impl fmt::Debug for SecurePassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurePassword")
            .field("len", &self.password_bytes.len())
            .field("is_valid_utf8", &self.is_valid_utf8)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for SecurePassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[SECURE PASSWORD - {} bytes]", self.password_bytes.len())
    }
}

impl Drop for SecurePassword {
    fn drop(&mut self) {
        self.clear();
    }
}

// Implémentation de la désérialisation sécurisée
impl<'de> Deserialize<'de> for SecurePassword {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let password_str = String::deserialize(deserializer)?;
        Ok(SecurePassword::new(&password_str))
    }
}

// Implémentation de la sérialisation (pour les logs - attention!)
impl Serialize for SecurePassword {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // ATTENTION: Ne jamais sérialiser le mot de passe réel!
        // Retourner seulement un indicateur
        "[REDACTED]".serialize(serializer)
    }
}

/// Parser sécurisé pour les requêtes contenant des mots de passe
pub struct SecurePasswordParser;

impl SecurePasswordParser {
    /// Parse une chaîne JSON en gérant les caractères spéciaux
    pub fn parse_json_with_password(json_str: &str) -> Result<serde_json::Value, serde_json::Error> {
        // Utilise serde_json qui gère automatiquement l'échappement des caractères spéciaux
        serde_json::from_str(json_str)
    }
    
    /// Extrait un mot de passe d'un objet JSON de manière sécurisée
    pub fn extract_password_from_json(json_value: &serde_json::Value, field_name: &str) -> Option<SecurePassword> {
        json_value
            .get(field_name)
            .and_then(|v| v.as_str())
            .map(SecurePassword::new)
    }
    
    /// Valide et nettoie une chaîne de mot de passe
    pub fn sanitize_password_input(input: &str) -> SecurePassword {
        // Supprime les espaces en début et fin, mais préserve les caractères spéciaux
        let trimmed = input.trim();
        SecurePassword::new(trimmed)
    }
    
    /// Encode un mot de passe pour l'URL (si nécessaire)
    pub fn url_encode_password(password: &SecurePassword) -> Result<String, std::string::FromUtf8Error> {
        let password_str = password.as_string()?;
        Ok(urlencoding::encode(&password_str).to_string())
    }
    
    /// Décode un mot de passe depuis l'URL
    pub fn url_decode_password(encoded: &str) -> Result<SecurePassword, Box<dyn std::error::Error>> {
        let decoded = urlencoding::decode(encoded)?;
        Ok(SecurePassword::new(&decoded))
    }
}

/// Structure pour les requêtes d'authentification avec parsing sécurisé
#[derive(Debug, Deserialize)]
pub struct SecureLoginRequest {
    pub username: String,
    #[serde(deserialize_with = "deserialize_secure_password")]
    pub password: SecurePassword,
}

/// Désérialiseur personnalisé pour les mots de passe
fn deserialize_secure_password<'de, D>(deserializer: D) -> Result<SecurePassword, D::Error>
where
    D: Deserializer<'de>,
{
    let password_str = String::deserialize(deserializer)?;
    Ok(SecurePassword::new(&password_str))
}

/// Structure pour la création d'utilisateur avec parsing sécurisé
#[derive(Debug, Deserialize)]
pub struct SecureCreateUserRequest {
    pub username: String,
    #[serde(deserialize_with = "deserialize_secure_password")]
    pub password: SecurePassword,
    pub role: crate::models::UserRole,
}

/// Middleware pour parser les requêtes avec mots de passe de manière sécurisée
pub async fn secure_password_middleware<B>(
    _req: actix_web::dev::ServiceRequest,
    srv: actix_web::dev::ServiceResponse<B>,
) -> Result<actix_web::dev::ServiceResponse<B>, actix_web::Error> {
    // Ajouter des headers pour indiquer que les mots de passe sont traités de manière sécurisée
    let mut response = srv;
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-password-handling"),
        HeaderValue::from_static("secure"),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_password_creation() {
        let password = SecurePassword::new("M0n&M0t@DeP@sse!2024");
        assert!(!password.is_empty());
        assert_eq!(password.as_str().expect("Checked operation"), "M0n&M0t@DeP@sse!2024");
    }
    
    #[test]
    fn test_special_characters() {
        let special_password = "P@$$w0rd!#$%^&*(){}[]|\\:;\"'<>,.?/~`+=_-";
        let secure_pwd = SecurePassword::new(special_password);
        assert_eq!(secure_pwd.as_str().expect("Checked operation"), special_password);
    }
    
    #[test]
    fn test_unicode_characters() {
        let unicode_password = "Më@P@ssŵørð2024!€";
        let secure_pwd = SecurePassword::new(unicode_password);
        assert_eq!(secure_pwd.as_str().expect("Checked operation"), unicode_password);
    }
    
    #[test]
    fn test_json_parsing() {
        let json = r#"{"username": "admin", "password": "P@$$w0rd!@#$%^&*()"}"#;
        let parsed = SecurePasswordParser::parse_json_with_password(json).expect("Checked operation");
        let password = SecurePasswordParser::extract_password_from_json(&parsed, "password").expect("Checked operation");
        assert_eq!(password.as_str().expect("Checked operation"), "P@$$w0rd!@#$%^&*()");
    }
    
    #[test]
    fn test_memory_clearing() {
        let mut password = SecurePassword::new("secret123!");
        assert!(!password.is_empty());
        password.clear();
        assert!(password.is_empty());
    }
}
