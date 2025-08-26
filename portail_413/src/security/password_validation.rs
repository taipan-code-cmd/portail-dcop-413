use regex::Regex;
use std::collections::HashSet;
use lazy_static::lazy_static;
use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use std::future::{Ready, ready};

// Module de validation des mots de passe selon les standards de sécurité gouvernementaux
// Implémente les recommandations ANSSI et les bonnes pratiques internationales

lazy_static! {
    /// Liste noire des mots de passe couramment utilisés et faibles
    static ref COMMON_PASSWORDS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        
        // Mots de passe numériques courants
        set.insert("123456");
        set.insert("1234567");
        set.insert("12345678");
        set.insert("123456789");
        set.insert("1234567890");
        set.insert("0000");
        set.insert("1111");
        set.insert("2222");
        set.insert("9999");
        set.insert("1234");
        set.insert("4321");
        
        // Mots de passe alphabétiques courants
        set.insert("password");
        set.insert("motdepasse");
        set.insert("azerty");
        set.insert("qwerty");
        set.insert("admin");
        set.insert("administrator");
        set.insert("root");
        set.insert("user");
        set.insert("guest");
        set.insert("test");
        
        // Combinaisons courantes
        set.insert("password123");
        set.insert("password1234");
        set.insert("motdepasse123");
        set.insert("azerty123");
        set.insert("qwerty123");
        set.insert("admin123");
        set.insert("admin1234");
        set.insert("123abc");
        set.insert("abc123");
        set.insert("pass123");
        set.insert("user123");
        
        // Mots français courants
        set.insert("bonjour");
        set.insert("salut");
        set.insert("france");
        set.insert("paris");
        set.insert("soleil");
        set.insert("amour");
        set.insert("famille");
        
        // Suites logiques
        set.insert("abcdef");
        set.insert("abcd1234");
        set.insert("qwertz");
        set.insert("asdfgh");
        set.insert("zxcvbn");
        
        set
    };
    
    /// Expressions régulières pour détecter les patterns faibles
    static ref WEAK_PATTERNS: Vec<Regex> = {
        vec![
            // Suites croissantes (123, abc)
            Regex::new(r"(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)").expect("Checked operation"),
            // Suites décroissantes (321, cba)
            Regex::new(r"(987|876|765|654|543|432|321|210|zyx|yxw|xwv|wvu|vut|uts|tsr|srq|rqp|qpo|pon|onm|nml|mlk|lkj|kji|jih|ihg|hgf|gfe|fed|edc|dcb|cba)").expect("Checked operation"),
            // Clavier AZERTY/QWERTY
            Regex::new(r"(azerty|qwerty|asdfgh|zxcvbn|qwertz)").expect("Checked operation"),
            // Années récentes
            Regex::new(r"(19[0-9]{2}|20[0-2][0-9])").expect("Checked operation"),
            // Mois/jours
            Regex::new(r"(janvier|fevrier|mars|avril|mai|juin|juillet|aout|septembre|octobre|novembre|decembre|lundi|mardi|mercredi|jeudi|vendredi|samedi|dimanche)").expect("Checked operation"),
        ]
    };
}

#[derive(Debug, Clone)]
pub struct PasswordValidationError {
    pub message: String,
    pub code: String,
}

impl std::fmt::Display for PasswordValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PasswordValidationError {}

/// Structure pour la validation complète des mots de passe
pub struct PasswordValidator;

impl PasswordValidator {
    /// Validation complète d'un mot de passe selon les standards de sécurité
    pub fn validate_password(password: &str, username: Option<&str>) -> Result<(), Vec<PasswordValidationError>> {
        let mut errors = Vec::new();
        
        // 1. Vérification de la longueur minimale (12 caractères minimum)
        if password.len() < 12 {
            errors.push(PasswordValidationError {
                message: "Le mot de passe doit contenir au minimum 12 caractères".to_string(),
                code: "MIN_LENGTH".to_string(),
            });
        }
        
        // 2. Vérification de la longueur maximale (pour éviter les attaques DoS)
        if password.len() > 128 {
            errors.push(PasswordValidationError {
                message: "Le mot de passe ne peut pas dépasser 128 caractères".to_string(),
                code: "MAX_LENGTH".to_string(),
            });
        }
        
        // 3. Vérification de la complexité - Lettres majuscules
        if !password.chars().any(|c| c.is_uppercase() && c.is_alphabetic()) {
            errors.push(PasswordValidationError {
                message: "Le mot de passe doit contenir au moins une lettre majuscule".to_string(),
                code: "MISSING_UPPERCASE".to_string(),
            });
        }
        
        // 4. Vérification de la complexité - Lettres minuscules
        if !password.chars().any(|c| c.is_lowercase() && c.is_alphabetic()) {
            errors.push(PasswordValidationError {
                message: "Le mot de passe doit contenir au moins une lettre minuscule".to_string(),
                code: "MISSING_LOWERCASE".to_string(),
            });
        }
        
        // 5. Vérification de la complexité - Chiffres
        if !password.chars().any(|c| c.is_numeric()) {
            errors.push(PasswordValidationError {
                message: "Le mot de passe doit contenir au moins un chiffre".to_string(),
                code: "MISSING_DIGIT".to_string(),
            });
        }
        
        // 6. Vérification de la complexité - Caractères spéciaux
        let special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`";
        if !password.chars().any(|c| special_chars.contains(c)) {
            errors.push(PasswordValidationError {
                message: "Le mot de passe doit contenir au moins un caractère spécial (!@#$%^&*()_+-=[]{}|;:,.<>?/~`)".to_string(),
                code: "MISSING_SPECIAL".to_string(),
            });
        }
        
        // 7. Vérification contre la liste noire
        let password_lower = password.to_lowercase();
        if COMMON_PASSWORDS.contains(password) || COMMON_PASSWORDS.contains(password_lower.as_str()) {
            errors.push(PasswordValidationError {
                message: "Ce mot de passe est trop courant et facilement devinable".to_string(),
                code: "COMMON_PASSWORD".to_string(),
            });
        }
        
        // 8. Vérification des répétitions de caractères (aaa, 111, etc.)
        if has_character_repetition(password) {
            errors.push(PasswordValidationError {
                message: "Le mot de passe ne doit pas contenir de répétitions de caractères (ex: aaa, 111)".to_string(),
                code: "CHARACTER_REPETITION".to_string(),
            });
        }
        
        // 9. Vérification des patterns faibles
        for pattern in WEAK_PATTERNS.iter() {
            if pattern.is_match(&password_lower) {
                errors.push(PasswordValidationError {
                    message: "Le mot de passe contient des séquences prévisibles (ex: 123, abc, azerty)".to_string(),
                    code: "WEAK_PATTERN".to_string(),
                });
                break; // Un seul message pour tous les patterns
            }
        }
        
        // 9. Vérification que le mot de passe ne contient pas le nom d'utilisateur
        if let Some(username) = username {
            if !username.is_empty() && password_lower.contains(&username.to_lowercase()) {
                errors.push(PasswordValidationError {
                    message: "Le mot de passe ne doit pas contenir le nom d'utilisateur".to_string(),
                    code: "CONTAINS_USERNAME".to_string(),
                });
            }
        }
        
        // 10. Vérification de la diversité des caractères (au moins 3 types différents)
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| special_chars.contains(c));
        
        let complexity_count = [has_upper, has_lower, has_digit, has_special].iter().filter(|&&x| x).count();
        if complexity_count < 3 {
            errors.push(PasswordValidationError {
                message: "Le mot de passe doit contenir au moins 3 types de caractères différents".to_string(),
                code: "INSUFFICIENT_COMPLEXITY".to_string(),
            });
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
    
    /// Validation pour la création d'utilisateur avec nom d'utilisateur
    pub fn validate_user_password(password: &str, username: &str) -> Result<(), Vec<PasswordValidationError>> {
        Self::validate_password(password, Some(username))
    }
    
    /// Validation pour la connexion (moins stricte, juste longueur minimale)
    pub fn validate_login_password(password: &str) -> Result<(), PasswordValidationError> {
        if password.is_empty() {
            return Err(PasswordValidationError {
                message: "Le mot de passe ne peut pas être vide".to_string(),
                code: "EMPTY_PASSWORD".to_string(),
            });
        }
        
        if password.len() > 128 {
            return Err(PasswordValidationError {
                message: "Le mot de passe est trop long".to_string(),
                code: "PASSWORD_TOO_LONG".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Génère un score de force du mot de passe (0-100)
    pub fn calculate_strength_score(password: &str) -> u8 {
        let mut score = 0u8;
        
        // Longueur (max 30 points)
        let length_score = std::cmp::min(password.len() * 2, 30);
        score = score.saturating_add(length_score as u8);
        
        // Complexité (max 40 points, 10 par type)
        if password.chars().any(|c| c.is_uppercase()) { score = score.saturating_add(10); }
        if password.chars().any(|c| c.is_lowercase()) { score = score.saturating_add(10); }
        if password.chars().any(|c| c.is_numeric()) { score = score.saturating_add(10); }
        if password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?/~`".contains(c)) { score = score.saturating_add(10); }
        
        // Diversité des caractères (max 20 points)
        let unique_chars = password.chars().collect::<std::collections::HashSet<_>>().len();
        let diversity_score = std::cmp::min(unique_chars * 2, 20);
        score = score.saturating_add(diversity_score as u8);
        
        // Pénalités
        if COMMON_PASSWORDS.contains(&password.to_lowercase().as_str()) {
            score = score.saturating_sub(50);
        }
        
        for pattern in WEAK_PATTERNS.iter() {
            if pattern.is_match(&password.to_lowercase()) {
                score = score.saturating_sub(20);
                break;
            }
        }
        
        std::cmp::min(score, 100)
    }
}

/// Fonction utilitaire pour détecter les répétitions de caractères
/// Détecte 3 caractères identiques consécutifs ou plus
fn has_character_repetition(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    
    for i in 0..chars.len().saturating_sub(2) {
        if chars[i] == chars[i + 1] && chars[i + 1] == chars[i + 2] {
            return true;
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_weak_passwords() {
        assert!(PasswordValidator::validate_password("123456", None).is_err());
        assert!(PasswordValidator::validate_password("password", None).is_err());
        assert!(PasswordValidator::validate_password("azerty123", None).is_err());
    }
    
    #[test]
    fn test_strong_passwords() {
        assert!(PasswordValidator::validate_password("MyStr0ng!P@ssw0rd2024", None).is_ok());
        assert!(PasswordValidator::validate_password("C0mpl3x&S3cur3!2024", None).is_ok());
    }
    
    #[test]
    fn test_username_in_password() {
        assert!(PasswordValidator::validate_user_password("john123!STRONG", "john").is_err());
        assert!(PasswordValidator::validate_user_password("Str0ng!P@ssw0rd", "john").is_ok());
    }
    
    #[test]
    fn test_strength_scoring() {
        assert!(PasswordValidator::calculate_strength_score("123456") < 30);
        assert!(PasswordValidator::calculate_strength_score("MyStr0ng!P@ssw0rd2024") > 80);
    }
}

// Implémentation pour validation dans les middlewares Actix-web
impl FromRequest for PasswordValidator {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(_req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(Ok(PasswordValidator))
    }
}
