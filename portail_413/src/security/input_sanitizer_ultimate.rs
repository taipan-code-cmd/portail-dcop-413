//! Module de validation et sanitisation ultra-sécurisé

use regex::Regex;
use std::collections::HashSet;

pub struct InputSanitizerUltimate;

impl InputSanitizerUltimate {
    /// Sanitise complètement une chaîne en supprimant tous caractères dangereux
    pub fn sanitize_string(input: &str) -> String {
        // Suppression caractères dangereux et de contrôle
        let dangerous_chars = Regex::new(r"[<>&\"'`\x00-\x1f\x7f-\x9f\\\$]").expect("Valid regex");
        let sanitized = dangerous_chars.replace_all(input, "");
        
        // Limitation longueur
        if sanitized.len() > 1000 {
            sanitized.chars().take(1000).collect()
        } else {
            sanitized.to_string()
        }
    }
    
    /// Validation email ultra-stricte
    pub fn validate_email(email: &str) -> bool {
        if email.len() > 254 || email.len() < 5 {
            return false;
        }
        
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .expect("Valid regex");
        
        email_regex.is_match(email)
            && !email.contains("..")
            && !email.starts_with('.')
            && !email.ends_with('.')
    }
    
    /// Validation nom d'utilisateur ultra-stricte
    pub fn validate_username(username: &str) -> bool {
        if username.len() < 3 || username.len() > 32 {
            return false;
        }
        
        let username_regex = Regex::new(r"^[a-zA-Z0-9_-]+$").expect("Valid regex");
        username_regex.is_match(username)
            && !username.starts_with('-')
            && !username.ends_with('-')
            && !username.contains("__")
            && !username.contains("--")
    }
    
    /// Validation mot de passe ultra-stricte
    pub fn validate_password_strength(password: &str) -> bool {
        if password.len() < 14 || password.len() > 128 {
            return false;
        }
        
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));
        
        // Vérification patterns interdits
        let forbidden_patterns = [
            "password", "123456", "qwerty", "admin", "test",
            "user", "login", "pass", "secret"
        ];
        
        let password_lower = password.to_lowercase();
        let has_forbidden = forbidden_patterns.iter()
            .any(|&pattern| password_lower.contains(pattern));
        
        has_upper && has_lower && has_digit && has_special && !has_forbidden
    }
    
    /// Validation IP ultra-stricte
    pub fn validate_ip_address(ip: &str) -> bool {
        let ip_regex = Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
            .expect("Valid regex");
        
        if !ip_regex.is_match(ip) {
            return false;
        }
        
        // Vérification que ce n'est pas une IP privée ou de loopback
        let octets: Vec<u8> = ip.split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        
        if octets.len() != 4 {
            return false;
        }
        
        // Interdiction IPs privées/locales
        !(octets[0] == 10 ||
          (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
          (octets[0] == 192 && octets[1] == 168) ||
          octets[0] == 127 ||
          octets[0] == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sanitize_string() {
        assert_eq!(InputSanitizerUltimate::sanitize_string("<script>alert('xss')</script>"), 
                   "scriptalert('xss')/script");
    }
    
    #[test]
    fn test_validate_email() {
        assert!(InputSanitizerUltimate::validate_email("user@example.com"));
        assert!(!InputSanitizerUltimate::validate_email("invalid..email@test.com"));
    }
    
    #[test]
    fn test_validate_password() {
        assert!(InputSanitizerUltimate::validate_password_strength("MyVerySecure123!@#Pass"));
        assert!(!InputSanitizerUltimate::validate_password_strength("password123"));
    }
}
