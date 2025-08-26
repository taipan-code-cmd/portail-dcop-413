use regex::Regex;
use std::collections::HashMap;

pub struct InputValidator;

impl InputValidator {
    pub fn validate_email(email: &str) -> bool {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").expect("Checked operation");
        email_regex.is_match(email) && email.len() <= 254
    }

    pub fn validate_password(password: &str) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        
        if password.len() < 12 {
            errors.push("Le mot de passe doit contenir au moins 12 caractères".to_string());
        }
        
        if !password.chars().any(|c| c.is_uppercase()) {
            errors.push("Le mot de passe doit contenir au moins une majuscule".to_string());
        }
        
        if !password.chars().any(|c| c.is_lowercase()) {
            errors.push("Le mot de passe doit contenir au moins une minuscule".to_string());
        }
        
        if !password.chars().any(|c| c.is_numeric()) {
            errors.push("Le mot de passe doit contenir au moins un chiffre".to_string());
        }
        
        if !password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;':\",./<>?".contains(c)) {
            errors.push("Le mot de passe doit contenir au moins un caractère spécial".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn sanitize_input(input: &str) -> String {
        input
            .chars()
            .filter(|c| c.is_alphanumeric() || " .-_@".contains(*c))
            .collect::<String>()
            .trim()
            .to_string()
    }
}
