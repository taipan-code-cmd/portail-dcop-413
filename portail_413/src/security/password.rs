use crate::security::password_security::{hash_password, verify_password};
use crate::errors::{AppError, Result};

pub struct PasswordService;

impl PasswordService {
    // Coût bcrypt optimisé pour la sécurité vs performance
    // 12 = ~250ms sur CPU moderne, 10 = ~60ms (ajustable selon besoins)
    const BCRYPT_COST: u32 = 12;

    /// Hash un mot de passe avec bcrypt
    pub fn hash_password(password: &str) -> Result<String> {
        hash_password(Self::BCRYPT_COST)
            .map_err(|e| AppError::Encryption(format!("Password hashing failed: {e}")))
    }

    /// Vérifie un mot de passe contre son hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
        verify_password(password, hash)
            .map_err(|e| AppError::Encryption(format!("Password verification failed: {e}")))
    }

    /// Valide la force d'un mot de passe selon les politiques strictes DCOP renforcées
    pub fn validate_password_strength(password: &str) -> Result<()> {
        // 1. Longueur minimale renforcée (14-16 caractères pour sécurité maximale)
        if password.len() < 14 {
            return Err(AppError::Validation(
                "Le mot de passe doit contenir au moins 14 caractères pour une sécurité maximale".to_string(),
            ));
        }

        if password.len() > 128 {
            return Err(AppError::Validation(
                "Le mot de passe ne peut pas dépasser 128 caractères".to_string(),
            ));
        }

        // 2. Complexité renforcée - Vérifications des types de caractères
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?~`".contains(c));

        let mut missing = Vec::new();

        if !has_lowercase {
            missing.push("au moins une lettre minuscule (a-z)");
        }
        if !has_uppercase {
            missing.push("au moins une lettre majuscule (A-Z)");
        }
        if !has_digit {
            missing.push("au moins un chiffre (0-9)");
        }
        if !has_special {
            missing.push("au moins un caractère spécial (!@#$%^&*...)");
        }

        if !missing.is_empty() {
            return Err(AppError::Validation(format!(
                "Le mot de passe doit contenir : {}",
                missing.join(", ")
            )));
        }

        // 3. Vérifications de sécurité avancées
        
        // 3a. Pas de séquences répétitives
        if Self::has_repetitive_sequences(password) {
            return Err(AppError::Validation(
                "Le mot de passe ne doit pas contenir de séquences répétitives (ex: aaa, 111, !!!)".to_string(),
            ));
        }

        // 3b. Pas de séquences de clavier
        if Self::has_keyboard_sequences(password) {
            return Err(AppError::Validation(
                "Le mot de passe ne doit pas contenir de séquences de clavier (ex: azerty, 123456)".to_string(),
            ));
        }

        // 3c. Vérification contre les mots de passe compromis
        if Self::is_common_or_compromised_password(password) {
            return Err(AppError::Validation(
                "Ce mot de passe figure dans les bases de données de mots de passe compromis. Veuillez en choisir un autre.".to_string(),
            ));
        }

        // 3d. Pas de mots de dictionnaire communs
        let password_lower = password.to_lowercase();
        let common_words = [
            "azerty", "qwerty", "123456", "password123", "admin123", "welcome",
            "bonjour", "salut", "france", "paris", "gouvernement"
        ];
        
        for word in &common_words {
            if password_lower.contains(word) {
                return Err(AppError::Validation(
                    "Le mot de passe ne doit pas contenir de mots communs ou prévisibles".to_string(),
                ));
            }
        }

        // 3e. Entropie minimale (diversité des caractères)
        let unique_chars: std::collections::HashSet<char> = password.chars().collect();
        let entropy_ratio = unique_chars.len() as f64 / password.len() as f64;
        
        if entropy_ratio < 0.6 {
            return Err(AppError::Validation(
                "Le mot de passe doit avoir une plus grande diversité de caractères".to_string(),
            ));
        }

        // 4. Score de complexité global
        let complexity_score = Self::calculate_complexity_score_internal(password);
        if complexity_score < 60 {
            return Err(AppError::Validation(
                "Le mot de passe n'est pas suffisamment complexe. Variez davantage les types de caractères.".to_string(),
            ));
        }

        Ok(())
    }

    /// Détecte les séquences répétitives dangereuses
    fn has_repetitive_sequences(password: &str) -> bool {
        let chars: Vec<char> = password.chars().collect();
        if chars.len() < 3 { return false; }

        for i in 0..chars.len()-2 {
            if chars[i] == chars[i+1] && chars[i+1] == chars[i+2] {
                return true; // 3 caractères identiques consécutifs
            }
        }
        false
    }

    /// Détecte les séquences de clavier communes
    fn has_keyboard_sequences(password: &str) -> bool {
        let dangerous_sequences = [
            "azerty", "qwerty", "123456", "abcdef", "fedcba", "654321",
            "azer", "qwer", "1234", "4321", "abcd", "dcba", "uiop",
            "asdf", "hjkl", "zxcv", "bnm", "poi", "lkj", "mnb"
        ];
        
        let password_lower = password.to_lowercase();
        dangerous_sequences.iter().any(|seq| password_lower.contains(seq))
    }

    /// Calcule un score de complexité interne pour validation
    fn calculate_complexity_score_internal(password: &str) -> u8 {
        let mut score = 0u8;
        
        // Longueur (max 25 points)
        score += (password.len() as u8).min(25);
        
        // Types de caractères (max 40 points)
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?~`".contains(c));
        
        if has_lowercase { score += 10; }
        if has_uppercase { score += 10; }
        if has_digit { score += 10; }
        if has_special { score += 10; }
        
        // Unicité des caractères (max 20 points)
        let unique_chars: std::collections::HashSet<char> = password.chars().collect();
        let uniqueness_ratio = unique_chars.len() as f64 / password.len() as f64;
        score += (uniqueness_ratio * 20.0) as u8;
        
        // Absence de mots de dictionnaire (max 15 points)
        if !Self::contains_dictionary_words(password) {
            score += 15;
        }
        
        // PÉNALITÉS pour les vulnérabilités de sécurité
        
        // Pénalité sévère pour les mots de passe compromis (-30 points)
        if Self::is_common_or_compromised_password(password) {
            score = score.saturating_sub(30);
        }
        
        // Pénalité pour les séquences répétitives (-15 points)
        if Self::has_repetitive_sequences(password) {
            score = score.saturating_sub(15);
        }
        
        // Pénalité pour les séquences de clavier (-20 points)
        if Self::has_keyboard_sequences(password) {
            score = score.saturating_sub(20);
        }
        
        score.min(100)
    }

    /// Vérifie la présence de mots de dictionnaire simples
    fn contains_dictionary_words(password: &str) -> bool {
        let common_words = [
            "password", "admin", "user", "login", "secret", "secure",
            "motdepasse", "utilisateur", "connexion", "secret", "securise",
            "welcome", "bonjour", "hello", "salut", "bienvenue",
            "france", "paris", "london", "madrid", "berlin"
        ];
        
        let password_lower = password.to_lowercase();
        common_words.iter().any(|word| password_lower.contains(word))
    }

    /// Vérifie si le mot de passe fait partie des mots de passe communs et compromis
    fn is_common_or_compromised_password(password: &str) -> bool {
        // Base de données étendue de mots de passe compromis (basée sur des fuites réelles)
        let compromised_passwords = [
            // Top 200 mots de passe de fuites de données récentes
            "password", "123456", "123456789", "12345678", "12345", "1234567",
            "password123", "admin", "qwerty", "abc123", "Password1", "welcome",
            "monkey", "dragon", "master", "shadow", "superman", "michael",
            "football", "baseball", "liverpool", "jordan", "princess", "charlie",
            "1234567890", "111111", "123123", "letmein", "pass", "hello",
            "freedom", "whatever", "qazwsx", "trustno1", "jordan23", "harley",
            "robert", "matthew", "asshole", "password1", "1234", "fuckyou",
            "hunter", "2000", "test", "batman", "thomas", "tigger", "access",
            "love", "buster", "soccer", "hockey", "killer", "george", "sexy",
            "andrew", "superman", "dallas", "jessica", "panties", "pepper",
            "1111", "austin", "william", "daniel", "golfer", "summer", "heather",
            "hammer", "yankees", "joshua", "maggie", "biteme", "enter", "ashley",
            "thunder", "cowboy", "silver", "richard", "fucker", "orange", "merlin",
            "michelle", "corvette", "bigdog", "cheese", "121212", "patrick",
            "martin", "ginger", "blowjob", "nicole", "sparky", "yellow", "camaro",
            "secret", "dick", "falcon", "taylor", "birdman", "donald", "murphy",
            "mexico", "anthony", "eagles", "viper", "spencer", "melissa", "ou812",
            "kevin", "amanda", "proteus", "blazer", "crystal", "bradford", "united",
            "rambo", "jennifer", "johnny", "gibson", "green", "jordan1", "pepper1",
            // Variations courantes avec chiffres
            "password01", "password12", "password123", "admin123", "admin2023",
            "welcome1", "welcome123", "qwerty123", "abc12345", "password2023",
            // Mots de passe français compromis
            "azerty", "motdepasse", "soleil", "bonjour", "france", "paris",
            "marseille", "lyon", "toulouse", "bordeaux", "lille", "nantes",
            "strasbourg", "montpellier", "rennes", "reims", "saint", "pierre",
            "nicolas", "julien", "marie", "sophie", "claire", "alexandre",
            "azerty123", "motdepasse1", "soleil123", "bonjour123", "france123",
            // Mots de passe d'entreprise courants
            "company123", "entreprise", "bureau123", "office123", "admin2024",
            "user123", "utilisateur", "manager", "directeur", "secretaire",
            // Patterns dangereux couramment utilisés
            "azertyuiop", "qwertyuiop", "1qaz2wsx", "2wsxzaq1", "qwaszx",
            "123qwe", "qwe123", "abc123def", "password!", "Password@123",
            "123456a", "a123456", "password1!", "Password1@", "Admin123!",
            // Dates et années communes (patterns faibles)
            "19700101", "19800101", "19900101", "20000101", "20230101",
            "01011970", "01011980", "01011990", "01012000", "01012023",
            // Séquences numériques étendues
            "0123456789", "9876543210", "1357924680", "2468013579",
            "147258369", "963852741", "159753", "357159", "789456123"
        ];

        let password_lower = password.to_lowercase();
        
        // Vérification exacte
        if compromised_passwords.iter().any(|&p| password_lower == p) {
            return true;
        }
        
        // Vérification avec variations communes (ajout de chiffres à la fin)
        for &base_password in compromised_passwords.iter() {
            if password_lower.starts_with(base_password) && password_lower.len() <= base_password.len() + 4 {
                let suffix = &password_lower[base_password.len()..];
                if suffix.chars().all(|c| c.is_ascii_digit()) {
                    return true;
                }
            }
        }

        false
    }

    /// Calcule le score de complexité d'un mot de passe (interface publique)
    pub fn calculate_complexity_score(password: &str) -> u8 {
        Self::calculate_complexity_score_internal(password)
    }

    /// Génère des suggestions pour améliorer un mot de passe
    pub fn get_password_suggestions(password: &str) -> Vec<String> {
        let mut suggestions = Vec::new();

        if password.len() < 14 {
            suggestions.push("Utilisez au moins 14 caractères".to_string());
        }

        if !password.chars().any(|c| c.is_lowercase()) {
            suggestions.push("Ajoutez des lettres minuscules".to_string());
        }

        if !password.chars().any(|c| c.is_uppercase()) {
            suggestions.push("Ajoutez des lettres majuscules".to_string());
        }

        if !password.chars().any(|c| c.is_ascii_digit()) {
            suggestions.push("Ajoutez des chiffres".to_string());
        }

        if !password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?~`".contains(c)) {
            suggestions.push("Ajoutez des caractères spéciaux (!@#$%...)".to_string());
        }

        if Self::has_repetitive_sequences(password) {
            suggestions.push("Évitez les répétitions (aaa, 111, !!!)".to_string());
        }

        if Self::has_keyboard_sequences(password) {
            suggestions.push("Évitez les séquences de clavier (azerty, 123456)".to_string());
        }

        if Self::contains_dictionary_words(password) {
            suggestions.push("Évitez les mots courants du dictionnaire".to_string());
        }

        if suggestions.is_empty() {
            suggestions.push("Votre mot de passe semble sécurisé !".to_string());
        }

        suggestions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let password = "SecurePassword123!";
        let hash = PasswordService::hash_password(password).expect("Checked operation");

        assert!(PasswordService::verify_password(password, &hash).expect("Checked operation"));
        assert!(!PasswordService::verify_password("WrongPassword", &hash).expect("Checked operation"));
    }

    #[test]
    fn test_password_strength_validation() {
        // Mot de passe valide (14+ chars avec complexité)
        assert!(PasswordService::validate_password_strength("SecurePassw0rd123!").is_ok());

        // Trop court
        assert!(PasswordService::validate_password_strength("Short1!").is_err());

        // Manque majuscule
        assert!(PasswordService::validate_password_strength("lowercase123!").is_err());

        // Manque minuscule
        assert!(PasswordService::validate_password_strength("UPPERCASE123!").is_err());

        // Manque chiffre
        assert!(PasswordService::validate_password_strength("NoNumbers!").is_err());

        // Manque caractère spécial
        assert!(PasswordService::validate_password_strength("NoSpecial123").is_err());

        // Mot de passe commun
        assert!(PasswordService::validate_password_strength("password123").is_err());
    }

    #[test]
    fn test_different_hashes_for_same_password() {
        let password = "TestPassword123!";
        let hash1 = PasswordService::hash_password(password).expect("Checked operation");
        let hash2 = PasswordService::hash_password(password).expect("Checked operation");

        // Les hashes doivent être différents (sel aléatoire)
        assert_ne!(hash1, hash2);

        // Mais les deux doivent être valides
        assert!(PasswordService::verify_password(password, &hash1).expect("Checked operation"));
        assert!(PasswordService::verify_password(password, &hash2).expect("Checked operation"));
    }

    #[test]
    fn test_complexity_score() {
        let weak_password = "123456";
        let strong_password = "MyStr0ng!P@ssw0rd2024#";

        let weak_score = PasswordService::calculate_complexity_score(weak_password);
        let strong_score = PasswordService::calculate_complexity_score(strong_password);

        assert!(weak_score < 40);
        assert!(strong_score > 80);
    }

    #[test]
    fn test_password_suggestions() {
        let weak_password = "test";
        let suggestions = PasswordService::get_password_suggestions(weak_password);

        assert!(suggestions.len() > 1);
        assert!(suggestions.iter().any(|s| s.contains("14 caractères")));
    }
}
