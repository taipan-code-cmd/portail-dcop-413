use portail_413::security::password::PasswordService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    log::info!("🔐 Génération de hashs pour les utilisateurs de test...\n");

    // Mots de passe conformes aux nouvelles règles (12+ caractères, complexité élevée)
    let test_passwords = vec![
        ("admin_dcop", "AdminDCOP2025!@#"),
        ("admin_security", "SecuAdmin2025$%"), 
        ("admin_system", "SysAdmin2025&*()"),
        ("user_reception", "Reception2025!@"),
        ("user_security", "Security2025#$"),
        ("user_manager", "Manager2025%^&"),
        ("test_user1", "TestUser2025!@#"),
        ("test_user2", "TestUser2025$%^"),
    ];

    log::info!("📊 Validation et hashage des mots de passe...\n");

    for (username, password) in test_passwords {
        // Validation du mot de passe
        match PasswordService::validate_password_strength(password) {
            Ok(_) => {
                let score = PasswordService::calculate_complexity_score(password);
                let hash = PasswordService::hash_password(password)?;
                log::info!("✅ {}: {} (Score: {}/100)", username, password, score);
                log::info!("   Hash: {}", hash);
                log::info!("   Longueur: {} caractères\n", password.len());
            },
            Err(e) => {
                log::info!("❌ {} - Erreur: {}\n", username, e);
            }
        }
    }

    log::info!("🎯 INFORMATIONS DE CONNEXION:");
    log::info!("{}", "=".repeat(80));
    log::info!("👤 Username: admin_dcop        | 🔑 Password: AdminDCOP2025!@#");
    log::info!("👤 Username: admin_security    | 🔑 Password: SecuAdmin2025$%");
    log::info!("👤 Username: admin_system      | 🔑 Password: SysAdmin2025&*()");
    log::info!("👤 Username: user_reception    | 🔑 Password: Reception2025!@");
    log::info!("👤 Username: user_security     | 🔑 Password: Security2025#$");
    log::info!("👤 Username: user_manager      | 🔑 Password: Manager2025%^&");
    log::info!("👤 Username: test_user1        | 🔑 Password: TestUser2025!@#");
    log::info!("👤 Username: test_user2        | 🔑 Password: TestUser2025$%^");
    log::info!("{}", "=".repeat(80));
    
    log::info!("\n🔐 RAPPEL SÉCURITÉ:");
    log::info!("• Tous les mots de passe respectent les nouvelles règles (12+ caractères)");
    log::info!("• Protection contre les attaques par force brute activée");
    log::info!("• Verrouillage progressif après tentatives échouées");

    Ok(())
}
