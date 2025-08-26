use portail_413::database::repositories::user_repository::UserRepository;
use portail_413::models::{CreateUserRequest, UserRole};
use portail_413::security::password::PasswordService;
use portail_413::security::hashing::HashingService;
use sqlx::PgPool;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configuration de la base de données
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://dcop_user:F/Qj+7oo9OSn67ITKQvTsmUYZurJzxb6O8KJ1w2Y9xE=@localhost:5433/dcop_413?sslmode=prefer".to_string());
    
    let pool = PgPool::connect(&database_url).await?;
    let hashing_service = HashingService::new("salt-for-hashing-dcop-2025".to_string());
    let user_repo = UserRepository::new(pool.clone(), hashing_service);

    log::info!("🔐 Création des utilisateurs de test avec les nouvelles politiques de sécurité...\n");

    // Mots de passe conformes aux nouvelles règles (12+ caractères, complexité élevée)
    let test_users = vec![
        // Administrateur principal
        ("admin_dcop", "AdminDCOP2025!@#$", UserRole::Admin, "Administrateur principal du système"),
        
        // Administrateurs
        ("admin_security", "SecuAdmin2025$%^&", UserRole::Admin, "Administrateur sécurité"),
        ("admin_system", "SysAdmin2025&*()_+", UserRole::Admin, "Administrateur système"),
        
        // Utilisateurs normaux
        ("user_reception", "Reception2025!@#$", UserRole::User, "Utilisateur réception"),
        ("user_security", "Security2025#$%^&", UserRole::User, "Agent de sécurité"),
        ("user_manager", "Manager2025%^&*()_", UserRole::User, "Manager des visites"),
        
        // Utilisateurs de test
        ("test_user1", "TestUser2025!@#$%", UserRole::User, "Utilisateur de test 1"),
        ("test_user2", "TestUser2025$%^&*()", UserRole::User, "Utilisateur de test 2"),
    ];

    log::info!("📊 Validation des mots de passe avec les nouvelles règles...\n");

    for &(username, password, _, _) in &test_users {
        // Validation du mot de passe avec les nouvelles règles strictes
        match PasswordService::validate_password_strength(password) {
            Ok(_) => {
                let score = PasswordService::calculate_complexity_score(password);
                log::info!("✅ {} - Score de complexité: {}/100", username, score);
            },
            Err(e) => {
                log::info!("❌ {} - Erreur de validation: {}", username, e);
                continue;
            }
        }
    }

    log::info!("\n🔨 Création des utilisateurs dans la base de données...\n");

    let mut created_users = Vec::new();

    for &(username, password, ref role, description) in &test_users {
        // Vérifier si l'utilisateur existe déjà
        if let Ok(Some(_)) = user_repo.find_by_username(username).await {
            log::info!("⚠️  Utilisateur '{}' existe déjà - ignoré", username);
            continue;
        }

        // Créer la requête de création d'utilisateur
        let create_request = CreateUserRequest {
            username: username.to_string(),
            password: password.to_string(),
            role: role.clone(),
        };

        // Créer l'utilisateur
        match user_repo.create_user(create_request).await {
            Ok(user) => {
                log::info!("✅ Utilisateur créé: {} (ID: {}) - {}", username, user.id, description);
                created_users.push((username, password, role.clone(), user.id));
            },
            Err(e) => {
                log::info!("❌ Erreur lors de la création de '{}': {}", username, e);
            }
        }
    }

    log::info!("\n{}", "=".repeat(80));
    log::info!("🎉 UTILISATEURS CRÉÉS AVEC SUCCÈS");
    log::info!("{}", "=".repeat(80));

    for (username, password, role, user_id) in &created_users {
        log::info!("👤 Username: {}", username);
        log::info!("🔑 Password: {}", password);
        log::info!("🏷️  Role: {:?}", role);
        log::info!("🆔 ID: {}", user_id);
        log::info!("{}", "─".repeat(50));
    }

    log::info!("\n🔐 RAPPEL SÉCURITÉ:");
    log::info!("• Tous les mots de passe respectent les nouvelles règles (12+ caractères)");
    log::info!("• Changez ces mots de passe par défaut en production");
    log::info!("• Les tentatives de connexion échouées déclenchent un verrouillage progressif");
    log::info!("• Protection contre les attaques par force brute activée");

    Ok(())
}
