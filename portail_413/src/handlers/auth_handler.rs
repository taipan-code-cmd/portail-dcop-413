use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use crate::security::password_security::{hash_password, verify_password, migrate_from_bcrypt};
use crate::utils::security_logger::SecurityLogger;
use crate::utils::input_validator::InputValidator;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub token: Option<String>,
    pub message: String,
}

pub async fn login_handler(
    req: HttpRequest,
    login_data: web::Json<LoginRequest>,
) -> Result<HttpResponse> {
    let client_ip = req
        .connection_info()
        .remote_addr()
        .unwrap_or("unknown")
        .to_string();

    // Validation et sanitisation des entrées
    let username = InputValidator::sanitize_input(&login_data.username);
    let password = &login_data.password;

    if username.is_empty() || password.is_empty() {
        SecurityLogger::log_authentication_attempt(&username, false, &client_ip);
        return Ok(HttpResponse::BadRequest().json(LoginResponse {
            success: false,
            token: None,
            message: "Nom d'utilisateur et mot de passe requis".to_string(),
        }));
    }

    // Simulation récupération utilisateur depuis DB
    // TODO: Remplacer par vraie requête DB
    let stored_hash = get_user_password_hash(&username).await;
    
    match stored_hash {
        Some(hash) => {
            let is_valid = if hash.starts_with("$argon2") {
                // Hash Argon2 - vérification directe
                verify_password(password, &hash).unwrap_or(false)
            } else if hash.starts_with("$2") {
                // Hash bcrypt - migration vers Argon2
                match migrate_from_bcrypt(password, &hash) {
                    Ok(Some(new_hash)) => {
                        // Mettre à jour le hash en DB avec Argon2
                        update_user_password_hash(&username, &new_hash).await;
                        true
                    }
                    Ok(None) => false,
                    Err(_) => false,
                }
            } else {
                false
            };

            if is_valid {
                SecurityLogger::log_authentication_attempt(&username, true, &client_ip);
                
                // Génération JWT avec secret sécurisé
                let token = generate_jwt_token(&username)?;
                
                Ok(HttpResponse::Ok().json(LoginResponse {
                    success: true,
                    token: Some(token),
                    message: "Authentification réussie".to_string(),
                }))
            } else {
                SecurityLogger::log_authentication_attempt(&username, false, &client_ip);
                Ok(HttpResponse::Unauthorized().json(LoginResponse {
                    success: false,
                    token: None,
                    message: "Identifiants invalides".to_string(),
                }))
            }
        }
        None => {
            SecurityLogger::log_authentication_attempt(&username, false, &client_ip);
            Ok(HttpResponse::Unauthorized().json(LoginResponse {
                success: false,
                token: None,
                message: "Utilisateur non trouvé".to_string(),
            }))
        }
    }
}

// Fonctions utilitaires (à implémenter avec votre DB)
async fn get_user_password_hash(username: &str) -> Option<String> {
    // TODO: Implémenter requête DB réelle
    None
}

async fn update_user_password_hash(username: &str, new_hash: &str) {
    // TODO: Implémenter mise à jour DB
}

fn generate_jwt_token(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // TODO: Implémenter génération JWT avec secret sécurisé
    Ok(format!("jwt_token_for_{}", username))
}
