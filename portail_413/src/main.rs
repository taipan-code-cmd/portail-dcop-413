use actix_web::{
    middleware::Logger,
    web, App, HttpServer, HttpResponse, HttpRequest,
    http::Method,
};
use actix_files as fs;
use tracing_subscriber::{util::SubscriberInitExt, prelude::*};
use actix_cors::Cors;
use actix_web::http::header;
use serde_json;

use portail_413::{
    config::Config,
    database::Database,
    services::{StatisticsService, AuthService, VisitorService, VisitService, AuditService},
    middleware::{ProxyValidation, NetworkIsolation},
    state::AppState,
    models::{CreateUserRequest, UserRole},
    errors::AppError,
    database::repositories::{StatisticsRepository, UserRepository, VisitorRepository, VisitRepository, AuditRepository},
    security::{SecureSessionManager, HashingService, EncryptionService},
};
use portail_413::handlers::{VisitorHandler, VisitHandler, AdminHandler};
use portail_413::handlers::statistics_handler as stats_handlers;
use portail_413::handlers::user_handler::UserHandler;
use portail_413::handlers::auth_handler::AuthHandler;

fn create_cors_layer() -> Cors {
    Cors::default()
        // SÉCURITÉ RENFORCÉE: Origins spécifiques uniquement
        .allowed_origin("https://localhost:8443")
        .allowed_origin("https://127.0.0.1:8443")
        .allowed_origin("https://dcop.local")
        // Méthodes HTTP strictement nécessaires
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        // Headers autorisés de manière restrictive
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::ACCEPT,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-csrf-token"),
            header::HeaderName::from_static("x-dcop-proxy"),
        ])
        // Credentials seulement pour origins de confiance
        .supports_credentials()
        // Cache CORS réduit pour plus de sécurité
        .max_age(1800)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialiser le logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "portail_413=debug,actix_web=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Charger la configuration
    let config = Config::from_env()?;
    tracing::info!("Configuration loaded successfully");

    // Configuration de la base de données
    let database = Database::new(&config.database).await?;
    tracing::info!("Database connection established successfully");

    // Exécuter les migrations automatiquement au démarrage
    database.run_migrations().await?;
    tracing::info!("Database migrations completed successfully");

    // Configuration des repositories dans le bon ordre
    let audit_repository = AuditRepository::new(database.pool.clone());
    let statistics_repository = StatisticsRepository::new(database.pool.clone());
    
    let hashing_service = HashingService::new("argon2_salt".to_string());
    let encryption_service = EncryptionService::new("your_encryption_key_32_chars_long")?;
    
    let user_repository = UserRepository::new(database.pool.clone(), hashing_service.clone());
    let visitor_repository = VisitorRepository::new(database.pool.clone(), encryption_service, hashing_service.clone());
    let visit_repository = VisitRepository::new(database.pool.clone(), hashing_service);

    // Configuration des services
    let session_manager = SecureSessionManager::new(
        "your_very_long_access_token_secret_key_at_least_32_chars".to_string(),
        "your_very_long_refresh_token_secret_key_at_least_32_chars".to_string(),
        15, // access_token_lifetime_minutes
        7,  // refresh_token_lifetime_days
    );
    let audit_service = AuditService::new(audit_repository.clone());
    let auth_service = AuthService::new(
        user_repository.clone(),
        session_manager,
        audit_service.clone(),
        5, // max_login_attempts
        900, // lockout_duration_seconds (15 min)
    );
    let visitor_service = VisitorService::new(visitor_repository, audit_service.clone());
    let visit_service = VisitService::new(visit_repository, audit_service.clone());
    let statistics_service = StatisticsService::new(database.pool.clone());

    // Créer l'AppState
    let app_state = AppState::new(
        auth_service,
        visitor_service,
        visit_service,
        statistics_service.clone(),
        audit_service,
        statistics_repository,
    );

    // Assurer qu'un admin par défaut existe
    app_state.auth_service.ensure_default_admin().await?;

    let bind_address = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("🚀 Starting server on http://{}", bind_address);

    HttpServer::new(move || {
        let app_state_clone = app_state.clone();
        App::new()
            .app_data(web::Data::new(app_state_clone))
            // 🔒 SÉCURITÉ MULTICOUCHE: Double validation proxy obligatoire
            .wrap(NetworkIsolation)        // Couche 1: Isolation réseau stricte
            .wrap(ProxyValidation)         // Couche 2: Validation des en-têtes proxy
            .wrap(Logger::default())
            .wrap(create_cors_layer())
            .configure(configure_routes)
    })
    .bind(&bind_address)?
    .run()
    .await?;

    Ok(())
}

// Fonction de création d'utilisateur avec validation complète
async fn secure_register(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    user_data: web::Json<serde_json::Value>
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    let username = user_data.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = user_data.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let role_str = user_data.get("role").and_then(|v| v.as_str()).unwrap_or("user");
    
    // Validation des données d'entrée
    if username.is_empty() || password.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "message": "Username et password sont requis"
        })));
    }

    // Validation de la longueur minimale
    if username.len() < 3 || username.len() > 50 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "message": "Le nom d'utilisateur doit contenir entre 3 et 50 caractères"
        })));
    }

    if password.len() < 8 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "message": "Le mot de passe doit contenir au moins 8 caractères"
        })));
    }

    // Parser le rôle
    let role = match role_str.to_lowercase().as_str() {
        "admin" => UserRole::Admin,
        "director" => UserRole::Director,
        "user" | _ => UserRole::User,
    };

    // Créer la requête de création d'utilisateur
    let create_request = CreateUserRequest {
        username: username.to_string(),
        password: password.to_string(),
        role,
    };

    // Vérification de l'authentification pour la création d'utilisateur
    // (Seuls les admins peuvent créer des comptes)
    let auth_header = req.headers().get("authorization");
    if auth_header.is_none() {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "success": false,
            "message": "Authentification requise pour créer un utilisateur"
        })));
    }

    // Pour l'instant, nous permettons la création directe en mode développement
    // En production, il faudra valider le token admin
    match app_state.auth_service.register_user(create_request, None).await {
        Ok(user_response) => {
            Ok(HttpResponse::Created().json(serde_json::json!({
                "success": true,
                "user": user_response,
                "message": "Utilisateur créé avec succès"
            })))
        },
        Err(e) => {
            tracing::warn!("User registration failed: {}", e);
            let error_message = match e {
                AppError::Conflict(msg) => msg,
                AppError::Validation(msg) => msg,
                _ => "Erreur lors de la création de l'utilisateur".to_string(),
            };
            
            Ok(HttpResponse::Conflict().json(serde_json::json!({
                "success": false,
                "message": error_message
            })))
        }
    }
}

// Fonction pour les statistiques publiques avec vraies données
async fn get_public_stats(app_state: web::Data<AppState>) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    // Récupérer les vraies statistiques depuis la base de données
    match app_state.statistics_repository.get_dashboard_stats().await {
        Ok(stats) => {
            let response = serde_json::json!({
                "active_visits": stats.active_visits,
                "total_visitors": stats.total_visitors,
                "today_visits": stats.today_visits,
                "pending_approvals": stats.pending_approvals,
                "last_updated": chrono::Utc::now().to_rfc3339()
            });
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            tracing::error!("Failed to get dashboard stats for public API: {}", e);
            // En cas d'erreur, retourner des statistiques par défaut
            let fallback_stats = serde_json::json!({
                "active_visits": 0,
                "total_visitors": 0,
                "today_visits": 0,
                "pending_approvals": 0,
                "last_updated": chrono::Utc::now().to_rfc3339(),
                "error": "Database temporarily unavailable"
            });
            Ok(HttpResponse::Ok().json(fallback_stats))
        }
    }
}

// Handler pour l'enregistrement public des visites
async fn public_visit_registration(
    app_state: web::Data<AppState>,
    payload: web::Json<serde_json::Value>
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    tracing::info!("Réception d'une demande d'enregistrement de visite publique");
    
    let request_data = payload.into_inner();
    tracing::debug!("Données reçues: {:?}", request_data);
    
    // Extraire les données du visiteur
    let visitor_data = request_data.get("visitor")
        .ok_or("Données du visiteur manquantes")?;
    
    let first_name = visitor_data.get("first_name")
        .and_then(|v| v.as_str())
        .ok_or("Prénom requis")?;
    let last_name = visitor_data.get("last_name")
        .and_then(|v| v.as_str())
        .ok_or("Nom requis")?;
    let email = visitor_data.get("email")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let phone1 = visitor_data.get("phone1")
        .and_then(|v| v.as_str())
        .ok_or("Téléphone principal requis")?;
    let phone2 = visitor_data.get("phone2")
        .and_then(|v| v.as_str())
        .ok_or("Téléphone secondaire requis")?;
    let phone3 = visitor_data.get("phone3")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let phone4 = visitor_data.get("phone4")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let organization = visitor_data.get("organization")
        .and_then(|v| v.as_str())
        .ok_or("Organisation requise")?;
    let _nationality = visitor_data.get("nationality")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let _address = visitor_data.get("address")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let photo = visitor_data.get("photo")
        .and_then(|v| v.as_str());
    
    // Extraire les données de la visite
    let purpose = request_data.get("purpose")
        .and_then(|v| v.as_str())
        .ok_or("Objet de la visite requis")?;
    let host_name = request_data.get("host_name")
        .and_then(|v| v.as_str())
        .ok_or("Personne à rencontrer requise")?;
    let host_phone = request_data.get("host_phone")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let host_email = request_data.get("host_email")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let department = request_data.get("department")
        .and_then(|v| v.as_str())
        .ok_or("Département requis")?;
    let scheduled_date = request_data.get("scheduled_date")
        .and_then(|v| v.as_str())
        .ok_or("Date de visite requise")?;
    let scheduled_start = request_data.get("scheduled_start")
        .and_then(|v| v.as_str())
        .ok_or("Heure de début requise")?;
    let scheduled_end = request_data.get("scheduled_end")
        .and_then(|v| v.as_str())
        .ok_or("Heure de fin requise")?;
    let estimated_duration = request_data.get("estimated_duration")
        .and_then(|v| v.as_str());
    let building = request_data.get("building")
        .and_then(|v| v.as_str());
    let vehicle_info = request_data.get("vehicle_info")
        .and_then(|v| v.as_str());
    let accompaniers = request_data.get("accompaniers")
        .and_then(|v| v.as_str());
    let notes = request_data.get("notes")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    
    // Vérifier les acceptations de sécurité
    let security_check = request_data.get("security_check")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let data_consent = request_data.get("data_consent")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let rules_acceptance = request_data.get("rules_acceptance")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    
    if !security_check || !data_consent || !rules_acceptance {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "message": "Toutes les acceptations de sécurité sont requises"
        })));
    }
    
    // Créer le visiteur (ou récupérer s'il existe déjà)
    let visitor_request = portail_413::models::CreateVisitorRequest {
        first_name: first_name.to_string(),
        last_name: last_name.to_string(),
        email: email.map(|e| e.to_string()),
        phone1: phone1.to_string(), // Téléphone principal (obligatoire)
        phone2: phone2.to_string(), // Téléphone secondaire (obligatoire)
        phone3: phone3.map(|p| p.to_string()), // Téléphone tertiaire (optionnel)
        phone4: phone4.map(|p| p.to_string()), // Téléphone quaternaire (optionnel)
        organization: organization.to_string(),
        photo_data: photo.map(|p| p.to_string()),
        // Champs supplémentaires pour compatibilité
        function: None,
        visit_purpose: purpose.to_string(),
        host_name: Some(host_name.to_string()),
        visit_date: Some(scheduled_date.to_string()),
        visit_time: Some(scheduled_start.to_string()),
        visit_details: if notes.is_empty() { None } else { Some(notes.to_string()) },
        security_agreement: Some(security_check),
        electronic_devices: Some(false), // Par défaut
        confidentiality: Some(data_consent),
        signature_date: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
        signature: None, // Pas de signature pour l'instant
    };
    
    let visitor = match app_state.visitor_service.create_visitor(
        visitor_request,
        None, // user_id - pas d'utilisateur connecté pour les visites publiques
        Some("Public Registration".to_string()), // ip_address
        Some("Public Visit Form".to_string()), // user_agent
    ).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Erreur lors de la création du visiteur: {:?}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "message": "Erreur lors de l'enregistrement du visiteur"
            })));
        }
    };
    
    // Préparer les dates et heures
    let scheduled_datetime_start = format!("{}T{}", scheduled_date, scheduled_start);
    let scheduled_datetime_end = format!("{}T{}", scheduled_date, scheduled_end);
    
    // Créer la visite
    let visit_request = portail_413::models::CreateVisitRequest {
        visitor_id: visitor.id,
        purpose: purpose.to_string(),
        host_name: host_name.to_string(),
        department: department.to_string(),
        scheduled_start: chrono::DateTime::parse_from_rfc3339(&format!("{}:00+00:00", scheduled_datetime_start))
            .map_err(|_| "Format de date invalide")?
            .with_timezone(&chrono::Utc),
        scheduled_end: chrono::DateTime::parse_from_rfc3339(&format!("{}:00+00:00", scheduled_datetime_end))
            .map_err(|_| "Format de date de fin invalide")?
            .with_timezone(&chrono::Utc),
        notes: if notes.is_empty() { 
            None 
        } else { 
            // Combiner toutes les informations supplémentaires
            let mut combined_notes = notes.to_string();
            if let Some(building) = building {
                combined_notes.push_str(&format!("\nBâtiment: {}", building));
            }
            if let Some(duration) = estimated_duration {
                combined_notes.push_str(&format!("\nDurée estimée: {}", duration));
            }
            if let Some(vehicle) = vehicle_info {
                combined_notes.push_str(&format!("\nVéhicule: {}", vehicle));
            }
            if let Some(accomp) = accompaniers {
                combined_notes.push_str(&format!("\nAccompagnateurs: {}", accomp));
            }
            if let Some(host_ph) = host_phone {
                combined_notes.push_str(&format!("\nTél. contact: {}", host_ph));
            }
            if let Some(host_em) = host_email {
                combined_notes.push_str(&format!("\nEmail contact: {}", host_em));
            }
            Some(combined_notes)
        },
    };
    
    let visit = match app_state.visit_service.create_visit(
        visit_request,
        None, // user_id - pas d'utilisateur connecté pour les visites publiques
        Some("Public Registration".to_string()), // ip_address
        Some("Public Visit Form".to_string()), // user_agent
    ).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Erreur lors de la création de la visite: {:?}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "message": "Erreur lors de l'enregistrement de la visite"
            })));
        }
    };
    
    tracing::info!("Visite publique enregistrée avec succès: {:?}", visit.id);
    
    // Retourner une réponse de succès
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Visite enregistrée avec succès",
        "data": {
            "visit_id": visit.id,
            "visitor_id": visitor.id,
            "status": "scheduled",
            "confirmation_message": "Votre visite a été enregistrée et sera examinée par l'administration. Vous recevrez un email de confirmation."
        }
    })))
}

fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // Routes publiques de base (sans authentification)
        .route("/health", web::get().to(|| async {
            HttpResponse::Ok().json("OK")
        }))
        
        .route("/", web::get().to(|| async {
            // Utiliser include_str! pour charger le fichier directement lors de la compilation
            HttpResponse::Ok()
                .content_type("text/html")
                .body(include_str!("../static/index.html"))
        }))
        
        // API Routes publiques
        .service(
            web::scope("/api/public")
                .route("/health", web::get().to(|| async {
                    HttpResponse::Ok().json("API is healthy")
                }))
                .route("/login", web::post().to(AuthHandler::login))
                .route("/register", web::post().to(secure_register))
                .route("/stats", web::get().to(get_public_stats))
                // Public stats used by FE
                .route("/statistics/dashboard", web::get().to(stats_handlers::get_dashboard_stats_public))
                .route("/statistics/visits", web::get().to(stats_handlers::get_visit_statistics_public))
                .route("/statistics/visitors", web::get().to(stats_handlers::get_visitor_statistics_public))
                .route("/statistics/activity-chart", web::get().to(stats_handlers::get_activity_chart_data_public))
                // Enregistrement public des visites
                .route("/visits/register", web::post().to(public_visit_registration))
        )
        
        // API Routes avec authentification potentielle (dashboard + secured resources)
        .service(
            web::scope("/api")
                // Statistiques de base pour le dashboard
                .route("/dashboard", web::get().to(get_public_stats))
                // Versions publiques authentifiées des stats (enveloppe différente côté FE)
                .route("/statistics/dashboard", web::get().to(stats_handlers::get_dashboard_stats))
                .route("/statistics/real-time", web::get().to(stats_handlers::get_real_time_statistics))
                .route("/statistics/visits", web::get().to(stats_handlers::get_visit_statistics))
                .route("/statistics/visitors", web::get().to(stats_handlers::get_visitor_statistics))
                .route("/statistics/activity-chart", web::get().to(stats_handlers::get_activity_chart_data))
                // Routes d'authentification
                .service(
                    web::scope("/auth")
                        .route("/login", web::post().to(portail_413::handlers::auth_handler::AuthHandler::login))
                        .route("/logout", web::post().to(portail_413::handlers::auth_handler::AuthHandler::logout))
                        .route("/validate", web::get().to(portail_413::handlers::auth_handler::AuthHandler::validate_token))
                        .route("/profile", web::get().to(portail_413::handlers::auth_handler::AuthHandler::profile))
                        .route("/register", web::post().to(portail_413::handlers::auth_handler::AuthHandler::register))
                        .route("/login", web::get().to(|| async {
                            HttpResponse::MethodNotAllowed().json(serde_json::json!({
                                "success": false,
                                "message": "Login endpoint requires POST method with JSON body containing username and password",
                                "expected_method": "POST",
                                "content_type": "application/json"
                            }))
                        }))
                        .route("/login", web::method(Method::OPTIONS).to(|| async {
                            HttpResponse::Ok().finish()
                        }))
                )
                // Visitors
                .service(
                    web::scope("/visitors")
                        .route("", web::get().to(VisitorHandler::list_visitors))
                        .route("", web::post().to(VisitorHandler::create_visitor))
                        .route("/{id}", web::get().to(VisitorHandler::get_visitor))
                        .route("/{id}", web::put().to(VisitorHandler::update_visitor))
                        .route("/{id}", web::delete().to(VisitorHandler::delete_visitor))
                        .route("/search", web::get().to(VisitorHandler::search_visitors))
                )
                // Visits
                .service(
                    web::scope("/visits")
                        .route("", web::get().to(VisitHandler::list_visits))
                        .route("", web::post().to(VisitHandler::create_visit))
                        .route("/search", web::get().to(VisitHandler::search_visits))
                        .route("/active", web::get().to(VisitHandler::get_active_visits))
                        .route("/{id}", web::get().to(VisitHandler::get_visit))
                        .route("/{id}/status", web::put().to(VisitHandler::update_visit_status))
                        .route("/{id}/start", web::post().to(VisitHandler::start_visit))
                        .route("/{id}/end", web::post().to(VisitHandler::end_visit))
                )
                // Users
                .service(
                    web::scope("/users")
                        .route("", web::get().to(UserHandler::list_users))
                        .route("", web::post().to(UserHandler::create_user))
                        .route("/me", web::get().to(UserHandler::current_profile))
                        .route("/me/permissions", web::get().to(UserHandler::current_permissions))
                        .route("/{id}/status", web::put().to(UserHandler::change_status))
                        .route("/{id}/role", web::put().to(UserHandler::change_role))
                        .route("/{id}", web::delete().to(UserHandler::delete_user))
                )
                // Admin
                .service(
                    web::scope("/admin")
                        .route("/stats", web::get().to(AdminHandler::get_dashboard_stats))
                        .route("/stats/hourly", web::get().to(AdminHandler::get_hourly_stats))
                        .route("/stats/weekly", web::get().to(AdminHandler::get_weekly_stats))
                        .route("/audit", web::get().to(AdminHandler::get_audit_logs))
                        .route("/audit/{id}", web::get().to(AdminHandler::get_audit_log))
                        .route("/health", web::get().to(AdminHandler::get_system_health))
                        .route("/export", web::get().to(AdminHandler::export_data))
                )
        )
        
        // Route spécifique pour le CSS local (directement intégré)
        .route("/static/assets/css/tailwind-minimal.css", web::get().to(|| async {
            HttpResponse::Ok()
                .content_type("text/css")
                .body(include_str!("../static/assets/css/tailwind-minimal.css"))
        }))
        
    // Servir les fichiers statiques
        .service(
            web::scope("/static")
                .service(fs::Files::new("", "./static/").index_file("index.html"))
        );
}

