use actix_cors::Cors;
use actix_web::http::{header, Method};

pub fn create_cors_layer() -> Cors {
    Cors::default()
        // Origines autorisées (à restreindre en production)
        .allowed_origin("https://localhost")
        .allowed_origin("https://127.0.0.1")
        .allowed_origin("https://dcop.local")
        // Origines HTTP pour développement et proxy reverse
        .allowed_origin("http://localhost:8080")
        .allowed_origin("http://127.0.0.1:8080")
        .allowed_origin("http://dcop.local:8080")
        // Origines pour le frontend de développement (trunk serve port par défaut)
        .allowed_origin("http://localhost:8081")
        .allowed_origin("http://127.0.0.1:8081")
        // Méthodes HTTP autorisées
        .allowed_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        // Headers autorisés
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::ORIGIN,
            header::HeaderName::from_static("x-requested-with"),
            header::HeaderName::from_static("x-csrf-token"),
        ])
        // Headers exposés au client
        .expose_headers(vec![
            "x-total-count",
            "x-page-count",
        ])
        // Autoriser les credentials (cookies, authorization headers)
        .supports_credentials()
        // Durée de cache pour les requêtes preflight
        .max_age(3600)
}

// Configuration CORS restrictive pour la production
pub fn create_production_cors_layer(allowed_origins: Vec<&str>) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec![Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
        ])
        .supports_credentials()
        .max_age(300); // 5 minutes en production

    // Ajouter les origines autorisées
    for origin in allowed_origins {
        cors = cors.allowed_origin(origin);
    }

    cors
}
