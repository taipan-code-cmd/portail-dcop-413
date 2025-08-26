use actix_cors::Cors;
use actix_web::http::header;

pub fn create_cors() -> Cors {
    Cors::default()
        .allowed_origin("https://localhost") // Seulement HTTPS
        .allowed_origin("https://127.0.0.1")
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::ACCEPT,
            header::CONTENT_TYPE,
        ])
        .max_age(3600)
        .supports_credentials()
}
