use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::cookie::Key;
use std::time::Duration;

pub fn create_session_middleware(secret_key: &[u8]) -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(
        CookieSessionStore::default(),
        Key::from(secret_key)
    )
    .cookie_name("session_dcop413".to_string())
    .cookie_secure(true) // HTTPS only
    .cookie_http_only(true) // Pas d'accès JavaScript
    .cookie_same_site(actix_web::cookie::SameSite::Strict)
    .session_lifecycle(
        PersistentSession::default()
            .session_ttl(Duration::from_secs(900)) // 15 minutes au lieu de 1h
    )
    .build()
}
