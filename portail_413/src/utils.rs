// Module utilitaire temporaire
use actix_web::HttpRequest;

pub fn generate_badge_number() -> String {
    format!("BADGE{}", chrono::Utc::now().timestamp_millis())
}

pub fn extract_user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(String::from)
}
