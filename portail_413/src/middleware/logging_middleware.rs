use actix_web::HttpRequest;
use tracing::{info, warn};

// Actix-web utilise le middleware Logger intégré
// Ces fonctions sont des utilitaires pour le logging personnalisé

pub fn log_request_info(req: &HttpRequest) {
    let method = req.method();
    let uri = req.uri();
    let version = req.version();

    // Extraire les headers importants pour la sécurité
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    let x_forwarded_for = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok());

    let x_real_ip = req
        .headers()
        .get("x-real-ip")
        .and_then(|h| h.to_str().ok());

    // Déterminer l'IP réelle du client
    let client_ip = x_real_ip
        .or(x_forwarded_for.and_then(|xff| xff.split(',').next().map(|ip| ip.trim())))
        .unwrap_or("unknown");

    info!(
        target: "http_request",
        method = %method,
        uri = %uri,
        version = ?version,
        client_ip = %client_ip,
        user_agent = %user_agent,
        "HTTP request received"
    );
}

pub fn log_security_event(req: &HttpRequest, event: &str, details: &str) {
    let connection_info = req.connection_info();
    let client_ip = connection_info.realip_remote_addr().unwrap_or("unknown");
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    warn!(
        target: "security",
        event = %event,
        details = %details,
        client_ip = %client_ip,
        user_agent = %user_agent,
        uri = %req.uri(),
        "Security event detected"
    );
}