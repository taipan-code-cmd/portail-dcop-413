use actix_web::HttpResponse;
use crate::middleware::auth_middleware::AuthenticatedUser;

pub struct AuthenticatedHandler;

impl AuthenticatedHandler {
    /// Dashboard principal avec navigation vers toutes les pages
    pub async fn dashboard_with_navigation(_user: AuthenticatedUser) -> HttpResponse {
        let html_content = include_str!("../../static/templates/dashboard_main.html");
        HttpResponse::Ok().content_type("text/html").body(html_content)
    }

    /// Page de gestion des visiteurs
    pub async fn visitors_management(_user: AuthenticatedUser) -> HttpResponse {
        // Pour l'instant, rediriger vers le dashboard avec la page visiteurs active
        let html_content = include_str!("../../static/templates/dashboard_main.html");
        let modified_content = html_content.replace(
            "showPage('dashboard');",
            "showPage('visitors');"
        );
        HttpResponse::Ok().content_type("text/html").body(modified_content)
    }

    /// Page de gestion des visites
    pub async fn visits_management(_user: AuthenticatedUser) -> HttpResponse {
        let html_content = include_str!("../../static/templates/dashboard_main.html");
        let modified_content = html_content.replace(
            "showPage('dashboard');",
            "showPage('visits');"
        );
        HttpResponse::Ok().content_type("text/html").body(modified_content)
    }

    /// Page des visites actives
    pub async fn active_visits(_user: AuthenticatedUser) -> HttpResponse {
        let html_content = include_str!("../../static/templates/dashboard_main.html");
        let modified_content = html_content.replace(
            "showPage('dashboard');",
            "showPage('active-visits');"
        );
        HttpResponse::Ok().content_type("text/html").body(modified_content)
    }

    /// Page des logs d'audit
    pub async fn audit_logs(_user: AuthenticatedUser) -> HttpResponse {
        let html_content = include_str!("../../static/templates/dashboard_main.html");
        let modified_content = html_content.replace(
            "showPage('dashboard');",
            "showPage('audit-logs');"
        );
        HttpResponse::Ok().content_type("text/html").body(modified_content)
    }

    /// Page d'exportation de données
    pub async fn data_export(_user: AuthenticatedUser) -> HttpResponse {
        let html_content = include_str!("../../static/templates/dashboard_main.html");
        let modified_content = html_content.replace(
            "showPage('dashboard');",
            "showPage('data-export');"
        );
        HttpResponse::Ok().content_type("text/html").body(modified_content)
    }

    /// Page de gestion des utilisateurs (admin seulement)
    pub async fn user_management(_user: AuthenticatedUser) -> HttpResponse {
        // FIXME: Implémenter vérification du rôle admin
        let html_content = include_str!("../../static/templates/dashboard_main.html");
        let modified_content = html_content.replace(
            "showPage('dashboard');",
            "showPage('user-management');"
        );
        HttpResponse::Ok().content_type("text/html").body(modified_content)
    }

    /// Page de détails d'un visiteur
    pub async fn visitor_details(_user: AuthenticatedUser) -> HttpResponse {
        let html_content = include_str!("../../static/templates/dashboard_main.html");
        HttpResponse::Ok().content_type("text/html").body(html_content)
    }

    /// Page de détails d'une visite
    pub async fn visit_details(_user: AuthenticatedUser) -> HttpResponse {
        let html_content = include_str!("../../static/templates/dashboard_main.html");
        HttpResponse::Ok().content_type("text/html").body(html_content)
    }
}
