// DCOP (413) - Middleware d'Isolation Réseau
// Couche de sécurité supplémentaire pour empêcher tout accès direct
// Complément du ProxyValidation pour une sécurité renforcée

use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorForbidden,
    Error,
};
use std::{
    future::{ready, Ready},
    net::{IpAddr, Ipv4Addr},
};
use futures_util::future::LocalBoxFuture;
use tracing::{debug, error};
use serde_json::json;

/// Middleware d'isolation réseau strict
/// Bloque TOUT trafic qui ne vient pas du proxy nginx
pub struct NetworkIsolation;

impl<S, B> Transform<S, ServiceRequest> for NetworkIsolation
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = NetworkIsolationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(NetworkIsolationMiddleware { service }))
    }
}

pub struct NetworkIsolationMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for NetworkIsolationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let connection_info = req.connection_info().clone();
        let path = req.path().to_string();
        
        // Obtenir l'IP source réelle
        let source_ip = connection_info.realip_remote_addr()
            .and_then(|ip| ip.parse::<IpAddr>().ok());

        debug!("Network isolation check - Source IP: {:?}, Path: {}", source_ip, path);

        // Validation stricte: SEULE l'IP du nginx est autorisée
        let is_nginx_ip = match source_ip {
            Some(IpAddr::V4(ipv4)) => {
                // UNIQUEMENT l'IP du conteneur nginx
                ipv4 == Ipv4Addr::new(172, 25, 2, 2) ||
                // Ou l'IP de l'hôte Docker (gateway)
                ipv4 == Ipv4Addr::new(172, 25, 2, 1) ||
                // Ou loopback pour les health checks internes
                (ipv4.is_loopback() && (path.starts_with("/internal/") || path == "/metrics"))
            },
            _ => false,
        };

        if !is_nginx_ip {
            error!(
                "🚨 NETWORK ISOLATION BREACH: Unauthorized IP {} attempting access to {}",
                source_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string()),
                path
            );

            let error_json = json!({
                "error": "NETWORK_ISOLATION_VIOLATION",
                "message": "Direct network access forbidden - use official proxy only",
                "code": "ISOLATION_BREACH",
                "source_ip": source_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string()),
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "security_level": "CRITICAL"
            });

            let error = ErrorForbidden(error_json.to_string());
            return Box::pin(async move { Err(error) });
        }

        debug!("✅ Network isolation passed for IP: {:?}", source_ip);
        
        let fut = self.service.call(req);
        Box::pin(async move { fut.await })
    }
}
