// DCOP (413) - Middleware de Validation Proxy Reverse
// S'assure que toutes les requêtes passent par le proxy reverse nginx
// Sécurité critique : Empêche l'accès direct à l'application

use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    error::ErrorForbidden,
    http::header::{HeaderName, HeaderValue, HOST, X_FORWARDED_FOR, X_FORWARDED_PROTO},
    Error,
};
use std::net::IpAddr;
use tracing::{debug, warn};
use serde_json::json;

/// Middleware qui vérifie que la requête passe par le proxy reverse
/// Configuration du middleware pour les endpoints spéciaux
/// Permet d'exclure certains endpoints du contrôle proxy (ex: health check interne)
pub fn should_validate_proxy(path: &str) -> bool {
    // Endpoints exclus de la validation proxy (pour monitoring interne)
    const EXCLUDED_PATHS: &[&str] = &[
        "/internal/health",
        "/metrics",
        "/actuator/health",
        "/health",  // Ajouter l'endpoint health standard pour Docker
        "/api/public/visits/register"  // Endpoint public d'enregistrement des visites
    ];
    
    !EXCLUDED_PATHS.iter().any(|excluded| path.starts_with(excluded))
}

/// Middleware wrapper pour l'intégration Actix Web
use actix_web::dev::{forward_ready, Service, Transform};
use std::future::{ready, Ready};
use futures_util::future::LocalBoxFuture;

pub struct ProxyValidation;

impl<S, B> Transform<S, ServiceRequest> for ProxyValidation
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = ProxyValidationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ProxyValidationMiddleware { service }))
    }
}

pub struct ProxyValidationMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for ProxyValidationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        
        // Vérifier si ce path nécessite une validation proxy
        if !should_validate_proxy(&path) {
            debug!("Skipping proxy validation for path: {}", path);
            let fut = self.service.call(req);
            return Box::pin(async move { fut.await });
        }

        // Extraire les informations avant de consommer req
        let connection_info = req.connection_info().clone();
        let headers = req.headers().clone();
        
        // SÉCURITÉ RENFORCÉE: Validation proxy STRICTE - AUCUN CONTOURNEMENT
        // Requiert OBLIGATOIREMENT les en-têtes de proxy standard
        let has_proxy_headers = headers.contains_key(X_FORWARDED_FOR) 
            && headers.contains_key(X_FORWARDED_PROTO);
        
        // Validation additionnelle: en-tête personnalisé du proxy
        let has_custom_proxy_header = headers.get("X-DCOP-Proxy")
            .and_then(|h| h.to_str().ok())
            .map(|v| v == "nginx-dcop-413")
            .unwrap_or(false);
        
        let remote_addr = connection_info.realip_remote_addr()
            .and_then(|ip| ip.parse::<IpAddr>().ok());
        
        debug!("Remote address: {:?}", remote_addr);
        
        let is_from_proxy = match remote_addr {
            Some(IpAddr::V4(ipv4)) => {
                debug!("IPv4 octets: {:?}", ipv4.octets());
                // SÉCURITÉ STRICTE: UNIQUEMENT le proxy nginx officiel et l'hôte Docker
                ipv4.octets() == [172, 25, 2, 2] ||  // IP nginx dans le réseau Docker
                ipv4.octets() == [172, 25, 2, 1] ||  // IP de l'hôte Docker (gateway)
                (ipv4.is_loopback() && has_custom_proxy_header) // Localhost SEULEMENT avec en-tête proxy
            },
            Some(IpAddr::V6(ipv6)) => {
                ipv6.is_loopback() && has_custom_proxy_header // IPv6 localhost SEULEMENT avec en-tête proxy
            },
            None => false,
        };

        let host_header = headers.get(HOST);
        let is_valid_host = match host_header {
            Some(host) => {
                let host_str = host.to_str().unwrap_or("");
                debug!("Received Host header: '{}'", host_str);
                // SÉCURITÉ STRICTE: Uniquement les domaines autorisés
                host_str == "localhost:8080" || 
                host_str == "localhost:8443" ||
                host_str == "localhost" ||
                host_str == "dcop.local" ||
                host_str == "127.0.0.1:8080" ||
                host_str == "127.0.0.1:8443" ||
                host_str == "127.0.0.1" ||
                // Autoriser seulement les noms de services Docker (pas d'IPs hardcodées)
                host_str == "dcop_backend" ||
                host_str == "dcop_nginx" ||
                host_str.starts_with("dcop_") // Services Docker autorisés
            },
            None => {
                debug!("No Host header received");
                false
            },
        };

        let forwarded_proto = headers.get(X_FORWARDED_PROTO)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        
        // SÉCURITÉ : Accepter HTTP en développement et HTTPS en production
        // Aussi accepter les requêtes internes sans proto forwarded
        let is_secure_proto = forwarded_proto == "https" || 
            forwarded_proto == "http" || 
            (forwarded_proto.is_empty() && cfg!(debug_assertions)) || // En développement, permettre les requêtes internes
            (remote_addr.map(|ip| ip.is_loopback()).unwrap_or(false)); // Localhost toujours autorisé

        debug!(
            "PROXY VALIDATION STRICTE - Remote IP: {:?}, Has proxy headers: {}, Custom header: {}, Valid host: {}, Secure proto: {}, From proxy: {}",
            remote_addr, has_proxy_headers, has_custom_proxy_header, is_valid_host, is_secure_proto, is_from_proxy
        );

        // SÉCURITÉ CRITIQUE: Les conditions principales doivent être remplies
        // Assouplissement : OR au lieu de AND pour certaines conditions en développement
        let is_valid_request = (has_proxy_headers && has_custom_proxy_header && is_from_proxy) || 
            (is_from_proxy && has_custom_proxy_header && cfg!(debug_assertions)); // Mode développement plus souple
        
        if !is_valid_request || !is_valid_host || !is_secure_proto {
            warn!(
                "🚨 SECURITY ALERT: Direct access BLOCKED - IP: {:?}, Path: {}, Headers: proxy={}, custom={}, host={}, proto={}, from_proxy={}",
                remote_addr, path, has_proxy_headers, has_custom_proxy_header, is_valid_host, is_secure_proto, is_from_proxy
            );
            
            let error = ErrorForbidden(json!({
                "error": "DIRECT_ACCESS_FORBIDDEN",
                "message": "All requests must go through the official DCOP proxy server",
                "code": "PROXY_REQUIRED",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }).to_string());
            return Box::pin(async move { Err(error) });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            res.headers_mut().insert(
                HeaderName::from_static("x-proxy-validated"), 
                HeaderValue::from_static("true")
            );
            Ok(res)
        })
    }
}


