// DCOP (413) - Système de Rate Limiting Avancé
// Implémentation moderne avec support Redis et algorithmes multiples

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    web, Error, HttpResponse,
};
use anyhow::{Context, Result};
use governor::{
    clock::{DefaultClock},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use ipnetwork::IpNetwork;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::security::security_config::{EndpointRateLimit, RateLimitAlgorithm, RateLimitConfig};

/// Clé unique pour identifier une limite de taux
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RateLimitKey {
    pub identifier: String, // IP, user_id, API key, etc.
    pub endpoint: String,   // Endpoint HTTP concerné
    pub method: String,     // Méthode HTTP
}

impl RateLimitKey {
    pub fn from_ip_endpoint(ip: IpAddr, endpoint: &str, method: &str) -> Self {
        Self {
            identifier: ip.to_string(),
            endpoint: endpoint.to_string(),
            method: method.to_string(),
        }
    }

    pub fn from_user_endpoint(user_id: &str, endpoint: &str, method: &str) -> Self {
        Self {
            identifier: format!("user:{}", user_id),
            endpoint: endpoint.to_string(),
            method: method.to_string(),
        }
    }

    pub fn to_redis_key(&self) -> String {
        format!("rate_limit:{}:{}:{}", self.identifier, self.endpoint, self.method)
    }
}

/// Informations sur l'état du rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub allowed: bool,
    pub requests_remaining: u32,
    pub reset_time: SystemTime,
    pub retry_after: Option<Duration>,
    pub current_requests: u32,
    pub window_start: SystemTime,
}

/// Compteur de requêtes avec fenêtre glissante
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SlidingWindowCounter {
    pub requests: Vec<RequestRecord>,
    pub window_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestRecord {
    pub timestamp: SystemTime,
    pub count: u32,
}

/// Bucket de tokens pour l'algorithme Token Bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenBucket {
    pub tokens: f64,
    pub capacity: f64,
    pub refill_rate: f64, // tokens per second
    pub last_refill: SystemTime,
}

/// Gestionnaire de rate limiting distribué
pub struct RateLimitManager {
    config: RateLimitConfig,
    in_memory_limiters: Arc<RwLock<HashMap<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>>>>,
    sliding_windows: Arc<RwLock<HashMap<String, SlidingWindowCounter>>>,
    token_buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    exempted_ips: Vec<IpNetwork>,
}

impl RateLimitManager {
    /// Crée un nouveau gestionnaire de rate limiting
    pub async fn new(config: RateLimitConfig) -> Result<Self> {
        info!("Initializing advanced rate limiting manager");

        // Initialisation des limiteurs en mémoire
        let mut in_memory_limiters = HashMap::new();
        for (endpoint, limit_config) in &config.endpoint_limits {
            let quota = Quota::per_minute(
                std::num::NonZeroU32::new(limit_config.requests_per_minute)
                    .context("Invalid rate limit configuration")?
            );
            let limiter = Arc::new(RateLimiter::direct(quota));
            in_memory_limiters.insert(endpoint.clone(), limiter);
        }

        Ok(Self {
            exempted_ips: config.ip_exemptions.clone(),
            config,
            in_memory_limiters: Arc::new(RwLock::new(in_memory_limiters)),
            sliding_windows: Arc::new(RwLock::new(HashMap::new())),
            token_buckets: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Point d'entrée principal pour vérifier les limites de taux
    pub async fn check_rate_limit(&self, key: &RateLimitKey) -> Result<RateLimitInfo> {
        // Vérifier si l'IP est exempte
        if let Ok(ip) = key.identifier.parse::<IpAddr>() {
            for exempt_network in &self.exempted_ips {
                if exempt_network.contains(ip) {
                    return Ok(RateLimitInfo {
                        allowed: true,
                        requests_remaining: u32::MAX,
                        reset_time: SystemTime::now() + Duration::from_secs(60),
                        retry_after: None,
                        current_requests: 0,
                        window_start: SystemTime::now(),
                    });
                }
            }
        }

        // Rechercher la configuration pour cet endpoint
        let endpoint_config = self.config.endpoint_limits
            .get(&key.endpoint)
            .cloned()
            .unwrap_or_else(|| EndpointRateLimit {
                requests_per_minute: 60,  // Valeurs par défaut
                requests_per_hour: 1000,
                requests_per_day: 10000,
                burst_capacity: 10,
            });

        // Appliquer l'algorithme de rate limiting configuré
        match self.config.algorithm {
            RateLimitAlgorithm::TokenBucket => {
                self.check_token_bucket(key, &endpoint_config).await
            },
            RateLimitAlgorithm::SlidingWindow => {
                self.check_sliding_window(key, &endpoint_config).await
            },
            _ => {
                // Fallback vers token bucket pour les autres algorithmes
                self.check_token_bucket(key, &endpoint_config).await
            }
        }
    }

    /// Vérifie le rate limiting avec algorithme Token Bucket
    pub async fn check_token_bucket(&self, key: &RateLimitKey, config: &EndpointRateLimit) -> Result<RateLimitInfo> {
        let bucket_key = format!("token_bucket:{}", key.to_redis_key());
        let now = SystemTime::now();

        // Utiliser uniquement l'implémentation en mémoire locale
        self.check_token_bucket_memory(&bucket_key, config, now).await
    }

    async fn check_token_bucket_memory(
        &self,
        key: &str,
        config: &EndpointRateLimit,
        now: SystemTime,
    ) -> Result<RateLimitInfo> {
        let mut buckets = self.token_buckets.write();
        
        let bucket = buckets.entry(key.to_string()).or_insert_with(|| TokenBucket {
            tokens: config.burst_capacity as f64,
            capacity: config.burst_capacity as f64,
            refill_rate: config.requests_per_minute as f64 / 60.0,
            last_refill: now,
        });

        // Calculer les tokens à ajouter
        let time_passed = now.duration_since(bucket.last_refill).unwrap_or_default();
        let tokens_to_add = time_passed.as_secs_f64() * bucket.refill_rate;
        bucket.tokens = (bucket.tokens + tokens_to_add).min(bucket.capacity);
        bucket.last_refill = now;

        let allowed = bucket.tokens >= 1.0;
        if allowed {
            bucket.tokens -= 1.0;
        }

        let reset_time = now + Duration::from_secs_f64((bucket.capacity - bucket.tokens) / bucket.refill_rate);

        Ok(RateLimitInfo {
            allowed,
            requests_remaining: bucket.tokens as u32,
            reset_time,
            retry_after: if allowed { None } else { Some(Duration::from_secs(60)) },
            current_requests: (bucket.capacity - bucket.tokens) as u32,
            window_start: now,
        })
    }

    /// Implémentation de la fenêtre glissante (Sliding Window)
    async fn check_sliding_window(&self, key: &RateLimitKey, config: &EndpointRateLimit) -> Result<RateLimitInfo> {
        let window_key = key.to_redis_key();
        let now = SystemTime::now();
        let window_duration = Duration::from_secs(60); // 1 minute

        // Utiliser uniquement l'implémentation en mémoire locale
        self.check_sliding_window_memory(&window_key, config, now, window_duration).await
    }

    async fn check_sliding_window_memory(
        &self,
        key: &str,
        config: &EndpointRateLimit,
        now: SystemTime,
        window_duration: Duration,
    ) -> Result<RateLimitInfo> {
        let mut windows = self.sliding_windows.write();
        
        let window = windows.entry(key.to_string()).or_insert_with(|| SlidingWindowCounter {
            requests: Vec::new(),
            window_duration,
        });

        // Nettoyer les anciennes requêtes
        let window_start = now - window_duration;
        window.requests.retain(|record| record.timestamp >= window_start);

        // Compter les requêtes dans la fenêtre
        let current_count: u32 = window.requests.iter().map(|r| r.count).sum();
        let allowed = current_count < config.requests_per_minute;

        if allowed {
            window.requests.push(RequestRecord {
                timestamp: now,
                count: 1,
            });
        }

        let remaining = config.requests_per_minute.saturating_sub(current_count + if allowed { 1 } else { 0 });

        Ok(RateLimitInfo {
            allowed,
            requests_remaining: remaining,
            reset_time: window_start + window_duration,
            retry_after: if allowed { None } else { Some(Duration::from_secs(60)) },
            current_requests: current_count + if allowed { 1 } else { 0 },
            window_start,
        })
    }

    /// Implémentation de la fenêtre fixe (Fixed Window)
    #[allow(dead_code)]
    async fn _check_fixed_window(&self, key: &RateLimitKey, config: &EndpointRateLimit) -> Result<RateLimitInfo> {
        // Utiliser les limiteurs Governor en mémoire pour la fenêtre fixe
        let endpoint_key = self._normalize_endpoint(&key.endpoint);
        
        if let Some(limiter) = self.in_memory_limiters.read().get(&endpoint_key) {
            match limiter.check() {
                Ok(_) => {
                    debug!("Rate limit passed for endpoint: {}", endpoint_key);
                    Ok(RateLimitInfo {
                        allowed: true,
                        requests_remaining: config.requests_per_minute.saturating_sub(1),
                        reset_time: SystemTime::now() + Duration::from_secs(60),
                        retry_after: None,
                        current_requests: 1,
                        window_start: SystemTime::now(),
                    })
                }
                Err(_) => {
                    warn!("Rate limit exceeded for endpoint: {}", endpoint_key);
                    Ok(RateLimitInfo {
                        allowed: false,
                        requests_remaining: 0,
                        reset_time: SystemTime::now() + Duration::from_secs(60),
                        retry_after: Some(Duration::from_secs(60)),
                        current_requests: config.requests_per_minute,
                        window_start: SystemTime::now(),
                    })
                }
            }
        } else {
            // Endpoint non configuré, permettre par défaut
            warn!("No rate limit configuration found for endpoint: {}", endpoint_key);
            Ok(RateLimitInfo {
                allowed: true,
                requests_remaining: u32::MAX,
                reset_time: SystemTime::now() + Duration::from_secs(3600),
                retry_after: None,
                current_requests: 0,
                window_start: SystemTime::now(),
            })
        }
    }

    /// Implémentation du seau percé (Leaky Bucket)
    #[allow(dead_code)]
    async fn _check_leaky_bucket(&self, key: &RateLimitKey, config: &EndpointRateLimit) -> Result<RateLimitInfo> {
        // Pour simplifier, utilisons l'implémentation Token Bucket
        // Dans un vrai système, on implémenterait une queue avec fuite constante
        self.check_token_bucket(key, config).await
    }

    /// Obtient la configuration de limite pour un endpoint
    #[allow(dead_code)]
    fn _get_endpoint_limit(&self, endpoint: &str) -> Result<&EndpointRateLimit> {
        // Chercher une correspondance exacte
        if let Some(config) = self.config.endpoint_limits.get(endpoint) {
            return Ok(config);
        }

        // Chercher une correspondance avec wildcard
        for (pattern, config) in &self.config.endpoint_limits {
            if pattern.ends_with("*") {
                let prefix = &pattern[..pattern.len() - 1];
                if endpoint.starts_with(prefix) {
                    return Ok(config);
                }
            }
        }

        // Configuration par défaut
        self.config.endpoint_limits.get("/api/*")
            .context("No rate limit configuration found and no default available")
    }

    /// Normalise l'endpoint pour la recherche de configuration
    #[allow(dead_code)]
    fn _normalize_endpoint(&self, endpoint: &str) -> String {
        // Chercher une correspondance exacte d'abord
        if self.config.endpoint_limits.contains_key(endpoint) {
            return endpoint.to_string();
        }

        // Chercher des patterns avec wildcard
        for pattern in self.config.endpoint_limits.keys() {
            if pattern.ends_with("*") {
                let prefix = &pattern[..pattern.len() - 1];
                if endpoint.starts_with(prefix) {
                    return pattern.clone();
                }
            }
        }

        // Fallback vers le pattern générique
        "/api/*".to_string()
    }

    /// Vérifie si une IP est exemptée du rate limiting
    #[allow(dead_code)]
    fn _is_ip_exempted(&self, ip: IpAddr) -> bool {
        self.exempted_ips.iter().any(|network| network.contains(ip))
    }

    /// Enregistre une violation de rate limiting pour analyse
    pub async fn log_violation(&self, key: &RateLimitKey, _info: &RateLimitInfo) -> Result<()> {
        warn!("Rate limit violation detected: {:?}", key);

        // Log local uniquement sans Valkey
        debug!("Violation logged for key: {}", key.to_redis_key());

        Ok(())
    }

    /// Nettoie les données expirées (maintenance)
    pub async fn cleanup_expired_data(&self) -> Result<()> {
        info!("Cleaning up expired rate limiting data");

        // Nettoyer les données en mémoire
        let now = SystemTime::now();
        
        {
            let mut windows = self.sliding_windows.write();
            for (key, window) in windows.iter_mut() {
                let window_start = now - window.window_duration;
                let old_len = window.requests.len();
                window.requests.retain(|record| record.timestamp >= window_start);
                if window.requests.len() != old_len {
                    debug!("Cleaned {} expired requests for key: {}", old_len - window.requests.len(), key);
                }
            }
        }

        // Valkey se charge automatiquement du nettoyage avec les TTL
        debug!("Rate limiting cleanup completed");
        Ok(())
    }

    /// Retourne des statistiques sur l'utilisation
    pub async fn get_statistics(&self) -> Result<serde_json::Value> {
        let mut stats = serde_json::Map::new();
        
        stats.insert("algorithm".to_string(), serde_json::Value::String(format!("{:?}", self.config.algorithm)));
        stats.insert("valkey_enabled".to_string(), serde_json::Value::Bool(false)); // Pas de Valkey dans cette version
        stats.insert("in_memory_limiters".to_string(), serde_json::Value::Number(self.in_memory_limiters.read().len().into()));
        stats.insert("sliding_windows".to_string(), serde_json::Value::Number(self.sliding_windows.read().len().into()));
        stats.insert("token_buckets".to_string(), serde_json::Value::Number(self.token_buckets.read().len().into()));
        stats.insert("exempted_ips".to_string(), serde_json::Value::Number(self.exempted_ips.len().into()));

        // Statistiques des endpoints configurés
        let mut endpoint_stats = serde_json::Map::new();
        for (endpoint, config) in &self.config.endpoint_limits {
            endpoint_stats.insert(endpoint.clone(), serde_json::json!({
                "requests_per_minute": config.requests_per_minute,
                "requests_per_hour": config.requests_per_hour,
                "burst_capacity": config.burst_capacity,
            }));
        }
        stats.insert("endpoint_configurations".to_string(), serde_json::Value::Object(endpoint_stats));

        Ok(serde_json::Value::Object(stats))
    }
}

/// Middleware Actix-Web pour le rate limiting
pub async fn rate_limit_middleware(
    req: ServiceRequest,
    manager: web::Data<Arc<RateLimitManager>>,
) -> Result<ServiceResponse, Error> {
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .parse::<IpAddr>()
        .unwrap_or_else(|_| "127.0.0.1".parse().expect("Checked operation"));

    let endpoint = req.path();
    let method = req.method().as_str();
    
    let key = RateLimitKey::from_ip_endpoint(client_ip, endpoint, method);
    
    match manager.check_rate_limit(&key).await {
        Ok(info) => {
            if info.allowed {
                // Ajouter les headers de rate limiting
                let mut response = req.into_response(HttpResponse::Ok().finish());
                let headers = response.headers_mut();
                headers.insert(
                    actix_web::http::header::HeaderName::from_static("x-ratelimit-remaining"),
                    actix_web::http::header::HeaderValue::from(info.requests_remaining),
                );
                
                if let Ok(reset_time) = info.reset_time.duration_since(UNIX_EPOCH) {
                    headers.insert(
                        actix_web::http::header::HeaderName::from_static("x-ratelimit-reset"),
                        actix_web::http::header::HeaderValue::from(reset_time.as_secs()),
                    );
                }

                Ok(response)
            } else {
                // Enregistrer la violation
                if let Err(e) = manager.log_violation(&key, &info).await {
                    error!("Failed to record rate limit violation: {}", e);
                }

                // Retourner 429 Too Many Requests
                let mut response_builder = HttpResponse::TooManyRequests();
                
                response_builder.insert_header(("X-RateLimit-Remaining", "0"));
                
                if let Ok(reset_time) = info.reset_time.duration_since(UNIX_EPOCH) {
                    response_builder.insert_header(("X-RateLimit-Reset", reset_time.as_secs().to_string()));
                }
                
                if let Some(retry_after) = info.retry_after {
                    response_builder.insert_header(("Retry-After", retry_after.as_secs().to_string()));
                }

                let response = response_builder.json(serde_json::json!({
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": info.retry_after.map(|d| d.as_secs()),
                }));

                Ok(req.into_response(response))
            }
        }
        Err(e) => {
            error!("Rate limiting check failed: {}", e);
            // En cas d'erreur, laisser passer la requête mais logger l'erreur
            Ok(req.into_response(HttpResponse::Ok().finish()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_rate_limit_manager_creation() {
        let config = RateLimitConfig {
            endpoint_limits: HashMap::new(),
            valkey_config: None,
            algorithm: RateLimitAlgorithm::TokenBucket,
            ip_exemptions: vec![],
        };

        let _manager = RateLimitManager::new(config).await.expect("Checked operation");
        // Manager created successfully
    }

    #[tokio::test]
    async fn test_token_bucket_memory() {
        let mut config = RateLimitConfig {
            endpoint_limits: HashMap::new(),
            valkey_config: None,
            algorithm: RateLimitAlgorithm::TokenBucket,
            ip_exemptions: vec![],
        };

        config.endpoint_limits.insert("/test".to_string(), EndpointRateLimit {
            requests_per_minute: 10,
            requests_per_hour: 100,
            requests_per_day: 1000,
            burst_capacity: 5,
        });

        let manager = RateLimitManager::new(config).await.expect("Checked operation");
        let key = RateLimitKey::from_ip_endpoint("127.0.0.1".parse().expect("Checked operation"), "/test", "GET");

        // Première requête devrait passer
        let info = manager.check_rate_limit(&key).await.expect("Checked operation");
        assert!(info.allowed);
        assert!(info.requests_remaining < 5);
    }

    #[test]
    fn test_rate_limit_key_creation() {
        let ip: IpAddr = "127.0.0.1".parse().expect("Checked operation");
        let key = RateLimitKey::from_ip_endpoint(ip, "/api/test", "POST");
        
        assert_eq!(key.identifier, "127.0.0.1");
        assert_eq!(key.endpoint, "/api/test");
        assert_eq!(key.method, "POST");
    }

    #[test]
    fn test_redis_key_generation() {
        let key = RateLimitKey {
            identifier: "user:123".to_string(),
            endpoint: "/api/data".to_string(),
            method: "GET".to_string(),
        };

        let redis_key = key.to_redis_key();
        assert_eq!(redis_key, "rate_limit:user:123:/api/data:GET");
    }
}
