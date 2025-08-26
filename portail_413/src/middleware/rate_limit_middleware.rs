use actix_web::HttpRequest;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct RateLimiter {
    // IP -> (count, window_start)
    requests: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    max_requests: u32,
    window_duration: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_duration,
        }
    }

    pub fn is_allowed(&self, ip: &str) -> bool {
        let mut requests = match self.requests.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("Rate limiter mutex was poisoned, recovering");
                poisoned.into_inner()
            }
        };
        let now = Instant::now();

        match requests.get_mut(ip) {
            Some((count, window_start)) => {
                // Vérifier si la fenêtre a expiré
                if now.duration_since(*window_start) > self.window_duration {
                    // Nouvelle fenêtre
                    *count = 1;
                    *window_start = now;
                    true
                } else if *count >= self.max_requests {
                    // Limite atteinte
                    false
                } else {
                    // Incrémenter le compteur
                    *count += 1;
                    true
                }
            }
            None => {
                // Première requête pour cette IP
                requests.insert(ip.to_string(), (1, now));
                true
            }
        }
    }

    pub fn cleanup_expired(&self) {
        let mut requests = match self.requests.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("Rate limiter mutex was poisoned during cleanup, recovering");
                poisoned.into_inner()
            }
        };
        let now = Instant::now();
        
        requests.retain(|_, (_, window_start)| {
            now.duration_since(*window_start) <= self.window_duration
        });
    }
}

// Rate limiter global pour les requêtes générales
pub fn create_general_rate_limiter() -> RateLimiter {
    RateLimiter::new(100, Duration::from_secs(60)) // 100 requêtes par minute
}

// Rate limiter strict pour l'authentification
pub fn create_auth_rate_limiter() -> RateLimiter {
    RateLimiter::new(5, Duration::from_secs(300)) // 5 tentatives par 5 minutes
}

// Rate limiter pour les endpoints publics
pub fn create_public_rate_limiter() -> RateLimiter {
    RateLimiter::new(20, Duration::from_secs(60)) // 20 requêtes par minute
}

// Fonction utilitaire pour extraire l'IP d'une requête
pub fn extract_client_ip(req: &HttpRequest) -> String {
    // Essayer d'obtenir l'IP réelle depuis les headers de proxy
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }
    
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }
    
    // Fallback vers l'IP de connexion
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string()
}

// Fonction simple de vérification de rate limit
pub fn check_rate_limit(ip: &str, rate_limiter: &RateLimiter) -> bool {
    rate_limiter.is_allowed(ip)
}

// Structure pour le monitoring des rate limits
#[derive(Clone)]
pub struct RateLimitMonitor {
    limiters: HashMap<String, RateLimiter>,
}

impl RateLimitMonitor {
    pub fn new() -> Self {
        let mut limiters = HashMap::new();
        
        limiters.insert("general".to_string(), create_general_rate_limiter());
        limiters.insert("auth".to_string(), create_auth_rate_limiter());
        limiters.insert("public".to_string(), create_public_rate_limiter());
        
        Self { limiters }
    }

    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "rate_limiters": {
                "general": {
                    "max_requests": 100,
                    "window_seconds": 60,
                    "description": "General API endpoints"
                },
                "auth": {
                    "max_requests": 5,
                    "window_seconds": 300,
                    "description": "Authentication endpoints"
                },
                "public": {
                    "max_requests": 20,
                    "window_seconds": 60,
                    "description": "Public endpoints"
                }
            },
            "timestamp": chrono::Utc::now()
        })
    }

    pub fn cleanup_all(&self) {
        for limiter in self.limiters.values() {
            limiter.cleanup_expired();
        }
    }
}

impl Default for RateLimitMonitor {
    fn default() -> Self {
        Self::new()
    }
}
