use actix_web::{dev::ServiceRequest, HttpRequest};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::errors::{AppError, Result};
use crate::security::{SecurityLogger, SecurityEventType, SecuritySeverity};

/// Service de limitation de débit (rate limiting) distribué conforme OWASP
#[derive(Clone)]
pub struct RateLimitingService {
    limits: Arc<Mutex<HashMap<String, RateLimitConfig>>>,
    counters: Arc<Mutex<HashMap<String, RateLimitCounter>>>,
    global_config: GlobalRateLimitConfig,
    security_logger: SecurityLogger,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_duration: Duration,
    pub burst_allowance: u32,
    pub block_duration: Duration,
}

#[derive(Debug, Clone)]
pub struct GlobalRateLimitConfig {
    pub enable_captcha_after_failures: u32,
    pub progressive_delays: bool,
    pub whitelist_ips: Vec<IpAddr>,
    pub blacklist_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
struct RateLimitCounter {
    requests: Vec<DateTime<Utc>>,
    blocked_until: Option<DateTime<Utc>>,
    failure_count: u32,
    last_request: DateTime<Utc>,
}

#[derive(Debug)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub reset_time: DateTime<Utc>,
    pub retry_after: Option<Duration>,
    pub requires_captcha: bool,
}

impl RateLimitingService {
    /// Crée un nouveau service de rate limiting
    pub fn new(global_config: GlobalRateLimitConfig) -> Self {
        let mut limits = HashMap::new();

        // Configuration par défaut pour différents endpoints
        limits.insert("login".to_string(), RateLimitConfig {
            max_requests: 3,
            window_duration: Duration::minutes(5),
            burst_allowance: 1,
            block_duration: Duration::minutes(15),
        });

        limits.insert("api_general".to_string(), RateLimitConfig {
            max_requests: 100,
            window_duration: Duration::minutes(1),
            burst_allowance: 20,
            block_duration: Duration::minutes(1),
        });

        limits.insert("password_reset".to_string(), RateLimitConfig {
            max_requests: 3,
            window_duration: Duration::hours(1),
            burst_allowance: 0,
            block_duration: Duration::hours(1),
        });

        limits.insert("file_upload".to_string(), RateLimitConfig {
            max_requests: 10,
            window_duration: Duration::minutes(10),
            burst_allowance: 2,
            block_duration: Duration::minutes(5),
        });

        Self {
            limits: Arc::new(Mutex::new(limits)),
            counters: Arc::new(Mutex::new(HashMap::new())),
            global_config,
            security_logger: SecurityLogger::new(true), // Alertes temps réel activées
        }
    }

    /// Vérifie si une requête est autorisée selon les limites de débit
    pub fn check_rate_limit(
        &self,
        identifier: &str,
        endpoint_type: &str,
        ip_address: Option<IpAddr>,
    ) -> Result<RateLimitResult> {
        // Vérifier la whitelist/blacklist IP
        if let Some(ip) = ip_address {
            if self.global_config.blacklist_ips.contains(&ip) {
                return Ok(RateLimitResult {
                    allowed: false,
                    remaining: 0,
                    reset_time: Utc::now() + Duration::hours(24),
                    retry_after: Some(Duration::hours(24)),
                    requires_captcha: false,
                });
            }

            if self.global_config.whitelist_ips.contains(&ip) {
                return Ok(RateLimitResult {
                    allowed: true,
                    remaining: u32::MAX,
                    reset_time: Utc::now() + Duration::hours(1),
                    retry_after: None,
                    requires_captcha: false,
                });
            }
        }

        let limits = self.limits.lock()
            .map_err(|_| AppError::Internal("Failed to acquire limits lock".to_string()))?;

        let config = limits.get(endpoint_type)
            .or_else(|| limits.get("api_general"))
            .ok_or_else(|| AppError::Internal("No rate limit config found".to_string()))?
            .clone();

        drop(limits);

        let mut counters = self.counters.lock()
            .map_err(|_| AppError::Internal("Failed to acquire counters lock".to_string()))?;

        let now = Utc::now();
        let counter_key = format!("{}:{}", endpoint_type, identifier);

        let counter = counters.entry(counter_key.clone()).or_insert_with(|| RateLimitCounter {
            requests: Vec::new(),
            blocked_until: None,
            failure_count: 0,
            last_request: now,
        });

        // Vérifier si l'utilisateur est actuellement bloqué
        if let Some(blocked_until) = counter.blocked_until {
            if now < blocked_until {
                // Log de sécurité pour tentative pendant blocage
                if counter.failure_count >= 3 {
                    self.security_logger.log_security_event(
                        SecurityEventType::SuspiciousActivity,
                        SecuritySeverity::High,
                        None, // user_id
                        Some(identifier.to_string()), // ip_address
                        None, // user_agent
                        format!("Persistent attempts during rate limit block on {}: {} failures",
                               endpoint_type, counter.failure_count),
                        Some("blocked_attempts".to_string()), // context
                        None, // request_id
                    ).unwrap_or_else(|e| {
                        tracing::error!("Failed to log security event: {}", e);
                    });
                }

                let retry_after = blocked_until - now;
                return Ok(RateLimitResult {
                    allowed: false,
                    remaining: 0,
                    reset_time: blocked_until,
                    retry_after: Some(retry_after),
                    requires_captcha: counter.failure_count >= self.global_config.enable_captcha_after_failures,
                });
            } else {
                // Le blocage a expiré, réinitialiser
                counter.blocked_until = None;
                counter.failure_count = 0;
            }
        }

        // Nettoyer les anciennes requêtes hors de la fenêtre
        let window_start = now - config.window_duration;
        counter.requests.retain(|&req_time| req_time > window_start);

        // Calculer les requêtes restantes
        let current_requests = counter.requests.len() as u32;
        let max_allowed = config.max_requests + config.burst_allowance;

        if current_requests >= max_allowed {
            // Limite dépassée, bloquer l'utilisateur
            counter.blocked_until = Some(now + config.block_duration);
            counter.failure_count += 1;

            // Délais progressifs si activés
            let block_duration = if self.global_config.progressive_delays {
                config.block_duration * (counter.failure_count as i32).min(10)
            } else {
                config.block_duration
            };

            counter.blocked_until = Some(now + block_duration);

            // Log de sécurité pour dépassement de limite
            let severity = if counter.failure_count >= 5 {
                SecuritySeverity::High // Attaque potentielle
            } else {
                SecuritySeverity::Medium
            };

            self.security_logger.log_security_event(
                SecurityEventType::RateLimitExceeded,
                severity,
                None, // user_id
                Some(identifier.to_string()), // ip_address
                None, // user_agent
                format!("Rate limit exceeded on {}: {} requests in window (attempt {}/{})",
                       endpoint_type, current_requests, counter.failure_count, max_allowed),
                Some(format!("endpoint_{}", endpoint_type)), // context
                None, // request_id
            ).unwrap_or_else(|e| {
                tracing::error!("Failed to log security event: {}", e);
            });

            tracing::warn!(
                "Rate limit exceeded for {} on endpoint {}: {} requests in window (blocked for {:?})",
                identifier, endpoint_type, current_requests, block_duration
            );

            return Ok(RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_time: now + config.window_duration,
                retry_after: Some(block_duration),
                requires_captcha: counter.failure_count >= self.global_config.enable_captcha_after_failures,
            });
        }

        // Ajouter la requête actuelle
        counter.requests.push(now);
        counter.last_request = now;

        let remaining = max_allowed - (current_requests + 1);
        let reset_time = window_start + config.window_duration;

        Ok(RateLimitResult {
            allowed: true,
            remaining,
            reset_time,
            retry_after: None,
            requires_captcha: false,
        })
    }

    /// Extrait l'identifiant pour le rate limiting depuis une requête
    pub fn extract_identifier(&self, req: &HttpRequest, user_id: Option<Uuid>) -> String {
        // Priorité : User ID > IP Address > User-Agent hash
        if let Some(uid) = user_id {
            return format!("user:{}", uid);
        }

        if let Some(ip) = req.connection_info().realip_remote_addr() {
            return format!("ip:{}", ip);
        }

        if let Some(user_agent) = req.headers().get("User-Agent") {
            if let Ok(ua_str) = user_agent.to_str() {
                let ua_hash = format!("{:x}", md5::compute(ua_str.as_bytes()));
                return format!("ua:{}", ua_hash);
            }
        }

        "anonymous".to_string()
    }

    /// Détermine le type d'endpoint depuis le chemin de la requête
    pub fn determine_endpoint_type(&self, path: &str) -> String {
        if path.contains("/auth/login") || path.contains("/auth/signin") {
            "login".to_string()
        } else if path.contains("/auth/reset-password") {
            "password_reset".to_string()
        } else if path.contains("/upload") || path.contains("/photo") {
            "file_upload".to_string()
        } else {
            "api_general".to_string()
        }
    }

    /// Ajoute une IP à la whitelist
    pub fn add_to_whitelist(&mut self, ip: IpAddr) {
        if !self.global_config.whitelist_ips.contains(&ip) {
            self.global_config.whitelist_ips.push(ip);
            tracing::info!("Added IP {} to whitelist", ip);
        }
    }

    /// Ajoute une IP à la blacklist
    pub fn add_to_blacklist(&mut self, ip: IpAddr) {
        if !self.global_config.blacklist_ips.contains(&ip) {
            self.global_config.blacklist_ips.push(ip);
            tracing::warn!("Added IP {} to blacklist", ip);
        }
    }

    /// Nettoie les anciens compteurs
    pub fn cleanup_old_counters(&self) -> Result<usize> {
        let mut counters = self.counters.lock()
            .map_err(|_| AppError::Internal("Failed to acquire counters lock".to_string()))?;

        let cutoff_time = Utc::now() - Duration::hours(24);
        let initial_count = counters.len();

        counters.retain(|_, counter| {
            counter.last_request > cutoff_time || 
            counter.blocked_until.map_or(false, |blocked| blocked > Utc::now())
        });

        let cleaned_count = initial_count - counters.len();
        
        if cleaned_count > 0 {
            tracing::info!("Cleaned up {} old rate limit counters", cleaned_count);
        }

        Ok(cleaned_count)
    }

    /// Obtient les statistiques du rate limiting
    pub fn get_rate_limit_stats(&self) -> Result<RateLimitStats> {
        let counters = self.counters.lock()
            .map_err(|_| AppError::Internal("Failed to acquire counters lock".to_string()))?;

        let total_identifiers = counters.len();
        let blocked_identifiers = counters.values()
            .filter(|c| c.blocked_until.map_or(false, |blocked| blocked > Utc::now()))
            .count();
        let active_identifiers = counters.values()
            .filter(|c| !c.requests.is_empty())
            .count();

        Ok(RateLimitStats {
            total_identifiers,
            blocked_identifiers,
            active_identifiers,
            whitelist_size: self.global_config.whitelist_ips.len(),
            blacklist_size: self.global_config.blacklist_ips.len(),
        })
    }
}

#[derive(Debug, serde::Serialize)]
pub struct RateLimitStats {
    pub total_identifiers: usize,
    pub blocked_identifiers: usize,
    pub active_identifiers: usize,
    pub whitelist_size: usize,
    pub blacklist_size: usize,
}

/// Middleware de rate limiting
pub struct RateLimitMiddleware {
    service: RateLimitingService,
}

impl RateLimitMiddleware {
    pub fn new(service: RateLimitingService) -> Self {
        Self { service }
    }

    /// Vérifie le rate limiting pour une requête
    pub fn check_request(&self, req: &ServiceRequest, user_id: Option<Uuid>) -> Result<RateLimitResult> {
        let identifier = self.service.extract_identifier(req.request(), user_id);
        let endpoint_type = self.service.determine_endpoint_type(req.path());
        let ip_address = req.connection_info()
            .realip_remote_addr()
            .and_then(|ip_str| ip_str.parse().ok());

        self.service.check_rate_limit(&identifier, &endpoint_type, ip_address)
    }
}

impl Default for GlobalRateLimitConfig {
    fn default() -> Self {
        Self {
            enable_captcha_after_failures: 3,
            progressive_delays: true,
            whitelist_ips: vec![
                "127.0.0.1".parse().expect("Checked operation"),
                "::1".parse().expect("Checked operation"),
            ],
            blacklist_ips: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiting_basic() {
        let config = GlobalRateLimitConfig::default();
        let service = RateLimitingService::new(config);

        // Configuration d'une limite pour les tests
        let limit_config = RateLimitConfig {
            max_requests: 3,
            window_duration: Duration::seconds(60),
            burst_allowance: 1,
            block_duration: Duration::seconds(300),
        };

        // Ajouter la limite directement dans le service
        {
            let mut limits = service.limits.lock().expect("Checked operation");
            limits.insert("login".to_string(), limit_config);
        }

        // Première requête devrait être autorisée
        let result = service.check_rate_limit("test_user", "login", None).expect("Checked operation");
        assert!(result.allowed);

        // Deuxième requête devrait être autorisée
        let result = service.check_rate_limit("test_user", "login", None).expect("Checked operation");
        assert!(result.allowed);

        // Troisième requête devrait être autorisée
        let result = service.check_rate_limit("test_user", "login", None).expect("Checked operation");
        assert!(result.allowed);

        // Quatrième requête devrait être autorisée (burst)
        let result = service.check_rate_limit("test_user", "login", None).expect("Checked operation");
        assert!(result.allowed);

        // Cinquième requête devrait être bloquée
        let result = service.check_rate_limit("test_user", "login", None).expect("Checked operation");
        assert!(!result.allowed);
        assert!(result.retry_after.is_some());
    }

    #[test]
    fn test_whitelist_bypass() {
        let mut config = GlobalRateLimitConfig::default();
        let whitelist_ip: IpAddr = "127.0.0.1".parse().expect("Checked operation");
        config.whitelist_ips.push(whitelist_ip);
        
        let service = RateLimitingService::new(config);
        
        // Les IPs en whitelist devraient toujours être autorisées
        for _ in 0..100 {
            let result = service.check_rate_limit("test_user", "login", Some(whitelist_ip)).expect("Checked operation");
            assert!(result.allowed);
        }
    }

    #[test]
    fn test_blacklist_block() {
        let mut config = GlobalRateLimitConfig::default();
        let blacklist_ip: IpAddr = "127.0.0.1".parse().expect("Checked operation");
        config.blacklist_ips.push(blacklist_ip);
        
        let service = RateLimitingService::new(config);
        
        // Les IPs en blacklist devraient toujours être bloquées
        let result = service.check_rate_limit("test_user", "login", Some(blacklist_ip)).expect("Checked operation");
        assert!(!result.allowed);
    }
}
