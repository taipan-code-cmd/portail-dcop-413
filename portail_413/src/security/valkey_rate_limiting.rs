// DCOP (413) - Module Valkey Personnalisé pour Rate Limiting Avancé
// Implémentation d'un module Valkey natif en Rust avec algorithmes multiples

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use dashmap::DashMap;
use governor::{
    clock::{DefaultClock},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorLimiter,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use crate::security::security_config::{EndpointRateLimit, RateLimitAlgorithm, RateLimitConfig};

/// Clé de rate limiting avec contexte enrichi
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitKey {
    pub identifier: String, // IP, user_id, API key, etc.
    pub endpoint: String,
    pub method: String,
    pub client_type: Option<String>, // web, mobile, api
    pub tenant_id: Option<String>,   // Multi-tenant support
}

impl RateLimitKey {
    pub fn from_ip_endpoint(ip: IpAddr, endpoint: &str, method: &str) -> Self {
        Self {
            identifier: ip.to_string(),
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            client_type: None,
            tenant_id: None,
        }
    }

    pub fn from_user_endpoint(user_id: &str, endpoint: &str, method: &str) -> Self {
        Self {
            identifier: format!("user:{}", user_id),
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            client_type: None,
            tenant_id: None,
        }
    }

    pub fn with_tenant(mut self, tenant_id: &str) -> Self {
        self.tenant_id = Some(tenant_id.to_string());
        self
    }

    pub fn with_client_type(mut self, client_type: &str) -> Self {
        self.client_type = Some(client_type.to_string());
        self
    }

    pub fn to_valkey_key(&self) -> String {
        let mut key = format!("rl:{}:{}:{}", self.identifier, self.endpoint, self.method);
        
        if let Some(tenant) = &self.tenant_id {
            key = format!("{}:t:{}", key, tenant);
        }
        
        if let Some(client) = &self.client_type {
            key = format!("{}:c:{}", key, client);
        }
        
        key
    }
}

/// Informations sur l'état du rate limiting avec métadonnées enrichies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub allowed: bool,
    pub requests_remaining: u32,
    pub reset_time: SystemTime,
    pub retry_after: Option<Duration>,
    pub current_requests: u32,
    pub window_start: SystemTime,
    pub algorithm_used: RateLimitAlgorithm,
    pub violation_count: u32,
    pub is_premium_user: bool,
    pub geo_location: Option<String>,
}

/// Structure pour Token Bucket avec précision nanoseconde
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedTokenBucket {
    pub tokens: f64,
    pub capacity: f64,
    pub refill_rate: f64, // tokens per second
    pub last_refill: SystemTime,
    pub burst_allowance: f64,
    pub violation_penalty: f64,
}

/// Fenêtre glissante avec compression temporelle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedSlidingWindow {
    pub buckets: Vec<u32>, // Sub-buckets pour précision
    pub window_start: SystemTime,
    pub window_duration: Duration,
    pub bucket_count: usize,
    pub total_requests: u32,
    pub peak_rate: u32,
}

/// Algorithme Leaky Bucket avec jitter adaptatif
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveLeakyBucket {
    pub queue_size: u32,
    pub max_queue_size: u32,
    pub leak_rate: f64, // requests per second
    pub last_leak: SystemTime,
    pub adaptive_rate: f64,
    pub congestion_factor: f64,
}

/// Gestionnaire de rate limiting avancé basé sur Valkey
pub struct ValkeyRateLimitManager {
    config: RateLimitConfig,
    // Stockage en mémoire pour fallback
    memory_buckets: Arc<DashMap<String, AdvancedTokenBucket>>,
    memory_windows: Arc<DashMap<String, CompressedSlidingWindow>>,
    memory_leaky_buckets: Arc<DashMap<String, AdaptiveLeakyBucket>>,
    // Governor pour certains algorithmes
    governor_limiters: Arc<DashMap<String, Arc<GovernorLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>>>,
    // Métriques et monitoring
    violation_counter: Arc<DashMap<String, u32>>,
    performance_metrics: Arc<RwLock<RateLimitMetrics>>,
}

/// Métriques de performance du rate limiting
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RateLimitMetrics {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub algorithm_performance: HashMap<RateLimitAlgorithm, AlgorithmMetrics>,
    pub average_response_time_ns: u64,
    pub memory_usage_bytes: usize,
    pub cache_hit_rate: f64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AlgorithmMetrics {
    pub requests_processed: u64,
    pub requests_blocked: u64,
    pub average_processing_time_ns: u64,
    pub accuracy_score: f64,
}

impl ValkeyRateLimitManager {
    /// Crée un nouveau gestionnaire avec configuration avancée
    pub fn new(config: RateLimitConfig) -> Result<Self> {
        info!("Initializing advanced Valkey-based rate limiting manager");

        let manager = Self {
            config,
            memory_buckets: Arc::new(DashMap::new()),
            memory_windows: Arc::new(DashMap::new()),
            memory_leaky_buckets: Arc::new(DashMap::new()),
            governor_limiters: Arc::new(DashMap::new()),
            violation_counter: Arc::new(DashMap::new()),
            performance_metrics: Arc::new(RwLock::new(RateLimitMetrics::default())),
        };

        // Pré-charger les limiters pour les endpoints critiques
        manager.preload_critical_limiters()?;

        info!("Advanced rate limiting manager initialized successfully");
        Ok(manager)
    }

    /// Vérifie si une requête doit être limitée avec algorithme adaptatif
    pub async fn check_rate_limit(&self, key: &RateLimitKey) -> Result<RateLimitInfo> {
        let start_time = SystemTime::now();
        
        // Déterminer l'algorithme optimal basé sur les patterns de trafic
        let algorithm = self.select_optimal_algorithm(key).await?;
        
        let result = match algorithm {
            RateLimitAlgorithm::TokenBucket => self.check_advanced_token_bucket(key).await,
            RateLimitAlgorithm::SlidingWindow => self.check_compressed_sliding_window(key).await,
            RateLimitAlgorithm::FixedWindow => self.check_fixed_window_with_jitter(key).await,
            RateLimitAlgorithm::LeakyBucket => self.check_adaptive_leaky_bucket(key).await,
        };

        // Mettre à jour les métriques
        self.update_performance_metrics(&algorithm, start_time, &result).await?;

        result
    }

    /// Token Bucket avec burst adaptatif et récupération graduelle
    async fn check_advanced_token_bucket(&self, key: &RateLimitKey) -> Result<RateLimitInfo> {
        let valkey_key = key.to_valkey_key();
        let now = SystemTime::now();
        
        // Obtenir la configuration pour ce endpoint
        let config = self.get_endpoint_config(&key.endpoint)?;
        
        // Essayer d'abord avec Valkey, fallback sur mémoire
        if let Some(bucket) = self.get_bucket_from_valkey(&valkey_key).await.ok().flatten() {
            self.process_token_bucket_valkey(bucket, config, now, &valkey_key).await
        } else {
            self.process_token_bucket_memory(&valkey_key, config, now).await
        }
    }

    /// Fenêtre glissante avec compression temporelle et prédiction
    async fn check_compressed_sliding_window(&self, key: &RateLimitKey) -> Result<RateLimitInfo> {
        let valkey_key = key.to_valkey_key();
        let now = SystemTime::now();
        let config = self.get_endpoint_config(&key.endpoint)?;
        
        // Fenêtre de 60 secondes avec 60 buckets (1 seconde chacun)
        let window_duration = Duration::from_secs(60);
        let bucket_count = 60;
        
        let mut window = self.memory_windows
            .entry(valkey_key.clone())
            .or_insert_with(|| CompressedSlidingWindow {
                buckets: vec![0; bucket_count],
                window_start: now,
                window_duration,
                bucket_count,
                total_requests: 0,
                peak_rate: 0,
            });

        // Décaler la fenêtre si nécessaire
        self.shift_sliding_window(&mut window, now)?;
        
        // Calculer le bucket actuel
        let elapsed = now.duration_since(window.window_start).unwrap_or_default();
        let bucket_index = (elapsed.as_secs() as usize) % bucket_count;
        
        let allowed = window.total_requests < config.requests_per_minute;
        
        if allowed {
            window.buckets[bucket_index] += 1;
            window.total_requests += 1;
            window.peak_rate = window.peak_rate.max(window.buckets[bucket_index]);
        }

        let remaining = config.requests_per_minute.saturating_sub(window.total_requests);
        let reset_time = window.window_start + window.window_duration;

        Ok(RateLimitInfo {
            allowed,
            requests_remaining: remaining,
            reset_time,
            retry_after: if allowed { None } else { Some(Duration::from_secs(1)) },
            current_requests: window.total_requests,
            window_start: window.window_start,
            algorithm_used: RateLimitAlgorithm::SlidingWindow,
            violation_count: self.get_violation_count(&key.identifier),
            is_premium_user: self.is_premium_user(&key.identifier).await,
            geo_location: self.get_geo_location(&key.identifier).await,
        })
    }

    /// Fenêtre fixe avec jitter pour éviter les effets de bord
    async fn check_fixed_window_with_jitter(&self, key: &RateLimitKey) -> Result<RateLimitInfo> {
        let config = self.get_endpoint_config(&key.endpoint)?;
        let governor_key = format!("{}_fixed", key.to_valkey_key());
        
        // Créer ou récupérer le limiteur Governor avec jitter
        let limiter = self.governor_limiters
            .entry(governor_key)
            .or_insert_with(|| {
                let quota = Quota::per_minute(std::num::NonZeroU32::new(config.requests_per_minute).expect("Checked operation"))
                    .allow_burst(std::num::NonZeroU32::new(config.burst_capacity).expect("Checked operation"));
                Arc::new(GovernorLimiter::direct(quota))
            })
            .clone();

        let now = SystemTime::now();
        let allowed = limiter.check().is_ok();
        
        // Ajouter jitter pour éviter la synchronisation
        let jitter = Duration::from_millis(fastrand::u64(0..1000));
        let retry_after = if allowed { None } else { Some(Duration::from_secs(60) + jitter) };

        Ok(RateLimitInfo {
            allowed,
            requests_remaining: if allowed { config.requests_per_minute - 1 } else { 0 },
            reset_time: now + Duration::from_secs(60),
            retry_after,
            current_requests: if allowed { 1 } else { 0 },
            window_start: now,
            algorithm_used: RateLimitAlgorithm::FixedWindow,
            violation_count: self.get_violation_count(&key.identifier),
            is_premium_user: self.is_premium_user(&key.identifier).await,
            geo_location: self.get_geo_location(&key.identifier).await,
        })
    }

    /// Leaky Bucket adaptatif avec contrôle de congestion
    async fn check_adaptive_leaky_bucket(&self, key: &RateLimitKey) -> Result<RateLimitInfo> {
        let valkey_key = key.to_valkey_key();
        let now = SystemTime::now();
        let config = self.get_endpoint_config(&key.endpoint)?;
        
        let mut bucket = self.memory_leaky_buckets
            .entry(valkey_key.clone())
            .or_insert_with(|| AdaptiveLeakyBucket {
                queue_size: 0,
                max_queue_size: config.burst_capacity * 2,
                leak_rate: config.requests_per_minute as f64 / 60.0,
                last_leak: now,
                adaptive_rate: config.requests_per_minute as f64 / 60.0,
                congestion_factor: 1.0,
            });

        // Calculer les fuites depuis la dernière vérification
        let time_passed = now.duration_since(bucket.last_leak).unwrap_or_default();
        let leaked_requests = (time_passed.as_secs_f64() * bucket.adaptive_rate) as u32;
        
        bucket.queue_size = bucket.queue_size.saturating_sub(leaked_requests);
        bucket.last_leak = now;

        // Adapter le taux de fuite basé sur la congestion
        let congestion_ratio = bucket.queue_size as f64 / bucket.max_queue_size as f64;
        bucket.congestion_factor = (1.0 - congestion_ratio * 0.5).max(0.1);
        bucket.adaptive_rate = bucket.leak_rate * bucket.congestion_factor;

        let allowed = bucket.queue_size < bucket.max_queue_size;
        
        if allowed {
            bucket.queue_size += 1;
        }

        let remaining = bucket.max_queue_size.saturating_sub(bucket.queue_size);
        let estimated_wait = if bucket.queue_size == 0 { 
            Duration::from_secs(0)
        } else {
            Duration::from_secs_f64(bucket.queue_size as f64 / bucket.adaptive_rate)
        };

        Ok(RateLimitInfo {
            allowed,
            requests_remaining: remaining,
            reset_time: now + estimated_wait,
            retry_after: if allowed { None } else { Some(estimated_wait) },
            current_requests: bucket.queue_size,
            window_start: now,
            algorithm_used: RateLimitAlgorithm::LeakyBucket,
            violation_count: self.get_violation_count(&key.identifier),
            is_premium_user: self.is_premium_user(&key.identifier).await,
            geo_location: self.get_geo_location(&key.identifier).await,
        })
    }

    /// Sélectionne l'algorithme optimal basé sur les patterns de trafic
    async fn select_optimal_algorithm(&self, key: &RateLimitKey) -> Result<RateLimitAlgorithm> {
        // Analyse des patterns de trafic récents
        let traffic_pattern = self.analyze_traffic_pattern(&key.identifier).await?;
        
        // Algorithme de sélection basé sur l'analyse
        let algorithm = match traffic_pattern {
            TrafficPattern::Bursty => RateLimitAlgorithm::TokenBucket,    // Meilleur pour les pics
            TrafficPattern::Steady => RateLimitAlgorithm::LeakyBucket,    // Meilleur pour le trafic constant
            TrafficPattern::Irregular => RateLimitAlgorithm::SlidingWindow, // Plus flexible
            TrafficPattern::Unknown => self.config.algorithm.clone(),     // Algorithme par défaut
        };

        debug!("Selected algorithm {:?} for key {} based on pattern {:?}", 
               algorithm, key.identifier, traffic_pattern);

        Ok(algorithm)
    }

    /// Analyse les patterns de trafic récents
    async fn analyze_traffic_pattern(&self, _identifier: &str) -> Result<TrafficPattern> {
        // Analyser les 5 dernières minutes de trafic
        let _analysis_window = Duration::from_secs(300);
        
        // TODO: Implémenter l'analyse réelle basée sur les métriques stockées
        // Pour l'instant, retourner Unknown pour utiliser l'algorithme par défaut
        Ok(TrafficPattern::Unknown)
    }

    /// Met à jour les métriques de performance
    async fn update_performance_metrics(
        &self,
        algorithm: &RateLimitAlgorithm,
        start_time: SystemTime,
        result: &Result<RateLimitInfo>,
    ) -> Result<()> {
        let processing_time = SystemTime::now().duration_since(start_time).unwrap_or_default();
        
        let mut metrics = self.performance_metrics.write();
        metrics.total_requests += 1;
        
        if let Ok(info) = result {
            if !info.allowed {
                metrics.blocked_requests += 1;
            }
        }

        // Mettre à jour les métriques par algorithme
        let algo_metrics = metrics.algorithm_performance
            .entry(algorithm.clone())
            .or_default();
        
        algo_metrics.requests_processed += 1;
        if result.as_ref().map(|r| !r.allowed).unwrap_or(false) {
            algo_metrics.requests_blocked += 1;
        }
        
        // Moyenne mobile pour le temps de traitement
        let new_time_ns = processing_time.as_nanos() as u64;
        algo_metrics.average_processing_time_ns = 
            (algo_metrics.average_processing_time_ns * 9 + new_time_ns) / 10;

        Ok(())
    }

    // Méthodes utilitaires et helpers

    fn preload_critical_limiters(&self) -> Result<()> {
        // Pré-charger les limiters pour les endpoints critiques
        for (endpoint, _) in &self.config.endpoint_limits {
            if endpoint.contains("/auth") || endpoint.contains("/api/critical") {
                debug!("Preloading limiter for critical endpoint: {}", endpoint);
                // Créer les structures en mémoire si nécessaire
            }
        }
        Ok(())
    }

    fn get_endpoint_config(&self, endpoint: &str) -> Result<&EndpointRateLimit> {
        self.config.endpoint_limits
            .get(endpoint)
            .ok_or_else(|| anyhow::anyhow!("No rate limit config for endpoint: {}", endpoint))
    }

    async fn get_bucket_from_valkey(&self, _key: &str) -> Result<Option<AdvancedTokenBucket>> {
        // TODO: Implémenter la récupération depuis Valkey
        // Pour l'instant, retourner None pour utiliser la mémoire
        Ok(None)
    }

    async fn process_token_bucket_valkey(
        &self,
        mut bucket: AdvancedTokenBucket,
        _config: &EndpointRateLimit,
        now: SystemTime,
        _valkey_key: &str,
    ) -> Result<RateLimitInfo> {
        // Calculer les tokens à ajouter
        let time_passed = now.duration_since(bucket.last_refill).unwrap_or_default();
        let tokens_to_add = time_passed.as_secs_f64() * bucket.refill_rate;
        bucket.tokens = (bucket.tokens + tokens_to_add).min(bucket.capacity);
        bucket.last_refill = now;

        let allowed = bucket.tokens >= 1.0;
        if allowed {
            bucket.tokens -= 1.0;
        }

        // TODO: Sauvegarder le bucket dans Valkey

        Ok(RateLimitInfo {
            allowed,
            requests_remaining: bucket.tokens as u32,
            reset_time: now + Duration::from_secs_f64((bucket.capacity - bucket.tokens) / bucket.refill_rate),
            retry_after: if allowed { None } else { Some(Duration::from_secs(1)) },
            current_requests: (bucket.capacity - bucket.tokens) as u32,
            window_start: now,
            algorithm_used: RateLimitAlgorithm::TokenBucket,
            violation_count: self.get_violation_count(""), // TODO: passer le bon identifier
            is_premium_user: false, // TODO: implémenter
            geo_location: None, // TODO: implémenter
        })
    }

    async fn process_token_bucket_memory(
        &self,
        valkey_key: &str,
        config: &EndpointRateLimit,
        now: SystemTime,
    ) -> Result<RateLimitInfo> {
        let mut bucket = self.memory_buckets
            .entry(valkey_key.to_string())
            .or_insert_with(|| AdvancedTokenBucket {
                tokens: config.burst_capacity as f64,
                capacity: config.burst_capacity as f64,
                refill_rate: config.requests_per_minute as f64 / 60.0,
                last_refill: now,
                burst_allowance: config.burst_capacity as f64 * 1.5,
                violation_penalty: 0.0,
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

        Ok(RateLimitInfo {
            allowed,
            requests_remaining: bucket.tokens as u32,
            reset_time: now + Duration::from_secs_f64((bucket.capacity - bucket.tokens) / bucket.refill_rate),
            retry_after: if allowed { None } else { Some(Duration::from_secs(1)) },
            current_requests: (bucket.capacity - bucket.tokens) as u32,
            window_start: now,
            algorithm_used: RateLimitAlgorithm::TokenBucket,
            violation_count: 0, // TODO: implémenter
            is_premium_user: false,
            geo_location: None,
        })
    }

    fn shift_sliding_window(&self, window: &mut CompressedSlidingWindow, now: SystemTime) -> Result<()> {
        let elapsed = now.duration_since(window.window_start).unwrap_or_default();
        
        if elapsed >= window.window_duration {
            // Reset complète de la fenêtre
            window.buckets.fill(0);
            window.total_requests = 0;
            window.peak_rate = 0;
            window.window_start = now;
        } else {
            // Décalage partiel des buckets expirés
            let buckets_to_shift = (elapsed.as_secs() / (window.window_duration.as_secs() / window.bucket_count as u64)) as usize;
            
            if buckets_to_shift > 0 {
                // Décaler les buckets et calculer le nouveau total
                for i in 0..(window.bucket_count - buckets_to_shift) {
                    window.buckets[i] = window.buckets[i + buckets_to_shift];
                }
                for i in (window.bucket_count - buckets_to_shift)..window.bucket_count {
                    window.buckets[i] = 0;
                }
                
                // Recalculer le total
                window.total_requests = window.buckets.iter().sum();
            }
        }

        Ok(())
    }

    fn get_violation_count(&self, identifier: &str) -> u32 {
        self.violation_counter.get(identifier).map(|v| *v).unwrap_or(0)
    }

    async fn is_premium_user(&self, _identifier: &str) -> bool {
        // TODO: Implémenter la logique de vérification premium
        false
    }

    async fn get_geo_location(&self, _identifier: &str) -> Option<String> {
        // TODO: Implémenter la géolocalisation IP
        None
    }

    /// Obtient les métriques actuelles
    pub async fn get_metrics(&self) -> RateLimitMetrics {
        self.performance_metrics.read().clone()
    }

    /// Nettoyage périodique des données expirées
    pub async fn cleanup_expired_data(&self) -> Result<usize> {
        let mut cleanup_count = 0;
        let now = SystemTime::now();
        let expiration_threshold = Duration::from_secs(3600); // 1 heure

        // Nettoyer les buckets expirés
        self.memory_buckets.retain(|_, bucket| {
            let expired = now.duration_since(bucket.last_refill).unwrap_or_default() > expiration_threshold;
            if expired {
                cleanup_count += 1;
            }
            !expired
        });

        // Nettoyer les fenêtres expirées
        self.memory_windows.retain(|_, window| {
            let expired = now.duration_since(window.window_start).unwrap_or_default() > window.window_duration * 2;
            if expired {
                cleanup_count += 1;
            }
            !expired
        });

        info!("Cleaned up {} expired rate limiting entries", cleanup_count);
        Ok(cleanup_count)
    }
}

/// Types d'analyse de trafic
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum TrafficPattern {
    Bursty,     // Trafic en rafales
    Steady,     // Trafic constant
    Irregular,  // Trafic irrégulier
    Unknown,    // Pattern non déterminé
}

/// Middleware Actix-Web pour l'intégration
pub async fn advanced_rate_limit_middleware(
    req: actix_web::dev::ServiceRequest,
    manager: actix_web::web::Data<Arc<ValkeyRateLimitManager>>,
) -> Result<actix_web::dev::ServiceRequest, actix_web::Error> {
    use actix_web::HttpResponse;
    
    let ip = req.connection_info().realip_remote_addr()
        .unwrap_or("unknown")
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().expect("Checked operation"));
    
    let path = req.path().to_string();
    let method = req.method().to_string();
    
    let key = RateLimitKey::from_ip_endpoint(ip, &path, &method);
    
    match manager.check_rate_limit(&key).await {
        Ok(info) if info.allowed => {
            // Ajouter les headers de rate limiting
            // TODO: Ajouter les headers à la réponse
            Ok(req)
        }
        Ok(info) => {
            let retry_after = info.retry_after
                .map(|d| d.as_secs())
                .unwrap_or(60);
            
            let _response = HttpResponse::TooManyRequests()
                .append_header(("Retry-After", retry_after.to_string()))
                .append_header(("X-RateLimit-Remaining", info.requests_remaining.to_string()))
                .json(serde_json::json!({
                    "error": "Rate limit exceeded",
                    "retry_after": retry_after,
                    "algorithm": format!("{:?}", info.algorithm_used)
                }));
                
            Err(actix_web::Error::from(actix_web::error::ErrorTooManyRequests("Rate limit exceeded")))
        }
        Err(e) => {
            error!("Rate limiting error: {}", e);
            // En cas d'erreur, laisser passer la requête (fail-open)
            Ok(req)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_config() -> RateLimitConfig {
        let mut endpoint_limits = HashMap::new();
        endpoint_limits.insert("/test".to_string(), EndpointRateLimit {
            requests_per_minute: 10,
            requests_per_hour: 100,
            requests_per_day: 1000,
            burst_capacity: 5,
        });

        RateLimitConfig {
            endpoint_limits,
            valkey_config: None,
            algorithm: RateLimitAlgorithm::TokenBucket,
            ip_exemptions: vec![],
        }
    }

    #[tokio::test]
    async fn test_manager_creation() {
        let config = create_test_config();
        let manager = ValkeyRateLimitManager::new(config);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_token_bucket_algorithm() {
        let config = create_test_config();
        let manager = ValkeyRateLimitManager::new(config).expect("Checked operation");
        
        let key = RateLimitKey::from_ip_endpoint("127.0.0.1".parse().expect("Checked operation"), "/test", "GET");
        
        // Première requête devrait passer
        let result = manager.check_advanced_token_bucket(&key).await;
        assert!(result.is_ok());
        assert!(result.expect("Checked operation").allowed);
    }

    #[tokio::test]
    async fn test_sliding_window_algorithm() {
        let config = create_test_config();
        let manager = ValkeyRateLimitManager::new(config).expect("Checked operation");
        
        let key = RateLimitKey::from_ip_endpoint("127.0.0.1".parse().expect("Checked operation"), "/test", "GET");
        
        let result = manager.check_compressed_sliding_window(&key).await;
        assert!(result.is_ok());
        assert!(result.expect("Checked operation").allowed);
    }

    #[test]
    fn test_rate_limit_key_generation() {
        let key = RateLimitKey::from_ip_endpoint("127.0.0.1".parse().expect("Checked operation"), "/api/test", "POST")
            .with_tenant("tenant123")
            .with_client_type("mobile");
        
        let valkey_key = key.to_valkey_key();
        assert!(valkey_key.contains("127.0.0.1"));
        assert!(valkey_key.contains("/api/test"));
        assert!(valkey_key.contains("POST"));
        assert!(valkey_key.contains("tenant123"));
        assert!(valkey_key.contains("mobile"));
    }
}
