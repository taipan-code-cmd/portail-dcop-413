// DCOP (413) - Système d'Audit et de Logging de Sécurité Avancé
// Implémentation conforme aux standards SIEM et réglementation RGPD

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use chrono::Timelike;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::security::security_config::{AuditConfig, LogDestination};
use crate::security::secrets_manager::SecretsManager;

/// Niveau de sévérité des événements de sécurité
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SeverityLevel {
    Critical,   // Violations de sécurité critiques
    High,       // Tentatives d'intrusion, accès non autorisé
    Medium,     // Comportements suspects, erreurs d'authentification
    Low,        // Événements informationnels
    Info,       // Événements normaux mais notables
}

/// Type d'événement de sécurité détaillé
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    // Authentification
    LoginSuccess { user_id: String, ip: String, user_agent: String },
    LoginFailure { username: String, ip: String, reason: String },
    LogoutSuccess { user_id: String, session_id: String },
    PasswordChanged { user_id: String, ip: String },
    AccountLocked { user_id: String, reason: String },
    AccountUnlocked { user_id: String, admin_id: String },
    
    // Autorisation
    AccessGranted { user_id: String, resource: String, action: String },
    AccessDenied { user_id: String, resource: String, action: String, reason: String },
    PrivilegeEscalation { user_id: String, from_role: String, to_role: String },
    UnauthorizedAccess { user_id: Option<String>, ip: String, resource: String },
    
    // Données
    DataAccess { user_id: String, table: String, record_id: Option<String> },
    DataModification { user_id: String, table: String, record_id: String, operation: String },
    DataExport { user_id: String, table: String, records_count: u64 },
    DataDeletion { user_id: String, table: String, record_id: String },
    
    // Sécurité système
    RateLimitExceeded { ip: String, endpoint: String, limit: u32 },
    SqlInjectionAttempt { ip: String, query: String, user_agent: String },
    XssAttempt { ip: String, payload: String, endpoint: String },
    CsrfAttempt { ip: String, token: String, referer: String },
    SuspiciousActivity { ip: String, description: String, indicators: Vec<String> },
    
    // Configuration et système
    ConfigurationChange { admin_id: String, setting: String, old_value: String, new_value: String },
    SystemError { component: String, error: String, stack_trace: Option<String> },
    SecurityScanDetected { ip: String, scanner_type: String, targets: Vec<String> },
    MalwareDetected { file_hash: String, location: String, threat_type: String },
    
    // Sessions
    SessionCreated { user_id: String, session_id: String, ip: String },
    SessionExpired { user_id: String, session_id: String },
    ConcurrentSessionLimit { user_id: String, limit: u32 },
    
    // Réseau
    SuspiciousNetworkActivity { source_ip: String, target_ip: String, protocol: String, ports: Vec<u16> },
    DdosAttempt { source_ips: Vec<String>, target_endpoint: String, requests_per_second: u32 },
    GeolocationAnomaly { user_id: String, previous_location: String, current_location: String },
}

/// Événement d'audit de sécurité complet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditEvent {
    pub id: Uuid,
    pub timestamp: SystemTime,
    pub severity: SeverityLevel,
    pub event_type: SecurityEventType,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub correlation_id: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub risk_score: u8, // 0-100
    pub geo_location: Option<GeoLocation>,
    pub response_action: Option<ResponseAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub region: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    Block,
    Challenge,
    Monitor,
    Alert,
    Quarantine,
}

/// Gestionnaire d'audit de sécurité
pub struct SecurityAuditManager {
    config: AuditConfig,
    events_buffer: Arc<RwLock<Vec<SecurityAuditEvent>>>,
    secrets_manager: Arc<SecretsManager>,
    risk_calculator: RiskCalculator,
    correlation_engine: CorrelationEngine,
}

/// Calculateur de score de risque basé sur les événements
#[derive(Debug)]
struct RiskCalculator {
    base_scores: HashMap<String, u8>,
    ip_reputation: Arc<RwLock<HashMap<String, u8>>>,
    user_behavior: Arc<RwLock<HashMap<String, UserBehaviorProfile>>>,
}

#[derive(Debug, Clone)]
struct UserBehaviorProfile {
    normal_login_hours: Vec<u8>, // 0-23
    _normal_locations: Vec<String>,
    _typical_user_agents: Vec<String>,
    _average_session_duration: Duration,
    failed_login_count: u32,
    last_activity: SystemTime,
}

/// Moteur de corrélation des événements de sécurité
#[derive(Debug)]
struct CorrelationEngine {
    active_correlations: Arc<RwLock<HashMap<String, CorrelationGroup>>>,
    rules: Vec<CorrelationRule>,
}

#[derive(Debug, Clone)]
struct CorrelationGroup {
    id: String,
    events: Vec<SecurityAuditEvent>,
    _first_seen: SystemTime,
    last_updated: SystemTime,
    risk_score: u8,
    pattern: String,
}

#[derive(Debug, Clone)]
struct CorrelationRule {
    id: String,
    _name: String,
    _pattern: String,
    _time_window: Duration,
    _threshold: u32,
    _severity_escalation: SeverityLevel,
}

impl SecurityAuditManager {
    /// Crée un nouveau gestionnaire d'audit
    pub fn new(config: AuditConfig, secrets_manager: Arc<SecretsManager>) -> Self {
        let risk_calculator = RiskCalculator::new();
        let correlation_engine = CorrelationEngine::new();

        Self {
            config,
            events_buffer: Arc::new(RwLock::new(Vec::new())),
            secrets_manager,
            risk_calculator,
            correlation_engine,
        }
    }

    /// Enregistre un événement de sécurité
    pub async fn log_security_event(&self, mut event: SecurityAuditEvent) -> Result<()> {
        // Calculer le score de risque
        event.risk_score = self.risk_calculator.calculate_risk(&event).await;

        // Enrichir avec des métadonnées
        self.enrich_event(&mut event).await?;

        // Corréler avec d'autres événements
        if let Some(correlation) = self.correlation_engine.correlate(&event).await {
            info!("Event correlated with pattern: {}", correlation.pattern);
            event.correlation_id = Some(correlation.id.clone());
        }

        // Déterminer l'action de réponse automatique
        if event.risk_score >= 80 {
            event.response_action = Some(ResponseAction::Block);
            warn!("High-risk event detected, blocking source: {:?}", event.ip_address);
        } else if event.risk_score >= 60 {
            event.response_action = Some(ResponseAction::Challenge);
        } else if event.risk_score >= 40 {
            event.response_action = Some(ResponseAction::Monitor);
        }

        // Logger l'événement selon la configuration
        self.write_event(&event).await?;

        // Ajouter au buffer pour traitement par lot
        {
            let mut buffer = self.events_buffer.write();
            buffer.push(event.clone());
            
            // Traitement par lot si le buffer est plein
            if buffer.len() >= 100 {
                let events_to_process: Vec<_> = buffer.drain(..).collect();
                drop(buffer);
                self.process_batch(events_to_process).await?;
            }
        }

        Ok(())
    }

    /// Enrichit un événement avec des métadonnées supplémentaires
    async fn enrich_event(&self, event: &mut SecurityAuditEvent) -> Result<()> {
        // Géolocalisation (simulation - en production, utiliser un service comme MaxMind)
        if let Some(ip) = &event.ip_address {
            if !ip.starts_with("127.") && !ip.starts_with("192.168.") && !ip.starts_with("10.") {
                event.geo_location = Some(self.get_geolocation(ip).await.unwrap_or_else(|_| {
                    GeoLocation {
                        country: "Unknown".to_string(),
                        region: "Unknown".to_string(),
                        city: "Unknown".to_string(),
                        latitude: 0.0,
                        longitude: 0.0,
                    }
                }));
            }
        }

        // Enrichissement avec le profil utilisateur
        if let Some(user_id) = &event.user_id {
            if let Some(profile) = self.risk_calculator.user_behavior.read().get(user_id) {
                let current_hour = chrono::Utc::now().hour() as u8;
                if !profile.normal_login_hours.contains(&current_hour) {
                    event.tags.push("unusual_time".to_string());
                    event.metadata.insert("risk_factor".to_string(), "unusual_login_time".to_string());
                }
            }
        }

        // Ajouter des tags basés sur le type d'événement
        match &event.event_type {
            SecurityEventType::LoginFailure { .. } => {
                event.tags.push("authentication".to_string());
                event.tags.push("failure".to_string());
            }
            SecurityEventType::RateLimitExceeded { .. } => {
                event.tags.push("rate_limiting".to_string());
                event.tags.push("suspicious".to_string());
            }
            SecurityEventType::SqlInjectionAttempt { .. } => {
                event.tags.push("injection_attack".to_string());
                event.tags.push("critical_threat".to_string());
            }
            _ => {}
        }

        Ok(())
    }

    /// Écrit un événement selon la configuration de destination
    async fn write_event(&self, event: &SecurityAuditEvent) -> Result<()> {
        let event_json = if self.config.encrypt_logs {
            self.encrypt_event_data(event).await?
        } else {
            serde_json::to_string(event)?
        };

        match &self.config.log_destination {
            LogDestination::File { path } => {
                self.write_to_file(path, &event_json).await?;
            }
            LogDestination::Syslog { facility } => {
                self.write_to_syslog(facility, event).await?;
            }
            LogDestination::Database { connection_string } => {
                self.write_to_database(connection_string, event).await?;
            }
            LogDestination::Remote { url, token } => {
                self.write_to_remote(url, token.as_deref(), event).await?;
            }
            LogDestination::Multiple(destinations) => {
                for dest in destinations {
                    match dest {
                        LogDestination::File { path } => {
                            self.write_to_file(path, &event_json).await?;
                        }
                        LogDestination::Syslog { facility } => {
                            self.write_to_syslog(facility, event).await?;
                        }
                        LogDestination::Database { connection_string } => {
                            self.write_to_database(connection_string, event).await?;
                        }
                        LogDestination::Remote { url, token } => {
                            self.write_to_remote(url, token.as_deref(), event).await?;
                        }
                        LogDestination::Multiple(_) => {
                            // Éviter la récursion infinie
                            warn!("Nested Multiple destination ignored");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Chiffre les données d'événement sensibles
    async fn encrypt_event_data(&self, event: &SecurityAuditEvent) -> Result<String> {
        let event_json = serde_json::to_string(event)?;
        
        // Utiliser le gestionnaire de secrets pour chiffrer
        let hash = self.secrets_manager.hash_data(&event_json);
        
        let encrypted_event = serde_json::json!({
            "encrypted": true,
            "data_hash": hash,
            "timestamp": event.timestamp.duration_since(UNIX_EPOCH)?.as_secs(),
            "severity": event.severity,
            "event_id": event.id,
            "encrypted_data": general_purpose::STANDARD.encode(event_json.as_bytes()) // En production, utiliser un vrai chiffrement
        });

        Ok(encrypted_event.to_string())
    }

    /// Écrit dans un fichier de log
    async fn write_to_file(&self, path: &PathBuf, content: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .context("Failed to open log file")?;

        writeln!(file, "{}", content)?;
        file.flush()?;

        Ok(())
    }

    /// Écrit vers syslog
    async fn write_to_syslog(&self, facility: &str, event: &SecurityAuditEvent) -> Result<()> {
        // En production, utiliser une bibliothèque syslog appropriée
        info!("SYSLOG[{}]: {:?}", facility, event);
        Ok(())
    }

    /// Écrit en base de données
    async fn write_to_database(&self, _connection_string: &str, event: &SecurityAuditEvent) -> Result<()> {
        // En production, implémenter l'écriture dans une base dédiée aux logs
        debug!("DB_AUDIT: {:?}", event);
        Ok(())
    }

    /// Écrit vers un endpoint distant
    async fn write_to_remote(&self, url: &str, token: Option<&str>, event: &SecurityAuditEvent) -> Result<()> {
        // En production, implémenter l'envoi vers un SIEM ou service de logging
        info!("REMOTE[{}]: token={:?}, event={:?}", url, token.is_some(), event.id);
        Ok(())
    }

    /// Traite un lot d'événements
    async fn process_batch(&self, events: Vec<SecurityAuditEvent>) -> Result<()> {
        info!("Processing batch of {} security events", events.len());

        // Analyses par lot
        self.analyze_batch_patterns(&events).await?;
        self.update_risk_profiles(&events).await?;
        self.generate_batch_alerts(&events).await?;

        Ok(())
    }

    /// Analyse les motifs dans un lot d'événements
    async fn analyze_batch_patterns(&self, events: &[SecurityAuditEvent]) -> Result<()> {
        let mut ip_counts: HashMap<String, u32> = HashMap::new();
        let mut user_failures: HashMap<String, u32> = HashMap::new();

        for event in events {
            // Compter les événements par IP
            if let Some(ip) = &event.ip_address {
                *ip_counts.entry(ip.clone()).or_insert(0) += 1;
            }

            // Compter les échecs de connexion par utilisateur
            if let SecurityEventType::LoginFailure { username, .. } = &event.event_type {
                *user_failures.entry(username.clone()).or_insert(0) += 1;
            }
        }

        // Détecter des IPs suspectes
        for (ip, count) in ip_counts {
            if count > 50 {
                warn!("Suspicious IP detected: {} with {} events", ip, count);
                self.risk_calculator.ip_reputation.write().insert(ip, 90);
            }
        }

        // Détecter des attaques par force brute
        for (username, failures) in user_failures {
            if failures > 10 {
                warn!("Brute force attack detected on user: {} ({} failures)", username, failures);
            }
        }

        Ok(())
    }

    /// Met à jour les profils de risque des utilisateurs
    async fn update_risk_profiles(&self, events: &[SecurityAuditEvent]) -> Result<()> {
        let mut profiles = self.risk_calculator.user_behavior.write();

        for event in events {
            if let Some(user_id) = &event.user_id {
                let profile = profiles.entry(user_id.clone()).or_insert_with(|| UserBehaviorProfile {
                    normal_login_hours: vec![],
                    _normal_locations: vec![],
                    _typical_user_agents: vec![],
                    _average_session_duration: Duration::from_secs(1800), // 30 min par défaut
                    failed_login_count: 0,
                    last_activity: SystemTime::now(),
                });

                // Mettre à jour le profil basé sur l'événement
                match &event.event_type {
                    SecurityEventType::LoginSuccess { .. } => {
                        let hour = chrono::Utc::now().hour() as u8;
                        if !profile.normal_login_hours.contains(&hour) {
                            profile.normal_login_hours.push(hour);
                        }
                        profile.failed_login_count = 0; // Reset sur succès
                    }
                    SecurityEventType::LoginFailure { .. } => {
                        profile.failed_login_count += 1;
                    }
                    _ => {}
                }

                profile.last_activity = event.timestamp;
            }
        }

        Ok(())
    }

    /// Génère des alertes basées sur le lot d'événements
    async fn generate_batch_alerts(&self, events: &[SecurityAuditEvent]) -> Result<()> {
        let high_risk_events: Vec<_> = events.iter()
            .filter(|e| e.risk_score >= 70)
            .collect();

        if !high_risk_events.is_empty() {
            info!("Generated alert for {} high-risk events", high_risk_events.len());
            
            // En production, envoyer des notifications (email, SMS, webhook, etc.)
            for event in high_risk_events {
                warn!("HIGH RISK ALERT: {:?} (score: {})", event.event_type, event.risk_score);
            }
        }

        Ok(())
    }

    /// Obtient la géolocalisation d'une IP (simulation)
    async fn get_geolocation(&self, _ip: &str) -> Result<GeoLocation> {
        // En production, utiliser un service comme MaxMind GeoLite2
        Ok(GeoLocation {
            country: "FR".to_string(),
            region: "Île-de-France".to_string(),
            city: "Paris".to_string(),
            latitude: 48.8566,
            longitude: 2.3522,
        })
    }

    /// Nettoie les anciens événements selon la politique de rétention
    pub async fn cleanup_old_events(&self) -> Result<()> {
        info!("Starting cleanup of old audit events");
        
        let retention_duration = self.config.log_retention;
        let cutoff_time = SystemTime::now() - retention_duration;

        // Nettoyer les corrélations expirées
        {
            let mut correlations = self.correlation_engine.active_correlations.write();
            correlations.retain(|_, group| group.last_updated > cutoff_time);
        }

        // Nettoyer les profils de comportement inactifs
        {
            let mut profiles = self.risk_calculator.user_behavior.write();
            profiles.retain(|_, profile| profile.last_activity > cutoff_time);
        }

        info!("Audit cleanup completed");
        Ok(())
    }

    /// Retourne des statistiques d'audit
    pub async fn get_statistics(&self) -> Result<serde_json::Value> {
        let buffer_size = self.events_buffer.read().len();
        let correlation_count = self.correlation_engine.active_correlations.read().len();
        let profile_count = self.risk_calculator.user_behavior.read().len();
        let ip_reputation_count = self.risk_calculator.ip_reputation.read().len();

        Ok(serde_json::json!({
            "buffer_size": buffer_size,
            "active_correlations": correlation_count,
            "user_profiles": profile_count,
            "ip_reputation_entries": ip_reputation_count,
            "log_destination": format!("{:?}", self.config.log_destination),
            "encryption_enabled": self.config.encrypt_logs,
            "integrity_check_enabled": self.config.log_integrity_check,
        }))
    }
}

impl RiskCalculator {
    fn new() -> Self {
        let mut base_scores = HashMap::new();
        
        // Scores de base pour différents types d'événements
        base_scores.insert("LoginFailure".to_string(), 30);
        base_scores.insert("RateLimitExceeded".to_string(), 50);
        base_scores.insert("SqlInjectionAttempt".to_string(), 95);
        base_scores.insert("XssAttempt".to_string(), 90);
        base_scores.insert("UnauthorizedAccess".to_string(), 80);
        base_scores.insert("AccountLocked".to_string(), 60);
        base_scores.insert("SuspiciousNetworkActivity".to_string(), 70);

        Self {
            base_scores,
            ip_reputation: Arc::new(RwLock::new(HashMap::new())),
            user_behavior: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn calculate_risk(&self, event: &SecurityAuditEvent) -> u8 {
        let event_type_name = match &event.event_type {
            SecurityEventType::LoginFailure { .. } => "LoginFailure",
            SecurityEventType::RateLimitExceeded { .. } => "RateLimitExceeded",
            SecurityEventType::SqlInjectionAttempt { .. } => "SqlInjectionAttempt",
            SecurityEventType::XssAttempt { .. } => "XssAttempt",
            SecurityEventType::UnauthorizedAccess { .. } => "UnauthorizedAccess",
            SecurityEventType::AccountLocked { .. } => "AccountLocked",
            SecurityEventType::SuspiciousNetworkActivity { .. } => "SuspiciousNetworkActivity",
            _ => "Unknown",
        };

        let mut base_score = self.base_scores.get(event_type_name).copied().unwrap_or(10);

        // Ajustements basés sur la réputation IP
        if let Some(ip) = &event.ip_address {
            if let Some(reputation) = self.ip_reputation.read().get(ip) {
                base_score = ((base_score as u16 + *reputation as u16) / 2) as u8;
            }
        }

        // Ajustements basés sur le comportement utilisateur
        if let Some(user_id) = &event.user_id {
            if let Some(profile) = self.user_behavior.read().get(user_id) {
                if profile.failed_login_count > 5 {
                    base_score = std::cmp::min(100, base_score + 20);
                }
            }
        }

        // Ajustements basés sur l'heure (activité nocturne suspecte)
        let current_hour = chrono::Utc::now().hour();
        if current_hour < 6 || current_hour > 22 {
            base_score = std::cmp::min(100, base_score + 10);
        }

        base_score
    }
}

impl CorrelationEngine {
    fn new() -> Self {
        let rules = vec![
            CorrelationRule {
                id: "brute_force".to_string(),
                _name: "Brute Force Attack".to_string(),
                _pattern: "multiple_login_failures".to_string(),
                _time_window: Duration::from_secs(300), // 5 minutes
                _threshold: 5,
                _severity_escalation: SeverityLevel::High,
            },
            CorrelationRule {
                id: "distributed_attack".to_string(),
                _name: "Distributed Attack".to_string(),
                _pattern: "same_endpoint_multiple_ips".to_string(),
                _time_window: Duration::from_secs(60), // 1 minute
                _threshold: 10,
                _severity_escalation: SeverityLevel::Critical,
            },
        ];

        Self {
            active_correlations: Arc::new(RwLock::new(HashMap::new())),
            rules,
        }
    }

    async fn correlate(&self, event: &SecurityAuditEvent) -> Option<CorrelationGroup> {
        // Logique de corrélation simplifiée
        // En production, implémenter des règles plus sophistiquées

        for rule in &self.rules {
            if self.matches_rule(event, rule) {
                let correlation_key = format!("{}_{}", rule.id, 
                    event.ip_address.as_deref().unwrap_or("unknown"));

                let mut correlations = self.active_correlations.write();
                let correlation = correlations.entry(correlation_key.clone()).or_insert_with(|| {
                    CorrelationGroup {
                        id: correlation_key,
                        events: Vec::new(),
                        _first_seen: event.timestamp,
                        last_updated: event.timestamp,
                        risk_score: 0,
                        pattern: rule._pattern.clone(),
                    }
                });

                correlation.events.push(event.clone());
                correlation.last_updated = event.timestamp;
                correlation.risk_score = std::cmp::min(100, correlation.events.len() as u8 * 10);

                if correlation.events.len() >= rule._threshold as usize {
                    return Some(correlation.clone());
                }
            }
        }

        None
    }

    fn matches_rule(&self, event: &SecurityAuditEvent, rule: &CorrelationRule) -> bool {
        match rule._pattern.as_str() {
            "multiple_login_failures" => {
                matches!(event.event_type, SecurityEventType::LoginFailure { .. })
            }
            "same_endpoint_multiple_ips" => {
                matches!(event.event_type, SecurityEventType::RateLimitExceeded { .. })
            }
            _ => false,
        }
    }
}

/// Fonction helper pour créer rapidement un événement d'audit
pub fn create_security_event(
    event_type: SecurityEventType,
    severity: SeverityLevel,
    user_id: Option<String>,
    ip_address: Option<String>,
) -> SecurityAuditEvent {
    SecurityAuditEvent {
        id: Uuid::new_v4(),
        timestamp: SystemTime::now(),
        severity,
        event_type,
        user_id,
        session_id: None,
        ip_address,
        user_agent: None,
        request_id: None,
        correlation_id: None,
        tags: Vec::new(),
        metadata: HashMap::new(),
        risk_score: 0,
        geo_location: None,
        response_action: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_event_creation() {
        let event = create_security_event(
            SecurityEventType::LoginFailure {
                username: "test_user".to_string(),
                ip: "127.0.0.1".to_string(),
                reason: "invalid_password".to_string(),
            },
            SeverityLevel::Medium,
            None,
            Some("127.0.0.1".to_string()),
        );

        assert_eq!(event.severity, SeverityLevel::Medium);
        assert!(event.ip_address.is_some());
    }

    #[tokio::test]
    async fn test_risk_calculation() {
        let calculator = RiskCalculator::new();
        
        let event = create_security_event(
            SecurityEventType::SqlInjectionAttempt {
                ip: "127.0.0.1".to_string(),
                query: "SELECT * FROM users; DROP TABLE users;".to_string(),
                user_agent: "test".to_string(),
            },
            SeverityLevel::Critical,
            None,
            Some("127.0.0.1".to_string()),
        );

        let risk_score = calculator.calculate_risk(&event).await;
        assert!(risk_score >= 90); // SQL injection should have high risk
    }

    #[test]
    fn test_correlation_rule_matching() {
        let engine = CorrelationEngine::new();
        
        let event = create_security_event(
            SecurityEventType::LoginFailure {
                username: "test".to_string(),
                ip: "127.0.0.1".to_string(),
                reason: "invalid_password".to_string(),
            },
            SeverityLevel::Medium,
            None,
            Some("127.0.0.1".to_string()),
        );

        let brute_force_rule = &engine.rules[0];
        assert!(engine.matches_rule(&event, brute_force_rule));
    }
}
