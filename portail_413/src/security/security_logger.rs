use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::errors::{AppError, Result};

/// Service de logs de sécurité avec alertes temps réel
/// Conforme aux recommandations OWASP pour la surveillance de sécurité
#[derive(Clone)]
pub struct SecurityLogger {
    events: Arc<Mutex<Vec<SecurityEvent>>>,
    alert_thresholds: HashMap<String, AlertThreshold>,
    enable_real_time_alerts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: String,
    pub context: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    AuthenticationSuccess,
    AuthenticationFailure,
    AuthorizationFailure,
    AccountLocked,
    AccountUnlocked,
    PasswordChanged,
    SessionCreated,
    SessionExpired,
    SessionRevoked,
    SuspiciousActivity,
    RateLimitExceeded,
    CSRFAttempt,
    XSSAttempt,
    SQLInjectionAttempt,
    MaliciousFileUpload,
    UnauthorizedAccess,
    DataExfiltrationAttempt,
    SystemError,
    ConfigurationChange,
    AdminAction,      // Ajout pour les actions administratives
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,        // Ajout pour les événements de faible priorité
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct AlertThreshold {
    pub max_events_per_minute: usize,
    pub max_events_per_hour: usize,
    pub severity_threshold: SecuritySeverity,
}

impl SecurityLogger {
    /// Crée un nouveau service de logs de sécurité
    pub fn new(enable_real_time_alerts: bool) -> Self {
        let mut alert_thresholds = HashMap::new();
        
        // Seuils d'alerte pour différents types d'événements
        alert_thresholds.insert("authentication_failure".to_string(), AlertThreshold {
            max_events_per_minute: 5,
            max_events_per_hour: 50,
            severity_threshold: SecuritySeverity::Medium,
        });
        
        alert_thresholds.insert("authorization_failure".to_string(), AlertThreshold {
            max_events_per_minute: 10,
            max_events_per_hour: 100,
            severity_threshold: SecuritySeverity::Medium,
        });
        
        alert_thresholds.insert("suspicious_activity".to_string(), AlertThreshold {
            max_events_per_minute: 3,
            max_events_per_hour: 20,
            severity_threshold: SecuritySeverity::High,
        });
        
        alert_thresholds.insert("injection_attempt".to_string(), AlertThreshold {
            max_events_per_minute: 1,
            max_events_per_hour: 5,
            severity_threshold: SecuritySeverity::Critical,
        });

        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            alert_thresholds,
            enable_real_time_alerts,
        }
    }

    /// Log un événement de sécurité
    pub fn log_security_event(
        &self,
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        user_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        details: String,
        context: Option<String>,
        request_id: Option<String>,
    ) -> Result<()> {
        let event = SecurityEvent {
            id: Uuid::new_v4(),
            event_type: event_type.clone(),
            severity: severity.clone(),
            timestamp: Utc::now(),
            user_id,
            ip_address: ip_address.clone(),
            user_agent,
            details: details.clone(),
            context: context.clone(),
            request_id,
        };

        // Ajouter l'événement à la liste
        {
            let mut events = self.events.lock()
                .map_err(|_| AppError::Internal("Failed to acquire events lock".to_string()))?;
            events.push(event.clone());
            
            // Limiter la taille de la liste (garder les 10000 derniers événements)
            if events.len() > 10000 {
                events.drain(0..1000);
            }
        }

        // Log structuré selon le type d'événement
        self.log_structured_event(&event);

        // Vérifier les seuils d'alerte
        if self.enable_real_time_alerts {
            self.check_alert_thresholds(&event_type, &ip_address)?;
        }

        Ok(())
    }

    /// Log structuré selon le type d'événement
    fn log_structured_event(&self, event: &SecurityEvent) {
        let base_fields = format!(
            "event_id={} user_id={:?} ip={:?} timestamp={}",
            event.id,
            event.user_id,
            event.ip_address,
            event.timestamp
        );

        match event.severity {
            SecuritySeverity::Critical => {
                tracing::error!(
                    target: "security_critical",
                    event_type = ?event.event_type,
                    details = %event.details,
                    context = ?event.context,
                    "{} - CRITICAL SECURITY EVENT",
                    base_fields
                );
            },
            SecuritySeverity::High => {
                tracing::warn!(
                    target: "security_high",
                    event_type = ?event.event_type,
                    details = %event.details,
                    context = ?event.context,
                    "{} - HIGH SECURITY EVENT",
                    base_fields
                );
            },
            SecuritySeverity::Medium => {
                tracing::warn!(
                    target: "security_medium",
                    event_type = ?event.event_type,
                    details = %event.details,
                    context = ?event.context,
                    "{} - MEDIUM SECURITY EVENT",
                    base_fields
                );
            },
            SecuritySeverity::Low => {
                tracing::info!(
                    target: "security_low",
                    event_type = ?event.event_type,
                    details = %event.details,
                    context = ?event.context,
                    "{} - LOW SECURITY EVENT",
                    base_fields
                );
            },
        }
    }

    /// Vérifie les seuils d'alerte et déclenche des alertes si nécessaire
    fn check_alert_thresholds(&self, event_type: &SecurityEventType, ip_address: &Option<String>) -> Result<()> {
        let threshold_key = match event_type {
            SecurityEventType::AuthenticationFailure => "authentication_failure",
            SecurityEventType::AuthorizationFailure => "authorization_failure",
            SecurityEventType::SuspiciousActivity => "suspicious_activity",
            SecurityEventType::XSSAttempt | SecurityEventType::SQLInjectionAttempt => "injection_attempt",
            _ => return Ok(()),
        };

        if let Some(threshold) = self.alert_thresholds.get(threshold_key) {
            let events = self.events.lock()
                .map_err(|_| AppError::Internal("Failed to acquire events lock".to_string()))?;

            let now = Utc::now();
            let one_minute_ago = now - chrono::Duration::minutes(1);
            let one_hour_ago = now - chrono::Duration::hours(1);

            // Compter les événements récents du même type
            let recent_events_minute = events.iter()
                .filter(|e| e.timestamp > one_minute_ago && std::mem::discriminant(&e.event_type) == std::mem::discriminant(event_type))
                .count();

            let recent_events_hour = events.iter()
                .filter(|e| e.timestamp > one_hour_ago && std::mem::discriminant(&e.event_type) == std::mem::discriminant(event_type))
                .count();

            // Déclencher des alertes si les seuils sont dépassés
            if recent_events_minute > threshold.max_events_per_minute {
                self.trigger_alert(
                    format!("ALERT: {} events of type {:?} in the last minute from IP {:?}", 
                           recent_events_minute, event_type, ip_address),
                    SecuritySeverity::High,
                )?;
            }

            if recent_events_hour > threshold.max_events_per_hour {
                self.trigger_alert(
                    format!("ALERT: {} events of type {:?} in the last hour from IP {:?}", 
                           recent_events_hour, event_type, ip_address),
                    SecuritySeverity::Critical,
                )?;
            }
        }

        Ok(())
    }

    /// Déclenche une alerte de sécurité
    fn trigger_alert(&self, message: String, severity: SecuritySeverity) -> Result<()> {
        match severity {
            SecuritySeverity::Critical => {
                tracing::error!(target: "security_alert", "🚨 CRITICAL ALERT: {}", message);
            },
            SecuritySeverity::High => {
                tracing::warn!(target: "security_alert", "⚠️ HIGH ALERT: {}", message);
            },
            _ => {
                tracing::info!(target: "security_alert", "ℹ️ ALERT: {}", message);
            }
        }

        // Ici, on pourrait ajouter d'autres mécanismes d'alerte :
        // - Envoi d'emails
        // - Notifications Slack/Discord
        // - Webhooks
        // - Intégration SIEM

        Ok(())
    }

    /// Obtient les statistiques de sécurité
    pub fn get_security_stats(&self) -> Result<SecurityStats> {
        let events = self.events.lock()
            .map_err(|_| AppError::Internal("Failed to acquire events lock".to_string()))?;

        let now = Utc::now();
        let one_hour_ago = now - chrono::Duration::hours(1);
        let one_day_ago = now - chrono::Duration::days(1);

        let total_events = events.len();
        let events_last_hour = events.iter().filter(|e| e.timestamp > one_hour_ago).count();
        let events_last_day = events.iter().filter(|e| e.timestamp > one_day_ago).count();

        let critical_events = events.iter()
            .filter(|e| matches!(e.severity, SecuritySeverity::Critical))
            .count();

        let high_events = events.iter()
            .filter(|e| matches!(e.severity, SecuritySeverity::High))
            .count();

        Ok(SecurityStats {
            total_events,
            events_last_hour,
            events_last_day,
            critical_events,
            high_events,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct SecurityStats {
    pub total_events: usize,
    pub events_last_hour: usize,
    pub events_last_day: usize,
    pub critical_events: usize,
    pub high_events: usize,
}

impl Default for SecurityLogger {
    fn default() -> Self {
        Self::new(true) // Alertes temps réel activées par défaut
    }
}
