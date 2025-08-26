// DCOP (413) - Service de Gestion des Tentatives de Connexion
// Implémente la protection contre les attaques par force brute
// avec verrouillage adaptatif et détection d'anomalies

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::errors::Result;
use crate::security::{SecurityLogger, SecurityEventType, SecuritySeverity};

/// Structure pour tracker les tentatives de connexion par utilisateur
#[derive(Debug, Clone)]
pub struct UserLoginAttempts {
    pub user_id: Uuid,
    pub username: String,
    pub failed_attempts: u32,
    pub last_attempt: DateTime<Utc>,
    pub locked_until: Option<DateTime<Utc>>,
    pub lockout_level: LockoutLevel,
    pub suspicious_ips: Vec<IpAddr>,
}

/// Structure pour tracker les tentatives par IP
#[derive(Debug, Clone)]
pub struct IpLoginAttempts {
    pub ip: IpAddr,
    pub failed_attempts: u32,
    pub last_attempt: DateTime<Utc>,
    pub locked_until: Option<DateTime<Utc>>,
    pub targeted_users: Vec<String>,
}

/// Niveaux de verrouillage progressif
#[derive(Debug, Clone, PartialEq)]
pub enum LockoutLevel {
    None,
    Warning,      // 3-4 tentatives
    Temporary,    // 5-7 tentatives - 15 minutes
    Extended,     // 8-10 tentatives - 1 heure  
    Severe,       // 11+ tentatives - 24 heures
    Permanent,    // Tentatives répétées - intervention manuelle
}

impl LockoutLevel {
    pub fn get_duration(&self) -> Duration {
        match self {
            LockoutLevel::None | LockoutLevel::Warning => Duration::zero(),
            LockoutLevel::Temporary => Duration::minutes(15),
            LockoutLevel::Extended => Duration::hours(1),
            LockoutLevel::Severe => Duration::hours(24),
            LockoutLevel::Permanent => Duration::days(365), // Nécessite intervention manuelle
        }
    }
    
    pub fn next_level(&self) -> LockoutLevel {
        match self {
            LockoutLevel::None => LockoutLevel::Warning,
            LockoutLevel::Warning => LockoutLevel::Temporary,
            LockoutLevel::Temporary => LockoutLevel::Extended,
            LockoutLevel::Extended => LockoutLevel::Severe,
            LockoutLevel::Severe => LockoutLevel::Permanent,
            LockoutLevel::Permanent => LockoutLevel::Permanent,
        }
    }
}

/// Service principal de gestion des tentatives de connexion
#[derive(Clone)]
pub struct LoginAttemptService {
    // Cache en mémoire pour les tentatives récentes (production: Redis)
    user_attempts: Arc<RwLock<HashMap<String, UserLoginAttempts>>>,
    ip_attempts: Arc<RwLock<HashMap<IpAddr, IpLoginAttempts>>>,
    security_logger: SecurityLogger,
    
    // Configuration
    _max_attempts_per_user: u32,
    max_attempts_per_ip: u32,
    cleanup_interval_hours: u64,
}

impl LoginAttemptService {
    pub fn new(
        max_attempts_per_user: u32,
        max_attempts_per_ip: u32,
        cleanup_interval_hours: u64,
    ) -> Self {
        Self {
            user_attempts: Arc::new(RwLock::new(HashMap::new())),
            ip_attempts: Arc::new(RwLock::new(HashMap::new())),
            security_logger: SecurityLogger::new(true),
            _max_attempts_per_user: max_attempts_per_user,
            max_attempts_per_ip,
            cleanup_interval_hours,
        }
    }

    /// Vérifie si un utilisateur peut tenter une connexion
    pub async fn can_attempt_login(&self, username: &str, ip: IpAddr) -> Result<bool> {
        let now = Utc::now();
        
        // Vérifier le verrouillage utilisateur
        if let Some(user_locked_until) = self.check_user_lockout(username, now).await? {
            if user_locked_until > now {
                return Ok(false);
            }
        }
        
        // Vérifier le verrouillage IP
        if let Some(ip_locked_until) = self.check_ip_lockout(ip, now).await? {
            if ip_locked_until > now {
                return Ok(false);
            }
        }
        
        Ok(true)
    }

    /// Enregistre une tentative de connexion échouée
    pub async fn record_failed_attempt(
        &self,
        user_id: Option<Uuid>,
        username: &str,
        ip: IpAddr,
        user_agent: Option<String>,
    ) -> Result<()> {
        let now = Utc::now();
        
        // Enregistrer pour l'utilisateur
        if let Some(uid) = user_id {
            self.record_user_failed_attempt(uid, username, ip, now).await?;
        }
        
        // Enregistrer pour l'IP
        self.record_ip_failed_attempt(ip, username, now).await?;
        
        // Logger l'événement de sécurité
        self.security_logger.log_security_event(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::Medium,
            user_id,
            Some(ip.to_string()),
            user_agent,
            format!("Failed login attempt for user '{username}' from IP {ip}"),
            Some("brute_force_detection".to_string()),
            None,
        )?;
        
        Ok(())
    }

    /// Enregistre une connexion réussie (reset des compteurs)
    pub async fn record_successful_login(
        &self,
        user_id: Uuid,
        username: &str,
        ip: IpAddr,
    ) -> Result<()> {
        // Reset compteurs utilisateur
        {
            let mut user_attempts = self.user_attempts.write().expect("Checked operation");
            user_attempts.remove(username);
        }
        
        // Réduire le compteur IP (mais ne pas supprimer complètement)
        {
            let mut ip_attempts = self.ip_attempts.write().expect("Checked operation");
            if let Some(ip_attempt) = ip_attempts.get_mut(&ip) {
                ip_attempt.failed_attempts = ip_attempt.failed_attempts.saturating_sub(2);
                if ip_attempt.failed_attempts == 0 {
                    ip_attempts.remove(&ip);
                }
            }
        }
        
        self.security_logger.log_security_event(
            SecurityEventType::AuthenticationSuccess,
            SecuritySeverity::Low,
            Some(user_id),
            Some(ip.to_string()),
            None,
            format!("Successful login for user '{username}' from IP {ip}"),
            Some("login_success".to_string()),
            None,
        )?;
        
        Ok(())
    }

    /// Vérifie le statut de verrouillage d'un utilisateur
    async fn check_user_lockout(&self, username: &str, now: DateTime<Utc>) -> Result<Option<DateTime<Utc>>> {
        let user_attempts = self.user_attempts.read().expect("Checked operation");
        
        if let Some(attempt) = user_attempts.get(username) {
            if let Some(locked_until) = attempt.locked_until {
                if locked_until > now {
                    return Ok(Some(locked_until));
                }
            }
        }
        
        Ok(None)
    }

    /// Vérifie le statut de verrouillage d'une IP
    async fn check_ip_lockout(&self, ip: IpAddr, now: DateTime<Utc>) -> Result<Option<DateTime<Utc>>> {
        let ip_attempts = self.ip_attempts.read().expect("Checked operation");
        
        if let Some(attempt) = ip_attempts.get(&ip) {
            if let Some(locked_until) = attempt.locked_until {
                if locked_until > now {
                    return Ok(Some(locked_until));
                }
            }
        }
        
        Ok(None)
    }

    /// Enregistre une tentative échouée pour un utilisateur
    async fn record_user_failed_attempt(
        &self,
        user_id: Uuid,
        username: &str,
        ip: IpAddr,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let mut user_attempts = self.user_attempts.write().expect("Checked operation");
        
        let attempt = user_attempts.entry(username.to_string()).or_insert(UserLoginAttempts {
            user_id,
            username: username.to_string(),
            failed_attempts: 0,
            last_attempt: now,
            locked_until: None,
            lockout_level: LockoutLevel::None,
            suspicious_ips: Vec::new(),
        });
        
        attempt.failed_attempts += 1;
        attempt.last_attempt = now;
        
        // Ajouter l'IP aux IPs suspectes si pas déjà présente
        if !attempt.suspicious_ips.contains(&ip) {
            attempt.suspicious_ips.push(ip);
        }
        
        // Déterminer le niveau de verrouillage
        let new_level = match attempt.failed_attempts {
            1..=2 => LockoutLevel::None,
            3..=4 => LockoutLevel::Warning,
            5..=7 => LockoutLevel::Temporary,
            8..=10 => LockoutLevel::Extended,
            11..=15 => LockoutLevel::Severe,
            _ => LockoutLevel::Permanent,
        };
        
        if new_level != attempt.lockout_level {
            attempt.lockout_level = new_level.clone();
            attempt.locked_until = if new_level == LockoutLevel::None {
                None
            } else {
                Some(now + new_level.get_duration())
            };
            
            // Logger l'escalade de sécurité
            if attempt.failed_attempts >= 5 {
                self.security_logger.log_security_event(
                    SecurityEventType::AccountLocked,
                    SecuritySeverity::High,
                    Some(user_id),
                    Some(ip.to_string()),
                    None,
                    format!(
                        "User '{}' locked out at level {:?} after {} failed attempts from {} IPs",
                        username, new_level, attempt.failed_attempts, attempt.suspicious_ips.len()
                    ),
                    Some("account_lockout".to_string()),
                    None,
                )?;
            }
        }
        
        Ok(())
    }

    /// Enregistre une tentative échouée pour une IP
    async fn record_ip_failed_attempt(
        &self,
        ip: IpAddr,
        username: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let mut ip_attempts = self.ip_attempts.write().expect("Checked operation");
        
        let attempt = ip_attempts.entry(ip).or_insert(IpLoginAttempts {
            ip,
            failed_attempts: 0,
            last_attempt: now,
            locked_until: None,
            targeted_users: Vec::new(),
        });
        
        attempt.failed_attempts += 1;
        attempt.last_attempt = now;
        
        // Ajouter le username aux utilisateurs ciblés
        if !attempt.targeted_users.contains(&username.to_string()) {
            attempt.targeted_users.push(username.to_string());
        }
        
        // Verrouiller l'IP si trop de tentatives
        if attempt.failed_attempts >= self.max_attempts_per_ip {
            let lockout_duration = match attempt.failed_attempts {
                10..=19 => Duration::minutes(30),
                20..=49 => Duration::hours(2),
                50..=99 => Duration::hours(12),
                _ => Duration::hours(24),
            };
            
            attempt.locked_until = Some(now + lockout_duration);
            
            // Logger l'événement critique
            self.security_logger.log_security_event(
                SecurityEventType::SuspiciousActivity,
                SecuritySeverity::Critical,
                None,
                Some(ip.to_string()),
                None,
                format!(
                    "IP {} locked out after {} failed attempts targeting {} users: {:?}",
                    ip, attempt.failed_attempts, attempt.targeted_users.len(), attempt.targeted_users
                ),
                Some("ip_lockout".to_string()),
                None,
            )?;
        }
        
        Ok(())
    }

    /// Nettoie les tentatives expirées (à appeler périodiquement)
    pub async fn cleanup_expired_attempts(&self) -> Result<usize> {
        let now = Utc::now();
        let cleanup_threshold = now - Duration::hours(self.cleanup_interval_hours as i64);
        let mut cleaned_count = 0;
        
        // Nettoyer les tentatives utilisateurs
        {
            let mut user_attempts = self.user_attempts.write().expect("Checked operation");
            let before_count = user_attempts.len();
            user_attempts.retain(|_, attempt| {
                if let Some(locked_until) = attempt.locked_until {
                    locked_until > now || attempt.last_attempt > cleanup_threshold
                } else {
                    attempt.last_attempt > cleanup_threshold
                }
            });
            cleaned_count += before_count - user_attempts.len();
        }
        
        // Nettoyer les tentatives IP
        {
            let mut ip_attempts = self.ip_attempts.write().expect("Checked operation");
            let before_count = ip_attempts.len();
            ip_attempts.retain(|_, attempt| {
                if let Some(locked_until) = attempt.locked_until {
                    locked_until > now || attempt.last_attempt > cleanup_threshold
                } else {
                    attempt.last_attempt > cleanup_threshold
                }
            });
            cleaned_count += before_count - ip_attempts.len();
        }
        
        if cleaned_count > 0 {
            tracing::debug!("Cleaned up {} expired login attempt records", cleaned_count);
        }
        
        Ok(cleaned_count)
    }

    /// Obtient les statistiques des tentatives de connexion
    pub async fn get_attempt_statistics(&self) -> HashMap<String, serde_json::Value> {
        let user_attempts = self.user_attempts.read().expect("Checked operation");
        let ip_attempts = self.ip_attempts.read().expect("Checked operation");
        
        let mut stats = HashMap::new();
        
        // Statistiques utilisateurs
        let mut user_lockout_levels = HashMap::new();
        for attempt in user_attempts.values() {
            *user_lockout_levels.entry(format!("{:?}", attempt.lockout_level)).or_insert(0) += 1;
        }
        
        stats.insert("total_users_tracked".to_string(), serde_json::json!(user_attempts.len()));
        stats.insert("user_lockout_levels".to_string(), serde_json::json!(user_lockout_levels));
        
        // Statistiques IP
        let locked_ips = ip_attempts.values()
            .filter(|attempt| attempt.locked_until.is_some_and(|until| until > Utc::now()))
            .count();
        
        stats.insert("total_ips_tracked".to_string(), serde_json::json!(ip_attempts.len()));
        stats.insert("locked_ips".to_string(), serde_json::json!(locked_ips));
        
        stats
    }

    /// Débloquer manuellement un utilisateur (pour les administrateurs)
    pub async fn unlock_user(&self, username: &str, admin_user_id: Uuid) -> Result<bool> {
        let mut user_attempts = self.user_attempts.write().expect("Checked operation");
        
        if let Some(attempt) = user_attempts.get_mut(username) {
            attempt.failed_attempts = 0;
            attempt.locked_until = None;
            attempt.lockout_level = LockoutLevel::None;
            
            self.security_logger.log_security_event(
                SecurityEventType::AdminAction,
                SecuritySeverity::Low,
                Some(admin_user_id),
                None,
                None,
                format!("Admin manually unlocked user '{username}'"),
                Some("manual_unlock".to_string()),
                None,
            )?;
            
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Débloquer manuellement une IP (pour les administrateurs)
    pub async fn unlock_ip(&self, ip: IpAddr, admin_user_id: Uuid) -> Result<bool> {
        let mut ip_attempts = self.ip_attempts.write().expect("Checked operation");
        
        if let Some(attempt) = ip_attempts.get_mut(&ip) {
            attempt.failed_attempts = 0;
            attempt.locked_until = None;
            
            self.security_logger.log_security_event(
                SecurityEventType::AdminAction,
                SecuritySeverity::Low,
                Some(admin_user_id),
                None,
                None,
                format!("Admin manually unlocked IP '{ip}'"),
                Some("manual_ip_unlock".to_string()),
                None,
            )?;
            
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
