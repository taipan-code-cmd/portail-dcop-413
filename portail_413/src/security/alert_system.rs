use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

pub struct SecurityAlertSystem {
    alert_threshold: u32,
    current_alerts: u32,
}

impl SecurityAlertSystem {
    pub fn new() -> Self {
        Self {
            alert_threshold: 10, // Seuil d'alerte
            current_alerts: 0,
        }
    }

    pub async fn send_critical_alert(&mut self, alert_type: &str, details: &str, source_ip: &str) {
        let alert = json!({
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).expect("Checked operation").as_secs(),
            "severity": "CRITICAL",
            "type": alert_type,
            "details": details,
            "source_ip": source_ip,
            "alert_id": uuid::Uuid::new_v4().to_string()
        });

        // Log l'alerte
        log::error!("SECURITY_CRITICAL_ALERT: {}", alert);

        // Sauvegarder dans fichier d'alertes
        self.save_alert_to_file(&alert).await;

        // Incrémenter compteur
        self.current_alerts += 1;

        // Envoyer notification si seuil atteint
        if self.current_alerts >= self.alert_threshold {
            self.send_notification(&alert).await;
            self.current_alerts = 0; // Reset compteur
        }
    }

    pub async fn send_high_alert(&self, alert_type: &str, details: &str, source_ip: &str) {
        let alert = json!({
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).expect("Checked operation").as_secs(),
            "severity": "HIGH",
            "type": alert_type,
            "details": details,
            "source_ip": source_ip
        });

        log::warn!("SECURITY_HIGH_ALERT: {}", alert);
        self.save_alert_to_file(&alert).await;
    }

    async fn save_alert_to_file(&self, alert: &serde_json::Value) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/dcop413/security_alerts.log")
            .await
            .unwrap_or_else(|_| panic!("Cannot open alert log file"));

        let log_line = format!("{}\n", alert.to_string());
        let _ = file.write_all(log_line.as_bytes()).await;
    }

    async fn send_notification(&self, alert: &serde_json::Value) {
        // TODO: Intégrer avec Slack, email, etc.
        log::error!("NOTIFICATION_TRIGGERED: {}", alert);
        
        // Simulation envoi webhook
        let webhook_payload = json!({
            "text": format!("🚨 ALERTE SÉCURITÉ DCOP-413 🚨\n{}", alert),
            "channel": "#security-alerts",
            "username": "DCOP-413-Security-Bot"
        });
        
        // TODO: Envoyer via HTTP client vers webhook Slack/Teams
    }
}

// Service global d'alertes
lazy_static::lazy_static! {
    static ref ALERT_SYSTEM: tokio::sync::Mutex<SecurityAlertSystem> = 
        tokio::sync::Mutex::new(SecurityAlertSystem::new());
}

pub async fn trigger_security_alert(severity: &str, alert_type: &str, details: &str, source_ip: &str) {
    let mut system = ALERT_SYSTEM.lock().await;
    
    match severity {
        "CRITICAL" => {
            system.send_critical_alert(alert_type, details, source_ip).await;
        }
        "HIGH" => {
            system.send_high_alert(alert_type, details, source_ip).await;
        }
        _ => {
            log::info!("Security event: {} - {} - {}", alert_type, details, source_ip);
        }
    }
}
