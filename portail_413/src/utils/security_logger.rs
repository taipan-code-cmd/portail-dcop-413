use log::{error, info, warn};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SecurityLogger;

impl SecurityLogger {
    pub fn log_authentication_attempt(username: &str, success: bool, ip: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Checked operation")
            .as_secs();
            
        let event = json!({
            "event_type": "authentication",
            "timestamp": timestamp,
            "username": username,
            "success": success,
            "source_ip": ip,
            "severity": if success { "info" } else { "warning" }
        });

        if success {
            info!("AUTH_SUCCESS: {}", event);
        } else {
            warn!("AUTH_FAILURE: {}", event);
        }
    }

    pub fn log_security_event(event_type: &str, details: &str, severity: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Checked operation")
            .as_secs();
            
        let event = json!({
            "event_type": event_type,
            "timestamp": timestamp,
            "details": details,
            "severity": severity
        });

        match severity {
            "critical" | "high" => error!("SECURITY_ALERT: {}", event),
            "medium" => warn!("SECURITY_WARNING: {}", event),
            _ => info!("SECURITY_INFO: {}", event),
        }
    }
}
