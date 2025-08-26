// Configuration réseau centralisée
pub struct NetworkConfig {
    pub allowed_proxy_ips: Vec<&'static str>,
    pub test_ips: Vec<&'static str>,
    pub whitelist_ranges: Vec<&'static str>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            allowed_proxy_ips: vec![
                "127.0.0.1",
                "127.0.0.1",
                "127.0.0.1",
            ],
            test_ips: vec![
                "127.0.0.1",   // IP de test locale
                "127.0.0.1", // IP de test blacklist
            ],
            whitelist_ranges: vec![
                // Configuration dynamique via variables d'environnement
                // Plus d'IPs hardcodées en production
            ],
        }
    }
}
