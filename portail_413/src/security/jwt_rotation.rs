use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::fs;
use rand::RngCore;
use hex;

pub struct JwtSecretManager {
    current_secret: Vec<u8>,
    previous_secret: Option<Vec<u8>>,
    last_rotation: u64,
    rotation_interval: u64, // en secondes
}

impl JwtSecretManager {
    pub fn new(rotation_interval_hours: u64) -> Self {
        let current_secret = Self::load_or_generate_secret();
        
        Self {
            current_secret,
            previous_secret: None,
            last_rotation: Self::current_timestamp(),
            rotation_interval: rotation_interval_hours * 3600,
        }
    }

    pub fn get_current_secret(&self) -> &[u8] {
        &self.current_secret
    }

    pub fn should_rotate(&self) -> bool {
        let now = Self::current_timestamp();
        now - self.last_rotation > self.rotation_interval
    }

    pub fn rotate_secret(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Garder l'ancien secret pour valider les tokens existants
        self.previous_secret = Some(self.current_secret.clone());
        
        // Générer nouveau secret
        self.current_secret = Self::generate_new_secret();
        self.last_rotation = Self::current_timestamp();
        
        // Sauvegarder le nouveau secret
        self.save_secret()?;
        
        log::info!("JWT secret rotation completed at {}", self.last_rotation);
        Ok(())
    }

    pub fn validate_token_with_any_secret(&self, token: &str) -> bool {
        // Essayer avec le secret actuel
        if self.validate_with_secret(token, &self.current_secret) {
            return true;
        }
        
        // Essayer avec l'ancien secret si disponible
        if let Some(ref prev_secret) = self.previous_secret {
            return self.validate_with_secret(token, prev_secret);
        }
        
        false
    }

    fn validate_with_secret(&self, token: &str, secret: &[u8]) -> bool {
        // TODO: Implémenter validation JWT avec secret spécifique
        true // Placeholder
    }

    fn load_or_generate_secret() -> Vec<u8> {
        match fs::read("/home/taipan_51/portail_413/portail_413/secrets_secure/jwt_secret.key") {
            Ok(data) => {
                if data.len() >= 32 {
                    data[..32].to_vec()
                } else {
                    Self::generate_new_secret()
                }
            }
            Err(_) => Self::generate_new_secret()
        }
    }

    fn generate_new_secret() -> Vec<u8> {
        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        secret
    }

    fn save_secret(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(
            "/home/taipan_51/portail_413/portail_413/secrets_secure/jwt_secret.key",
            &self.current_secret
        )?;
        Ok(())
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }
}

// Service de rotation automatique en arrière-plan
pub async fn start_jwt_rotation_service() {
    let mut manager = JwtSecretManager::new(24); // Rotation toutes les 24h
    
    loop {
        if manager.should_rotate() {
            if let Err(e) = manager.rotate_secret() {
                log::error!("Erreur rotation JWT secret: {}", e);
            }
        }
        
        // Vérifier toutes les heures
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
