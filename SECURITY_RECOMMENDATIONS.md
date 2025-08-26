# 🔒 Recommandations de Sécurité - Portail DCOP-413

## 📋 Vue d'ensemble

Ce document présente les recommandations de sécurité critiques pour le backend **Portail des Visites DCOP-413** après analyse complète de l'architecture et des tests de sécurité.

---

## ⚠️ Vulnérabilités Critiques à Corriger

### 1. 🔑 **Gestion des [REDACTED]

**CRITIQUE - Priorité 1**
```
Status: DÉVELOPPEMENT UNIQUEMENT
Risque: TRÈS ÉLEVÉ en production
```

**Problèmes identifiés:**
- [REDACTED] de développement hardcodés dans le code
- Variables d'environnement avec valeurs par défaut faibles
- JWT_[REDACTED] ENCRYPTION_KEY, SECURITY_SALT non sécurisés

**Actions requises:**
```bash
# 1. Générer des [REDACTED] cryptographiquement sûrs
openssl rand -base64 32 > [REDACTED]
openssl rand -base64 32 > encryption.key
openssl rand -base64 32 > security_salt.key

# 2. Configurer les variables d'environnement
export JWT_[REDACTED] [REDACTED]
export ENCRYPTION_KEY=$(cat encryption.key)
export SECURITY_SALT=$(cat security_salt.key)

# 3. Supprimer les fichiers de [REDACTED]
rm *.key
```

**Configuration recommandée:**
```rust
// src/config.rs - Validation des [REDACTED]
pub fn validate_production_[REDACTED] -> Result<(), ConfigError> {
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
        let [REDACTED] = std::env::var("JWT_[REDACTED]
        if [REDACTED] < 32 || [REDACTED] {
            return Err(ConfigError::Insecure[REDACTED]
        }
    }
    Ok(())
}
```

### 2. 🚫 **Authentication Faible**

**CRITIQUE - Priorité 1**
```rust
// PROBLÈME ACTUEL dans main.rs:
async fn simple_login(login_data: web::Json<serde_json::Value>) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    let username = login_data.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let [REDACTED] v.as_str()).unwrap_or("");
    
    // DANGEREUX: Comparaison en texte clair
    if username == "admin_test" && [REDACTED] {
        // Token factice
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "token": "test_[REDACTED] // TOKEN FACTICE!
        })))
    }
}
```

**Solution recommandée:**
```rust
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, Header, EncodingKey};

async fn secure_login(
    login_data: web::Json<LoginRequest>,
    auth_service: web::Data<AuthService>
) -> Result<HttpResponse, AuthError> {
    // 1. Validation des données d'entrée
    login_data.validate()?;
    
    // 2. Récupération sécurisée depuis la DB
    let user = auth_service.get_user_by_username(&login_data.username).await?;
    
    // 3. Vérification du hash bcrypt
    if !verify(&login_data.[REDACTED] &user.[REDACTED] {
        return Err(AuthError::InvalidCredentials);
    }
    
    // 4. Génération JWT sécurisé
    let claims = JWTClaims {
        sub: user.id,
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp(),
        role: user.role,
    };
    
    let token = encode(&Header::default(), &claims, &EncodingKey::from_[REDACTED]
    
    Ok(HttpResponse::Ok().json(LoginResponse {
        success: true,
        token,
        expires_at: claims.exp
    }))
}
```

### 3. 🛡️ **Validation des Données**

**ÉLEVÉ - Priorité 2**

**Problèmes identifiés:**
- Pas de validation stricte des entrées utilisateur
- Utilisation de `serde_json::Value` générique
- Risque d'injection NoSQL/SQL

**Solution recommandée:**
```rust
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 3, max = 50))]
    #[validate(regex = "USERNAME_REGEX")]
    pub username: String,
    
    #[validate(length(min = 8, max = 128))]
    pub [REDACTED] String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct VisitorRequest {
    #[validate(length(min = 2, max = 100))]
    pub name: String,
    
    #[validate(email)]
    pub email: String,
    
    #[validate(regex = "PHONE_REGEX")]
    pub phone: Option<String>,
    
    #[validate(length(max = 500))]
    pub purpose: String,
}

// Middleware de validation
async fn validate_request<T: Validate>(
    payload: web::Json<T>
) -> Result<web::Json<T>, ValidationError> {
    payload.validate()?;
    Ok(payload)
}
```

---

## 🔐 Sécurisations de Base à Implémenter

### 4. **Rate Limiting**

```rust
use actix_web_httpauth::middleware::HttpAuthentication;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct RateLimiter {
    attempts: Arc<Mutex<HashMap<String, Vec<Instant>>>>
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(Mutex::new(HashMap::new()))
        }
    }
    
    pub fn check_rate_limit(&self, ip: &str) -> bool {
        let mut attempts = self.attempts.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(3600); // 1 heure
        
        let ip_attempts = attempts.entry(ip.to_string()).or_insert_with(Vec::new);
        
        // Nettoyer les tentatives expirées
        ip_attempts.retain(|&attempt| now.duration_since(attempt) < window);
        
        // Vérifier la limite (5 tentatives par heure)
        if ip_attempts.len() >= 5 {
            return false;
        }
        
        ip_attempts.push(now);
        true
    }
}

// Configuration dans main.rs
.route("/api/public/login", 
    web::post()
    .wrap(RateLimitMiddleware::new(5, Duration::from_secs(3600)))
    .to(secure_login)
)
```

### 5. **Headers de Sécurité**

```rust
use actix_web::middleware::DefaultHeaders;

fn create_security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add(("X-Content-Type-Options", "nosniff"))
        .add(("X-Frame-Options", "DENY"))
        .add(("X-XSS-Protection", "1; mode=block"))
        .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .add(("Content-Security-Policy", 
              "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"))
        .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
}

// Dans main.rs
App::new()
    .wrap(create_security_headers())
    .wrap(Logger::default())
```

### 6. **Chiffrement des Données Sensibles**

```rust
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

pub struct DataEncryption {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl DataEncryption {
    pub fn new(key_material: &[u8]) -> Result<Self, EncryptionError> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_material)?;
        let key = LessSafeKey::new(unbound_key);
        
        Ok(Self {
            key,
            rng: SystemRandom::new(),
        })
    }
    
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let mut nonce_bytes = [0u8; 12];
        self.rng.fill(&mut nonce_bytes)?;
        
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        
        self.key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)?;
        
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);
        
        Ok(result)
    }
}

// Usage pour données sensibles
pub async fn store_visitor_data(visitor: &Visitor, encryption: &DataEncryption) -> Result<(), DatabaseError> {
    let encrypted_email = encryption.encrypt(visitor.email.as_bytes())?;
    let encrypted_phone = visitor.phone.as_ref()
        .map(|p| encryption.encrypt(p.as_bytes()))
        .transpose()?;
    
    sqlx::query!(
        "INSERT INTO visitors (name, email_encrypted, phone_encrypted) VALUES ($1, $2, $3)",
        visitor.name,
        encrypted_email,
        encrypted_phone
    )
    .execute(&pool)
    .await?;
    
    Ok(())
}
```

---

## 🔍 Audit et Monitoring

### 7. **Logging de Sécurité**

```rust
use tracing::{info, warn, error};
use serde_json::json;

#[derive(Debug, Serialize)]
pub struct SecurityEvent {
    pub event_type: String,
    pub user_id: Option<i32>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub details: serde_json::Value,
}

pub trait SecurityLogger {
    async fn log_login_attempt(&self, ip: &str, username: &str, success: bool);
    async fn log_access_denied(&self, ip: &str, resource: &str, reason: &str);
    async fn log_data_access(&self, user_id: i32, resource: &str, action: &str);
}

// Implémentation
impl SecurityLogger for AuditService {
    async fn log_login_attempt(&self, ip: &str, username: &str, success: bool) {
        let event = SecurityEvent {
            event_type: "LOGIN_ATTEMPT".to_string(),
            user_id: None,
            ip_address: ip.to_string(),
            user_agent: None,
            timestamp: chrono::Utc::now(),
            details: json!({
                "username": username,
                "success": success
            }),
        };
        
        if success {
            info!("Login successful: {}", serde_json::to_string(&event).unwrap());
        } else {
            warn!("Login failed: {}", serde_json::to_string(&event).unwrap());
        }
        
        self.store_security_event(&event).await.unwrap_or_else(|e| {
            error!("Failed to store security event: {}", e);
        });
    }
}
```

### 8. **Protection CSRF**

```rust
use actix_web_httpauth::extractors::bearer::BearerAuth;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct CSRFProtection {
    [REDACTED] Vec<u8>,
}

impl CSRFProtection {
    pub fn new([REDACTED] &[u8]) -> Self {
        Self {
            [REDACTED] [REDACTED]
        }
    }
    
    pub fn generate_token(&self, user_id: i32) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.[REDACTED]
        mac.update(&user_id.to_le_bytes());
        mac.update(&chrono::Utc::now().timestamp().to_le_bytes());
        
        base64::encode(mac.finalize().into_bytes())
    }
    
    pub fn verify_token(&self, token: &str, user_id: i32) -> bool {
        // Implémentation de la vérification
        true // Simplifié
    }
}

// Middleware CSRF
pub async fn csrf_middleware(
    req: HttpRequest,
    payload: web::Payload,
    csrf: web::Data<CSRFProtection>,
) -> Result<HttpRequest, Error> {
    // Vérification du token CSRF pour POST/PUT/DELETE
    if matches!(req.method(), &http::Method::POST | &http::Method::PUT | &http::Method::DELETE) {
        let token = req.headers().get("X-CSRF-Token")
            .and_then(|h| h.to_str().ok());
            
        if token.is_none() {
            return Err(ErrorForbidden("CSRF token required"));
        }
        
        // Validation du token...
    }
    
    Ok(req)
}
```

---

## 🚨 Configuration de Production

### 9. **Variables d'Environnement Sécurisées**

```bash
# .env.production (NE PAS COMMITTER)
ENVIRONMENT=production
RUST_LOG=warn,portail_413=info

# [REDACTED] (générer avec openssl rand -base64 32)
JWT_[REDACTED]
ENCRYPTION_KEY=<GENERATED_[REDACTED]
SECURITY_SALT=<GENERATED_[REDACTED]

# Database
DATABASE_URL=postgresql://user:[SECURE_[REDACTED]
DATABASE_MAX_CONNECTIONS=10
DATABASE_CONNECTION_TIMEOUT=30

# Server
SERVER_HOST=127.0.0.1  # Pas 0.0.0.0 en production
SERVER_PORT=8443
SERVER_WORKERS=4

# SSL/TLS
SSL_CERT_PATH=/etc/ssl/certs/dcop413.crt
SSL_KEY_PATH=/etc/ssl/private/dcop413.key

# Session
SESSION_TIMEOUT=3600  # 1 heure
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTP_ONLY=true
SESSION_COOKIE_SAME_SITE=strict
```

### 10. **Configuration Docker Sécurisée**

```dockerfile
# Dockerfile.production
FROM rust:1.83-slim as builder

# Installation des dépendances minimales
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build en mode release avec optimisations de sécurité
RUN cargo build --release --target-dir /app/target

# Runtime avec utilisateur non-root
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r dcop && useradd -r -g dcop dcop

COPY --from=builder /app/target/release/portail_413 /usr/local/bin/
COPY --from=builder /app/static /app/static
COPY --from=builder /app/migrations /app/migrations

# Permissions strictes
RUN chown -R dcop:dcop /app
USER dcop

# Port non-root
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8443/health || exit 1

CMD ["/usr/local/bin/portail_413"]
```

---

## ✅ Checklist de Sécurité

### Avant Mise en Production

- [ ] **[REDACTED] Tous les [REDACTED] de développement remplacés
- [ ] **JWT**: Clés cryptographiquement sûres (256-bit minimum)
- [ ] **Base de données**: Mots de passe forts, connexions chiffrées
- [ ] **Hachage**: bcrypt avec cost ≥ 12 pour tous les mots de passe
- [ ] **HTTPS**: Certificats SSL/TLS configurés
- [ ] **Headers**: Headers de sécurité activés
- [ ] **CORS**: Origines autorisées limitées
- [ ] **Rate Limiting**: Limites strictes sur login/API
- [ ] **Validation**: Tous les inputs validés et sanitisés
- [ ] **Logging**: Événements de sécurité tracés
- [ ] **Monitoring**: Alertes configurées
- [ ] **Backups**: Sauvegardes chiffrées automatiques
- [ ] **Tests**: Tests de pénétration effectués

### Monitoring Continue

- [ ] **Logs de sécurité**: Analyse quotidienne
- [ ] **Tentatives de connexion**: Surveillance des échecs
- [ ] **Performance**: Détection des anomalies
- [ ] **Certificats**: Renouvellement automatique
- [ ] **Dépendances**: Mise à jour des vulnérabilités
- [ ] **Sauvegardes**: Vérification d'intégrité

---

## 🆘 Incident Response

### Procédure en Cas d'Intrusion

1. **Isolation immédiate**
   ```bash
   # Arrêter les services
   docker-compose down
   
   # Sauvegarder les logs
   cp -r logs/ /secure/incident-$(date +%Y%m%d)/
   ```

2. **Analyse forensique**
   - Examiner les logs de sécurité
   - Identifier les vecteurs d'attaque
   - Évaluer les données compromises

3. **Correction et récupération**
   - Changer tous les [REDACTED] de passe
   - Révoquer les tokens actifs
   - Appliquer les correctifs de sécurité
   - Restaurer depuis une sauvegarde propre

4. **Communication**
   - Informer les utilisateurs affectés
   - Déclarer l'incident selon RGPD si nécessaire
   - Documenter les leçons apprises

---

## 📚 Ressources Additionnelles

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [Actix-Web Security](https://actix.rs/docs/middleware/)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)

---

*Document généré le 14 août 2025 - Version 1.0*
*Prochaine révision: 14 septembre 2025*
