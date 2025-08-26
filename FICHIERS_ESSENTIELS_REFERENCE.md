# 🗂️ FICHIERS ESSENTIELS - RÉFÉRENCE DÉVELOPPEUR

## 📊 **BASE DE DONNÉES**

### **Configuration principale**
- **Fichier :** `docker-compose.full.yml` (lignes 15-32)
- **Type :** PostgreSQL 16-alpine avec SSL
- **Nom BD :** `portail_production`
- **Utilisateur :** `dcop_user`
- **Mot de passe :** Stocké dans `secrets_secure/postgres_password.key`

### **Schéma de base**
```sql
-- Tables principales
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'Utilisateur',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE visitors (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    phone VARCHAR(20),
    company VARCHAR(200),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE visits (
    id SERIAL PRIMARY KEY,
    visitor_id INTEGER REFERENCES visitors(id),
    purpose TEXT,
    host_name VARCHAR(200),
    check_in_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    check_out_time TIMESTAMP,
    expected_duration INTEGER,
    created_by INTEGER REFERENCES users(id)
);
```

---

## 🔐 **AUTHENTIFICATION**

### **Comptes de test disponibles**
```yaml
# Compte Admin principal
admin:
  username: "admin"
  password: "AdminDCOP2025!@#$"
  role: "Admin"
  email: "principal@dcop.local"

# Compte Admin de test
test_admin:
  username: "test_admin"
  password: "TestAdmin2025!@#$%^"
  role: "Admin"
  email: "admin@dcop.local"

# Compte Directeur
directeur:
  username: "directeur"
  password: "DirectorSecure2025!@#"
  role: "Directeur"
  email: "directeur@dcop.local"
```

### **Configuration JWT**
- **Secret :** Stocké dans `secrets_secure/jwt_secret.key`
- **Algorithme :** HS256
- **Durée :** 24 heures
- **Rotation :** Automatique

---

## 🐳 **DOCKER & CONTENEURS**

### **Fichier principal :** `docker-compose.full.yml`
```yaml
# Services configurés
services:
  postgres:          # Base de données PostgreSQL 16
  dcop_app:         # Backend Rust/Actix
  nginx:            # Proxy reverse avec SSL
  
# Réseaux isolés
networks:
  frontend-network:  # Communication nginx <-> backend
  backend-network:   # Communication backend <-> DB
  database-network:  # Réseau isolé DB
```

### **Scripts de démarrage**
- **`start_system.sh`** - Démarrage complet du système
- **`stop_system.sh`** - Arrêt propre de tous les services
- **`restart_system.sh`** - Redémarrage avec reconstruction

---

## 🌐 **NGINX - PROXY REVERSE**

### **Configuration principale :** `portail_413/nginx/nginx.conf`
```nginx
# Proxy API vers backend
location /api/ {
    proxy_pass http://dcop_app:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}

# Fichiers statiques frontend
location / {
    root /usr/share/nginx/html;
    try_files $uri $uri/ /index.html;
    index index.html;
}
```

### **Headers de sécurité :** `portail_413/nginx/security_headers_ultimate.conf`
```nginx
# Sécurité renforcée
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self' 'unsafe-inline'" always;
```

---

## 🦀 **BACKEND RUST**

### **Configuration :** `portail_413/src/config/mod.rs`
```rust
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub server_port: u16,
    pub allowed_origins: Vec<String>,
}
```

### **Routes API principales :** `portail_413/src/routes/`
```
routes/
├── auth.rs          # /api/auth/* - Authentification
├── visitors.rs      # /api/visitors/* - Gestion visiteurs
├── visits.rs        # /api/visits/* - Gestion visites
├── statistics.rs    # /api/statistics/* - Stats détaillées
└── public.rs        # /api/public/* - Endpoints publics
```

### **Sécurité :** `portail_413/src/security/`
```
security/
├── password_security.rs    # Hachage Argon2
├── jwt_rotation.rs         # Rotation automatique JWT
├── input_sanitizer.rs      # Validation entrées
└── alert_system.rs         # Système d'alertes
```

---

## 📁 **SECRETS ET CLÉS**

### **Dossier :** `secrets_secure/` (permissions 600)
```
secrets_secure/
├── postgres_password.key   # Mot de passe PostgreSQL
├── jwt_secret.key         # Secret JWT (256 bits)
├── admin_password.key     # Mot de passe admin principal
└── ssl_certificates/      # Certificats SSL (si utilisés)
```

### **Variables d'environnement**
```bash
# Dans docker-compose.full.yml
POSTGRES_DB=portail_production
POSTGRES_USER=dcop_user
POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
JWT_SECRET_FILE=/run/secrets/jwt_secret
```

---

## 🧪 **DONNÉES DE TEST**

### **Script SQL :** `create_test_users.sql`
```sql
-- Utilisateurs de test
INSERT INTO users (username, password_hash, email, role) VALUES
('test_admin', '$argon2id$...', 'admin@dcop.local', 'Admin'),
('directeur', '$argon2id$...', 'directeur@dcop.local', 'Directeur');

-- Visiteurs de test
INSERT INTO visitors (first_name, last_name, email, company) VALUES
('Jean', 'Dupont', 'jean.dupont@test.com', 'Entreprise Test'),
('Marie', 'Martin', 'marie.martin@test.com', 'Société Demo'),
('Pierre', 'Durand', 'pierre.durand@test.com', 'Company ABC');

-- Visites de test
INSERT INTO visits (visitor_id, purpose, host_name) VALUES
(1, 'Réunion commerciale', 'Paul Manager'),
(2, 'Entretien technique', 'Sophie Tech'),
(3, 'Visite guidée', 'Marc Guide');
```

### **Scripts de génération :** 
- **`add_real_test_data.sh`** - Génère des données réalistes
- **`create_test_data_stats.sh`** - Données pour tests statistiques

---

## 🔧 **SCRIPTS UTILES**

### **Validation et tests**
```bash
# Test complet du système
./validation_complete_auth.sh

# Test des endpoints API
./test_auth_api_fixed.sh

# Diagnostic complet
./diagnostic_complet_stats.sh

# Test des statistiques temps réel
./test_statistiques_temps_reel.sh
```

### **Administration**
```bash
# Création d'utilisateurs
./create_new_user.sh

# Réinitialisation mot de passe admin
./fix_admin_password.sh

# Vérification des utilisateurs
./check_users.sh
```

---

## 📊 **ENDPOINTS API COMPLETS**

### **Authentification (/api/auth/)**
```
POST   /api/auth/login           # Connexion utilisateur
POST   /api/auth/logout          # Déconnexion
GET    /api/auth/validate        # Validation token
POST   /api/auth/refresh         # Renouvellement token
```

### **Visiteurs (/api/visitors/)**
```
GET    /api/visitors             # Liste tous les visiteurs
POST   /api/visitors             # Créer un visiteur
GET    /api/visitors/{id}        # Détails d'un visiteur
PUT    /api/visitors/{id}        # Modifier un visiteur
DELETE /api/visitors/{id}        # Supprimer un visiteur
```

### **Visites (/api/visits/)**
```
POST   /api/visits/register      # Enregistrer une visite (PUBLIC)
GET    /api/visits/active        # Visites en cours
GET    /api/visits/history       # Historique des visites
PUT    /api/visits/{id}/checkout # Finaliser une visite
GET    /api/visits/{id}          # Détails d'une visite
```

### **Statistiques (/api/statistics/ et /api/public/)**
```
GET    /api/public/statistics/dashboard    # Stats publiques temps réel
GET    /api/statistics/detailed           # Stats détaillées (Admin/Directeur)
GET    /api/statistics/reports            # Rapports périodiques
GET    /api/statistics/trends             # Tendances et analyses
```

### **Administration (/api/admin/)**
```
GET    /api/admin/users          # Gestion utilisateurs (Admin only)
POST   /api/admin/users          # Créer utilisateur
PUT    /api/admin/users/{id}     # Modifier utilisateur
DELETE /api/admin/users/{id}     # Supprimer utilisateur
GET    /api/admin/logs           # Logs système
```

---

## 🌐 **INTÉGRATION FRONTEND**

### **Configuration de base**
```javascript
// Configuration API
const API_CONFIG = {
  baseURL: 'http://localhost:8080/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
};

// URLs importantes
const URLS = {
  homepage: 'http://localhost:8080',
  api: 'http://localhost:8080/api',
  websocket: 'ws://localhost:8080/ws' // Pour stats temps réel
};
```

### **Gestion des tokens**
```javascript
// Storage sécurisé
const TokenManager = {
  get: () => localStorage.getItem('dcop_jwt_token'),
  set: (token) => localStorage.setItem('dcop_jwt_token', token),
  remove: () => localStorage.removeItem('dcop_jwt_token'),
  isValid: async () => {
    const token = TokenManager.get();
    if (!token) return false;
    
    try {
      const response = await fetch('/api/auth/validate', {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.ok;
    } catch {
      return false;
    }
  }
};
```

---

## 🛠️ **COMMANDES DOCKER UTILES**

### **Gestion des conteneurs**
```bash
# Voir les logs en temps réel
docker-compose logs -f dcop_app      # Backend
docker-compose logs -f dcop_nginx    # Proxy
docker-compose logs -f dcop_postgres_secure # Base de données

# Accès aux conteneurs
docker exec -it dcop_app bash        # Backend Rust
docker exec -it dcop_nginx sh        # Nginx
docker exec -it dcop_postgres_secure psql -U dcop_user -d portail_production

# Statistiques des conteneurs
docker stats

# Redémarrage d'un service spécifique
docker-compose restart dcop_app
```

### **Maintenance**
```bash
# Cleanup
docker system prune -a

# Rebuild complet
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

---

## 📋 **CHECKLIST DÉVELOPPEUR**

### **✅ Avant de commencer**
- [ ] Docker et Docker Compose installés
- [ ] Ports 8080 et 8443 disponibles
- [ ] Cloner le repository complet
- [ ] Vérifier les permissions sur `secrets_secure/` (600)

### **✅ Tests de base**
- [ ] `./start_system.sh` fonctionne
- [ ] `curl http://localhost:8080/api/public/statistics/dashboard` retourne des données
- [ ] Connexion avec `test_admin:TestAdmin2025!@#$%^` fonctionne
- [ ] Les logs ne montrent pas d'erreurs critiques

### **✅ Développement frontend**
- [ ] Configuration de l'API service
- [ ] Gestion de l'authentification JWT
- [ ] Interface de connexion fonctionnelle
- [ ] Tests avec les comptes de développement
- [ ] Validation des permissions par rôle

Cette référence contient tous les fichiers, mots de passe, et configurations nécessaires pour intégrer efficacement le frontend avec l'application DCOP-413 ! 🚀
