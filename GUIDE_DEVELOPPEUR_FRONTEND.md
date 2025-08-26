# 📚 GUIDE DÉVELOPPEUR FRONTEND - PORTAIL DCOP-413

## 🎯 **PRÉSENTATION DE L'APPLICATION**

### **Vue d'ensemble**
Le **Portail DCOP-413** est une application web sécurisée de gestion des visiteurs développée en architecture moderne :
- **Backend :** Rust + Actix-web (API REST sécurisée)
- **Base de données :** PostgreSQL 16 avec SSL/TLS
- **Proxy :** Nginx avec sécurité renforcée
- **Conteneurisation :** Docker Compose
- **Frontend :** À intégrer (HTML/CSS/JavaScript, React, Vue.js, etc.)

### **Fonctionnalités principales**
1. **🔐 Authentification sécurisée** (JWT + Argon2)
2. **👥 Gestion des utilisateurs** (Admin, Directeur, Utilisateur)
3. **📝 Enregistrement des visites** 
4. **👤 Gestion des visiteurs**
5. **📊 Statistiques temps réel**
6. **🔍 Audit et logs sécurisés**
7. **🛡️ Sécurité enterprise-grade**

---

## 🏗️ **ARCHITECTURE TECHNIQUE**

### **Stack technologique**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FRONTEND      │────│   NGINX PROXY   │────│  BACKEND RUST   │
│   (À développer)│    │   Port 8080/8443│    │   Port 8080     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                 │
                       ┌─────────────────┐
                       │  POSTGRESQL 16  │
                       │   Port 5432     │
                       └─────────────────┘
```

### **URLs d'accès**
- **Frontend :** http://localhost:8080
- **API Backend :** Accessible via proxy (pas directement)
- **Base de données :** Accessible uniquement en interne

---

## 🔌 **APIs DISPONIBLES**

### **1. Authentification**

#### **POST /api/auth/login**
```json
// Requête
{
  "username": "test_admin",
  "password": "TestAdmin2025!@#$%^"
}

// Réponse succès
{
  "success": true,
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {
    "id": 1,
    "username": "test_admin",
    "role": "Admin",
    "email": "admin@dcop.local"
  }
}
```

#### **POST /api/auth/logout**
```json
// Headers requis
Authorization: Bearer {token}

// Réponse
{
  "success": true,
  "message": "Déconnexion réussie"
}
```

#### **GET /api/auth/validate**
```json
// Headers requis
Authorization: Bearer {token}

// Réponse
{
  "valid": true,
  "user": {
    "id": 1,
    "username": "test_admin",
    "role": "Admin"
  }
}
```

### **2. Gestion des visiteurs**

#### **GET /api/visitors**
```json
// Headers requis
Authorization: Bearer {token}

// Réponse
{
  "success": true,
  "visitors": [
    {
      "id": 1,
      "first_name": "Jean",
      "last_name": "Dupont",
      "email": "jean.dupont@email.com",
      "phone": "0123456789",
      "company": "Entreprise ABC",
      "created_at": "2025-08-26T10:30:00Z"
    }
  ]
}
```

#### **POST /api/visitors**
```json
// Requête
{
  "first_name": "Marie",
  "last_name": "Martin",
  "email": "marie.martin@email.com",
  "phone": "0987654321",
  "company": "Société XYZ"
}

// Réponse
{
  "success": true,
  "visitor_id": 2,
  "message": "Visiteur créé avec succès"
}
```

### **3. Gestion des visites**

#### **POST /api/visits/register**
```json
// Requête (accès public)
{
  "visitor_id": 1,
  "purpose": "Réunion commerciale",
  "host_name": "Paul Durand",
  "expected_duration": 120
}

// Réponse
{
  "success": true,
  "visit_id": 1,
  "check_in_time": "2025-08-26T14:30:00Z",
  "message": "Visite enregistrée"
}
```

#### **GET /api/visits/active**
```json
// Headers requis
Authorization: Bearer {token}

// Réponse
{
  "success": true,
  "active_visits": [
    {
      "id": 1,
      "visitor": {
        "first_name": "Jean",
        "last_name": "Dupont",
        "company": "Entreprise ABC"
      },
      "purpose": "Réunion commerciale",
      "check_in_time": "2025-08-26T14:30:00Z",
      "host_name": "Paul Durand"
    }
  ]
}
```

### **4. Statistiques**

#### **GET /api/public/statistics/dashboard**
```json
// Accès public
{
  "success": true,
  "statistics": {
    "total_visits_today": 15,
    "active_visits": 3,
    "total_visitors": 125,
    "most_visited_hours": ["09:00", "14:00", "16:00"]
  }
}
```

#### **GET /api/statistics/detailed**
```json
// Headers requis
Authorization: Bearer {token}
// Rôle requis: Admin ou Directeur

{
  "success": true,
  "detailed_stats": {
    "daily_visits": [10, 15, 8, 20, 12],
    "top_companies": [
      {"name": "Entreprise ABC", "visits": 25},
      {"name": "Société XYZ", "visits": 18}
    ],
    "average_duration": 85
  }
}
```

---

## 🔐 **AUTHENTIFICATION ET SÉCURITÉ**

### **Système JWT**
- **Durée de vie :** 24 heures
- **Rotation automatique :** Oui
- **Headers requis :**
```javascript
{
  "Authorization": "Bearer " + token,
  "Content-Type": "application/json"
}
```

### **Gestion des rôles**
```javascript
// Niveaux d'accès
const ROLES = {
  Admin: 3,        // Accès complet
  Directeur: 2,    // Accès étendu
  Utilisateur: 1   // Accès limité
};

// Vérification côté frontend
function hasPermission(userRole, requiredLevel) {
  return ROLES[userRole] >= requiredLevel;
}
```

### **Gestion des erreurs**
```javascript
// Codes d'erreur standards
const ERROR_CODES = {
  401: "Non authentifié",
  403: "Accès refusé", 
  404: "Ressource non trouvée",
  422: "Données invalides",
  500: "Erreur serveur"
};
```

---

## 📁 **FICHIERS DE CONFIGURATION ESSENTIELS**

### **1. Configuration Base de Données**
**Fichier :** `docker-compose.full.yml`
```yaml
# Configuration PostgreSQL
postgres:
  image: postgres:16-alpine
  environment:
    POSTGRES_DB: portail_production
    POSTGRES_USER: dcop_user
    POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password
```

**Fichier :** `secrets_secure/postgres_password.key`
```
# Mot de passe BD (généré automatiquement)
# Accès via Docker secrets uniquement
```

### **2. Configuration Backend**
**Fichier :** `portail_413/src/config/mod.rs`
```rust
// Configuration principale
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub server_port: u16,
    // ...
}
```

**Fichier :** `secrets_secure/jwt_secret.key`
```
# Secret JWT (généré automatiquement)
# 256 bits de sécurité
```

### **3. Configuration Nginx**
**Fichier :** `portail_413/nginx/nginx.conf`
```nginx
# Proxy vers backend
location /api/ {
    proxy_pass http://dcop_app:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

# Serveur de fichiers statiques
location / {
    root /usr/share/nginx/html;
    try_files $uri $uri/ /index.html;
}
```

---

## 👥 **COMPTES DE TEST**

### **Comptes utilisateurs**
```javascript
// Comptes de développement
const TEST_ACCOUNTS = {
  admin: {
    username: "test_admin",
    password: "TestAdmin2025!@#$%^",
    role: "Admin",
    email: "admin@dcop.local"
  },
  directeur: {
    username: "directeur", 
    password: "DirectorSecure2025!@#",
    role: "Directeur",
    email: "directeur@dcop.local"
  },
  principal: {
    username: "admin",
    password: "AdminDCOP2025!@#$",
    role: "Admin", 
    email: "principal@dcop.local"
  }
};
```

### **Données de test**
**Script :** `create_test_users.sql`
```sql
-- Visiteurs de test
INSERT INTO visitors (first_name, last_name, email, company) VALUES
('Jean', 'Dupont', 'jean.dupont@test.com', 'Entreprise Test'),
('Marie', 'Martin', 'marie.martin@test.com', 'Société Demo'),
('Pierre', 'Durand', 'pierre.durand@test.com', 'Company ABC');
```

---

## 🛠️ **INTÉGRATION FRONTEND**

### **Structure recommandée**
```
frontend/
├── src/
│   ├── components/
│   │   ├── Auth/
│   │   │   ├── LoginForm.js
│   │   │   └── LogoutButton.js
│   │   ├── Visitors/
│   │   │   ├── VisitorList.js
│   │   │   ├── VisitorForm.js
│   │   │   └── VisitorCard.js
│   │   ├── Visits/
│   │   │   ├── RegisterVisit.js
│   │   │   ├── ActiveVisits.js
│   │   │   └── VisitHistory.js
│   │   └── Dashboard/
│   │       ├── Statistics.js
│   │       └── Charts.js
│   ├── services/
│   │   ├── api.js
│   │   ├── auth.js
│   │   └── storage.js
│   ├── utils/
│   │   ├── validators.js
│   │   └── formatters.js
│   └── App.js
├── public/
└── package.json
```

### **Service API (JavaScript/TypeScript)**
```javascript
// services/api.js
class ApiService {
  constructor() {
    this.baseURL = 'http://localhost:8080/api';
    this.token = localStorage.getItem('jwt_token');
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(this.token && { 'Authorization': `Bearer ${this.token}` })
      },
      ...options
    };

    const response = await fetch(url, config);
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    return response.json();
  }

  // Authentification
  async login(username, password) {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
    
    if (response.success) {
      this.token = response.token;
      localStorage.setItem('jwt_token', this.token);
    }
    
    return response;
  }

  // Visiteurs
  async getVisitors() {
    return this.request('/visitors');
  }

  async createVisitor(visitor) {
    return this.request('/visitors', {
      method: 'POST',
      body: JSON.stringify(visitor)
    });
  }

  // Visites
  async registerVisit(visit) {
    return this.request('/visits/register', {
      method: 'POST',
      body: JSON.stringify(visit)
    });
  }

  async getActiveVisits() {
    return this.request('/visits/active');
  }

  // Statistiques
  async getDashboardStats() {
    return this.request('/public/statistics/dashboard');
  }
}

export default new ApiService();
```

### **Composant de connexion (React)**
```jsx
// components/Auth/LoginForm.js
import React, { useState } from 'react';
import ApiService from '../../services/api';

const LoginForm = ({ onLogin }) => {
  const [credentials, setCredentials] = useState({
    username: '',
    password: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await ApiService.login(
        credentials.username, 
        credentials.password
      );
      
      if (response.success) {
        onLogin(response.user);
      } else {
        setError('Identifiants incorrects');
      }
    } catch (err) {
      setError('Erreur de connexion');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label>Nom d'utilisateur:</label>
        <input
          type="text"
          value={credentials.username}
          onChange={(e) => setCredentials({
            ...credentials,
            username: e.target.value
          })}
          required
        />
      </div>
      <div>
        <label>Mot de passe:</label>
        <input
          type="password"
          value={credentials.password}
          onChange={(e) => setCredentials({
            ...credentials,
            password: e.target.value
          })}
          required
        />
      </div>
      {error && <div className="error">{error}</div>}
      <button type="submit" disabled={loading}>
        {loading ? 'Connexion...' : 'Se connecter'}
      </button>
    </form>
  );
};

export default LoginForm;
```

---

## 🚀 **DÉMARRAGE RAPIDE**

### **1. Lancer l'application**
```bash
# Démarrer tous les services
./start_system.sh

# Vérifier le statut
docker-compose ps
```

### **2. Développement frontend**
```bash
# Dans le dossier frontend/
npm install
npm start

# Ou avec un autre framework
yarn install
yarn dev
```

### **3. Tests API**
```bash
# Test de connexion
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test_admin","password":"TestAdmin2025!@#$%^"}'

# Test des statistiques publiques
curl http://localhost:8080/api/public/statistics/dashboard
```

---

## 🔧 **OUTILS DE DÉVELOPPEMENT**

### **Scripts utiles**
- `./validation_complete_auth.sh` - Test complet de l'authentification
- `./diagnostic_endpoints.sh` - Test de tous les endpoints
- `docker-compose logs -f dcop_app` - Logs du backend
- `docker-compose logs -f dcop_nginx` - Logs du proxy

### **Base de données**
```bash
# Connexion à la BD
docker exec -it dcop_postgres_secure psql -U dcop_user -d portail_production

# Voir les tables
\dt

# Voir les utilisateurs
SELECT * FROM users;
```

### **Monitoring**
- **Logs :** `/var/log/nginx/` (dans le conteneur nginx)
- **Métriques :** Endpoint `/api/health` pour la santé du système
- **Sécurité :** Logs dans `portail_413/app.log`

---

## 🛡️ **SÉCURITÉ - POINTS IMPORTANTS**

### **Headers de sécurité**
```javascript
// Headers requis côté frontend
const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block'
};
```

### **Validation côté client**
```javascript
// Validation des données
const validators = {
  email: (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
  phone: (phone) => /^[0-9+\-\s()]{10,}$/.test(phone),
  password: (pwd) => pwd.length >= 12 && /[A-Z]/.test(pwd) && /[0-9]/.test(pwd)
};
```

### **Protection CSRF**
```javascript
// Token CSRF dans les headers
const csrf_token = document.querySelector('meta[name="csrf-token"]').content;
headers['X-CSRF-Token'] = csrf_token;
```

---

## 📞 **SUPPORT ET DOCUMENTATION**

### **Documentation technique**
- **Architecture :** `ARCHITECTURE_DOCKER.md`
- **Sécurité :** `SECURITY_RECOMMENDATIONS.md`
- **Administration :** `GUIDE_ADMINISTRATION_COMPLET.md`

### **Ports et services**
- **Frontend :** Port 8080 (HTTP) / 8443 (HTTPS)
- **Backend :** Port 8080 (interne uniquement)
- **Base de données :** Port 5432 (interne uniquement)
- **Proxy :** Nginx (point d'entrée unique)

Cette documentation vous donne tous les éléments nécessaires pour développer une interface frontend moderne et sécurisée pour le Portail DCOP-413. L'application backend est entièrement fonctionnelle et prête à être utilisée ! 🚀
