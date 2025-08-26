# DCOP (413) - Structure du Projet

## 📁 Architecture des Fichiers

```
portail_413/
├── 📄 Cargo.toml                    # Configuration Rust et dépendances
├── 📄 Cargo.lock                    # Verrouillage des versions
├── 📄 Dockerfile                    # Image Docker multi-stage sécurisée
├── 📄 docker-compose.yml            # Orchestration des services
├── 📄 .env.example                  # Template de configuration
├── 📄 .dockerignore                 # Exclusions Docker
├── 📄 .gitignore                    # Exclusions Git
├── 📄 Makefile                      # Automatisation des tâches
├── 📄 README.md                     # Documentation principale
├── 📄 STRUCTURE.md                  # Ce fichier
├── 📄 init-db.sql                   # Initialisation PostgreSQL
│
├── 📂 src/                          # Code source Rust
│   ├── 📄 lib.rs                    # Point d'entrée de la bibliothèque
│   ├── 📄 main.rs                   # Point d'entrée de l'application
│   │
│   ├── 📂 config/                   # Configuration
│   │   └── 📄 mod.rs                # Gestion des variables d'environnement
│   │
│   ├── 📂 database/                 # Accès aux données
│   │   ├── 📄 mod.rs                # Module principal
│   │   ├── 📄 connection.rs         # Connexion PostgreSQL
│   │   └── 📂 repositories/         # Repositories (pattern Repository)
│   │       ├── 📄 mod.rs            # Module repositories
│   │       ├── 📄 user_repository.rs      # Gestion des utilisateurs
│   │       ├── 📄 visitor_repository.rs   # Gestion des visiteurs
│   │       ├── 📄 visit_repository.rs     # Gestion des visites
│   │       └── 📄 audit_repository.rs     # Gestion de l'audit
│   │
│   ├── 📂 models/                   # Modèles de données
│   │   ├── 📄 mod.rs                # Module principal
│   │   ├── 📄 user.rs               # Modèle utilisateur
│   │   ├── 📄 visitor.rs            # Modèle visiteur (4 téléphones)
│   │   ├── 📄 visit.rs              # Modèle visite
│   │   └── 📄 audit.rs              # Modèle audit
│   │
│   ├── 📂 handlers/                 # Contrôleurs HTTP (Actix-web)
│   │   ├── 📄 mod.rs                # Module principal
│   │   ├── 📄 auth_handler.rs       # Authentification
│   │   ├── 📄 visitor_handler.rs    # Gestion visiteurs
│   │   ├── 📄 visit_handler.rs      # Gestion visites
│   │   ├── 📄 admin_handler.rs      # Administration
│   │   └── 📄 public_handler.rs     # Endpoints publics
│   │
│   ├── 📂 services/                 # Logique métier
│   │   ├── 📄 mod.rs                # Module principal
│   │   ├── 📄 auth_service.rs       # Service d'authentification
│   │   ├── 📄 visitor_service.rs    # Service visiteurs
│   │   ├── 📄 visit_service.rs      # Service visites
│   │   ├── 📄 audit_service.rs      # Service d'audit
│   │   └── 📄 statistics_service.rs # Service statistiques
│   │
│   ├── 📂 security/                 # Services de sécurité
│   │   ├── 📄 mod.rs                # Module principal
│   │   ├── 📄 encryption.rs         # Chiffrement AES-256-GCM
│   │   ├── 📄 hashing.rs            # Hachage SHA-512
│   │   ├── 📄 [REDACTED]           # Gestion mots de passe Argon2id
│   │   └── 📄 jwt.rs                # Tokens JWT
│   │
│   ├── 📂 middleware/               # Middleware Actix-web
│   │   ├── 📄 mod.rs                # Module principal
│   │   ├── 📄 auth_middleware.rs    # Authentification
│   │   ├── 📄 cors_middleware.rs    # CORS
│   │   ├── 📄 logging_middleware.rs # Logging
│   │   └── 📄 rate_limit_middleware.rs # Limitation de débit
│   │
│   ├── 📂 utils/                    # Utilitaires
│   │   └── 📄 mod.rs                # Fonctions utilitaires
│   │
│   └── 📂 errors/                   # Gestion d'erreurs
│       └── 📄 mod.rs                # Types d'erreurs personnalisés
│
├── 📂 migrations/                   # Migrations SQL
│   ├── 📄 001_initial_schema.sql    # Schéma initial avec sécurité
│   └── 📄 002_seed_data.sql         # Données de base
│
├── 📂 nginx/                        # Configuration Nginx
│   ├── 📄 nginx.conf                # Reverse proxy TLS 1.3
│   └── 📂 ssl/                      # Certificats SSL (générés)
│
└── 📂 scripts/                      # Scripts d'automatisation
    ├── 📄 deploy.sh                 # Déploiement automatisé
    ├── 📄 backup.sh                 # Sauvegarde sécurisée
    └── 📄 test.sh                   # Suite de tests complète
```

## 🔧 Technologies Utilisées

### Backend
- **Rust 2021** - Langage principal
- **Actix-web** - Framework web moderne
- **Tokio** - Runtime asynchrone
- **SQLx** - ORM type-safe
- **PostgreSQL** - Base de données

### Sécurité
- **AES-256-GCM** - Chiffrement des données sensibles
- **Argon2id** - Hachage des mots de passe
- **SHA-512** - Intégrité des données
- **JWT** - Authentification stateless
- **TLS 1.3** - Chiffrement des communications

### Infrastructure
- **Docker** - Conteneurisation
- **Docker Compose** - Orchestration
- **Nginx** - Reverse proxy
- **PostgreSQL** - Base de données sécurisée

## 🚀 Commandes Principales

```bash
# Installation complète
make install

# Déploiement
make deploy

# Tests complets
make test

# Développement
make dev

# Sauvegarde
make backup

# Surveillance
make logs
make status
make health
```

## 🔐 Fonctionnalités de Sécurité

### Chiffrement
- **Données au repos** : AES-256-GCM
- **Communications** : TLS 1.3
- **Mots de passe** : Argon2id
- **Intégrité** : SHA-512

### Authentification
- **JWT sécurisés** avec expiration
- **Protection anti-brute force**
- **Verrouillage temporaire**
- **Audit complet** des connexions

### Architecture
- **Défense en profondeur**
- **Séparation des composants**
- **Principe du moindre privilège**
- **Traçabilité exhaustive**

## 📊 Modèle de Données

### Visiteurs
- **4 numéros de téléphone** (2 obligatoires, 2 optionnels)
- **Données personnelles chiffrées**
- **Photo intégrée**
- **Hash d'intégrité**

### Visites
- **Cycle de vie complet**
- **Badges sécurisés**
- **Validation directeur**
- **Traçabilité temporelle**

### Audit
- **Toutes les actions tracées**
- **Horodatage précis**
- **Adresses IP et User-Agent**
- **Détection d'anomalies**

## 🌐 API Endpoints

### Publics
- `GET /` - Page d'accueil
- `GET /health` - Santé de l'application
- `POST /api/auth/login` - Connexion
- `POST /api/auth/register` - Inscription

### Protégés (JWT requis)
- `POST /api/auth/logout` - Déconnexion
- `GET /api/auth/validate` - Validation token
- `GET /api/visitors` - Liste visiteurs
- `POST /api/visitors` - Créer visiteur
- `GET /api/visits` - Liste visites
- `POST /api/visits` - Créer visite

## 📈 Monitoring

### Logs
- **Application** : Structured logging avec tracing
- **Base de données** : Requêtes et performances
- **Nginx** : Accès et erreurs
- **Audit** : Actions utilisateurs

### Métriques
- **Visiteurs** : Total, journalier, hebdomadaire
- **Visites** : Par statut, département, période
- **Performance** : Temps de réponse, throughput
- **Sécurité** : Tentatives d'intrusion, anomalies

## 🔄 Déploiement

### Environnements
- **Développement** : `cargo run`
- **Test** : `make test`
- **Production** : `make deploy`

### Configuration
- **Variables d'environnement** : `.env`
- **[REDACTED] : Chiffrement externe
- **Certificats** : TLS 1.3
- **Base de données** : PostgreSQL sécurisée

---

**DCOP (413) - Portail des Visites**  
*Architecture sécurisée • Performance optimisée • Traçabilité complète*
