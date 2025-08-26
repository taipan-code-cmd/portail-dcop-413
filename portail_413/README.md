# DCOP (413) - Portail des Visites

## 🛡️ Système Sécurisé de Gestion des Visiteurs

**DCOP (413)** est une application web haute sécurité développée en Rust pour l'enregistrement, la gestion et le suivi des visiteurs d'un site à haute sensibilité. L'application respecte les normes modernes du génie logiciel avec une architecture modulaire, segmentée et résiliente.

![Logo DCOP](docs/images/dcop_logo.png)

## 🎯 Objectifs Principaux

- **Enregistrement sécurisé** des visiteurs avec chiffrement des données sensibles
- **Gestion complète** du cycle de vie des visites
- **Traçabilité exhaustive** de toutes les opérations
- **Interface intuitive** pour les utilisateurs et administrateurs
- **Sécurité renforcée** avec défense en profondeur

## 🏗️ Architecture Technique

### Technologies Principales
- **Langage** : Rust (Edition 2021)
- **Framework Web** : Actix-web avec Tokio
- **Base de données** : PostgreSQL avec extensions de sécurité
- **Conteneurisation** : Docker & Docker Compose
- **Reverse Proxy** : Nginx avec TLS 1.3

### Principes de Sécurité
- **Chiffrement des communications** : TLS 1.3
- **Chiffrement des données au repos** : AES-256-GCM
- **Hachage des mots de passe** : Argon2id
- **Intégrité des données** : SHA-512
- **Authentification** : JWT avec rotation
- **Audit complet** : Traçabilité de toutes les actions

## 🚀 Installation et Déploiement

### Prérequis
- Docker 20.10+
- Docker Compose 2.0+
- Git
- OpenSSL (pour les certificats)

### Déploiement Rapide

1. **Cloner le repository**
```bash
git clone <repository-url>
cd portail_413
```

2. **Configuration**
```bash
cp .env.example .env
# Modifier les valeurs dans .env (OBLIGATOIRE pour la production)
```

3. **Déploiement automatisé**
```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

4. **Accès à l'application**
- **HTTPS** : https://localhost
- **API Health** : https://localhost/health
- **Port interne** : 8443

### Configuration Manuelle

1. **Variables d'environnement critiques** (à modifier obligatoirement) :
```bash
JWT_[REDACTED]
ENCRYPTION_KEY=votre_cle_chiffrement_32_caracteres
SECURITY_SALT=votre_sel_securise_pour_hachage
POSTGRES_[REDACTED]
```

2. **Démarrage des services**
```bash
docker-compose up -d
```

## 📊 Modèle de Données

### Visiteurs
- **Données personnelles chiffrées** : Nom, prénom, email
- **4 numéros de téléphone** : 2 obligatoires, 2 optionnels (tous chiffrés)
- **Organisation** et **photo** intégrée
- **Hash d'intégrité** SHA-512

### Visites
- **Cycle de vie complet** : Planification → Approbation → Exécution → Clôture
- **Badges sécurisés** avec numérotation unique
- **Validation directeur** pour les visites sensibles
- **Traçabilité temporelle** complète

### Utilisateurs
- **Rôles** : Admin, Utilisateur, Directeur
- **Authentification sécurisée** avec protection anti-brute force
- **Sessions** avec expiration automatique
- **Audit** de toutes les connexions

## 🔐 Fonctionnalités de Sécurité

### Authentification et Autorisation
- **Mots de passe robustes** avec validation de complexité
- **Protection anti-brute force** avec verrouillage temporaire
- **JWT sécurisés** avec expiration et rotation
- **Contrôle d'accès basé sur les rôles** (RBAC)

### Chiffrement et Intégrité
- **AES-256-GCM** pour les données sensibles
- **SHA-512** pour la vérification d'intégrité
- **Argon2id** pour les mots de passe
- **TLS 1.3** pour les communications

### Audit et Traçabilité
- **Journalisation complète** de toutes les actions
- **Horodatage précis** avec timezone UTC
- **Adresses IP** et **User-Agent** enregistrés
- **Détection d'anomalies** d'intégrité

## 🖥️ Interface Utilisateur

### Formulaire Public
- **Pré-enregistrement** accessible à tous
- **Capture photo** via webcam ou upload
- **Validation** en temps réel des données
- **Aperçu** du badge avant soumission

### Interface Administrateur
- **Tableau de bord** avec statistiques temps réel
- **Gestion des visiteurs** et des visites
- **Validation** des demandes par le directeur
- **Historique** filtrable et exportable

### Statistiques et Rapports
- **Fréquentation** : journalière, hebdomadaire, mensuelle
- **Graphiques interactifs** des pics d'activité
- **Rapports** d'audit et de sécurité
- **Export** des données (CSV, PDF)

## 🛠️ Développement

### Structure du Projet
```
portail_413/
├── src/
│   ├── config/          # Configuration
│   ├── database/        # Accès données
│   ├── handlers/        # Contrôleurs HTTP
│   ├── middleware/      # Middleware Actix-web
│   ├── models/          # Modèles de données
│   ├── security/        # Services de sécurité
│   ├── services/        # Logique métier
│   └── utils/           # Utilitaires
├── migrations/          # Migrations SQL
├── nginx/              # Configuration Nginx
├── scripts/            # Scripts de déploiement
└── docker-compose.yml  # Orchestration Docker
```

### Commandes de Développement
```bash
# Compilation
cargo build

# Tests
cargo test

# Linting
cargo clippy

# Formatage
cargo fmt

# Démarrage en mode développement
cargo run
```

## 📋 Maintenance

### Sauvegarde
```bash
chmod +x scripts/backup.sh
./scripts/backup.sh
```

### Surveillance
```bash
# Logs de l'application
docker-compose logs -f dcop_app

# Logs de la base de données
docker-compose logs -f postgres

# Logs Nginx
docker-compose logs -f nginx

# Statut des services
docker-compose ps
```

### Mise à jour
```bash
# Arrêt des services
docker-compose down

# Mise à jour du code
git pull

# Reconstruction et redémarrage
docker-compose build --no-cache
docker-compose up -d
```

## 🔒 Sécurité en Production

### Checklist de Sécurité
- [ ] Modifier tous les [REDACTED] par défaut
- [ ] Installer des certificats SSL valides
- [ ] Configurer un firewall approprié
- [ ] Activer la surveillance des logs
- [ ] Planifier les sauvegardes automatiques
- [ ] Tester la procédure de restauration
- [ ] Configurer les alertes de sécurité

### Recommandations
- **Audit de sécurité** régulier par un expert
- **Mise à jour** fréquente des dépendances
- **Surveillance** continue des logs d'audit
- **Formation** du personnel sur les procédures

## 📞 Support

### Documentation
- **API** : `/docs` (Swagger/OpenAPI)
- **Architecture** : `docs/architecture.md`
- **Sécurité** : `docs/security.md`

### Contact
- **Équipe DCOP** : dcop-support@example.com
- **Urgences sécurité** : security@example.com

## 📄 Licence

Ce projet est développé pour le **Conseil National de Cyberdéfense** de la République Démocratique du Congo.

## 🛠️ Outils de Gestion

### Scripts Principaux
```bash
# Démarrage automatique complet
./scripts/start-server.sh

# Arrêt propre du serveur
./scripts/stop-server.sh

# Gestion de la base de données
./scripts/db-[REDACTED] [show|connect|test|sqlx]

# Maintenance du projet
./scripts/maintenance.sh [clean|docker|check|stats|update|all]
```

### Configuration Optimisée
- **PostgreSQL 16** sur port dédié 5433 (évite les conflits)
- **Authentification SCRAM-SHA-256** sécurisée
- **Configuration personnalisée** pour performance et sécurité
- **Gestion automatique des [REDACTED] via Docker [REDACTED]

---

**DCOP (413) - Portail des Visites**
*Sécurité • Performance • Traçabilité*
