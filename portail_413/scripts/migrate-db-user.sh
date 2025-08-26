#!/bin/bash
set -euo pipefail

# DCOP (413) - Script de migration de l'utilisateur de base de données
# Remplace dcop_user (superutilisateur) par app_user (privilèges minimaux)

set -euo pipefail

# Configuration
DB_NAME="dcop_413"
OLD_USER="dcop_user"
NEW_USER="app_user"
POSTGRES_CONTAINER="dcop_postgres_secure"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction d'affichage
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Vérification des prérequis
check_prerequisites() {
    log "Vérification des prérequis..."
    
    if ! command -v docker &> /dev/null; then
        error "Docker n'est pas installé ou accessible"
        exit 1
    fi
    
    if ! docker ps | grep -q "${POSTGRES_CONTAINER}""; then
        error "Le conteneur PostgreSQL '"${POSTGRES_CONTAINER}"' n'est pas en cours d'exécution"
        exit 1
    fi
    
    success "Prérequis validés"
}

# Génération d'un mot de passe sécurisé
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Création du nouvel utilisateur avec privilèges minimaux
create_app_user() {
    log "Création de l'utilisateur app_user avec privilèges minimaux..."
    
    # Générer un nouveau mot de passe
    NEW_PASSWORD=$(generate_password)
    
    # Créer l'utilisateur dans PostgreSQL
    docker exec -i "${POSTGRES_CONTAINER}"" psql -U postgres -d "${DB_NAME}"" << EOF
-- Créer l'utilisateur app_user s'il n'existe pas
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '"${NEW_USER}"') THEN
        CREATE USER "${NEW_USER}" WITH PASSWORD '"${NEW_PASSWORD}"';
        RAISE NOTICE 'Utilisateur "${NEW_USER}" créé avec succès';
    ELSE
        ALTER USER "${NEW_USER}" WITH PASSWORD '"${NEW_PASSWORD}"';
        RAISE NOTICE 'Mot de passe de "${NEW_USER}" mis à jour';
    END IF;
END
\$\$;

-- Révoquer tous les privilèges par défaut
REVOKE ALL ON DATABASE "${DB_NAME}" FROM "${NEW_USER}";
REVOKE ALL ON SCHEMA public FROM "${NEW_USER}";

-- Accorder uniquement les privilèges nécessaires
GRANT CONNECT ON DATABASE "${DB_NAME}" TO "${NEW_USER}";
GRANT USAGE ON SCHEMA public TO "${NEW_USER}";

-- Privilèges sur les tables existantes
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "${NEW_USER}";

-- Privilèges sur les séquences
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "${NEW_USER}";

-- Privilèges sur les fonctions
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO "${NEW_USER}";

-- Privilèges par défaut pour les futures tables/séquences
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "${NEW_USER}";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "${NEW_USER}";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO "${NEW_USER}";

-- Vérification des privilèges
\dp
EOF

    # Sauvegarder le nouveau mot de passe
    echo "${NEW_PASSWORD}"" > ../secrets/postgres_password_new.txt
    chmod 600 ../secrets/postgres_password_new.txt
    
    success "Utilisateur app_user créé avec privilèges minimaux"
    warning "Nouveau mot de passe sauvegardé dans secrets/postgres_password_new.txt"
}

# Test de connexion avec le nouvel utilisateur
test_new_user() {
    log "Test de connexion avec le nouvel utilisateur..."
    
    NEW_PASSWORD=$(cat ../secrets/postgres_password_new.txt)
    
    if docker exec -i "${POSTGRES_CONTAINER}"" psql -U "${NEW_USER}"" -d "${DB_NAME}"" -c "SELECT current_user, current_database();" > /dev/null 2>&1; then
        success "Connexion réussie avec l'utilisateur "${NEW_USER}""
    else
        error "Échec de la connexion avec l'utilisateur "${NEW_USER}""
        exit 1
    fi
}

# Mise à jour de la configuration Docker
update_docker_config() {
    log "Mise à jour de la configuration Docker..."
    
    # Backup du fichier docker-compose.yml
    cp ../docker-compose.yml ../docker-compose.yml.backup
    
    # Remplacer dcop_user par app_user dans docker-compose.yml
    sed -i "s/POSTGRES_USER: "${OLD_USER}"/POSTGRES_USER: "${NEW_USER}"/g" ../docker-compose.yml
    sed -i "s/dcop_user/"${NEW_USER}"/g" ../docker-compose.yml
    
    success "Configuration Docker mise à jour"
    warning "Backup sauvegardé dans docker-compose.yml.backup"
}

# Fonction principale
main() {
    log "Début de la migration de l'utilisateur de base de données"
    
    check_prerequisites
    create_app_user
    test_new_user
    update_docker_config
    
    success "Migration terminée avec succès !"
    echo ""
    echo "Prochaines étapes :"
    echo "1. Remplacer le contenu de secrets/postgres_password.txt" par celui de secrets/postgres_password_new.txt"
    echo "2. Redémarrer les conteneurs : docker-compose down && docker-compose up -d"
    echo "3. Tester l'application"
    echo "4. Supprimer l'ancien utilisateur dcop_user si tout fonctionne"
}

# Exécution du script
main "$@"
