#!/bin/bash
set -euo pipefail

# DCOP (413) - Générateur de secrets sécurisés
# Génère tous les secrets nécessaires pour l'application

set -euo pipefail

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Fonction pour générer un secret cryptographiquement fort avec CSPRNG
# Conforme aux exigences OWASP A02:2021 (minimum 256 bits)
generate_secret() {
    local bytes=$1
    local min_bytes=32  # 256 bits minimum

    if [ "$bytes" -lt "$min_bytes" ]; then
        log_error "Secret trop faible: $bytes bytes < $min_bytes bytes (256 bits minimum)"
        exit 1
    fi

    # Utiliser OpenSSL avec CSPRNG pour générer des bytes aléatoires sécurisés
    openssl rand -base64 $bytes | tr -d "=+/\n"
}

# Fonction pour générer une clé de chiffrement de 256 bits (32 bytes)
generate_encryption_key() {
    generate_secret 32  # 256 bits
}

# Fonction pour générer un secret JWT de 512 bits (64 bytes)
generate_jwt_secret() {
    generate_secret 64  # 512 bits
}

# Fonction pour générer un sel de sécurité de 384 bits (48 bytes)
generate_security_salt() {
    generate_secret 48  # 384 bits
}

# Fonction pour générer un mot de passe PostgreSQL de 256 bits (32 bytes)
generate_postgres_password() {
    generate_secret 32  # 256 bits
}

# Créer le répertoire des secrets
create_secrets_dir() {
    log_info "Création du répertoire des secrets..."
    
    mkdir -p secrets
    chmod 700 secrets
    
    log_success "Répertoire des secrets créé avec permissions 700"
}

# Générer le mot de passe PostgreSQL avec 256 bits de sécurité
generate_postgres_password_file() {
    log_info "Génération du mot de passe PostgreSQL (256 bits)..."

    local password=$(generate_postgres_password)
    echo -n "$password" > secrets/postgres_password.txt"
    chmod 600 secrets/postgres_password.txt"

    log_success "Mot de passe PostgreSQL généré: $(echo -n "$password" | wc -c) caractères"
}

# Générer le secret JWT avec 512 bits de sécurité
generate_jwt_secret_file() {
    log_info "Génération du secret JWT (512 bits)..."

    local secret=$(generate_jwt_secret)
    echo -n "$secret" > secrets/jwt_secret.txt
    chmod 600 secrets/jwt_secret.txt

    log_success "Secret JWT généré: $(echo -n "$secret" | wc -c) caractères"
}

# Générer la clé de chiffrement avec 256 bits de sécurité
generate_encryption_key_file() {
    log_info "Génération de la clé de chiffrement (256 bits)..."

    local key=$(generate_encryption_key)
    echo -n "$key" > secrets/encryption_key.txt
    chmod 600 secrets/encryption_key.txt

    log_success "Clé de chiffrement générée: $(echo -n "$key" | wc -c) caractères"
}

# Générer le sel de sécurité avec 384 bits de sécurité
generate_security_salt_file() {
    log_info "Génération du sel de sécurité (384 bits)..."

    local salt=$(generate_security_salt)
    echo -n "$salt" > secrets/security_salt.txt
    chmod 600 secrets/security_salt.txt

    log_success "Sel de sécurité généré: $(echo -n "$salt" | wc -c) caractères"
}

# Vérifier les prérequis
check_prerequisites() {
    log_info "Vérification des prérequis..."
    
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL n'est pas installé"
        exit 1
    fi
    
    log_success "Prérequis vérifiés"
}

# Afficher le résumé
show_summary() {
    log_info "=== RÉSUMÉ DES SECRETS GÉNÉRÉS ==="
    echo ""
    log_success "Secrets créés dans le répertoire ./secrets/ :"
    echo "  - postgres_password.txt" (32 caractères)"
    echo "  - jwt_secret.txt (64 caractères)"
    echo "  - encryption_key.txt (32 caractères hex)"
    echo "  - security_salt.txt (48 caractères)"
    echo ""
    log_warning "IMPORTANT :"
    echo "  - Ces fichiers contiennent des secrets critiques"
    echo "  - Permissions définies à 600 (lecture/écriture propriétaire uniquement)"
    echo "  - Ne jamais commiter ces fichiers dans Git"
    echo "  - Sauvegarder ces secrets de manière sécurisée"
    echo ""
    log_info "Prochaines étapes :"
    echo "  1. Vérifier que .gitignore exclut le répertoire secrets/"
    echo "  2. Démarrer l'application : docker-compose up -d"
    echo "  3. Les secrets seront automatiquement montés dans les conteneurs"
}

# Fonction principale
main() {
    log_info "=== GÉNÉRATION DES SECRETS DCOP (413) ==="
    
    check_prerequisites
    create_secrets_dir
    generate_postgres_password_file
    generate_jwt_secret_file
    generate_encryption_key_file
    generate_security_salt_file
    show_summary
    
    log_success "Génération des secrets terminée avec succès !"
}

# Gestion des erreurs
trap 'log_error "Erreur lors de la génération des secrets"; exit 1' ERR

# Exécution
main "$@"
