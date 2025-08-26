#!/bin/bash
set -euo pipefail

# DCOP (413) - Gestionnaire de Mot de Passe PostgreSQL
# Script sécurisé pour gérer et utiliser le mot de passe de la base de données

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

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}"")"
SECRETS_DIR="${PROJECT_DIR}"/secrets"
PASSWORD_FILE="${SECRETS_DIR}"/postgres_password.txt""
ENV_FILE="${PROJECT_DIR}"/.env"

# Fonction pour récupérer le mot de passe
get_password() {
    if [[ -f "${PASSWORD_FILE}"" ]]; then
        cat "${PASSWORD_FILE}""
    else
        log_error "Fichier de mot de passe non trouvé : "${PASSWORD_FILE}""
        exit 1
    fi
}

# Fonction pour afficher le mot de passe
show_password() {
    log_info "=== MOT DE PASSE POSTGRESQL DCOP (413) ==="
    echo
    echo "Utilisateur : dcop_user"
    echo "Base de données : dcop_413"
    echo "Port : 5433 (conteneur sécurisé)"
    echo "Mot de passe : $(get_password)"
    echo
    log_warning "⚠️  Ce mot de passe est sensible - ne le partagez pas !"
}

# Fonction pour copier le mot de passe dans le presse-papiers
copy_password() {
    local password=$(get_password)
    
    if command -v xclip &> /dev/null; then
        echo -n "$password" | xclip -selection clipboard
        log_success "Mot de passe copié dans le presse-papiers (xclip)"
    elif command -v pbcopy &> /dev/null; then
        echo -n "$password" | pbcopy
        log_success "Mot de passe copié dans le presse-papiers (pbcopy)"
    elif command -v wl-copy &> /dev/null; then
        echo -n "$password" | wl-copy
        log_success "Mot de passe copié dans le presse-papiers (wl-copy)"
    else
        log_warning "Aucun outil de presse-papiers trouvé"
        log_info "Mot de passe : $password"
    fi
}

# Fonction pour se connecter à PostgreSQL
connect_db() {
    local password=$(get_password)
    log_info "Connexion à PostgreSQL..."
    
    # Exporter le mot de passe pour psql
    export PGPASSWORD="$password"
    
    if command -v psql &> /dev/null; then
        psql -h localhost -p 5433 -U dcop_user -d dcop_413
    else
        log_info "psql non trouvé, utilisation de Docker..."
        echo "$password" | docker-compose -f "${PROJECT_DIR}"/docker-compose.yml" exec -T postgres psql -U dcop_user -d dcop_413
    fi
}

# Fonction pour exécuter une commande SQL
execute_sql() {
    local sql_command="$1"
    local password=$(get_password)
    
    log_info "Exécution de la commande SQL..."
    export PGPASSWORD="$password"
    
    if command -v psql &> /dev/null; then
        psql -h localhost -p 5433 -U dcop_user -d dcop_413 -c "$sql_command"
    else
        echo "$password" | docker-compose -f "${PROJECT_DIR}"/docker-compose.yml" exec -T postgres psql -U dcop_user -d dcop_413 -c "$sql_command"
    fi
}

# Fonction pour générer le cache SQLx
generate_sqlx_cache() {
    local password=$(get_password)
    log_info "Génération du cache SQLx..."
    
    cd "${PROJECT_DIR}""
    
    # Charger les variables d'environnement
    if [[ -f "${ENV_FILE}"" ]]; then
        source "${ENV_FILE}""
    fi
    
    # Exporter le mot de passe
    export PGPASSWORD="$password"
    export DATABASE_URL="postgresql://dcop_user:$password@localhost:5433/dcop_413"
    
    # Générer le cache
    cargo sqlx prepare
    
    log_success "Cache SQLx généré avec succès !"
}

# Fonction pour tester la connexion
test_connection() {
    log_info "Test de connexion à PostgreSQL..."
    
    if execute_sql "SELECT current_user, current_database(), version();" &> /dev/null; then
        log_success "✅ Connexion PostgreSQL réussie !"
        execute_sql "SELECT current_user as utilisateur, current_database() as base_donnees;"
    else
        log_error "❌ Échec de la connexion PostgreSQL"
        exit 1
    fi
}

# Fonction d'aide
show_help() {
    echo "DCOP (413) - Gestionnaire de Mot de Passe PostgreSQL"
    echo
    echo "Usage: $0 [COMMANDE]"
    echo
    echo "Commandes disponibles :"
    echo "  show       Afficher les informations de connexion"
    echo "  copy       Copier le mot de passe dans le presse-papiers"
    echo "  connect    Se connecter à PostgreSQL"
    echo "  test       Tester la connexion"
    echo "  sql        Exécuter une commande SQL (usage: $0 sql \"SELECT ...\")"
    echo "  sqlx       Générer le cache SQLx"
    echo "  help       Afficher cette aide"
    echo
    echo "Exemples :"
    echo "  $0 show                           # Afficher les infos de connexion"
    echo "  $0 copy                           # Copier le mot de passe"
    echo "  $0 connect                        # Se connecter à la DB"
    echo "  $0 test                           # Tester la connexion"
    echo "  $0 sql \"SELECT COUNT(*) FROM users;\"  # Exécuter une requête"
    echo "  $0 sqlx                           # Générer le cache SQLx"
}

# Fonction principale
main() {
    local command="${1:-help}"
    
    case "$command" in
        "show")
            show_password
            ;;
        "copy")
            copy_password
            ;;
        "connect")
            connect_db
            ;;
        "test")
            test_connection
            ;;
        "sql")
            if [[ $# -lt 2 ]]; then
                log_error "Commande SQL manquante"
                echo "Usage: $0 sql \"SELECT ...\""
                exit 1
            fi
            execute_sql "$2"
            ;;
        "sqlx")
            generate_sqlx_cache
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "Commande inconnue : $command"
            show_help
            exit 1
            ;;
    esac
}

# Vérifications préliminaires
if [[ ! -f "${PASSWORD_FILE}"" ]]; then
    log_error "Fichier de mot de passe non trouvé : "${PASSWORD_FILE}""
    exit 1
fi

# Exécution
main "$@"
