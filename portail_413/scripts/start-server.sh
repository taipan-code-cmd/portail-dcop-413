#!/bin/bash
set -euo pipefail

# DCOP (413) - Script de Démarrage Intelligent du Serveur
# Gestion automatique des conflits de ports et initialisation complète

set -euo pipefail

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

log_step() {
    echo -e "${CYAN}[ÉTAPE]${NC} $1"
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}"")"
POSTGRES_PORT=5433
APP_PORT=8443

# Fonction pour vérifier si un port est libre
check_port() {
    local port=$1
    if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
        return 1  # Port occupé
    else
        return 0  # Port libre
    fi
}

# Fonction pour arrêter les services conflictuels
stop_conflicting_services() {
    log_step "Vérification des conflits de ports..."
    
    # Vérifier le port PostgreSQL (5433)
    if ! check_port "${POSTGRES_PORT}"; then
        log_warning "Port "${POSTGRES_PORT}" occupé, tentative d'arrêt des services conflictuels..."
        docker stop $(docker ps -q --filter "publish="${POSTGRES_PORT}"") 2>/dev/null || true
        sleep 2
    fi
    
    # Vérifier le port de l'application (8443)
    if ! check_port "${APP_PORT}"; then
        log_warning "Port "${APP_PORT}" occupé, tentative d'arrêt des services conflictuels..."
        docker stop $(docker ps -q --filter "publish="${APP_PORT}"") 2>/dev/null || true
        sleep 2
    fi
    
    log_success "Vérification des ports terminée"
}

# Fonction pour démarrer PostgreSQL
start_postgres() {
    log_step "Démarrage de PostgreSQL sécurisé (port "${POSTGRES_PORT}")..."
    
    cd "${PROJECT_DIR}""
    
    # Démarrer uniquement PostgreSQL
    docker-compose up -d postgres
    
    # Attendre que PostgreSQL soit prêt
    log_info "Attente de l'initialisation de PostgreSQL..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose exec -T postgres pg_isready -U dcop_user -d dcop_413 >/dev/null 2>&1; then
            log_success "PostgreSQL est prêt !"
            return 0
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    log_error "PostgreSQL n'a pas pu démarrer dans les temps"
    return 1
}

# Fonction pour exécuter les migrations
run_migrations() {
    log_step "Exécution des migrations de base de données..."
    
    cd "${PROJECT_DIR}""
    
    # Charger les variables d'environnement
    source .env
    
    # Exécuter les migrations SQLx
    if command -v sqlx &> /dev/null; then
        sqlx migrate run
        log_success "Migrations exécutées avec succès"
    else
        log_warning "SQLx CLI non trouvé, installation..."
        cargo install sqlx-cli --no-default-features --features postgres
        sqlx migrate run
        log_success "Migrations exécutées avec succès"
    fi
}

# Fonction pour générer le cache SQLx
generate_sqlx_cache() {
    log_step "Génération du cache SQLx..."
    
    cd "${PROJECT_DIR}""
    source .env
    
    # Générer le cache
    cargo sqlx prepare
    log_success "Cache SQLx généré"
}

# Fonction pour démarrer l'application
start_application() {
    log_step "Démarrage de l'application DCOP (413)..."
    
    cd "${PROJECT_DIR}""
    
    # Compilation et démarrage
    log_info "Compilation de l'application..."
    cargo build --release
    
    log_info "Démarrage du serveur sur le port "${APP_PORT}"..."
    cargo run --release &
    
    # Sauvegarder le PID
    echo $! > .server.pid
    
    log_success "Serveur démarré (PID: $!)"
}

# Fonction pour vérifier le statut du serveur
check_server_status() {
    log_step "Vérification du statut du serveur..."
    
    local max_attempts=10
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl --max-time 10 --retry 3 -k -s https://localhost:"${APP_PORT}"/health >/dev/null 2>&1; then
            log_success "✅ Serveur DCOP (413) opérationnel !"
            log_info "🌐 URL: https://localhost:"${APP_PORT}""
            log_info "📊 Health Check: https://localhost:"${APP_PORT}"/health"
            return 0
        fi
        
        echo -n "."
        sleep 3
        ((attempt++))
    done
    
    log_warning "Le serveur ne répond pas encore, mais il peut encore être en cours de démarrage"
    return 1
}

# Fonction pour afficher les informations de connexion
show_connection_info() {
    echo
    log_success "🎉 DCOP (413) - SERVEUR DÉMARRÉ AVEC SUCCÈS !"
    echo
    echo -e "${CYAN}📋 INFORMATIONS DE CONNEXION :${NC}"
    echo -e "   🌐 Application Web : ${GREEN}https://localhost:"${APP_PORT}"${NC}"
    echo -e "   🗄️  Base de données : ${GREEN}localhost:"${POSTGRES_PORT}"${NC}"
    echo -e "   👤 Utilisateur DB : ${GREEN}dcop_user${NC}"
    echo -e "   🔑 Mot de passe : ${GREEN}dcop_password_123${NC}"
    echo
    echo -e "${CYAN}🛠️  COMMANDES UTILES :${NC}"
    echo -e "   📊 Logs du serveur : ${YELLOW}docker-compose logs -f app${NC}"
    echo -e "   🗄️  Connexion DB : ${YELLOW}./scripts/db-password-manager.sh connect${NC}"
    echo -e "   🛑 Arrêter le serveur : ${YELLOW}./scripts/stop-server.sh${NC}"
    echo
}

# Fonction principale
main() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    DCOP (413) - SERVEUR                     ║"
    echo "║              Démarrage Intelligent et Sécurisé              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Étapes de démarrage
    stop_conflicting_services
    start_postgres
    
    # Attendre un peu plus pour la stabilisation
    sleep 5
    
    run_migrations
    generate_sqlx_cache
    start_application
    
    # Vérification finale
    sleep 10
    check_server_status
    
    show_connection_info
}

# Gestion des erreurs
trap 'log_error "Erreur lors du démarrage du serveur"' ERR

# Exécution
main "$@"
