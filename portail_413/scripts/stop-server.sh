#!/bin/bash
set -euo pipefail

# DCOP (413) - Script d'Arrêt Propre du Serveur
# Arrêt sécurisé de tous les services

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

# Fonction pour arrêter l'application Rust
stop_rust_app() {
    log_step "Arrêt de l'application Rust..."
    
    cd "${PROJECT_DIR}""
    
    # Arrêter via le PID sauvegardé
    if [[ -f ".server.pid" ]]; then
        local pid=$(cat .server.pid)
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Arrêt du processus $pid..."
            kill -TERM "$pid"
            sleep 3
            
            # Vérifier si le processus est toujours actif
            if kill -0 "$pid" 2>/dev/null; then
                log_warning "Arrêt forcé du processus $pid..."
                kill -KILL "$pid"
            fi
            
            rm -f .server.pid
            log_success "Application Rust arrêtée"
        else
            log_info "Aucun processus actif trouvé"
            rm -f .server.pid
        fi
    else
        log_info "Aucun fichier PID trouvé, recherche des processus..."
        pkill -f "portail_413" || log_info "Aucun processus portail_413 trouvé"
    fi
}

# Fonction pour arrêter Docker Compose
stop_docker_services() {
    log_step "Arrêt des services Docker..."
    
    cd "${PROJECT_DIR}""
    
    # Arrêter tous les services Docker Compose
    docker-compose down
    
    log_success "Services Docker arrêtés"
}

# Fonction pour nettoyer les ressources
cleanup_resources() {
    log_step "Nettoyage des ressources..."
    
    cd "${PROJECT_DIR}""
    
    # Nettoyer les fichiers temporaires
    rm -f .server.pid
    
    # Nettoyer les logs temporaires (optionnel)
    # rm -f logs/*.log
    
    log_success "Nettoyage terminé"
}

# Fonction pour vérifier l'arrêt complet
verify_shutdown() {
    log_step "Vérification de l'arrêt complet..."
    
    local ports=(5433 8443)
    local all_free=true
    
    for port in "${ports[@]}"; do
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            log_warning "Port $port encore occupé"
            all_free=false
        else
            log_info "Port $port libéré ✓"
        fi
    done
    
    if $all_free; then
        log_success "Tous les ports sont libérés"
    else
        log_warning "Certains ports sont encore occupés"
    fi
}

# Fonction principale
main() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    DCOP (413) - SERVEUR                     ║"
    echo "║                    Arrêt Propre et Sécurisé                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Étapes d'arrêt
    stop_rust_app
    stop_docker_services
    cleanup_resources
    verify_shutdown
    
    echo
    log_success "🛑 DCOP (413) - SERVEUR ARRÊTÉ AVEC SUCCÈS !"
    echo
}

# Gestion des erreurs
trap 'log_error "Erreur lors de l arrêt du serveur"' ERR

# Exécution
main "$@"
