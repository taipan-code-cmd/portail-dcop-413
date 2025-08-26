#!/bin/bash
set -euo pipefail

# DCOP (413) - Script de Maintenance
# Nettoyage et maintenance du projet

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

log_step() {
    echo -e "${CYAN}[ÉTAPE]${NC} $1"
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}"")"

# Fonction pour nettoyer les fichiers de build
clean_build_files() {
    log_step "Nettoyage des fichiers de build..."
    
    cd "${PROJECT_DIR}""
    
    # Nettoyage Cargo
    cargo clean
    
    # Suppression des fichiers temporaires
    find . -name "*.tmp" -delete 2>/dev/null || true
    find . -name "*~" -delete 2>/dev/null || true
    find . -name "*.bak" -delete 2>/dev/null || true
    
    log_success "Fichiers de build nettoyés"
}

# Fonction pour nettoyer les logs
clean_logs() {
    log_step "Nettoyage des logs..."
    
    cd "${PROJECT_DIR}""
    
    # Nettoyer les logs anciens (plus de 7 jours)
    if [[ -d "logs" ]]; then
        find logs/ -name "*.log" -mtime +7 -delete 2>/dev/null || true
        log_success "Logs anciens supprimés"
    else
        log_info "Aucun répertoire de logs trouvé"
    fi
}

# Fonction pour nettoyer les conteneurs Docker
clean_docker() {
    log_step "Nettoyage des ressources Docker..."
    
    # Arrêter les conteneurs orphelins
    docker-compose down --remove-orphans 2>/dev/null || true
    
    # Nettoyer les images non utilisées
    docker image prune -f 2>/dev/null || true
    
    # Nettoyer les volumes non utilisés (avec prudence)
    log_warning "Nettoyage des volumes Docker (volumes non utilisés uniquement)..."
    docker volume prune -f 2>/dev/null || true
    
    log_success "Ressources Docker nettoyées"
}

# Fonction pour vérifier l'intégrité du projet
check_integrity() {
    log_step "Vérification de l'intégrité du projet..."
    
    cd "${PROJECT_DIR}""
    
    # Vérifier les fichiers essentiels
    local essential_files=(
        "Cargo.toml"
        "docker-compose.yml"
        ".env.example"
        "scripts/start-server.sh"
        "scripts/stop-server.sh"
        "config/postgresql.conf"
        "config/pg_hba.conf"
    )
    
    local missing_files=()
    
    for file in "${essential_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            missing_files+=("$file")
        fi
    done
    
    if [[ ${#missing_files[@]} -eq 0 ]]; then
        log_success "Tous les fichiers essentiels sont présents"
    else
        log_warning "Fichiers manquants : ${missing_files[*]}"
    fi
}

# Fonction pour afficher les statistiques du projet
show_stats() {
    log_step "Statistiques du projet..."
    
    cd "${PROJECT_DIR}""
    
    echo -e "${CYAN}📊 STATISTIQUES DCOP (413) :${NC}"
    echo -e "   📁 Fichiers Rust : $(find src/ -name "*.rs" | wc -l)"
    echo -e "   🐳 Services Docker : $(grep -c "^  [a-z]" docker-compose.yml || echo "0")"
    echo -e "   📜 Scripts : $(ls scripts/*.sh 2>/dev/null | wc -l)"
    echo -e "   🗄️  Migrations : $(ls migrations/*.sql 2>/dev/null | wc -l)"
    echo -e "   🔐 Secrets : $(ls secrets/*.txt 2>/dev/null | wc -l)"
    
    # Taille du projet
    local project_size=$(du -sh . 2>/dev/null | cut -f1)
    echo -e "   💾 Taille totale : $project_size"
}

# Fonction pour mettre à jour les dépendances
update_dependencies() {
    log_step "Mise à jour des dépendances..."
    
    cd "${PROJECT_DIR}""
    
    # Mise à jour Cargo
    cargo update
    
    log_success "Dépendances mises à jour"
}

# Fonction principale
main() {
    local action="${1:-all}"
    
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    DCOP (413) - MAINTENANCE                 ║"
    echo "║                  Nettoyage et Optimisation                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    case "$action" in
        "clean")
            clean_build_files
            clean_logs
            ;;
        "docker")
            clean_docker
            ;;
        "check")
            check_integrity
            ;;
        "stats")
            show_stats
            ;;
        "update")
            update_dependencies
            ;;
        "all")
            clean_build_files
            clean_logs
            clean_docker
            check_integrity
            update_dependencies
            show_stats
            ;;
        *)
            echo "Usage: $0 [clean|docker|check|stats|update|all]"
            echo
            echo "Actions disponibles :"
            echo "  clean  - Nettoyer les fichiers de build et logs"
            echo "  docker - Nettoyer les ressources Docker"
            echo "  check  - Vérifier l'intégrité du projet"
            echo "  stats  - Afficher les statistiques"
            echo "  update - Mettre à jour les dépendances"
            echo "  all    - Effectuer toutes les actions (défaut)"
            exit 1
            ;;
    esac
    
    echo
    log_success "🧹 MAINTENANCE TERMINÉE AVEC SUCCÈS !"
}

# Exécution
main "$@"
