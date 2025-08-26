#!/bin/bash
set -euo pipefail

# DCOP (413) - Script de Monitoring de Sécurité NGINX
# Surveillance en temps réel des tentatives d'intrusion et attaques

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

log_alert() {
    echo -e "${RED}[ALERT]${NC} $1"
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}"")"
LOG_DIR="/var/log/nginx"

# Fonction pour analyser les logs d'attaque
analyze_attacks() {
    log_info "Analyse des tentatives d'attaque..."
    
    local today=$(date +%Y-%m-%d)
    
    # Tentatives d'injection SQL
    if docker-compose exec -T nginx test -f /var/log/nginx/sql_injection.log; then
        local sql_attacks=$(docker-compose exec -T nginx grep "$today" /var/log/nginx/sql_injection.log 2>/dev/null | wc -l)
        if [[ $sql_attacks -gt 0 ]]; then
            log_alert "🚨 $sql_attacks tentatives d'injection SQL détectées aujourd'hui"
        fi
    fi
    
    # Tentatives XSS
    if docker-compose exec -T nginx test -f /var/log/nginx/xss_attempts.log; then
        local xss_attacks=$(docker-compose exec -T nginx grep "$today" /var/log/nginx/xss_attempts.log 2>/dev/null | wc -l)
        if [[ $xss_attacks -gt 0 ]]; then
            log_alert "🚨 $xss_attacks tentatives XSS détectées aujourd'hui"
        fi
    fi
    
    # User agents suspects
    if docker-compose exec -T nginx test -f /var/log/nginx/suspicious_agents.log; then
        local suspicious_agents=$(docker-compose exec -T nginx grep "$today" /var/log/nginx/suspicious_agents.log 2>/dev/null | wc -l)
        if [[ $suspicious_agents -gt 0 ]]; then
            log_alert "🚨 $suspicious_agents user agents suspects détectés aujourd'hui"
        fi
    fi
    
    # Accès bloqués
    if docker-compose exec -T nginx test -f /var/log/nginx/blocked_access.log; then
        local blocked_access=$(docker-compose exec -T nginx grep "$today" /var/log/nginx/blocked_access.log 2>/dev/null | wc -l)
        if [[ $blocked_access -gt 0 ]]; then
            log_warning "⚠️  $blocked_access tentatives d'accès bloquées aujourd'hui"
        fi
    fi
}

# Fonction pour analyser les tentatives de connexion
analyze_login_attempts() {
    log_info "Analyse des tentatives de connexion..."
    
    if docker-compose exec -T nginx test -f /var/log/nginx/login_attempts.log; then
        local today=$(date +%Y-%m-%d)
        local login_attempts=$(docker-compose exec -T nginx grep "$today" /var/log/nginx/login_attempts.log 2>/dev/null | wc -l)
        
        if [[ $login_attempts -gt 100 ]]; then
            log_alert "🚨 Nombre élevé de tentatives de connexion : $login_attempts"
        elif [[ $login_attempts -gt 50 ]]; then
            log_warning "⚠️  Tentatives de connexion modérées : $login_attempts"
        else
            log_success "✅ Tentatives de connexion normales : $login_attempts"
        fi
    fi
}

# Fonction pour vérifier les IPs suspectes
check_suspicious_ips() {
    log_info "Vérification des IPs suspectes..."
    
    # Top 10 des IPs avec le plus de requêtes
    if docker-compose exec -T nginx test -f /var/log/nginx/access.log; then
        log_info "Top 10 des IPs les plus actives :"
        docker-compose exec -T nginx awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head -10 | while read count ip; do
            if [[ $count -gt 1000 ]]; then
                log_alert "🚨 IP suspecte : $ip ($count requêtes)"
            elif [[ $count -gt 500 ]]; then
                log_warning "⚠️  IP active : $ip ($count requêtes)"
            else
                echo "   $ip ($count requêtes)"
            fi
        done
    fi
}

# Fonction pour vérifier l'état SSL/TLS
check_ssl_status() {
    log_info "Vérification de l'état SSL/TLS..."
    
    # Test de connexion SSL
    if timeout 5 openssl s_client -connect localhost:443 -servername localhost </dev/null >/dev/null 2>&1; then
        log_success "✅ Certificat SSL valide"
        
        # Vérifier la version TLS
        local tls_version=$(timeout 5 openssl s_client -connect localhost:443 -servername localhost </dev/null 2>/dev/null | grep "Protocol" | awk '{print $3}')
        if [[ "$tls_version" == "TLSv1.3" ]]; then
            log_success "✅ TLS 1.3 actif"
        else
            log_warning "⚠️  Version TLS : $tls_version"
        fi
    else
        log_error "❌ Problème avec le certificat SSL"
    fi
}

# Fonction pour générer un rapport de sécurité
generate_security_report() {
    log_info "Génération du rapport de sécurité..."
    
    local report_file="/tmp/dcop_security_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "DCOP (413) - Rapport de Sécurité"
        echo "================================="
        echo "Date : $(date)"
        echo "Serveur : $(hostname)"
        echo ""
        
        echo "STATISTIQUES DES ATTAQUES"
        echo "-------------------------"
        analyze_attacks 2>&1
        echo ""
        
        echo "TENTATIVES DE CONNEXION"
        echo "----------------------"
        analyze_login_attempts 2>&1
        echo ""
        
        echo "IPS SUSPECTES"
        echo "-------------"
        check_suspicious_ips 2>&1
        echo ""
        
        echo "ÉTAT SSL/TLS"
        echo "------------"
        check_ssl_status 2>&1
        
    } > "$report_file"
    
    log_success "Rapport généré : $report_file"
}

# Fonction pour surveiller en temps réel
monitor_realtime() {
    log_info "Surveillance en temps réel (Ctrl+C pour arrêter)..."
    
    # Surveiller les logs d'attaque en temps réel
    docker-compose exec nginx tail -f /var/log/nginx/access.log /var/log/nginx/error.log /var/log/nginx/*_attempts.log /var/log/nginx/blocked_access.log 2>/dev/null | while read line; do
        if echo "$line" | grep -q "sql_injection\|xss_attempts\|suspicious_agents"; then
            log_alert "🚨 ATTAQUE DÉTECTÉE : $line"
        elif echo "$line" | grep -q "blocked_access"; then
            log_warning "⚠️  ACCÈS BLOQUÉ : $line"
        elif echo "$line" | grep -q "login_attempts"; then
            log_info "🔐 TENTATIVE CONNEXION : $line"
        fi
    done
}

# Fonction principale
main() {
    local action="${1:-status}"
    
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                DCOP (413) - MONITORING SÉCURITÉ             ║"
    echo "║              Surveillance des Tentatives d'Intrusion        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    cd "${PROJECT_DIR}""
    
    case "$action" in
        "status")
            analyze_attacks
            analyze_login_attempts
            check_suspicious_ips
            check_ssl_status
            ;;
        "attacks")
            analyze_attacks
            ;;
        "logins")
            analyze_login_attempts
            ;;
        "ips")
            check_suspicious_ips
            ;;
        "ssl")
            check_ssl_status
            ;;
        "report")
            generate_security_report
            ;;
        "monitor")
            monitor_realtime
            ;;
        *)
            echo "Usage: $0 [status|attacks|logins|ips|ssl|report|monitor]"
            echo
            echo "Actions disponibles :"
            echo "  status  - Vérification complète de sécurité"
            echo "  attacks - Analyser les tentatives d'attaque"
            echo "  logins  - Analyser les tentatives de connexion"
            echo "  ips     - Vérifier les IPs suspectes"
            echo "  ssl     - Vérifier l'état SSL/TLS"
            echo "  report  - Générer un rapport de sécurité"
            echo "  monitor - Surveillance en temps réel"
            exit 1
            ;;
    esac
}

# Exécution
main "$@"
